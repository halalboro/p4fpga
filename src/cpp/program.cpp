// program.cpp

#include "common.h"
#include "frontends/p4/coreLibrary.h"
#include "program.h"
#include "parser.h"
#include "table.h"
#include "control.h"
#include "deparser.h"
#include "lib/log.h"
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <iomanip>

namespace SV {

// Destructor implementation
SVProgram::~SVProgram() {
    delete parser;
    delete ingress;
    delete egress;
    delete deparser;
}

bool SVProgram::copyTemplates(const std::string& outputDir) {
    LOG1("Copying  parser/deparser templates");
    
    // Create hdl directory if it doesn't exist
    std::string hdlDir = outputDir + "/hdl";
    mkdir(hdlDir.c_str(), 0755);
    
    // Paths to source templates
    // Assuming templates are in src/sv/ relative to build directory
    std::string srcParserPath = "../src/sv/parser.sv";
    std::string srcDeparserPath = "../src/sv/deparser.sv";
    
    // Destination paths
    std::string dstParserPath = hdlDir + "/parser.sv";
    std::string dstDeparserPath = hdlDir + "/deparser.sv";
    
    // Copy parser template
    std::ifstream srcParser(srcParserPath, std::ios::binary);
    if (!srcParser.is_open()) {
        P4::error("Failed to open  parser template: %s", srcParserPath.c_str());
        return false;
    }
    
    std::ofstream dstParser(dstParserPath, std::ios::binary);
    if (!dstParser.is_open()) {
        P4::error("Failed to create parser destination: %s", dstParserPath.c_str());
        return false;
    }
    
    dstParser << srcParser.rdbuf();
    srcParser.close();
    dstParser.close();
    
    LOG1("Copied parser.sv to " << dstParserPath);
    
    // Copy deparser template
    std::ifstream srcDeparser(srcDeparserPath, std::ios::binary);
    if (!srcDeparser.is_open()) {
        P4::error("Failed to open  deparser template: %s", srcDeparserPath.c_str());
        return false;
    }
    
    std::ofstream dstDeparser(dstDeparserPath, std::ios::binary);
    if (!dstDeparser.is_open()) {
        P4::error("Failed to create deparser destination: %s", dstDeparserPath.c_str());
        return false;
    }
    
    dstDeparser << srcDeparser.rdbuf();
    srcDeparser.close();
    dstDeparser.close();
    
    LOG1("Copied deparser.sv to " << dstDeparserPath);
    
    return true;
}

bool SVProgram::build() {
    if (!toplevel) {
        P4::error("No toplevel block provided");
        return false;
    }
    
    auto pack = toplevel->getMain();
    if (!pack) {
        P4::error("No main package found");
        return false;
    }
    
    std::cerr << "Main package found: " << pack->getName().toString() << std::endl;
    
    if (!program) {
        program = toplevel->getProgram();
        if (!program) {
            P4::error("No P4Program found in toplevel block");
            return false;
        }
    }
    
    // Process all objects in the program
    for (auto obj : program->objects) {
        if (auto p = obj->to<IR::P4Parser>()) {
            std::cerr << "Found parser: " << p->name << std::endl;
            if (p->name.string().find("Parser") != std::string::npos) {
                auto pb = new IR::ParserBlock(p, p->type, p);
                parser = new SVParser(this, pb, typeMap, refMap);
                if (!parser->build()) {
                    std::cerr << "WARNING: Parser build failed" << std::endl;
                } else {
                    // NEW: Extract parser configuration
                    parserConfig = parser->getParserConfig();
                    LOG1("Parser configuration extracted: 0b" << parser->getParserConfigString());
                }
                LOG1("Built parser: " << p->name);
            }
        } else if (auto c = obj->to<IR::P4Control>()) {
            std::cerr << "Found control: " << c->name << std::endl;
            
            if (c->name == "MyIngress") {
                std::cerr << "Building ingress control..." << std::endl;
                auto cb = new IR::ControlBlock(c, c->type, c);
                ingress = new SVControl(this, cb, typeMap, refMap);
                ingress->setIsIngress(true);
                if (!ingress->build()) {
                    std::cerr << "WARNING: Ingress build failed" << std::endl;
                }
                
                // NEW: Extract control configuration for submodules
                controlConfig = ingress->extractConfiguration();
                LOG1("Control configuration extracted");
                
                std::cerr << "Built ingress control" << std::endl;
            } else if (c->name == "MyEgress") {
                std::cerr << "Building egress control..." << std::endl;
                auto cb = new IR::ControlBlock(c, c->type, c);
                egress = new SVControl(this, cb, typeMap, refMap);
                egress->setIsIngress(false);
                if (!egress->build()) {
                    std::cerr << "WARNING: Egress build failed" << std::endl;
                }
                std::cerr << "Built egress control" << std::endl;
            } else if (c->name == "MyDeparser") {
                std::cerr << "Building deparser..." << std::endl;
                auto cb = new IR::ControlBlock(c, c->type, c);
                deparser = new SVDeparser(this, cb);
                if (!deparser->build()) {
                    std::cerr << "WARNING: Deparser build failed" << std::endl;
                } else {
                    // NEW: Extract deparser configuration
                    deparserConfig = deparser->getDeparserConfig();
                    LOG1("Deparser configuration extracted: 0x" << std::hex << deparserConfig << std::dec);
                }
                std::cerr << "Built deparser" << std::endl;
            }
        }
    }
    
    // Create defaults only if components weren't found
    if (!parser) {
        std::cerr << "WARNING: No parser found, creating default" << std::endl;
        parser = new SVParser(this, nullptr, typeMap, refMap);
        parser->build();
        parserConfig = parser->getParserConfig();
    }
    if (!ingress) {
        std::cerr << "WARNING: No ingress found, creating default" << std::endl;
        ingress = new SVControl(this, nullptr, typeMap, refMap);
        ingress->setIsIngress(true);
        ingress->build();
    }
    if (!egress) {
        std::cerr << "WARNING: No egress found, creating default" << std::endl;
        egress = new SVControl(this, nullptr, typeMap, refMap);
        egress->setIsIngress(false);
        egress->build();
    }
    if (!deparser) {
        std::cerr << "WARNING: No deparser found, creating default" << std::endl;
        deparser = new SVDeparser(this, nullptr);
        deparser->build();
        deparserConfig = deparser->getDeparserConfig();
    }
    
    pipelineConfig.stageCount = 4;
    LOG1("Total pipeline stages: " << pipelineConfig.stageCount);
    
    // Print configuration summary
    std::cerr << "\n========================================" << std::endl;
    std::cerr << "Configuration Summary:" << std::endl;
    std::cerr << "  Parser Config:   8'b" << parser->getParserConfigString() << std::endl;
    std::cerr << "  Deparser Config: 16'h" << deparser->getDeparserConfigString() << std::endl;
    std::cerr << "========================================\n" << std::endl;
    
    return true;
}

void SVProgram::emit(SVCodeGen& codegen) {
    LOG1("Generating SystemVerilog code");
    
    if (parser) parser->emit(codegen);
    if (deparser) deparser->emit(codegen);
        
    // Generate top-level router integration with configurations
    emitRouterTop(codegen);
}

// Generate control slave module
void SVProgram::emitControlSlave(const std::string& outputDir, const std::string& baseName) {
    LOG1("Generating control slave module: " << baseName << "_slave");
    
    std::string slavePath = outputDir + "/hdl/" + baseName + "_slave.sv";
    std::ofstream slave(slavePath);
    
    if (!slave.is_open()) {
        P4::error("Failed to create control slave file: %s", slavePath.c_str());
        return;
    }
    
    slave << "/**\n";
    slave << " * " << baseName << " Control Slave\n";
    slave << " * Generated by P4-to-SystemVerilog Compiler\n";
    slave << " * \n";
    slave << " * Converts AXI-Lite slave interface to simple table write signals\n";
    slave << " */\n\n";
    
    slave << "import lynxTypes::*;\n\n";
    
    slave << "module " << baseName << "_slave (\n";  // Dynamic module name
    slave << "    input  logic                          aclk,\n";
    slave << "    input  logic                          aresetn,\n";
    slave << "    \n";
    slave << "    // AXI-Lite slave interface\n";
    slave << "    AXI4L.s                              axi_ctrl,\n";
    slave << "    \n";
    slave << "    // Table configuration outputs\n";
    slave << "    output logic                          table_write_enable,\n";
    slave << "    output logic [9:0]                    table_write_addr,\n";
    slave << "    output logic                          table_entry_valid,\n";
    slave << "    output logic [31:0]                   table_entry_prefix,\n";
    slave << "    output logic [5:0]                    table_entry_prefix_len,\n";
    slave << "    output logic [2:0]                    table_entry_action,\n";
    slave << "    output logic [47:0]                   table_entry_dst_mac,\n";
    slave << "    output logic [8:0]                    table_entry_egress_port\n";
    slave << ");\n\n";
    
    slave << "    // Register map\n";
    slave << "    localparam integer N_REGS = 16;\n";
    slave << "    localparam integer ADDR_LSB = $clog2(AXIL_DATA_BITS/8);\n";
    slave << "    localparam integer ADDR_MSB = $clog2(N_REGS);\n";
    slave << "    localparam integer AXIL_ADDR_BITS = ADDR_LSB + ADDR_MSB;\n\n";
    
    slave << "    // Internal AXI signals\n";
    slave << "    logic [AXIL_ADDR_BITS-1:0] axi_awaddr;\n";
    slave << "    logic axi_awready;\n";
    slave << "    logic [AXIL_ADDR_BITS-1:0] axi_araddr;\n";
    slave << "    logic axi_arready;\n";
    slave << "    logic [1:0] axi_bresp;\n";
    slave << "    logic axi_bvalid;\n";
    slave << "    logic axi_wready;\n";
    slave << "    logic [AXIL_DATA_BITS-1:0] axi_rdata;\n";
    slave << "    logic [1:0] axi_rresp;\n";
    slave << "    logic axi_rvalid;\n";
    slave << "    logic aw_en;\n\n";
    
    slave << "    // Register storage\n";
    slave << "    logic [N_REGS-1:0][AXIL_DATA_BITS-1:0] slv_reg;\n";
    slave << "    logic slv_reg_wren;\n\n";
    
    slave << "    /* Register Map:\n";
    slave << "     * 0x00 (RW): Control - bit[0]=table_write_trigger\n";
    slave << "     * 0x04 (RW): Table address - bits[9:0]=address\n";
    slave << "     * 0x08 (RW): Entry control - bit[0]=valid, bits[8:6]=action\n";
    slave << "     * 0x0C (RW): IPv4 prefix - bits[31:0]=prefix\n";
    slave << "     * 0x10 (RW): Prefix length - bits[5:0]=length\n";
    slave << "     * 0x14 (RW): Destination MAC low - bits[31:0]=mac[31:0]\n";
    slave << "     * 0x18 (RW): Destination MAC high - bits[15:0]=mac[47:32]\n";
    slave << "     * 0x1C (RW): Egress port - bits[8:0]=port\n";
    slave << "     */\n\n";
    
    slave << "    // Write process\n";
    slave << "    assign slv_reg_wren = axi_wready && axi_ctrl.wvalid && axi_awready && axi_ctrl.awvalid;\n\n";
    
    slave << "    // Table write pulse generation\n";
    slave << "    logic write_pulse;\n";
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            write_pulse <= 1'b0;\n";
    slave << "            table_write_enable <= 1'b0;\n";
    slave << "        end else begin\n";
    slave << "            if (slv_reg_wren && axi_awaddr[ADDR_LSB+:ADDR_MSB] == 4'h0 && axi_ctrl.wdata[0]) begin\n";
    slave << "                write_pulse <= 1'b1;\n";
    slave << "            end else begin\n";
    slave << "                write_pulse <= 1'b0;\n";
    slave << "            end\n";
    slave << "            table_write_enable <= write_pulse;\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            slv_reg <= '0;\n";
    slave << "            slv_reg[2] <= 32'h00000001; // Valid entry, action=DROP\n";
    slave << "        end else begin\n";
    slave << "            slv_reg[0][0] <= 1'b0;\n\n";
    slave << "            if (slv_reg_wren) begin\n";
    slave << "                case (axi_awaddr[ADDR_LSB+:ADDR_MSB])\n";
    slave << "                    4'h0, 4'h1, 4'h2, 4'h3, 4'h4, 4'h5, 4'h6, 4'h7:\n";
    slave << "                        for (int i = 0; i < AXIL_DATA_BITS/8; i++) begin\n";
    slave << "                            if (axi_ctrl.wstrb[i]) begin\n";
    slave << "                                slv_reg[axi_awaddr[ADDR_LSB+:ADDR_MSB]][(i*8)+:8] <= axi_ctrl.wdata[(i*8)+:8];\n";
    slave << "                            end\n";
    slave << "                        end\n";
    slave << "                    default: ;\n";
    slave << "                endcase\n";
    slave << "            end\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    // Output assignments\n";
    slave << "    assign table_write_addr = slv_reg[1][9:0];\n";
    slave << "    assign table_entry_valid = slv_reg[2][0];\n";
    slave << "    assign table_entry_action = slv_reg[2][8:6];\n";
    slave << "    assign table_entry_prefix = slv_reg[3][31:0];\n";
    slave << "    assign table_entry_prefix_len = slv_reg[4][5:0];\n";
    slave << "    assign table_entry_dst_mac = {slv_reg[6][15:0], slv_reg[5][31:0]};\n";
    slave << "    assign table_entry_egress_port = slv_reg[7][8:0];\n\n";
    
    slave << "    // Read process\n";
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            axi_rdata <= '0;\n";
    slave << "        end else if (axi_arready & axi_ctrl.arvalid & ~axi_rvalid) begin\n";
    slave << "            case (axi_araddr[ADDR_LSB+:ADDR_MSB])\n";
    slave << "                4'h0: axi_rdata <= slv_reg[0];\n";
    slave << "                4'h1: axi_rdata <= slv_reg[1];\n";
    slave << "                4'h2: axi_rdata <= slv_reg[2];\n";
    slave << "                4'h3: axi_rdata <= slv_reg[3];\n";
    slave << "                4'h4: axi_rdata <= slv_reg[4];\n";
    slave << "                4'h5: axi_rdata <= slv_reg[5];\n";
    slave << "                4'h6: axi_rdata <= slv_reg[6];\n";
    slave << "                4'h7: axi_rdata <= slv_reg[7];\n";
    slave << "                4'h8: axi_rdata <= {31'h0, 1'b1}; // Status: always ready\n";
    slave << "                default: axi_rdata <= '0;\n";
    slave << "            endcase\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    // Write address channel\n";
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            axi_awready <= 1'b0;\n";
    slave << "            axi_awaddr <= '0;\n";
    slave << "            aw_en <= 1'b1;\n";
    slave << "        end else begin\n";
    slave << "            if (~axi_awready && axi_ctrl.awvalid && axi_ctrl.wvalid && aw_en) begin\n";
    slave << "                axi_awready <= 1'b1;\n";
    slave << "                axi_awaddr <= axi_ctrl.awaddr;\n";
    slave << "                aw_en <= 1'b0;\n";
    slave << "            end else begin\n";
    slave << "                axi_awready <= 1'b0;\n";
    slave << "                if (axi_ctrl.bready && axi_bvalid)\n";
    slave << "                    aw_en <= 1'b1;\n";
    slave << "            end\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    // Write data channel\n";
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            axi_wready <= 1'b0;\n";
    slave << "        end else begin\n";
    slave << "            axi_wready <= ~axi_wready && axi_ctrl.wvalid && axi_ctrl.awvalid && aw_en;\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    // Write response channel\n";
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            axi_bvalid <= 1'b0;\n";
    slave << "            axi_bresp <= 2'b00;\n";
    slave << "        end else begin\n";
    slave << "            if (axi_awready && axi_ctrl.awvalid && ~axi_bvalid && axi_wready && axi_ctrl.wvalid) begin\n";
    slave << "                axi_bvalid <= 1'b1;\n";
    slave << "                axi_bresp <= 2'b00;\n";
    slave << "            end else if (axi_ctrl.bready && axi_bvalid) begin\n";
    slave << "                axi_bvalid <= 1'b0;\n";
    slave << "            end\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    // Read address channel\n";
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            axi_arready <= 1'b0;\n";
    slave << "            axi_araddr <= '0;\n";
    slave << "        end else begin\n";
    slave << "            if (~axi_arready && axi_ctrl.arvalid) begin\n";
    slave << "                axi_arready <= 1'b1;\n";
    slave << "                axi_araddr <= axi_ctrl.araddr;\n";
    slave << "            end else begin\n";
    slave << "                axi_arready <= 1'b0;\n";
    slave << "            end\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    // Read data channel\n";
    slave << "    always_ff @(posedge aclk) begin\n";
    slave << "        if (!aresetn) begin\n";
    slave << "            axi_rvalid <= 1'b0;\n";
    slave << "            axi_rresp <= 2'b00;\n";
    slave << "        end else begin\n";
    slave << "            if (axi_arready && axi_ctrl.arvalid && ~axi_rvalid) begin\n";
    slave << "                axi_rvalid <= 1'b1;\n";
    slave << "                axi_rresp <= 2'b00;\n";
    slave << "            end else if (axi_rvalid && axi_ctrl.rready) begin\n";
    slave << "                axi_rvalid <= 1'b0;\n";
    slave << "            end\n";
    slave << "        end\n";
    slave << "    end\n\n";
    
    slave << "    // Connect AXI interface\n";
    slave << "    assign axi_ctrl.awready = axi_awready;\n";
    slave << "    assign axi_ctrl.arready = axi_arready;\n";
    slave << "    assign axi_ctrl.bresp = axi_bresp;\n";
    slave << "    assign axi_ctrl.bvalid = axi_bvalid;\n";
    slave << "    assign axi_ctrl.wready = axi_wready;\n";
    slave << "    assign axi_ctrl.rdata = axi_rdata;\n";
    slave << "    assign axi_ctrl.rresp = axi_rresp;\n";
    slave << "    assign axi_ctrl.rvalid = axi_rvalid;\n\n";
    
    slave << "endmodule\n";
    
    slave.close();
    
    LOG1("Generated control slave: " << slavePath);
}

void SVProgram::emitRouterTop(SVCodeGen& codegen) {
    LOG1("Generating top-level router module with direct submodule instantiation");
    
    auto builder = codegen.getTopBuilder();
    std::stringstream ss;
    
    // Module header
    builder->appendLine("//");
    builder->appendLine("// P4 Top Module");
    builder->appendLine("// Direct submodule instantiation: Parser -> Match -> Action -> Stats -> Deparser");
    builder->appendLine("//");
    builder->appendLine("// Parser Config:   8'b" + parser->getParserConfigString());
    builder->appendLine("// Deparser Config: 16'h" + deparser->getDeparserConfigString());
    builder->appendLine("//");
    builder->newline();
    
    // Module declaration - name will be replaced by backend
    builder->appendLine("module router #(");  // Default name, backend renames file
    builder->increaseIndent();
    builder->appendLine("parameter DATA_WIDTH = 512,");
    builder->appendLine("parameter TABLE_SIZE = 1024");
    builder->decreaseIndent();
    builder->appendLine(") (");
    builder->increaseIndent();
    
    // Clock and reset
    builder->appendLine("input  logic                     aclk,");
    builder->appendLine("input  logic                     aresetn,");
    builder->newline();
    
    // External AXI-Stream input
    builder->appendLine("// Packet input interface");
    builder->appendLine("input  logic [DATA_WIDTH-1:0]   s_axis_tdata,");
    builder->appendLine("input  logic                     s_axis_tvalid,");
    builder->appendLine("output logic                     s_axis_tready,");
    builder->appendLine("input  logic [DATA_WIDTH/8-1:0] s_axis_tkeep,");
    builder->appendLine("input  logic                     s_axis_tlast,");
    builder->newline();
    
    // External AXI-Stream output
    builder->appendLine("// Packet output interface");
    builder->appendLine("output logic [DATA_WIDTH-1:0]   m_axis_tdata,");
    builder->appendLine("output logic                     m_axis_tvalid,");
    builder->appendLine("input  logic                     m_axis_tready,");
    builder->appendLine("output logic [DATA_WIDTH/8-1:0] m_axis_tkeep,");
    builder->appendLine("output logic                     m_axis_tlast,");
    builder->appendLine("output logic [8:0]              m_axis_tdest,");
    builder->newline();
    
    // Control interface
    builder->appendLine("// Simple table control interface");
    builder->appendLine("input  logic                        table_write_enable,");
    builder->appendLine("input  logic [9:0]                 table_write_addr,");
    builder->appendLine("input  logic                        table_entry_valid,");
    builder->appendLine("input  logic [31:0]                table_entry_prefix,");
    builder->appendLine("input  logic [5:0]                 table_entry_prefix_len,");
    builder->appendLine("input  logic [2:0]                 table_entry_action,");
    builder->appendLine("input  logic [47:0]                table_entry_dst_mac,");
    builder->appendLine("input  logic [8:0]                 table_entry_egress_port,");
    builder->newline();
    
    // Statistics outputs
    builder->appendLine("// Statistics outputs");
    builder->appendLine("output logic [31:0]             packet_count,");
    builder->appendLine("output logic [31:0]             dropped_count,");
    builder->appendLine("output logic [31:0]             forwarded_count");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Configuration parameters
    builder->appendLine("// ============================================");
    builder->appendLine("// Parser/Deparser Configurations");
    builder->appendLine("// ============================================");
    ss.str("");
    ss << "localparam [7:0]  PARSER_CONFIG   = 8'b" << parser->getParserConfigString() << ";";
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "localparam [15:0] DEPARSER_CONFIG = 16'h" << deparser->getDeparserConfigString() << ";";
    builder->appendLine(ss.str());
    builder->newline();
    
    // Inter-stage signals
    emitInterStageSignals(builder);
    
    // Module instances 
    emitParserInstance(builder);
    emitMatchEngineInstance(builder);      
    emitActionEngineInstance(builder);     
    emitStatsEngineInstance(builder);      
    emitDeparserInstance(builder);
    
    builder->appendLine("endmodule");
}

void SVProgram::emitInterStageSignals(CodeBuilder* builder) {
    builder->appendLine("// ==========================================");
    builder->appendLine("// Inter-stage Signals");
    builder->appendLine("// ==========================================");
    builder->newline();
    
    // Parser outputs
    builder->appendLine("// Parser → Match");
    builder->appendLine("logic                        parser_valid;");
    builder->appendLine("logic                        parser_ready;");
    builder->appendLine("logic [511:0]                parser_data;");
    builder->appendLine("logic [63:0]                 parser_keep;");
    builder->appendLine("logic                        parser_last;");
    builder->appendLine("logic                        ethernet_valid;");
    builder->appendLine("logic [47:0]                 eth_dst_addr;");
    builder->appendLine("logic [47:0]                 eth_src_addr;");
    builder->appendLine("logic [15:0]                 eth_type;");
    builder->appendLine("logic                        ipv4_valid;");
    builder->appendLine("logic [7:0]                  ipv4_ttl;");
    builder->appendLine("logic [31:0]                 ipv4_src_addr;");
    builder->appendLine("logic [31:0]                 ipv4_dst_addr;");
    builder->newline();
    
    // Match outputs
    builder->appendLine("// Match → Action");
    builder->appendLine("logic                        lpm_valid;");
    builder->appendLine("logic                        lpm_ready;");
    builder->appendLine("logic                        lpm_hit;");
    builder->appendLine("logic [2:0]                  lpm_action;");
    builder->appendLine("logic [127:0]                lpm_action_data;");
    builder->appendLine("logic [511:0]                lpm_data;");
    builder->appendLine("logic [63:0]                 lpm_keep;");
    builder->appendLine("logic                        lpm_last;");
    builder->newline();
    
    // ADDED: Preserved signals from match
    builder->appendLine("// Preserved through match stage");
    builder->appendLine("logic                        lpm_ipv4_valid;");
    builder->appendLine("logic [47:0]                 lpm_eth_dst;");
    builder->appendLine("logic [47:0]                 lpm_eth_src;");
    builder->appendLine("logic [7:0]                  lpm_ipv4_ttl;");
    builder->newline();
    
    // Action outputs
    builder->appendLine("// Action → Deparser");
    builder->appendLine("logic                        action_valid;");
    builder->appendLine("logic                        action_ready;");
    builder->appendLine("logic                        action_drop;");
    builder->appendLine("logic [8:0]                  action_egress_port;");
    builder->appendLine("logic [511:0]                action_data;");
    builder->appendLine("logic [63:0]                 action_keep;");
    builder->appendLine("logic                        action_last;");
    builder->appendLine("logic                        header_modified;");
    builder->appendLine("logic [15:0]                 parser_packet_length;");
    builder->newline();
}

void SVProgram::emitParserInstance(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("// ============================================");
    builder->appendLine("//  Parser Instance");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("parser #(");
    builder->increaseIndent();
    builder->appendLine(".DATA_WIDTH(DATA_WIDTH),");
    builder->appendLine(".KEEP_WIDTH(DATA_WIDTH/8),");
    builder->appendLine(".PARSER_CONFIG(PARSER_CONFIG)");
    builder->decreaseIndent();
    builder->appendLine(") parser_inst (");
    builder->increaseIndent();
    
    builder->appendLine(".aclk(aclk),");
    builder->appendLine(".aresetn(aresetn),");
    builder->newline();
    
    builder->appendLine("// External input");
    builder->appendLine(".s_axis_tdata(s_axis_tdata),");
    builder->appendLine(".s_axis_tkeep(s_axis_tkeep),");
    builder->appendLine(".s_axis_tvalid(s_axis_tvalid),");
    builder->appendLine(".s_axis_tlast(s_axis_tlast),");
    builder->appendLine(".s_axis_tready(s_axis_tready),");
    builder->newline();
    
    // Connect parsed headers based on configuration
    if (parser->parsesHeader(cstring("ethernet"))) {
        builder->appendLine("// Ethernet outputs");
        builder->appendLine(".eth_dst_addr(ethernet_dstAddr),");
        builder->appendLine(".eth_src_addr(ethernet_srcAddr),");
        builder->appendLine(".eth_ether_type(ethernet_etherType),");
        builder->appendLine(".eth_valid(ethernet_valid),");
        builder->newline();
    }
    
    if (parser->parsesHeader(cstring("ipv4"))) {
        builder->appendLine("// IPv4 outputs");
        builder->appendLine(".ipv4_version(ipv4_version),");
        builder->appendLine(".ipv4_ihl(ipv4_ihl),");
        builder->appendLine(".ipv4_tos(ipv4_diffserv),");
        builder->appendLine(".ipv4_total_len(ipv4_totalLen),");
        builder->appendLine(".ipv4_identification(ipv4_identification),");
        builder->appendLine(".ipv4_flags(ipv4_flags),");
        builder->appendLine(".ipv4_frag_offset(ipv4_fragOffset),");
        builder->appendLine(".ipv4_ttl(ipv4_ttl),");
        builder->appendLine(".ipv4_protocol(ipv4_protocol),");
        builder->appendLine(".ipv4_hdr_checksum(ipv4_hdrChecksum),");
        builder->appendLine(".ipv4_src_addr(ipv4_srcAddr),");
        builder->appendLine(".ipv4_dst_addr(ipv4_dstAddr),");
        builder->appendLine(".ipv4_valid(ipv4_valid),");
        builder->newline();
    }
    
    if (parser->parsesHeader(cstring("udp"))) {
        builder->appendLine("// UDP outputs");
        builder->appendLine(".udp_src_port(udp_srcPort),");
        builder->appendLine(".udp_dst_port(udp_dstPort),");
        builder->appendLine(".udp_length(udp_length),");
        builder->appendLine(".udp_checksum(udp_checksum),");
        builder->appendLine(".udp_valid(udp_valid),");
        builder->newline();
    }
    
    builder->appendLine("// Payload outputs");
    builder->appendLine(".payload_data(parser_payload_data),");
    builder->appendLine(".payload_keep(parser_payload_keep),");
    builder->appendLine(".payload_valid(parser_payload_valid),");
    builder->appendLine(".payload_last(parser_payload_last),");
    builder->appendLine(".packet_length(parser_packet_length)");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Note about pass-through for now (can be refined later)
    builder->appendLine("// Pass-through packet data to pipeline (for now)");
    builder->appendLine("assign parser_to_pipeline_tdata = s_axis_tdata;");
    builder->appendLine("assign parser_to_pipeline_tvalid = parser_payload_valid;");
    builder->appendLine("assign parser_to_pipeline_tkeep = parser_payload_keep;");
    builder->appendLine("assign parser_to_pipeline_tlast = parser_payload_last;");
    builder->newline();
}

void SVProgram::emitMatchEngineInstance(CodeBuilder* builder) {
    builder->appendLine("// ==========================================");
    builder->appendLine("// Match Engine (LPM Table)");
    builder->appendLine("// ==========================================");
    
    builder->appendLine("match #(");
    builder->increaseIndent();
    builder->appendLine(".MATCH_TYPE(1),        // LPM");
    builder->appendLine(".KEY_WIDTH(32),        // IPv4 address");
    builder->appendLine(".TABLE_SIZE(1024),");
    builder->appendLine(".ACTION_DATA_WIDTH(128),");
    builder->appendLine(".DATA_WIDTH(512)");    // ADDED
    builder->decreaseIndent();
    builder->appendLine(") inst_match (");
    builder->increaseIndent();
    
    builder->appendLine(".aclk(aclk),");
    builder->appendLine(".aresetn(aresetn),");
    builder->newline();
    
    // Lookup interface
    builder->appendLine("// Lookup interface");
    builder->appendLine(".lookup_key(ipv4_dst_addr),");
    builder->appendLine(".lookup_key_mask(32'hFFFFFFFF),");
    builder->appendLine(".lookup_valid(parser_valid && ipv4_valid),");
    builder->appendLine(".lookup_ready(parser_ready),");
    builder->newline();
    
    // ADDED: Header validity and fields preservation
    builder->appendLine("// Header preservation");
    builder->appendLine(".ipv4_valid_in(ipv4_valid),");
    builder->appendLine(".eth_dst_addr_in(eth_dst_addr),");
    builder->appendLine(".eth_src_addr_in(eth_src_addr),");
    builder->appendLine(".ipv4_ttl_in(ipv4_ttl),");
    builder->newline();
    
    // ADDED: Packet data pass-through
    builder->appendLine("// Packet data pass-through");
    builder->appendLine(".packet_data_in(parser_data),");
    builder->appendLine(".packet_keep_in(parser_keep),");
    builder->appendLine(".packet_last_in(parser_last),");
    builder->newline();
    
    // Match results
    builder->appendLine("// Match results");
    builder->appendLine(".match_hit(lpm_hit),");
    builder->appendLine(".match_action_id(lpm_action),");
    builder->appendLine(".match_action_data(lpm_action_data),");
    builder->appendLine(".match_valid(lpm_valid),");
    builder->newline();
    
    // ADDED: Preserved outputs
    builder->appendLine("// Preserved outputs");
    builder->appendLine(".ipv4_valid_out(lpm_ipv4_valid),");
    builder->appendLine(".eth_dst_addr_out(lpm_eth_dst),");
    builder->appendLine(".eth_src_addr_out(lpm_eth_src),");
    builder->appendLine(".ipv4_ttl_out(lpm_ipv4_ttl),");
    builder->appendLine(".packet_data_out(lpm_data),");
    builder->appendLine(".packet_keep_out(lpm_keep),");
    builder->appendLine(".packet_last_out(lpm_last),");
    builder->newline();
    
    // Table programming
    builder->appendLine("// Table programming");
    builder->appendLine(".table_write_enable(table_write_enable),");
    builder->appendLine(".table_write_addr(table_write_addr),");
    builder->appendLine(".table_entry_valid(table_entry_valid),");
    builder->appendLine(".table_entry_key(table_entry_prefix),");
    builder->appendLine(".table_entry_mask(32'h0),");
    builder->appendLine(".table_entry_prefix_len(table_entry_prefix_len),");
    builder->appendLine(".table_entry_action_id(table_entry_action),");
    builder->appendLine(".table_entry_action_data({table_entry_egress_port, 71'h0, table_entry_dst_mac})");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
}

void SVProgram::emitActionEngineInstance(CodeBuilder* builder) {
    builder->appendLine("// ==========================================");
    builder->appendLine("// Action Engine");
    builder->appendLine("// ==========================================");
    
    builder->appendLine("action #(");
    builder->increaseIndent();
    builder->appendLine(".DATA_WIDTH(512),");
    builder->appendLine(".ACTION_DATA_WIDTH(128),");
    builder->appendLine(".ACTION_CONFIG(8'b00000111)  // Forward, Drop, Modify");
    builder->decreaseIndent();
    builder->appendLine(") inst_action (");
    builder->increaseIndent();
    
    builder->appendLine(".aclk(aclk),");
    builder->appendLine(".aresetn(aresetn),");
    builder->newline();
    
    // Packet input
    builder->appendLine("// Packet input");
    builder->appendLine(".packet_in(lpm_data),");
    builder->appendLine(".packet_keep_in(lpm_keep),");      // ADDED
    builder->appendLine(".packet_last_in(lpm_last),");      // ADDED
    builder->appendLine(".packet_valid(lpm_valid),");
    builder->appendLine(".packet_ready(lpm_ready),");
    builder->newline();
    
    // Action control
    builder->appendLine("// Action control");
    builder->appendLine(".action_id(lpm_action),");
    builder->appendLine(".action_data(lpm_action_data),");
    builder->appendLine(".action_valid(lpm_valid),");
    builder->newline();
    
    // CHANGED: Header fields (now from match engine outputs)
    builder->appendLine("// Header fields (preserved from match)");
    builder->appendLine(".ipv4_valid(lpm_ipv4_valid),");     // CHANGED
    builder->appendLine(".eth_dst_addr(lpm_eth_dst),");      // CHANGED
    builder->appendLine(".eth_src_addr(lpm_eth_src),");      // CHANGED
    builder->appendLine(".ipv4_ttl(lpm_ipv4_ttl),");         // CHANGED
    builder->appendLine(".ipv4_src_addr(ipv4_src_addr),");
    builder->appendLine(".ipv4_dst_addr(ipv4_dst_addr),");
    builder->newline();
    
    // Packet output
    builder->appendLine("// Packet output");
    builder->appendLine(".packet_out(action_data),");
    builder->appendLine(".packet_keep_out(action_keep),");   // ADDED
    builder->appendLine(".packet_last_out(action_last),");   // ADDED
    builder->appendLine(".packet_out_valid(action_valid),");
    builder->appendLine(".packet_out_ready(action_ready),");
    builder->newline();
    
    // Action results
    builder->appendLine("// Action results");
    builder->appendLine(".drop(action_drop),");
    builder->appendLine(".egress_port(action_egress_port),");
    builder->appendLine(".header_modified(header_modified)");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
}


void SVProgram::emitStatsEngineInstance(CodeBuilder* builder) {
    builder->appendLine("// ============================================");
    builder->appendLine("// Statistics Engine Instance");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("stats #(");
    builder->increaseIndent();
    builder->appendLine(".NUM_PORTS(16),");
    builder->appendLine(".NUM_REGISTERS(8),");
    builder->appendLine(".COUNTER_WIDTH(32)");
    builder->decreaseIndent();
    
    builder->appendLine(") stats_inst (");
    builder->increaseIndent();
    builder->appendLine(".aclk(aclk),");
    builder->appendLine(".aresetn(aresetn),");
    builder->newline();
    
    builder->appendLine("// Packet events");
    builder->appendLine(".packet_valid(action_valid),");
    builder->appendLine(".packet_last(action_last),");
    builder->appendLine(".packet_drop(action_drop),");
    builder->appendLine(".packet_length(parser_packet_length),");  
    builder->appendLine(".egress_port(action_egress_port),");
    builder->newline();
    
    builder->appendLine("// Global statistics");
    builder->appendLine(".packet_count(packet_count),");
    builder->appendLine(".dropped_count(dropped_count),");
    builder->appendLine(".forwarded_count(forwarded_count),");
    builder->appendLine(".byte_count(),");
    builder->newline();
    
    builder->appendLine("// Per-port statistics");
    builder->appendLine(".port_packet_count(),");
    builder->appendLine(".port_byte_count(),");
    builder->newline();
    
    builder->appendLine("// User registers");
    builder->appendLine(".reg_write_enable(1'b0),");
    builder->appendLine(".reg_write_addr(3'h0),");
    builder->appendLine(".reg_write_data(32'h0),");
    builder->appendLine(".user_registers()");
    builder->decreaseIndent();
    
    builder->appendLine(");");
    builder->newline();
}

void SVProgram::emitPipelineInstance(CodeBuilder* builder) {
    builder->appendLine("// ============================================");
    builder->appendLine("// Control Instance");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("control #("); 
    builder->increaseIndent();
    builder->appendLine(".DATA_WIDTH(DATA_WIDTH),");
    builder->appendLine(".TABLE_SIZE(TABLE_SIZE)");
    builder->decreaseIndent();
    builder->appendLine(") control_inst ("); 
    
    builder->appendLine(".aclk(aclk),");
    builder->appendLine(".aresetn(aresetn),");
    builder->newline();
    
    builder->appendLine("// Input from parser");
    builder->appendLine(".s_axis_tdata(parser_to_pipeline_tdata),");
    builder->appendLine(".s_axis_tvalid(parser_to_pipeline_tvalid),");
    builder->appendLine(".s_axis_tready(parser_to_pipeline_tready),");
    builder->appendLine(".s_axis_tkeep(parser_to_pipeline_tkeep),");
    builder->appendLine(".s_axis_tlast(parser_to_pipeline_tlast),");
    builder->newline();
    
    // Connect parsed headers
    if (parser->parsesHeader(cstring("ethernet"))) {
        builder->appendLine("// Ethernet inputs");
        builder->appendLine(".ethernet_valid(ethernet_valid),");
        builder->appendLine(".ethernet_dstAddr(ethernet_dstAddr),");
        builder->appendLine(".ethernet_srcAddr(ethernet_srcAddr),");
        builder->appendLine(".ethernet_etherType(ethernet_etherType),");
        builder->newline();
    }
    
    if (parser->parsesHeader(cstring("ipv4"))) {
        builder->appendLine("// IPv4 inputs");
        builder->appendLine(".ipv4_valid(ipv4_valid),");
        builder->appendLine(".ipv4_version(ipv4_version),");
        builder->appendLine(".ipv4_ihl(ipv4_ihl),");
        builder->appendLine(".ipv4_diffserv(ipv4_diffserv),");
        builder->appendLine(".ipv4_totalLen(ipv4_totalLen),");
        builder->appendLine(".ipv4_identification(ipv4_identification),");
        builder->appendLine(".ipv4_flags(ipv4_flags),");
        builder->appendLine(".ipv4_fragOffset(ipv4_fragOffset),");
        builder->appendLine(".ipv4_ttl(ipv4_ttl),");
        builder->appendLine(".ipv4_protocol(ipv4_protocol),");
        builder->appendLine(".ipv4_hdrChecksum(ipv4_hdrChecksum),");
        builder->appendLine(".ipv4_srcAddr(ipv4_srcAddr),");
        builder->appendLine(".ipv4_dstAddr(ipv4_dstAddr),");
        builder->newline();
    }
    
    builder->appendLine("// Output to deparser");
    builder->appendLine(".m_axis_tdata(pipeline_to_deparser_tdata),");
    builder->appendLine(".m_axis_tvalid(pipeline_to_deparser_tvalid),");
    builder->appendLine(".m_axis_tready(pipeline_to_deparser_tready),");
    builder->appendLine(".m_axis_tkeep(pipeline_to_deparser_tkeep),");
    builder->appendLine(".m_axis_tlast(pipeline_to_deparser_tlast),");
    builder->appendLine(".m_axis_drop(pipeline_to_deparser_drop),");
    builder->appendLine(".m_axis_egress_port(pipeline_to_deparser_egress_port),");
    builder->newline();
    
    builder->appendLine("// Control interface");
    builder->appendLine(".table_write_enable(table_write_enable),");
    builder->appendLine(".table_write_addr(table_write_addr),");
    builder->appendLine(".table_entry_valid(table_entry_valid),");
    builder->appendLine(".table_entry_prefix(table_entry_prefix),");
    builder->appendLine(".table_entry_prefix_len(table_entry_prefix_len),");
    builder->appendLine(".table_entry_action(table_entry_action),");
    builder->appendLine(".table_entry_dst_mac(table_entry_dst_mac),");
    builder->appendLine(".table_entry_egress_port(table_entry_egress_port),");
    builder->newline();
    
    builder->appendLine("// Statistics outputs");
    builder->appendLine(".packet_count(packet_count),");
    builder->appendLine(".dropped_count(dropped_count),");
    builder->appendLine(".forwarded_count(forwarded_count)");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
}

void SVProgram::emitDeparserInstance(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("// ============================================");
    builder->appendLine("//  Deparser Instance");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("deparser #(");
    builder->increaseIndent();
    builder->appendLine(".DATA_WIDTH(DATA_WIDTH),");
    builder->appendLine(".KEEP_WIDTH(DATA_WIDTH/8),");
    builder->appendLine(".DEPARSER_CONFIG(DEPARSER_CONFIG)");
    builder->decreaseIndent();
    builder->appendLine(") deparser_inst (");
    builder->increaseIndent();
    
    builder->appendLine(".aclk(aclk),");
    builder->appendLine(".aresetn(aresetn),");
    builder->newline();
    
    // Connect modified headers from pipeline
    if (deparser->emitsHeader(cstring("ethernet"))) {
        builder->appendLine("// Ethernet inputs (modified by pipeline)");
        builder->appendLine(".eth_dst_addr(ethernet_dstAddr),");
        builder->appendLine(".eth_src_addr(ethernet_srcAddr),");
        builder->appendLine(".eth_ether_type(ethernet_etherType),");
        builder->appendLine(".eth_valid(ethernet_valid),");
        builder->newline();
    }
    
    if (deparser->emitsHeader(cstring("ipv4"))) {
        builder->appendLine("// IPv4 inputs (modified by pipeline)");
        builder->appendLine(".ipv4_version(ipv4_version),");
        builder->appendLine(".ipv4_ihl(ipv4_ihl),");
        builder->appendLine(".ipv4_tos(ipv4_diffserv),");
        builder->appendLine(".ipv4_total_len(ipv4_totalLen),");
        builder->appendLine(".ipv4_identification(ipv4_identification),");
        builder->appendLine(".ipv4_flags(ipv4_flags),");
        builder->appendLine(".ipv4_frag_offset(ipv4_fragOffset),");
        builder->appendLine(".ipv4_ttl(ipv4_ttl),");
        builder->appendLine(".ipv4_protocol(ipv4_protocol),");
        builder->appendLine(".ipv4_hdr_checksum(ipv4_hdrChecksum),");
        builder->appendLine(".ipv4_src_addr(ipv4_srcAddr),");
        builder->appendLine(".ipv4_dst_addr(ipv4_dstAddr),");
        builder->appendLine(".ipv4_valid(ipv4_valid),");
        builder->newline();
    }
    
    builder->appendLine("// Payload input");
    builder->appendLine(".payload_data(parser_payload_data),");
    builder->appendLine(".payload_keep(parser_payload_keep),");
    builder->appendLine(".payload_valid(pipeline_to_deparser_tvalid),");
    builder->appendLine(".payload_last(pipeline_to_deparser_tlast),");
    builder->newline();
    
    builder->appendLine("// Control input");
    builder->appendLine(".drop_packet(pipeline_to_deparser_drop),");
    builder->newline();
    
    builder->appendLine("// External output");
    builder->appendLine(".m_axis_tdata(m_axis_tdata),");
    builder->appendLine(".m_axis_tkeep(m_axis_tkeep),");
    builder->appendLine(".m_axis_tvalid(m_axis_tvalid),");
    builder->appendLine(".m_axis_tlast(m_axis_tlast),");
    builder->appendLine(".m_axis_tready(m_axis_tready)");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    builder->appendLine("// Map egress port to tdest");
    builder->appendLine("assign m_axis_tdest = pipeline_to_deparser_egress_port;");
    builder->newline();
}

// LEGACY METHODS (kept for compatibility)
void SVProgram::emitTypeDefinitions(CodeBuilder* builder) {
    builder->appendLine("`ifndef TYPES_SVH");
    builder->appendLine("`define TYPES_SVH");
    builder->newline();
    builder->appendLine("// Type definitions (legacy - not used by new pipeline)");
    builder->newline();
    builder->appendLine("`endif");
}

void SVProgram::emitHeaders(CodeBuilder* /*builder*/) {
    // Not used
}

void SVProgram::emitMetadata(CodeBuilder* /*builder*/) {
    // Not used
}

void SVProgram::emitStandardMetadata(CodeBuilder* /*builder*/) {
    // Not used
}

void SVProgram::emitInterfaces(CodeBuilder* builder) {
    builder->appendLine("`ifndef INTERFACES_SVH");
    builder->appendLine("`define INTERFACES_SVH");
    builder->newline();
    builder->appendLine("// Interface definitions (legacy - not used)");
    builder->newline();
    builder->appendLine("`endif");
}

}  // namespace SV
