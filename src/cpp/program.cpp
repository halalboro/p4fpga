#include "common.h"
#include "frontends/p4/coreLibrary.h"
#include "program.h"
#include "parser.h"
#include "table.h"
#include "control.h"
#include "deparser.h"
#include <sstream>

namespace SV {

// Destructor implementation
SVProgram::~SVProgram() {
    delete parser;
    delete ingress;
    delete egress;
    delete deparser;
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
    }
    
    pipelineConfig.stageCount = 4;
    LOG1("Total pipeline stages: " << pipelineConfig.stageCount);
    
    return true;
}


void SVProgram::emit(SVCodeGen& codegen) {
    LOG1("Generating SystemVerilog code");
    
    // Generate type definitions
    emitTypeDefinitions(codegen.getTypesBuilder());
    
    // Generate interface definitions
    emitInterfaces(codegen.getInterfacesBuilder());
    
    // Generate individual modules
    if (parser) parser->emit(codegen);
    if (ingress) ingress->emit(codegen);
    if (egress) egress->emit(codegen);
    if (deparser) deparser->emit(codegen);
    
    auto tablesBuilder = codegen.getTablesBuilder();
    if (ingress) {
        for (auto& p : ingress->getTables()) {
            p.second->emit(tablesBuilder);
        }
    }
    if (egress) {
        for (auto& p : egress->getTables()) {
            p.second->emit(tablesBuilder);
        }
    }
    
    // Generate top-level module
    emitTopModule(codegen);
}

void SVProgram::emitTopModule(SVCodeGen& codegen) {
    auto builder = codegen.getTopBuilder();
    std::stringstream ss;
    
    builder->appendLine("//");
    builder->appendLine("// P4-generated SystemVerilog Top Module");
    builder->appendLine("//");
    builder->newline();
    
    builder->appendLine("`include \"types.svh\"");
    builder->newline();
    
    builder->appendLine("module p4_pipeline #(");
    builder->increaseIndent();
    builder->appendLine("parameter DATA_WIDTH = 512");
    builder->decreaseIndent();
    builder->appendLine(") (");
    builder->increaseIndent();
    
    // Clock and reset
    builder->appendLine("input  logic                      clk,");
    builder->appendLine("input  logic                      rst_n,");
    builder->newline();
    
    // AXI-Stream input
    builder->appendLine("// Packet input interface");
    builder->appendLine("input  logic [DATA_WIDTH-1:0]    s_axis_tdata,");
    builder->appendLine("input  logic [DATA_WIDTH/8-1:0]  s_axis_tkeep,");
    builder->appendLine("input  logic                      s_axis_tvalid,");
    builder->appendLine("output logic                      s_axis_tready,");
    builder->appendLine("input  logic                      s_axis_tlast,");
    builder->newline();
    
    // AXI-Stream output
    builder->appendLine("// Packet output interface");
    builder->appendLine("output logic [DATA_WIDTH-1:0]    m_axis_tdata,");
    builder->appendLine("output logic [DATA_WIDTH/8-1:0]  m_axis_tkeep,");
    builder->appendLine("output logic                      m_axis_tvalid,");
    builder->appendLine("input  logic                      m_axis_tready,");
    builder->appendLine("output logic                      m_axis_tlast");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Internal signals
    builder->appendLine("// Internal pipeline connections");
    builder->appendLine("headers_t   parser_headers;");
    builder->appendLine("metadata_t  parser_metadata;");
    builder->appendLine("logic       parser_valid;");
    builder->appendLine("logic       parser_ready;");
    builder->newline();
    
    builder->appendLine("headers_t   ingress_headers;");
    builder->appendLine("metadata_t  ingress_metadata;");
    builder->appendLine("logic       ingress_valid;");
    builder->appendLine("logic       ingress_ready;");
    builder->newline();
    
    builder->appendLine("headers_t   egress_headers;");
    builder->appendLine("metadata_t  egress_metadata;");
    builder->appendLine("logic       egress_valid;");
    builder->appendLine("logic       egress_ready;");
    builder->newline();
    
    // Module instances
    builder->appendLine("// Parser instance");
    builder->appendLine("parser parser_inst (");
    builder->increaseIndent();
    builder->appendLine(".clk(clk),");
    builder->appendLine(".rst_n(rst_n),");
    builder->appendLine(".s_axis_tdata(s_axis_tdata),");
    builder->appendLine(".s_axis_tkeep(s_axis_tkeep),");
    builder->appendLine(".s_axis_tvalid(s_axis_tvalid),");
    builder->appendLine(".s_axis_tready(s_axis_tready),");
    builder->appendLine(".s_axis_tlast(s_axis_tlast),");
    builder->appendLine(".out_headers(parser_headers),");
    builder->appendLine(".out_metadata(parser_metadata),");
    builder->appendLine(".out_valid(parser_valid),");
    builder->appendLine(".out_ready(parser_ready)");
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Ingress instance
    builder->appendLine("// Ingress pipeline instance");
    builder->appendLine("ingress_pipeline ingress_inst (");
    builder->increaseIndent();
    builder->appendLine(".clk(clk),");
    builder->appendLine(".rst_n(rst_n),");
    builder->appendLine(".in_headers(parser_headers),");
    builder->appendLine(".in_metadata(parser_metadata),");
    builder->appendLine(".in_valid(parser_valid),");
    builder->appendLine(".in_ready(parser_ready),");
    builder->appendLine(".out_headers(ingress_headers),");
    builder->appendLine(".out_metadata(ingress_metadata),");
    builder->appendLine(".out_valid(ingress_valid),");
    builder->appendLine(".out_ready(ingress_ready)");
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Egress instance
    builder->appendLine("// Egress pipeline instance");
    builder->appendLine("egress_pipeline egress_inst (");
    builder->increaseIndent();
    builder->appendLine(".clk(clk),");
    builder->appendLine(".rst_n(rst_n),");
    builder->appendLine(".in_headers(ingress_headers),");
    builder->appendLine(".in_metadata(ingress_metadata),");
    builder->appendLine(".in_valid(ingress_valid),");
    builder->appendLine(".in_ready(ingress_ready),");
    builder->appendLine(".out_headers(egress_headers),");
    builder->appendLine(".out_metadata(egress_metadata),");
    builder->appendLine(".out_valid(egress_valid),");
    builder->appendLine(".out_ready(egress_ready)");
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Deparser instance
    builder->appendLine("// Deparser instance");
    builder->appendLine("deparser deparser_inst (");
    builder->increaseIndent();
    builder->appendLine(".clk(clk),");
    builder->appendLine(".rst_n(rst_n),");
    builder->appendLine(".in_headers(egress_headers),");
    builder->appendLine(".in_metadata(egress_metadata),");
    builder->appendLine(".in_valid(egress_valid),");
    builder->appendLine(".in_ready(egress_ready),");
    builder->appendLine(".m_axis_tdata(m_axis_tdata),");
    builder->appendLine(".m_axis_tkeep(m_axis_tkeep),");
    builder->appendLine(".m_axis_tvalid(m_axis_tvalid),");
    builder->appendLine(".m_axis_tready(m_axis_tready),");
    builder->appendLine(".m_axis_tlast(m_axis_tlast),");
    builder->appendLine(".m_axis_tuser()");  // Not connected
    builder->decreaseIndent();
    builder->appendLine(");");
    
    builder->appendLine("");
    builder->appendLine("endmodule");
}

void SVProgram::emitTypeDefinitions(CodeBuilder* builder) {
    builder->appendLine("`ifndef TYPES_SVH");
    builder->appendLine("`define TYPES_SVH");
    builder->newline();
    
    builder->appendLine("// Header types");
    builder->appendLine("typedef struct packed {");
    builder->increaseIndent();
    builder->appendLine("logic [47:0] dstAddr;");
    builder->appendLine("logic [47:0] srcAddr;");
    builder->appendLine("logic [15:0] etherType;");
    builder->decreaseIndent();
    builder->appendLine("} ethernet_t;");
    builder->newline();
    
    // Add IPv4 header
    builder->appendLine("typedef struct packed {");
    builder->increaseIndent();
    builder->appendLine("logic [3:0]  version;");
    builder->appendLine("logic [3:0]  ihl;");
    builder->appendLine("logic [7:0]  diffserv;");
    builder->appendLine("logic [15:0] totalLen;");
    builder->appendLine("logic [15:0] identification;");
    builder->appendLine("logic [2:0]  flags;");
    builder->appendLine("logic [12:0] fragOffset;");
    builder->appendLine("logic [7:0]  ttl;");
    builder->appendLine("logic [7:0]  protocol;");
    builder->appendLine("logic [15:0] hdrChecksum;");
    builder->appendLine("logic [31:0] srcAddr;");
    builder->appendLine("logic [31:0] dstAddr;");
    builder->decreaseIndent();
    builder->appendLine("} ipv4_t;");
    builder->newline();
    
    builder->appendLine("// Metadata types");
    builder->appendLine("typedef struct packed {");
    builder->increaseIndent();
    builder->appendLine("logic [31:0] ingress_port;");
    builder->appendLine("logic [31:0] egress_port;");
    builder->appendLine("logic        drop_flag;");
    builder->decreaseIndent();
    builder->appendLine("} metadata_t;");
    builder->newline();
    
    builder->appendLine("// Combined headers structure");
    builder->appendLine("typedef struct packed {");
    builder->increaseIndent();
    builder->appendLine("ethernet_t ethernet;");
    builder->appendLine("logic      ethernet_valid;");
    builder->appendLine("ipv4_t     ipv4;");
    builder->appendLine("logic      ipv4_valid;");
    builder->decreaseIndent();
    builder->appendLine("} headers_t;");
    builder->newline();
    
    builder->appendLine("`endif");
}

void SVProgram::emitHeaders(CodeBuilder* /*builder*/) {
    // Implemented in emitTypeDefinitions
}

void SVProgram::emitMetadata(CodeBuilder* /*builder*/) {
    // Implemented in emitTypeDefinitions
}

void SVProgram::emitStandardMetadata(CodeBuilder* /*builder*/) {
    // Implemented in emitTypeDefinitions
}

void SVProgram::emitInterfaces(CodeBuilder* builder) {
    builder->appendLine("`ifndef INTERFACES_SVH");
    builder->appendLine("`define INTERFACES_SVH");
    builder->newline();
    builder->appendLine("// Interface definitions would go here");
    builder->newline();
    builder->appendLine("`endif");
}

}  // namespace SV