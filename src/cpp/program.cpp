#include "common.h"
#include "frontends/p4/coreLibrary.h"
#include "program.h"
#include "parser.h"
#include "control.h"
#include "deparser.h"
#include <sstream>

namespace SV {

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
    
    // For v1model, we need to extract the parser, ingress, egress, and deparser blocks
    // These are passed as constructor parameters to the main package
    auto constructorParams = pack->getConstructorParameters();
    
    if (!constructorParams || constructorParams->size() < 6) {
        P4::error("Expected v1model package with 6 parameters");
        return false;
    }
    
    // v1model parameter order:
    // 0: Parser
    // 1: VerifyChecksum
    // 2: Ingress
    // 3: Egress
    // 4: ComputeChecksum
    // 5: Deparser
    
    // Extract parser (parameter 0)
    if (auto parserParam = constructorParams->getParameter(0)) {
        if (auto pb = parserParam->to<IR::ParserBlock>()) {
            parser = new SVParser(this, pb, typeMap, refMap);
            if (!parser->build()) {
                P4::error("Failed to build parser");
                return false;
            }
            LOG1("Built parser");
        }
    }
    
    // Extract ingress control (parameter 2)
    if (auto ingressParam = constructorParams->getParameter(2)) {
        if (auto cb = ingressParam->to<IR::ControlBlock>()) {
            ingress = new SVControl(this, cb, typeMap, refMap);
            ingress->setIsIngress(true);
            if (!ingress->build()) {
                P4::error("Failed to build ingress control");
                return false;
            }
            LOG1("Built ingress control");
        }
    }
    
    // Extract egress control (parameter 3)
    if (auto egressParam = constructorParams->getParameter(3)) {
        if (auto cb = egressParam->to<IR::ControlBlock>()) {
            egress = new SVControl(this, cb, typeMap, refMap);
            egress->setIsIngress(false);
            if (!egress->build()) {
                P4::error("Failed to build egress control");
                return false;
            }
            LOG1("Built egress control");
        }
    }
    
    // Extract deparser (parameter 5)
    if (auto deparserParam = constructorParams->getParameter(5)) {
        if (auto cb = deparserParam->to<IR::ControlBlock>()) {
            deparser = new SVDeparser(this, cb);
            if (!deparser->build()) {
                P4::error("Failed to build deparser");
                return false;
            }
            LOG1("Built deparser");
        }
    }
    
    if (!parser || !ingress || !egress || !deparser) {
        P4::error("Could not extract all required pipeline components");
        return false;
    }
    
    pipelineConfig.stageCount = 1 + // parser
                                ingress->getStageCount() + 
                                egress->getStageCount() + 
                                1; // deparser
    
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
    
    // Add similar instances for egress and deparser...
    
    builder->appendLine("endmodule");
}

void SVProgram::emitTypeDefinitions(CodeBuilder* builder) {
    builder->appendLine("`ifndef TYPES_SVH");
    builder->appendLine("`define TYPES_SVH");
    builder->newline();
    
    // TODO: Extract actual types from the P4 program
    builder->appendLine("// Header types");
    builder->appendLine("typedef struct packed {");
    builder->increaseIndent();
    builder->appendLine("logic [47:0] dstAddr;");
    builder->appendLine("logic [47:0] srcAddr;");
    builder->appendLine("logic [15:0] etherType;");
    builder->decreaseIndent();
    builder->appendLine("} ethernet_t;");
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
    builder->decreaseIndent();
    builder->appendLine("} headers_t;");
    builder->newline();
    
    builder->appendLine("`endif");
}

void SVProgram::emitHeaders(CodeBuilder* builder) {
    // Implemented in emitTypeDefinitions
}

void SVProgram::emitMetadata(CodeBuilder* builder) {
    // Implemented in emitTypeDefinitions
}

void SVProgram::emitStandardMetadata(CodeBuilder* builder) {
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