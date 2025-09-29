#include "common.h"
#include "deparser.h"
#include "program.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

bool SVDeparser::build() {
    LOG1("Building deparser");
    
    extractEmitStatements();
    calculateHeaderOrder();
    
    return true;
}

void SVDeparser::extractEmitStatements() {
    // Extract packet.emit() calls from deparser body
    for (auto stmt : controlBlock->container->body->components) {
        if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            auto expr = methodCall->methodCall;
            if (expr->method->toString() == "emit") {
                // Process emit arguments
                for (auto arg : *expr->arguments) {
                    if (auto member = arg->expression->to<IR::Member>()) {
                        auto headerName = member->member;
                        auto type = program->typeMap->getType(arg->expression, true);
                        
                        if (type && type->is<IR::Type_Header>()) {
                            auto headerType = type->to<IR::Type_Header>();
                            auto state = new SVDeparseState(headerName, headerType);
                            state->width = type->width_bits();
                            deparseStates.push_back(state);
                            LOG2("Deparser emits header: " << headerName 
                                 << " width: " << state->width);
                        }
                    }
                }
            }
        }
    }
}

void SVDeparser::calculateHeaderOrder() {
    // Assign order to headers for emission
    int order = 0;
    for (auto state : deparseStates) {
        headerOrder[state->headerName] = order++;
    }
}

void SVDeparser::emit(SVCodeGen& codegen) {
    auto builder = codegen.getDeparserBuilder();
    emitModule(builder);
}

void SVDeparser::emitModule(CodeBuilder* builder) {
    // Module header
    builder->appendLine("//");
    builder->appendLine("// Deparser Module");
    builder->appendLine("//");
    builder->newline();
    
    builder->appendLine("`include \"types.svh\"");
    builder->newline();
    
    // Module declaration
    builder->appendLine("module deparser #(");
    builder->increaseIndent();
    builder->appendLine("parameter DATA_WIDTH = 512");
    builder->decreaseIndent();
    builder->appendLine(") (");
    builder->increaseIndent();
    
    // Clock and reset
    builder->appendLine("input  logic                      clk,");
    builder->appendLine("input  logic                      rst_n,");
    builder->newline();
    
    // Input interface
    builder->appendLine("// Input from egress pipeline");
    builder->appendLine("input  headers_t                  in_headers,");
    builder->appendLine("input  metadata_t                 in_metadata,");
    builder->appendLine("input  logic                      in_valid,");
    builder->appendLine("output logic                      in_ready,");
    builder->newline();
    
    // AXI-Stream output
    builder->appendLine("// Packet output interface");
    builder->appendLine("output logic [DATA_WIDTH-1:0]    m_axis_tdata,");
    builder->appendLine("output logic [DATA_WIDTH/8-1:0]  m_axis_tkeep,");
    builder->appendLine("output logic                      m_axis_tvalid,");
    builder->appendLine("input  logic                      m_axis_tready,");
    builder->appendLine("output logic                      m_axis_tlast,");
    builder->appendLine("output logic [31:0]              m_axis_tuser");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Internal signals
    builder->appendLine("// Deparser state");
    builder->appendLine("typedef enum logic [2:0] {");
    builder->increaseIndent();
    builder->appendLine("IDLE,");
    builder->appendLine("EMIT_HEADERS,");
    builder->appendLine("EMIT_PAYLOAD,");
    builder->appendLine("DONE");
    builder->decreaseIndent();
    builder->appendLine("} deparse_state_t;");
    builder->newline();
    
    builder->appendLine("deparse_state_t state, next_state;");
    builder->newline();
    
    builder->appendLine("// Header assembly buffer");
    builder->appendLine("logic [2047:0] header_buffer;  // Max header size");
    builder->appendLine("logic [10:0] header_len;");
    builder->appendLine("logic [10:0] emit_offset;");
    builder->newline();
    
    // State machine
    builder->appendLine("// State machine");
    builder->appendLine("always_ff @(posedge clk) begin");
    builder->increaseIndent();
    builder->appendLine("if (!rst_n) begin");
    builder->increaseIndent();
    builder->appendLine("state <= IDLE;");
    builder->decreaseIndent();
    builder->appendLine("end else begin");
    builder->increaseIndent();
    builder->appendLine("state <= next_state;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    // State transitions
    builder->appendLine("// Next state logic");
    builder->appendLine("always_comb begin");
    builder->increaseIndent();
    builder->appendLine("next_state = state;");
    builder->appendLine("case (state)");
    builder->increaseIndent();
    
    builder->appendLine("IDLE: begin");
    builder->increaseIndent();
    builder->appendLine("if (in_valid && in_ready) begin");
    builder->increaseIndent();
    builder->appendLine("next_state = EMIT_HEADERS;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->appendLine("EMIT_HEADERS: begin");
    builder->increaseIndent();
    builder->appendLine("if (m_axis_tready && emit_offset >= header_len) begin");
    builder->increaseIndent();
    builder->appendLine("next_state = EMIT_PAYLOAD;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->appendLine("EMIT_PAYLOAD: begin");
    builder->increaseIndent();
    builder->appendLine("if (m_axis_tready && m_axis_tlast) begin");
    builder->increaseIndent();
    builder->appendLine("next_state = DONE;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->appendLine("DONE: begin");
    builder->increaseIndent();
    builder->appendLine("next_state = IDLE;");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("endcase");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    // Packet assembly
    emitPacketAssembly(builder);
    builder->newline();
    
    // Stream output
    emitStreamOutput(builder);
    
    builder->appendLine("endmodule");
}

void SVDeparser::emitPacketAssembly(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("// Header assembly");
    builder->appendLine("always_comb begin");
    builder->increaseIndent();
    builder->appendLine("header_buffer = '0;");
    builder->appendLine("header_len = 0;");
    builder->newline();
    
    // Concatenate headers in order
    int offset = 0;
    for (auto state : deparseStates) {
        ss.str("");
        ss << "if (in_headers." << state->headerName << "_valid) begin";
        builder->appendLine(ss.str());
        builder->increaseIndent();
        
        ss.str("");
        ss << "header_buffer[" << (offset + state->width - 1) << ":" << offset 
           << "] = in_headers." << state->headerName << ";";
        builder->appendLine(ss.str());
        
        ss.str("");
        ss << "header_len = header_len + " << state->width << ";";
        builder->appendLine(ss.str());
        
        builder->decreaseIndent();
        builder->appendLine("end");
        
        offset += state->width;
    }
    
    builder->decreaseIndent();
    builder->appendLine("end");
}

void SVDeparser::emitStreamOutput(CodeBuilder* builder) {
    builder->appendLine("// AXI-Stream output generation");
    builder->appendLine("always_ff @(posedge clk) begin");
    builder->increaseIndent();
    builder->appendLine("if (!rst_n) begin");
    builder->increaseIndent();
    builder->appendLine("m_axis_tdata <= '0;");
    builder->appendLine("m_axis_tkeep <= '0;");
    builder->appendLine("m_axis_tvalid <= 1'b0;");
    builder->appendLine("m_axis_tlast <= 1'b0;");
    builder->appendLine("emit_offset <= '0;");
    builder->decreaseIndent();
    builder->appendLine("end else begin");
    builder->increaseIndent();
    
    builder->appendLine("case (state)");
    builder->increaseIndent();
    
    builder->appendLine("EMIT_HEADERS: begin");
    builder->increaseIndent();
    builder->appendLine("if (m_axis_tready || !m_axis_tvalid) begin");
    builder->increaseIndent();
    builder->appendLine("m_axis_tdata <= header_buffer[emit_offset +: DATA_WIDTH];");
    builder->appendLine("m_axis_tkeep <= '1;  // All bytes valid");
    builder->appendLine("m_axis_tvalid <= 1'b1;");
    builder->appendLine("emit_offset <= emit_offset + DATA_WIDTH;");
    builder->appendLine("if (emit_offset + DATA_WIDTH >= header_len) begin");
    builder->increaseIndent();
    builder->appendLine("m_axis_tlast <= 1'b1;  // Simplified: headers only");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->appendLine("default: begin");
    builder->increaseIndent();
    builder->appendLine("if (m_axis_tready) begin");
    builder->increaseIndent();
    builder->appendLine("m_axis_tvalid <= 1'b0;");
    builder->appendLine("m_axis_tlast <= 1'b0;");
    builder->appendLine("emit_offset <= '0;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("endcase");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    builder->appendLine("// Backpressure");
    builder->appendLine("assign in_ready = (state == IDLE);");
}

}  // namespace SV