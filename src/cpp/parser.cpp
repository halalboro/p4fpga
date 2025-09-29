#include "common.h"
#include "parser.h"
#include "program.h"
#include "lib/log.h"
#include "lib/error.h"
#include <sstream>
#include <algorithm>

namespace SV {

SVParser::SVParser(SVProgram* program,
                   const IR::ParserBlock* block,
                   const P4::TypeMap* typeMap,
                   const P4::ReferenceMap* refMap) :
    program(program), 
    parserBlock(block), 
    typeMap(typeMap), 
    refMap(refMap),
    packet(nullptr),
    headers(nullptr),
    userMetadata(nullptr),
    stdMetadata(nullptr),
    startState(nullptr),
    acceptState(nullptr),
    totalHeaderBits(0) {
}

bool SVParser::build() {
    // Get parameters (as defined in v1model)
    auto pl = parserBlock->container->type->applyParams;
    if (pl->size() != 4) {
        P4::error("Expected parser to have exactly 4 parameters, got %1%", pl->size());
        return false;
    }
    
    // Standard v1model parameter order
    packet = pl->getParameter(0);
    headers = pl->getParameter(1);
    userMetadata = pl->getParameter(2);
    stdMetadata = pl->getParameter(3);
    
    // Extract and analyze parser states
    extractStates();
    analyzeTransitions();
    calculateHeaderOffsets();
    
    return true;
}

void SVParser::extractStates() {
    // Find start state (first state in the list)
    if (parserBlock->container->states.size() > 0) {
        startState = parserBlock->container->states.at(0);
    }
    
    // Process all states
    for (auto state : parserBlock->container->states) {
        auto svState = new SVParseState(state);
        
        // Extract statements (header extraction)
        for (auto stmt : state->components) {
            if (auto extract = stmt->to<IR::MethodCallStatement>()) {
                auto method = extract->methodCall;
                if (method && method->method->toString() == "extract") {
                    // Handle IR::Argument properly
                    if (method->arguments && method->arguments->size() > 0) {
                        auto arg = method->arguments->at(0);
                        if (arg->expression) {
                            svState->extracts.push_back(arg->expression);
                        }
                    }
                }
            }
        }
        
        // Handle transitions
        if (state->selectExpression != nullptr) {
            if (auto select = state->selectExpression->to<IR::SelectExpression>()) {
                // Complex select expression
                for (auto selectCase : select->selectCases) {
                    // Track next state
                    if (auto nextState = selectCase->state->to<IR::PathExpression>()) {
                        svState->transitions[cstring("default")] = nextState->path->name;
                    }
                }
            } else if (auto path = state->selectExpression->to<IR::PathExpression>()) {
                // Simple transition
                svState->transitions[cstring("always")] = path->path->name;
            }
        }
        
        stateMap[state->name] = svState;
        stateList.push_back(svState);
        
        if (state->name == "accept") {
            acceptState = state;
        }
    }
}

void SVParser::analyzeTransitions() {
    // Analyze state transitions and build transition conditions
    for (auto& p : stateMap) {
        auto name = p.first;
        auto state = p.second;
        LOG3("State " << name << " has " << state->transitions.size() << " transitions");
    }
}

void SVParser::calculateHeaderOffsets() {
    // Calculate bit offsets for each header field
    totalHeaderBits = 0;
    
    if (!headers) return;
    
    auto headersType = typeMap->getType(headers);
    
    if (headersType && headersType->is<IR::Type_Struct>()) {
        auto structType = headersType->to<IR::Type_Struct>();
        for (auto field : structType->fields) {
            auto fieldType = typeMap->getType(field);
            int width = fieldType->width_bits();
            headerOffsets[field->name] = totalHeaderBits;
            headerWidths[field->name] = width;
            totalHeaderBits += width;
            LOG3("Header field " << field->name << " at offset " << headerOffsets[field->name] 
                 << " width " << width);
        }
    }
}

void SVParser::emit(SVCodeGen& codegen) {
    auto builder = codegen.getParserBuilder();
    std::stringstream ss;
    
    // Module header
    builder->appendLine("//");
    builder->appendLine("// P4 Parser Module");
    ss << "// Generated from: " << parserBlock->container->name;
    builder->appendLine(ss.str());
    builder->appendLine("//");
    builder->newline();
    
    builder->appendLine("`include \"types.svh\"");
    builder->newline();
    
    // Module declaration
    builder->appendLine("module parser #(");
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
    
    // Output interface
    builder->appendLine("// Parsed headers and metadata output");
    builder->appendLine("output headers_t                  out_headers,");
    builder->appendLine("output metadata_t                 out_metadata,");
    builder->appendLine("output logic                      out_valid,");
    builder->appendLine("input  logic                      out_ready");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Internal signals
    builder->appendLine("// Internal signals");
    builder->appendLine("parser_state_t current_state, next_state;");
    builder->appendLine("logic [DATA_WIDTH-1:0] packet_buffer, packet_buffer_next;");
    builder->appendLine("logic [9:0] extract_offset, extract_offset_next;");
    builder->appendLine("headers_t headers_reg, headers_next;");
    builder->appendLine("metadata_t metadata_reg, metadata_next;");
    builder->appendLine("logic parsing_done, load_packet;");
    builder->newline();
    
    emitStateEnum(builder);
    builder->newline();
    
    emitStateMachine(builder);
    builder->newline();
    emitHeaderExtraction(builder);
    builder->newline();
    emitTransitionLogic(builder);
    builder->newline();
    emitInterface(builder);
    
    builder->appendLine("endmodule");
}

void SVParser::emitStateEnum(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("// Parser states");
    builder->appendLine("typedef enum logic [3:0] {");
    builder->increaseIndent();
    
    int stateNum = 0;
    for (auto state : stateList) {
        std::string upperName = state->name.string();
        std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);
        
        ss.str("");
        ss << "STATE_" << upperName << " = 4'd" << stateNum;
        if (stateNum < stateList.size() - 1) {
            ss << ",";
        }
        builder->appendLine(ss.str());
        stateNum++;
    }
    
    builder->decreaseIndent();
    builder->appendLine("} parser_state_t;");
}

void SVParser::emitStateMachine(CodeBuilder* builder) {
    builder->appendLine("// Main state machine");
    builder->appendLine("always_ff @(posedge clk) begin");
    builder->increaseIndent();
    builder->appendLine("if (!rst_n) begin");
    builder->increaseIndent();
    builder->appendLine("current_state <= STATE_START;");
    builder->appendLine("packet_buffer <= '0;");
    builder->appendLine("extract_offset <= '0;");
    builder->appendLine("headers_reg <= '0;");
    builder->appendLine("metadata_reg <= '0;");
    builder->decreaseIndent();
    builder->appendLine("end else begin");
    builder->increaseIndent();
    builder->appendLine("current_state <= next_state;");
    builder->appendLine("packet_buffer <= packet_buffer_next;");
    builder->appendLine("extract_offset <= extract_offset_next;");
    builder->appendLine("headers_reg <= headers_next;");
    builder->appendLine("metadata_reg <= metadata_next;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
}

void SVParser::emitHeaderExtraction(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("// Header extraction logic");
    builder->appendLine("always_comb begin");
    builder->increaseIndent();
    builder->appendLine("headers_next = headers_reg;");
    builder->appendLine("metadata_next = metadata_reg;");
    builder->appendLine("packet_buffer_next = packet_buffer;");
    builder->appendLine("extract_offset_next = extract_offset;");
    builder->newline();
    
    builder->appendLine("case (current_state)");
    builder->increaseIndent();
    
    // Generate extraction logic for each state
    for (auto state : stateList) {
        std::string upperName = state->name.string();
        std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);
        
        ss.str("");
        ss << "STATE_" << upperName << ": begin";
        builder->appendLine(ss.str());
        builder->increaseIndent();
        
        // Handle extracts in this state
        if (!state->extracts.empty()) {
            builder->appendLine("// Extract headers");
            for (auto extract : state->extracts) {
                if (auto member = extract->to<IR::Member>()) {
                    auto headerName = member->member.toString();
                    if (headerWidths.count(member->member)) {
                        int width = headerWidths[member->member];
                        
                        ss.str("");
                        ss << "headers_next." << headerName << " = packet_buffer[extract_offset +: " << width << "];";
                        builder->appendLine(ss.str());
                        
                        ss.str("");
                        ss << "extract_offset_next = extract_offset + " << width << ";";
                        builder->appendLine(ss.str());
                    }
                }
            }
        }
        
        builder->decreaseIndent();
        builder->appendLine("end");
    }
    
    builder->appendLine("default: begin");
    builder->increaseIndent();
    builder->appendLine("// Stay in current state");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("endcase");
    builder->decreaseIndent();
    builder->appendLine("end");
}

void SVParser::emitTransitionLogic(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("// State transition logic");
    builder->appendLine("always_comb begin");
    builder->increaseIndent();
    builder->appendLine("next_state = current_state;");
    builder->appendLine("parsing_done = 1'b0;");
    builder->appendLine("load_packet = 1'b0;");
    builder->newline();
    
    builder->appendLine("case (current_state)");
    builder->increaseIndent();
    
    for (auto state : stateList) {
        std::string upperName = state->name.string();
        std::transform(upperName.begin(), upperName.end(), upperName.begin(), ::toupper);
        
        ss.str("");
        ss << "STATE_" << upperName << ": begin";
        builder->appendLine(ss.str());
        builder->increaseIndent();
        
        if (state->name == "start") {
            builder->appendLine("if (s_axis_tvalid && s_axis_tready) begin");
            builder->increaseIndent();
            builder->appendLine("load_packet = 1'b1;");

            if (state->transitions.count(cstring("always"))) {
                std::string nextStateName = state->transitions.at(cstring("always")).string();
                std::transform(nextStateName.begin(), nextStateName.end(), nextStateName.begin(), ::toupper);
                
                ss.str("");
                ss << "next_state = STATE_" << nextStateName << ";";
                builder->appendLine(ss.str());
            }
            builder->decreaseIndent();
            builder->appendLine("end");
        } else if (state->name == "accept") {
            builder->appendLine("parsing_done = 1'b1;");
            builder->appendLine("if (out_ready) begin");
            builder->increaseIndent();
            builder->appendLine("next_state = STATE_START;");
            builder->decreaseIndent();
            builder->appendLine("end");
        } else {
            // Regular state transitions
            for (auto& p : state->transitions) {
                auto condition = p.first;
                auto nextStateName = p.second.string();
                
                if (condition == "always") {
                    std::transform(nextStateName.begin(), nextStateName.end(), nextStateName.begin(), ::toupper);
                    
                    ss.str("");
                    ss << "next_state = STATE_" << nextStateName << ";";
                    builder->appendLine(ss.str());
                }
            }
        }
        
        builder->decreaseIndent();
        builder->appendLine("end");
    }
    
    builder->appendLine("default: begin");
    builder->increaseIndent();
    builder->appendLine("next_state = STATE_START;");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("endcase");
    builder->decreaseIndent();
    builder->appendLine("end");
}

void SVParser::emitInterface(CodeBuilder* builder) {
    builder->appendLine("// AXI-Stream interface logic");
    builder->appendLine("assign s_axis_tready = (current_state == STATE_START);");
    builder->appendLine("assign out_valid = parsing_done;");
    builder->appendLine("assign out_headers = headers_reg;");
    builder->appendLine("assign out_metadata = metadata_reg;");
    builder->newline();
    
    builder->appendLine("// Packet loading");
    builder->appendLine("always_ff @(posedge clk) begin");
    builder->increaseIndent();
    builder->appendLine("if (load_packet) begin");
    builder->increaseIndent();
    builder->appendLine("packet_buffer <= s_axis_tdata;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
}

}  // namespace SV