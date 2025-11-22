#include "common.h"
#include "bsvprogram.h"
#include "parser.h"
#include "action.h"
#include <cstdarg>
#include <cstdio>
#include <sstream>
#include <fstream>
#include <iomanip>

namespace SV {

// ==========================================
// Private Helper Functions (Anonymous Namespace)
// ==========================================

namespace {

/**
 * Format custom header field declarations with consistent style
 * @param info Custom header information
 * @param portType Port direction/type (e.g., "output reg", "input wire")
 * @param indent Indentation string (e.g., "    ")
 * @param prefix Optional prefix for signal names (e.g., "pipeline_")
 * @return Formatted field declarations
 */
std::string formatCustomHeaderFields(
    const SVParser::CustomHeaderInfo& info,
    const std::string& portType,
    const std::string& indent,
    const std::string& prefix = ""
) {
    std::stringstream ss;
    
    // Iterate over map
    for (const auto& fieldPair : info.fields) {
        const std::string fieldName = fieldPair.first.string();
        const SVParser::CustomHeaderField& field = fieldPair.second;
        
        ss << indent << portType << " [" << (field.width - 1) << ":0]";
        int padding = 20 - std::to_string(field.width - 1).length();
        ss << std::string(padding, ' ');
        ss << prefix << info.name << "_" << fieldName << ",\n";
    }
    
    // Generate valid signal
    ss << indent;
    if (portType.find("output") != std::string::npos) {
        ss << "output reg                       ";
    } else if (portType.find("input") != std::string::npos) {
        ss << "input  wire                      ";
    } else {
        ss << "logic                        ";
    }
    ss << prefix << info.name << "_valid";
    
    return ss.str();
}

}   // anonymous namespace

// ==========================================
// Utility Methods
// ==========================================

void SVCodeGen::replaceAll(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}

void SVCodeGen::writeToFile(const std::string& content, const std::string& filepath) {
    std::ofstream outFile(filepath);
    if (!outFile.is_open()) {
        std::cerr << "Error: Cannot write to file: " << filepath << std::endl;
        return;
    }
    outFile << content;
    outFile.close();
}

std::string SVCodeGen::getTemplateDir() {
    return "../src/sv/hdl";
}

std::string SVCodeGen::readTemplate(const std::string& templateName) {
    std::string templatePath = getTemplateDir() + "/" + templateName;
    std::ifstream inFile(templatePath);
    
    if (!inFile.is_open()) {
        std::cerr << "Error: Cannot read template: " << templatePath << std::endl;
        return "";
    }
    
    std::string content((std::istreambuf_iterator<char>(inFile)),
                        std::istreambuf_iterator<char>());
    inFile.close();
    
    return content;
}

// ==========================================
// Parser-Specific Generators 
// ==========================================

std::string SVCodeGen::generateCustomHeaderPorts(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    ss << "    \n";
    ss << "    // ==========================================\n";
    ss << "    // Custom Header Outputs\n";
    ss << "    // ==========================================\n";
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        ss << "    // Custom header: " << info.name;
        
        if (info.isStack) {
            ss << " [stack, max " << info.maxStackSize << "]\n";
            
            // Generate array signals for each field
            std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
            for (const auto& fieldPair : info.fields) {
                sortedFields.push_back(fieldPair);
            }
            
            for (const auto& fieldPair : sortedFields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "    output reg [" << (field.width - 1) << ":0]"
                   << std::string(20 - std::to_string(field.width - 1).length(), ' ')
                   << info.name << "_" << fieldName 
                   << " [0:" << (info.maxStackSize - 1) << "],\n";
            }
            
            // Valid array
            ss << "    output reg                       "
               << info.name << "_valid [0:" << (info.maxStackSize - 1) << "],\n";
            
        } else {
            ss << "\n";
            
            std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
            for (const auto& fieldPair : info.fields) {
                sortedFields.push_back(fieldPair);
            }
            
            for (const auto& fieldPair : sortedFields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "    output reg [" << (field.width - 1) << ":0]";
                int padding = 20 - std::to_string(field.width - 1).length();
                ss << std::string(padding, ' ');
                ss << info.name << "_" << fieldName << ",\n";
            }
            
            ss << "    output reg                       ";
            ss << info.name << "_valid,\n";
        }
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderLocalparams(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        ss << "    localparam PARSE_" << info.name 
           << " = PARSER_CONFIG[" << info.parserBit << "];\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomStateDefinition(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    if (parser->hasHeaderStacks()) {
        // Need extra states for stack parsing
        ss << "    localparam STATE_CUSTOM       = 4'd2;\n";
        ss << "    localparam STATE_CUSTOM_LOOP  = 4'd3;\n";  
        ss << "    localparam STATE_CUSTOM_CHECK = 4'd4;\n";  
    } else {
        // Just one custom state for simple headers
        ss << "    localparam STATE_CUSTOM     = 4'd2;\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generateStateValue(const SVParser* parser, const std::string& stateName) {
    if (!parser) return "4'd0";
    
    const auto& customHeaders = parser->getCustomHeaders();
    bool hasCustom = !customHeaders.empty();
    bool hasStacks = parser->hasHeaderStacks();
    
    int offset = 0;
    if (hasCustom) offset += 1;  // STATE_CUSTOM
    if (hasStacks) offset += 2;  // STATE_CUSTOM_LOOP, STATE_CUSTOM_CHECK
    
    if (stateName == "L3") {
        return "4'd" + std::to_string(2 + offset);
    } else if (stateName == "L4") {
        return "4'd" + std::to_string(3 + offset);
    } else if (stateName == "PAYLOAD") {
        return "4'd" + std::to_string(4 + offset);
    } else if (stateName == "DONE") {
        return "4'd" + std::to_string(5 + offset);
    }
    
    return "4'd0";
}

std::string SVCodeGen::generateCustomHeaderEthertypes(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        ss << "    localparam ETHERTYPE_" << info.name 
           << " = 16'h" << std::hex << std::setw(4) << std::setfill('0')
           << (0x1200 + info.parserBit) << ";\n" << std::dec;
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderReset(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        
        if (info.isStack) {
            // Reset all array elements
            ss << "            for (int i = 0; i < " << info.maxStackSize << "; i++) begin\n";
            ss << "                " << info.name << "_valid[i] <= 1'b0;\n";
            ss << "            end\n";
        } else {
            ss << "            " << info.name << "_valid <= 1'b0;\n";
        }
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderClear(const SVParser* parser) {
    return generateCustomHeaderReset(parser);
}

std::string SVCodeGen::generateCustomHeaderEthertypeCheck(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    ss << "                        // Check for custom headers\n";
    
    bool first = true;
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        
        if (first) {
            ss << "                        if ((eth_ether_type == ETHERTYPE_" << info.name;
            first = false;
        } else {
            ss << "                        else if ((eth_ether_type == ETHERTYPE_" << info.name;
        }
        
        ss << " || (vlan_valid && vlan_ether_type == ETHERTYPE_" << info.name << "))";
        ss << " && PARSE_" << info.name << ") begin\n";
        ss << "                            parse_state <= STATE_CUSTOM;\n";
        ss << "                        end ";
    }
    
    if (!customHeaders.empty()) {
        ss << "else begin\n";
        ss << "                            parse_state <= STATE_L3;\n";
        ss << "                        end\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderState(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    bool hasStacks = parser->hasHeaderStacks();
    
    if (hasStacks) {
        // ==========================================
        // MULTI-STATE STACK PARSING
        // ==========================================
        ss << "                // ==========================================\n";
        ss << "                // STATE_CUSTOM - Initialize stack parsing\n";
        ss << "                // ==========================================\n";
        ss << "                STATE_CUSTOM: begin\n";
        
        for (const auto& ch : customHeaders) {
            const auto& info = ch.second;
            
            if (info.isStack) {
                ss << "                    if (PARSE_" << info.name << ") begin\n";
                ss << "                        " << info.name << "_stack_idx <= 0;\n";
                ss << "                        " << info.name << "_parsing <= 1'b1;\n";
                ss << "                        parse_state <= STATE_CUSTOM_LOOP;\n";
                ss << "                    end else begin\n";
                ss << "                        parse_state <= STATE_L3;\n";
                ss << "                    end\n";
            } else {
                // Simple header - parse in one cycle
                ss << "                    if (PARSE_" << info.name << ") begin\n";
                
                std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
                for (const auto& fieldPair : info.fields) {
                    sortedFields.push_back(fieldPair);
                }
                std::sort(sortedFields.begin(), sortedFields.end(),
                    [](const auto& a, const auto& b) {
                        return a.second.offset < b.second.offset;
                    });
                
                for (const auto& fieldPair : sortedFields) {
                    const std::string fieldName = fieldPair.first.string();
                    const SVParser::CustomHeaderField& field = fieldPair.second;
                    
                    ss << "                        " << info.name << "_" << fieldName;
                    ss << " <= packet_buffer[byte_offset*8 + " << field.offset;
                    ss << " +: " << field.width << "];\n";
                }
                
                ss << "                        " << info.name << "_valid <= 1'b1;\n";
                ss << "                        byte_offset <= byte_offset + 11'd" 
                   << (info.totalWidth / 8) << ";\n";
                ss << "                        parse_state <= STATE_L3;\n";
                ss << "                    end\n";
            }
        }
        
        ss << "                end\n\n";
        
        // ==========================================
        // STATE_CUSTOM_LOOP - Extract one stack element per cycle
        // ==========================================
        ss << "                // ==========================================\n";
        ss << "                // STATE_CUSTOM_LOOP - Parse stack elements\n";
        ss << "                // ==========================================\n";
        ss << "                STATE_CUSTOM_LOOP: begin\n";
        
        for (const auto& ch : customHeaders) {
            const auto& info = ch.second;
            if (!info.isStack) continue;
            
            ss << "                    if (" << info.name << "_parsing) begin\n";
            ss << "                        // Extract element at stack_idx\n";
            
            std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
            for (const auto& fieldPair : info.fields) {
                sortedFields.push_back(fieldPair);
            }
            std::sort(sortedFields.begin(), sortedFields.end(),
                [](const auto& a, const auto& b) {
                    return a.second.offset < b.second.offset;
                });
            
            for (const auto& fieldPair : sortedFields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "                        " << info.name << "_" << fieldName 
                   << "[" << info.name << "_stack_idx] <= packet_buffer[byte_offset*8 + " 
                   << field.offset << " +: " << field.width << "];\n";
            }
            
            ss << "                        " << info.name << "_valid[" 
               << info.name << "_stack_idx] <= 1'b1;\n";
            ss << "                        byte_offset <= byte_offset + 11'd" 
               << (info.totalWidth / 8) << ";\n";
            ss << "                        " << info.name << "_stack_idx <= " 
               << info.name << "_stack_idx + 1;\n";
            ss << "                        parse_state <= STATE_CUSTOM_CHECK;\n";
            ss << "                    end\n";
        }
        
        ss << "                end\n\n";
        
        // ==========================================
        // STATE_CUSTOM_CHECK - Check termination
        // ==========================================
        ss << "                // ==========================================\n";
        ss << "                // STATE_CUSTOM_CHECK - Check termination\n";
        ss << "                // ==========================================\n";
        ss << "                STATE_CUSTOM_CHECK: begin\n";
        
        for (const auto& ch : customHeaders) {
            const auto& info = ch.second;
            if (!info.isStack) continue;
            
            ss << "                    if (" << info.name << "_parsing) begin\n";
            
            if (info.hasBosField) {
                ss << "                        // Check BOS bit\n";
                ss << "                        if (" << info.name << "_" << info.bosFieldName 
                   << "[" << info.name << "_stack_idx - 1] == 1'b1) begin\n";
                ss << "                            " << info.name << "_parsing <= 1'b0;\n";
                ss << "                            parse_state <= STATE_L3;\n";
                ss << "                        end\n";
            }
            
            ss << "                        else if (" << info.name << "_stack_idx >= " 
               << info.maxStackSize << ") begin\n";
            ss << "                            " << info.name << "_parsing <= 1'b0;\n";
            ss << "                            parse_state <= STATE_L3;\n";
            ss << "                        end\n";
            ss << "                        else begin\n";
            ss << "                            parse_state <= STATE_CUSTOM_LOOP;\n";
            ss << "                        end\n";
            ss << "                    end\n";
        }
        
        ss << "                end\n";
        
    } else {
        // ==========================================
        // SIMPLE CUSTOM HEADER (no stacks)
        // ==========================================
        ss << "                // ==========================================\n";
        ss << "                // STATE_CUSTOM - Parse custom headers\n";
        ss << "                // ==========================================\n";
        ss << "                STATE_CUSTOM: begin\n";
        
        for (const auto& ch : customHeaders) {
            const auto& info = ch.second;
            
            ss << "                    if (PARSE_" << info.name << ") begin\n";
            
            std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
            for (const auto& fieldPair : info.fields) {
                sortedFields.push_back(fieldPair);
            }
            std::sort(sortedFields.begin(), sortedFields.end(),
                [](const auto& a, const auto& b) {
                    return a.second.offset < b.second.offset;
                });
            
            for (const auto& fieldPair : sortedFields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "                        " << info.name << "_" << fieldName;
                ss << " <= packet_buffer[byte_offset*8 + " << field.offset;
                ss << " +: " << field.width << "];\n";
            }
            
            ss << "                        " << info.name << "_valid <= 1'b1;\n";
            ss << "                        byte_offset <= byte_offset + 11'd" 
               << (info.totalWidth / 8) << ";\n";
            ss << "                    end\n\n";
        }
        
        ss << "                    parse_state <= STATE_L3;\n";
        ss << "                end\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderInternalSignals(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (!parser->hasHeaderStacks()) return "";
    
    std::stringstream ss;
    ss << "    // ==========================================\n";
    ss << "    // Stack Parsing State\n";
    ss << "    // ==========================================\n";
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        if (!info.isStack) continue;
        
        int idxBits = 1;
        int maxIdx = info.maxStackSize;
        while (maxIdx > (1 << idxBits)) idxBits++;
        
        ss << "    reg [" << (idxBits - 1) << ":0]            "
           << info.name << "_stack_idx;\n";
        ss << "    reg                        "
           << info.name << "_parsing;\n";
    }
    
    ss << "\n";
    
    return ss.str();
}

// ==========================================
// Deparser-Specific Generators (PHASE 1.9)
// ==========================================

std::string SVCodeGen::generateCustomHeaderInputs(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    ss << "    \n";
    ss << "    // ==========================================\n";
    ss << "    // Custom Header Inputs\n";
    ss << "    // ==========================================\n";
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        ss << "    // Custom header: " << info.name;
        
        if (info.isStack) {
            ss << " [stack, max " << info.maxStackSize << "]\n";
            
            std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
            for (const auto& fieldPair : info.fields) {
                sortedFields.push_back(fieldPair);
            }
            
            for (const auto& fieldPair : sortedFields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "    input  wire [" << (field.width - 1) << ":0]"
                   << std::string(20 - std::to_string(field.width - 1).length(), ' ')
                   << info.name << "_" << fieldName 
                   << " [0:" << (info.maxStackSize - 1) << "],\n";
            }
            
            ss << "    input  wire                      "
               << info.name << "_valid [0:" << (info.maxStackSize - 1) << "],\n";
            
        } else {
            ss << "\n";
            ss << formatCustomHeaderFields(info, "input  wire", "    ") << ",\n";
        }
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderEmit(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        int deparserBit = 10 + (info.parserBit - 7);
        
        ss << "    localparam EMIT_" << info.name 
           << " = DEPARSER_CONFIG[" << deparserBit << "];\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderBuildLogic(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        
        if (info.isStack) {
            // ==========================================
            // POINTER-BASED STACK EMISSION
            // ==========================================
            ss << "                    // Build " << info.name << " stack (" 
               << (info.totalWidth / 8) << " bytes per element)\n";
            ss << "                    if (EMIT_" << info.name << ") begin\n";
            ss << "                        // Loop from stack_ptr to end (skip popped elements)\n";
            ss << "                        for (int stack_i = " << info.name << "_ptr; stack_i < " 
               << info.maxStackSize << "; stack_i++) begin\n";
            ss << "                            if (" << info.name << "_valid[stack_i]) begin\n";
            
            // Sort fields by offset
            std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
            for (const auto& fieldPair : info.fields) {
                sortedFields.push_back(fieldPair);
            }
            std::sort(sortedFields.begin(), sortedFields.end(),
                [](const auto& a, const auto& b) {
                    return a.second.offset < b.second.offset;
                });
            
            // Emit each field from the stack element
            for (const auto& fieldPair : sortedFields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "                                header_buffer[byte_offset*8 + " << field.offset;  
                ss << " +: " << field.width << "] <= " << info.name << "_" << fieldName 
                   << "[stack_i];\n";
            }
            
            ss << "                                byte_offset <= byte_offset + 11'd" 
               << (info.totalWidth / 8) << ";\n";
            ss << "                            end\n";
            ss << "                        end\n";
            ss << "                    end\n\n";
            
        } else {
            // ==========================================
            // SINGLE HEADER EMISSION (unchanged)
            // ==========================================
            ss << "                    // Build " << info.name << " header (" 
               << (info.totalWidth / 8) << " bytes)\n";
            ss << "                    if (EMIT_" << info.name 
               << " && " << info.name << "_valid) begin\n";
            
            std::vector<std::pair<cstring, SVParser::CustomHeaderField>> sortedFields;
            for (const auto& fieldPair : info.fields) {
                sortedFields.push_back(fieldPair);
            }
            std::sort(sortedFields.begin(), sortedFields.end(),
                [](const auto& a, const auto& b) {
                    return a.second.offset < b.second.offset;
                });
            
            for (const auto& fieldPair : sortedFields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "                        header_buffer[byte_offset*8 + " << field.offset;  
                ss << " +: " << field.width << "] <= " << info.name << "_" << fieldName << ";\n";
            }
            
            ss << "                        byte_offset <= byte_offset + 11'd" 
               << (info.totalWidth / 8) << ";\n";
            ss << "                    end\n\n";
        }
    }
    
    return ss.str();
}

// ==========================================
// Generate Stack Pointer Inputs for Deparser
// ==========================================
std::string SVCodeGen::generateDeparserStackPointerInputs(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    bool hasStacks = false;
    
    // Check if there are any stack headers
    for (const auto& ch : customHeaders) {
        if (ch.second.isStack) {
            hasStacks = true;
            break;
        }
    }
    
    if (!hasStacks) return "";
    
    ss << "    // ==========================================\n";
    ss << "    // Stack Pointers (for skipping popped elements)\n";
    ss << "    // ==========================================\n";
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        if (!info.isStack) continue;
        
        // Calculate pointer width
        int ptrBits = 1;
        int maxIdx = info.maxStackSize;
        while (maxIdx > (1 << ptrBits)) ptrBits++;
        
        ss << "    input  wire [" << (ptrBits - 1) << ":0] "
           << info.name << "_ptr,\n";
    }
    
    ss << "\n";
    return ss.str();
}

// ==========================================
// Top-Specific Generators 
// ==========================================

std::string SVCodeGen::generateCustomHeaderSignals(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    ss << "\n// Custom header signals (Parser → Pipeline)\n";
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
        
        if (headerInfo.isStack) {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "logic [" << (field.width - 1) << ":0] "
                   << headerName << "_" << fieldName 
                   << " [0:" << (headerInfo.maxStackSize - 1) << "];\n";
            }
            ss << "logic " << headerName << "_valid [0:" << (headerInfo.maxStackSize - 1) << "];\n";
        } else {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "logic [" << (field.width - 1) << ":0] "
                   << headerName << "_" << fieldName << ";\n";
            }
            ss << "logic " << headerName << "_valid;\n";
        }
        ss << "\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generateCustomHeaderPipelineSignals(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    ss << "\n// Custom header signals (Pipeline → Deparser)\n";
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
        
        if (headerInfo.isStack) {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "logic [" << (field.width - 1) << ":0] "
                   << "pipeline_" << headerName << "_" << fieldName 
                   << " [0:" << (headerInfo.maxStackSize - 1) << "];\n";
            }
            ss << "logic pipeline_" << headerName << "_valid [0:" 
               << (headerInfo.maxStackSize - 1) << "];\n";
        } else {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                ss << "logic [" << (field.width - 1) << ":0] "
                   << "pipeline_" << headerName << "_" << fieldName << ";\n";
            }
            ss << "logic pipeline_" << headerName << "_valid;\n";
        }
        ss << "\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generateParserCustomHeaderPorts(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
        
        if (headerInfo.isStack) {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                
                ss << "    ." << headerName << "_" << fieldName 
                   << "(" << headerName << "_" << fieldName << "),\n";
            }
            ss << "    ." << headerName << "_valid(" << headerName << "_valid),\n";
        } else {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                
                ss << "    ." << headerName << "_" << fieldName 
                   << "(" << headerName << "_" << fieldName << "),\n";
            }
            ss << "    ." << headerName << "_valid(" << headerName << "_valid),\n";
        }
    }
    
    return ss.str();
}

std::string SVCodeGen::generatePipelineCustomHeaderInputs(const SVParser* parser) {
    return generateParserCustomHeaderPorts(parser);
}

std::string SVCodeGen::generatePipelineCustomHeaderOutputs(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
        
        if (headerInfo.isStack) {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                
                ss << "    .out_" << headerName << "_" << fieldName 
                   << "(pipeline_" << headerName << "_" << fieldName << "),\n";
            }
            ss << "    .out_" << headerName << "_valid(pipeline_" 
               << headerName << "_valid),\n";
        } else {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                
                ss << "    .out_" << headerName << "_" << fieldName 
                   << "(pipeline_" << headerName << "_" << fieldName << "),\n";
            }
            ss << "    .out_" << headerName << "_valid(pipeline_" 
               << headerName << "_valid),\n";
        }
    }
    
    return ss.str();
}

std::string SVCodeGen::generateDeparserCustomHeaderPorts(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
        
        if (headerInfo.isStack) {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                
                ss << "    .pipeline_" << headerName << "_" << fieldName 
                   << "(pipeline_" << headerName << "_" << fieldName << "),\n";
            }
            ss << "    .pipeline_" << headerName << "_valid(pipeline_" 
               << headerName << "_valid),\n";
        } else {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                
                ss << "    .pipeline_" << headerName << "_" << fieldName 
                   << "(pipeline_" << headerName << "_" << fieldName << "),\n";
            }
            ss << "    .pipeline_" << headerName << "_valid(pipeline_" 
               << headerName << "_valid),\n";
        }
    }
    
    return ss.str();
}

// ==========================================
// Template Processing Methods
// ==========================================

void SVCodeGen::processParserTemplate(const SVParser* parser, const std::string& outputPath) {
    std::string content = readTemplate("parser.sv.in");
    if (content.empty()) {
        std::cerr << "Error: Failed to read parser template" << std::endl;
        return;
    }
    
    replaceAll(content, "{{CUSTOM_HEADER_PORTS}}", 
               generateCustomHeaderPorts(parser));
    replaceAll(content, "{{CUSTOM_HEADER_LOCALPARAMS}}", 
               generateCustomHeaderLocalparams(parser));
    replaceAll(content, "{{CUSTOM_STATE_DEFINITION}}", 
               generateCustomStateDefinition(parser));
    replaceAll(content, "{{L3_STATE_VALUE}}", 
               generateStateValue(parser, "L3"));
    replaceAll(content, "{{L4_STATE_VALUE}}", 
               generateStateValue(parser, "L4"));
    replaceAll(content, "{{PAYLOAD_STATE_VALUE}}", 
               generateStateValue(parser, "PAYLOAD"));
    replaceAll(content, "{{DONE_STATE_VALUE}}", 
               generateStateValue(parser, "DONE"));
    replaceAll(content, "{{CUSTOM_HEADER_ETHERTYPES}}", 
               generateCustomHeaderEthertypes(parser));
    replaceAll(content, "{{CUSTOM_HEADER_RESET}}", 
               generateCustomHeaderReset(parser));
    replaceAll(content, "{{CUSTOM_HEADER_CLEAR}}", 
               generateCustomHeaderClear(parser));
    replaceAll(content, "{{CUSTOM_HEADER_ETHERTYPE_CHECK}}", 
               generateCustomHeaderEthertypeCheck(parser));
    replaceAll(content, "{{CUSTOM_HEADER_STATE}}", 
               generateCustomHeaderState(parser));
    replaceAll(content, "{{CUSTOM_HEADER_INTERNAL_SIGNALS}}", 
               generateCustomHeaderInternalSignals(parser));
    
    writeToFile(content, outputPath);
}

void SVCodeGen::processDeparserTemplate(const SVParser* parser, const std::string& outputPath) {
    std::string content = readTemplate("deparser.sv.in");
    if (content.empty()) {
        std::cerr << "Error: Failed to read deparser template" << std::endl;
        return;
    }
    
    replaceAll(content, "{{STACK_POINTER_INPUTS}}", 
               generateDeparserStackPointerInputs(parser));  
    replaceAll(content, "{{CUSTOM_HEADER_INPUTS}}", 
               generateCustomHeaderInputs(parser));
    replaceAll(content, "{{CUSTOM_HEADER_EMIT_PARAMS}}", 
               generateCustomHeaderEmit(parser));
    replaceAll(content, "{{CUSTOM_HEADER_BUILD}}", 
               generateCustomHeaderBuildLogic(parser));
    
    writeToFile(content, outputPath);
}

void SVCodeGen::processTopTemplate(const SVParser* parser, const std::string& outputPath) 
{
    std::string content = readTemplate("vfpga_top.svh.in");
    if (content.empty()) {
        std::cerr << "Error: Failed to read vfpga_top template" << std::endl;
        return;
    }
    
    replaceAll(content, "{{CUSTOM_HEADER_SIGNALS}}", 
               generateCustomHeaderSignals(parser));
    replaceAll(content, "{{CUSTOM_HEADER_PIPELINE_SIGNALS}}", 
               generateCustomHeaderPipelineSignals(parser));
    replaceAll(content, "{{PARSER_CUSTOM_HEADER_PORTS}}", 
               generateParserCustomHeaderPorts(parser));
    replaceAll(content, "{{PIPELINE_CUSTOM_HEADER_INPUTS}}", 
               generatePipelineCustomHeaderInputs(parser));
    replaceAll(content, "{{PIPELINE_CUSTOM_HEADER_OUTPUTS}}", 
               generatePipelineCustomHeaderOutputs(parser));
    replaceAll(content, "{{DEPARSER_CUSTOM_HEADER_PORTS}}", 
               generateDeparserCustomHeaderPorts(parser));
    
    writeToFile(content, outputPath);
}

// ==========================================
// Stack Pointer Generation
// ==========================================

// Generate stack pointer register declarations
std::string SVCodeGen::generateStackPointerSignals(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    // Always generate pointers for stack headers
    bool hasStacks = false;
    for (const auto& ch : customHeaders) {
        if (ch.second.isStack) {
            hasStacks = true;
            break;
        }
    }
    
    if (!hasStacks) return "";
    
    std::stringstream ss;
    ss << "    // ==========================================\n";
    ss << "    // Stack Pointers\n";
    ss << "    // ==========================================\n";
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        if (!info.isStack) continue;
        
        // Calculate pointer width (log2 of max size)
        int ptrBits = 1;
        int maxIdx = info.maxStackSize;
        while (maxIdx > (1 << ptrBits)) ptrBits++;
        
        ss << "    reg [" << (ptrBits - 1) << ":0] " << info.name << "_ptr;\n";
    }
    
    ss << "\n";
    return ss.str();
}

// Generate stack pointer update logic 
std::string SVCodeGen::generateStackPointerLogic(
    const std::map<cstring, SV::SVAction*>& actions,
    const std::map<int, cstring>& actionIdMap
) {
    std::stringstream ss;
    
    // Generate logic for each action ID
    for (const auto& idPair : actionIdMap) {
        int actionId = idPair.first;
        cstring actionName = idPair.second;
        
        auto it = actions.find(actionName);
        if (it == actions.end()) continue;
        
        const SV::SVAction* action = it->second;
        if (!action->usesStackOperations()) continue;
        
        const auto& stackOps = action->getStackOperations();
        
        ss << "            " << actionId << ": begin  // " << actionName << "\n";
        
        for (const auto& op : stackOps) {
            const std::string stackName = op.stackName.string();
            
            if (op.type == SV::StackOperation::OpType::POP_FRONT) {
                ss << "                // pop_front(" << op.count << ") on " << stackName << "\n";
                ss << "                " << stackName << "_ptr <= " << stackName << "_ptr + " 
                   << op.count << ";\n";
            } else if (op.type == SV::StackOperation::OpType::PUSH_FRONT) {
                ss << "                // push_front(" << op.count << ") on " << stackName << "\n";
                ss << "                if (" << stackName << "_ptr >= " << op.count << ") begin\n";
                ss << "                    " << stackName << "_ptr <= " << stackName << "_ptr - " 
                   << op.count << ";\n";
                ss << "                end\n";
            }
        }
        
        ss << "            end\n";
    }
    
    return ss.str();
}



}  // namespace SV