#include "common.h"
#include "bsvprogram.h"
#include "parser.h"
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
    
    // FIXED: Iterate over map instead of vector
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

/**
 * Format custom header port connections for instantiation
 * @param info Custom header information
 * @param signalPrefix Prefix for the signal being connected (e.g., "pipeline_")
 * @param portPrefix Prefix for the port name (e.g., "out_")
 * @param indent Indentation string
 * @return Formatted port connections
 */
std::string formatCustomHeaderPortConnections(
    const SVParser::CustomHeaderInfo& info,
    const std::string& signalPrefix,
    const std::string& portPrefix,
    const std::string& indent
) {
    std::stringstream ss;
    
    // FIXED: Iterate over map instead of vector
    for (const auto& fieldPair : info.fields) {
        const std::string fieldName = fieldPair.first.string();
        
        ss << indent << "." << portPrefix << info.name << "_" << fieldName 
           << "(" << signalPrefix << info.name << "_" << fieldName << "),\n";
    }
    
    ss << indent << "." << portPrefix << info.name << "_valid"
       << "(" << signalPrefix << info.name << "_valid)";
    
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
        ss << "    // Custom header: " << info.name << "\n";
        ss << formatCustomHeaderFields(info, "output reg", "    ") << ",\n";
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
    
    return "    localparam STATE_CUSTOM     = 4'd2;\n";
}

std::string SVCodeGen::generateStateValue(const SVParser* parser, const std::string& stateName) {
    if (!parser) return "4'd0";
    
    const auto& customHeaders = parser->getCustomHeaders();
    bool hasCustom = !customHeaders.empty();
    
    if (stateName == "L3") {
        return hasCustom ? "4'd3" : "4'd2";
    } else if (stateName == "L4") {
        return hasCustom ? "4'd4" : "4'd3";
    } else if (stateName == "PAYLOAD") {
        return hasCustom ? "4'd5" : "4'd4";
    } else if (stateName == "DONE") {
        return hasCustom ? "4'd6" : "4'd5";
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
        ss << "            " << ch.second.name << "_valid <= 1'b0;\n";
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
        
        // First custom header uses "if", rest use "else if"
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
    
    // Close with proper else clause
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
    ss << "                // ==========================================\n";
    ss << "                // STATE_CUSTOM - Parse custom headers\n";
    ss << "                // ==========================================\n";
    ss << "                STATE_CUSTOM: begin\n";
    
    for (const auto& ch : customHeaders) {
        const auto& info = ch.second;
        
        ss << "                    // Parse " << info.name << " header\n";
        ss << "                    if (PARSE_" << info.name << ") begin\n";
        
        int bitOffset = 0;
    for (const auto& fieldPair : info.fields) {
        const std::string fieldName = fieldPair.first.string();      // Get the key
        const SVParser::CustomHeaderField& field = fieldPair.second; // Get the value
            
            ss << "                        " << info.name << "_" << fieldName;
            ss << " <= packet_buffer[byte_offset*8 + " << bitOffset;
            ss << " +: " << field.width << "];\n";
            
            bitOffset += field.width;
        }
        
        ss << "                        " << info.name << "_valid <= 1'b1;\n";
        ss << "                        byte_offset <= byte_offset + 11'd" 
           << (info.totalWidth / 8) << ";\n";
        ss << "                    end\n\n";
    }
    
    ss << "                    parse_state <= STATE_L3;\n";
    ss << "                end\n";
    
    return ss.str();
}

// ==========================================
// Deparser-Specific Generators 
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
        ss << "    // Custom header: " << info.name << "\n";
        ss << formatCustomHeaderFields(info, "input  wire", "    ") << ",\n";
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
        
        ss << "                    // Build " << info.name << " header (" 
           << (info.totalWidth / 8) << " bytes)\n";
        ss << "                    if (EMIT_" << info.name 
           << " && " << info.name << "_valid) begin\n";
        
        int bitOffset = 0;
    for (const auto& fieldPair : info.fields) {
        const std::string fieldName = fieldPair.first.string();      // Get the key
        const SVParser::CustomHeaderField& field = fieldPair.second; // Get the value
            
            ss << "                        header_buffer[byte_offset*8 + " << bitOffset;
            ss << " +: " << field.width << "] <= " << info.name << "_" << fieldName << ";\n";
            
            bitOffset += field.width;
        }
        
        ss << "                        byte_offset <= byte_offset + 11'd" 
           << (info.totalWidth / 8) << ";\n";
        ss << "                    end\n\n";
    }
    
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
        
        // Iterate over fields map
        for (const auto& fieldPair : headerInfo.fields) {
            const std::string fieldName = fieldPair.first.string();
            const SVParser::CustomHeaderField& field = fieldPair.second;
            
            ss << "logic [" << (field.width - 1) << ":0] "
               << headerName << "_" << fieldName << ";\n";
        }
        
        ss << "logic " << headerName << "_valid;\n";
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
        
        for (const auto& fieldPair : headerInfo.fields) {
            const std::string fieldName = fieldPair.first.string();
            const SVParser::CustomHeaderField& field = fieldPair.second;
            
            ss << "logic [" << (field.width - 1) << ":0] "
               << "pipeline_" << headerName << "_" << fieldName << ";\n";
        }
        
        ss << "logic pipeline_" << headerName << "_valid;\n";
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
        
        for (const auto& fieldPair : headerInfo.fields) {
            const std::string fieldName = fieldPair.first.string();
            const SVParser::CustomHeaderField& field = fieldPair.second;
            
            ss << "    ." << headerName << "_" << fieldName 
               << "(" << headerName << "_" << fieldName << "),\n";
        }
        
        ss << "    ." << headerName << "_valid(" << headerName << "_valid),\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generatePipelineCustomHeaderInputs(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
        
        for (const auto& fieldPair : headerInfo.fields) {
            const std::string fieldName = fieldPair.first.string();
            
            ss << "    ." << headerName << "_" << fieldName 
               << "(" << headerName << "_" << fieldName << "),\n";
        }
        
        ss << "    ." << headerName << "_valid(" << headerName << "_valid),\n";
    }
    
    return ss.str();
}

std::string SVCodeGen::generatePipelineCustomHeaderOutputs(const SVParser* parser) {
    if (!parser) return "";
    
    const auto& customHeaders = parser->getCustomHeaders();
    if (customHeaders.empty()) return "";
    
    std::stringstream ss;
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
        
        for (const auto& fieldPair : headerInfo.fields) {
            const std::string fieldName = fieldPair.first.string();
            
            ss << "    .out_" << headerName << "_" << fieldName 
               << "(pipeline_" << headerName << "_" << fieldName << "),\n";
        }
        
        ss << "    .out_" << headerName << "_valid(pipeline_" 
           << headerName << "_valid),\n";
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
        
        for (const auto& fieldPair : headerInfo.fields) {
            const std::string fieldName = fieldPair.first.string();
            
            ss << "    .pipeline_" << headerName << "_" << fieldName 
               << "(pipeline_" << headerName << "_" << fieldName << "),\n";
        }
        
        ss << "    .pipeline_" << headerName << "_valid(pipeline_" 
           << headerName << "_valid),\n";
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
    
    writeToFile(content, outputPath);
}

void SVCodeGen::processDeparserTemplate(const SVParser* parser, const std::string& outputPath) {
    std::string content = readTemplate("deparser.sv.in");
    if (content.empty()) {
        std::cerr << "Error: Failed to read deparser template" << std::endl;
        return;
    }
    
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

}  // namespace SV