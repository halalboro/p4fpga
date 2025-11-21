// backend.cpp

#include "common.h"
#include "backend.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <map>
#include <string>
#include <sstream>
#include <chrono>
#include "ir/ir.h"
#include "lib/error.h"
#include "lib/nullstream.h"
#include "lib/cstring.h"
#include "lib/log.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/toP4/toP4.h"
#include "program.h"
#include "type.h"
#include "options.h"
#include "bsvprogram.h"
#include "parser.h"       
#include "deparser.h"      
#include "control.h" 

namespace SV {

// ==========================================
// Debug Control
// ==========================================
#define BACKEND_INFO(msg)    std::cerr << "[INFO] " << msg << std::endl
#define BACKEND_SUCCESS(msg) std::cerr << "[✓] " << msg << std::endl
#define BACKEND_ERROR(msg)   std::cerr << "[ERROR] " << msg << std::endl

#define BACKEND_DEBUG(msg) if (SV::g_verbose) std::cerr << "  " << msg << std::endl

// ======================================
// Template Engine Helper Functions
// ======================================

std::string loadTemplate(const std::string& templatePath) {
    std::ifstream file(templatePath);
    if (!file.is_open()) {
        P4::error("Failed to load template: %s", templatePath.c_str());
        return "";
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    return content;
}

std::string replaceAll(std::string str, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
    return str;
}

// ======================================
// Generate Conditional Logic
// ======================================

std::string generateConditionalLogic(SVProgram* program) {
    if (g_detectedIfElse.empty()) {
        return "";
    }
    
    BACKEND_DEBUG("Generating conditional logic for " << g_detectedIfElse.size() << " if-else statement(s)");
    
    std::stringstream ss;
    
    ss << "\n    // ==========================================\n";
    ss << "    // Phase 3b: Conditional Action Selection\n";
    ss << "    // ==========================================\n";
    ss << "    // Overrides table action when conditions match\n\n";
    
    // Get action list to map names to IDs
    const auto& actions = program->getIngress()->getActions();
    std::map<std::string, int> actionNameToId;
    
    int actionIdx = 0;
    for (const auto& action : actions) {
        actionNameToId[action.first.string()] = actionIdx;
        actionIdx++;
    }
    
    // Generate conditional logic
    bool hasConditional = false;
    int condId = 0;
    
    for (const auto& ifElse : g_detectedIfElse) {
        // Only generate for ingress control
        if (ifElse.controlName != "MyIngress") {
            continue;
        }
        
        // Parse the condition
        if (auto equ = ifElse.condition->to<IR::Equ>()) {
            auto left = equ->left;
            auto right = equ->right;
            
            // Extract field name and value
            std::string fieldName;
            std::string compareValue;
            int bitWidth = 8;
            
            // Left side: field access (e.g., hdr.ipv4.protocol)
            if (auto member = left->to<IR::Member>()) {
                fieldName = member->member.string();
                
                // Determine bit width
                if (fieldName == "protocol") bitWidth = 8;
                else if (fieldName == "dstAddr" || fieldName == "srcAddr") bitWidth = 32;
                else if (fieldName == "diffserv") bitWidth = 6;
                else bitWidth = 8;
            }
            
            // Right side: constant value
            if (auto constant = right->to<IR::Constant>()) {
                compareValue = std::to_string(constant->asInt());
            } else if (auto path = right->to<IR::PathExpression>()) {
                // Named constant (e.g., IP_PROTOCOLS_UDP)
                std::string constName = path->path->name.string();
                
                if (constName == "IP_PROTOCOLS_UDP") compareValue = "17";
                else if (constName == "IP_PROTOCOLS_TCP") compareValue = "6";
                else if (constName == "IP_PROTOCOLS_ICMP") compareValue = "1";
                else if (constName == "IP_PROTOCOLS_IGMP") compareValue = "2";
                else compareValue = "0";
            }
            
            if (!fieldName.empty() && !compareValue.empty()) {
                hasConditional = true;
                condId++;
                
                // Map field to hardware signal
                std::string hwSignal = "ipv4_" + fieldName;
                
                // Look up action IDs
                int trueActionId = 0;  // NoAction
                int falseActionId = 0;
                
                auto trueIt = actionNameToId.find(ifElse.trueAction.string());
                if (trueIt != actionNameToId.end()) {
                    trueActionId = trueIt->second;
                }
                
                if (!ifElse.falseAction.isNullOrEmpty()) {
                    auto falseIt = actionNameToId.find(ifElse.falseAction.string());
                    if (falseIt != actionNameToId.end()) {
                        falseActionId = falseIt->second;
                    }
                }
                
                ss << "    // Conditional #" << condId << ": " << fieldName << " == " << compareValue << "\n";
                ss << "    wire cond_" << condId << "_match;\n";
                ss << "    wire [2:0] cond_" << condId << "_action;\n";
                ss << "    assign cond_" << condId << "_match = (" << hwSignal 
                   << " == " << bitWidth << "'d" << compareValue << ");\n";
                ss << "    assign cond_" << condId << "_action = cond_" << condId << "_match ? 3'd" 
                   << trueActionId << " : 3'd" << falseActionId << ";\n\n";
                
                BACKEND_DEBUG("  Cond " << condId << ": " << fieldName << " == " << compareValue 
                            << " → true=" << ifElse.trueAction << " (id=" << trueActionId << ")"
                            << " false=" << ifElse.falseAction << " (id=" << falseActionId << ")");
            }
        }
    }
    
    if (!hasConditional) {
        return "";
    }
    
    // Generate action override logic
    ss << "    // Action Override Logic\n";
    ss << "    // When conditional matches, override table action\n";
    ss << "    wire conditional_override;\n";
    ss << "    wire [2:0] conditional_action_id;\n\n";
    
    if (condId == 1) {
        // Single condition
        ss << "    assign conditional_override = cond_1_match;\n";
        ss << "    assign conditional_action_id = cond_1_action;\n\n";
    } else {
        // Multiple conditions - OR them together
        ss << "    assign conditional_override = ";
        for (int i = 1; i <= condId; i++) {
            if (i > 1) ss << " || ";
            ss << "cond_" << i << "_match";
        }
        ss << ";\n\n";
        
        // Priority encoder for action selection (first match wins)
        ss << "    assign conditional_action_id = \n";
        for (int i = 1; i <= condId; i++) {
            ss << "        cond_" << i << "_match ? cond_" << i << "_action :\n";
        }
        ss << "        3'd0;  // NoAction if no match\n\n";
    }
    
    ss << "    // Final action selection: conditional overrides table\n";
    ss << "    wire [2:0] final_action_id;\n";
    ss << "    assign final_action_id = conditional_override ? conditional_action_id : match_action_id;\n\n";
    
    BACKEND_DEBUG("Generated conditional override logic with " << condId << " condition(s)");
    
    return ss.str();
}

// ======================================
// Copy Static Module Templates
// ======================================

bool Backend::copyStaticTemplates(const std::string& outputDir) {
    BACKEND_DEBUG("Copying static modules");
    
    // Ensure hdl directory exists
    boost::filesystem::path hdlDir = boost::filesystem::path(outputDir) / "hdl";
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }
    
    // Source directory
    boost::filesystem::path srcDir = "../src/sv/hdl";
    
    // Define static modules
    std::map<std::string, std::string> staticModules = {
        {"match.sv.in", "match.sv"},
        {"action.sv.in", "action.sv"},
        {"stats.sv.in", "stats.sv"}
    };
    
    // Copy each module
    for (const auto& pair : staticModules) {
        boost::filesystem::path srcPath = srcDir / pair.first;
        boost::filesystem::path dstPath = hdlDir / pair.second;
        
        if (!boost::filesystem::exists(srcPath)) {
            BACKEND_ERROR("Template not found: " << srcPath.string());
            return false;
        }
        
        try {
            boost::filesystem::copy_file(
                srcPath,
                dstPath,
                boost::filesystem::copy_option::overwrite_if_exists
            );
            BACKEND_DEBUG("Copied " << pair.second);
            
        } catch (const boost::filesystem::filesystem_error& e) {
            BACKEND_ERROR("Failed to copy " << pair.first << ": " << e.what());
            return false;
        }
    }
    
    return true;
}

bool Backend::processMatchActionTemplate(SVProgram* program, const std::string& outputDir) {
    BACKEND_DEBUG("Generating match_action.sv with custom header support");
    
    // Load template
    std::string templatePath = "../src/sv/hdl/match_action.sv.in";
    std::string matchActionTemplate = loadTemplate(templatePath);
    if (matchActionTemplate.empty()) {
        BACKEND_ERROR("Failed to load match_action.sv template");
        return false;
    }
    
    // Get custom headers
    const auto& customHeaders = program->getParser()->getCustomHeaders();
    
    // ==========================================
    // Generate Custom Header INPUTS
    // ==========================================
    std::stringstream customInputs;

    if (!customHeaders.empty()) {
        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
            
            // Iterate over fields map
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                customInputs << "    input  wire [" << (field.width - 1) << ":0] "
                           << headerName << "_" << fieldName << ",\n";
            }
            customInputs << "    input  wire " << headerName << "_valid,\n";
        }
    }
    
    // ==========================================
    // Generate Custom Header OUTPUTS
    // ==========================================
    std::stringstream customOutputs;

    if (!customHeaders.empty()) {
        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
            
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                customOutputs << "    output wire [" << (field.width - 1) << ":0] "
                            << "out_" << headerName << "_" << fieldName << ",\n";
            }
            customOutputs << "    output wire " << "out_" << headerName << "_valid,\n";
        }
    }
    
    // ==========================================
    // Generate Custom Header WIRES
    // ==========================================
    std::stringstream customWires;

    if (!customHeaders.empty()) {
        customWires << "    // Custom header pass-through wires\n";
        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
            
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;
                
                customWires << "    wire [" << (field.width - 1) << ":0] "
                          << "pipeline_" << headerName << "_" << fieldName << ";\n";
            }
            customWires << "    wire pipeline_" << headerName << "_valid;\n";
        }
    }
    
    // ==========================================
    // Generate Custom Header PASSTHROUGH
    // ==========================================
    std::stringstream customPassthrough;

    if (!customHeaders.empty()) {
        customPassthrough << "    // Custom headers: direct pass-through (no modification)\n";
        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;
            
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                
                customPassthrough << "    assign out_" << headerName << "_" << fieldName
                                << " = " << headerName << "_" << fieldName << ";\n";
            }
            customPassthrough << "    assign out_" << headerName << "_valid"
                            << " = " << headerName << "_valid;\n";
        }
    }
    
    // ==========================================
    // Generate Conditional Logic
    // ==========================================
    std::string conditionalLogic = generateConditionalLogic(program);
    
    // ==========================================
    // Replace Template Placeholders
    // ==========================================
    matchActionTemplate = replaceAll(matchActionTemplate, 
                                     "{{CUSTOM_HEADER_INPUTS}}", 
                                     customInputs.str());
    
    matchActionTemplate = replaceAll(matchActionTemplate, 
                                     "{{CUSTOM_HEADER_OUTPUTS}}", 
                                     customOutputs.str());
    
    matchActionTemplate = replaceAll(matchActionTemplate, 
                                     "{{CUSTOM_HEADER_WIRES}}", 
                                     customWires.str());
    
    matchActionTemplate = replaceAll(matchActionTemplate, 
                                     "{{CUSTOM_HEADER_PASSTHROUGH}}", 
                                     customPassthrough.str());
    
    if (!g_detectedIfElse.empty()) {
        // Replace match_action_id with final_action_id in action instantiation
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        ".action_id(match_action_id),",
                                        ".action_id(final_action_id),");
        
        BACKEND_DEBUG("Patched action_id connection to use conditional override");
    }
    
    // ==========================================
    // Write Output File
    // ==========================================
    boost::filesystem::path outputPath = 
        boost::filesystem::path(outputDir) / "hdl" / "match_action.sv";
    
    std::ofstream outFile(outputPath.string());
    if (!outFile) {
        BACKEND_ERROR("Failed to create match_action.sv");
        return false;
    }
    
    outFile << matchActionTemplate;
    outFile.close();
    
    BACKEND_DEBUG("Generated match_action.sv");
    return true;
}

// ======================================
// Main Compilation Entry Point
// ======================================

bool Backend::run(const SVOptions& options,
                  const IR::ToplevelBlock* toplevel,
                  P4::ReferenceMap* refMap,
                  P4::TypeMap* typeMap) {
    
    SV::g_verbose = options.verbose;
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Extract base name from input file
    std::string p4FileName = options.file.string();
    std::string baseName = "router";
    
    size_t lastSlash = p4FileName.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        p4FileName = p4FileName.substr(lastSlash + 1);
    }
    
    size_t lastDot = p4FileName.find_last_of(".");
    if (lastDot != std::string::npos) {
        baseName = p4FileName.substr(0, lastDot);
    } else {
        baseName = p4FileName;
    }
    
    BACKEND_INFO("Compiling " << p4FileName);
    
    // Create type factory
    FPGATypeFactory::createFactory(typeMap);
    
    // Build the program representation
    BACKEND_DEBUG("Building program");
    SVProgram svprog(toplevel, refMap, typeMap);
    if (!svprog.build()) {
        BACKEND_ERROR("Program build failed");
        return false;
    }
    
    // Validate output directory
    if (options.outputDir.isNullOrEmpty()) {
        BACKEND_ERROR("Must specify output directory with --out");
        return false;
    }
    
    // Create output directory structure
    boost::filesystem::path outputDir(options.outputDir.c_str());
    boost::filesystem::path hdlDir = outputDir / "hdl";
    
    if (!boost::filesystem::exists(outputDir)) {
        boost::filesystem::create_directories(outputDir);
    }
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }
    
    // ======================================
    // Generate SystemVerilog Modules
    // ======================================
    
    SVCodeGen codegen;
    
    // Generate parser
    BACKEND_DEBUG("Generating parser.sv");
    std::string parserPath = (hdlDir / "parser.sv").string();
    codegen.processParserTemplate(svprog.getParser(), parserPath);
    
    if (!boost::filesystem::exists(parserPath)) {
        BACKEND_ERROR("Failed to generate parser.sv");
        return false;
    }
    BACKEND_SUCCESS("Generated parser.sv");
    
    // Generate deparser
    BACKEND_DEBUG("Generating deparser.sv");
    std::string deparserPath = (hdlDir / "deparser.sv").string();
    codegen.processDeparserTemplate(svprog.getParser(), deparserPath);
    
    if (!boost::filesystem::exists(deparserPath)) {
        BACKEND_ERROR("Failed to generate deparser.sv");
        return false;
    }
    BACKEND_SUCCESS("Generated deparser.sv");
    
    // Copy static modules
    if (!copyStaticTemplates(options.outputDir.string())) {
        return false;
    }
    BACKEND_SUCCESS("Copied static modules");

    // Process match_action.sv template with custom headers AND conditional logic
    if (!processMatchActionTemplate(&svprog, options.outputDir.string())) {
        return false;
    }
    BACKEND_SUCCESS("Generated match_action.sv");
    
    // Generate control slave
    BACKEND_DEBUG("Generating control slave");
    std::string slaveTemplate = loadTemplate("../src/sv/hdl/slave.sv.in");
    if (slaveTemplate.empty()) {
        BACKEND_ERROR("Failed to load slave template");
        return false;
    }
    
    slaveTemplate = replaceAll(slaveTemplate, "{{MODULE_NAME}}", baseName);
    
    boost::filesystem::path slavePath = hdlDir / (baseName + "_slave.sv");
    std::ofstream slaveFile(slavePath.string());
    if (!slaveFile) {
        BACKEND_ERROR("Failed to create slave file");
        return false;
    }
    slaveFile << slaveTemplate;
    slaveFile.close();
    
    // Generate vfpga_top.svh
    BACKEND_DEBUG("Generating vfpga_top.svh");
    std::string vfpgaTemplate = loadTemplate("../src/sv/vfpga_top.svh.in");
    if (vfpgaTemplate.empty()) {
        BACKEND_ERROR("Failed to load vfpga_top template");
        return false;
    }
    
    // Basic replacements
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MODULE_NAME}}", baseName);
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PARSER_CONFIG}}", 
                                svprog.getParser()->getParserConfigString());
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{DEPARSER_CONFIG}}", 
                                svprog.getDeparser()->getDeparserConfigString());
    
    // Custom header replacements
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{CUSTOM_HEADER_SIGNALS}}", 
                                codegen.generateCustomHeaderSignals(svprog.getParser()));
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{CUSTOM_HEADER_PIPELINE_SIGNALS}}", 
                                codegen.generateCustomHeaderPipelineSignals(svprog.getParser()));
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PARSER_CUSTOM_HEADER_PORTS}}", 
                                codegen.generateParserCustomHeaderPorts(svprog.getParser()));
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_CUSTOM_HEADER_INPUTS}}", 
                                codegen.generatePipelineCustomHeaderInputs(svprog.getParser()));
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_CUSTOM_HEADER_OUTPUTS}}", 
                                codegen.generatePipelineCustomHeaderOutputs(svprog.getParser()));
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{DEPARSER_CUSTOM_HEADER_PORTS}}", 
                                codegen.generateDeparserCustomHeaderPorts(svprog.getParser()));
    
    // Handle egress configuration
    ControlConfig controlConfig = svprog.getControlConfig();
    bool hasEgress = (controlConfig.egressConfig != 0);
    bool hasStateful = (controlConfig.egressConfig & 0x04) != 0;
    bool hasHash = (controlConfig.actionConfig & 0x20) != 0;
    
    std::stringstream ss;
    
    if (hasEgress) {
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_SIGNALS}}",
            "logic [1:0]                  ipv4_ecn;");
        
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_PIPELINE_SIGNALS}}",
            "logic                        pipeline_ecn_marked;");
        
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ECN_EXTRACT}}",
            "// Extract ECN bits from IPv4 ToS field\n"
            "assign ipv4_ecn = ipv4_diffserv[7:6];");
        
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_ECN_INPUT}}",
            "    .ipv4_ecn(ipv4_ecn),");
        
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_EGRESS_INPUT}}",
            "    // Egress control\n"
            "    .enq_qdepth(19'd15),  // TODO: Connect to actual queue depth");
        
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_ECN_OUTPUT}}",
            "    .ecn_marked(pipeline_ecn_marked),");
        
        ss << "8'b";
        for (int i = 7; i >= 0; i--) {
            ss << ((controlConfig.egressConfig >> i) & 1);
        }
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_CONFIG}}", ss.str());
        
        ss.str("");
        ss << "19'd" << svprog.getECNThreshold();
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ECN_THRESHOLD}}", ss.str());
        
    } else {
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_SIGNALS}}", "");
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_PIPELINE_SIGNALS}}", "");
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ECN_EXTRACT}}", "");
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_ECN_INPUT}}", "");
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_EGRESS_INPUT}}", "");
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PIPELINE_ECN_OUTPUT}}", "");
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_CONFIG}}", "8'b00000000");
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ECN_THRESHOLD}}", "19'd10");
    }
    
    // Write vfpga_top.svh
    boost::filesystem::path vfpgaPath = outputDir / "vfpga_top.svh";
    std::ofstream vfpgaFile(vfpgaPath.string());
    if (!vfpgaFile) {
        BACKEND_ERROR("Failed to create vfpga_top.svh");
        return false;
    }
    vfpgaFile << vfpgaTemplate;
    vfpgaFile.close();
    BACKEND_SUCCESS("Generated vfpga_top.svh");
    
    // Generate init_ip.tcl
    BACKEND_DEBUG("Generating init_ip.tcl");
    std::string tclTemplate = loadTemplate("../src/sv/init_ip.tcl.in");
    if (tclTemplate.empty()) {
        BACKEND_ERROR("Failed to load init_ip.tcl template");
        return false;
    }
    
    tclTemplate = replaceAll(tclTemplate, "{{MODULE_NAME}}", baseName);
    
    boost::filesystem::path tclPath = outputDir / "init_ip.tcl";
    std::ofstream tclFile(tclPath.string());
    if (!tclFile) {
        BACKEND_ERROR("Failed to create init_ip.tcl");
        return false;
    }
    tclFile << tclTemplate;
    tclFile.close();
    
    // ======================================
    // Print Beautiful Summary
    // ======================================
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    const auto& customHeaders = svprog.getParser()->getCustomHeaders();
    uint8_t parserConfig = svprog.getParser()->getParserConfig();
    
    std::cerr << "\nCompilation Summary:" << std::endl;
    std::cerr << "  Module:          " << baseName << std::endl;
    
    // Show enabled protocols
    std::cerr << "  Protocols:       ";
    bool first = true;
    if (parserConfig & 0x01) { if (!first) std::cerr << ", "; std::cerr << "Ethernet"; first = false; }
    if (parserConfig & 0x02) { if (!first) std::cerr << ", "; std::cerr << "VLAN"; first = false; }
    if (parserConfig & 0x04) { if (!first) std::cerr << ", "; std::cerr << "IPv4"; first = false; }
    if (parserConfig & 0x08) { if (!first) std::cerr << ", "; std::cerr << "IPv6"; first = false; }
    if (parserConfig & 0x10) { if (!first) std::cerr << ", "; std::cerr << "TCP"; first = false; }
    if (parserConfig & 0x20) { if (!first) std::cerr << ", "; std::cerr << "UDP"; first = false; }
    if (parserConfig & 0x40) { if (!first) std::cerr << ", "; std::cerr << "VXLAN"; first = false; }
    std::cerr << std::endl;
    
    // Show custom headers
    if (!customHeaders.empty()) {
        std::cerr << "  Custom Headers:  ";
        first = true;
        for (const auto& ch : customHeaders) {
            if (!first) std::cerr << ", ";
            std::cerr << ch.first << " (" << ch.second.totalWidth << " bits)";
            first = false;
        }
        std::cerr << std::endl;
    }
    
    // Show tables and actions from ingress control
    if (svprog.getIngress()) {
        const auto& tables = svprog.getIngress()->getTables();
        const auto& actions = svprog.getIngress()->getActions();
        
        if (!tables.empty()) {
            std::cerr << "  Tables:          ";
            first = true;
            for (const auto& t : tables) {
                if (!first) std::cerr << ", ";
                std::cerr << t.first;
                first = false;
            }
            std::cerr << " (" << tables.size() << ")" << std::endl;
        }
        
        if (!actions.empty()) {
            std::cerr << "  Actions:         ";
            first = true;
            for (const auto& a : actions) {
                if (!first) std::cerr << ", ";
                std::cerr << a.first;
                first = false;
            }
            std::cerr << " (" << actions.size() << ")" << std::endl;
        }
    }
    
    // Show features
    std::cerr << "  Features:        ";
    first = true;
    if (hasEgress) {
        if (!first) std::cerr << ", ";
        std::cerr << "ECN";
        first = false;
    }
    if (hasStateful) {
        if (!first) std::cerr << ", ";
        std::cerr << "Stateful";
        first = false;
    }
    if (hasHash) {
        if (!first) std::cerr << ", ";
        std::cerr << "Hash";
        first = false;
    }
    
    // Show conditional logic
    if (!g_detectedIfElse.empty()) {
        if (!first) std::cerr << ", ";
        std::cerr << "Conditional";
        first = false;
    }
    
    if (first) {
        std::cerr << "None";
    }
    std::cerr << std::endl;
    
    std::cerr << "  Output:          " << outputDir.string() << "/" << std::endl;
    
    std::cerr << "\n[SUCCESS] Compilation complete in " 
              << (duration.count() / 1000.0) << "s" << std::endl;
    
    return true;
}

}  // namespace SV