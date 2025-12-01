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
#include "action.h"
#include "table.h"

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
    ss << "    //          Conditional Action Selection\n";
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
            
            // Extract header type, field name, and value
            std::string headerType;  // "ipv4", "tcp", "udp", etc.
            std::string fieldName;
            std::string compareValue;
            int bitWidth = 8;
            
            // ==========================================
            // LEFT SIDE: Extract header.field
            // ==========================================
            if (auto member = left->to<IR::Member>()) {
                fieldName = member->member.string();
                
                // Try to determine header type from the expression
                if (auto pathExpr = member->expr->to<IR::Member>()) {
                    // Pattern: hdr.ipv4.protocol or hdr.tcp.dstPort
                    headerType = pathExpr->member.string();
                } else {
                    // Fallback: assume IPv4 for common fields
                    headerType = "ipv4";
                }
                
                // Map field name to hardware signal and bit width
                if (fieldName == "protocol") {
                    bitWidth = 8;
                } else if (fieldName == "dstAddr" || fieldName == "srcAddr") {
                    bitWidth = 32;
                } else if (fieldName == "diffserv") {
                    bitWidth = 6;
                } else if (fieldName == "dstPort" || fieldName == "srcPort") {
                    bitWidth = 16;
                } else if (fieldName == "ttl") {
                    bitWidth = 8;
                } else {
                    bitWidth = 8;  // Default
                }
            }
            
            // ==========================================
            // RIGHT SIDE: Extract comparison value
            // ==========================================
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
                
                // ==========================================
                // MAP TO HARDWARE SIGNAL
                // ==========================================
                std::string hwSignal;
                
                // Map based on header type and field name
                if (headerType == "ipv4" || headerType == "ipv6") {
                    hwSignal = headerType + "_" + fieldName;
                } else if (headerType == "tcp") {
                    // TCP fields map to ipv4_src_port/ipv4_dst_port
                    if (fieldName == "srcPort") {
                        hwSignal = "ipv4_src_port";
                    } else if (fieldName == "dstPort") {
                        hwSignal = "ipv4_dst_port";
                    } else {
                        hwSignal = "tcp_" + fieldName;  // For future TCP fields
                    }
                } else if (headerType == "udp") {
                    // UDP fields also map to ipv4_src_port/ipv4_dst_port
                    if (fieldName == "srcPort") {
                        hwSignal = "ipv4_src_port";
                    } else if (fieldName == "dstPort") {
                        hwSignal = "ipv4_dst_port";
                    } else {
                        hwSignal = "udp_" + fieldName;  // For future UDP fields
                    }
                } else {
                    // Fallback: assume IPv4
                    hwSignal = "ipv4_" + fieldName;
                }
                
                // ==========================================
                // LOOKUP ACTION IDs
                // ==========================================
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
                
                // ==========================================
                // GENERATE HARDWARE LOGIC
                // ==========================================
                ss << "    // Conditional #" << condId << ": " 
                   << headerType << "." << fieldName << " == " << compareValue << "\n";
                ss << "    wire cond_" << condId << "_match;\n";
                ss << "    wire [2:0] cond_" << condId << "_action;\n";
                ss << "    assign cond_" << condId << "_match = (" << hwSignal 
                   << " == " << bitWidth << "'d" << compareValue << ");\n";
                ss << "    assign cond_" << condId << "_action = cond_" << condId << "_match ? 3'd" 
                   << trueActionId << " : 3'd" << falseActionId << ";\n\n";
                
                BACKEND_DEBUG("  Cond " << condId << ": " << headerType << "." << fieldName 
                            << " == " << compareValue 
                            << " → hw=" << hwSignal
                            << ", true=" << ifElse.trueAction << " (id=" << trueActionId << ")"
                            << ", false=" << ifElse.falseAction << " (id=" << falseActionId << ")");
            }
        }
    }
    
    if (!hasConditional) {
        return "";
    }
    
    // ==========================================
    // Generate Action Override Logic
    // ==========================================
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

std::string generateHashInstantiation(SVProgram* program) {
    if (!program->getIngress()) return "";
    
    // Check if any action uses hash
    bool hasHashAction = false;
    const auto& actions = program->getIngress()->getActions();
    
    for (const auto& actionPair : actions) {
        if (actionPair.second->usesHash()) {
            hasHashAction = true;
            BACKEND_DEBUG("Action " << actionPair.first << " uses hash");
            break;
        }
    }
    
    if (!hasHashAction) {
        BACKEND_DEBUG("No actions use hash, skipping hash module");
        return "";
    }
    
    BACKEND_DEBUG("Generating hash module instantiation");
    
    std::stringstream ss;
    
    ss << "\n    // ==========================================\n";
    ss << "    // Hash Module Instantiation\n";
    ss << "    // ==========================================\n";
    ss << "    wire [31:0] hash_result_0;\n";
    ss << "    wire hash_valid_0;\n\n";
    
    ss << "    hash #(\n";
    ss << "        .HASH_TYPE(0),        // CRC16\n";
    ss << "        .INPUT_WIDTH(104),    // 5-tuple: 32+32+16+16+8 bits\n";
    ss << "        .OUTPUT_WIDTH(32)\n";
    ss << "    ) hash_inst_0 (\n";
    ss << "        .aclk(aclk),\n";
    ss << "        .aresetn(aresetn),\n";
    ss << "        .data_in({ipv4_src_addr, ipv4_dst_addr, ipv4_src_port, ipv4_dst_port, ipv4_protocol}),\n";
    ss << "        .valid_in(packet_valid_in && ipv4_valid),\n";
    ss << "        .ready_out(),\n";
    ss << "        .hash_out(hash_result_0),\n";
    ss << "        .valid_out(hash_valid_0)\n";
    ss << "    );\n\n";
    
    ss << "    // Use hardware hash result\n";
    ss << "    assign flow_hash = hash_result_0;\n\n";
    
    return ss.str();
}

// ======================================
// Helper: Map P4 Field Name to Hardware Signal
// ======================================
std::string mapFieldToSignal(const std::string& p4FieldName, SVProgram* program) {
    // Check if it's a custom header field
    const auto& customHeaders = program->getParser()->getCustomHeaders();
    
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const auto& headerInfo = headerPair.second;
        
        for (const auto& fieldPair : headerInfo.fields) {
            std::string fullFieldName = headerName + "." + fieldPair.first.string();
            if (fullFieldName == p4FieldName || fieldPair.first.string() == p4FieldName) {
                // Found custom header field!
                return headerName + "_" + fieldPair.first.string();
            }
        }
    }
    
    // Standard field mapping
    if (p4FieldName == "dstAddr") return "ipv4_dst_addr";
    if (p4FieldName == "srcAddr") return "ipv4_src_addr";
    if (p4FieldName == "protocol") return "ipv4_protocol";
    if (p4FieldName == "op") return "p4calc_op";  // For calc.p4
    
    // Try pattern matching for "header.field"
    size_t dotPos = p4FieldName.find('.');
    if (dotPos != std::string::npos) {
        std::string headerName = p4FieldName.substr(0, dotPos);
        std::string fieldName = p4FieldName.substr(dotPos + 1);
        
        // Check if it's a custom header
        if (customHeaders.count(cstring(headerName))) {
            return headerName + "_" + fieldName;
        }
        
        // Standard headers
        return headerName + "_" + fieldName;
    }
    
    // Default: return as-is with underscores
    std::string signal = p4FieldName;
    std::replace(signal.begin(), signal.end(), '.', '_');
    return signal;
}

// ======================================
// Generate Inline Register Operations
// For firewall.p4 bloom filter pattern
// ======================================

std::string generateInlineRegisterLogic(SVProgram* program) {
    auto ingress = program->getIngress();
    if (!ingress) return "";
    
    const auto& registers = ingress->getRegisters();
    
    // Check for bloom filter pattern
    std::vector<std::string> bloomFilterRegs;
    for (const auto& reg : registers) {
        std::string regName = reg.name.string();
        if (regName.find("bloom_filter") != std::string::npos) {
            bloomFilterRegs.push_back(regName);
        }
    }
    
    if (bloomFilterRegs.size() < 2) {
        return "";
    }
    
    BACKEND_DEBUG("Generating bloom filter logic for " << bloomFilterRegs.size() << " registers");
    
    std::stringstream ss;
    
    ss << "\n    // ==========================================\n";
    ss << "    // Bloom Filter Logic (firewall.p4 pattern)\n";
    ss << "    // ==========================================\n";
    ss << "    // Implements stateful TCP connection tracking:\n";
    ss << "    // - Outbound (internal→external): Record connection in bloom filter\n";
    ss << "    // - Inbound (external→internal): Check bloom filter, drop if no match\n";
    ss << "    // ==========================================\n\n";
    
    // Declare registers
    for (const auto& regName : bloomFilterRegs) {
        ss << "    reg [0:0] " << regName << " [0:4095];\n";
    }
    ss << "\n";
    
    // Hash indices from flow_hash
    ss << "    // Hash indices for bloom filter lookup\n";
    ss << "    wire [11:0] reg_pos_one = flow_hash[11:0];\n";
    ss << "    wire [11:0] reg_pos_two = flow_hash[11:0] ^ 12'hA5A;\n\n";
    
    // Read value registers
    ss << "    // Bloom filter read values (registered for timing)\n";
    ss << "    reg reg_val_one, reg_val_two;\n\n";
    
    // Direction signal
    ss << "    // Direction: 0=outbound (set bloom), 1=inbound (check bloom)\n";
    ss << "    // Determined by ingress port (workaround for single-table architecture)\n";
    ss << "    // Port 0 = external interface → inbound traffic (direction=1)\n";
    ss << "    // Port 1+ = internal interfaces → outbound traffic (direction=0)\n";
    ss << "    wire direction;\n";
    ss << "    assign direction = (ingress_port == 9'd0) ? 1'b1 : 1'b0;\n\n";
    
    // TCP SYN detection for outbound connection establishment
    ss << "    // TCP flags from parser (assumes tcp header follows ipv4)\n";
    ss << "    // For full implementation, parser should extract tcp.syn flag\n";
    ss << "    // Using simplified approach: record all outbound TCP packets\n\n";
    
    // Sequential logic
    ss << "    always_ff @(posedge aclk or negedge aresetn) begin\n";
    ss << "        if (!aresetn) begin\n";
    ss << "            reg_val_one <= 1'b0;\n";
    ss << "            reg_val_two <= 1'b0;\n";
    ss << "        end else if (packet_valid_in && ipv4_valid && ipv4_protocol == 8'd6) begin\n";
    ss << "            // TCP packet processing\n";
    ss << "            \n";
    ss << "            // Always read current bloom filter values\n";
    ss << "            reg_val_one <= " << bloomFilterRegs[0] << "[reg_pos_one];\n";
    ss << "            reg_val_two <= " << bloomFilterRegs[1] << "[reg_pos_two];\n";
    ss << "            \n";
    ss << "            // Write to bloom filter on outbound traffic (direction=0)\n";
    ss << "            // This records the connection for later inbound verification\n";
    ss << "            if (direction == 1'b0) begin\n";
    ss << "                " << bloomFilterRegs[0] << "[reg_pos_one] <= 1'b1;\n";
    ss << "                " << bloomFilterRegs[1] << "[reg_pos_two] <= 1'b1;\n";
    ss << "            end\n";
    ss << "        end\n";
    ss << "    end\n\n";
    
    // Drop logic for inbound packets without matching outbound connection
    ss << "    // Bloom filter drop decision\n";
    ss << "    // Drop inbound TCP packets if bloom filter check fails\n";
    ss << "    // (no matching outbound connection was recorded)\n";
    ss << "    wire bloom_filter_drop;\n";
    ss << "    assign bloom_filter_drop = (direction == 1'b1) &&           // Inbound traffic\n";
    ss << "                               (ipv4_protocol == 8'd6) &&       // TCP protocol\n";
    ss << "                               packet_valid_in && ipv4_valid && // Valid packet\n";
    ss << "                               (reg_val_one == 1'b0 || reg_val_two == 1'b0);  // Bloom filter miss\n\n";
    
    return ss.str();
}

// ======================================
// Generate ECMP Load Balancing Logic
// For load_balance.p4 pattern
// ======================================

std::string generateECMPLogic(SVProgram* program) {
    auto ingress = program->getIngress();
    if (!ingress) return "";
    
    const auto& tables = ingress->getTables();
    
    // Check for ECMP pattern: ecmp_group and ecmp_nhop tables
    bool hasEcmpGroup = false;
    bool hasEcmpNhop = false;
    
    for (const auto& tablePair : tables) {
        std::string tname = tablePair.first.string();
        if (tname.find("ecmp_group") != std::string::npos) {
            hasEcmpGroup = true;
        }
        if (tname.find("ecmp_nhop") != std::string::npos || 
            tname.find("nexthop") != std::string::npos) {
            hasEcmpNhop = true;
        }
    }
    
    if (!hasEcmpGroup || !hasEcmpNhop) {
        return "";
    }
    
    BACKEND_DEBUG("Generating ECMP load balancing logic (programmable)");
    
    std::stringstream ss;
    
    ss << "\n    // ==========================================\n";
    ss << "    // ECMP Load Balancing Logic (load_balance.p4)\n";
    ss << "    // ==========================================\n";
    ss << "    // Programmable hash-based ECMP with control plane interface\n";
    ss << "    // ==========================================\n\n";
    
    // ECMP configuration parameters
    ss << "    // ECMP configuration\n";
    ss << "    localparam ECMP_MAX_NHOPS = 16;  // Maximum next-hops\n";
    ss << "    localparam ECMP_NHOP_WIDTH = 4;  // log2(ECMP_MAX_NHOPS)\n\n";
    
    // Programmable next-hop table
    ss << "    // Programmable next-hop table (control plane writes via AXI)\n";
    ss << "    reg [8:0]  ecmp_nhop_port  [0:ECMP_MAX_NHOPS-1];\n";
    ss << "    reg [47:0] ecmp_nhop_dmac  [0:ECMP_MAX_NHOPS-1];\n";
    ss << "    reg [31:0] ecmp_nhop_ipv4  [0:ECMP_MAX_NHOPS-1];\n";
    ss << "    reg [ECMP_NHOP_WIDTH-1:0] ecmp_group_size;  // Active next-hops (1-16)\n\n";
    
    // Initialize with defaults
    ss << "    // Initialize with default values\n";
    ss << "    initial begin\n";
    ss << "        ecmp_group_size = 4'd4;  // Default 4-way ECMP\n";
    ss << "        for (int i = 0; i < ECMP_MAX_NHOPS; i++) begin\n";
    ss << "            ecmp_nhop_port[i] = 9'd1 + i[8:0];\n";
    ss << "            ecmp_nhop_dmac[i] = 48'h00_00_00_00_00_01 + i;\n";
    ss << "            ecmp_nhop_ipv4[i] = 32'h0A_00_00_01 + i;\n";
    ss << "        end\n";
    ss << "    end\n\n";
    
    // ECMP select from hash
    ss << "    // ECMP selection from 5-tuple hash\n";
    ss << "    wire [13:0] ecmp_select;\n";
    ss << "    assign ecmp_select = flow_hash[13:0];\n\n";
    
    // Next-hop index using modulo
    ss << "    // Next-hop index = hash mod group_size\n";
    ss << "    wire [ECMP_NHOP_WIDTH-1:0] nhop_index;\n";
    ss << "    assign nhop_index = ecmp_select[ECMP_NHOP_WIDTH-1:0] % ecmp_group_size;\n\n";
    
    // Lookup results
    ss << "    // Next-hop lookup results\n";
    ss << "    wire [8:0]  ecmp_egress_port;\n";
    ss << "    wire [47:0] ecmp_dmac;\n";
    ss << "    wire [31:0] ecmp_ipv4;\n";
    ss << "    assign ecmp_egress_port = ecmp_nhop_port[nhop_index];\n";
    ss << "    assign ecmp_dmac = ecmp_nhop_dmac[nhop_index];\n";
    ss << "    assign ecmp_ipv4 = ecmp_nhop_ipv4[nhop_index];\n\n";
    
    // ECMP active signal
    ss << "    // ECMP active for valid IPv4 TCP packets with TTL > 0\n";
    ss << "    wire ecmp_active;\n";
    ss << "    assign ecmp_active = packet_valid_in && ipv4_valid && \n";
    ss << "                         (ipv4_protocol == 8'd6) &&  // TCP\n";
    ss << "                         (ipv4_ttl > 8'd0);\n\n";
    
    // Control plane programming interface
    ss << "    // ==========================================\n";
    ss << "    // ECMP Control Plane Interface\n";
    ss << "    // ==========================================\n";
    ss << "    // Address map (offset from ECMP base):\n";
    ss << "    //   0x00: ecmp_group_size (RW)\n";
    ss << "    //   0x10 + i*0x10: nhop[i].port (RW)\n";
    ss << "    //   0x14 + i*0x10: nhop[i].dmac_lo (RW)\n";
    ss << "    //   0x18 + i*0x10: nhop[i].dmac_hi (RW)\n";
    ss << "    //   0x1C + i*0x10: nhop[i].ipv4 (RW)\n";
    ss << "    // ==========================================\n\n";
    
    // ECMP override signals - these override action module outputs when ECMP is active
    ss << "    // ==========================================\n";
    ss << "    // ECMP Output Override\n";
    ss << "    // ==========================================\n";
    ss << "    // When ECMP is active, override egress port and destination MAC\n";
    ss << "    wire ecmp_override;\n";
    ss << "    assign ecmp_override = ecmp_active && match_hit;\n\n";
    
    ss << "    // Final egress port: ECMP overrides table result\n";
    ss << "    wire [8:0] ecmp_final_egress_port;\n";
    ss << "    assign ecmp_final_egress_port = ecmp_override ? ecmp_egress_port : egress_port_from_action;\n\n";
    
    ss << "    // Final destination MAC: ECMP overrides for next-hop\n";
    ss << "    wire [47:0] ecmp_final_dmac;\n";
    ss << "    assign ecmp_final_dmac = ecmp_override ? ecmp_dmac : eth_dst_addr;\n\n";
    
    ss << "    // Final destination IP: ECMP can modify (for NAT-like behavior)\n";
    ss << "    wire [31:0] ecmp_final_dst_ip;\n";
    ss << "    assign ecmp_final_dst_ip = ecmp_override ? ecmp_ipv4 : ipv4_dst_addr;\n\n";

    return ss.str();
}

// ======================================
// Helper: Generate Table Lookup Logic
// ======================================
std::string generateTableLookup(SVProgram* program) {
    auto ingress = program->getIngress();
    if (!ingress) {
        return "";
    }
    
    const auto& tables = ingress->getTables();
    if (tables.empty()) {
        return "";
    }
    
    // Get first table (primary matching table)
    // Prefer ipv4_lpm or similar routing table as primary
    SVTable* firstTable = tables.begin()->second;
    for (const auto& tablePair : tables) {
        std::string tname = tablePair.first.string();
        if (tname.find("ipv4") != std::string::npos || 
            tname.find("lpm") != std::string::npos ||
            tname.find("routing") != std::string::npos) {
            firstTable = tablePair.second;
            break;
        }
    }
    
    // Get key field names
    auto keyFieldNames = firstTable->getKeyFieldNames();
    
    if (keyFieldNames.empty()) {
        BACKEND_DEBUG("No key fields found, using default ipv4_dst_addr");
        return "";
    }
    
    // Check if any key field references egress_spec (standard_metadata.egress_spec)
    bool needsEgressSpec = false;
    for (const auto& fieldName : keyFieldNames) {
        std::string fn = fieldName.string();
        if (fn.find("egress_spec") != std::string::npos || 
            fn.find("egress_port") != std::string::npos) {
            needsEgressSpec = true;
            break;
        }
    }
    
    // Generate lookup key expression
    std::stringstream keyExpr;
    std::stringstream validCondition;
    
    if (keyFieldNames.size() == 1) {
        std::string fieldName = keyFieldNames[0].string();
        std::string hwSignal = mapFieldToSignal(fieldName, program);
        
        keyExpr << hwSignal;
        
        if (fieldName.find("ipv4") != std::string::npos || 
            fieldName.find("dstAddr") != std::string::npos ||
            fieldName.find("srcAddr") != std::string::npos ||
            fieldName.find("protocol") != std::string::npos) {
            validCondition << " && ipv4_valid";
        } else {
            size_t dotPos = fieldName.find('.');
            if (dotPos != std::string::npos) {
                std::string headerName = fieldName.substr(0, dotPos);
                validCondition << " && " << headerName << "_valid";
            } else {
                const auto& customHeaders = program->getParser()->getCustomHeaders();
                for (const auto& headerPair : customHeaders) {
                    const std::string headerName = headerPair.first.string();
                    const auto& headerInfo = headerPair.second;
                    
                    for (const auto& fieldPair : headerInfo.fields) {
                        if (fieldPair.first.string() == fieldName) {
                            validCondition << " && " << headerName << "_valid";
                            break;
                        }
                    }
                }
            }
        }
        
        BACKEND_DEBUG("Lookup key: " << hwSignal);
        
    } else {
        // Concatenated key (multiple fields)
        keyExpr << "{";
        bool first = true;
        for (const auto& fieldName : keyFieldNames) {
            if (!first) keyExpr << ", ";
            std::string fn = fieldName.string();
            
            // Map standard_metadata fields to hardware signals
            if (fn.find("ingress_port") != std::string::npos) {
                keyExpr << "ingress_port_in";
            } else if (fn.find("egress_spec") != std::string::npos) {
                keyExpr << "egress_spec";  // Will be declared separately
            } else {
                keyExpr << mapFieldToSignal(fn, program);
            }
            first = false;
        }
        keyExpr << "}";
        
        validCondition << " && ipv4_valid";
        BACKEND_DEBUG("Lookup key: " << keyExpr.str());
    }
    
    // Build the complete lookup key line
    std::stringstream result;
    result << ".lookup_key(" << keyExpr.str() << "),\n";
    result << "        .lookup_key_mask(";
    
    int keyWidth = firstTable->getKeyWidth();
    if (firstTable->getMatchType() == SVTable::MatchType::EXACT) {
        result << keyWidth << "'hFFFFFFFF";
    } else {
        result << keyWidth << "'h0";
    }
    result << "),\n";
    
    result << "        .lookup_valid(packet_valid_in" << validCondition.str() << "),\n";
    
    return result.str();
}

// ======================================
// Generate Stack Pointer Feedback Logic
// ======================================
std::string generateStackPointerFeedback(SVProgram* program) {
    const auto& customHeaders = program->getParser()->getCustomHeaders();
    
    std::stringstream ss;
    bool hasStacks = false;
    
    // Check if there are any stacks
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            hasStacks = true;
            break;
        }
    }
    
    if (!hasStacks) {
        return "";
    }
    
    ss << "// ==========================================\n";
    ss << "    // Stack Pointer Feedback Registers\n";
    ss << "    // ==========================================\n";
    
    // Declare _next wires
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            int ptrBits = 1;
            int maxSize = headerPair.second.maxStackSize;
            while (maxSize > (1 << ptrBits)) ptrBits++;
            
            ss << "    wire [" << (ptrBits-1) << ":0] " 
               << headerPair.first.string() << "_ptr_next;\n";
        }
    }
    
    ss << "\n    // Feedback register: capture updated pointer values\n";
    ss << "    always_ff @(posedge aclk or negedge aresetn) begin\n";
    ss << "        if (!aresetn) begin\n";
    
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            ss << "            " << headerPair.first.string() << "_ptr <= 0;\n";
        }
    }
    
    ss << "        end else if (packet_valid_out) begin\n";
    
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            ss << "            " << headerPair.first.string() << "_ptr <= " 
               << headerPair.first.string() << "_ptr_next;\n";
        }
    }
    
    ss << "        end\n";
    ss << "    end\n\n";
    
    return ss.str();
}

// ======================================
// Generate Stack Pointer Connections for Action
// ======================================
std::string generateStackPointerConnections(SVProgram* program) {
    const auto& customHeaders = program->getParser()->getCustomHeaders();
    std::stringstream ss;
    
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            ss << "        ." << headerPair.first.string() << "_ptr_in(" 
               << headerPair.first.string() << "_ptr),\n";
            ss << "        ." << headerPair.first.string() << "_ptr_out(" 
               << headerPair.first.string() << "_ptr_next),\n";
        }
    }
    
    return ss.str();
}

bool Backend::processMatchActionTemplate(SVProgram* program, const std::string& outputDir) {
    BACKEND_DEBUG("Generating match_action.sv with custom header support");

    SVCodeGen codegen;
    
    // Load template
    std::string templatePath = "../src/sv/hdl/match_action.sv.in";
    std::string matchActionTemplate = loadTemplate(templatePath);
    if (matchActionTemplate.empty()) {
        BACKEND_ERROR("Failed to load match_action.sv template");
        return false;
    }
    
    // ==========================================
    // Generate Table Parameters
    // ==========================================
    auto ingress = program->getIngress();
    int matchType = 1;   // Default LPM
    int keyWidth = 32;   // Default
    
    if (ingress) {
        const auto& tables = ingress->getTables();
        if (!tables.empty()) {
            // Prefer ipv4_lpm or similar routing table as primary (same logic as generateTableLookup)
            SVTable* firstTable = tables.begin()->second;
            for (const auto& tablePair : tables) {
                std::string tname = tablePair.first.string();
                if (tname.find("ipv4") != std::string::npos || 
                    tname.find("lpm") != std::string::npos ||
                    tname.find("routing") != std::string::npos) {
                    firstTable = tablePair.second;
                    break;
                }
            }
            matchType = static_cast<int>(firstTable->getMatchType());
            keyWidth = firstTable->getKeyWidth();
            
            BACKEND_DEBUG("Table match type: " << matchType);
            BACKEND_DEBUG("Table key width: " << keyWidth);
        }
    }
    
    // Replace match parameters in template
    matchActionTemplate = replaceAll(matchActionTemplate, 
                                     "{{MATCH_TYPE}}", 
                                     std::to_string(matchType));
    matchActionTemplate = replaceAll(matchActionTemplate, 
                                     "{{KEY_WIDTH}}", 
                                     std::to_string(keyWidth));
        
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
    // Generate Stack Pointer Signals
    // ==========================================
    std::string stackPointerSignals = codegen.generateStackPointerSignals(program->getParser());

    // ==========================================
    // Generate Stack Pointer Logic
    // ==========================================
    std::string stackPointerLogic;
    if (ingress) {
        const auto& actions = ingress->getActions();
        
        // Build action ID map (action name → ID)
        std::map<int, cstring> actionIdMap;
        int actionId = 0;
        for (const auto& actionPair : actions) {
            actionIdMap[actionId] = actionPair.first;
            actionId++;
        }
        
        stackPointerLogic = codegen.generateStackPointerLogic(actions, actionIdMap);
    }

    // ==========================================
    // Generate Conditional Logic
    // ==========================================
    std::string conditionalLogic = generateConditionalLogic(program);
    
    // ==========================================
    //Generate Hash Instantiation
    // ==========================================
    std::string hashInstantiation = generateHashInstantiation(program);

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
    
    matchActionTemplate = replaceAll(matchActionTemplate,
                                 "{{STACK_POINTER_SIGNALS}}",
                                 stackPointerSignals);

    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{STACK_POINTER_LOGIC}}",
                                    stackPointerLogic);
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{CONDITIONAL_LOGIC}}",
                                    conditionalLogic);

    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{HASH_INSTANTIATION}}",
                                    hashInstantiation);

    std::string lookupLogic = generateTableLookup(program);
    if (!lookupLogic.empty()) {
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{TABLE_LOOKUP_LOGIC}}",
                                        lookupLogic);
    } else {
        // Default lookup for programs without tables
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{TABLE_LOOKUP_LOGIC}}",
                                        ".lookup_key(ipv4_dst_addr),\n"
                                        "        .lookup_key_mask(32'hFFFFFFFF),\n"
                                        "        .lookup_valid(packet_valid_in && ipv4_valid),\n");
    }

    // Generate stack pointer connections
    std::stringstream connSS;
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            connSS << "        ." << headerPair.first.string() << "_ptr(" 
                << headerPair.first.string() << "_ptr),\n";
        }
    }

    // Generate feedback logic
    std::string feedbackLogic = generateStackPointerFeedback(program);
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{STACK_POINTER_FEEDBACK}}",
                                    feedbackLogic);
    
    // Generate bidirectional connections
    std::string ptrConnections = generateStackPointerConnections(program);
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{STACK_POINTER_CONNECTIONS}}",
                                    ptrConnections);

    if (!conditionalLogic.empty()) {
        BACKEND_DEBUG("Inserted conditional logic into template");
        
        // Replace placeholder with final_action_id
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_ID_SIGNAL}}",
                                        "final_action_id");
        
        BACKEND_DEBUG("Using final_action_id for conditional override");
    } else {
        // Replace placeholder with match_action_id (no conditionals)
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_ID_SIGNAL}}",
                                        "match_action_id");
        
        BACKEND_DEBUG("Using match_action_id (no conditionals)");
    }
    
    // ==========================================
    // Generate Inline Register Logic (for firewall bloom filter)
    // ==========================================
    std::string inlineRegisterLogic = generateInlineRegisterLogic(program);
    
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{INLINE_REGISTER_LOGIC}}",
                                    inlineRegisterLogic);
    
    // Check for bloom filter registers to determine drop signal wiring
    bool hasBloomFilter = false;
    if (ingress) {
        for (const auto& reg : ingress->getRegisters()) {
            if (reg.name.string().find("bloom_filter") != std::string::npos) {
                hasBloomFilter = true;
                break;
            }
        }
    }
    
    if (hasBloomFilter) {
        BACKEND_DEBUG("Enabling bloom filter drop logic");
        
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DROP_SIGNAL_NAME}}",
                                        "action_drop");
        // Declare wire BEFORE action module
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_DROP_WIRE}}",
                                        "wire action_drop;  // Declared for bloom filter combine");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DROP_ASSIGNMENT}}",
                                        "// Combine action drop with bloom filter drop\n"
                                        "    assign drop = action_drop || bloom_filter_drop;");
    } else {
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DROP_SIGNAL_NAME}}",
                                        "drop");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_DROP_WIRE}}",
                                        "");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DROP_ASSIGNMENT}}",
                                        "// No bloom filter - drop comes directly from action");
    }


    // Check for ECMP pattern
    bool hasECMP = false;
    if (ingress) {
        for (const auto& tablePair : ingress->getTables()) {
            std::string tname = tablePair.first.string();
            if (tname.find("ecmp") != std::string::npos) {
                hasECMP = true;
                break;
            }
        }
    }
    
    if (hasECMP) {
        BACKEND_DEBUG("Enabling ECMP egress port override");
        
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{EGRESS_PORT_WIRE}}",
                                        "wire [8:0] egress_port_from_action;");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{EGRESS_PORT_ACTION_NAME}}",
                                        "egress_port_from_action");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_EGRESS_PORT}}",
                                        "assign egress_port = ecmp_final_egress_port;");
    } else {
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{EGRESS_PORT_WIRE}}",
                                        "");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{EGRESS_PORT_ACTION_NAME}}",
                                        "egress_port");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_EGRESS_PORT}}",
                                        "");
    }
    
    // ==========================================
    // Generate ECMP Logic (for load_balance.p4)
    // ==========================================
    std::string ecmpLogic = generateECMPLogic(program);
    
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{ECMP_LOGIC}}",
                                    ecmpLogic);

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

bool Backend::processActionTemplate(SVProgram* program, const std::string& outputDir) {
    BACKEND_DEBUG("Generating action.sv from template");
    
    std::string templatePath = "../src/sv/hdl/action.sv.in";
    std::string actionTemplate = loadTemplate(templatePath);
    if (actionTemplate.empty()) {
        BACKEND_ERROR("Failed to load action.sv template");
        return false;
    }
    
    const auto& customHeaders = program->getParser()->getCustomHeaders();
    
    // ==========================================
    // 1. Generate Stack Pointer INPUTS
    // ==========================================
    std::stringstream inputsSS;
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            int ptrBits = 1;
            int maxSize = headerPair.second.maxStackSize;
            while (maxSize > (1 << ptrBits)) ptrBits++;
            
            inputsSS << "    input  wire [" << (ptrBits-1) << ":0] " 
                    << headerPair.first.string() << "_ptr_in,\n";
        }
    }
    
    // ==========================================
    // 2. Generate Stack Pointer OUTPUTS
    // ==========================================
    std::stringstream outputsSS;
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            int ptrBits = 1;
            int maxSize = headerPair.second.maxStackSize;
            while (maxSize > (1 << ptrBits)) ptrBits++;
            
            outputsSS << "    output reg  [" << (ptrBits-1) << ":0] " 
                     << headerPair.first.string() << "_ptr_out,\n";
        }
    }
    
    // ==========================================
    // 3. Generate Stack Pointer RESET (for _out)
    // ==========================================
    std::stringstream resetSS;
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            resetSS << "            " << headerPair.first.string() << "_ptr_out <= 0;\n";
        }
    }
    
    // ==========================================
    // 4. Generate Stack Pointer LOGIC
    // ==========================================
    std::stringstream logicSS;
    auto ingress = program->getIngress();
    auto egress = program->getEgress();
    
    if (!customHeaders.empty()) {
        // Build action name → ID map for ingress
        std::map<cstring, int> ingressActionNameToId;
        if (ingress) {
            int actionId = 0;
            for (const auto& actionPair : ingress->getActions()) {
                ingressActionNameToId[actionPair.first] = actionId++;
            }
        }
        
        // Build action name → ID map for egress (offset by ingress count)
        std::map<cstring, int> egressActionNameToId;
        int egressActionOffset = ingressActionNameToId.size();
        if (egress) {
            int actionId = 0;
            for (const auto& actionPair : egress->getActions()) {
                egressActionNameToId[actionPair.first] = egressActionOffset + actionId++;
            }
        }
        
        // Process ingress actions
        if (ingress) {
            for (const auto& actionPair : ingress->getActions()) {
                SVAction* action = actionPair.second;
                int currentActionId = ingressActionNameToId[actionPair.first];
                std::string actionName = actionPair.first.string();
                
                // Use proper stack operation detection
                if (action->usesStackOperations()) {
                    for (const auto& stackOp : action->getStackOperations()) {
                        std::string stackName = stackOp.stackName.string();
                        
                        if (stackOp.type == StackOperation::POP_FRONT) {
                            logicSS << "                    " << currentActionId 
                                   << ": begin  // " << actionName << " (pop_front)\n";
                            if (stackOp.count == 1) {
                                logicSS << "                        " << stackName 
                                       << "_ptr_out <= " << stackName << "_ptr_in + 1;\n";
                            } else {
                                logicSS << "                        " << stackName 
                                       << "_ptr_out <= " << stackName << "_ptr_in + " 
                                       << stackOp.count << ";\n";
                            }
                            logicSS << "                    end\n";
                            
                            BACKEND_DEBUG("Action " << actionName << " uses pop_front(" 
                                        << stackOp.count << ") on " << stackName);
                        }
                        else if (stackOp.type == StackOperation::PUSH_FRONT) {
                            logicSS << "                    " << currentActionId 
                                   << ": begin  // " << actionName << " (push_front)\n";
                            // push_front DECREMENTS the pointer
                            // Also need bounds checking to prevent underflow
                            if (stackOp.count == 1) {
                                logicSS << "                        if (" << stackName 
                                       << "_ptr_in > 0)\n";
                                logicSS << "                            " << stackName 
                                       << "_ptr_out <= " << stackName << "_ptr_in - 1;\n";
                                logicSS << "                        else\n";
                                logicSS << "                            " << stackName 
                                       << "_ptr_out <= 0;  // Already at beginning\n";
                            } else {
                                logicSS << "                        if (" << stackName 
                                       << "_ptr_in >= " << stackOp.count << ")\n";
                                logicSS << "                            " << stackName 
                                       << "_ptr_out <= " << stackName << "_ptr_in - " 
                                       << stackOp.count << ";\n";
                                logicSS << "                        else\n";
                                logicSS << "                            " << stackName 
                                       << "_ptr_out <= 0;\n";
                            }
                            logicSS << "                    end\n";
                            
                            BACKEND_DEBUG("Action " << actionName << " uses push_front(" 
                                        << stackOp.count << ") on " << stackName);
                        }
                    }
                }
            }
        }
        
        // Process egress actions (link_monitor uses push_front in egress!)
        if (egress) {
            for (const auto& actionPair : egress->getActions()) {
                SVAction* action = actionPair.second;
                int currentActionId = egressActionNameToId[actionPair.first];
                std::string actionName = actionPair.first.string();
                
                if (action->usesStackOperations()) {
                    for (const auto& stackOp : action->getStackOperations()) {
                        std::string stackName = stackOp.stackName.string();
                        
                        if (stackOp.type == StackOperation::PUSH_FRONT) {
                            // For egress push_front (like link_monitor's probe_data)
                            // This happens in the egress processing section
                            BACKEND_DEBUG("Egress action " << actionName 
                                        << " uses push_front on " << stackName);
                    
                        }
                    }
                }
            }
        }
    }

    // ==========================================
    // 5. Detect Multicast Actions
    // ==========================================
    bool hasMulticast = false;
    if (ingress) {
        for (const auto& actionPair : ingress->getActions()) {
            SVAction* action = actionPair.second;
            for (const auto& assignment : action->getAssignments()) {
                if (assignment.dest.find("mcast_grp") != std::string::npos) {
                    hasMulticast = true;
                    BACKEND_DEBUG("Action " << actionPair.first << " modifies mcast_grp");
                    break;
                }
            }
            if (hasMulticast) break;
        }
    }

    // ==========================================
    // 6. Generate Egress Register Parameters
    // ==========================================
    uint8_t egressConfig = 0;

    if (egress && egress->hasRegisters()) {
        egressConfig |= 0x05;  // Bits 0,2: ENABLE_EGRESS + ENABLE_STATEFUL
        
        const auto& registers = egress->getRegisters();
        int maxRegSize = 8;
        for (const auto& reg : registers) {
            if (reg.arraySize > maxRegSize) maxRegSize = reg.arraySize;
        }
        
        actionTemplate = replaceAll(actionTemplate,
            "{{NUM_EGRESS_REGISTERS}}", std::to_string(maxRegSize));
        
        BACKEND_DEBUG("Enabled egress stateful with " << maxRegSize << " registers");
    } else {
        actionTemplate = replaceAll(actionTemplate,
            "{{NUM_EGRESS_REGISTERS}}", "8");
    }

    if (hasMulticast) {
        egressConfig |= 0x41;  // Bits 0,6: ENABLE_EGRESS + ENABLE_MCAST_PRUNING
        BACKEND_DEBUG("Enabled multicast pruning");
    }

    std::stringstream configSS;
    configSS << "8'b";
    for (int i = 7; i >= 0; i--) {
        configSS << ((egressConfig >> i) & 1);
    }
    actionTemplate = replaceAll(actionTemplate, "{{EGRESS_CONFIG}}", configSS.str());

    // ==========================================
    // 7. Replace All Placeholders
    // ==========================================
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_INPUTS}}", inputsSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_OUTPUTS}}", outputsSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_RESET_OUT}}", resetSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_LOGIC_INOUT}}", logicSS.str());
    
    // ==========================================
    // 8. Write Output File
    // ==========================================
    boost::filesystem::path outputPath = 
        boost::filesystem::path(outputDir) / "hdl" / "action.sv";
    
    std::ofstream outFile(outputPath.string());
    if (!outFile) {
        BACKEND_ERROR("Failed to create action.sv");
        return false;
    }
    
    outFile << actionTemplate;
    outFile.close();
    
    BACKEND_DEBUG("Generated action.sv");
    return true;
}

bool Backend::processEgressTemplate(SVProgram* program, const std::string& outputDir) {
    BACKEND_DEBUG("Generating egress pipeline");
    
    auto egress = program->getEgress();
    if (!egress || !egress->hasRegisters()) {
        return true;  // No egress processing needed
    }
    
    const auto& registers = egress->getRegisters();
    BACKEND_DEBUG("Egress has " << registers.size() << " register(s)");
    
    for (const auto& reg : registers) {
        BACKEND_DEBUG("  Register: " << reg.name << "[" << reg.arraySize << "] x " << reg.elementWidth << " bits");
    }
    
    return true;
}

std::string generateEgressInstance(SVProgram* program) {
    auto egress = program->getEgress();
    if (!egress || !egress->hasRegisters()) {
        return "";
    }
    
    // egress is part of match_action pipeline
    // Return empty - no separate instance needed
    return "";
}

std::string generateConstEntriesInit(SVTable* table, SVControl* control) {
    if (!table->hasConstEntries()) return "";
    
    std::stringstream ss;
    
    ss << "\n        // Const table entries\n";
    
    int entryIdx = 0;
    for (const auto& entry : table->getConstEntries()) {
        ss << "        table_mem[" << entryIdx << "].valid = 1'b1;\n";
        
        // Set key
        ss << "        table_mem[" << entryIdx << "].key = "
           << entry.keyValues[0] << ";\n";
        
        // Find action ID
        auto action = control->getAction(entry.actionName);
        if (action) {
            int actionId = control->getActionId(entry.actionName);
            ss << "        table_mem[" << entryIdx << "].action_id = 3'd"
               << actionId << ";\n";
            
            // Set action data if present
            if (!entry.actionArgs.empty()) {
                ss << "        table_mem[" << entryIdx << "].action_data = {"
                   << (128 - entry.actionArgs.size() * 32) << "'h0";
                for (const auto& arg : entry.actionArgs) {
                    ss << ", 32'" << arg;
                }
                ss << "};\n";
            }
        }
        
        entryIdx++;
    }
    
    return ss.str();
}

std::string generateMetadataSignals(SVProgram* program) {
    const auto& metadata = program->getMetadata();
    if (!metadata || metadata->totalWidth == 0) {
        return "";  // No metadata
    }
    
    std::stringstream ss;
    ss << "    // Metadata signals (" << metadata->totalWidth << " bits total)\n";
    
    for (const auto& field : metadata->fields) {
        ss << "    logic [" << (field.second.width - 1) << ":0] meta_"
           << field.first << ";\n";
    }
    
    return ss.str();
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

    // Generate action.sv
    BACKEND_DEBUG("Generating action.sv");
    if (!processActionTemplate(&svprog, options.outputDir.string())) {
        return false;
    }
    BACKEND_SUCCESS("Generated action.sv");
    
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

    if (svprog.getEgress() && svprog.getEgress()->hasRegisters()) {
        if (!processEgressTemplate(&svprog, options.outputDir.string())) {
            BACKEND_ERROR("Failed to generate egress module");
            // Non-fatal - egress is optional
        }
    }

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

    // ==========================================
    // Generate Stack Pointer Wires
    // ==========================================
    std::stringstream ptrWiresSS;
    const auto& stackHeaders = svprog.getParser()->getCustomHeaders();  // ← Different name
    for (const auto& headerPair : stackHeaders) {
        if (headerPair.second.isStack) {
            int ptrBits = 1;
            int maxSize = headerPair.second.maxStackSize;
            while (maxSize > (1 << ptrBits)) ptrBits++;
            
            ptrWiresSS << "logic [" << (ptrBits-1) << ":0] " 
                    << headerPair.first.string() << "_ptr;\n";
            ptrWiresSS << "logic [" << (ptrBits-1) << ":0] " 
                    << headerPair.first.string() << "_ptr_next;\n";
        }
    }
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{STACK_POINTER_WIRES}}", ptrWiresSS.str());

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
    std::string egressInstance = "";
    if (svprog.getEgress() && svprog.getEgress()->hasRegisters()) {
        egressInstance = generateEgressInstance(&svprog);
    }
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_PIPELINE_INSTANCE}}", egressInstance);
    
    // ==========================================
    // Generate Deparser Stack Pointer Connections
    // ==========================================
    std::stringstream deparserPtrSS;
    for (const auto& headerPair : stackHeaders) {  
        if (headerPair.second.isStack) {
            deparserPtrSS << "    ." << headerPair.first.string() << "_ptr(" 
                        << headerPair.first.string() << "_ptr_next),\n";
        }
    }
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{DEPARSER_STACK_POINTER_PORTS}}", deparserPtrSS.str());

    // Generate metadata signals// ==========================================
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{METADATA_SIGNALS}}",
                                generateMetadataSignals(&svprog));

    // ==========================================
    // Generate Deparser Egress Probe Data Wiring 
    // ==========================================
    std::stringstream deparserEgressSS;
    bool hasProbeDataStack = false;
    for (const auto& headerPair : stackHeaders) {
        std::string headerName = headerPair.first.string();
        if ((headerName == "probe_data" || headerName.find("probe_data") != std::string::npos) 
            && headerPair.second.isStack) {
            hasProbeDataStack = true;
            break;
        }
    }

    if (hasProbeDataStack) {
        deparserEgressSS << "    // Egress probe_data element (from push_front)\n";
        deparserEgressSS << "    .egress_probe_data_valid(pipeline_out_probe_data_valid),\n";
        deparserEgressSS << "    .egress_probe_data_bos(pipeline_out_probe_data_bos),\n";
        deparserEgressSS << "    .egress_probe_data_swid(pipeline_out_probe_data_swid),\n";
        deparserEgressSS << "    .egress_probe_data_port(pipeline_out_probe_data_port),\n";
        deparserEgressSS << "    .egress_probe_data_byte_cnt(pipeline_out_probe_data_byte_cnt),\n";
        deparserEgressSS << "    .egress_probe_data_last_time(pipeline_out_probe_data_last_time),\n";
        deparserEgressSS << "    .egress_probe_data_cur_time(pipeline_out_probe_data_cur_time),\n";
    }

    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{DEPARSER_EGRESS_PROBE_DATA_PORTS}}", 
                            deparserEgressSS.str());
    
    // ==========================================
    // Calculate and Replace Metadata Width
    // ==========================================
    int metadataWidth = 64;  // Default
    if (svprog.getMetadata() && svprog.getMetadata()->totalWidth > 0) {
        metadataWidth = svprog.getMetadata()->totalWidth;
        BACKEND_DEBUG("Metadata width: " << metadataWidth << " bits");
    }

    std::string metadataWidthStr = std::to_string(metadataWidth);
    std::string metadataZeros = "{" + metadataWidthStr + "{1'b0}}";

    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{METADATA_WIDTH}}", metadataWidthStr);
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{METADATA_IN}}", metadataZeros);
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{METADATA_OUT}}", "");

    BACKEND_DEBUG("Metadata connections added");

    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{CUSTOM_HEADER_PIPELINE_SIGNALS}}", 
                                codegen.generateCustomHeaderPipelineSignals(svprog.getParser()));
    
    // ==========================================
    // Generate Match-Action Stack Pointer Connections
    // ==========================================
    std::stringstream matchActionPtrSS;
    for (const auto& headerPair : stackHeaders) {
        if (headerPair.second.isStack) {
            matchActionPtrSS << "    ." << headerPair.first.string() << "_ptr_in(" 
                            << headerPair.first.string() << "_ptr),\n";
            matchActionPtrSS << "    ." << headerPair.first.string() << "_ptr_out(" 
                            << headerPair.first.string() << "_ptr_next),\n";
        }
    }
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_ACTION_STACK_POINTER_PORTS}}", matchActionPtrSS.str());

    ControlConfig controlConfig = svprog.getControlConfig();
    
    // Detect multicast for EGRESS_CONFIG
    bool hasMulticast = false;
    if (svprog.getIngress()) {
        for (const auto& actionPair : svprog.getIngress()->getActions()) {
            SVAction* action = actionPair.second;
            for (const auto& assignment : action->getAssignments()) {
                if (assignment.dest.find("mcast_grp") != std::string::npos) {
                    hasMulticast = true;
                    BACKEND_DEBUG("Action " << actionPair.first << " uses multicast");
                    break;
                }
            }
            if (hasMulticast) break;
        }
    }

    if (hasMulticast) {
        controlConfig.egressConfig |= 0x41;  // Enable egress + multicast pruning
    }

    // Handle egress configuration
    bool hasEgress = (controlConfig.egressConfig != 0);
    bool hasStateful = (controlConfig.egressConfig & 0x04) != 0;
    bool hasHash = (controlConfig.actionConfig & 0x20) != 0;
    
    std::stringstream ss;
    
    if (hasEgress) {
        vfpgaTemplate = replaceAll(vfpgaTemplate, "{{EGRESS_SIGNALS}}",
            "");
        
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

    // ==========================================
    // Generate Probe Header Wiring 
    // For link_monitor.p4: probe_t header → match_action
    // ==========================================
    std::string probeValidExpr = "1'b0";
    std::string probeHopCntExpr = "8'd0";
    
    for (const auto& headerPair : stackHeaders) {
        std::string headerName = headerPair.first.string();
        const auto& headerInfo = headerPair.second;
        
        // Check if this is a probe header (name contains "probe" or type is "probe_t")
        bool isProbeHeader = (headerName == "probe" || 
                            headerName.find("probe") != std::string::npos);
        
        // Also check element type name for stacks
        if (!isProbeHeader && !headerInfo.elementTypeName.isNullOrEmpty()) {
            std::string typeName = headerInfo.elementTypeName.string();
            isProbeHeader = (typeName.find("probe") != std::string::npos);
        }
        
        if (isProbeHeader && !headerInfo.isStack) {
            // Single probe header - wire directly
            probeValidExpr = headerName + "_valid";
            
            // Look for hop_cnt field
            for (const auto& fieldPair : headerInfo.fields) {
                std::string fieldName = fieldPair.first.string();
                if (fieldName == "hop_cnt" || fieldName == "hopCnt" || 
                    fieldName == "hop_count" || fieldName == "hops") {
                    probeHopCntExpr = headerName + "_" + fieldName;
                    BACKEND_DEBUG("Found probe header: " << headerName 
                                << " with " << fieldName << " field");
                    break;
                }
            }
            break;
        }
    }
    
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PROBE_VALID}}", probeValidExpr);
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PROBE_HOP_CNT}}", probeHopCntExpr);
    
    BACKEND_DEBUG("Probe wiring: valid=" << probeValidExpr << ", hop_cnt=" << probeHopCntExpr);
    
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