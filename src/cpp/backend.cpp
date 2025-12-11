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
// Helper: Check if action only modifies DSCP/diffserv
// ======================================
static bool isDscpOnlyAction(SVProgram* program, const std::string& actionName) {
    if (!program->getIngress()) return false;

    const auto& actions = program->getIngress()->getActions();
    auto it = actions.find(cstring(actionName));
    if (it == actions.end()) return false;

    SVAction* action = it->second;
    const auto& assignments = action->getAssignments();

    // Check if all assignments only modify diffserv
    for (const auto& assign : assignments) {
        // dest format is typically "ipv4.diffserv" or similar
        if (assign.dest.find("diffserv") == std::string::npos &&
            assign.dest.find("dscp") == std::string::npos) {
            // This action modifies something other than DSCP
            return false;
        }
    }

    // Action only modifies DSCP (or is empty)
    return !assignments.empty();
}

// ======================================
// Helper: Extract DSCP value from action
// ======================================
static int getDscpValueFromAction(SVProgram* program, const std::string& actionName) {
    if (!program->getIngress()) return 0;

    const auto& actions = program->getIngress()->getActions();
    auto it = actions.find(cstring(actionName));
    if (it == actions.end()) return 0;

    SVAction* action = it->second;
    const auto& assignments = action->getAssignments();

    for (const auto& assign : assignments) {
        if (assign.dest.find("diffserv") != std::string::npos ||
            assign.dest.find("dscp") != std::string::npos) {
            // Try to parse the source as a constant
            try {
                return std::stoi(assign.source);
            } catch (...) {
                return 0;
            }
        }
    }
    return 0;
}

// ======================================
// Helper: Detect Source Routing Pattern
// ======================================
// Source routing uses header stacks and isValid() checks.
// The pattern is: if srcRoutes[0].isValid() { srcRoute_nhop(); } else { drop(); }
// This maps to: ipv4_valid ? DROP : srcRoute_nhop
static bool isSourceRoutingPattern(SVProgram* program) {
    if (!program->getIngress()) return false;

    const auto& actions = program->getIngress()->getActions();

    // Check for srcRoute_nhop action
    bool hasSrcRouteNhop = false;
    for (const auto& action : actions) {
        std::string actionName = action.first.string();
        if (actionName.find("srcRoute") != std::string::npos ||
            actionName.find("source_route") != std::string::npos) {
            hasSrcRouteNhop = true;
            break;
        }
    }

    // Check if there's a header stack (srcRoutes, etc.) by looking at stack operations
    bool hasStackOps = false;
    for (const auto& action : actions) {
        SVAction* svAction = action.second;
        if (!svAction->getStackOperations().empty()) {
            hasStackOps = true;
            break;
        }
    }

    return hasSrcRouteNhop || hasStackOps;
}

// ======================================
// Helper: Detect Tunnel Pattern
// ======================================
// Tunnel pattern uses a custom header (myTunnel) with conditional table selection:
// - if ipv4.isValid() && !myTunnel.isValid(): ipv4_lpm.apply()
// - if myTunnel.isValid(): myTunnel_exact.apply()
// This requires dynamic lookup key selection based on header validity.
static bool isTunnelPattern(SVProgram* program) {
    if (!program->getIngress() || !program->getParser()) return false;

    const auto& tables = program->getIngress()->getTables();
    const auto& customHeaders = program->getParser()->getCustomHeaders();

    // Need at least 2 tables for tunnel pattern
    if (tables.size() < 2) return false;

    // Check for tunnel-like custom header (myTunnel, tunnel, etc.)
    bool hasTunnelHeader = false;
    std::string tunnelHeaderName;
    for (const auto& header : customHeaders) {
        std::string headerName = header.first.string();
        // Case-insensitive check for "tunnel" in header name
        std::string lowerName = headerName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        if (lowerName.find("tunnel") != std::string::npos) {
            hasTunnelHeader = true;
            tunnelHeaderName = headerName;
            BACKEND_DEBUG("Found tunnel header: " << headerName);
            break;
        }
    }

    if (!hasTunnelHeader) return false;

    // Check if we have tables that use both ipv4 and tunnel header fields as keys
    bool hasIpv4Table = false;
    bool hasTunnelTable = false;

    for (const auto& tablePair : tables) {
        SVTable* table = tablePair.second;
        auto keyFieldNames = table->getKeyFieldNames();

        for (const auto& field : keyFieldNames) {
            std::string fieldName = field.string();
            std::string lowerField = fieldName;
            std::transform(lowerField.begin(), lowerField.end(), lowerField.begin(), ::tolower);

            if (lowerField.find("ipv4") != std::string::npos &&
                (lowerField.find("dst") != std::string::npos || lowerField.find("addr") != std::string::npos)) {
                hasIpv4Table = true;
                BACKEND_DEBUG("Found IPv4 table: " << tablePair.first.string());
            }
            if (lowerField.find("tunnel") != std::string::npos) {
                hasTunnelTable = true;
                BACKEND_DEBUG("Found tunnel table: " << tablePair.first.string());
            }
        }
    }

    bool isTunnel = hasTunnelHeader && hasIpv4Table && hasTunnelTable;
    if (isTunnel) {
        BACKEND_DEBUG("Detected tunnel pattern with header: " << tunnelHeaderName);
    }

    return isTunnel;
}

// ======================================
// Feature Detection: Hash Engine Needed
// ======================================
// Returns true if program uses hash (ECMP, bloom filter, etc.)
static bool needsHashEngine(SVProgram* program) {
    if (!program->getIngress()) return false;

    const auto& actions = program->getIngress()->getActions();
    for (const auto& actionPair : actions) {
        SVAction* action = actionPair.second;
        // Check if action uses hash operations
        if (action->usesHash()) {
            BACKEND_DEBUG("Hash engine needed for action: " << actionPair.first.string());
            return true;
        }
    }
    return false;
}

// ======================================
// Feature Detection: Registers Needed
// ======================================
// Returns true if program uses stateful registers (firewall, link_monitor)
static bool needsRegisters(SVProgram* program) {
    if (!program->getIngress()) return false;

    // Check ingress registers
    if (!program->getIngress()->getRegisters().empty()) {
        BACKEND_DEBUG("Registers needed: found ingress registers");
        return true;
    }

    // Check egress registers
    if (program->getEgress() && !program->getEgress()->getRegisters().empty()) {
        BACKEND_DEBUG("Registers needed: found egress registers");
        return true;
    }

    return false;
}

// ======================================
// Feature Detection: Encap/Decap Needed
// ======================================
// Returns true if program uses stack operations (push_front, pop_front)
static bool needsEncapDecap(SVProgram* program) {
    if (!program->getIngress()) return false;

    const auto& actions = program->getIngress()->getActions();
    for (const auto& actionPair : actions) {
        SVAction* action = actionPair.second;
        if (!action->getStackOperations().empty()) {
            BACKEND_DEBUG("Encap/Decap needed for action: " << actionPair.first.string());
            return true;
        }
    }

    // Also check egress actions
    if (program->getEgress()) {
        const auto& egressActions = program->getEgress()->getActions();
        for (const auto& actionPair : egressActions) {
            SVAction* action = actionPair.second;
            if (!action->getStackOperations().empty()) {
                BACKEND_DEBUG("Encap/Decap needed for egress action: " << actionPair.first.string());
                return true;
            }
        }
    }

    return false;
}

// ======================================
// Feature Detection: Get Match Type
// ======================================
// Returns the match type: 0=Exact, 1=LPM, 2=Ternary, 3=Range
static int getMatchType(SVProgram* program) {
    if (!program->getIngress()) return 1;  // Default LPM

    const auto& tables = program->getIngress()->getTables();
    if (tables.empty()) return 1;

    // Get the primary table's match type
    for (const auto& tablePair : tables) {
        SVTable* table = tablePair.second;
        return static_cast<int>(table->getMatchType());
    }

    return 1;  // Default LPM
}

// ======================================
// Conditional Section Processing
// ======================================
// Replace {{#IF_TAG}}...{{/IF_TAG}} with content when condition is true
static std::string replaceConditionalSection(const std::string& tmpl,
                                              const std::string& tag,
                                              const std::string& content) {
    std::string result = tmpl;
    std::string startTag = "{{#" + tag + "}}";
    std::string endTag = "{{/" + tag + "}}";

    size_t startPos = result.find(startTag);
    size_t endPos = result.find(endTag);

    if (startPos != std::string::npos && endPos != std::string::npos) {
        // Replace the section including tags with content
        result.replace(startPos, endPos + endTag.length() - startPos, content);
    }

    return result;
}

// Remove {{#IF_TAG}}...{{/IF_TAG}} section entirely when condition is false
static std::string removeConditionalSection(const std::string& tmpl,
                                             const std::string& tag) {
    std::string result = tmpl;
    std::string startTag = "{{#" + tag + "}}";
    std::string endTag = "{{/" + tag + "}}";

    size_t startPos = result.find(startTag);
    size_t endPos = result.find(endTag);

    if (startPos != std::string::npos && endPos != std::string::npos) {
        // Remove the section including tags
        result.erase(startPos, endPos + endTag.length() - startPos);
    }

    return result;
}

// ======================================
// Helper: Get Tunnel Header Info
// ======================================
// Returns the tunnel header name and key field name
static std::pair<std::string, std::string> getTunnelHeaderInfo(SVProgram* program) {
    const auto& customHeaders = program->getParser()->getCustomHeaders();

    for (const auto& header : customHeaders) {
        std::string headerName = header.first.string();
        std::string lowerName = headerName;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

        if (lowerName.find("tunnel") != std::string::npos) {
            // Find the dst_id field (key field for tunnel lookup)
            for (const auto& field : header.second.fields) {
                std::string fieldName = field.first.string();
                std::string lowerField = fieldName;
                std::transform(lowerField.begin(), lowerField.end(), lowerField.begin(), ::tolower);

                if (lowerField.find("dst") != std::string::npos) {
                    return {headerName, fieldName};
                }
            }
            // Fallback: return first field
            if (!header.second.fields.empty()) {
                return {headerName, header.second.fields.begin()->first.string()};
            }
        }
    }

    return {"", ""};
}

// ======================================
// Generate Lookup Key Selection for Tunnel
// ======================================
static std::string generateTunnelLookupKeySelection(SVProgram* program) {
    auto tunnelInfo = getTunnelHeaderInfo(program);
    std::string tunnelHeaderName = tunnelInfo.first;
    std::string tunnelKeyField = tunnelInfo.second;

    if (tunnelHeaderName.empty()) return "";

    // Get the field width
    const auto& customHeaders = program->getParser()->getCustomHeaders();
    int tunnelKeyWidth = 16;  // Default

    for (const auto& header : customHeaders) {
        if (header.first.string() == tunnelHeaderName) {
            for (const auto& field : header.second.fields) {
                if (field.first.string() == tunnelKeyField) {
                    tunnelKeyWidth = field.second.width;
                    break;
                }
            }
            break;
        }
    }

    int paddingBits = 32 - tunnelKeyWidth;

    std::stringstream ss;
    ss << "    // ==========================================\n";
    ss << "    // Lookup Key Selection for Tunnel Support\n";
    ss << "    // ==========================================\n";
    ss << "    // " << tunnelHeaderName << " packets: use " << tunnelKeyField << " in MSBs (for LPM prefix=" << tunnelKeyWidth << " match)\n";
    ss << "    // Regular IPv4:     use ipv4_dst_addr\n";
    ss << "    wire [31:0] selected_lookup_key;\n";
    ss << "    assign selected_lookup_key = " << tunnelHeaderName << "_valid ? {"
       << tunnelHeaderName << "_" << tunnelKeyField << ", " << paddingBits << "'b0} : ipv4_dst_addr;\n\n";

    BACKEND_DEBUG("Generated tunnel lookup key selection for " << tunnelHeaderName << "_" << tunnelKeyField);

    return ss.str();
}

// ======================================
// Generate Conditional Logic
// ======================================

std::string generateConditionalLogic(SVProgram* program) {
    // Special case: Tunnel pattern (check BEFORE g_detectedIfElse empty check)
    // For tunneling, we need dynamic lookup key selection based on header validity
    // Tunnel programs may not have explicit if-else in P4 but still need key selection
    if (isTunnelPattern(program)) {
        BACKEND_DEBUG("Detected tunnel pattern - generating lookup key selection");
        return generateTunnelLookupKeySelection(program);
    }

    if (g_detectedIfElse.empty()) {
        return "";
    }

    BACKEND_DEBUG("Generating conditional logic for " << g_detectedIfElse.size() << " if-else statement(s)");

    // Special case: Source routing pattern
    // For source routing, we use packet type detection instead of header field comparison
    if (isSourceRoutingPattern(program)) {
        BACKEND_DEBUG("Detected source routing pattern - using simplified logic");

        std::stringstream ss;
        ss << "\n    // ==========================================\n";
        ss << "    //          Conditional Action Selection\n";
        ss << "    // ==========================================\n";
        ss << "    // Source Routing Action Logic:\n";
        ss << "    // - Source routed packets (eth_type=0x1234, ipv4_valid=0): use srcRoute_nhop action (2)\n";
        ss << "    // - Regular IPv4 packets (eth_type=0x0800, ipv4_valid=1): DROP (no srcRoutes)\n";
        ss << "    //\n";
        ss << "    // Detection: use match_ipv4_valid which is already pipelined by match module\n\n";

        // Use fixed action IDs that match action.sv localparams:
        // ACTION_DROP = 4'd1, srcRoute_nhop is handled as action_id=2 in action.sv case statement
        // The action module has hardcoded handling for these IDs
        int dropActionId = 1;       // ACTION_DROP in action.sv
        int srcRouteActionId = 2;   // srcRoute_nhop case in action.sv

        ss << "    // Final action selection based on packet type\n";
        ss << "    wire [3:0] final_action_id;\n";
        ss << "    assign final_action_id = match_ipv4_valid ? 4'd" << dropActionId << " :  // Regular IPv4 -> DROP\n";
        ss << "                                                4'd" << srcRouteActionId << ";   // Source routed -> srcRoute_nhop\n\n";

        return ss.str();
    }

    std::stringstream ss;

    // Separate DSCP-only conditionals from action-override conditionals
    std::vector<std::tuple<std::string, std::string, int>> dscpConditions;  // (condition, hwSignal, dscpValue)
    std::vector<std::tuple<std::string, std::string, int, int>> actionConditions;  // (condition, hwSignal, trueActionId, falseActionId)

    // Get action list to map names to IDs
    const auto& actions = program->getIngress()->getActions();
    std::map<std::string, int> actionNameToId;

    int actionIdx = 0;
    for (const auto& action : actions) {
        actionNameToId[action.first.string()] = actionIdx;
        actionIdx++;
    }

    // Classify each conditional
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
            bool isHeaderStack = false;
            int stackIndex = 0;

            if (auto member = left->to<IR::Member>()) {
                fieldName = member->member.string();

                // Try to determine header type from the expression
                if (auto pathExpr = member->expr->to<IR::Member>()) {
                    // Pattern: hdr.ipv4.protocol or hdr.tcp.dstPort
                    headerType = pathExpr->member.string();
                } else if (auto arrayIndex = member->expr->to<IR::ArrayIndex>()) {
                    // Pattern: hdr.srcRoutes[0].bos (header stack access)
                    isHeaderStack = true;
                    if (auto constant = arrayIndex->right->to<IR::Constant>()) {
                        stackIndex = constant->asInt();
                    }
                    if (auto stackMember = arrayIndex->left->to<IR::Member>()) {
                        headerType = stackMember->member.string();
                    }
                    BACKEND_DEBUG("  Detected header stack access: " << headerType << "[" << stackIndex << "]." << fieldName);
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
                } else if (fieldName == "bos") {
                    bitWidth = 1;  // Bottom-of-stack bit
                } else if (fieldName == "port") {
                    bitWidth = 15;  // Source routing port field
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
                // ==========================================
                // MAP TO HARDWARE SIGNAL
                // ==========================================
                std::string hwSignal;

                // Map based on header type and field name
                if (isHeaderStack) {
                    // Header stack: srcRoutes[0].bos -> srcRoutes_bos[0]
                    hwSignal = headerType + "_" + fieldName + "[" + std::to_string(stackIndex) + "]";
                    BACKEND_DEBUG("  Header stack signal: " << hwSignal);
                } else if (headerType == "ipv4" || headerType == "ipv6") {
                    hwSignal = headerType + "_" + fieldName;
                } else if (headerType == "tcp") {
                    if (fieldName == "srcPort") {
                        hwSignal = "ipv4_src_port";
                    } else if (fieldName == "dstPort") {
                        hwSignal = "ipv4_dst_port";
                    } else {
                        hwSignal = "tcp_" + fieldName;
                    }
                } else if (headerType == "udp") {
                    if (fieldName == "srcPort") {
                        hwSignal = "ipv4_src_port";
                    } else if (fieldName == "dstPort") {
                        hwSignal = "ipv4_dst_port";
                    } else {
                        hwSignal = "udp_" + fieldName;
                    }
                } else {
                    hwSignal = "ipv4_" + fieldName;
                }

                // Build condition string
                std::string condStr = "(" + hwSignal + " == " + std::to_string(bitWidth) + "'d" + compareValue + ")";

                // Check if this is a DSCP-only action
                std::string trueActionName = ifElse.trueAction.string();
                if (isDscpOnlyAction(program, trueActionName)) {
                    int dscpValue = getDscpValueFromAction(program, trueActionName);
                    dscpConditions.push_back(std::make_tuple(condStr, hwSignal, dscpValue));

                    BACKEND_DEBUG("  DSCP-only conditional: " << headerType << "." << fieldName
                                << " == " << compareValue << " → DSCP=" << dscpValue);
                } else {
                    // Regular action override
                    int trueActionId = 0;
                    int falseActionId = 0;

                    auto trueIt = actionNameToId.find(trueActionName);
                    if (trueIt != actionNameToId.end()) {
                        trueActionId = trueIt->second;
                    }

                    if (!ifElse.falseAction.isNullOrEmpty()) {
                        auto falseIt = actionNameToId.find(ifElse.falseAction.string());
                        if (falseIt != actionNameToId.end()) {
                            falseActionId = falseIt->second;
                        }
                    }

                    actionConditions.push_back(std::make_tuple(condStr, hwSignal, trueActionId, falseActionId));

                    BACKEND_DEBUG("  Action-override conditional: " << headerType << "." << fieldName
                                << " == " << compareValue
                                << " → true=" << ifElse.trueAction << " (id=" << trueActionId << ")"
                                << ", false=" << ifElse.falseAction << " (id=" << falseActionId << ")");
                }
            }
        }
    }

    // ==========================================
    // Generate DSCP Override Logic (Post-Action)
    // ==========================================
    if (!dscpConditions.empty()) {
        ss << "\n    // ==========================================\n";
        ss << "    //          QoS DSCP Override Logic\n";
        ss << "    // ==========================================\n";
        ss << "    // Post-action DSCP modification based on protocol\n";
        ss << "    // Allows forwarding action to execute normally,\n";
        ss << "    // then overrides DSCP field based on conditions\n\n";

        // Pipeline protocol detection to align with action output (3 cycles)
        ss << "    // Pipeline protocol detection to align with action output (3 cycles)\n";
        ss << "    reg [7:0] proto_d1, proto_d2, proto_d3;\n";
        ss << "    reg ipv4_valid_d1, ipv4_valid_d2, ipv4_valid_d3;\n\n";

        ss << "    always @(posedge aclk) begin\n";
        ss << "        if (!aresetn) begin\n";
        ss << "            proto_d1 <= 8'd0;\n";
        ss << "            proto_d2 <= 8'd0;\n";
        ss << "            proto_d3 <= 8'd0;\n";
        ss << "            ipv4_valid_d1 <= 1'b0;\n";
        ss << "            ipv4_valid_d2 <= 1'b0;\n";
        ss << "            ipv4_valid_d3 <= 1'b0;\n";
        ss << "        end else begin\n";
        ss << "            proto_d1 <= ipv4_protocol;\n";
        ss << "            proto_d2 <= proto_d1;\n";
        ss << "            proto_d3 <= proto_d2;\n";
        ss << "            ipv4_valid_d1 <= ipv4_valid;\n";
        ss << "            ipv4_valid_d2 <= ipv4_valid_d1;\n";
        ss << "            ipv4_valid_d3 <= ipv4_valid_d2;\n";
        ss << "        end\n";
        ss << "    end\n\n";

        // Generate condition wires
        int qosCondId = 0;
        for (const auto& cond : dscpConditions) {
            qosCondId++;
            std::string condStr = std::get<0>(cond);
            int dscpValue = std::get<2>(cond);

            // Replace the original signal with the delayed version
            std::string delayedCond = condStr;
            size_t pos = delayedCond.find("ipv4_protocol");
            if (pos != std::string::npos) {
                delayedCond.replace(pos, 13, "proto_d3");
            }

            ss << "    // QoS Condition #" << qosCondId << ": DSCP = " << dscpValue << "\n";
            ss << "    wire qos_cond_" << qosCondId << "_match;\n";
            ss << "    assign qos_cond_" << qosCondId << "_match = ipv4_valid_d3 && " << delayedCond << ";\n\n";
        }

        // Generate DSCP override mux
        // Note: action_ipv4_diffserv will be connected from action module output
        ss << "    // DSCP value from action module (before override)\n";
        ss << "    wire [5:0] action_ipv4_diffserv;\n\n";

        ss << "    // Final DSCP with QoS override\n";
        ss << "    wire [5:0] qos_ipv4_diffserv;\n";
        ss << "    assign qos_ipv4_diffserv = \n";

        qosCondId = 0;
        for (const auto& cond : dscpConditions) {
            qosCondId++;
            int dscpValue = std::get<2>(cond);
            ss << "        qos_cond_" << qosCondId << "_match ? 6'd" << dscpValue << " :\n";
        }
        ss << "        action_ipv4_diffserv;  // Default: use action output\n\n";

        BACKEND_DEBUG("Generated QoS DSCP override logic with " << dscpConditions.size() << " condition(s)");
    }

    // ==========================================
    // Generate Action Override Logic (if any)
    // ==========================================
    if (!actionConditions.empty()) {
        ss << "\n    // ==========================================\n";
        ss << "    //          Conditional Action Selection\n";
        ss << "    // ==========================================\n";
        ss << "    // Overrides table action when conditions match\n\n";

        int condId = 0;
        for (const auto& cond : actionConditions) {
            condId++;
            std::string condStr = std::get<0>(cond);
            int trueActionId = std::get<2>(cond);
            int falseActionId = std::get<3>(cond);

            ss << "    // Conditional #" << condId << "\n";
            ss << "    wire cond_" << condId << "_match;\n";
            ss << "    wire [3:0] cond_" << condId << "_action;\n";
            ss << "    assign cond_" << condId << "_match = " << condStr << ";\n";
            ss << "    assign cond_" << condId << "_action = cond_" << condId << "_match ? 4'd"
               << trueActionId << " : 4'd" << falseActionId << ";\n\n";
        }

        ss << "    // Action Override Logic\n";
        ss << "    wire conditional_override;\n";
        ss << "    wire [3:0] conditional_action_id;\n\n";

        if (condId == 1) {
            ss << "    assign conditional_override = cond_1_match;\n";
            ss << "    assign conditional_action_id = cond_1_action;\n\n";
        } else {
            ss << "    assign conditional_override = ";
            for (int i = 1; i <= condId; i++) {
                if (i > 1) ss << " || ";
                ss << "cond_" << i << "_match";
            }
            ss << ";\n\n";

            ss << "    assign conditional_action_id = \n";
            for (int i = 1; i <= condId; i++) {
                ss << "        cond_" << i << "_match ? cond_" << i << "_action :\n";
            }
            ss << "        4'd0;  // NoAction if no match\n\n";
        }

        ss << "    // Final action selection: conditional overrides table\n";
        ss << "    wire [3:0] final_action_id;\n";
        ss << "    assign final_action_id = conditional_override ? conditional_action_id : match_action_id;\n\n";

        BACKEND_DEBUG("Generated conditional action override logic with " << actionConditions.size() << " condition(s)");
    }

    return ss.str();
}

// ======================================
// Helper: Check if there are DSCP-only conditionals
// ======================================
static bool hasDscpOnlyConditionals(SVProgram* program) {
    if (g_detectedIfElse.empty()) {
        return false;
    }

    for (const auto& ifElse : g_detectedIfElse) {
        if (ifElse.controlName != "MyIngress") {
            continue;
        }

        std::string trueActionName = ifElse.trueAction.string();
        if (isDscpOnlyAction(program, trueActionName)) {
            return true;
        }
    }
    return false;
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
    
    // Define static modules (match.sv is processed separately with custom headers)
    std::map<std::string, std::string> staticModules = {
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

// ======================================
// Process Modular Match Template
// ======================================
// Generates exact_match.sv or lpm_match.sv based on match type

bool Backend::processModularMatchTemplate(SVProgram* program, const std::string& outputDir) {
    BACKEND_DEBUG("Processing modular match template");

    // Determine match type
    int matchType = getMatchType(program);
    std::string templateName;
    std::string outputName;

    switch (matchType) {
        case 0:  // Exact
            templateName = "exact_match.sv.in";
            outputName = "exact_match.sv";
            break;
        case 1:  // LPM
        default:
            templateName = "lpm_match.sv.in";
            outputName = "lpm_match.sv";
            break;
    }

    // Load template
    std::string matchTemplate = loadTemplate("../src/sv/hdl/" + templateName);
    if (matchTemplate.empty()) {
        BACKEND_ERROR("Failed to load " << templateName);
        return false;
    }

    // Get custom headers for pass-through
    const auto& customHeaders = program->getParser()->getCustomHeaders();

    // Generate custom header inputs/outputs for pass-through
    std::stringstream customInputs;
    std::stringstream customOutputs;
    std::stringstream customRegs;
    std::stringstream customRegResets;
    std::stringstream customRegAssigns;
    std::stringstream customOutResets;
    std::stringstream customOutAssigns;

    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

        // Only process non-stack headers (like probe)
        if (!headerInfo.isStack) {
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;

                customInputs << "    input  wire [" << (field.width - 1) << ":0]           "
                             << headerName << "_" << fieldName << "_in,\n";

                customOutputs << "    output reg  [" << (field.width - 1) << ":0]           "
                              << headerName << "_" << fieldName << "_out,\n";

                customRegs << "    reg  [" << (field.width - 1) << ":0]                   "
                           << headerName << "_" << fieldName << "_d1;\n";

                customRegResets << "            " << headerName << "_" << fieldName << "_d1  <= "
                                << field.width << "'b0;\n";

                customRegAssigns << "            " << headerName << "_" << fieldName << "_d1  <= "
                                 << headerName << "_" << fieldName << "_in;\n";

                customOutResets << "            " << headerName << "_" << fieldName << "_out <= "
                                << field.width << "'b0;\n";

                customOutAssigns << "            " << headerName << "_" << fieldName << "_out <= "
                                 << headerName << "_" << fieldName << "_d1;\n";
            }
            // Valid signal
            customInputs << "    input  wire                           " << headerName << "_valid_in,\n";
            customOutputs << "    output reg                            " << headerName << "_valid_out,\n";
            customRegs << "    reg                           " << headerName << "_valid_d1;\n";
            customRegResets << "            " << headerName << "_valid_d1   <= 1'b0;\n";
            customRegAssigns << "            " << headerName << "_valid_d1   <= " << headerName << "_valid_in;\n";
            customOutResets << "            " << headerName << "_valid_out  <= 1'b0;\n";
            customOutAssigns << "            " << headerName << "_valid_out  <= " << headerName << "_valid_d1;\n";
        }
    }

    // Replace placeholders
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_INPUTS}}", customInputs.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_OUTPUTS}}", customOutputs.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_REGS}}", customRegs.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_REG_RESETS}}", customRegResets.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_REG_ASSIGNS}}", customRegAssigns.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_OUT_RESETS}}", customOutResets.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_OUT_ASSIGNS}}", customOutAssigns.str());

    // Write output
    boost::filesystem::path hdlDir = boost::filesystem::path(outputDir) / "hdl";
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }

    std::string outputPath = (hdlDir / outputName).string();
    std::ofstream ofs(outputPath);
    if (!ofs.is_open()) {
        BACKEND_ERROR("Failed to create " << outputName);
        return false;
    }
    ofs << matchTemplate;
    ofs.close();

    BACKEND_DEBUG("Generated " << outputName << " (match type: " << matchType << ")");
    return true;
}

// ======================================
// Process Action Engine Template
// ======================================

bool Backend::processActionEngineTemplate(SVProgram* program, const std::string& outputDir) {
    BACKEND_DEBUG("Processing action_engine.sv template");

    // Load template
    std::string actionTemplate = loadTemplate("../src/sv/hdl/action_engine.sv.in");
    if (actionTemplate.empty()) {
        BACKEND_ERROR("Failed to load action_engine.sv.in template");
        return false;
    }

    // Detect features needed
    bool enableHash = needsHashEngine(program);
    bool enableRegisters = needsRegisters(program);
    bool enableEncap = needsEncapDecap(program);
    bool enableDecap = needsEncapDecap(program);

    // Replace feature flags (empty strings for now - these will be filled by vfpga_top)
    actionTemplate = replaceAll(actionTemplate, "{{ACTION_CUSTOM_INPUTS}}", "");
    actionTemplate = replaceAll(actionTemplate, "{{ACTION_CUSTOM_OUTPUTS}}", "");
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_INPUTS}}", "");
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_OUTPUTS}}", "");
    actionTemplate = replaceAll(actionTemplate, "{{ACTION_CUSTOM_LOGIC}}", "");

    // Write output
    boost::filesystem::path hdlDir = boost::filesystem::path(outputDir) / "hdl";
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }

    std::string outputPath = (hdlDir / "action_engine.sv").string();
    std::ofstream ofs(outputPath);
    if (!ofs.is_open()) {
        BACKEND_ERROR("Failed to create action_engine.sv");
        return false;
    }
    ofs << actionTemplate;
    ofs.close();

    BACKEND_DEBUG("Generated action_engine.sv (hash=" << enableHash
                  << ", registers=" << enableRegisters
                  << ", encap=" << enableEncap << ")");
    return true;
}

// ======================================
// Process Match Module Template (Legacy)
// ======================================

bool Backend::processMatchTemplate(SVProgram* program, const std::string& outputDir) {
    BACKEND_DEBUG("Processing match.sv template (legacy)");

    // Load template
    std::string matchTemplate = loadTemplate("../src/sv/hdl/match.sv.in");
    if (matchTemplate.empty()) {
        BACKEND_ERROR("Failed to load match.sv.in template");
        return false;
    }

    // Get custom headers
    const auto& customHeaders = program->getParser()->getCustomHeaders();

    // Generate custom header inputs (for non-stack headers only: probe)
    std::stringstream customInputs;
    std::stringstream customOutputs;
    std::stringstream customRegs;
    std::stringstream customRegResets;
    std::stringstream customRegAssigns;
    std::stringstream customOutResets;
    std::stringstream customOutAssigns;

    if (!customHeaders.empty()) {
        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

            // Only process non-stack headers (like probe)
            // Stack headers (probe_data, probe_fwd) pass through match_action directly
            if (!headerInfo.isStack) {
                // Generate input ports
                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();
                    const SVParser::CustomHeaderField& field = fieldPair.second;

                    customInputs << "    input  wire [" << (field.width - 1) << ":0]           "
                                 << headerName << "_" << fieldName << "_in,\n";

                    customOutputs << "    output reg  [" << (field.width - 1) << ":0]           "
                                  << headerName << "_" << fieldName << "_out,\n";

                    customRegs << "    reg  [" << (field.width - 1) << ":0]                   "
                               << headerName << "_" << fieldName << "_d1;\n";

                    customRegResets << "            " << headerName << "_" << fieldName << "_d1  <= "
                                    << field.width << "'b0;\n";

                    customRegAssigns << "            " << headerName << "_" << fieldName << "_d1  <= "
                                     << headerName << "_" << fieldName << "_in;\n";

                    customOutResets << "            " << headerName << "_" << fieldName << "_out <= "
                                    << field.width << "'b0;\n";

                    customOutAssigns << "            " << headerName << "_" << fieldName << "_out <= "
                                     << headerName << "_" << fieldName << "_d1;\n";
                }
                // Valid signal
                customInputs << "    input  wire                           " << headerName << "_valid_in,\n";
                customOutputs << "    output reg                            " << headerName << "_valid_out,\n";
                customRegs << "    reg                           " << headerName << "_valid_d1;\n";
                customRegResets << "            " << headerName << "_valid_d1   <= 1'b0;\n";
                customRegAssigns << "            " << headerName << "_valid_d1   <= " << headerName << "_valid_in;\n";
                customOutResets << "            " << headerName << "_valid_out  <= 1'b0;\n";
                customOutAssigns << "            " << headerName << "_valid_out  <= " << headerName << "_valid_d1;\n";
            }
        }
    }

    // Replace placeholders
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_INPUTS}}", customInputs.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_OUTPUTS}}", customOutputs.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_REGS}}", customRegs.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_REG_RESETS}}", customRegResets.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_REG_ASSIGNS}}", customRegAssigns.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_OUT_RESETS}}", customOutResets.str());
    matchTemplate = replaceAll(matchTemplate, "{{MATCH_CUSTOM_HEADER_OUT_ASSIGNS}}", customOutAssigns.str());

    // Write output
    boost::filesystem::path hdlDir = boost::filesystem::path(outputDir) / "hdl";
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }

    std::string outputPath = (hdlDir / "match.sv").string();
    std::ofstream ofs(outputPath);
    if (!ofs.is_open()) {
        BACKEND_ERROR("Failed to create match.sv");
        return false;
    }
    ofs << matchTemplate;
    ofs.close();

    BACKEND_DEBUG("Generated match.sv with custom headers");
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

    // Add pipeline registers to align ECMP signals with action output (3-cycle delay)
    ss << "    // Pipeline registers to align ECMP signals with action output (3-cycle delay)\n";
    ss << "    // Stage 1-2: align with match output, Stage 3: align with action output\n";
    ss << "    reg ecmp_active_d1, ecmp_active_d2, ecmp_active_d3;\n";
    ss << "    reg [31:0] flow_hash_d1, flow_hash_d2, flow_hash_d3;\n";
    ss << "    reg match_hit_d1;\n\n";

    ss << "    always @(posedge aclk or negedge aresetn) begin\n";
    ss << "        if (!aresetn) begin\n";
    ss << "            ecmp_active_d1 <= 1'b0;\n";
    ss << "            ecmp_active_d2 <= 1'b0;\n";
    ss << "            ecmp_active_d3 <= 1'b0;\n";
    ss << "            flow_hash_d1   <= 32'd0;\n";
    ss << "            flow_hash_d2   <= 32'd0;\n";
    ss << "            flow_hash_d3   <= 32'd0;\n";
    ss << "            match_hit_d1   <= 1'b0;\n";
    ss << "        end else begin\n";
    ss << "            // Stage 1: delay inputs\n";
    ss << "            ecmp_active_d1 <= packet_valid_in && ipv4_valid &&\n";
    ss << "                             (ipv4_protocol == 8'd6) && (ipv4_ttl > 8'd0);\n";
    ss << "            flow_hash_d1   <= flow_hash;\n";
    ss << "            // Stage 2: align with match output\n";
    ss << "            ecmp_active_d2 <= ecmp_active_d1;\n";
    ss << "            flow_hash_d2   <= flow_hash_d1;\n";
    ss << "            // Stage 3: align with action output (one more cycle)\n";
    ss << "            ecmp_active_d3 <= ecmp_active_d2;\n";
    ss << "            flow_hash_d3   <= flow_hash_d2;\n";
    ss << "            match_hit_d1   <= match_hit;\n";
    ss << "        end\n";
    ss << "    end\n\n";

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
    
    // Try pattern matching for "header.field" FIRST (more specific)
    size_t dotPos = p4FieldName.find('.');
    if (dotPos != std::string::npos) {
        std::string headerName = p4FieldName.substr(0, dotPos);
        std::string fieldName = p4FieldName.substr(dotPos + 1);

        // Check if it's a custom header
        if (customHeaders.count(cstring(headerName))) {
            return headerName + "_" + fieldName;
        }

        // Standard header mappings with proper signal names
        if (headerName == "ethernet" || headerName == "eth") {
            if (fieldName == "dstAddr") return "eth_dst_addr";
            if (fieldName == "srcAddr") return "eth_src_addr";
            if (fieldName == "etherType") return "eth_type";
        }
        if (headerName == "ipv4") {
            if (fieldName == "dstAddr") return "ipv4_dst_addr";
            if (fieldName == "srcAddr") return "ipv4_src_addr";
            if (fieldName == "protocol") return "ipv4_protocol";
            if (fieldName == "ttl") return "ipv4_ttl";
            if (fieldName == "diffserv") return "ipv4_diffserv";
            if (fieldName == "ecn") return "ipv4_ecn";
        }
        if (headerName == "tcp" || headerName == "udp") {
            if (fieldName == "srcPort") return headerName + "_src_port";
            if (fieldName == "dstPort") return headerName + "_dst_port";
        }

        // Default: use header_field format
        return headerName + "_" + fieldName;
    }

    // Fallback for simple field names without header prefix (legacy behavior)
    if (p4FieldName == "dstAddr") return "ipv4_dst_addr";
    if (p4FieldName == "srcAddr") return "ipv4_src_addr";
    if (p4FieldName == "protocol") return "ipv4_protocol";
    if (p4FieldName == "op") return "p4calc_op";  // For calc.p4
    
    // Default: return as-is with underscores
    std::string signal = p4FieldName;
    std::replace(signal.begin(), signal.end(), '.', '_');
    return signal;
}

// ======================================
// Generate Inline Register Operations
// For firewall bloom filter pattern
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
    ss << "    // Key insight: Use canonical hash so both directions produce same indices\n";
    ss << "    // ==========================================\n\n";
    
    // Declare registers with initialization
    for (const auto& regName : bloomFilterRegs) {
        ss << "    reg [0:0] " << regName << " [0:4095];\n";
    }
    ss << "\n";
    
    // Initialize bloom filter arrays
    ss << "    // Initialize bloom filter arrays\n";
    ss << "    initial begin\n";
    ss << "        for (int i = 0; i < 4096; i++) begin\n";
    for (const auto& regName : bloomFilterRegs) {
        ss << "            " << regName << "[i] = 1'b0;\n";
    }
    ss << "        end\n";
    ss << "    end\n\n";
    
    // Canonical hash - order IPs and ports so both directions produce same hash
    ss << "    // Canonical 5-tuple hash - order IPs and ports so both directions match\n";
    ss << "    // This ensures outbound (A→B) and inbound reply (B→A) hash to same indices\n";
    ss << "    wire [31:0] ip_min  = (ipv4_src_addr < ipv4_dst_addr) ? ipv4_src_addr : ipv4_dst_addr;\n";
    ss << "    wire [31:0] ip_max  = (ipv4_src_addr < ipv4_dst_addr) ? ipv4_dst_addr : ipv4_src_addr;\n";
    ss << "    wire [15:0] port_min = (ipv4_src_port < ipv4_dst_port) ? ipv4_src_port : ipv4_dst_port;\n";
    ss << "    wire [15:0] port_max = (ipv4_src_port < ipv4_dst_port) ? ipv4_dst_port : ipv4_src_port;\n";
    ss << "    \n";
    ss << "    wire [31:0] bloom_hash = ip_min ^ ip_max ^ {port_min, port_max} ^ {24'd0, ipv4_protocol};\n";
    ss << "    \n";
    ss << "    wire [11:0] reg_pos_one = bloom_hash[11:0];\n";
    ss << "    wire [11:0] reg_pos_two = bloom_hash[11:0] ^ 12'hA5A;\n\n";
    
    // Direction signal
    ss << "    // Direction: 0=outbound (set bloom), 1=inbound (check bloom)\n";
    ss << "    // Port 0 = external interface → inbound traffic (direction=1)\n";
    ss << "    // Port 1+ = internal interfaces → outbound traffic (direction=0)\n";
    ss << "    wire direction;\n";
    ss << "    assign direction = (ingress_port == 9'd0) ? 1'b1 : 1'b0;\n\n";
    
    // Combinational reads for drop decision
    ss << "    // Combinational reads - must be evaluated same cycle as packet_valid_in\n";
    ss << "    wire bloom_val_one = " << bloomFilterRegs[0] << "[reg_pos_one];\n";
    ss << "    wire bloom_val_two = " << bloomFilterRegs[1] << "[reg_pos_two];\n\n";
    
    // Bloom filter write logic
    ss << "    // Bloom filter write (outbound TCP packets only)\n";
    ss << "    always_ff @(posedge aclk) begin\n";
    ss << "        if (packet_valid_in && ipv4_valid && ipv4_protocol == 8'd6 && direction == 1'b0) begin\n";
    ss << "            " << bloomFilterRegs[0] << "[reg_pos_one] <= 1'b1;\n";
    ss << "            " << bloomFilterRegs[1] << "[reg_pos_two] <= 1'b1;\n";
    ss << "        end\n";
    ss << "    end\n\n";
    
    // Combinational drop decision
    ss << "    // Bloom filter drop decision - fully combinational\n";
    ss << "    wire bloom_filter_drop_comb;\n";
    ss << "    assign bloom_filter_drop_comb = (direction == 1'b1) &&           // Inbound\n";
    ss << "                                    (ipv4_protocol == 8'd6) &&       // TCP\n";
    ss << "                                    packet_valid_in && ipv4_valid && \n";
    ss << "                                    (!bloom_val_one || !bloom_val_two);\n\n";
    
    // Latched values for pipeline alignment
    ss << "    // Latch bloom filter values when packet arrives for pipeline alignment\n";
    ss << "    reg bloom_val_one_lat, bloom_val_two_lat, direction_lat, is_tcp_lat;\n\n";
    
    ss << "    always_ff @(posedge aclk or negedge aresetn) begin\n";
    ss << "        if (!aresetn) begin\n";
    ss << "            bloom_val_one_lat <= 1'b1;\n";
    ss << "            bloom_val_two_lat <= 1'b1;\n";
    ss << "            direction_lat <= 1'b0;\n";
    ss << "            is_tcp_lat <= 1'b0;\n";
    ss << "        end else if (packet_valid_in && ipv4_valid) begin\n";
    ss << "            bloom_val_one_lat <= bloom_val_one;\n";
    ss << "            bloom_val_two_lat <= bloom_val_two;\n";
    ss << "            direction_lat <= direction;\n";
    ss << "            is_tcp_lat <= (ipv4_protocol == 8'd6);\n";
    ss << "        end else if (packet_valid_out) begin\n";
    ss << "            // Clear after packet exits pipeline\n";
    ss << "            bloom_val_one_lat <= 1'b1;\n";
    ss << "            bloom_val_two_lat <= 1'b1;\n";
    ss << "            direction_lat <= 1'b0;\n";
    ss << "            is_tcp_lat <= 1'b0;\n";
    ss << "        end\n";
    ss << "    end\n\n";
    
    // Compute drop from latched values (aligned with action module output)
    ss << "    // Compute drop from latched values (aligned with action module output)\n";
    ss << "    wire bloom_drop_latched;\n";
    ss << "    assign bloom_drop_latched = direction_lat && is_tcp_lat &&\n";
    ss << "                               (!bloom_val_one_lat || !bloom_val_two_lat);\n\n";
    
    // Final bloom_filter_drop signal
    ss << "    // Final bloom filter drop signal\n";
    ss << "    wire bloom_filter_drop;\n";
    ss << "    assign bloom_filter_drop = bloom_drop_latched;\n\n";
    
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

    // ECMP select from hash - use delayed version for proper pipeline alignment
    ss << "    // ECMP selection from 5-tuple hash (use delayed hash aligned with action output)\n";
    ss << "    wire [13:0] ecmp_select;\n";
    ss << "    assign ecmp_select = flow_hash_d3[13:0];\n\n";

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

    // ECMP active signal - use delayed version
    ss << "    // ECMP active (use delayed signal aligned with action output)\n";
    ss << "    wire ecmp_active;\n";
    ss << "    assign ecmp_active = ecmp_active_d3;\n\n";

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
    ss << "    // Use delayed match_hit aligned with action output\n";
    ss << "    wire ecmp_override;\n";
    ss << "    assign ecmp_override = ecmp_active && match_hit_d1;\n\n";

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

std::string generateConstTableLogic(SVProgram* program) {
    auto ingress = program->getIngress();
    if (!ingress) return "";
    
    const auto& tables = ingress->getTables();
    
    // Find tables with const entries
    SVTable* constTable = nullptr;
    for (const auto& tablePair : tables) {
        if (tablePair.second->hasConstEntries()) {
            constTable = tablePair.second;
            BACKEND_DEBUG("Found const table: " << tablePair.first);
            break;
        }
    }
    
    if (!constTable) return "";

    const auto& constEntries = constTable->getConstEntries();
    std::cerr << "Const entries count: " << constEntries.size() << std::endl;
    for (const auto& entry : constEntries) {
        std::cerr << "  Entry: key=" << entry.keyValues[0] << " action=" << entry.actionName << std::endl;
    }
    
    std::stringstream ss;
    
    ss << "\n    // ==========================================\n";
    ss << "    //          Const Table Logic\n";
    ss << "    // ==========================================\n";
    ss << "    // Generated from P4 const entries\n";
    ss << "    // Implements inline action execution without runtime table lookup\n";
    ss << "    // ==========================================\n\n";
    
    auto keyFieldNames = constTable->getKeyFieldNames();
    if (keyFieldNames.empty()) {
        BACKEND_DEBUG("No key fields in const table");
        return "";
    }
    
    std::string keySignal = mapFieldToSignal(keyFieldNames[0].string(), program);
    BACKEND_DEBUG("Const table key signal: " << keySignal);
    
    const auto& customHeaders = program->getParser()->getCustomHeaders();
    const auto& actions = ingress->getActions();

    // Helper to get effective action (follows callee chain)
    auto getEffectiveAction = [&actions](SVAction* action) -> SVAction* {
        cstring calleeName = action->getCalledAction();
        if (!calleeName.isNullOrEmpty()) {
            auto it = actions.find(calleeName);
            if (it != actions.end()) {
                return it->second;
            }
        }
        return action;
    };

    // Debug print with effective action info
    std::cerr << "Actions count: " << actions.size() << std::endl;
    for (const auto& a : actions) {
        SVAction* effective = getEffectiveAction(a.second);
        std::cerr << "  Action: " << a.first 
                  << " hasArithOps=" << a.second->hasArithmeticOps() 
                  << " hasMacSwap=" << a.second->hasMacSwap() 
                  << " hasEgressSpec=" << a.second->hasEgressSpec();
        if (effective != a.second) {
            std::cerr << " -> calls " << a.second->getCalledAction()
                      << " (hasMacSwap=" << effective->hasMacSwap()
                      << " hasEgressSpec=" << effective->hasEgressSpec() << ")";
        }
        std::cerr << std::endl;
    }
    
    // Helper lambda to resolve callee parameter destination
    auto resolveCalleeDestination = [&actions](const ArithmeticOperation& op, 
                                                std::string& destHeader, 
                                                std::string& destField) -> bool {
        if (!op.needsCalleeResolution()) {
            destHeader = op.destHeader.string();
            destField = op.destField.string();
            return true;
        }
        
        BACKEND_DEBUG("Resolving callee: " << op.calleeAction << " param index: " << op.calleeParamIndex);
        
        auto calleeIt = actions.find(op.calleeAction);
        if (calleeIt == actions.end()) {
            return false;
        }
        
        SVAction* callee = calleeIt->second;
        const auto& params = callee->getParameters();
        
        BACKEND_DEBUG("Callee has " << params.size() << " parameters");
        
        if (op.calleeParamIndex >= params.size()) {
            return false;
        }
        
        cstring paramName = params[op.calleeParamIndex]->name;
        BACKEND_DEBUG("Looking for param: " << paramName);
        
        for (const auto& calleeOp : callee->getArithmeticOps()) {
            BACKEND_DEBUG("  Checking op: dest=" << calleeOp.destHeader << "." << calleeOp.destField 
                     << " src1=" << calleeOp.srcField1 << " opType=" << (int)calleeOp.op);
            if (calleeOp.op == ArithmeticOperation::ASSIGN &&
                !calleeOp.src1IsConstant &&
                calleeOp.srcField1 == paramName) {
                destHeader = calleeOp.destHeader.string();
                destField = calleeOp.destField.string();
                BACKEND_DEBUG("Resolved to " << destHeader << "." << destField);
                return true;
            }
        }
        
        return false;
    };
    
    // Determine which header fields are modified by actions (including callees)
    std::set<std::string> modifiedFields;
    bool hasArithmetic = false;
    bool hasMacSwap = false;
    bool hasEgressSpec = false;
    bool hasDrop = false;
    
    for (const auto& entry : constTable->getConstEntries()) {
        auto actionIt = actions.find(entry.actionName);
        if (actionIt == actions.end()) continue;
        
        SVAction* action = actionIt->second;
        SVAction* effectiveAction = getEffectiveAction(action);
        
        if (action->hasArithmeticOps()) {
            hasArithmetic = true;
            for (const auto& op : action->getArithmeticOps()) {
                std::string destHeader, destField;
                if (resolveCalleeDestination(op, destHeader, destField)) {
                    modifiedFields.insert(destHeader + "_" + destField);
                }
            }
        }
        
        // Check both direct action AND callee for MAC swap and egress spec
        if (action->hasMacSwap() || effectiveAction->hasMacSwap()) {
            hasMacSwap = true;
        }
        
        if (action->hasEgressSpec() || effectiveAction->hasEgressSpec()) {
            hasEgressSpec = true;
        }
        
        if (action->isDropAction()) {
            hasDrop = true;
        }
    }
    
    // Generate computed result register(s)
    if (hasArithmetic) {
        for (const auto& field : modifiedFields) {
            int width = 32;
            for (const auto& headerPair : customHeaders) {
                for (const auto& fieldPair : headerPair.second.fields) {
                    std::string fullName = headerPair.first.string() + "_" + fieldPair.first.string();
                    if (fullName == field) {
                        width = fieldPair.second.width;
                        break;
                    }
                }
            }
            ss << "    reg [" << (width - 1) << ":0] computed_" << field << ";\n";
        }
        ss << "    reg computed_valid;\n";
    }
    
    ss << "    reg computed_drop;\n\n";
    
    if (hasMacSwap) {
        ss << "    reg [47:0] swapped_eth_dst_addr;\n";
        ss << "    reg [47:0] swapped_eth_src_addr;\n";
        ss << "    reg mac_swap_valid;\n\n";
    }
    
    if (hasEgressSpec) {
        ss << "    reg [8:0] computed_egress_port;\n";
        ss << "    reg egress_port_valid;\n\n";
    }
    
    // Generate the main case statement
    ss << "    // Const table action execution\n";
    ss << "    always_comb begin\n";
    
    for (const auto& field : modifiedFields) {
        ss << "        computed_" << field << " = '0;\n";
    }
    if (hasArithmetic) {
        ss << "        computed_valid = 1'b0;\n";
    }
    ss << "        computed_drop = 1'b0;\n";
    
    if (hasMacSwap) {
        ss << "        swapped_eth_dst_addr = eth_dst_addr;\n";
        ss << "        swapped_eth_src_addr = eth_src_addr;\n";
        ss << "        mac_swap_valid = 1'b0;\n";
    }
    
    if (hasEgressSpec) {
        ss << "        computed_egress_port = 9'd0;\n";
        ss << "        egress_port_valid = 1'b0;\n";
    }
    
    ss << "\n";
    ss << "        case (" << keySignal << ")\n";
    
    // Generate case for each const entry
    for (const auto& entry : constTable->getConstEntries()) {
        std::string keyValue = entry.keyValues[0].string();
        
        ss << "            8'h" << std::hex;
        if (keyValue.find("0x") == 0 || keyValue.find("0X") == 0) {
            ss << keyValue.substr(2);
        } else {
            int val = std::stoi(keyValue);
            ss << std::setw(2) << std::setfill('0') << val;
        }
        ss << std::dec << ": begin  // " << entry.actionName << "\n";
        
        auto actionIt = actions.find(entry.actionName);
        if (actionIt != actions.end()) {
            SVAction* action = actionIt->second;
            SVAction* effectiveAction = getEffectiveAction(action);
            
            // Generate arithmetic operations
            if (action->hasArithmeticOps()) {
                for (const auto& op : action->getArithmeticOps()) {
                    std::string destHeader, destField;
                    if (!resolveCalleeDestination(op, destHeader, destField)) {
                        continue;
                    }
                    std::string destSignal = destHeader + "_" + destField;
                    
                    std::string leftOp;
                    if (op.src1IsConstant) {
                        leftOp = std::to_string(op.srcConstant1);
                    } else {
                        leftOp = op.srcHeader1.string() + "_" + op.srcField1.string();
                    }
                    
                    std::string rightOp;
                    if (op.isBinaryOp()) {
                        if (op.src2IsConstant) {
                            rightOp = std::to_string(op.srcConstant2);
                        } else {
                            rightOp = op.srcHeader2.string() + "_" + op.srcField2.string();
                        }
                    }
                    
                    ss << "                computed_" << destSignal << " = ";
                    if (op.isBinaryOp()) {
                        ss << leftOp << " " << op.getOperatorString() << " " << rightOp;
                    } else {
                        ss << leftOp;
                    }
                    ss << ";\n";
                }
                ss << "                computed_valid = 1'b1;\n";
            }
            
            // Generate MAC swap (check both action and callee)
            if (action->hasMacSwap() || effectiveAction->hasMacSwap()) {
                ss << "                swapped_eth_dst_addr = eth_src_addr;\n";
                ss << "                swapped_eth_src_addr = eth_dst_addr;\n";
                ss << "                mac_swap_valid = 1'b1;\n";
            }
            
            // Generate egress spec (check both action and callee)
            if (action->hasEgressSpec() || effectiveAction->hasEgressSpec()) {
                const auto& spec = effectiveAction->hasEgressSpec() ? 
                                   effectiveAction->getEgressSpec() : action->getEgressSpec();
                if (spec.useIngressPort) {
                    ss << "                computed_egress_port = ingress_port;\n";
                } else {
                    ss << "                computed_egress_port = 9'd" << spec.constantPort << ";\n";
                }
                ss << "                egress_port_valid = 1'b1;\n";
            }
            
            // Generate drop
            if (action->isDropAction()) {
                ss << "                computed_drop = 1'b1;\n";
            }
        }
        
        ss << "            end\n";
    }
    
    ss << "            default: begin  // operation_drop (default)\n";
    ss << "                computed_drop = 1'b1;\n";
    ss << "            end\n";
    
    ss << "        endcase\n";
    ss << "    end\n\n";
    
    // Generate output assignments
    ss << "    // Override outputs with computed values\n";
    
    for (const auto& field : modifiedFields) {
        ss << "    assign out_" << field << " = computed_valid ? computed_" << field 
           << " : " << field << ";\n";
    }
    
    // Generate passthrough for UNMODIFIED custom header fields
    ss << "\n    // Passthrough for unmodified custom header fields\n";
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const auto& headerInfo = headerPair.second;
        
        for (const auto& fieldPair : headerInfo.fields) {
            const std::string fieldName = fieldPair.first.string();
            std::string fullSignal = headerName + "_" + fieldName;
            
            // Skip if this field is already handled by computed output
            if (modifiedFields.count(fullSignal) > 0) {
                continue;
            }
            
            ss << "    assign out_" << fullSignal << " = " << fullSignal << ";\n";
        }
        
        // Always passthrough valid signal
        ss << "    assign out_" << headerName << "_valid = " << headerName << "_valid;\n";
    }
    
    if (hasMacSwap) {
        ss << "    assign out_eth_dst_addr = mac_swap_valid ? swapped_eth_dst_addr : eth_dst_addr;\n";
        ss << "    assign out_eth_src_addr = mac_swap_valid ? swapped_eth_src_addr : eth_src_addr;\n";
    }
    
    if (hasEgressSpec) {
        ss << "    assign egress_port = egress_port_valid ? computed_egress_port : 9'd0;\n";
    }
    
    ss << "    assign drop = computed_drop;\n\n";
    
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

        // Determine valid condition based on header type
        size_t dotPos = fieldName.find('.');
        if (dotPos != std::string::npos) {
            std::string headerName = fieldName.substr(0, dotPos);
            // Use proper valid signal for each header type
            if (headerName == "ethernet" || headerName == "eth") {
                validCondition << " && ethernet_valid";
            } else if (headerName == "ipv4") {
                validCondition << " && ipv4_valid";
            } else if (headerName == "ipv6") {
                validCondition << " && ipv6_valid";
            } else if (headerName == "tcp") {
                validCondition << " && tcp_valid";
            } else if (headerName == "udp") {
                validCondition << " && udp_valid";
            } else {
                // Custom header or unknown - use header_valid
                validCondition << " && " << headerName << "_valid";
            }
        } else {
            // No header prefix - check for known patterns
            if (fieldName.find("ipv4") != std::string::npos ||
                fieldName == "dstAddr" || fieldName == "srcAddr" ||
                fieldName == "protocol") {
                validCondition << " && ipv4_valid";
            } else {
                // Check custom headers
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

    // For tunnel pattern, use the dynamically selected lookup key
    if (isTunnelPattern(program)) {
        result << ".lookup_key(selected_lookup_key),\n";
        BACKEND_DEBUG("Using selected_lookup_key for tunnel pattern");
    } else {
        result << ".lookup_key(" << keyExpr.str() << "),\n";
    }

    result << "        .lookup_key_mask(";

    int keyWidth = firstTable->getKeyWidth();
    if (firstTable->getMatchType() == SVTable::MatchType::EXACT) {
        // Generate proper all-ones mask based on key width
        // keyWidth/4 = number of hex digits needed
        int hexDigits = (keyWidth + 3) / 4;  // Round up
        result << keyWidth << "'h";
        for (int i = 0; i < hexDigits; i++) {
            result << "F";
        }
    } else {
        result << keyWidth << "'h0";
    }
    result << "),\n";
    
    // Allow ALL packets through the pipeline (not just matching ones)
    // This is important for programs like link_monitor that process probe packets in egress
    result << "        .lookup_valid(packet_valid_in),  // Allow all packets (probe and IPv4)\n";

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

    // Generate output port assignments for stack pointers
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            ss << "    assign " << headerPair.first.string() << "_ptr_out = "
               << headerPair.first.string() << "_ptr_next;\n";
        }
    }
    ss << "\n";

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

            if (headerInfo.isStack) {
                // For stack headers, generate array inputs
                int maxSize = headerInfo.maxStackSize;
                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();
                    const SVParser::CustomHeaderField& field = fieldPair.second;

                    customInputs << "    input  wire [" << (field.width - 1) << ":0] "
                               << headerName << "_" << fieldName << " [0:" << (maxSize-1) << "],\n";
                }
                customInputs << "    input  wire " << headerName << "_valid [0:" << (maxSize-1) << "],\n";
            } else {
                // For regular headers, generate scalar inputs
                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();
                    const SVParser::CustomHeaderField& field = fieldPair.second;

                    customInputs << "    input  wire [" << (field.width - 1) << ":0] "
                               << headerName << "_" << fieldName << ",\n";
                }
                customInputs << "    input  wire " << headerName << "_valid,\n";
            }
        }
    }

    // ==========================================
    // Add MRI-specific inputs (ipv4_ihl, ipv4_total_len from standard ipv4 header)
    // ==========================================
    bool hasMriForInputs = false;
    for (const auto& headerPair : customHeaders) {
        std::string hdrName = headerPair.first.string();
        if (hdrName == "mri" || hdrName.find("mri") != std::string::npos) {
            hasMriForInputs = true;
            break;
        }
    }
    if (hasMriForInputs) {
        customInputs << "    // MRI-specific inputs (from standard IPv4 header)\n";
        customInputs << "    input  wire [3:0]                     ipv4_ihl,\n";
        customInputs << "    input  wire [15:0]                    ipv4_total_len,\n";
    }

    // ==========================================
    // Generate Custom Header OUTPUTS
    // ==========================================
    std::stringstream customOutputs;

    if (!customHeaders.empty()) {
        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

            // Skip MRI header outputs - they're generated separately as MRI-specific outputs
            bool isMriHeader = (headerName == "mri" || headerName.find("mri") != std::string::npos);
            if (isMriHeader && !headerInfo.isStack) {
                continue;  // Skip non-stack MRI header (mri_count, mri_valid handled by MRI-specific)
            }

            if (headerInfo.isStack) {
                // For stack headers, generate array outputs
                int maxSize = headerInfo.maxStackSize;
                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();
                    const SVParser::CustomHeaderField& field = fieldPair.second;

                    customOutputs << "    output wire [" << (field.width - 1) << ":0] "
                                << "out_" << headerName << "_" << fieldName << " [0:" << (maxSize-1) << "],\n";
                }
                customOutputs << "    output wire out_" << headerName << "_valid [0:" << (maxSize-1) << "],\n";
            } else {
                // For regular headers, generate scalar outputs
                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();
                    const SVParser::CustomHeaderField& field = fieldPair.second;

                    customOutputs << "    output wire [" << (field.width - 1) << ":0] "
                                << "out_" << headerName << "_" << fieldName << ",\n";
                }
                customOutputs << "    output wire " << "out_" << headerName << "_valid,\n";
            }
        }
    }

    // ==========================================
    // Add MRI-specific outputs (includes out_mri_count which replaces custom header output)
    // ==========================================
    if (hasMriForInputs) {
        customOutputs << "    // MRI-specific outputs (modified by egress action)\n";
        customOutputs << "    output wire [15:0]                    out_mri_count,\n";  // Replaces custom header out_mri_count
        customOutputs << "    output wire [3:0]                     out_ipv4_ihl,\n";
        customOutputs << "    output wire [7:0]                     out_ipv4_option_length,\n";
        customOutputs << "    output wire [15:0]                    out_ipv4_total_len,\n";
        customOutputs << "    output wire [31:0]                    out_swtraces_0_swid,\n";
        customOutputs << "    output wire [31:0]                    out_swtraces_0_qdepth,\n";
        customOutputs << "    output wire                           out_swtraces_0_valid,\n";
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
    // Only pass through headers NOT modified by action module
    // probe and probe_data are modified by action, so only probe_fwd is passed through
    // ==========================================
    std::stringstream customPassthrough;

    if (!customHeaders.empty()) {
        customPassthrough << "    // Custom headers pass-through\n";
        customPassthrough << "    // Note: probe and probe_data are modified by action module\n";
        customPassthrough << "    // Only probe_fwd is passed through directly\n";

        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

            // Skip probe and probe_data - these are modified by action module
            // Only pass through probe_fwd (forwarding info not modified in egress)
            if (headerName.find("probe_fwd") == std::string::npos) {
                // These headers come from action module, not direct passthrough
                continue;
            }

            if (headerInfo.isStack) {
                // For stacks, use generate block to assign each array element
                int maxSize = headerInfo.maxStackSize;
                customPassthrough << "    // " << headerName << " pass-through (not modified by action)\n";
                customPassthrough << "    genvar i_" << headerName << ";\n";
                customPassthrough << "    generate\n";
                customPassthrough << "        for (i_" << headerName << " = 0; i_" << headerName
                                << " < " << maxSize << "; i_" << headerName << "++) begin : gen_" << headerName << "_passthrough\n";

                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();
                    customPassthrough << "            assign out_" << headerName << "_" << fieldName
                                    << "[i_" << headerName << "] = " << headerName << "_" << fieldName
                                    << "[i_" << headerName << "];\n";
                }
                customPassthrough << "            assign out_" << headerName << "_valid[i_" << headerName
                                << "] = " << headerName << "_valid[i_" << headerName << "];\n";
                customPassthrough << "        end\n";
                customPassthrough << "    endgenerate\n";
            } else {
                // For regular headers, simple assign
                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();

                    customPassthrough << "    assign out_" << headerName << "_" << fieldName
                                    << " = " << headerName << "_" << fieldName << ";\n";
                }
                customPassthrough << "    assign out_" << headerName << "_valid"
                                << " = " << headerName << "_valid;\n";
            }
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
    // Generate Stack Pointer Port Declarations
    // ==========================================
    std::stringstream stackPointerPorts;
    for (const auto& headerPair : customHeaders) {
        if (headerPair.second.isStack) {
            stackPointerPorts << "    input  wire [3:0]                     "
                            << headerPair.first.string() << "_ptr_in,\n";
            stackPointerPorts << "    output wire [3:0]                     "
                            << headerPair.first.string() << "_ptr_out,\n";
        }
    }

    // ==========================================
    matchActionTemplate = replaceAll(matchActionTemplate,
                                     "{{CUSTOM_HEADER_INPUTS}}",
                                     customInputs.str());

    matchActionTemplate = replaceAll(matchActionTemplate,
                                     "{{CUSTOM_HEADER_OUTPUTS}}",
                                     customOutputs.str());

    matchActionTemplate = replaceAll(matchActionTemplate,
                                     "{{STACK_POINTER_PORTS}}",
                                     stackPointerPorts.str());

    matchActionTemplate = replaceAll(matchActionTemplate,
                                     "{{CUSTOM_HEADER_WIRES}}",
                                     customWires.str());

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
                                        "        .lookup_valid(packet_valid_in),  // Allow all packets\n");
    }

    // ==========================================
    // Generate Match Module Custom Header Connections
    // ==========================================
    std::stringstream matchCustomInputs;
    std::stringstream matchCustomOutWires;
    std::stringstream matchCustomOutConnections;

    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

        // Only process non-stack headers (like probe)
        // Stack headers (probe_data, probe_fwd) are not pipelined through match
        if (!headerInfo.isStack) {
            // Generate input connections to match module
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                const SVParser::CustomHeaderField& field = fieldPair.second;

                matchCustomInputs << "        ." << headerName << "_" << fieldName << "_in("
                                  << headerName << "_" << fieldName << "),\n";

                matchCustomOutWires << "    wire [" << (field.width - 1) << ":0]           match_"
                                    << headerName << "_" << fieldName << ";\n";

                matchCustomOutConnections << "        ." << headerName << "_" << fieldName << "_out(match_"
                                          << headerName << "_" << fieldName << "),\n";
            }
            // Valid signal
            matchCustomInputs << "        ." << headerName << "_valid_in(" << headerName << "_valid),\n";
            matchCustomOutWires << "    wire                           match_" << headerName << "_valid;\n";
            matchCustomOutConnections << "        ." << headerName << "_valid_out(match_" << headerName << "_valid),\n";
        }
    }

    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{MATCH_CUSTOM_HEADER_CONNECTIONS}}",
                                    matchCustomInputs.str());
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{MATCH_CUSTOM_HEADER_OUT_WIRES}}",
                                    matchCustomOutWires.str());
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{MATCH_CUSTOM_HEADER_OUT_CONNECTIONS}}",
                                    matchCustomOutConnections.str());

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

    // ==========================================
    // Generate Const Table Logic (for calc.p4)
    // ==========================================
    std::string constTableLogic = generateConstTableLogic(program);
    
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{CONST_TABLE_LOGIC}}",
                                    constTableLogic);
    

    // ==========================================
    // Generate Probe Signal Connections
    // ==========================================
    std::string probeValidExpr = "1'b0";
    std::string probeHopCntExpr = "8'd0";
    
    for (const auto& headerPair : customHeaders) {
        std::string headerName = headerPair.first.string();
        const auto& headerInfo = headerPair.second;
        
        // Check for probe header (non-stack)
        bool isProbeHeader = (headerName == "probe" || 
                              headerName.find("probe") != std::string::npos);
        
        if (isProbeHeader && !headerInfo.isStack) {
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
    
    // Use match module outputs for probe signals (pipelined through match)
    std::stringstream probeSS;
    if (probeValidExpr != "1'b0") {
        // Probe header exists - use pipelined outputs from match module
        probeSS << "        .probe_valid(match_probe_valid),\n";
        probeSS << "        .probe_hop_cnt(match_probe_hop_cnt),";
    } else {
        // No probe header - use defaults
        probeSS << "        .probe_valid(1'b0),\n";
        probeSS << "        .probe_hop_cnt(8'd0),";
    }

    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{PROBE_SIGNAL_CONNECTIONS}}",
                                    probeSS.str());

    BACKEND_DEBUG("Probe connections: valid=" << probeValidExpr
                << ", hop_cnt=" << probeHopCntExpr);

    // ==========================================
    // Generate MRI/INT Signal Connections
    // Note: mri_valid and mri_count come from custom header generation
    // Here we only add MRI-specific signals not covered by custom headers
    // ==========================================
    bool hasMriHeader = false;
    for (const auto& headerPair : customHeaders) {
        std::string headerName = headerPair.first.string();
        if (headerName == "mri" || headerName.find("mri") != std::string::npos) {
            hasMriHeader = true;
            break;
        }
    }

    std::stringstream mriSS;
    if (hasMriHeader) {
        // MRI header exists - connect MRI-specific signals
        // mri_valid and mri_count are already connected via custom headers
        mriSS << "\n        // MRI/INT signal connections (MRI-specific fields)\n";
        mriSS << "        .mri_valid(mri_valid),\n";
        mriSS << "        .mri_count_in(mri_count),\n";
        mriSS << "        .deq_qdepth(deq_qdepth),\n";
        mriSS << "        .ipv4_ihl_in(ipv4_ihl),\n";
        mriSS << "        .ipv4_option_length_in(ipv4_option_optionLength),\n";  // From ipv4_option header
        mriSS << "        .ipv4_total_len_in(ipv4_total_len),\n";
        mriSS << "        .mri_count_out(out_mri_count),\n";
        mriSS << "        .ipv4_ihl_out(out_ipv4_ihl),\n";
        mriSS << "        .ipv4_option_length_out(out_ipv4_option_length),\n";
        mriSS << "        .ipv4_total_len_out(out_ipv4_total_len),\n";
        mriSS << "        .swtraces_0_swid_out(out_swtraces_0_swid),\n";
        mriSS << "        .swtraces_0_qdepth_out(out_swtraces_0_qdepth),\n";
        mriSS << "        .swtraces_0_valid_out(out_swtraces_0_valid),";
        BACKEND_DEBUG("MRI header found - generating MRI signal connections");
    } else {
        // No MRI header - connect to defaults
        mriSS << "\n        // MRI signals (no MRI header - defaults)\n";
        mriSS << "        .mri_valid(1'b0),\n";
        mriSS << "        .mri_count_in(16'd0),\n";
        mriSS << "        .deq_qdepth(19'd0),\n";
        mriSS << "        .ipv4_ihl_in(4'd0),\n";
        mriSS << "        .ipv4_option_length_in(8'd0),\n";
        mriSS << "        .ipv4_total_len_in(16'd0),\n";
        mriSS << "        .mri_count_out(),\n";
        mriSS << "        .ipv4_ihl_out(),\n";
        mriSS << "        .ipv4_option_length_out(),\n";
        mriSS << "        .ipv4_total_len_out(),\n";
        mriSS << "        .swtraces_0_swid_out(),\n";
        mriSS << "        .swtraces_0_qdepth_out(),\n";
        mriSS << "        .swtraces_0_valid_out(),";
    }

    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{MRI_SIGNAL_CONNECTIONS}}",
                                    mriSS.str());

    // ==========================================
    // Detect const table FIRST (needed for custom header connections)
    // ==========================================
    bool useConstTableForHeaders = false;
    if (ingress) {
        for (const auto& tablePair : ingress->getTables()) {
            if (tablePair.second->hasConstEntries()) {
                useConstTableForHeaders = true;
                BACKEND_DEBUG("Const table detected - will leave action custom header outputs unconnected");
                break;
            }
        }
    }

    // ==========================================
    // Generate Custom Header Connections for Action Module
    // ==========================================
    std::stringstream actionCustomSS;
    if (!customHeaders.empty()) {
        for (const auto& headerPair : customHeaders) {
            const std::string headerName = headerPair.first.string();
            const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

            // Skip MRI header outputs - they're handled by MRI-specific connections
            // (mri_count_out, etc. in action module connect to out_mri_count via MRI_SIGNAL_CONNECTIONS)
            bool isMriHeader = (headerName == "mri" || headerName.find("mri") != std::string::npos);

            // Generate INPUT connections for custom header data arrays
            // Action module needs access to stack data (e.g., srcRoutes_port for egress_spec)
            if (headerInfo.isStack) {
                for (const auto& fieldPair : headerInfo.fields) {
                    const std::string fieldName = fieldPair.first.string();
                    actionCustomSS << "        ." << headerName << "_" << fieldName
                                 << "(" << headerName << "_" << fieldName << "),\n";
                }
                actionCustomSS << "        ." << headerName << "_valid"
                             << "(" << headerName << "_valid),\n";
            }

            // Generate OUTPUT connections for action module
            // Skip MRI header - handled separately via MRI_SIGNAL_CONNECTIONS
            if (isMriHeader) {
                continue;  // MRI outputs handled by MRI signal connections
            }

            // When const table is used, leave unconnected to avoid multiple drivers
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                if (useConstTableForHeaders) {
                    actionCustomSS << "        .out_" << headerName << "_" << fieldName << "(),\n";
                } else {
                    actionCustomSS << "        .out_" << headerName << "_" << fieldName
                                 << "(out_" << headerName << "_" << fieldName << "),\n";
                }
            }
            if (useConstTableForHeaders) {
                actionCustomSS << "        .out_" << headerName << "_valid(),\n";
            } else {
                actionCustomSS << "        .out_" << headerName << "_valid"
                             << "(out_" << headerName << "_valid),\n";
            }
        }
    }

    // Add comment if const table handles custom headers
    if (useConstTableForHeaders && !customHeaders.empty()) {
        actionCustomSS.str("        // Custom header outputs handled by const table logic - leave unconnected\n" + actionCustomSS.str());
    }

    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{ACTION_CUSTOM_HEADER_CONNECTIONS}}",
                                    actionCustomSS.str());

    // Check for QoS DSCP-only conditionals
    bool hasQosDscp = hasDscpOnlyConditionals(program);

    if (!conditionalLogic.empty()) {
        BACKEND_DEBUG("Inserted conditional logic into template");

        // Check if we have action-override conditionals (not just DSCP-only)
        bool hasActionOverrideConditionals = false;
        for (const auto& ifElse : g_detectedIfElse) {
            if (ifElse.controlName != "MyIngress") continue;
            std::string trueActionName = ifElse.trueAction.string();
            if (!isDscpOnlyAction(program, trueActionName)) {
                hasActionOverrideConditionals = true;
                break;
            }
        }

        if (hasActionOverrideConditionals) {
            // Replace placeholder with final_action_id for action overrides
            matchActionTemplate = replaceAll(matchActionTemplate,
                                            "{{ACTION_ID_SIGNAL}}",
                                            "final_action_id");
            BACKEND_DEBUG("Using final_action_id for conditional action override");
        } else {
            // DSCP-only conditionals - use normal match_action_id
            matchActionTemplate = replaceAll(matchActionTemplate,
                                            "{{ACTION_ID_SIGNAL}}",
                                            "match_action_id");
            BACKEND_DEBUG("Using match_action_id (DSCP-only conditionals, no action override)");
        }
    } else {
        // Replace placeholder with match_action_id (no conditionals)
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_ID_SIGNAL}}",
                                        "match_action_id");

        BACKEND_DEBUG("Using match_action_id (no conditionals)");
    }

    // Handle DSCP output signal based on QoS presence
    if (hasQosDscp) {
        // QoS mode: action outputs to intermediate wire, then override mux assigns final output
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DIFFSERV_OUT_SIGNAL}}",
                                        "action_ipv4_diffserv");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DSCP_ASSIGNMENT}}",
                                        "// Final DSCP assignment with QoS override\n"
                                        "    assign out_ipv4_diffserv = qos_ipv4_diffserv;");
        BACKEND_DEBUG("QoS mode: using DSCP override logic");
    } else {
        // Normal mode: action outputs directly to module output
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DIFFSERV_OUT_SIGNAL}}",
                                        "out_ipv4_diffserv");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DSCP_ASSIGNMENT}}",
                                        "");
        BACKEND_DEBUG("Normal mode: direct DSCP pass-through");
    }
    
    // ==========================================
    // Detect feature flags FIRST (before placeholder replacement)
    // ==========================================
    
    // Check for const table
    bool useConstTable = false;
    if (ingress) {
        for (const auto& tablePair : ingress->getTables()) {
            if (tablePair.second->hasConstEntries()) {
                useConstTable = true;
                BACKEND_DEBUG("Using const table logic for " << tablePair.first);
                break;
            }
        }
    }
    
    // Check for bloom filter registers
    bool hasBloomFilter = false;
    if (ingress) {
        for (const auto& reg : ingress->getRegisters()) {
            if (reg.name.string().find("bloom_filter") != std::string::npos) {
                hasBloomFilter = true;
                break;
            }
        }
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
    
    // ==========================================
    // Replace placeholders based on mutually exclusive modes
    // Priority: const table > bloom filter > ECMP > default
    // ==========================================
    
    if (useConstTable) {
        // Const table handles everything - passthrough is in generateConstTableLogic()
        matchActionTemplate = replaceAll(matchActionTemplate, 
                                        "{{CUSTOM_HEADER_PASSTHROUGH}}", 
                                        "// Custom header outputs handled by const table logic");
        
        // Const table handles drop and egress_port directly
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DROP_SIGNAL_NAME}}",
                                        "action_drop_unused");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_DROP_WIRE}}",
                                        "wire action_drop_unused;  // Unused - const table drives drop");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DROP_ASSIGNMENT}}",
                                        "// drop driven by const table logic");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{EGRESS_PORT_WIRE}}",
                                        "wire [8:0] egress_port_unused;");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{EGRESS_PORT_ACTION_NAME}}",
                                        "egress_port_unused");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_EGRESS_PORT}}",
                                        "// egress_port driven by const table logic");
                                        
        BACKEND_DEBUG("Const table mode: action module outputs unused");
        
    } else if (hasBloomFilter) {
        // Bloom filter mode
        matchActionTemplate = replaceAll(matchActionTemplate, 
                                        "{{CUSTOM_HEADER_PASSTHROUGH}}", 
                                        customPassthrough.str());
        
        BACKEND_DEBUG("Enabling bloom filter drop logic");
        
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DROP_SIGNAL_NAME}}",
                                        "action_drop");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_DROP_WIRE}}",
                                        "wire action_drop;  // Declared for bloom filter combine");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DROP_ASSIGNMENT}}",
                                        "// Combine action drop with bloom filter drop\n"
                                        "    assign drop = action_drop || bloom_filter_drop;");
        
        // Egress port - check if also has ECMP
        if (hasECMP) {
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
        
    } else if (hasECMP) {
        // ECMP mode (no bloom filter)
        matchActionTemplate = replaceAll(matchActionTemplate, 
                                        "{{CUSTOM_HEADER_PASSTHROUGH}}", 
                                        customPassthrough.str());
        
        BACKEND_DEBUG("Enabling ECMP egress port override");
        
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DROP_SIGNAL_NAME}}",
                                        "drop");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_DROP_WIRE}}",
                                        "");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DROP_ASSIGNMENT}}",
                                        "// No bloom filter - drop comes directly from action");
        
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
        // Default mode - no special features
        matchActionTemplate = replaceAll(matchActionTemplate, 
                                        "{{CUSTOM_HEADER_PASSTHROUGH}}", 
                                        customPassthrough.str());
        
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{DROP_SIGNAL_NAME}}",
                                        "drop");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{ACTION_DROP_WIRE}}",
                                        "");
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{FINAL_DROP_ASSIGNMENT}}",
                                        "// No bloom filter - drop comes directly from action");
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

    if (!useConstTable) {
        // Default passthrough for MAC addresses
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{MAC_PASSTHROUGH}}",
                                        "assign out_eth_dst_addr = eth_dst_addr;\n"
                                        "    assign out_eth_src_addr = eth_src_addr;");
    } else {
        // Const table handles this
        matchActionTemplate = replaceAll(matchActionTemplate,
                                        "{{MAC_PASSTHROUGH}}",
                                        "// MAC handled by const table logic");
    }
    
    // ==========================================
    // Generate Inline Register Logic (for firewall bloom filter)
    // ==========================================
    std::string inlineRegisterLogic = generateInlineRegisterLogic(program);
    
    matchActionTemplate = replaceAll(matchActionTemplate,
                                    "{{INLINE_REGISTER_LOGIC}}",
                                    inlineRegisterLogic);
    
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
    // 2.5 Generate Custom Header Data INPUTS
    // For source routing, action needs srcRoutes_port[0] to set egress_spec
    // ==========================================
    std::stringstream customHeaderInputsSS;
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

        if (headerInfo.isStack) {
            int maxSize = headerInfo.maxStackSize;
            // Generate input arrays for each field in the stack
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                int fieldWidth = fieldPair.second.width;

                customHeaderInputsSS << "    input  wire ";
                customHeaderInputsSS << "[" << (fieldWidth-1) << ":0] ";
                customHeaderInputsSS << headerName << "_" << fieldName
                                   << " [0:" << (maxSize-1) << "],\n";
            }
            // Generate valid array input
            customHeaderInputsSS << "    input  wire " << headerName << "_valid"
                               << " [0:" << (maxSize-1) << "],\n";
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

                            // Check if action assigns to egress_spec from stack header
                            // Pattern: standard_metadata.egress_spec = hdr.srcRoutes[0].port
                            bool setsEgressPort = false;
                            std::string egressSourceField;
                            for (const auto& assign : action->getAssignments()) {
                                if (assign.dest.find("egress_spec") != std::string::npos ||
                                    assign.dest.find("egress_port") != std::string::npos) {
                                    // Check if source is from the stack (e.g., srcRoutes.port)
                                    if (assign.source.find(stackName) != std::string::npos ||
                                        assign.source.find("port") != std::string::npos) {
                                        setsEgressPort = true;
                                        // Extract field name (port from srcRoutes.port)
                                        size_t dotPos = assign.source.rfind('.');
                                        if (dotPos != std::string::npos) {
                                            egressSourceField = assign.source.substr(dotPos + 1);
                                        } else {
                                            egressSourceField = "port";  // Default
                                        }
                                        BACKEND_DEBUG("Action " << actionName
                                                   << " sets egress from " << stackName
                                                   << "." << egressSourceField);
                                    }
                                }
                            }

                            // If action sets egress_port from stack, generate assignment
                            // P4 accesses srcRoutes[0].port - always index 0 (the current first element)
                            // The pop_front logically removes the first element for the next iteration
                            if (setsEgressPort) {
                                logicSS << "                        egress_port <= {1'b0, "
                                       << stackName << "_" << egressSourceField
                                       << "[0][7:0]};\n";
                            }

                            // Generate pointer increment
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

    // Check for MRI/INT pattern (swtraces header with egress processing)
    bool hasMriEgress = false;
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        if ((headerName.find("swtraces") != std::string::npos ||
             headerName.find("swtrace") != std::string::npos) && headerPair.second.isStack) {
            hasMriEgress = true;
            BACKEND_DEBUG("Detected MRI/INT swtraces header for egress processing");
            break;
        }
    }

    if (hasMriEgress) {
        // MRI needs: ENABLE_EGRESS (0), ENABLE_EGRESS_TABLE (4), ENABLE_PUSH_FRONT (5)
        egressConfig |= 0x31;  // Bits 0,4,5: ENABLE_EGRESS + ENABLE_EGRESS_TABLE + ENABLE_PUSH_FRONT
        BACKEND_DEBUG("Enabled MRI egress processing (egress table + push_front)");
    }

    std::stringstream configSS;
    configSS << "8'b";
    for (int i = 7; i >= 0; i--) {
        configSS << ((egressConfig >> i) & 1);
    }
    actionTemplate = replaceAll(actionTemplate, "{{EGRESS_CONFIG}}", configSS.str());

    actionTemplate = replaceAll(actionTemplate, "{{ECN_THRESHOLD}}", 
                            "19'd" + std::to_string(program->getECNThreshold()));

    // ==========================================
    // 6.5. Generate Custom Header Outputs
    // ==========================================
    std::stringstream customHeaderOutputsSS;
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

        if (headerInfo.isStack) {
            // For stacks, generate arrays of outputs
            int maxSize = headerInfo.maxStackSize;
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                int fieldWidth = fieldPair.second.width;

                customHeaderOutputsSS << "    output reg  ";
                // Always specify bit width for arrays (even for 1-bit signals)
                customHeaderOutputsSS << "[" << (fieldWidth-1) << ":0] ";
                customHeaderOutputsSS << "out_" << headerName << "_" << fieldName
                                    << " [0:" << (maxSize-1) << "],\n";
            }

            // Generate valid array for stack
            customHeaderOutputsSS << "    output reg  [0:0]                     out_"
                                << headerName << "_valid [0:" << (maxSize-1) << "],\n";
        } else {
            // For regular headers, generate single outputs
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                int fieldWidth = fieldPair.second.width;

                customHeaderOutputsSS << "    output reg  ";
                if (fieldWidth > 1) {
                    customHeaderOutputsSS << "[" << (fieldWidth-1) << ":0] ";
                }
                customHeaderOutputsSS << "out_" << headerName << "_" << fieldName << ",\n";
            }

            // Generate valid output for regular header
            customHeaderOutputsSS << "    output reg                            out_"
                                << headerName << "_valid,\n";
        }
    }

    // ==========================================
    // 7. Replace All Placeholders
    // ==========================================
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_INPUTS}}", inputsSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_OUTPUTS}}", outputsSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{ACTION_CUSTOM_HEADER_INPUTS}}", customHeaderInputsSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_RESET_OUT}}", resetSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{STACK_POINTER_LOGIC_INOUT}}", logicSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{ACTION_CUSTOM_HEADER_OUTPUTS}}", customHeaderOutputsSS.str());

    // ==========================================
    // 7.1. Generate Reset Custom Header Outputs
    // ==========================================
    std::stringstream resetCustomHeadersSS;
    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        const SVParser::CustomHeaderInfo& headerInfo = headerPair.second;

        if (headerInfo.isStack) {
            int maxSize = headerInfo.maxStackSize;
            // Reset loop for stack arrays
            resetCustomHeadersSS << "            // Reset " << headerName << " stack outputs\n";
            resetCustomHeadersSS << "            for (int i = 0; i < " << maxSize << "; i++) begin\n";
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                int fieldWidth = fieldPair.second.width;
                resetCustomHeadersSS << "                out_" << headerName << "_" << fieldName
                                   << "[i] <= " << fieldWidth << "'d0;\n";
            }
            resetCustomHeadersSS << "                out_" << headerName << "_valid[i] <= 1'b0;\n";
            resetCustomHeadersSS << "            end\n";
        } else {
            // Reset scalar outputs
            resetCustomHeadersSS << "            // Reset " << headerName << " outputs\n";
            for (const auto& fieldPair : headerInfo.fields) {
                const std::string fieldName = fieldPair.first.string();
                int fieldWidth = fieldPair.second.width;
                resetCustomHeadersSS << "            out_" << headerName << "_" << fieldName
                                   << " <= " << fieldWidth << "'d0;\n";
            }
            resetCustomHeadersSS << "            out_" << headerName << "_valid <= 1'b0;\n";
        }
    }

    // ==========================================
    // 7.2. Generate Default Custom Header Outputs (clear valid on each cycle)
    // ==========================================
    std::stringstream defaultCustomHeadersSS;
    // Note: We don't clear all fields every cycle, just the valid signals
    // The actual data will be set when probe_valid is true

    // ==========================================
    // 7.3. Generate Egress Custom Header Logic (byte counting + probe push)
    // ==========================================
    std::stringstream egressCustomLogicSS;

    // Check if we have probe-related headers (link_monitor pattern)
    bool hasProbeData = false;
    std::string probeDataHeader;
    int probeDataMaxSize = 10;

    // Check if we have swtraces header (MRI/INT pattern)
    bool hasSwtraces = false;
    std::string swtracesHeader;
    int swtracesMaxSize = 9;

    for (const auto& headerPair : customHeaders) {
        const std::string headerName = headerPair.first.string();
        if (headerName.find("probe_data") != std::string::npos && headerPair.second.isStack) {
            hasProbeData = true;
            probeDataHeader = headerName;
            probeDataMaxSize = headerPair.second.maxStackSize;
        }
        if ((headerName.find("swtraces") != std::string::npos ||
             headerName.find("swtrace") != std::string::npos) && headerPair.second.isStack) {
            hasSwtraces = true;
            swtracesHeader = headerName;
            swtracesMaxSize = headerPair.second.maxStackSize;
            BACKEND_DEBUG("Found swtraces header: " << swtracesHeader << " with max size " << swtracesMaxSize);
        }
    }

    if (hasProbeData) {
        // Generate link_monitor style byte counting and probe push logic
        // This code goes inside the ENABLE_STATEFUL block's inner begin/end
        egressCustomLogicSS << R"(
                            // Byte counting logic for link_monitor
                            if (ipv4_valid && !probe_valid) begin
                                // Regular IPv4 packet: accumulate bytes
                                byte_cnt_write_data_in <= byte_cnt_read_out + {16'd0, packet_length_in};
                                byte_cnt_write_en_in   <= 1'b1;
                            end else if (probe_valid) begin
                                // Probe packet: capture current byte_cnt and reset
                                byte_cnt_write_data_in <= 32'd0;  // Reset counter
                                byte_cnt_write_en_in   <= 1'b1;
                                last_time_write_data_in <= global_timestamp;
                                last_time_write_en_in   <= 1'b1;

                                // PROBE DATA PUSH (link_monitor)
                                // Push captured data when probe packet arrives
                                if (ENABLE_PUSH_FRONT) begin
                                    automatic logic [7:0] new_hop_cnt;
                                    new_hop_cnt = probe_hop_cnt + 8'd1;

                                    // Push new probe_data entry at current pointer
                                    out_probe_data_bos[probe_data_ptr_in] <= (new_hop_cnt == 8'd1) ? 1'b1 : 1'b0;
                                    out_probe_data_swid[probe_data_ptr_in] <= 7'd1;  // Switch ID (configurable)
                                    out_probe_data_port[probe_data_ptr_in] <= egress_port_id[7:0];
                                    out_probe_data_byte_cnt[probe_data_ptr_in] <= byte_cnt_read_out;
                                    out_probe_data_last_time[probe_data_ptr_in] <= last_time_read_out;
                                    out_probe_data_cur_time[probe_data_ptr_in] <= global_timestamp;
                                    out_probe_data_valid[probe_data_ptr_in] <= 1'b1;

                                    // Increment stack pointer
                                    probe_data_ptr_out <= probe_data_ptr_in + 1;

                                    // Output incremented hop_cnt
                                    out_probe_hop_cnt <= new_hop_cnt;
                                    out_probe_valid <= 1'b1;
                                end

                                // Don't drop probe packets
                                drop <= 1'b0;
                            end else begin
                                // Non-probe, non-IPv4 packets: clear probe outputs
                                out_probe_valid <= 1'b0;
)";
        // Generate clear loop for probe data valid
        egressCustomLogicSS << "                                for (int i = 0; i < " << probeDataMaxSize << "; i++) begin\n";
        egressCustomLogicSS << "                                    out_probe_data_valid[i] <= 1'b0;\n";
        egressCustomLogicSS << "                                end\n";
        egressCustomLogicSS << "                            end\n";
    }

    // Generate MRI/INT swtrace push logic (different pattern from link_monitor)
    if (hasSwtraces) {
        // MRI logic: when mri header is valid, push swtrace entry
        // This is triggered by egress table action, not inline
        BACKEND_DEBUG("Generating MRI swtraces egress logic for " << swtracesHeader);
    }

    actionTemplate = replaceAll(actionTemplate, "{{RESET_CUSTOM_HEADER_OUTPUTS}}", resetCustomHeadersSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{DEFAULT_CUSTOM_HEADER_OUTPUTS}}", defaultCustomHeadersSS.str());
    actionTemplate = replaceAll(actionTemplate, "{{EGRESS_CUSTOM_HEADER_LOGIC}}", egressCustomLogicSS.str());

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

    // Copy static modules (stats, etc.)
    if (!copyStaticTemplates(options.outputDir.string())) {
        return false;
    }
    BACKEND_SUCCESS("Copied static modules");

    // Generate modular match template (exact_match or lpm_match)
    BACKEND_DEBUG("Generating modular match module");
    if (!processModularMatchTemplate(&svprog, options.outputDir.string())) {
        return false;
    }
    BACKEND_SUCCESS("Generated modular match module");

    // Generate action_engine.sv
    BACKEND_DEBUG("Generating action_engine.sv");
    if (!processActionEngineTemplate(&svprog, options.outputDir.string())) {
        return false;
    }
    BACKEND_SUCCESS("Generated action_engine.sv");

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

    // ==========================================
    // Modular Architecture Placeholders
    // ==========================================
    int matchType = getMatchType(&svprog);
    std::string matchModuleName = (matchType == 0) ? "exact_match" : "lpm_match";
    std::string matchTypeName = (matchType == 0) ? "Exact" : "LPM";

    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_MODULE_NAME}}", matchModuleName);
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_TYPE_NAME}}", matchTypeName);

    // Determine lookup key and key width
    std::string lookupKey = "ipv4_dst_addr";  // Default
    std::string keyWidth = "32";

    if (svprog.getIngress()) {
        const auto& tables = svprog.getIngress()->getTables();
        if (!tables.empty()) {
            SVTable* firstTable = tables.begin()->second;
            auto keyFields = firstTable->getKeyFieldNames();
            if (!keyFields.empty()) {
                std::string fieldName = keyFields[0].string();
                // Convert P4 field notation (hdr.ipv4.dstAddr) to signal name (ipv4_dst_addr)
                if (fieldName.find("ipv4") != std::string::npos &&
                    fieldName.find("dst") != std::string::npos) {
                    lookupKey = "ipv4_dst_addr";
                    keyWidth = "32";
                } else if (fieldName.find("ipv4") != std::string::npos &&
                           fieldName.find("src") != std::string::npos) {
                    lookupKey = "ipv4_src_addr";
                    keyWidth = "32";
                }
                // Check for tunnel header
                auto tunnelInfo = getTunnelHeaderInfo(&svprog);
                if (!tunnelInfo.first.empty()) {
                    // Tunnel application - might use tunnel header field
                    BACKEND_DEBUG("Tunnel lookup key detected");
                }
            }
        }
    }

    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{LOOKUP_KEY}}", lookupKey);
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{KEY_WIDTH}}", keyWidth);

    // Match table extra ports (for LPM: prefix_len)
    std::string matchTableExtraPorts = "";
    if (matchType == 1) {  // LPM
        matchTableExtraPorts = "    .table_entry_prefix_len(axi_ctrl_entry_prefix_len),\n";
    }
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_TABLE_EXTRA_PORTS}}", matchTableExtraPorts);

    // Feature detection for action_engine
    bool enableHash = needsHashEngine(&svprog);
    bool enableRegisters = needsRegisters(&svprog);
    bool enableEncap = needsEncapDecap(&svprog);
    bool enableDecap = needsEncapDecap(&svprog);
    bool enableEcnMarking = (svprog.getControlConfig().egressConfig & 0x02) != 0;
    bool enableMulticast = false;

    // Detect multicast
    if (svprog.getIngress()) {
        for (const auto& actionPair : svprog.getIngress()->getActions()) {
            SVAction* action = actionPair.second;
            for (const auto& assignment : action->getAssignments()) {
                if (assignment.dest.find("mcast_grp") != std::string::npos) {
                    enableMulticast = true;
                    break;
                }
            }
            if (enableMulticast) break;
        }
    }

    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ENABLE_HASH}}", enableHash ? "1" : "0");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ENABLE_REGISTERS}}", enableRegisters ? "1" : "0");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ENABLE_ENCAP}}", enableEncap ? "1" : "0");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ENABLE_DECAP}}", enableDecap ? "1" : "0");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ENABLE_ECN_MARKING}}", enableEcnMarking ? "1" : "0");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ENABLE_MULTICAST}}", enableMulticast ? "1" : "0");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{HASH_TYPE}}", "0");  // CRC16 default
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{NUM_REGISTERS}}", "1024");

    // Match custom header wires/inputs/outputs (empty for now)
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_CUSTOM_HEADER_WIRES}}", "");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_CUSTOM_HEADER_INPUTS}}", "");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_CUSTOM_HEADER_OUTPUTS}}", "");

    // Action custom inputs/outputs/stack ports (empty for now)
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ACTION_CUSTOM_INPUTS}}", "");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ACTION_CUSTOM_OUTPUTS}}", "");
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{ACTION_STACK_POINTER_PORTS}}", "");

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

    // Generate probe_data signal declarations (only if program has probe_data)
    std::stringstream probeDataSignalsSS;
    if (hasProbeDataStack) {
        probeDataSignalsSS << "// Egress probe_data outputs (from match_action)\n";
        probeDataSignalsSS << "logic                        pipeline_out_probe_data_valid;\n";
        probeDataSignalsSS << "logic                        pipeline_out_probe_data_bos;\n";
        probeDataSignalsSS << "logic [6:0]                  pipeline_out_probe_data_swid;\n";
        probeDataSignalsSS << "logic [7:0]                  pipeline_out_probe_data_port;\n";
        probeDataSignalsSS << "logic [31:0]                 pipeline_out_probe_data_byte_cnt;\n";
        probeDataSignalsSS << "logic [47:0]                 pipeline_out_probe_data_last_time;\n";
        probeDataSignalsSS << "logic [47:0]                 pipeline_out_probe_data_cur_time;\n";
    }
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{PROBE_DATA_SIGNALS}}", probeDataSignalsSS.str());

    // Generate match_action probe_data port connections (only if program has probe_data)
    std::stringstream matchActionProbeSS;
    if (hasProbeDataStack) {
        matchActionProbeSS << ",\n\n    // Egress probe data outputs\n";
        matchActionProbeSS << "    .out_probe_data_valid(pipeline_out_probe_data_valid),\n";
        matchActionProbeSS << "    .out_probe_data_bos(pipeline_out_probe_data_bos),\n";
        matchActionProbeSS << "    .out_probe_data_swid(pipeline_out_probe_data_swid),\n";
        matchActionProbeSS << "    .out_probe_data_port(pipeline_out_probe_data_port),\n";
        matchActionProbeSS << "    .out_probe_data_byte_cnt(pipeline_out_probe_data_byte_cnt),\n";
        matchActionProbeSS << "    .out_probe_data_last_time(pipeline_out_probe_data_last_time),\n";
        matchActionProbeSS << "    .out_probe_data_cur_time(pipeline_out_probe_data_cur_time)";
    }
    vfpgaTemplate = replaceAll(vfpgaTemplate, "{{MATCH_ACTION_PROBE_DATA_PORTS}}", matchActionProbeSS.str());

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