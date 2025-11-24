#include "common.h"
#include "control.h"
#include "table.h"
#include "action.h"
#include "program.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

// ==========================================
// Debug Control
// ==========================================
#define CONTROL_INFO(msg)    std::cerr << "[Control] " << msg << std::endl
#define CONTROL_SUCCESS(msg) std::cerr << "[✓] " << msg << std::endl
#define CONTROL_ERROR(msg)   std::cerr << "[ERROR] " << msg << std::endl

#define CONTROL_DEBUG(msg) if (SV::g_verbose) std::cerr << "  " << msg << std::endl
#define CONTROL_TRACE(msg) if (SV::g_verbose) std::cerr << "    " << msg << std::endl

// ==========================================
// Constructor & Destructor
// ==========================================

SVControl::SVControl(SVProgram* program,
                     const IR::ControlBlock* block,
                     const TypeMap* typeMap,
                     const ReferenceMap* refMap) :
    program(program), 
    controlBlock(block), 
    typeMap(typeMap), 
    refMap(refMap),
    isIngress(false),
    isEgress(false),           
    hasEgressActions(false) {
    
    if (block && block->container) {
        p4control = block->container;
        controlName = p4control->name;
        isIngress = (controlName.string().find("ingress") != std::string::npos ||
                    controlName.string().find("Ingress") != std::string::npos);
        isEgress = (controlName.string().find("egress") != std::string::npos ||
                   controlName.string().find("Egress") != std::string::npos);
    } else {
        p4control = nullptr;
        controlName = cstring("unknown");
    }
}

SVControl::~SVControl() {
    for (auto& p : svTables) {
        delete p.second;
    }
    for (auto& p : svActions) {
        delete p.second;
    }
}

// ==========================================
// Build Control
// ==========================================

bool SVControl::build() {
    CONTROL_DEBUG("Building control: " << controlName);
    
    if (!controlBlock || !controlBlock->container) {
        CONTROL_DEBUG("Invalid control block, using empty control");
        return true;
    }
    
    extractTables();
    extractActions();
    extractRegisters(); 
    detectHashCalls();
    
    // Detect egress actions
    if (isEgress) {
        for (const auto& actionPair : svActions) {
            cstring actionName = actionPair.first;
            if (actionName == "mark_ecn") {
                hasEgressActions = true;
                CONTROL_TRACE("Found egress action: mark_ecn");
            }
        }
    }
    
    // Concise summary
    std::stringstream summary;
    summary << controlName << ": " << svTables.size() << " tables, " 
            << svActions.size() << " actions";
    
    if (isIngress) summary << " [ingress]";
    if (isEgress) summary << " [egress]";
    
    CONTROL_SUCCESS(summary.str());
    
    return true;
}

// ==========================================
// Extract Tables
// ==========================================

void SVControl::extractTables() {
    if (!p4control) return;
    
    CONTROL_TRACE("Extracting tables");
    
    for (auto decl : p4control->controlLocals) {
        if (auto table = decl->to<IR::P4Table>()) {
            CONTROL_TRACE("Found table: " << table->name);
            
            auto svTable = new SVTable(this, table);
            svTable->build();  // ← build() will handle const entries!
            svTables[table->name] = svTable;
        }
    }
    
    // Track table-action relationships
    for (auto& p : svTables) {
        auto tableName = p.first;
        auto svTable = p.second;
        auto p4table = svTable->getP4Table();
        
        if (p4table && p4table->getActionList()) {
            for (auto actionElem : p4table->getActionList()->actionList) {
                if (auto elem = actionElem->to<IR::ActionListElement>()) {
                    cstring actionName;
                    
                    if (auto path = elem->expression->to<IR::PathExpression>()) {
                        actionName = path->path->name;
                    } else if (auto method = elem->expression->to<IR::MethodCallExpression>()) {
                        actionName = method->method->toString();
                    }
                    
                    if (actionName) {
                        action_to_table[actionName].insert(tableName);
                    }
                }
            }
        }
    }
    
    CONTROL_TRACE("Extracted " << svTables.size() << " tables");
}

// ==========================================
// Extract Actions
// ==========================================

void SVControl::extractActions() {
    if (!p4control) return;
    
    CONTROL_TRACE("Extracting actions");
    
    for (auto decl : p4control->controlLocals) {
        if (auto action = decl->to<IR::P4Action>()) {
            CONTROL_TRACE("Found action: " << action->name);
            
            auto svAction = new SVAction(this, action);
            svAction->setTypeMap(typeMap);
            svAction->build();
            
            svActions[action->name] = svAction;
        }
    }
    
    CONTROL_TRACE("Extracted " << svActions.size() << " actions");
}

void SVControl::extractRegisters() {
    if (!p4control) return;
    
    CONTROL_TRACE("Extracting registers");
    
    for (auto decl : p4control->controlLocals) {
        if (auto declInstance = decl->to<IR::Declaration_Instance>()) {
            std::string typeName = declInstance->type->toString().string();
            
            if (typeName.find("register") != std::string::npos ||
                typeName.find("Register") != std::string::npos) {
                
                RegisterInfo regInfo;
                regInfo.name = declInstance->name;
                
                // Parse register<T>(size)
                if (auto specialized = declInstance->type->to<IR::Type_Specialized>()) {
                    if (specialized->arguments && specialized->arguments->size() > 0) {
                        auto elementType = specialized->arguments->at(0);
                        regInfo.elementType = elementType->toString();
                        
                        if (auto bits = elementType->to<IR::Type_Bits>()) {
                            regInfo.elementWidth = bits->size;
                        }
                    }
                }
                
                // Get array size from constructor args
                if (declInstance->arguments && declInstance->arguments->size() > 0) {
                    auto sizeArg = declInstance->arguments->at(0);
                    if (auto constant = sizeArg->expression->to<IR::Constant>()) {
                        regInfo.arraySize = constant->asInt();
                    } else if (auto path = sizeArg->expression->to<IR::PathExpression>()) {
                        std::string constName = path->path->name.string();
                        if (constName == "MAX_PORTS") regInfo.arraySize = 8;
                        else if (constName == "MAX_HOPS") regInfo.arraySize = 10;
                        else regInfo.arraySize = 256;
                    }
                }
                
                registers.push_back(regInfo);
                CONTROL_DEBUG("Found register: " << regInfo.name 
                             << " [" << regInfo.elementWidth << " bits x " 
                             << regInfo.arraySize << "]");
            }
        }
    }
}


// ==========================================
// Extract Configuration
// ==========================================

ControlConfig SVControl::extractConfiguration() {
    CONTROL_DEBUG("Extracting configuration");
    
    ControlConfig config;
    
    // Default values
    config.matchType = 1;
    config.actionConfig = 0x07;
    config.egressConfig = 0;
    config.tableSize = 1024;
    config.keyWidth = 32;
    config.ecnThreshold = 10;
    
    // Extract from tables
    if (!svTables.empty()) {
        auto firstTable = svTables.begin()->second;
        config.matchType = static_cast<uint8_t>(firstTable->getMatchType());
        config.tableSize = static_cast<uint32_t>(firstTable->getTableSize());
        config.keyWidth = static_cast<uint32_t>(firstTable->getKeyWidth());
    }
    
    // Extract action types
    config.actionConfig = 0;
    
    // Track stateful features
    bool hasStateful = false;
    bool hasHash = false;

    if (hasStatefulOperations()) {
        hasStateful = true;
        CONTROL_TRACE("Control uses stateful registers/counters");
    }
    
    for (const auto& actionPair : svActions) {
        cstring actionName = actionPair.first;
        SVAction* action = actionPair.second;

        bool actionHasRegs = action->usesRegisters();
        bool actionHasHash = action->usesHash();
        
        CONTROL_TRACE("Action " << actionName 
                     << (actionHasRegs ? " [registers]" : "")
                     << (actionHasHash ? " [hash]" : ""));
        
        // Basic actions
        if (actionName == "ipv4_forward" || actionName == "forward" ||
            actionName.string().find("forward") != std::string::npos) {
            config.actionConfig |= 0x01;  // Forward
            config.actionConfig |= 0x04;  // Modify headers
        }
        if (actionName == "drop" || actionName.string().find("drop") != std::string::npos) {
            config.actionConfig |= 0x02;  // Drop
        }
        if (actionName.string().find("encap") != std::string::npos) {
            config.actionConfig |= 0x08;  // Encap
        }
        if (actionName.string().find("decap") != std::string::npos) {
            config.actionConfig |= 0x10;  // Decap
        }
        
        // Detect stateful operations
        if (actionHasHash) {
            config.actionConfig |= 0x20;  // Hash
            hasHash = true;
            CONTROL_TRACE("Hash support enabled");
        }
        
        if (actionHasRegs) {
            hasStateful = true;
            CONTROL_TRACE("Stateful support enabled");
        }
        
        // Egress actions (ECN marking)
        if (actionName == "mark_ecn") {
            config.egressConfig |= 0x01;  // Enable egress
            config.egressConfig |= 0x02;  // Enable ECN marking
            CONTROL_TRACE("ECN marking enabled");
        }
    }
    
    // Set stateful flag if detected
    if (hasStateful) {
        config.egressConfig |= 0x04;  // Bit 2 = stateful processing
        CONTROL_TRACE("Stateful processing enabled");
    }
    
    if (config.actionConfig == 0) {
        config.actionConfig = 0x07;  // Default: forward + drop + modify
    }
    
#if DEBUG_CONTROL_VERBOSE
    std::cerr << "[Control] Configuration:" << std::endl;
    std::cerr << "  Match type:   " << (int)config.matchType << std::endl;
    std::cerr << "  Action flags: 0x" << std::hex << (int)config.actionConfig << std::dec;
    if (hasStateful) std::cerr << " [stateful]";
    if (hasHash) std::cerr << " [hash]";
    std::cerr << std::endl;
    std::cerr << "  Egress flags: 0x" << std::hex << (int)config.egressConfig << std::dec << std::endl;
#endif
    
    return config;
}

// ==========================================
// Check Stateful Operations
// ==========================================

bool SVControl::hasStatefulOperations() const {
    if (!registers.empty()) return true;
    
    if (!p4control) return false;
    
    CONTROL_TRACE("Checking for stateful operations");
    
    // Check control-level declarations
    for (auto decl : p4control->controlLocals) {
        if (auto declInstance = decl->to<IR::Declaration_Instance>()) {
            std::string typeName = declInstance->type->toString().string();
            
            if (typeName.find("register") != std::string::npos ||
                typeName.find("Register") != std::string::npos ||
                typeName.find("counter") != std::string::npos ||
                typeName.find("Counter") != std::string::npos ||
                typeName.find("meter") != std::string::npos ||
                typeName.find("Meter") != std::string::npos) {
                CONTROL_TRACE("Found stateful extern: " << typeName);
                return true;
            }
        }
    }
    
    // Check apply block for register operations
    if (p4control->body) {
        for (auto stmt : p4control->body->components) {
            if (auto blockStmt = stmt->to<IR::BlockStatement>()) {
                for (auto innerStmt : blockStmt->components) {
                    if (auto methodCall = innerStmt->to<IR::MethodCallStatement>()) {
                        std::string methodStr = methodCall->methodCall->method->toString().string();
                        
                        if (methodStr.find(".write") != std::string::npos ||
                            methodStr.find(".read") != std::string::npos) {
                            CONTROL_TRACE("Found register operation: " << methodStr);
                            return true;
                        }
                        if (methodStr == "hash") {
                            HashInfo hashInfo;
                            
                            // Parse hash() call arguments
                            auto args = methodCall->methodCall->arguments;
                            if (args->size() >= 2) {
                                // Argument 0: output field (meta.flow_hash)
                                if (auto argPath = args->at(0)->to<IR::PathExpression>()) {
                                    hashInfo.outputField = argPath->path->name;
                                }
                                
                                // Argument 1: algorithm (HashAlgorithm.crc16)
                                if (auto argMember = args->at(1)->to<IR::Member>()) {
                                    hashInfo.algorithm = argMember->member;
                                }
                                
                                // Argument 2 (optional): input fields tuple
                                if (args->size() >= 3) {
                                    if (auto tuple = args->at(2)->to<IR::ListExpression>()) {
                                        for (auto comp : tuple->components) {
                                            if (auto member = comp->to<IR::Member>()) {
                                                hashInfo.inputFields.push_back(member->member);
                                            }
                                        }
                                    }
                                }
                                
                                CONTROL_TRACE("Found hash() call: output=" << hashInfo.outputField 
                                            << ", algo=" << hashInfo.algorithm 
                                            << ", inputs=" << hashInfo.inputFields.size());
                            }
                            
                            return true;  // Hash detected
                        }
                    }
                }
            }
        }
    }
    
    return false;
}

bool SVControl::detectHashCalls() {
    // Safety checks first
    if (!p4control) {
        CONTROL_TRACE("No p4control, skipping hash detection");
        return false;
    }
    
    if (!p4control->body) {
        CONTROL_TRACE("No control body, skipping hash detection");
        return false;
    }
    
    CONTROL_TRACE("Detecting hash() calls");
    
    // Manually iterate through body statements instead of using visitor
    std::vector<HashInfo> foundHashes;
    
    // p4control->body is a BlockStatement with components
    for (auto stmt : p4control->body->components) {
        if (!stmt) continue;
        
        // Check if it's a method call statement
        if (auto methodCallStmt = stmt->to<IR::MethodCallStatement>()) {
            if (!methodCallStmt->methodCall) continue;
            if (!methodCallStmt->methodCall->method) continue;
            
            auto method = methodCallStmt->methodCall->method;
            
            // Check if method is "hash"
            if (auto pathExpr = method->to<IR::PathExpression>()) {
                if (!pathExpr->path) continue;
                
                if (pathExpr->path->name == "hash") {
                    std::cerr << "    Found hash() call in control body" << std::endl;
                    
                    HashInfo hashInfo;
                    hashInfo.algorithm = cstring("crc16");  // Default
                    hashInfo.outputWidth = 32;
                    hashInfo.outputField = cstring("ecmp_select");  // Default
                    
                    // Parse arguments safely
                    auto args = methodCallStmt->methodCall->arguments;
                    if (args && args->size() >= 2) {
                        // Argument 0: output field
                        auto arg0 = args->at(0);
                        if (arg0) {
                            if (auto member = arg0->to<IR::Member>()) {
                                hashInfo.outputField = member->member;
                                std::cerr << "      Output: " << hashInfo.outputField << std::endl;
                            } else if (auto path = arg0->to<IR::PathExpression>()) {
                                if (path->path) {
                                    hashInfo.outputField = path->path->name;
                                    std::cerr << "      Output: " << hashInfo.outputField << std::endl;
                                }
                            }
                        }
                        
                        // Argument 1: algorithm
                        auto arg1 = args->at(1);
                        if (arg1) {
                            if (auto member = arg1->to<IR::Member>()) {
                                hashInfo.algorithm = member->member;
                                std::cerr << "      Algorithm: " << hashInfo.algorithm << std::endl;
                            }
                        }
                        
                        // Argument 3: input fields (arg 2 is base value)
                        if (args->size() >= 4) {
                            auto arg3 = args->at(3);
                            if (arg3) {
                                if (auto listExpr = arg3->to<IR::ListExpression>()) {
                                    for (auto comp : listExpr->components) {
                                        if (comp) {
                                            if (auto member = comp->to<IR::Member>()) {
                                                hashInfo.inputFields.push_back(member->member);
                                                std::cerr << "      Input: " << member->member << std::endl;
                                            }
                                        }
                                    }
                                } else if (auto structExpr = arg3->to<IR::StructExpression>()) {
                                    for (auto field : structExpr->components) {
                                        if (field && field->expression) {
                                            if (auto member = field->expression->to<IR::Member>()) {
                                                hashInfo.inputFields.push_back(member->member);
                                                std::cerr << "      Input: " << member->member << std::endl;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    foundHashes.push_back(hashInfo);
                    std::cerr << "    Hash detection complete: " 
                             << foundHashes.size() << " total" << std::endl;
                }
            }
        }
        
        // Also check inside BlockStatements (nested blocks)
        if (auto blockStmt = stmt->to<IR::BlockStatement>()) {
            for (auto innerStmt : blockStmt->components) {
                if (!innerStmt) continue;
                
                if (auto methodCallStmt = innerStmt->to<IR::MethodCallStatement>()) {
                    if (!methodCallStmt->methodCall) continue;
                    if (!methodCallStmt->methodCall->method) continue;
                    
                    auto method = methodCallStmt->methodCall->method;
                    
                    if (auto pathExpr = method->to<IR::PathExpression>()) {
                        if (!pathExpr->path) continue;
                        
                        if (pathExpr->path->name == "hash") {
                            std::cerr << "    Found hash() call in nested block" << std::endl;
                            
                            HashInfo hashInfo;
                            hashInfo.algorithm = cstring("crc16");
                            hashInfo.outputWidth = 32;
                            hashInfo.outputField = cstring("ecmp_select");
                            
                            // Parse arguments (same as above)
                            auto args = methodCallStmt->methodCall->arguments;
                            if (args && args->size() >= 2) {
                                auto arg0 = args->at(0);
                                if (arg0) {
                                    if (auto member = arg0->to<IR::Member>()) {
                                        hashInfo.outputField = member->member;
                                        std::cerr << "      Output: " << hashInfo.outputField << std::endl;
                                    } else if (auto path = arg0->to<IR::PathExpression>()) {
                                        if (path->path) {
                                            hashInfo.outputField = path->path->name;
                                            std::cerr << "      Output: " << hashInfo.outputField << std::endl;
                                        }
                                    }
                                }
                                
                                auto arg1 = args->at(1);
                                if (arg1) {
                                    if (auto member = arg1->to<IR::Member>()) {
                                        hashInfo.algorithm = member->member;
                                        std::cerr << "      Algorithm: " << hashInfo.algorithm << std::endl;
                                    }
                                }
                                
                                if (args->size() >= 4) {
                                    auto arg3 = args->at(3);
                                    if (arg3) {
                                        if (auto listExpr = arg3->to<IR::ListExpression>()) {
                                            for (auto comp : listExpr->components) {
                                                if (comp) {
                                                    if (auto member = comp->to<IR::Member>()) {
                                                        hashInfo.inputFields.push_back(member->member);
                                                        std::cerr << "      Input: " << member->member << std::endl;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                            foundHashes.push_back(hashInfo);
                        }
                    }
                }
            }
        }
    }
    
    if (!foundHashes.empty()) {
        CONTROL_DEBUG("Detected " << foundHashes.size() << " hash() call(s)");
        hashCalls = foundHashes;
        return true;
    }
    
    CONTROL_TRACE("No hash() calls found");
    return false;
}

}  // namespace SV
