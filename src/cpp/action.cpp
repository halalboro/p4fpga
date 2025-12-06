#include "common.h"
#include "action.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

// ==========================================
// Debug Control
// ==========================================
#define ACTION_DEBUG(msg) if (SV::g_verbose) std::cerr << "  " << msg << std::endl
#define ACTION_TRACE(msg) if (SV::g_verbose) std::cerr << "    " << msg << std::endl

// ==========================================
// Build Action
// ==========================================

bool SVAction::build() {
    ACTION_TRACE("Building action: " << actionName);
    extractParameters();
    ACTION_TRACE("Action " << actionName << " has " << parameters.size() << " parameters");
    
    if (SV::g_verbose) {
        for (auto p : parameters) {
            // Resolve typedef to get actual width
            auto paramType = p->type;
            
            // If it's a typedef, resolve it
            if (auto typeRef = paramType->to<IR::Type_Name>()) {
                if (typeMap) {
                    auto resolvedType = typeMap->getType(typeRef, true);
                    if (resolvedType) {
                        paramType = resolvedType;
                        
                        // Unwrap Type_Type if needed
                        if (auto typeType = paramType->to<IR::Type_Type>()) {
                            paramType = typeType->type;
                        }
                    }
                }
            }
            
            // Now get the width safely
            int width = 0;
            if (auto bits = paramType->to<IR::Type_Bits>()) {
                width = bits->size;
            }
            
            std::cerr << "    Parameter: " << p->name << " width: " << width << std::endl;
        }
    }
    
    analyzeBody();
    detectStackOperations();  
    return true;
}

// ==========================================
// Extract Member Info Helper
// Extracts header name and field name from IR::Member
// Returns true if successful
// ==========================================

bool SVAction::extractMemberInfo(const IR::Expression* expr,
                                 cstring& headerName,
                                 cstring& fieldName) {
    if (!expr) return false;
    
    if (auto member = expr->to<IR::Member>()) {
        fieldName = member->member;
        
        // Check for nested member (hdr.p4calc.res)
        if (auto parent = member->expr->to<IR::Member>()) {
            headerName = parent->member;
            return true;
        }
        // Check for path expression (standard_metadata.egress_spec)
        else if (auto path = member->expr->to<IR::PathExpression>()) {
            headerName = path->path->name;
            return true;
        }
    }
    
    return false;
}

// ==========================================
// Detect Stack Operations
// ==========================================

void SVAction::detectStackOperations() {
    if (!p4action->body) return;
    
    ACTION_TRACE("Detecting stack operations in action " << actionName);
    
    for (auto stmt : p4action->body->components) {
        if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            auto method = methodCall->methodCall;
            if (!method || !method->method) continue;
            
            // Check if this is a member method call (e.g., hdr.srcRoutes.pop_front)
            if (auto member = method->method->to<IR::Member>()) {
                std::string methodName = member->member.string();
                
                // Detect pop_front()
                if (methodName == "pop_front") {
                    // Get stack name from expression (hdr.srcRoutes.pop_front → srcRoutes)
                    if (auto stackMember = member->expr->to<IR::Member>()) {
                        StackOperation op;
                        op.type = StackOperation::POP_FRONT;
                        op.stackName = stackMember->member;
                        op.count = 1;  // Default count
                        
                        // Check if there's an argument for count
                        if (method->arguments && method->arguments->size() > 0) {
                            if (auto countArg = method->arguments->at(0)->to<IR::Constant>()) {
                                op.count = countArg->asInt();
                            }
                        }
                        
                        stackOperations.push_back(op);
                        ACTION_DEBUG("Found pop_front(" << op.count << ") on stack: " 
                                    << op.stackName);
                    }
                }
                // Detect push_front()
                else if (methodName == "push_front") {
                    if (auto stackMember = member->expr->to<IR::Member>()) {
                        StackOperation op;
                        op.type = StackOperation::PUSH_FRONT;
                        op.stackName = stackMember->member;
                        op.count = 1;
                        
                        if (method->arguments && method->arguments->size() > 0) {
                            if (auto countArg = method->arguments->at(0)->to<IR::Constant>()) {
                                op.count = countArg->asInt();
                            }
                        }
                        
                        stackOperations.push_back(op);
                        ACTION_DEBUG("Found push_front(" << op.count << ") on stack: " 
                                    << op.stackName);
                    }
                }
            }
        }
    }
    
    if (!stackOperations.empty()) {
        ACTION_DEBUG("Action " << actionName << " uses " << stackOperations.size() 
                    << " stack operation(s)");
    }
}

// ======================================
// Stateful Operation Detection
// ======================================

bool SVAction::usesRegisters() const {
    if (!p4action->body) return false;
    
    ACTION_TRACE("Checking if action " << actionName << " uses registers");
    
    for (auto stmt : p4action->body->components) {
        // Check for method calls
        if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            auto method = methodCall->methodCall;
            if (!method || !method->method) continue;
            
            std::string methodStr = method->method->toString().string();
            ACTION_TRACE("Found method call: " << methodStr);
            
            // Check for register operations (multiple patterns)
            if (methodStr.find(".read") != std::string::npos ||
                methodStr.find(".write") != std::string::npos ||
                methodStr.find("register") != std::string::npos ||
                methodStr.find("Register") != std::string::npos ||
                methodStr.find("table.read") != std::string::npos ||
                methodStr.find("table.write") != std::string::npos ||
                methodStr.find("counter") != std::string::npos ||
                methodStr.find("Counter") != std::string::npos) {
                ACTION_DEBUG("Action " << actionName << " uses registers: " << methodStr);
                return true;
            }
        }
        
        // Check for assignments that might involve registers
        if (auto assign = stmt->to<IR::AssignmentStatement>()) {
            if (auto methodCall = assign->right->to<IR::MethodCallExpression>()) {
                std::string methodStr = methodCall->method->toString().string();
                ACTION_TRACE("Found assignment method: " << methodStr);
                
                if (methodStr.find(".read") != std::string::npos ||
                    methodStr.find("register") != std::string::npos ||
                    methodStr.find("Register") != std::string::npos ||
                    methodStr.find("table") != std::string::npos) {
                    ACTION_DEBUG("Action " << actionName << " reads from register: " << methodStr);
                    return true;
                }
            }
        }
        
        // Check for extern references
        if (auto declStmt = stmt->to<IR::Declaration_Instance>()) {
            std::string typeName = declStmt->type->toString().string();
            ACTION_TRACE("Found declaration: " << typeName);
            
            if (typeName.find("Register") != std::string::npos ||
                typeName.find("Counter") != std::string::npos ||
                typeName.find("Meter") != std::string::npos) {
                ACTION_DEBUG("Action " << actionName << " declares stateful extern: " << typeName);
                return true;
            }
        }
    }
    
    ACTION_TRACE("No register usage found in action " << actionName);
    return false;
}

bool SVAction::usesHash() const {
    if (!p4action->body) return false;
    
    ACTION_TRACE("Checking if action " << actionName << " uses hash");
    
    for (auto stmt : p4action->body->components) {
        // Check for method calls
        if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            auto method = methodCall->methodCall;
            if (!method || !method->method) continue;
            
            std::string methodStr = method->method->toString().string();
            
            // Check for hash operations
            if (methodStr.find("hash") != std::string::npos ||
                methodStr.find(".get(") != std::string::npos) {
                ACTION_DEBUG("Action " << actionName << " uses hash: " << methodStr);
                return true;
            }
        }
        
        // Check for assignments involving hash
        if (auto assign = stmt->to<IR::AssignmentStatement>()) {
            if (auto methodCall = assign->right->to<IR::MethodCallExpression>()) {
                std::string methodStr = methodCall->method->toString().string();
                if (methodStr.find("hash") != std::string::npos) {
                    ACTION_DEBUG("Action " << actionName << " computes hash: " << methodStr);
                    return true;
                }
            }
        }
    }
    
    return false;
}

bool SVAction::usesCounters() const {
    if (!p4action->body) return false;
    
    ACTION_TRACE("Checking if action " << actionName << " uses counters");
    
    for (auto stmt : p4action->body->components) {
        if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            auto method = methodCall->methodCall;
            if (!method || !method->method) continue;
            
            std::string methodStr = method->method->toString().string();
            
            // Check for counter operations
            if (methodStr.find("count") != std::string::npos ||
                methodStr.find("counter") != std::string::npos) {
                ACTION_DEBUG("Action " << actionName << " uses counters: " << methodStr);
                return true;
            }
        }
    }
    
    return false;
}

// ==========================================
// Extract Parameters
// ==========================================

void SVAction::extractParameters() {
    if (SV::g_verbose) {
        std::cerr << "Extracting parameters for action " << actionName << std::endl;
    }
    
    if (!p4action->parameters) {
        if (SV::g_verbose) {
            std::cerr << "  p4action has no parameters" << std::endl;
        }
        return;
    }
    
    if (SV::g_verbose) {
        std::cerr << "  p4action has " << p4action->parameters->parameters.size() << " params" << std::endl;
    }
    
    for (auto param : p4action->parameters->parameters) {
        if (SV::g_verbose) {
            std::cerr << "  Found parameter: " << param->name;
        }
        
        parameters.push_back(param);
        
        // Get the actual type, resolving typedefs
        auto paramType = param->type;
        
        // If it's a typedef, resolve it to the underlying type
        if (auto typeRef = paramType->to<IR::Type_Name>()) {
            if (SV::g_verbose) {
                std::cerr << " (typedef: " << typeRef->path->name << ")";
            }
            
            // Try to resolve the typedef using the type map
            if (typeMap) {
                auto resolvedType = typeMap->getType(typeRef, true);
                if (resolvedType) {
                    if (SV::g_verbose) {
                        std::cerr << " -> resolved to " << resolvedType->node_type_name();
                    }
                    paramType = resolvedType;
                    
                    // If it's a Type_Type, unwrap it to get the actual type
                    if (auto typeType = paramType->to<IR::Type_Type>()) {
                        if (SV::g_verbose) {
                            std::cerr << " -> unwrapping Type_Type";
                        }
                        paramType = typeType->type;
                        if (SV::g_verbose) {
                            std::cerr << " -> " << paramType->node_type_name();
                        }
                    }
                }
            }
        }
        
        // Now get the width - use ->size directly for Type_Bits
        if (auto bits = paramType->to<IR::Type_Bits>()) {
            parameterWidth += bits->size;
            if (SV::g_verbose) {
                std::cerr << " (bit<" << bits->size << ">)";
            }
        } else {
            // For other types, log error
            if (SV::g_verbose) {
                std::cerr << " (ERROR: not a Type_Bits, got " << paramType->node_type_name() << ")";
            }
        }
        
        if (SV::g_verbose) {
            std::cerr << std::endl;
        }
    }
    
    if (SV::g_verbose) {
        std::cerr << "  Total parameter width: " << parameterWidth << " bits" << std::endl;
    }
}

// ==========================================
// Analyze Body - ENHANCED with Arithmetic Detection
// ==========================================

void SVAction::analyzeBody() {
    if (!p4action->body) {
        return;
    }
    
    ACTION_TRACE("Analyzing body of action: " << actionName);
    
    // Analyze action body to determine what fields are modified
    for (auto stmt : p4action->body->components) {
        if (auto assign = stmt->to<IR::AssignmentStatement>()) {
            Assignment a;

            // Build full destination path
            cstring destHeader, destField;
            if (extractMemberInfo(assign->left, destHeader, destField)) {
                a.dest = destHeader.string() + "." + destField.string();

                // Extract source value (constant or field reference)
                if (auto constant = assign->right->to<IR::Constant>()) {
                    // Direct constant assignment: hdr.ipv4.diffserv = 46
                    a.source = std::to_string(constant->asInt());
                    ACTION_TRACE("Action " << actionName << " assigns constant " << a.source << " to " << a.dest);
                } else if (auto cast = assign->right->to<IR::Cast>()) {
                    // Cast wrapping a constant: (bit<6>)46
                    if (auto constant = cast->expr->to<IR::Constant>()) {
                        a.source = std::to_string(constant->asInt());
                        ACTION_TRACE("Action " << actionName << " assigns cast constant " << a.source << " to " << a.dest);
                    }
                    // Cast wrapping a member: (bit<9>)hdr.srcRoutes[0].port
                    else if (auto castMember = cast->expr->to<IR::Member>()) {
                        // Check if it's array indexed (hdr.srcRoutes[0].port)
                        if (auto arrayIndex = castMember->expr->to<IR::ArrayIndex>()) {
                            // Pattern: hdr.srcRoutes[0].port -> srcRoutes.port
                            if (auto stackMember = arrayIndex->left->to<IR::Member>()) {
                                a.source = stackMember->member.string() + "." + castMember->member.string();
                                ACTION_TRACE("Action " << actionName << " assigns array-indexed cast " << a.source << " to " << a.dest);
                            }
                        } else {
                            cstring srcHeader, srcField;
                            if (extractMemberInfo(cast->expr, srcHeader, srcField)) {
                                a.source = srcHeader.string() + "." + srcField.string();
                                ACTION_TRACE("Action " << actionName << " assigns cast member " << a.source << " to " << a.dest);
                            }
                        }
                    }
                } else if (auto srcMember = assign->right->to<IR::Member>()) {
                    // Field-to-field assignment
                    cstring srcHeader, srcField;
                    if (extractMemberInfo(assign->right, srcHeader, srcField)) {
                        a.source = srcHeader.string() + "." + srcField.string();
                    }
                }

                assignments.push_back(a);

                if (auto member = assign->left->to<IR::Member>()) {
                    fieldModifications[member->member] = cstring::literal("modified");
                }

                ACTION_TRACE("Action " << actionName << " modifies field: " << a.dest);
            }
            
            // ==========================================
            // Detect arithmetic operations
            // ==========================================
            ArithmeticOperation arithOp;
            bool isArithOp = false;
            
            // Extract destination
            if (!extractMemberInfo(assign->left, arithOp.destHeader, arithOp.destField)) {
                continue;  // Skip if we can't parse destination
            }
            
            // Check for ADD: operand_a + operand_b
            if (auto addExpr = assign->right->to<IR::Add>()) {
                arithOp.op = ArithmeticOperation::ADD;
                isArithOp = true;
                
                // Left operand
                if (auto constant = addExpr->left->to<IR::Constant>()) {
                    arithOp.src1IsConstant = true;
                    arithOp.srcConstant1 = constant->asInt();
                } else {
                    arithOp.src1IsConstant = false;
                    extractMemberInfo(addExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                }
                
                // Right operand
                if (auto constant = addExpr->right->to<IR::Constant>()) {
                    arithOp.src2IsConstant = true;
                    arithOp.srcConstant2 = constant->asInt();
                } else {
                    arithOp.src2IsConstant = false;
                    extractMemberInfo(addExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                }
                
                ACTION_DEBUG("Found ADD: " << arithOp.destHeader << "." << arithOp.destField
                            << " = " << arithOp.srcHeader1 << "." << arithOp.srcField1
                            << " + " << arithOp.srcHeader2 << "." << arithOp.srcField2);
            }
            // Check for SUB: operand_a - operand_b
            else if (auto subExpr = assign->right->to<IR::Sub>()) {
                arithOp.op = ArithmeticOperation::SUB;
                isArithOp = true;
                
                if (auto constant = subExpr->left->to<IR::Constant>()) {
                    arithOp.src1IsConstant = true;
                    arithOp.srcConstant1 = constant->asInt();
                } else {
                    arithOp.src1IsConstant = false;
                    extractMemberInfo(subExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                }
                
                if (auto constant = subExpr->right->to<IR::Constant>()) {
                    arithOp.src2IsConstant = true;
                    arithOp.srcConstant2 = constant->asInt();
                } else {
                    arithOp.src2IsConstant = false;
                    extractMemberInfo(subExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                }
                
                ACTION_DEBUG("Found SUB: " << arithOp.destHeader << "." << arithOp.destField
                            << " = " << arithOp.srcHeader1 << "." << arithOp.srcField1
                            << " - " << arithOp.srcHeader2 << "." << arithOp.srcField2);
            }
            // Check for BAND (bitwise AND): operand_a & operand_b
            else if (auto bandExpr = assign->right->to<IR::BAnd>()) {
                arithOp.op = ArithmeticOperation::BAND;
                isArithOp = true;
                
                if (auto constant = bandExpr->left->to<IR::Constant>()) {
                    arithOp.src1IsConstant = true;
                    arithOp.srcConstant1 = constant->asInt();
                } else {
                    arithOp.src1IsConstant = false;
                    extractMemberInfo(bandExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                }
                
                if (auto constant = bandExpr->right->to<IR::Constant>()) {
                    arithOp.src2IsConstant = true;
                    arithOp.srcConstant2 = constant->asInt();
                } else {
                    arithOp.src2IsConstant = false;
                    extractMemberInfo(bandExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                }
                
                ACTION_DEBUG("Found BAND: " << arithOp.destHeader << "." << arithOp.destField
                            << " = " << arithOp.srcHeader1 << "." << arithOp.srcField1
                            << " & " << arithOp.srcHeader2 << "." << arithOp.srcField2);
            }
            // Check for BOR (bitwise OR): operand_a | operand_b
            else if (auto borExpr = assign->right->to<IR::BOr>()) {
                arithOp.op = ArithmeticOperation::BOR;
                isArithOp = true;
                
                if (auto constant = borExpr->left->to<IR::Constant>()) {
                    arithOp.src1IsConstant = true;
                    arithOp.srcConstant1 = constant->asInt();
                } else {
                    arithOp.src1IsConstant = false;
                    extractMemberInfo(borExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                }
                
                if (auto constant = borExpr->right->to<IR::Constant>()) {
                    arithOp.src2IsConstant = true;
                    arithOp.srcConstant2 = constant->asInt();
                } else {
                    arithOp.src2IsConstant = false;
                    extractMemberInfo(borExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                }
                
                ACTION_DEBUG("Found BOR: " << arithOp.destHeader << "." << arithOp.destField
                            << " = " << arithOp.srcHeader1 << "." << arithOp.srcField1
                            << " | " << arithOp.srcHeader2 << "." << arithOp.srcField2);
            }
            // Check for BXOR (bitwise XOR): operand_a ^ operand_b
            else if (auto bxorExpr = assign->right->to<IR::BXor>()) {
                arithOp.op = ArithmeticOperation::BXOR;
                isArithOp = true;
                
                if (auto constant = bxorExpr->left->to<IR::Constant>()) {
                    arithOp.src1IsConstant = true;
                    arithOp.srcConstant1 = constant->asInt();
                } else {
                    arithOp.src1IsConstant = false;
                    extractMemberInfo(bxorExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                }
                
                if (auto constant = bxorExpr->right->to<IR::Constant>()) {
                    arithOp.src2IsConstant = true;
                    arithOp.srcConstant2 = constant->asInt();
                } else {
                    arithOp.src2IsConstant = false;
                    extractMemberInfo(bxorExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                }
                
                ACTION_DEBUG("Found BXOR: " << arithOp.destHeader << "." << arithOp.destField
                            << " = " << arithOp.srcHeader1 << "." << arithOp.srcField1
                            << " ^ " << arithOp.srcHeader2 << "." << arithOp.srcField2);
            }
            // Check for simple field assignment: hdr.a.x = hdr.b.y OR hdr.a.x = param
            else if (auto memberExpr = assign->right->to<IR::Member>()) {
                arithOp.op = ArithmeticOperation::ASSIGN;
                arithOp.src1IsConstant = false;
                extractMemberInfo(memberExpr, arithOp.srcHeader1, arithOp.srcField1);
                isArithOp = true;
                
                ACTION_DEBUG("Found ASSIGN: " << arithOp.destHeader << "." << arithOp.destField
                            << " = " << arithOp.srcHeader1 << "." << arithOp.srcField1);
            }
            // Check for parameter assignment: hdr.a.x = param
            else if (auto pathExpr = assign->right->to<IR::PathExpression>()) {
                arithOp.op = ArithmeticOperation::ASSIGN;
                arithOp.src1IsConstant = false;
                arithOp.srcHeader1 = cstring("");  // No header - it's a parameter
                arithOp.srcField1 = pathExpr->path->name;  // Parameter name
                isArithOp = true;
                
                ACTION_DEBUG("Found ASSIGN from param: " << arithOp.destHeader << "." << arithOp.destField
                            << " = " << arithOp.srcField1);
            }
                        
            if (isArithOp) {
                arithmeticOps_.push_back(arithOp);
            }
            
            // ==========================================
            // Detect MAC swap pattern
            // ==========================================
            // Pattern: tmp = hdr.ethernet.dstAddr;
            //          hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
            //          hdr.ethernet.srcAddr = tmp;
            // We detect the middle assignment
            if (destHeader == "ethernet" && destField == "dstAddr") {
                cstring srcHdr, srcFld;
                if (extractMemberInfo(assign->right, srcHdr, srcFld)) {
                    if (srcHdr == "ethernet" && srcFld == "srcAddr") {
                        macSwap_.enabled = true;
                        macSwap_.srcMacHeader = cstring("ethernet");
                        macSwap_.srcMacField = cstring("srcAddr");
                        macSwap_.dstMacHeader = cstring("ethernet");
                        macSwap_.dstMacField = cstring("dstAddr");
                        ACTION_DEBUG("Found MAC swap pattern");
                    }
                }
            }
            
            // ==========================================
            // Detect egress_spec = ingress_port pattern
            // ==========================================
            if ((destHeader == "standard_metadata" && destField == "egress_spec") ||
                destField == "egress_spec") {
                cstring srcHdr, srcFld;
                if (extractMemberInfo(assign->right, srcHdr, srcFld)) {
                    if (srcFld == "ingress_port") {
                        egressSpec_.enabled = true;
                        egressSpec_.useIngressPort = true;
                        ACTION_DEBUG("Found egress_spec = ingress_port pattern");
                    }
                } else if (auto constant = assign->right->to<IR::Constant>()) {
                    egressSpec_.enabled = true;
                    egressSpec_.useIngressPort = false;
                    egressSpec_.constantPort = constant->asInt();
                    ACTION_DEBUG("Found egress_spec = " << egressSpec_.constantPort);
                }
            }
            
        } else if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
        auto method = methodCall->methodCall->method->toString();
        ACTION_TRACE("Action " << actionName << " calls method: " << method);
        
        // Store callee action name for later resolution
        cstring calleeName;
        if (auto pathExpr = methodCall->methodCall->method->to<IR::PathExpression>()) {
            calleeName = pathExpr->path->name;
            calledAction_ = calleeName;  // ADD THIS LINE
            ACTION_DEBUG("Action " << actionName << " calls action: " << calleeName);
        }
        
        // Analyze method call arguments for arithmetic operations
        if (methodCall->methodCall->arguments) {
            for (size_t argIdx = 0; argIdx < methodCall->methodCall->arguments->size(); argIdx++) {
                auto arg = methodCall->methodCall->arguments->at(argIdx)->expression;
                
                ArithmeticOperation arithOp;
                bool isArithOp = false;
                
                // Store callee info for backend resolution
                arithOp.calleeAction = calleeName;
                arithOp.calleeParamIndex = argIdx;
                
                // Check for ADD
                if (auto addExpr = arg->to<IR::Add>()) {
                    arithOp.op = ArithmeticOperation::ADD;
                    isArithOp = true;
                    
                    if (auto constant = addExpr->left->to<IR::Constant>()) {
                        arithOp.src1IsConstant = true;
                        arithOp.srcConstant1 = constant->asInt();
                    } else {
                        arithOp.src1IsConstant = false;
                        extractMemberInfo(addExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                    }
                    
                    if (auto constant = addExpr->right->to<IR::Constant>()) {
                        arithOp.src2IsConstant = true;
                        arithOp.srcConstant2 = constant->asInt();
                    } else {
                        arithOp.src2IsConstant = false;
                        extractMemberInfo(addExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                    }
                    
                    ACTION_DEBUG("Found ADD in call arg: " << arithOp.srcHeader1 << "." 
                                << arithOp.srcField1 << " + " << arithOp.srcHeader2 
                                << "." << arithOp.srcField2);
                }
                // Check for SUB
                else if (auto subExpr = arg->to<IR::Sub>()) {
                    arithOp.op = ArithmeticOperation::SUB;
                    isArithOp = true;
                    
                    if (auto constant = subExpr->left->to<IR::Constant>()) {
                        arithOp.src1IsConstant = true;
                        arithOp.srcConstant1 = constant->asInt();
                    } else {
                        arithOp.src1IsConstant = false;
                        extractMemberInfo(subExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                    }
                    
                    if (auto constant = subExpr->right->to<IR::Constant>()) {
                        arithOp.src2IsConstant = true;
                        arithOp.srcConstant2 = constant->asInt();
                    } else {
                        arithOp.src2IsConstant = false;
                        extractMemberInfo(subExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                    }
                    
                    ACTION_DEBUG("Found SUB in call arg");
                }
                // Check for BAND
                else if (auto bandExpr = arg->to<IR::BAnd>()) {
                    arithOp.op = ArithmeticOperation::BAND;
                    isArithOp = true;
                    
                    if (auto constant = bandExpr->left->to<IR::Constant>()) {
                        arithOp.src1IsConstant = true;
                        arithOp.srcConstant1 = constant->asInt();
                    } else {
                        arithOp.src1IsConstant = false;
                        extractMemberInfo(bandExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                    }
                    
                    if (auto constant = bandExpr->right->to<IR::Constant>()) {
                        arithOp.src2IsConstant = true;
                        arithOp.srcConstant2 = constant->asInt();
                    } else {
                        arithOp.src2IsConstant = false;
                        extractMemberInfo(bandExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                    }
                    
                    ACTION_DEBUG("Found BAND in call arg");
                }
                // Check for BOR
                else if (auto borExpr = arg->to<IR::BOr>()) {
                    arithOp.op = ArithmeticOperation::BOR;
                    isArithOp = true;
                    
                    if (auto constant = borExpr->left->to<IR::Constant>()) {
                        arithOp.src1IsConstant = true;
                        arithOp.srcConstant1 = constant->asInt();
                    } else {
                        arithOp.src1IsConstant = false;
                        extractMemberInfo(borExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                    }
                    
                    if (auto constant = borExpr->right->to<IR::Constant>()) {
                        arithOp.src2IsConstant = true;
                        arithOp.srcConstant2 = constant->asInt();
                    } else {
                        arithOp.src2IsConstant = false;
                        extractMemberInfo(borExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                    }
                    
                    ACTION_DEBUG("Found BOR in call arg");
                }
                // Check for BXOR
                else if (auto bxorExpr = arg->to<IR::BXor>()) {
                    arithOp.op = ArithmeticOperation::BXOR;
                    isArithOp = true;
                    
                    if (auto constant = bxorExpr->left->to<IR::Constant>()) {
                        arithOp.src1IsConstant = true;
                        arithOp.srcConstant1 = constant->asInt();
                    } else {
                        arithOp.src1IsConstant = false;
                        extractMemberInfo(bxorExpr->left, arithOp.srcHeader1, arithOp.srcField1);
                    }
                    
                    if (auto constant = bxorExpr->right->to<IR::Constant>()) {
                        arithOp.src2IsConstant = true;
                        arithOp.srcConstant2 = constant->asInt();
                    } else {
                        arithOp.src2IsConstant = false;
                        extractMemberInfo(bxorExpr->right, arithOp.srcHeader2, arithOp.srcField2);
                    }
                    
                    ACTION_DEBUG("Found BXOR in call arg");
                }
                
                if (isArithOp) {
                    arithmeticOps_.push_back(arithOp);
                }
            }
        }
    }
    }
    
    // Log summary
    if (!arithmeticOps_.empty()) {
        ACTION_DEBUG("Action " << actionName << " has " << arithmeticOps_.size() 
                    << " arithmetic operation(s)");
    }
}

// ==========================================
// Helper Methods (unchanged)
// ==========================================

std::string SVAction::getMemberString(const IR::Expression* expr,
                                      const std::string& prefix,
                                      bool isLhs) {
    if (auto member = expr->to<IR::Member>()) {
        return getMemberString(member, prefix, isLhs);
    }
    return "";
}

std::string SVAction::getMemberString(const IR::Member* member, 
                                      const std::string& prefix,
                                      bool isLhs) {
    std::stringstream ss;
    
    if (auto parent = member->expr->to<IR::Member>()) {
        // Nested member: hdr.ethernet.dstAddr
        auto structName = parent->member.toString();
        auto fieldName = member->member.toString();
        
        if (auto grandparent = parent->expr->to<IR::PathExpression>()) {
            std::string baseName = grandparent->path->name.toString().c_str();
            
            if (baseName == "hdr") {
                ss << prefix << "_headers." << structName << "." << fieldName;
            } else if (baseName == "meta") {
                ss << prefix << "_metadata." << fieldName;
            } else if (baseName == "standard_metadata") {
                if (fieldName == "egress_spec") {
                    ss << prefix << "_metadata.egress_port";
                } else {
                    ss << prefix << "_metadata." << fieldName;
                }
            } else {
                ss << prefix << "_headers." << structName << "." << fieldName;
            }
        }
    } else if (auto path = member->expr->to<IR::PathExpression>()) {
        // Simple member: standard_metadata.egress_spec
        auto baseName = path->path->name.toString();
        
        if (baseName == "standard_metadata") {
            if (member->member == "egress_spec") {
                ss << prefix << "_metadata.egress_port";
            } else {
                ss << prefix << "_metadata." << member->member.toString();
            }
        } else if (baseName == "hdr") {
            ss << prefix << "_headers." << member->member.toString();
        } else if (baseName == "meta") {
            ss << prefix << "_metadata." << member->member.toString();
        } else {
            ss << prefix << "_headers." << baseName << "." << member->member.toString();
        }
    }
    
    // For LHS (left-hand side), increment stage number
    if (isLhs) {
        std::string result = ss.str();
        size_t pos = result.find("stage");
        if (pos != std::string::npos && pos + 5 < result.length()) {
            if (isdigit(result[pos + 5])) {
                // Increment stage number (stage0 -> stage1)
                result[pos + 5] = '0' + ((result[pos + 5] - '0') + 1);
            }
        }
        return result;
    }
    
    return ss.str();
}

int SVAction::getParameterOffset(cstring paramName) {
    int offset = 0;
    for (auto param : parameters) {
        if (param->name == paramName) {
            return offset;
        }
        
        // Calculate offset using resolved type
        auto paramType = param->type;
        
        // If it's a typedef, resolve it
        if (auto typeRef = paramType->to<IR::Type_Name>()) {
            if (typeMap) {
                auto resolvedType = typeMap->getType(typeRef, true);
                if (resolvedType) {
                    paramType = resolvedType;
                    
                    // Unwrap Type_Type if needed
                    if (auto typeType = paramType->to<IR::Type_Type>()) {
                        paramType = typeType->type;
                    }
                }
            }
        }
        
        // Add width to offset
        if (auto type = paramType->to<IR::Type_Bits>()) {
            offset += type->size;
        }
    }
    return -1;
}

int SVAction::getParameterWidth(cstring paramName) {
    for (auto param : parameters) {
        if (param->name == paramName) {
            auto paramType = param->type;
            
            // If it's a typedef, resolve it
            if (auto typeRef = paramType->to<IR::Type_Name>()) {
                if (typeMap) {
                    auto resolvedType = typeMap->getType(typeRef, true);
                    if (resolvedType) {
                        paramType = resolvedType;
                        
                        // Unwrap Type_Type if needed
                        if (auto typeType = paramType->to<IR::Type_Type>()) {
                            paramType = typeType->type;
                        }
                    }
                }
            }
            
            // Get width from Type_Bits
            if (auto type = paramType->to<IR::Type_Bits>()) {
                return type->size;
            }
        }
    }
    return -1;
}

void SVAction::emitExecute(CodeBuilder* builder, const std::string& prefix) {
    if (isNoAction()) {
        builder->appendLine("// NoAction - pass through");
        return;
    }
    
    if (isDropAction()) {
        builder->appendLine("// Drop action");
        std::stringstream ss;
        
        // Fix: increment the stage number for LHS
        std::string lhs_prefix = prefix;
        size_t pos = lhs_prefix.find("stage");
        if (pos != std::string::npos && pos + 5 < lhs_prefix.length()) {
            if (isdigit(lhs_prefix[pos + 5])) {
                lhs_prefix[pos + 5] = '0' + ((lhs_prefix[pos + 5] - '0') + 1);
            }
        }
        ss << lhs_prefix << "_metadata.drop_flag = 1'b1;";
        builder->appendLine(ss.str());
        return;
    }
    
    builder->appendLine("// Execute action " + actionName.string());
    
    if (!p4action->body) {
        builder->appendLine("// Empty action body");
        return;
    }
    
    // Process action body
    for (auto stmt : p4action->body->components) {
        if (auto assign = stmt->to<IR::AssignmentStatement>()) {
            emitAssignment(builder, assign, prefix);
        } else if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            if (auto expr = methodCall->methodCall) {
                emitMethodCall(builder, expr, prefix);
            }
        }
    }
}

void SVAction::emitAssignment(CodeBuilder* builder, 
                              const IR::AssignmentStatement* stmt,
                              const std::string& prefix) {
    std::stringstream ss;
    
    // Get left-hand side (destination)
    std::string lhs_str;
    if (auto member = stmt->left->to<IR::Member>()) {
        lhs_str = getMemberString(member, prefix, true);  // true = LHS
    } else {
        builder->appendLine("// Unsupported LHS in assignment");
        return;
    }
    
    // Get right-hand side (source)
    std::string rhs_str;
    
    if (auto constant = stmt->right->to<IR::Constant>()) {
        // Constant value
        auto bitwidth = constant->type->width_bits();
        if (bitwidth > 0) {
            ss.str("");
            ss << bitwidth << "'d" << constant->asUnsigned();
            rhs_str = ss.str();
        } else {
            rhs_str = std::to_string(constant->asUnsigned());
        }
    } 
    else if (auto member = stmt->right->to<IR::Member>()) {
        // Member access (e.g., hdr.ethernet.srcAddr)
        rhs_str = getMemberString(member, prefix, false);  // false = RHS
    } 
    else if (auto param = stmt->right->to<IR::PathExpression>()) {
        // Action parameter - extract from action_data
        auto paramName = param->path->name;
        int paramOffset = getParameterOffset(paramName);
        int paramWidth = getParameterWidth(paramName);
        
        if (paramOffset >= 0 && paramWidth > 0) {
            ss.str("");
            // Extract parameter from table action_data signal
            ss << "table_" << associatedTable << "_action_data[" 
               << (paramOffset + paramWidth - 1) << ":" << paramOffset << "]";
            rhs_str = ss.str();
            
            ACTION_TRACE("Parameter " << paramName << " mapped to bits ["
                        << (paramOffset + paramWidth - 1) << ":" << paramOffset << "]");
        } else {
            if (SV::g_verbose) {
                std::cerr << "  ERROR: Parameter " << paramName << " not found or has invalid width" << std::endl;
            }
            builder->appendLine("// ERROR: Parameter " + paramName.string() + " not found");
            rhs_str = "0";
        }
    } 
    else if (auto binOp = stmt->right->to<IR::Sub>()) {
        // Handle subtraction (e.g., TTL decrement)
        if (auto left = binOp->left->to<IR::Member>()) {
            std::string left_str = getMemberString(left, prefix, false);
            if (auto const_right = binOp->right->to<IR::Constant>()) {
                ss.str("");
                ss << left_str << " - " << const_right->asUnsigned();
                rhs_str = ss.str();
            }
        }
    } 
    else if (auto binOp = stmt->right->to<IR::Add>()) {
        // Handle addition
        std::string left_str, right_str;
        
        if (auto left = binOp->left->to<IR::Member>()) {
            left_str = getMemberString(left, prefix, false);
        } else if (auto left = binOp->left->to<IR::Constant>()) {
            left_str = std::to_string(left->asUnsigned());
        }
        
        if (auto right = binOp->right->to<IR::Member>()) {
            right_str = getMemberString(right, prefix, false);
        } else if (auto right = binOp->right->to<IR::Constant>()) {
            right_str = std::to_string(right->asUnsigned());
        }
        
        ss.str("");
        ss << left_str << " + " << right_str;
        rhs_str = ss.str();
    }
    else {
        builder->appendLine("// Unsupported RHS type: " + std::string(stmt->right->node_type_name()));
        return;
    }
    
    // Generate assignment
    ss.str("");
    ss << lhs_str << " = " << rhs_str << ";";
    builder->appendLine(ss.str());
}

void SVAction::emitMethodCall(CodeBuilder* builder,
                             const IR::MethodCallExpression* expr,
                             const std::string& prefix) {
    std::string methodName = expr->method->toString().string();
    std::stringstream ss;
    
    if (methodName.find("mark_to_drop") != std::string::npos) {
        // Fix: increment stage for LHS
        std::string lhs_prefix = prefix;
        size_t pos = lhs_prefix.find("stage");
        if (pos != std::string::npos && pos + 5 < lhs_prefix.length()) {
            if (isdigit(lhs_prefix[pos + 5])) {
                lhs_prefix[pos + 5] = '0' + ((lhs_prefix[pos + 5] - '0') + 1);
            }
        }
        ss << lhs_prefix << "_metadata.drop_flag = 1'b1;";
        builder->appendLine(ss.str());
    } 
    else if (methodName.find("setValid") != std::string::npos) {
        builder->appendLine("// setValid - not yet implemented");
    } 
    else if (methodName.find("setInvalid") != std::string::npos) {
        builder->appendLine("// setInvalid - not yet implemented");
    }
    // PHASE 2: Stack operations handled separately in match_action.sv generation
    else if (methodName.find("pop_front") != std::string::npos ||
             methodName.find("push_front") != std::string::npos) {
        builder->appendLine("// Stack operation: " + methodName + " (handled by pointer logic)");
    }
    else {
        builder->appendLine("// Unknown method call: " + methodName);
    }
}

}  // namespace SV