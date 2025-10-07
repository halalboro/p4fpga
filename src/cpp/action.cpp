#include "common.h"
#include "action.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

bool SVAction::build() {
    LOG2("Building action: " << actionName);
    extractParameters();
    LOG2("Action " << actionName << " has " << parameters.size() << " parameters");
    for (auto p : parameters) {
        LOG2("  Parameter: " << p->name << " width: " << p->type->width_bits());
    }
    analyzeBody();
    return true;
}

void SVAction::extractParameters() {
    std::cerr << "Extracting parameters for action " << actionName << std::endl;
    
    if (!p4action->parameters) {
        std::cerr << "  p4action has no parameters" << std::endl;
        return;
    }
    
    std::cerr << "  p4action has " << p4action->parameters->parameters.size() << " params" << std::endl;
    
    for (auto param : p4action->parameters->parameters) {
        std::cerr << "  Found parameter: " << param->name;
        parameters.push_back(param);
        
        // Get the actual type, resolving typedefs
        auto paramType = param->type;
        
        // If it's a typedef, resolve it to the underlying type
        if (auto typeRef = paramType->to<IR::Type_Name>()) {
            std::cerr << " (typedef: " << typeRef->path->name << ")";
            
            // Try to resolve the typedef using the type map
            if (typeMap) {
                auto resolvedType = typeMap->getType(typeRef, true);
                if (resolvedType) {
                    std::cerr << " -> resolved to " << resolvedType->node_type_name();
                    paramType = resolvedType;
                    
                    // If it's a Type_Type, unwrap it to get the actual type
                    if (auto typeType = paramType->to<IR::Type_Type>()) {
                        std::cerr << " -> unwrapping Type_Type";
                        paramType = typeType->type;
                        std::cerr << " -> " << paramType->node_type_name();
                    }
                }
            }
        }
        
        // Now get the width - use ->size directly for Type_Bits
        if (auto bits = paramType->to<IR::Type_Bits>()) {
            parameterWidth += bits->size;
            std::cerr << " (bit<" << bits->size << ">)";
        } else {
            // For other types, log error
            std::cerr << " (ERROR: not a Type_Bits, got " << paramType->node_type_name() << ")";
        }
        
        std::cerr << std::endl;
    }
    
    std::cerr << "  Total parameter width: " << parameterWidth << " bits" << std::endl;
}

void SVAction::analyzeBody() {
    if (!p4action->body) {
        return;
    }
    
    // Analyze action body to determine what fields are modified
    for (auto stmt : p4action->body->components) {
        if (auto assign = stmt->to<IR::AssignmentStatement>()) {
            if (auto lhs = assign->left->to<IR::Member>()) {
                auto fieldName = lhs->member;
                // Store the assignment for code generation
                fieldModifications[fieldName] = cstring::literal("modified");
                LOG3("Action " << actionName << " modifies field: " << fieldName);
            }
        } else if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            auto method = methodCall->methodCall->method->toString();
            LOG3("Action " << actionName << " calls method: " << method);
        }
    }
}

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
            
            std::cerr << "  Parameter " << paramName << " mapped to bits ["
                     << (paramOffset + paramWidth - 1) << ":" << paramOffset << "]" << std::endl;
        } else {
            std::cerr << "  ERROR: Parameter " << paramName << " not found or has invalid width" << std::endl;
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
    else {
        builder->appendLine("// Unknown method call: " + methodName);
    }
}

}  // namespace SV