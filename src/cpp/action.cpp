#include "common.h"
#include "action.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

bool SVAction::build() {
    LOG2("Building action: " << actionName);
    
    extractParameters();
    analyzeBody();
    
    return true;
}

void SVAction::extractParameters() {
    for (auto param : p4action->parameters->parameters) {
        parameters.push_back(param);
        if (auto type = param->type->to<IR::Type_Bits>()) {
            parameterWidth += type->size;
        }
    }
    LOG3("Action " << actionName << " has " << parameters.size() 
         << " parameters, width: " << parameterWidth);
}

void SVAction::analyzeBody() {
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

void SVAction::emitExecute(CodeBuilder* builder, const std::string& prefix) {
    if (isNoAction()) {
        builder->appendLine("// NoAction - pass through");
        return;
    }
    
    if (isDropAction()) {
        builder->appendLine("// Drop action");
        builder->append("// TODO: implement drop");
        return;
    }
    
    builder->append("// TODO: action implementation");
    
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
    // Generate assignment statement
    if (auto lhs = stmt->left->to<IR::Member>()) {
        std::string target;
        std::string source;
        
        // Determine target location (header or metadata)
        if (auto lhsExpr = lhs->expr->to<IR::Member>()) {
            auto structName = lhsExpr->member;
            auto fieldName = lhs->member;
            
            if (structName == "hdr") {
                target = prefix + "_headers." + fieldName.toString();
            } else if (structName == "meta") {
                target = prefix + "_metadata." + fieldName.toString();
            } else {
                target = prefix + "_metadata.standard_metadata." + fieldName.toString();
            }
        }
        
        // Generate source expression
        if (auto constant = stmt->right->to<IR::Constant>()) {
            source = std::to_string(constant->asLong()) + "'d" + std::to_string(constant->asLong());
        } else if (auto rhs = stmt->right->to<IR::Member>()) {
            if (auto rhsExpr = rhs->expr->to<IR::Member>()) {
                auto structName = rhsExpr->member;
                auto fieldName = rhs->member;
                
                if (structName == "hdr") {
                    source = prefix + "_headers." + fieldName.toString();
                } else if (structName == "meta") {
                    source = prefix + "_metadata." + fieldName.toString();
                } else {
                    source = prefix + "_metadata.standard_metadata." + fieldName.toString();
                }
            }
        } else if (auto param = stmt->right->to<IR::PathExpression>()) {
            // Action parameter
            source = "action_data[" + param->path->name.toString() + "]";
        } else {
            source = "0";  // Default
        }
        
        // Build the assignment string
        std::stringstream ss;
        ss << target << " <= " << source << ";";
        builder->appendLine(ss.str());
    }
}

void SVAction::emitMethodCall(CodeBuilder* builder,
                             const IR::MethodCallExpression* expr,
                             const std::string& prefix) {
    auto methodName = expr->method->toString();
    
    if (methodName == "setValid") {
        // Set header validity
        if (expr->arguments->size() > 0) {
            auto arg = expr->arguments->at(0);
            if (arg->expression && arg->expression->is<IR::Member>()) {
                auto member = arg->expression->to<IR::Member>();
                auto headerName = member->member.toString();
                std::stringstream ss;
                ss << prefix << "_headers." << headerName << "_valid = 1'b1;";
                builder->appendLine(ss.str());
            }
        }
    } else if (methodName == "setInvalid") {
        // Clear header validity
        if (expr->arguments->size() > 0) {
            auto arg = expr->arguments->at(0);
            if (arg->expression && arg->expression->is<IR::Member>()) {
                auto member = arg->expression->to<IR::Member>();
                auto headerName = member->member.toString();
                std::stringstream ss;
                ss << prefix << "_headers." << headerName << "_valid = 1'b0;";
                builder->appendLine(ss.str());
            }
        }
    } else if (methodName == "mark_to_drop") {
        // Mark packet for dropping
        std::stringstream ss;
        ss << prefix << "_metadata.drop_flag = 1'b1;";
        builder->appendLine(ss.str());
    }
}

}  // namespace SV