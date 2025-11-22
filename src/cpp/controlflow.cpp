#include "controlflow.h"
#include "lib/log.h"
#include "common.h"
#include "control.h"
#include "table.h"
#include "action.h"
#include "program.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

ControlFlowLowering::ControlFlowLowering(P4::ReferenceMap* refMap, P4::TypeMap* typeMap) 
    : refMap(refMap), typeMap(typeMap), uniqueId(0) {
    // Note: setName() is not available in all Transform versions
    // If it fails to compile, comment out the next line
    // setName("ControlFlowLowering");
}

bool ControlFlowLowering::isSimpleIfElse(const IR::IfStatement* stmt) {
    // Must have true branch
    if (!stmt->ifTrue) return false;
    
    // True branch must be single action call
    if (!isActionCall(stmt->ifTrue)) return false;
    
    // False branch (if present) must also be single action call
    if (stmt->ifFalse && !isActionCall(stmt->ifFalse)) return false;
    
    // Condition must be a simple == comparison
    auto equ = stmt->condition->to<IR::Equ>();
    if (!equ) {
        LOG2("ControlFlow: Condition is not ==, skipping");
        return false;
    }
    
    return true;
}

bool ControlFlowLowering::isActionCall(const IR::Statement* stmt) {
    auto block = stmt->to<IR::BlockStatement>();
    if (!block) {
        LOG2("ControlFlow: Statement is not a block");
        return false;
    }
    
    if (block->components.size() != 1) {
        LOG2("ControlFlow: Block has " << block->components.size() 
             << " components, need exactly 1");
        return false;
    }
    
    auto methodCall = block->components[0]->to<IR::MethodCallStatement>();
    if (!methodCall) {
        LOG2("ControlFlow: Component is not a method call");
        return false;
    }
    
    return true;
}

const IR::MethodCallExpression* ControlFlowLowering::extractAction(
    const IR::Statement* stmt) {
    auto block = stmt->to<IR::BlockStatement>();
    if (!block || block->components.size() == 0) return nullptr;
    
    auto methodCall = block->components[0]->to<IR::MethodCallStatement>();
    if (!methodCall) return nullptr;
    
    return methodCall->methodCall;
}

const IR::Node* ControlFlowLowering::postorder(IR::IfStatement* stmt) {
    LOG2("ControlFlow: Examining if-statement");
    
    // Only handle simple if-else with == conditions
    if (!isSimpleIfElse(stmt)) {
        LOG2("ControlFlow: Not a simple if-else, keeping as-is");
        return stmt;
    }
    
    auto condition = stmt->condition->to<IR::Equ>();
    auto key = condition->left;
    auto value = condition->right;
    
    // Extract actions
    auto trueAction = extractAction(stmt->ifTrue);
    auto falseAction = stmt->ifFalse ? extractAction(stmt->ifFalse) : nullptr;
    
    // Log what we found
    LOG1("╔═══════════════════════════════════════════╗");
    LOG1("║  ControlFlow: Found simple if-else       ║");
    LOG1("╚═══════════════════════════════════════════╝");
    LOG1("  Condition: " << key << " == " << value);
    
    if (trueAction) {
        LOG1("  True branch:  " << trueAction->method);
        if (trueAction->arguments && trueAction->arguments->size() > 0) {
            LOG1("    Arguments: " << trueAction->arguments);
        }
    }
    
    if (falseAction) {
        LOG1("  False branch: " << falseAction->method);
        if (falseAction->arguments && falseAction->arguments->size() > 0) {
            LOG1("    Arguments: " << falseAction->arguments);
        }
    }
    
    LOG1("───────────────────────────────────────────");
    
    
    return stmt;
}

}  // namespace SV