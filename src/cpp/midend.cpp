#include "midend.h"
#include "options.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "lib/log.h"

namespace SV {

const IR::ToplevelBlock* MidEnd::run(const SVOptions& options,
                                     const IR::P4Program* program) {
    if (program == nullptr) {
        P4::error("Null program provided to midend");
        return nullptr;
    }
    
    if (refMap == nullptr || typeMap == nullptr) {
        P4::error("MidEnd requires refMap and typeMap to be set");
        return nullptr;
    }
    
    LOG1("Running midend passes");
        
    // Create toplevel block
    P4::Evaluator evaluator(refMap, typeMap);
    program->apply(evaluator);
    
    const IR::ToplevelBlock* toplevel = evaluator.getToplevelBlock();
    if (!toplevel) {
        // If evaluator didn't create one, make it manually
        toplevel = new IR::ToplevelBlock(program);
    }
    
    if (!toplevel) {
        P4::error("Failed to create toplevel block");
        return nullptr;
    }
    
    LOG1("Midend complete");
    return toplevel;
}

} // namespace SV