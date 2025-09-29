#include "midend.h"
#include "options.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/p4/simplify.h"
#include "frontends/common/resolveReferences/resolveReferences.h"
#include "midend/removeExits.h"
#include "lib/log.h"

namespace SV {

const IR::ToplevelBlock* MidEnd::run(const SVOptions& options,
                                      const IR::P4Program* program) {
    if (program == nullptr) {
        P4::error("Null program provided to midend");
        return nullptr;
    }
    
    LOG1("Running midend passes");
    
    // First resolve references and type check
    P4::PassManager initialPasses;
    initialPasses.addPasses({
        new P4::ResolveReferences(&refMap),
        new P4::TypeInference(&typeMap, false), 
    });
    
    program = program->apply(initialPasses);
    
    // Apply midend transformations
    P4::PassManager midEndPasses;
    
    // SimplifyControlFlow requires typeMap parameter
    midEndPasses.addPasses({
        new P4::SimplifyControlFlow(&typeMap, true),  
    });
    
    // RemoveExits requires both refMap and typeMap
    midEndPasses.addPasses({
        new P4::RemoveExits(&typeMap), 
    });
    
    program = program->apply(midEndPasses);
    
    // Final type checking
    P4::PassManager finalPasses;
    finalPasses.addPasses({
        new P4::TypeChecking(&refMap, &typeMap),
    });
    
    program = program->apply(finalPasses);
    
    // Create toplevel block
    const IR::ToplevelBlock* toplevel = nullptr;
    
    // The evaluator creates the ToplevelBlock from the P4Program
    P4::Evaluator evaluator(&refMap, &typeMap);
    
    program->apply(evaluator);
    
    // Get the toplevel block from evaluator
    toplevel = evaluator.getToplevelBlock();
    
    if (!toplevel) {
        // Fall back to manual creation
        toplevel = new IR::ToplevelBlock(program);
    }
    
    if (!toplevel) {
        P4::error("Failed to create toplevel block");
        return nullptr;
    }
    
    LOG1("Midend complete");
    return toplevel;
}

}  // namespace SV