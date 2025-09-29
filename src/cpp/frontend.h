#ifndef P4FPGA_FRONTEND_H
#define P4FPGA_FRONTEND_H

#include "frontends/p4/frontend.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/p4/simplify.h"
#include "frontends/common/resolveReferences/resolveReferences.h"
#include "frontends/p4/typeMap.h"
#include "frontends/p4/createBuiltins.h"
#include "frontends/p4/validateParsedProgram.h"

namespace SV {

// Frontend that does only essential passes
class FrontEnd {
    P4::TypeMap typeMap;
    P4::ReferenceMap refMap;
    
public:
    const IR::P4Program* run(const P4::CompilerOptions& options, 
                            const IR::P4Program* program) {
        if (program == nullptr) return nullptr;
        
        // Add essential passes that create built-ins and do type checking
        P4::PassManager passes;
        passes.addPasses({
            new P4::ValidateParsedProgram(),  // Basic validation
            new P4::CreateBuiltins(),         // Creates 'accept' and 'reject' states
            new P4::ResolveReferences(&refMap),
            new P4::TypeInference(&typeMap, false, false),  // Two bool params
            new P4::TypeChecking(&refMap, &typeMap)
        });
        
        // Don't add debug hooks - they're causing the crash
        passes.setStopOnError(true);
        
        return program->apply(passes);
    }
    
    P4::TypeMap& getTypeMap() { return typeMap; }
    P4::ReferenceMap& getRefMap() { return refMap; }
};

}  // namespace SV

#endif