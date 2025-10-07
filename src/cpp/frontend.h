#ifndef P4FPGA_FRONTEND_H
#define P4FPGA_FRONTEND_H

#include "frontends/p4/frontend.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/p4/createBuiltins.h"
#include "frontends/p4/validateParsedProgram.h"
#include "frontends/common/resolveReferences/resolveReferences.h"
#include "frontends/p4/typeMap.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/parserControlFlow.h"
#include "frontends/p4/parseAnnotations.h"

namespace SV {

class FrontEnd {
public:
    P4::TypeMap* typeMap;
    P4::ReferenceMap* refMap;
    
    FrontEnd() {
        typeMap = new P4::TypeMap();
        refMap = new P4::ReferenceMap();
        refMap->setIsV1(false);
    }
    
    ~FrontEnd() {
        delete typeMap;
        delete refMap;
    }
    
    const IR::P4Program* run(const P4::CompilerOptions&,
                            const IR::P4Program* program) {
        if (program == nullptr) return nullptr;
        
        // Run minimal passes to populate the IR properly
        // These passes populate parser states and control bodies
        P4::ParseAnnotations parseAnnotations;
        program = program->apply(parseAnnotations);
        
        P4::ValidateParsedProgram validator;
        program = program->apply(validator);
        
        P4::CreateBuiltins createBuiltins;
        program = program->apply(createBuiltins);
        
        P4::ResolveReferences resolver(refMap);
        program = program->apply(resolver);
        
        P4::TypeInference typeInf(typeMap, false, false, false);
        program = program->apply(typeInf);
        
        P4::TypeChecking typeCheck(refMap, typeMap);
        program = program->apply(typeCheck);
        
        return program;
    }
    
    P4::TypeMap* getTypeMap() { return typeMap; }
    P4::ReferenceMap* getRefMap() { return refMap; }
};

}  // namespace SV

#endif