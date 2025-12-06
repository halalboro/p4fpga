/*
 * P4-FPGA Compiler - Backend Component
 *
 * Orchestrates SystemVerilog code generation from P4 IR.
 * Processes templates and generates synthesizable HDL modules.
 */

#ifndef BACKENDS_SV_BACKEND_H_
#define BACKENDS_SV_BACKEND_H_

#include "common.h"
#include <fstream>
#include <string>

namespace SV {

class Backend {
private:
    P4::ReferenceMap* refMap;
    P4::TypeMap* typeMap;
    
    bool copyStaticTemplates(const std::string& outputDir);

    bool processMatchTemplate(SVProgram* program, const std::string& outputDir);
    bool processMatchActionTemplate(SVProgram* program, const std::string& outputDir);
    bool processActionTemplate(SVProgram* program, const std::string& outputDir);
    bool processEgressTemplate(SVProgram* program, const std::string& outputDir);
    
public:
    Backend(P4::ReferenceMap* rm, P4::TypeMap* tm) :
        refMap(rm), typeMap(tm) {}
    
    bool run(const SVOptions& options,
             const IR::ToplevelBlock* toplevel,
             P4::ReferenceMap* refMap,
             P4::TypeMap* typeMap);
};

}  // namespace SV

#endif  // BACKENDS_SV_BACKEND_H_