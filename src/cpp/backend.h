// backend.h
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
    
    // Helper methods for integration file generation
    void emitVFPGATemplate(std::ofstream& out, const std::string& baseName);
    void emitVivadoTCL(std::ofstream& out);
    
    // Copy parser/deparser templates
    bool copyTemplates(const std::string& outputDir);
    
    // Copy submodules (match, action, stats)
    bool copySubmodules(const std::string& outputDir);

public:
    Backend(P4::ReferenceMap* rm, P4::TypeMap* tm) :
        refMap(rm), typeMap(tm) {}
    
    bool run(const SVOptions& options,
             const IR::ToplevelBlock* toplevel,
             P4::ReferenceMap* refMap,
             P4::TypeMap* typeMap);
};

} // namespace SV

#endif // BACKENDS_SV_BACKEND_H_