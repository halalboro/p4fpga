#ifndef BACKENDS_SV_BACKEND_H_
#define BACKENDS_SV_BACKEND_H_

#include "common.h"

namespace SV {

class Backend {
    P4::ReferenceMap* refMap;
    P4::TypeMap* typeMap;
    
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