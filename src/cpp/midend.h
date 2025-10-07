#ifndef P4FPGA_MIDEND_H
#define P4FPGA_MIDEND_H
#include "common.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"
#include "ir/pass_manager.h"

namespace SV {
class SVOptions;

class MidEnd {
public:
    P4::ReferenceMap* refMap;
    P4::TypeMap* typeMap;
    
    MidEnd() : refMap(nullptr), typeMap(nullptr) {}
    
    const IR::ToplevelBlock* run(const SVOptions& options,
                                 const IR::P4Program* program);
};
} // namespace SV
#endif