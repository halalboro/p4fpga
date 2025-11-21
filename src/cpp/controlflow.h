#ifndef P4FPGA_CONTROLFLOW_H
#define P4FPGA_CONTROLFLOW_H

#include "common.h"
#include <vector>
#include <map>
#include <set>
#include <string>
#include "ir/ir.h"
#include "ir/visitor.h"
#include "frontends/p4/typeMap.h"
#include "frontends/common/resolveReferences/referenceMap.h"

namespace SV {

/**
 * Control Flow Lowering Pass
 * 
 * Phase 3: Detect and transform if-else statements
 * 
 * Detects simple conditional logic:
 *   if (hdr.field == value) { action_a(); } else { action_b(); }
 * 
 * Future: Will lower to match-action tables
 */
class ControlFlowLowering : public P4::Transform {
    P4::ReferenceMap* refMap;
    P4::TypeMap* typeMap;
    int uniqueId;
    
public:
    ControlFlowLowering(P4::ReferenceMap* refMap, P4::TypeMap* typeMap);
    
    const IR::Node* postorder(IR::IfStatement* stmt) override;
    
private:
    bool isSimpleIfElse(const IR::IfStatement* stmt);
    bool isActionCall(const IR::Statement* stmt);
    const IR::MethodCallExpression* extractAction(const IR::Statement* stmt);
};

}  // namespace SV

#endif  // P4FPGA_CONTROLFLOW_H