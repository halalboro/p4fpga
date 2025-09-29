#ifndef P4FPGA_ACTION_H
#define P4FPGA_ACTION_H

#include "common.h"
#include <vector>
#include <map>

namespace SV {

class SVControl;

class SVAction {
private:
    SVControl* control;
    const IR::P4Action* p4action;
    cstring actionName;
    
    std::vector<const IR::Parameter*> parameters;
    int parameterWidth = 0;
    std::map<cstring, cstring> fieldModifications;
    
    void extractParameters();
    void analyzeBody();
    void emitAssignment(CodeBuilder* builder, 
                       const IR::AssignmentStatement* stmt,
                       const std::string& prefix);
    void emitMethodCall(CodeBuilder* builder,
                       const IR::MethodCallExpression* expr,
                       const std::string& prefix);
    
public:
    SVAction(SVControl* ctrl, const IR::P4Action* act) : 
        control(ctrl), p4action(act), actionName(act->name) {}
    
    bool build();
    void emitExecute(CodeBuilder* builder, const std::string& prefix);
    
    bool isNoAction() const { return actionName == "NoAction"; }
    bool isDropAction() const { return actionName == "drop"; }
    
    cstring getName() const { return actionName; }
};

} // namespace SV

#endif