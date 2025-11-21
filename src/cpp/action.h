// action.h

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
    const TypeMap* typeMap;
    cstring actionName;
    
    int parameterWidth;
    std::vector<const IR::Parameter*> parameters;
    std::map<cstring, cstring> fieldModifications;
    cstring associatedTable;
    
    void extractParameters();
    void analyzeBody();
    
public:
    SVAction(SVControl* ctrl, const IR::P4Action* act) :
        control(ctrl),
        p4action(act),
        typeMap(nullptr),
        actionName(act->name),
        parameterWidth(0) {}
    
    bool build();
    
    void setTypeMap(const TypeMap* tm) { typeMap = tm; }
    void setAssociatedTable(cstring tableName) { associatedTable = tableName; }
    
    // NEW: Stateful operation detection
    bool usesRegisters() const;
    bool usesHash() const;
    bool usesCounters() const;
    
    // Existing methods
    bool isNoAction() const { 
        return actionName == "NoAction" || actionName == "noAction"; 
    }
    
    bool isDropAction() const { 
        return actionName == "drop" || 
               actionName.string().find("mark_to_drop") != std::string::npos; 
    }
    
    cstring getName() const { return actionName; }
    int getParameterWidth() const { return parameterWidth; }
    const std::vector<const IR::Parameter*>& getParameters() const { return parameters; }
    
    void emitExecute(CodeBuilder* builder, const std::string& prefix);
    void emitAssignment(CodeBuilder* builder, 
                       const IR::AssignmentStatement* stmt,
                       const std::string& prefix);
    void emitMethodCall(CodeBuilder* builder,
                       const IR::MethodCallExpression* expr,
                       const std::string& prefix);
    
    std::string getMemberString(const IR::Expression* expr,
                               const std::string& prefix,
                               bool isLhs);
    std::string getMemberString(const IR::Member* member,
                               const std::string& prefix,
                               bool isLhs);
    
    int getParameterOffset(cstring paramName);
    int getParameterWidth(cstring paramName);
};

}  // namespace SV

#endif