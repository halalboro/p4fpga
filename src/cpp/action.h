#ifndef P4FPGA_ACTION_H
#define P4FPGA_ACTION_H

#include "common.h"
#include <vector>
#include <map>

namespace SV {

class SVControl;

struct StackOperation {
    enum OpType {
        POP_FRONT,
        PUSH_FRONT
    };
    
    OpType type;
    cstring stackName;     // e.g., "srcRoutes"
    int count;             // Number of elements (default 1)
    
    StackOperation() : type(POP_FRONT), count(1) {}
};

struct Assignment {
    std::string dest;
    std::string source;
    // Add other fields if needed
};

class SVAction {
private:
    SVControl* control;
    const IR::P4Action* p4action;
    const TypeMap* typeMap;
    cstring actionName;
    int parameterWidth;
    std::vector<Assignment> assignments;
    
    std::vector<const IR::Parameter*> parameters;
    std::map<cstring, cstring> fieldModifications;
    cstring associatedTable;
    
    // Stack operations tracking
    std::vector<StackOperation> stackOperations;
    
    void extractParameters();
    void analyzeBody();
    void detectStackOperations(); 
    
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
    
    // Stateful operation detection
    bool usesRegisters() const;
    bool usesHash() const;
    bool usesCounters() const;

    const std::vector<Assignment>& getAssignments() const { return assignments; }
    
    // Stack operation queries
    bool usesStackOperations() const { return !stackOperations.empty(); }
    const std::vector<StackOperation>& getStackOperations() const { 
        return stackOperations; 
    }
    
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