/*
 * P4-FPGA Compiler - Action Component
 *
 * Handles P4 action analysis and operation detection.
 * Detects arithmetic operations, MAC swaps, stack operations,
 * register access, and other action patterns for hardware generation.
 */

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

// ==========================================
// Arithmetic Operation Structure
// For calc.p4 style computations
// ==========================================
struct ArithmeticOperation {
    enum OpType { NONE, ADD, SUB, BAND, BOR, BXOR, ASSIGN };
    OpType op = NONE;
    
    cstring destHeader;
    cstring destField;
    
    bool src1IsConstant = false;
    cstring srcHeader1;
    cstring srcField1;
    int64_t srcConstant1 = 0;
    
    bool src2IsConstant = false;
    cstring srcHeader2;
    cstring srcField2;
    int64_t srcConstant2 = 0;
    
    // For method call arguments - callee resolution
    cstring calleeAction;
    size_t calleeParamIndex = 0;
    
    bool needsCalleeResolution() const {
        return !calleeAction.isNullOrEmpty();
    }
    
    bool isBinaryOp() const {
        return op == ADD || op == SUB || op == BAND || op == BOR || op == BXOR;
    }
    
    std::string getOperatorString() const {
        switch (op) {
            case ADD: return "+";
            case SUB: return "-";
            case BAND: return "&";
            case BOR: return "|";
            case BXOR: return "^";
            default: return "";
        }
    }
};

// ==========================================
// MAC Swap Operation
// For send_back style actions
// ==========================================
struct MacSwapOperation {
    bool enabled;
    cstring srcMacHeader;   // "ethernet"
    cstring srcMacField;    // "srcAddr"
    cstring dstMacHeader;   // "ethernet"
    cstring dstMacField;    // "dstAddr"
    
    MacSwapOperation() : enabled(false) {}
};

// ==========================================
// Egress Spec Assignment
// For setting output port
// ==========================================
struct EgressSpecAssignment {
    bool enabled;
    bool useIngressPort;    // egress_spec = ingress_port
    int constantPort;       // egress_spec = constant
    
    EgressSpecAssignment() : enabled(false), useIngressPort(false), constantPort(0) {}
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
    
    // Arithmetic operations tracking
    std::vector<ArithmeticOperation> arithmeticOps_;
    
    // MAC swap tracking
    MacSwapOperation macSwap_;
    
    // Egress spec tracking
    EgressSpecAssignment egressSpec_;

    cstring calledAction_;  // Name of action called by this action (if any)
    
    void extractParameters();
    void analyzeBody();
    void detectStackOperations();
    
    // Helper to extract header.field from IR::Member
    bool extractMemberInfo(const IR::Expression* expr, 
                          cstring& headerName, 
                          cstring& fieldName);
    
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
    
    // Arithmetic operation queries
    bool hasArithmeticOps() const { return !arithmeticOps_.empty(); }
    const std::vector<ArithmeticOperation>& getArithmeticOps() const {
        return arithmeticOps_;
    }
    
    // MAC swap query
    bool hasMacSwap() const { return macSwap_.enabled; }
    const MacSwapOperation& getMacSwap() const { return macSwap_; }
    
    // Egress spec query
    bool hasEgressSpec() const { return egressSpec_.enabled; }
    const EgressSpecAssignment& getEgressSpec() const { return egressSpec_; }

    cstring getCalledAction() const { return calledAction_; }
    
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