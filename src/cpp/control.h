#ifndef EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_CONTROL_H_
#define EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_CONTROL_H_

#include "common.h"
#include <vector>
#include <map>
#include <set>
#include <string>

namespace SV {

class SVProgram;
class SVCodeGen;
class SVTable;
class SVAction;

// Configuration structure for submodules
struct ControlConfig {
    uint8_t matchType;        // 0=Exact, 1=LPM, 2=Ternary, 3=Range
    uint8_t actionConfig;     // Bitmask: [Hash|Decap|Encap|Modify|Drop|Forward]
                              //   Bit 0: Forward
                              //   Bit 1: Drop
                              //   Bit 2: (unused)
                              //   Bit 3: Modify headers
                              //   Bit 4: Encap
                              //   Bit 5: Decap
                              //   Bit 6: Hash
    uint8_t egressConfig;     // Egress processing config
                              //   Bit 0: Enable egress
                              //   Bit 1: ECN marking
                              //   Bit 2: Stateful (registers/counters)
    uint32_t tableSize;
    uint32_t keyWidth;
    uint32_t ecnThreshold;
};

struct HashInfo {
    cstring outputField;     // meta.flow_hash
    cstring algorithm;       // crc16, crc32, xor
    std::vector<cstring> inputFields;  // {srcAddr, dstAddr, ...}
    int outputWidth;
};

class SVControl {
private:
    SVProgram* program;
    const IR::ControlBlock* controlBlock;
    const IR::P4Control* p4control;
    const TypeMap* typeMap;
    const ReferenceMap* refMap;
    
    cstring controlName;
    bool isIngress;
    bool isEgress;                    
    bool hasEgressActions;
    bool detectHashCalls();            
    
    std::map<cstring, SVTable*> svTables;
    std::map<cstring, SVAction*> svActions;
    std::map<cstring, std::set<cstring>> action_to_table;
        
    std::vector<std::pair<cstring, int>> getRequiredParsedFields();
    std::vector<HashInfo> hashCalls;
    
    void extractTables();
    void extractActions();

public:
    SVControl(SVProgram* program,
              const IR::ControlBlock* block,
              const TypeMap* typeMap,
              const ReferenceMap* refMap);
    
    ~SVControl();
    
    bool build();
    void emit(SVCodeGen& codegen);
    
    // Extract configuration for submodules
    ControlConfig extractConfiguration();

    bool hasStatefulOperations() const;
    
    void setIsIngress(bool value) { isIngress = value; }
    const std::vector<HashInfo>& getHashCalls() const { return hashCalls; }
    bool hasHashOperations() const { return !hashCalls.empty(); }

     /** Get action by name */
    SVAction* getAction(const cstring& name) const {
        auto it = svActions.find(name);
        return (it != svActions.end()) ? it->second : nullptr;
    }
    
    /** Get action ID by name (index in action list) */
    int getActionId(const cstring& name) const {
        int actionId = 0;
        for (const auto& actionPair : svActions) {
            if (actionPair.first == name) {
                return actionId;
            }
            actionId++;
        }
        return 0;  // Default to NoAction
    }
    
    // Egress-related getters
    bool getIsEgress() const { return isEgress; }
    bool getHasEgressActions() const { return hasEgressActions; }
    
    SVProgram* getProgram() const { return program; }
    const std::map<cstring, SVTable*>& getTables() const { return svTables; }
    const std::map<cstring, SVAction*>& getActions() const { return svActions; }
    cstring getName() const { return controlName; }
    bool getIsIngress() const { return isIngress; }
};

}  // namespace SV

#endif  // EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_CONTROL_H_