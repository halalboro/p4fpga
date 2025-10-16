// control.h
#ifndef EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_CONTROL_H_
#define EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_CONTROL_H_

#include "common.h"
#include "analyzer.h"
#include <vector>
#include <map>
#include <set>
#include <string>

namespace SV {

class SVProgram;
class SVCodeGen;
class SVTable;
class SVAction;

// NEW: Configuration structure for submodules
struct ControlConfig {
    uint8_t matchType;        // 0=Exact, 1=LPM, 2=Ternary, 3=Range
    uint8_t actionConfig;     // Bitmask: [Hash|Encap|Decap|Modify|Drop|Forward]
    uint32_t tableSize;
    uint32_t keyWidth;
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
    
    std::map<cstring, SVTable*> svTables;
    std::map<cstring, SVAction*> svActions;
    std::map<cstring, std::set<cstring>> action_to_table;
    
    // Pipeline emission helpers (DEPRECATED - will be removed)
    void emitModuleHeader(CodeBuilder* builder);
    void emitPortDeclarations(CodeBuilder* builder);
    void emitInternalSignals(CodeBuilder* builder);
    void emitTableStructDefinition(CodeBuilder* builder);
    void emitTableStorage(CodeBuilder* builder);
    void emitTableLookupLogic(CodeBuilder* builder);
    void emitActionExecutionLogic(CodeBuilder* builder);
    void emitChecksumUpdateLogic(CodeBuilder* builder);
    void emitStatisticsCounters(CodeBuilder* builder);
    void emitSimpleTableControl(CodeBuilder* builder);
    
    // Helper to get parsed header inputs needed
    std::vector<std::pair<cstring, int>> getRequiredParsedFields();
    
    void extractTables();
    void extractActions();

public:
    SVControl(SVProgram* program,
              const IR::ControlBlock* block,
              const TypeMap* typeMap,
              const ReferenceMap* refMap);
    ~SVControl();
    
    bool build();
    
    // DEPRECATED: Will be replaced by extractConfiguration()
    void emit(SVCodeGen& codegen);
    
    // NEW: Extract configuration for submodules
    ControlConfig extractConfiguration();
    
    void setIsIngress(bool value) { isIngress = value; }
    SVProgram* getProgram() const { return program; }
    const std::map<cstring, SVTable*>& getTables() const { return svTables; }
    const std::map<cstring, SVAction*>& getActions() const { return svActions; }
    cstring getName() const { return controlName; }
    bool getIsIngress() const { return isIngress; }
};

} // namespace SV

#endif // EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_CONTROL_H_