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

class PipelineStage {
public:
    int stageNumber;
    std::vector<SVTable*> tables;
    std::vector<SVAction*> actions;
    std::set<cstring> dependencies;
    
    PipelineStage() : stageNumber(0) {}
    PipelineStage(int num) : stageNumber(num) {}
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
    int totalStages;
    
    std::map<cstring, SVTable*> svTables;
    std::map<cstring, SVAction*> svActions;
    std::map<cstring, std::set<cstring>> action_to_table;
    SV::CFG* cfg;
    std::vector<PipelineStage*> pipelineStages;
    
    void extractTables();
    void extractActions();
    void analyzePipeline();
    
public:
    void setIsIngress(bool value) { isIngress = value; }
    SVProgram* getProgram() const { return program; }
    SVControl(SVProgram* program,
              const IR::ControlBlock* block,
              const TypeMap* typeMap,
              const ReferenceMap* refMap);
    
    ~SVControl();  // Add destructor to clean up allocated memory
    
    bool build();
    void emit(SVCodeGen& codegen);
    void assignPipelineStages();
    void emitModule(CodeBuilder* builder);
    void emitPipelineRegisters(CodeBuilder* builder);
    void emitTableInstances(CodeBuilder* builder);
    void emitActionLogic(CodeBuilder* builder);
    void emitControlFlow(CodeBuilder* builder);
    
    int getStageCount() const { return totalStages; }
    cstring getName() const { return controlName; }
    bool getIsIngress() const { return isIngress; }
    
    std::map<const IR::Node*, const IR::Type*> metadata_to_table;
};

}  // namespace SV

#endif