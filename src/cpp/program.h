// program.h
#ifndef P4FPGA_PROGRAM_H
#define P4FPGA_PROGRAM_H

#include "common.h"
#include "bsvprogram.h"
#include "control.h"  // NEW: Include for ControlConfig
#include <map>
#include <vector>
#include <set>
#include <string>
#include <cstdint>

namespace SV {

class SVCodeGen;
class SVParser;
class SVControl;
class SVDeparser;

class SVProgram : public FPGAObject {
public:
    const IR::ToplevelBlock* toplevel;
    const IR::P4Program* program;
    ReferenceMap* refMap;
    TypeMap* typeMap;
    
    SVParser* parser;
    SVControl* ingress;
    SVControl* egress;
    SVDeparser* deparser;
    
    std::map<const IR::Node*, const IR::Type*> metadata_to_table;
    std::set<cstring> reservedWords;
    
    struct {
        int dataWidth = 512;
        int metadataWidth = 64;
        int stageCount = 0;
    } pipelineConfig;
    
    // Parser/Deparser configurations
    uint8_t parserConfig;
    uint16_t deparserConfig;
    
    // NEW: Control configuration for submodules
    ControlConfig controlConfig;
    
    // Constructor
    SVProgram(const IR::ToplevelBlock* toplevel,
              ReferenceMap* refMap,
              TypeMap* typeMap) :
        toplevel(toplevel),
        program(nullptr),
        refMap(refMap),
        typeMap(typeMap),
        parser(nullptr),
        ingress(nullptr),
        egress(nullptr),
        deparser(nullptr),
        parserConfig(0),
        deparserConfig(0) {}
    
    // Destructor
    ~SVProgram();
    
    bool build();
    void emit(SVCodeGen& codegen);
    
    // Copy parser/deparser templates
    bool copyTemplates(const std::string& outputDir);
    
    // Get configurations
    uint8_t getParserConfig() const { return parserConfig; }
    uint16_t getDeparserConfig() const { return deparserConfig; }
    ControlConfig getControlConfig() const { return controlConfig; }
    
    // Generate control slave module
    void emitControlSlave(const std::string& outputDir, const std::string& baseName);

private:
    void emitRouterTop(SVCodeGen& codegen);
    void emitInterStageSignals(CodeBuilder* builder);
    void emitParserInstance(CodeBuilder* builder);
    
    // NEW: Emit submodule instances instead of control wrapper
    void emitMatchEngineInstance(CodeBuilder* builder);
    void emitActionEngineInstance(CodeBuilder* builder);
    void emitStatsEngineInstance(CodeBuilder* builder);
    
    void emitDeparserInstance(CodeBuilder* builder);
    
    // LEGACY: Old-style type definitions (not used by new pipeline)
    void emitTypeDefinitions(CodeBuilder* builder);
    void emitHeaders(CodeBuilder* builder);
    void emitMetadata(CodeBuilder* builder);
    void emitStandardMetadata(CodeBuilder* builder);
    void emitInterfaces(CodeBuilder* builder);
    
    // DEPRECATED: Old pipeline instance (replaced by submodules)
    void emitPipelineInstance(CodeBuilder* builder);
};

} // namespace SV

#endif // P4FPGA_PROGRAM_H