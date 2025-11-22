#ifndef P4FPGA_PROGRAM_H
#define P4FPGA_PROGRAM_H

#include "common.h"
#include "bsvprogram.h"
#include "control.h"
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
class SVMetadata;

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

    const SVMetadata* getMetadata() const { return metadata; }
    void setMetadata(SVMetadata* m) { metadata = m; }
    
    std::map<const IR::Node*, const IR::Type*> metadata_to_table;
    std::set<cstring> reservedWords;
    
    struct {
        int dataWidth = 512;
        int metadataWidth = 64;
        int stageCount = 0;
    } pipelineConfig;
    
    uint8_t parserConfig;
    uint16_t deparserConfig;
    ControlConfig controlConfig;
    uint32_t ecnThreshold;  // Extracted from P4 constants
    
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
        deparserConfig(0),
        metadata(nullptr),   
        ecnThreshold(10) {}  // Default threshold
    
    ~SVProgram();
    
    bool build();
    void emit(SVCodeGen& codegen);
    bool copyTemplates(const std::string& outputDir);
    
    // ==========================================
    // PUBLIC GETTER METHODS
    // ==========================================
    
    // Component getters
    SVParser* getParser() const { return parser; }
    SVDeparser* getDeparser() const { return deparser; }
    SVControl* getIngress() const { return ingress; }
    SVControl* getEgress() const { return egress; }
    
    // Configuration getters
    uint8_t getParserConfig() const { return parserConfig; }
    uint16_t getDeparserConfig() const { return deparserConfig; }
    ControlConfig getControlConfig() const { return controlConfig; }
    unsigned getECNThreshold() const { return ecnThreshold; }

private:
    void extractConstants();  // Extract P4 constants
    SVMetadata* metadata;
};

}  // namespace SV

#endif  // P4FPGA_PROGRAM_H