#ifndef P4FPGA_PROGRAM_H
#define P4FPGA_PROGRAM_H

#include "common.h"
#include "bsvprogram.h"
#include <map>
#include <vector>
#include <set>

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
    
    SVProgram(const IR::ToplevelBlock* toplevel,
              ReferenceMap* refMap,
              TypeMap* typeMap) :
        toplevel(toplevel),
        program(toplevel ? toplevel->getProgram() : nullptr),
        refMap(refMap),
        typeMap(typeMap),
        parser(nullptr),
        ingress(nullptr),
        egress(nullptr),
        deparser(nullptr) {}
    
    ~SVProgram();  // Declare destructor, implement in .cpp
    
    bool build();
    void emit(SVCodeGen& codegen);
    
private:
    void emitTopModule(SVCodeGen& codegen);
    void emitTypeDefinitions(CodeBuilder* builder);
    void emitHeaders(CodeBuilder* builder);
    void emitMetadata(CodeBuilder* builder);
    void emitStandardMetadata(CodeBuilder* builder);
    void emitInterfaces(CodeBuilder* builder);
};

} // namespace SV

#endif