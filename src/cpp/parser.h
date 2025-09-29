#ifndef EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_PARSER_H_
#define EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_PARSER_H_

#include "common.h"
#include <vector>
#include <map>
#include <algorithm>

namespace SV {

class SVProgram;
class SVCodeGen;

class SVParser {
private:
    SVProgram* program;
    const IR::ParserBlock* parserBlock;
    const TypeMap* typeMap;
    const ReferenceMap* refMap;
    
public:
    const IR::Parameter* packet;
    const IR::Parameter* headers;
    const IR::Parameter* userMetadata;
    const IR::Parameter* stdMetadata;
    
    std::map<cstring, SVParseState*> stateMap;  // Changed to SVParseState*
    std::vector<SVParseState*> stateList;        // Changed to SVParseState*
    std::map<cstring, int> headerOffsets;
    std::map<cstring, int> headerWidths;
    
    const IR::ParserState* startState;
    const IR::ParserState* acceptState;
    int totalHeaderBits;
    
    void extractStates();
    void analyzeTransitions();
    void calculateHeaderOffsets();
    void emitStateEnum(CodeBuilder* builder);
    void emitStateMachine(CodeBuilder* builder);
    void emitHeaderExtraction(CodeBuilder* builder);
    void emitTransitionLogic(CodeBuilder* builder);
    void emitInterface(CodeBuilder* builder);
    
public:
    SVParser(SVProgram* program,
             const IR::ParserBlock* block,
             const TypeMap* typeMap,
             const ReferenceMap* refMap);
    
    ~SVParser() {
        // Clean up allocated states
        for (auto& p : stateMap) {
            delete p.second;
        }
    }
    
    bool build();
    void emit(SVCodeGen& codegen);
};

}  // namespace SV

#endif