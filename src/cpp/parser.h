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

    // Parser parameters
    const IR::Parameter* packet;
    const IR::Parameter* headers;
    const IR::Parameter* userMetadata;
    const IR::Parameter* stdMetadata;
    
    // Parser states
    std::map<cstring, SVParseState*> stateMap;
    std::vector<SVParseState*> stateList;
    
    // Header information
    std::map<cstring, int> headerOffsets;
    std::map<cstring, int> headerWidths;
    
    const IR::ParserState* startState;
    const IR::ParserState* acceptState;
    int totalHeaderBits;
    
    // Private helper methods for emission
    void analyzeTransitions();
    void calculateHeaderOffsets();
    void emitStateEnum(CodeBuilder* builder);
    void emitStateMachine(CodeBuilder* builder);
    void emitHeaderExtraction(CodeBuilder* builder);
    void emitTransitionLogic(CodeBuilder* builder);
    void emitInterface(CodeBuilder* builder);
    
    // REMOVED: extractStates() - no longer used
    // REMOVED: emitParserStates() - replaced by emitStateEnum()
    // REMOVED: emitStateTransitions() - replaced by emitTransitionLogic()

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

} // namespace SV

#endif