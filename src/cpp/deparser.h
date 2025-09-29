#ifndef _BACKENDS_SV_DEPARSER_H_
#define _BACKENDS_SV_DEPARSER_H_

#include "common.h"
#include <vector>
#include <map>

namespace SV {

class SVProgram;
class SVCodeGen;

class SVDeparseState {
public:
    cstring headerName;
    const IR::Type_Header* headerType;
    int width;
    bool isConditional;
    
    SVDeparseState(cstring name, const IR::Type_Header* type) :
        headerName(name), headerType(type), width(0), isConditional(false) {}
};

class SVDeparser : public FPGAObject {
public:
    const SVProgram* program;
    const IR::ControlBlock* controlBlock;
    
    std::vector<SVDeparseState*> deparseStates;
    std::map<cstring, int> headerOrder;
    
    explicit SVDeparser(const SVProgram* program, const IR::ControlBlock* block) :
        program(program), controlBlock(block) {}
    
    ~SVDeparser() {
        // Clean up allocated memory
        for (auto state : deparseStates) {
            delete state;
        }
    }
    
    void emit(SVCodeGen& codegen);
    bool build();
    
private:
    void extractEmitStatements();
    void calculateHeaderOrder();
    
    void emitModule(CodeBuilder* builder);
    void emitPacketAssembly(CodeBuilder* builder);
    void emitStreamOutput(CodeBuilder* builder);
};

}  // namespace SV

#endif