// deparser.h
#ifndef _BACKENDS_SV_DEPARSER_H_
#define _BACKENDS_SV_DEPARSER_H_

#include "common.h"
#include <cstdint>
#include <string>
#include <vector>

namespace SV {

class SVProgram;
class SVCodeGen;

class SVDeparser : public FPGAObject {
public:
    const SVProgram* program;
    const IR::ControlBlock* controlBlock;
    
    explicit SVDeparser(const SVProgram* program, const IR::ControlBlock* block) :
        program(program), 
        controlBlock(block),
        deparserConfig(0) {}
    
    ~SVDeparser() {}
    
    void emit(SVCodeGen& codegen);
    bool build();
    
    // NEW: Get deparser configuration
    uint16_t getDeparserConfig() const { return deparserConfig; }
    
    // NEW: Get configuration as hex string for SystemVerilog
    std::string getDeparserConfigString() const;
    
    // NEW: Check if specific header is emitted
    bool emitsHeader(const cstring& headerName) const;

private:
    // NEW: Deparser configuration (16-bit value)
    uint16_t deparserConfig;
    
    // NEW: Track which headers are emitted
    std::vector<cstring> emittedHeaders;
    
    // Configuration bit positions
    enum DeparserConfigBits {
        EMIT_ETHERNET          = 0,
        EMIT_VLAN              = 1,
        EMIT_IPV4              = 2,
        EMIT_IPV6              = 3,
        EMIT_TCP               = 4,
        EMIT_UDP               = 5,
        EMIT_VXLAN             = 6,
        UPDATE_IPV4_CHECKSUM   = 7,
        UPDATE_TCP_CHECKSUM    = 8,
        UPDATE_UDP_CHECKSUM    = 9
    };
    
    // Private methods
    void emitModuleHeader(CodeBuilder* builder);
    void emitPortDeclarations(CodeBuilder* builder);
    void emitDropFilter(CodeBuilder* builder);
    
    // NEW: Extract deparser configuration from P4 IR
    void extractDeparserConfiguration();
    void analyzeEmitStatements();
};

} // namespace SV

#endif