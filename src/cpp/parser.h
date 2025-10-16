// parser.h
#ifndef EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_PARSER_H_
#define EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_PARSER_H_

#include "common.h"
#include <vector>
#include <map>
#include <cstdint>

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
    
    // Header information for extraction
    struct HeaderInfo {
        cstring name;
        int startBit;
        int width;
        std::vector<std::pair<cstring, int>> fields; // field name, width
    };
    
    std::vector<HeaderInfo> headerSequence;
    std::map<cstring, const IR::Type_Header*> headerTypes;
    
    // Conditional parsing info
    struct ConditionalParse {
        cstring headerName;
        cstring conditionField;
        cstring conditionValue;
    };
    
    std::vector<ConditionalParse> conditionalHeaders;
    
    // NEW: Parser configuration (8-bit value)
    uint8_t parserConfig;
    
    // Private helper methods
    void analyzeHeaderTypes();
    void analyzeParserFlow();
    void calculateHeaderOffsets();
    void extractParserConfiguration();  // NEW
    
    // Configuration bit positions
    enum ParserConfigBits {
        PARSE_ETHERNET = 0,
        PARSE_VLAN     = 1,
        PARSE_IPV4     = 2,
        PARSE_IPV6     = 3,
        PARSE_TCP      = 4,
        PARSE_UDP      = 5,
        PARSE_VXLAN    = 6
    };
    
public:
    SVParser(SVProgram* program,
             const IR::ParserBlock* block,
             const TypeMap* typeMap,
             const ReferenceMap* refMap);
    
    ~SVParser() {}
    
    bool build();
    void emit(SVCodeGen& codegen);
    
    // NEW: Get parser configuration
    uint8_t getParserConfig() const { return parserConfig; }
    
    // NEW: Get configuration as binary string for SystemVerilog
    std::string getParserConfigString() const;
    
    const std::vector<HeaderInfo>& getHeaderSequence() const { 
        return headerSequence; 
    }
    
    // NEW: Check if specific header is parsed
    bool parsesHeader(const cstring& headerName) const;
};

} // namespace SV

#endif