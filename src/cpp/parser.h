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
public:
    
    // ==========================================
    // Custom Header Field Structure
    // ==========================================
    struct CustomHeaderField {
        cstring name;
        int width;      // Width in bits
        int offset;     // Bit offset within header
        
        CustomHeaderField() : width(0), offset(0) {}
        CustomHeaderField(cstring n, int w, int o = 0) 
            : name(n), width(w), offset(o) {}
    };

    // ==========================================
    // Custom Header Information
    // Stores metadata for user-defined P4 headers
    // ==========================================
    struct CustomHeaderInfo {
        cstring name;                                   // Header name (e.g., "myTunnel")
        std::map<cstring, CustomHeaderField> fields;    // Field name → field info
        int totalWidth;                                 // Total header width in bits
        int parserBit;                                  // Parser config bit position
        
        CustomHeaderInfo() : totalWidth(0), parserBit(-1) {}
    };
    
    // ==========================================
    // Header Information for Extraction
    // ==========================================
    struct HeaderInfo {
        cstring name;
        int startBit;
        int width;
        std::vector<std::pair<cstring, int>> fields;   // field name, width
    };
    
    // ==========================================
    // Conditional Parsing Information
    // ==========================================
    struct ConditionalParse {
        cstring headerName;
        cstring conditionField;
        cstring conditionValue;
    };
    
    // ==========================================
    // Parser Configuration Bit Positions
    // ==========================================
    enum ParserConfigBits {
        PARSE_ETHERNET = 0,
        PARSE_VLAN     = 1,
        PARSE_IPV4     = 2,
        PARSE_IPV6     = 3,
        PARSE_TCP      = 4,
        PARSE_UDP      = 5,
        PARSE_VXLAN    = 6,
        PARSE_CUSTOM   = 7
    };
    
    // ==========================================
    // Constructor & Destructor
    // ==========================================
    SVParser(SVProgram* program,
             const IR::ParserBlock* block,
             const TypeMap* typeMap,
             const ReferenceMap* refMap);
    ~SVParser() {}
    
    // ==========================================
    // Public Interface
    // ==========================================
    
    /** Build the parser representation from P4 AST */
    bool build();

    /** Get parser configuration bitmask */
    uint8_t getParserConfig() const { return parserConfig; }
    
    /** Get configuration as binary string for SystemVerilog */
    std::string getParserConfigString() const;
    
    void printSummary() const;
    
    /** Get header parsing sequence */
    const std::vector<HeaderInfo>& getHeaderSequence() const { 
        return headerSequence; 
    }
    
    /** Check if specific header is parsed */
    bool parsesHeader(const cstring& headerName) const;
    
    /** Get custom headers map */
    const std::map<cstring, CustomHeaderInfo>& getCustomHeaders() const {
        return customHeaders;
    }

private:
    // ==========================================
    // Private Members
    // ==========================================
    SVProgram* program;
    const IR::ParserBlock* parserBlock;
    const TypeMap* typeMap;
    const ReferenceMap* refMap;
    
    // Parser parameters
    const IR::Parameter* packet;
    const IR::Parameter* headers;
    const IR::Parameter* userMetadata;
    const IR::Parameter* stdMetadata;
    
    // Data structures
    std::vector<HeaderInfo> headerSequence;
    std::map<cstring, const IR::Type_Header*> headerTypes;
    std::map<cstring, CustomHeaderInfo> customHeaders; 
    std::vector<ConditionalParse> conditionalHeaders;
    
    // Configuration
    uint8_t parserConfig;
    int nextCustomBit;
    
    // ==========================================
    // Private Helper Methods
    // ==========================================
    void analyzeHeaderTypes();
    void analyzeParserFlow();
    void calculateHeaderOffsets();
    void extractParserConfiguration();  
    void extractCustomHeaders();
    bool isStandardHeader(const cstring& name) const;
};

} // namespace SV

#endif  // EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_PARSER_H_