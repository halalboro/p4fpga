/*
 * P4-FPGA Compiler - Parser Component
 *
 * Handles P4 parser analysis and SystemVerilog parser generation.
 * Extracts header definitions, parse states, transitions, and custom headers.
 * Generates parser configuration for hardware implementation.
 */

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
    struct LookaheadInfo {
        cstring state;
        const IR::Type* type;
        std::vector<cstring> fields;
        size_t offset;  // Byte offset in packet
    };

    // ==========================================
    // Custom Header Field Structure
    // ==========================================
    struct CustomHeaderField {
        cstring name;
        int width;      // Width in bits
        int offset;     // Bit offset within header
        bool isPartOfStack = false;
        
        CustomHeaderField() : width(0), offset(0) {}
        CustomHeaderField(cstring n, int w, int o = 0) 
            : name(n), width(w), offset(o) {}
    };

    // ==========================================
    // Custom Header Information
    // Stores metadata for user-defined P4 headers
    // ==========================================
    struct CustomHeaderInfo {
        cstring name;                                   // Header name (e.g., "srcRoutes")
        std::map<cstring, CustomHeaderField> fields;    // Field name → field info
        int totalWidth;                                 // Total header width in bits (per element for stacks)
        int parserBit;                                  // Parser config bit position

        uint16_t ethertype = 0x1234;

        // Stack-specific properties
        bool isStack = false;                          // Is this a header stack?
        int maxStackSize = 1;                          // Max elements in stack
        cstring elementTypeName;                       // Element type (e.g., "srcRoute_t")
        
        // BOS (Bottom-of-Stack) field tracking
        bool hasBosField = false;                      // Does element have BOS indicator?
        cstring bosFieldName;                          // Which field is the BOS indicator
        int bosFieldOffset = 0;                        // Bit offset of BOS field
        
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
    // Parser State Info (for state machine generation)
    // ==========================================
    struct ParserStateInfo {
        cstring name;
        bool isCustomState = false;
        bool isStackParsingState = false;
        cstring stackName;  // If stack parsing state
        
        std::vector<cstring> extractedHeaders;
        std::map<cstring, cstring> transitions;  // condition → next_state
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
        PARSE_CUSTOM   = 7  // Custom headers start at bit 7
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

    void detectHeaderStacksFromParser();
    
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

    std::vector<LookaheadInfo> lookaheads;
    
    void handleLookahead(const IR::MethodCallExpression* lookahead,
                        const IR::ParserState* state);
    std::vector<cstring> extractLookaheadFields(
        const IR::MethodCallExpression* lookahead);

    // Stack-related methods
    bool hasHeaderStacks() const;
    int getMaxStackSize() const;  // Largest stack size in program

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

class SVMetadata {
public:
    struct MetadataField {
        cstring name;
        unsigned width;
        unsigned offset;  // Bit offset in metadata bus
    };
    
    std::map<cstring, MetadataField> fields;
    unsigned totalWidth = 0;
    
    bool build(const IR::Type_Struct* metaStruct) {
        unsigned offset = 0;
        for (auto field : metaStruct->fields) {
            auto type = field->type->to<IR::Type_Bits>();
            if (!type) continue;
            
            MetadataField mf;
            mf.name = field->name;
            mf.width = type->width_bits();
            mf.offset = offset;
            
            fields[field->name] = mf;
            offset += mf.width;
        }
        totalWidth = offset;
        return true;
    }
};

} // namespace SV

#endif  // EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_PARSER_H_