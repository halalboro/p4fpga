// parser.cpp

#include "common.h"
#include "parser.h"
#include "program.h"
#include "lib/log.h"
#include "lib/error.h"
#include <sstream>
#include <algorithm>
#include <iomanip>

namespace SV {

// ==========================================
// Debug Control
// ==========================================
#define PARSER_INFO(msg)    std::cerr << "[Parser] " << msg << std::endl
#define PARSER_SUCCESS(msg) std::cerr << "[✓] " << msg << std::endl
#define PARSER_ERROR(msg)   std::cerr << "[ERROR] " << msg << std::endl

#define PARSER_DEBUG(msg) if (SV::g_verbose) std::cerr << "  " << msg << std::endl
#define PARSER_TRACE(msg) if (SV::g_verbose) std::cerr << "    " << msg << std::endl

// Global storage for extracted parser states
std::map<P4::cstring, std::vector<ExtractedParserState>> g_extractedParserStates;

// ==========================================
// Constructor
// ==========================================

SVParser::SVParser(SVProgram* program,
                   const IR::ParserBlock* block,
                   const TypeMap* typeMap,
                   const ReferenceMap* refMap) :
    program(program), 
    parserBlock(block), 
    typeMap(typeMap), 
    refMap(refMap),
    packet(nullptr),
    headers(nullptr),
    userMetadata(nullptr),
    stdMetadata(nullptr),
    parserConfig(0),
    nextCustomBit(PARSE_CUSTOM) {  // Initialize nextCustomBit
}

// ==========================================
// Build Parser
// ==========================================

bool SVParser::build() {
    if (!parserBlock || !parserBlock->container) {
        PARSER_DEBUG("No parser block, using default configuration");
        
        // Default: Ethernet + IPv4
        parserConfig = (1 << PARSE_ETHERNET) | (1 << PARSE_IPV4);
        
        // Create minimal header info for compatibility
        HeaderInfo ethInfo;
        ethInfo.name = cstring("ethernet");
        ethInfo.startBit = 0;
        ethInfo.width = 112;
        ethInfo.fields = {
            {cstring("dstAddr"), 48},
            {cstring("srcAddr"), 48},
            {cstring("etherType"), 16}
        };
        headerSequence.push_back(ethInfo);
        
        HeaderInfo ipv4Info;
        ipv4Info.name = cstring("ipv4");
        ipv4Info.startBit = 112;
        ipv4Info.width = 160;
        ipv4Info.fields = {
            {cstring("version"), 4},
            {cstring("ihl"), 4},
            {cstring("diffserv"), 8},
            {cstring("totalLen"), 16},
            {cstring("identification"), 16},
            {cstring("flags"), 3},
            {cstring("fragOffset"), 13},
            {cstring("ttl"), 8},
            {cstring("protocol"), 8},
            {cstring("hdrChecksum"), 16},
            {cstring("srcAddr"), 32},
            {cstring("dstAddr"), 32}
        };
        headerSequence.push_back(ipv4Info);
        
        return true;
    }
    
    // Get parser parameters
    auto p4parser = parserBlock->container->to<IR::P4Parser>();
    if (!p4parser) {
        P4::error("Container is not a P4Parser");
        return false;
    }
    
    auto pl = p4parser->type->applyParams;
    if (!pl || pl->size() != 4) {
        P4::error("Parser must have exactly 4 parameters");
        return false;
    }
    
    packet = pl->getParameter(0);
    headers = pl->getParameter(1);
    userMetadata = pl->getParameter(2);
    stdMetadata = pl->getParameter(3);
    
    PARSER_DEBUG("Parser parameters extracted");
    
    // Analyze header types from P4 program
    analyzeHeaderTypes();
    
    // Extract custom headers BEFORE analyzing parser flow
    nextCustomBit = PARSE_CUSTOM;
    extractCustomHeaders();
    
    // Analyze parser state flow
    analyzeParserFlow();
    
    // Calculate bit offsets
    calculateHeaderOffsets();
    
    // Extract parser configuration (now includes custom headers)
    extractParserConfiguration();
    
    // Print concise summary
    printSummary();
    
    return true;
}

// ==========================================
// Print Summary (Concise + Verbose)
// ==========================================

void SVParser::printSummary() const {
    // Build header list
    std::stringstream headerList;
    bool first = true;
    for (const auto& header : headerSequence) {
        if (!first) headerList << ", ";
        headerList << header.name;
        first = false;
    }
    
    // Concise output (always shown)
    if (customHeaders.empty()) {
        PARSER_SUCCESS("Parser: " << headerSequence.size() 
                      << " headers (" << headerList.str() << ")");
    } else {
        PARSER_SUCCESS("Parser: " << headerSequence.size() 
                      << " headers (" << headerList.str() << "), "
                      << customHeaders.size() << " custom");
    }
    
#if DEBUG_PARSER_VERBOSE
    // Verbose output (only if enabled)
    std::cerr << "[Parser] Header details:" << std::endl;
    for (const auto& header : headerSequence) {
        bool isCustom = customHeaders.count(header.name);
        std::cerr << "  ├─ " << header.name 
                  << " (" << header.width << " bits, " 
                  << header.fields.size() << " fields)";
        if (isCustom) {
            std::cerr << " [custom]";
        }
        std::cerr << std::endl;
    }
    
    std::cerr << "[Parser] Configuration: 0b" << getParserConfigString() << std::endl;
    
    if (!customHeaders.empty()) {
        std::cerr << "[Parser] Custom headers:" << std::endl;
        for (const auto& ch : customHeaders) {
            std::cerr << "  └─ " << ch.first 
                      << " (bit " << ch.second.parserBit 
                      << ", " << ch.second.totalWidth << " bits)" << std::endl;
        }
    }
#endif
}

// ==========================================
// Analyze Header Types
// ==========================================

void SVParser::analyzeHeaderTypes() {
    PARSER_DEBUG("Analyzing header types");
    
    if (!headers) return;
    
    auto headersType = typeMap->getType(headers);
    if (!headersType || !headersType->is<IR::Type_Struct>()) {
        PARSER_DEBUG("Warning: Headers parameter is not a struct");
        return;
    }
    
    auto structType = headersType->to<IR::Type_Struct>();
    
    for (auto field : structType->fields) {
        auto fieldType = typeMap->getType(field);
        if (!fieldType) continue;
        
        if (fieldType->is<IR::Type_Header>()) {
            auto headerType = fieldType->to<IR::Type_Header>();
            headerTypes[field->name] = headerType;
            
            PARSER_TRACE("Found header: " << field->name 
                        << " (" << headerType->width_bits() << " bits)");
        }
    }
}

// ==========================================
// Analyze Parser Flow
// ==========================================

void SVParser::analyzeParserFlow() {
    PARSER_DEBUG("Analyzing parser state flow");
    
    if (!parserBlock || !parserBlock->container) return;
    
    auto p4parser = parserBlock->container->to<IR::P4Parser>();
    if (!p4parser) return;
    
    // Check global extracted states
    if (g_extractedParserStates.count(p4parser->name) && 
        !g_extractedParserStates[p4parser->name].empty()) {
        
        PARSER_TRACE("Using extracted parser states");
        
        for (auto& extractedState : g_extractedParserStates[p4parser->name]) {
            if (extractedState.isStart || extractedState.isAccept) continue;
            
            // Process each state's extracted headers
            for (auto& headerName : extractedState.extractedHeaders) {
                // Parse "hdr.ethernet" → "ethernet"
                std::string fullName = headerName.string();
                size_t dotPos = fullName.find('.');
                std::string actualName = (dotPos != std::string::npos) 
                    ? fullName.substr(dotPos + 1) 
                    : fullName;
                
                cstring headerCName(actualName);
                
                if (headerTypes.count(headerCName)) {
                    HeaderInfo info;
                    info.name = headerCName;
                    info.width = headerTypes[headerCName]->width_bits();
                    
                    // Extract field information
                    auto headerType = headerTypes[headerCName];
                    for (auto hdrField : headerType->fields) {
                        auto fType = typeMap->getType(hdrField);
                        if (fType && fType->is<IR::Type_Bits>()) {
                            int fWidth = fType->to<IR::Type_Bits>()->size;
                            info.fields.push_back({hdrField->name, fWidth});
                        }
                    }
                    
                    headerSequence.push_back(info);
                    PARSER_TRACE("Added header: " << info.name);
                }
            }
            
            // Check for conditional transitions
            for (auto& trans : extractedState.transitions) {
                if (trans.first != cstring("always") && trans.first != cstring("default")) {
                    ConditionalParse cond;
                    cond.headerName = trans.second;
                    cond.conditionField = cstring("ethernet.etherType");
                    cond.conditionValue = trans.first;
                    conditionalHeaders.push_back(cond);
                    
                    PARSER_TRACE("Conditional: " << cond.headerName 
                                << " when " << cond.conditionValue);
                }
            }
        }
    }
    
    // Fallback: If no states found, use default sequence
    if (headerSequence.empty()) {
        PARSER_DEBUG("No parser states found, using defaults");
        
        if (headerTypes.count(cstring("ethernet"))) {
            HeaderInfo ethInfo;
            ethInfo.name = cstring("ethernet");
            ethInfo.width = headerTypes[cstring("ethernet")]->width_bits();
            
            auto ethType = headerTypes[cstring("ethernet")];
            for (auto field : ethType->fields) {
                auto fType = typeMap->getType(field);
                if (fType && fType->is<IR::Type_Bits>()) {
                    ethInfo.fields.push_back({field->name, fType->to<IR::Type_Bits>()->size});
                }
            }
            
            headerSequence.push_back(ethInfo);
        }
        
        if (headerTypes.count(cstring("ipv4"))) {
            HeaderInfo ipv4Info;
            ipv4Info.name = cstring("ipv4");
            ipv4Info.width = headerTypes[cstring("ipv4")]->width_bits();
            
            auto ipv4Type = headerTypes[cstring("ipv4")];
            for (auto field : ipv4Type->fields) {
                auto fType = typeMap->getType(field);
                if (fType && fType->is<IR::Type_Bits>()) {
                    ipv4Info.fields.push_back({field->name, fType->to<IR::Type_Bits>()->size});
                }
            }
            
            headerSequence.push_back(ipv4Info);
            
            ConditionalParse ipv4Cond;
            ipv4Cond.headerName = cstring("ipv4");
            ipv4Cond.conditionField = cstring("ethernet.etherType");
            ipv4Cond.conditionValue = cstring("16'h0800");
            conditionalHeaders.push_back(ipv4Cond);
        }
    }
}

// ==========================================
// Calculate Header Offsets
// ==========================================

void SVParser::calculateHeaderOffsets() {
    PARSER_TRACE("Calculating header offsets");
    
    int currentOffset = 0;
    for (auto& header : headerSequence) {
        header.startBit = currentOffset;
        currentOffset += header.width;
    }
}

// ==========================================
// Extract Parser Configuration
// ==========================================

void SVParser::extractParserConfiguration() {
    PARSER_DEBUG("Extracting parser configuration");
    
    parserConfig = 0;
    
    // Map header names to configuration bits
    for (auto& header : headerSequence) {
        std::string headerName = header.name.string();
        std::transform(headerName.begin(), headerName.end(), 
                      headerName.begin(), ::tolower);
        
        if (headerName == "ethernet") {
            parserConfig |= (1 << PARSE_ETHERNET);
        } else if (headerName == "vlan") {
            parserConfig |= (1 << PARSE_VLAN);
        } else if (headerName == "ipv4") {
            parserConfig |= (1 << PARSE_IPV4);
        } else if (headerName == "ipv6") {
            parserConfig |= (1 << PARSE_IPV6);
        } else if (headerName == "tcp") {
            parserConfig |= (1 << PARSE_TCP);
        } else if (headerName == "udp") {
            parserConfig |= (1 << PARSE_UDP);
        } else if (headerName == "vxlan") {
            parserConfig |= (1 << PARSE_VXLAN);
        } else {
            // Check if it's a custom header
            if (customHeaders.count(header.name)) {
                int bit = customHeaders.at(header.name).parserBit;
                parserConfig |= (1 << bit);
                PARSER_TRACE("Custom header " << header.name << " at bit " << bit);
            }
        }
    }
}

// ==========================================
// Extract Custom Headers
// ==========================================

void SVParser::extractCustomHeaders() {
    PARSER_DEBUG("Scanning for custom headers");
    
    if (!headers) return;
    
    auto headersType = typeMap->getType(headers);
    if (!headersType || !headersType->is<IR::Type_Struct>()) {
        return;
    }
    
    auto structType = headersType->to<IR::Type_Struct>();
    nextCustomBit = PARSE_CUSTOM;
    
    for (auto field : structType->fields) {
        auto fieldType = typeMap->getType(field);
        if (!fieldType || !fieldType->is<IR::Type_Header>()) continue;
        
        auto headerType = fieldType->to<IR::Type_Header>();
        cstring headerName = field->name;
        
        // Skip standard headers
        if (isStandardHeader(headerName)) {
            continue;
        }
        
        // Found a custom header!
        PARSER_TRACE("Found custom header: " << headerName);
        
        CustomHeaderInfo customInfo;
        customInfo.name = headerName;
        customInfo.totalWidth = 0;
        customInfo.parserBit = nextCustomBit++;
        
        // Extract fields into the NEW map-based structure
        int currentOffset = 0;
        for (auto hdrField : headerType->fields) {
            auto fType = typeMap->getType(hdrField);
            if (fType && fType->is<IR::Type_Bits>()) {
                int fWidth = fType->to<IR::Type_Bits>()->size;
                
                // NEW: Create CustomHeaderField and add to map
                CustomHeaderField field(hdrField->name, fWidth, currentOffset);
                customInfo.fields[hdrField->name] = field;
                
                customInfo.totalWidth += fWidth;
                currentOffset += fWidth;
            }
        }
        
        customHeaders[headerName] = customInfo;
    }
}

// ==========================================
// Utility Methods
// ==========================================

std::string SVParser::getParserConfigString() const {
    std::stringstream ss;
    for (int i = 7; i >= 0; i--) {
        ss << ((parserConfig >> i) & 1);
    }
    return ss.str();
}

bool SVParser::parsesHeader(const cstring& headerName) const {
    for (auto& header : headerSequence) {
        if (header.name == headerName) {
            return true;
        }
    }
    return false;
}

bool SVParser::isStandardHeader(const cstring& name) const {
    std::string headerName = name.string();
    std::transform(headerName.begin(), headerName.end(), 
                  headerName.begin(), ::tolower);
    
    return (headerName == "ethernet" ||
            headerName == "vlan" ||
            headerName == "ipv4" ||
            headerName == "ipv6" ||
            headerName == "tcp" ||
            headerName == "udp" ||
            headerName == "vxlan");
}

}  // namespace SV