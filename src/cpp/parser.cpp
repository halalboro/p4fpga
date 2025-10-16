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

std::map<P4::cstring, std::vector<ExtractedParserState>> g_extractedParserStates;

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
    parserConfig(0) {  // Initialize to 0
}

bool SVParser::build() {
    LOG1("Building parser configuration extractor");
    
    if (!parserBlock || !parserBlock->container) {
        LOG1("Warning: No parser block, using default configuration");
        
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
    
    LOG2("Parser parameters extracted successfully");
    
    // Analyze header types from P4 program
    analyzeHeaderTypes();
    
    // Analyze parser state flow
    analyzeParserFlow();
    
    // Calculate bit offsets
    calculateHeaderOffsets();
    
    // NEW: Extract parser configuration
    extractParserConfiguration();
    
    LOG1("Parser analysis complete: " << headerSequence.size() << " headers");
    LOG1("Parser configuration: 0b" << getParserConfigString());
    
    return true;
}

void SVParser::analyzeHeaderTypes() {
    LOG2("Analyzing header types");
    
    if (!headers) return;
    
    auto headersType = typeMap->getType(headers);
    if (!headersType || !headersType->is<IR::Type_Struct>()) {
        LOG1("Warning: Headers parameter is not a struct");
        return;
    }
    
    auto structType = headersType->to<IR::Type_Struct>();
    
    for (auto field : structType->fields) {
        auto fieldType = typeMap->getType(field);
        if (!fieldType) continue;
        
        if (fieldType->is<IR::Type_Header>()) {
            auto headerType = fieldType->to<IR::Type_Header>();
            headerTypes[field->name] = headerType;
            
            LOG3("Found header type: " << field->name 
                 << " width: " << headerType->width_bits() << " bits");
        }
    }
}

void SVParser::analyzeParserFlow() {
    LOG2("Analyzing parser flow");
    
    // Try to get parser states from global storage first
    if (!parserBlock || !parserBlock->container) return;
    
    auto p4parser = parserBlock->container->to<IR::P4Parser>();
    if (!p4parser) return;
    
    // Check global extracted states
    if (g_extractedParserStates.count(p4parser->name) && 
        !g_extractedParserStates[p4parser->name].empty()) {
        
        LOG2("Using extracted parser states from global storage");
        
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
                    LOG3("Added header from state: " << info.name << " (" << info.width << " bits)");
                }
            }
            
            // Check for conditional transitions
            for (auto& trans : extractedState.transitions) {
                if (trans.first != cstring("always") && trans.first != cstring("default")) {
                    // This is a conditional transition
                    ConditionalParse cond;
                    cond.headerName = trans.second;
                    cond.conditionField = cstring("ethernet.etherType");
                    cond.conditionValue = trans.first;
                    conditionalHeaders.push_back(cond);
                    
                    LOG3("Conditional parse: " << cond.headerName 
                         << " when " << cond.conditionField << " == " << cond.conditionValue);
                }
            }
        }
    }
    
    // Fallback: If no states found, use default sequence
    if (headerSequence.empty()) {
        LOG1("Warning: No parser states found, using default Ethernet→IPv4");
        
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

void SVParser::calculateHeaderOffsets() {
    LOG2("Calculating header bit offsets");
    
    int currentOffset = 0;
    for (auto& header : headerSequence) {
        header.startBit = currentOffset;
        currentOffset += header.width;
        
        LOG3("Header " << header.name << " at offset " << header.startBit 
             << " (width " << header.width << ")");
    }
}

void SVParser::extractParserConfiguration() {
    LOG2("Extracting parser configuration");
    
    parserConfig = 0;
    
    // Map header names to configuration bits
    for (auto& header : headerSequence) {
        std::string headerName = header.name.string();
        
        // Convert to lowercase for comparison
        std::transform(headerName.begin(), headerName.end(), 
                      headerName.begin(), ::tolower);
        
        if (headerName == "ethernet") {
            parserConfig |= (1 << PARSE_ETHERNET);
            LOG3("Config: PARSE_ETHERNET enabled");
        } 
        else if (headerName == "vlan") {
            parserConfig |= (1 << PARSE_VLAN);
            LOG3("Config: PARSE_VLAN enabled");
        }
        else if (headerName == "ipv4") {
            parserConfig |= (1 << PARSE_IPV4);
            LOG3("Config: PARSE_IPV4 enabled");
        }
        else if (headerName == "ipv6") {
            parserConfig |= (1 << PARSE_IPV6);
            LOG3("Config: PARSE_IPV6 enabled");
        }
        else if (headerName == "tcp") {
            parserConfig |= (1 << PARSE_TCP);
            LOG3("Config: PARSE_TCP enabled");
        }
        else if (headerName == "udp") {
            parserConfig |= (1 << PARSE_UDP);
            LOG3("Config: PARSE_UDP enabled");
        }
        else if (headerName == "vxlan") {
            parserConfig |= (1 << PARSE_VXLAN);
            LOG3("Config: PARSE_VXLAN enabled");
        }
        else {
            LOG2("Warning: Unknown header type '" << headerName 
                 << "', not included in config");
        }
    }
    
    LOG1("Final parser config: 0b" << std::bitset<8>(parserConfig));
}

std::string SVParser::getParserConfigString() const {
    std::stringstream ss;
    
    // Generate binary string (8 bits)
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

void SVParser::emit(SVCodeGen& codegen) {
    LOG1("Parser emission skipped - using parser template");
    LOG1("Parser configuration: 8'b" << getParserConfigString());
    
    // NOTE: We no longer generate parser.sv module
    // Instead, the configuration is used in the top-level module
    // to instantiate the parser.sv template
    
    // The  parser template should already be copied to the output
    // directory by the main compilation function
}

}  // namespace SV