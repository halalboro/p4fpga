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
    nextCustomBit(PARSE_CUSTOM) {
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

    // ==========================================
    // Extract User Metadata
    // ==========================================
    if (userMetadata) {
        auto metaType = typeMap->getType(userMetadata);
        if (metaType && metaType->is<IR::Type_Struct>()) {
            auto metaStruct = metaType->to<IR::Type_Struct>();
            
            SVMetadata* metadata = new SVMetadata();
            if (metadata->build(metaStruct)) {
                program->setMetadata(metadata);
                PARSER_DEBUG("Metadata: " << metadata->totalWidth << " bits");
            }
        }
    }
    
    // Analyze header types from P4 program
    analyzeHeaderTypes();
    
    // Extract custom headers BEFORE analyzing parser flow
    // This includes both single headers AND stacks from P4 struct
    nextCustomBit = PARSE_CUSTOM;
    extractCustomHeaders();
    
    // Detect .next accessor patterns in parser states
    detectHeaderStacksFromParser();
    
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
        int numStacks = 0;
        for (const auto& ch : customHeaders) {
            if (ch.second.isStack) numStacks++;
        }
        
        if (numStacks > 0) {
            PARSER_SUCCESS("Parser: " << headerSequence.size() 
                          << " headers (" << headerList.str() << "), "
                          << customHeaders.size() << " custom (" 
                          << numStacks << " stacks)");
        } else {
            PARSER_SUCCESS("Parser: " << headerSequence.size() 
                          << " headers (" << headerList.str() << "), "
                          << customHeaders.size() << " custom");
        }
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
                      << ", " << ch.second.totalWidth << " bits";
            if (ch.second.isStack) {
                std::cerr << ", stack[" << ch.second.maxStackSize << "]";
            }
            std::cerr << ")" << std::endl;
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

void SVParser::handleLookahead(const IR::MethodCallExpression* lookahead,
                                const IR::ParserState* state) {
    // Get the type being peeked at
    auto typeArgs = lookahead->typeArguments;
    if (typeArgs->size() != 1) {
        error("lookahead must have exactly one type argument");
        return;
    }
    
    auto peekType = typeArgs->at(0);
    PARSER_DEBUG("Lookahead type: " << peekType);
    
    // Store lookahead information for this state
    LookaheadInfo info;
    info.state = state->name;
    info.type = peekType;
    info.fields = extractLookaheadFields(lookahead);
    
    lookaheads.push_back(info);
}

std::vector<cstring> SVParser::extractLookaheadFields(
    const IR::MethodCallExpression* lookahead) {
    std::vector<cstring> fields;
    
    // The lookahead expression is typically followed by field access
    // e.g., packet.lookahead<p4calc_t>().p
    // We need to track which fields are being accessed
    
    return fields;
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

            // ==========================================
            // Find the actual P4 parser state
            // ==========================================
            const IR::ParserState* p4state = nullptr;
            
            for (auto state : p4parser->states) {
                if (state && state->name == extractedState.name) {
                    p4state = state;
                    break;
                }
            }
            
            // ==========================================
            // Only check lookahead if we found the state
            // ==========================================
            if (p4state && p4state->selectExpression) {
                if (auto selectExpr = p4state->selectExpression->to<IR::SelectExpression>()) {
                    if (auto listExpr = selectExpr->select->to<IR::ListExpression>()) {
                        for (auto component : listExpr->components) {
                            if (auto methodCall = component->to<IR::MethodCallExpression>()) {
                                if (auto member = methodCall->method->to<IR::Member>()) {
                                    if (member->member == "lookahead") {
                                        PARSER_DEBUG("Found lookahead in state: " << p4state->name);
                                        handleLookahead(methodCall, p4state);
                                    }
                                }
                            }
                        }
                    }
                }
            }

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

        if (headerTypes.count(cstring("tcp"))) {
            HeaderInfo tcpInfo;
            tcpInfo.name = cstring("tcp");
            tcpInfo.width = headerTypes[cstring("tcp")]->width_bits();
            
            auto tcpType = headerTypes[cstring("tcp")];
            for (auto field : tcpType->fields) {
                auto fType = typeMap->getType(field);
                if (fType && fType->is<IR::Type_Bits>()) {
                    tcpInfo.fields.push_back({field->name, fType->to<IR::Type_Bits>()->size});
                }
            }
            
            headerSequence.push_back(tcpInfo);
            
            // TCP is parsed when IPv4 protocol = 6
            ConditionalParse tcpCond;
            tcpCond.headerName = cstring("tcp");
            tcpCond.conditionField = cstring("ipv4.protocol");
            tcpCond.conditionValue = cstring("6");
            conditionalHeaders.push_back(tcpCond);
            
            PARSER_TRACE("Added TCP header (conditional on protocol=6)");
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
// Extract Custom Headers (PHASE 1.7 - COMPLETE)
// Detects both single headers AND header stacks from P4 struct
// ==========================================

void SVParser::extractCustomHeaders() {
    if (!parserBlock || !parserBlock->container) return;
    
    auto p4parser = parserBlock->container->to<IR::P4Parser>();
    if (!p4parser) return;
    
    if (g_verbose) {
        std::cerr << "  Scanning for custom headers" << std::endl;
    }
    
    // Get parser parameters from type
    auto parserType = p4parser->type;
    if (!parserType || !parserType->applyParams || 
        parserType->applyParams->size() < 2) {
        return;
    }
    
    // Second parameter is "out headers hdr"
    auto headersParam = parserType->applyParams->getParameter(1);
    if (!headersParam) return;
    
    // Get the type of the headers parameter
    auto headersTypeFromParam = typeMap->getType(headersParam);
    if (!headersTypeFromParam) return;
    
    auto headersType = headersTypeFromParam->to<IR::Type_Struct>();
    
    if (!headersType) {
        if (g_verbose) {
            std::cerr << "    No headers struct found" << std::endl;
        }
        return;
    }
    
    if (g_verbose) {
        std::cerr << "    Found headers struct with " 
                  << headersType->fields.size() << " fields" << std::endl;
    }
    
    // ==========================================
    // Iterate through header struct fields
    // ==========================================
    for (auto field : headersType->fields) {
        auto fieldType = field->type;
        
        // DEBUG OUTPUT: Show what types we're seeing
        if (g_verbose) {
            std::cerr << "    Field: " << field->name 
                      << " Type: " << fieldType->node_type_name() << std::endl;
        }
        
        // ==========================================
        // CASE 1: Single Header
        // ==========================================
        if (fieldType->is<IR::Type_Header>()) {
            auto headerType = fieldType->to<IR::Type_Header>();
            if (!headerType) continue;
            
            // Check if this is a standard header we already support
            cstring headerName = headerType->name;
            
            if (headerName == "ethernet_t" || 
                headerName == "ipv4_t" || 
                headerName == "ipv6_t" ||
                headerName == "tcp_t" || 
                headerName == "udp_t" ||
                headerName == "vlan_tag_t") {
                // Skip standard headers
                continue;
            }
            
            // This is a custom header!
            CustomHeaderInfo info;
            info.name = field->name;
            info.isStack = false;
            info.maxStackSize = 1;
            info.elementTypeName = headerName;
            info.parserBit = nextCustomBit++;
            
            // Extract fields
            int bitOffset = 0;
            for (auto hdrField : headerType->fields) {
                CustomHeaderField fieldInfo;
                fieldInfo.width = hdrField->type->width_bits();
                fieldInfo.offset = bitOffset;
                fieldInfo.isPartOfStack = false;
                
                info.fields[hdrField->name] = fieldInfo;
                bitOffset += fieldInfo.width;
            }
            
            info.totalWidth = bitOffset;
            customHeaders[field->name] = info;
            
            if (g_verbose) {
                std::cerr << "    Found custom header: " << field->name 
                          << " (" << info.totalWidth << " bits)" << std::endl;
            }
        }
        // ==========================================
        // CASE 2: Header Stack (Array)
        // ==========================================
        else if (fieldType->is<IR::Type_Array>()) {
            auto arrayType = fieldType->to<IR::Type_Array>();
            if (!arrayType) continue;
            
            cstring stackName = field->name;
            
            // Get element type
            auto elementType = arrayType->elementType->to<IR::Type_Header>();
            if (!elementType) {
                if (g_verbose) {
                    std::cerr << "    Warning: Array " << stackName 
                            << " has non-header element type" << std::endl;
                }
                continue;
            }
            
            // Get array size
            int stackSize = 10; // Default
            if (auto sizeExpr = arrayType->size->to<IR::Constant>()) {
                stackSize = sizeExpr->asInt();
            }
            
            CustomHeaderInfo info;
            info.name = stackName;
            info.isStack = true;
            info.maxStackSize = stackSize;
            info.elementTypeName = elementType->name;
            info.parserBit = nextCustomBit++;
            
            // Extract fields and detect BOS
            int bitOffset = 0;
            bool foundBos = false;
            
            for (auto hdrField : elementType->fields) {
                CustomHeaderField fieldInfo;
                fieldInfo.width = hdrField->type->width_bits();
                fieldInfo.offset = bitOffset;
                fieldInfo.isPartOfStack = true;
                
                std::string fieldNameStr = hdrField->name.string();
                std::transform(fieldNameStr.begin(), fieldNameStr.end(), 
                            fieldNameStr.begin(), ::tolower);
                
                if ((fieldNameStr == "bos" || fieldNameStr == "last") && 
                    fieldInfo.width == 1) {
                    info.hasBosField = true;
                    info.bosFieldName = hdrField->name;
                    info.bosFieldOffset = bitOffset;
                    foundBos = true;
                    
                    if (g_verbose) {
                        std::cerr << "      Found BOS field: " << hdrField->name 
                                << " at bit " << bitOffset << std::endl;
                    }
                }
                
                info.fields[hdrField->name] = fieldInfo;
                bitOffset += fieldInfo.width;
            }
            
            info.totalWidth = bitOffset;
            customHeaders[stackName] = info;
            
            if (g_verbose) {
                std::cerr << "    Found header stack: " << stackName 
                        << "[" << stackSize << "] of type " 
                        << info.elementTypeName
                        << " (" << info.totalWidth << " bits per element)" 
                        << std::endl;
                
                if (!foundBos) {
                    std::cerr << "      WARNING: No BOS field found!" << std::endl;
                }
            }
        }
    }
    
    if (g_verbose && !customHeaders.empty()) {
        std::cerr << "    Extracted " << customHeaders.size() 
                  << " custom header(s)" << std::endl;
    }
}

// ==========================================
// Detect Header Stacks from Parser (.next accessor)
// This complements extractCustomHeaders() by marking
// headers as stacks if they use .next in parser
// ==========================================

void SVParser::detectHeaderStacksFromParser() {
    if (!parserBlock || !parserBlock->container) return;
    
    auto p4parser = parserBlock->container->to<IR::P4Parser>();
    if (!p4parser) return;
    
    if (g_verbose) {
        std::cerr << "  Detecting .next accessor patterns" << std::endl;
    }
    
    // Analyze parser states for stack extraction patterns
    for (auto state : p4parser->states) {
        if (!state || state->components.empty()) continue;
        
        for (auto component : state->components) {
            // Look for packet.extract(hdr.xxx.next)
            if (auto methodCall = component->to<IR::MethodCallStatement>()) {
                auto method = methodCall->methodCall;
                if (!method) continue;
                
                // Check if this is an extract() call
                if (auto member = method->method->to<IR::Member>()) {
                    if (member->member != "extract") continue;
                    
                    // Check if argument uses .next accessor
                    if (method->arguments && method->arguments->size() > 0) {
                        auto arg = method->arguments->at(0);
                        if (!arg || !arg->expression) continue;
                        
                        // Look for hdr.srcRoutes.next pattern
                        if (auto argMember = arg->expression->to<IR::Member>()) {
                            if (argMember->member == "next") {
                                // Found a stack extraction!
                                if (auto stackAccess = argMember->expr->to<IR::Member>()) {
                                    cstring stackName = stackAccess->member;
                                    
                                    // Check if already processed
                                    if (customHeaders.count(stackName)) {
                                        // Mark as stack (may already be marked from extractCustomHeaders)
                                        if (!customHeaders[stackName].isStack) {
                                            customHeaders[stackName].isStack = true;
                                            customHeaders[stackName].maxStackSize = 10; // Default
                                            
                                            if (g_verbose) {
                                                std::cerr << "    Detected stack: " << stackName 
                                                          << " (from .next accessor)" << std::endl;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ==========================================
// Helper methods for stack queries
// ==========================================

bool SVParser::hasHeaderStacks() const {
    for (const auto& ch : customHeaders) {
        if (ch.second.isStack) {
            return true;
        }
    }
    return false;
}

int SVParser::getMaxStackSize() const {
    int maxSize = 0;
    for (const auto& ch : customHeaders) {
        if (ch.second.isStack && ch.second.maxStackSize > maxSize) {
            maxSize = ch.second.maxStackSize;
        }
    }
    return maxSize;
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