// deparser.cpp

#include "common.h"
#include "deparser.h"
#include "program.h"
#include "lib/log.h"
#include "lib/error.h"
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <bitset>

namespace SV {

bool SVDeparser::build() {
    LOG1("Building deparser configuration extractor");
    
    if (!controlBlock || !controlBlock->container) {
        LOG1("Warning: No deparser control block, using default configuration");
        
        // Default: Emit Ethernet + IPv4 with checksum update
        deparserConfig = (1 << EMIT_ETHERNET) | 
                        (1 << EMIT_IPV4) | 
                        (1 << UPDATE_IPV4_CHECKSUM);
        
        emittedHeaders.push_back(cstring("ethernet"));
        emittedHeaders.push_back(cstring("ipv4"));
        
        return true;
    }
    
    // Analyze the deparser control block
    analyzeEmitStatements();
    
    // Extract configuration bits
    extractDeparserConfiguration();
    
    LOG1("Deparser analysis complete: " << emittedHeaders.size() << " headers emitted");
    LOG1("Deparser configuration: 0x" << std::hex << std::setw(4) << std::setfill('0') 
         << deparserConfig << std::dec);
    
    return true;
}

void SVDeparser::analyzeEmitStatements() {
    LOG2("Analyzing deparser emit statements");
    
    if (!controlBlock || !controlBlock->container) return;
    
    auto p4control = controlBlock->container->to<IR::P4Control>();
    if (!p4control) {
        LOG1("Warning: Control block is not a P4Control");
        return;
    }
    
    // Find the apply block
    auto apply = p4control->body;
    if (!apply) {
        LOG1("Warning: No apply block found in deparser");
        return;
    }
    
    // Traverse the apply block to find emit() calls
    for (auto component : apply->components) {
        if (auto methodCall = component->to<IR::MethodCallStatement>()) {
            auto method = methodCall->methodCall;
            
            if (!method || !method->method) continue;
            
            // Check if this is an emit() call
            if (auto member = method->method->to<IR::Member>()) {
                std::string methodName = member->member.string();
                
                if (methodName == "emit") {
                    // Extract header being emitted
                    if (method->arguments && method->arguments->size() > 0) {
                        auto arg = method->arguments->at(0);
                        
                        // Parse "hdr.ethernet" → "ethernet"
                        if (auto memberArg = arg->expression->to<IR::Member>()) {
                            std::string headerName = memberArg->member.string();
                            
                            // Convert to lowercase for consistency
                            std::transform(headerName.begin(), headerName.end(),
                                         headerName.begin(), ::tolower);
                            
                            cstring headerCName(headerName);
                            emittedHeaders.push_back(headerCName);
                            
                            LOG3("Found emit: " << headerName);
                        }
                    }
                }
            }
        }
    }
    
    // If no emit statements found, use default sequence
    if (emittedHeaders.empty()) {
        LOG1("Warning: No emit statements found, using default Ethernet→IPv4");
        emittedHeaders.push_back(cstring("ethernet"));
        emittedHeaders.push_back(cstring("ipv4"));
    }
}

void SVDeparser::extractDeparserConfiguration() {
    LOG2("Extracting deparser configuration");
    
    deparserConfig = 0;
    
    // Map emitted headers to configuration bits
    for (auto& headerName : emittedHeaders) {
        std::string name = headerName.string();
        
        // Convert to lowercase
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        
        if (name == "ethernet") {
            deparserConfig |= (1 << EMIT_ETHERNET);
            LOG3("Config: EMIT_ETHERNET enabled");
        }
        else if (name == "vlan") {
            deparserConfig |= (1 << EMIT_VLAN);
            LOG3("Config: EMIT_VLAN enabled");
        }
        else if (name == "ipv4") {
            deparserConfig |= (1 << EMIT_IPV4);
            deparserConfig |= (1 << UPDATE_IPV4_CHECKSUM);  // Auto-enable checksum
            LOG3("Config: EMIT_IPV4 enabled (with checksum update)");
        }
        else if (name == "ipv6") {
            deparserConfig |= (1 << EMIT_IPV6);
            LOG3("Config: EMIT_IPV6 enabled");
        }
        else if (name == "tcp") {
            deparserConfig |= (1 << EMIT_TCP);
            deparserConfig |= (1 << UPDATE_TCP_CHECKSUM);  // Auto-enable checksum
            LOG3("Config: EMIT_TCP enabled (with checksum update)");
        }
        else if (name == "udp") {
            deparserConfig |= (1 << EMIT_UDP);
            deparserConfig |= (1 << UPDATE_UDP_CHECKSUM);  // Auto-enable checksum
            LOG3("Config: EMIT_UDP enabled (with checksum update)");
        }
        else if (name == "vxlan") {
            deparserConfig |= (1 << EMIT_VXLAN);
            LOG3("Config: EMIT_VXLAN enabled");
        }
        else {
            LOG2("Warning: Unknown header type '" << name 
                 << "' in deparser, not included in config");
        }
    }
    
    LOG1("Final deparser config: 0x" << std::hex << std::setw(4) 
         << std::setfill('0') << deparserConfig << std::dec);
}

std::string SVDeparser::getDeparserConfigString() const {
    std::stringstream ss;
    
    // Generate hex string (16-bit value)
    ss << std::hex << std::setw(4) << std::setfill('0') << deparserConfig;
    
    return ss.str();
}

bool SVDeparser::emitsHeader(const cstring& headerName) const {
    for (auto& header : emittedHeaders) {
        if (header == headerName) {
            return true;
        }
    }
    return false;
}

void SVDeparser::emit(SVCodeGen& codegen) {
    LOG1("Deparser emission skipped - using deparser template");
    LOG1("Deparser configuration: 16'h" << getDeparserConfigString());
    
    // NOTE: We no longer generate deparser.sv module
    // Instead, the configuration is used in the top-level module
    // to instantiate the deparser.sv template
    
    // Display configuration breakdown for debugging
    std::stringstream configInfo;
    configInfo << "Deparser config breakdown:";
    
    if (deparserConfig & (1 << EMIT_ETHERNET)) 
        configInfo << " ETHERNET";
    if (deparserConfig & (1 << EMIT_VLAN)) 
        configInfo << " VLAN";
    if (deparserConfig & (1 << EMIT_IPV4)) 
        configInfo << " IPv4";
    if (deparserConfig & (1 << EMIT_IPV6)) 
        configInfo << " IPv6";
    if (deparserConfig & (1 << EMIT_TCP)) 
        configInfo << " TCP";
    if (deparserConfig & (1 << EMIT_UDP)) 
        configInfo << " UDP";
    if (deparserConfig & (1 << EMIT_VXLAN)) 
        configInfo << " VXLAN";
    if (deparserConfig & (1 << UPDATE_IPV4_CHECKSUM)) 
        configInfo << " [IPv4-CKSUM]";
    if (deparserConfig & (1 << UPDATE_TCP_CHECKSUM)) 
        configInfo << " [TCP-CKSUM]";
    if (deparserConfig & (1 << UPDATE_UDP_CHECKSUM)) 
        configInfo << " [UDP-CKSUM]";
    
    LOG1(configInfo.str());
}

void SVDeparser::emitModuleHeader(CodeBuilder* builder) {
    // This method is now unused but kept for compatibility
    builder->appendLine("// Deparser module generation disabled");
    builder->appendLine("// Using deparser.sv template instead");
}

void SVDeparser::emitPortDeclarations(CodeBuilder* builder) {
    // This method is now unused but kept for compatibility
}

void SVDeparser::emitDropFilter(CodeBuilder* builder) {
    // This method is now unused but kept for compatibility
}

}  // namespace SV