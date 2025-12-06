// program.cpp

#include "common.h"
#include "frontends/p4/coreLibrary.h"
#include "program.h"
#include "parser.h"
#include "table.h"
#include "control.h"
#include "deparser.h"
#include "lib/log.h"
#include <sstream>
#include <fstream>
#include <sys/stat.h>
#include <sys/types.h>
#include <iomanip>

namespace SV {

// ==========================================
// Debug Control
// ==========================================
#define PROGRAM_DEBUG(msg) if (SV::g_verbose) std::cerr << "  " << msg << std::endl
#define PROGRAM_TRACE(msg) if (SV::g_verbose) std::cerr << "    " << msg << std::endl

// ==========================================
// Destructor
// ==========================================

SVProgram::~SVProgram() {
    delete parser;
    delete ingress;
    delete egress;
    delete deparser;
}

// ==========================================
// Copy Templates
// ==========================================

bool SVProgram::copyTemplates(const std::string& outputDir) {
    PROGRAM_DEBUG("Copying parser/deparser templates");
    
    // Create hdl directory if it doesn't exist
    std::string hdlDir = outputDir + "/hdl";
    mkdir(hdlDir.c_str(), 0755);
    
    // Paths to source templates
    std::string srcParserPath = "../src/sv/hdl/parser.sv.in";
    std::string srcDeparserPath = "../src/sv/hdl/deparser.sv.in";
    
    // Destination paths
    std::string dstParserPath = hdlDir + "/parser.sv";
    std::string dstDeparserPath = hdlDir + "/deparser.sv";
    
    // Copy parser template
    std::ifstream srcParser(srcParserPath, std::ios::binary);
    if (!srcParser.is_open()) {
        P4::error("Failed to open parser template: %s", srcParserPath.c_str());
        return false;
    }
    
    std::ofstream dstParser(dstParserPath, std::ios::binary);
    if (!dstParser.is_open()) {
        P4::error("Failed to create parser destination: %s", dstParserPath.c_str());
        return false;
    }
    
    dstParser << srcParser.rdbuf();
    srcParser.close();
    dstParser.close();
    
    PROGRAM_TRACE("Copied parser.sv");
    
    // Copy deparser template
    std::ifstream srcDeparser(srcDeparserPath, std::ios::binary);
    if (!srcDeparser.is_open()) {
        P4::error("Failed to open deparser template: %s", srcDeparserPath.c_str());
        return false;
    }
    
    std::ofstream dstDeparser(dstDeparserPath, std::ios::binary);
    if (!dstDeparser.is_open()) {
        P4::error("Failed to create deparser destination: %s", dstDeparserPath.c_str());
        return false;
    }
    
    dstDeparser << srcDeparser.rdbuf();
    srcDeparser.close();
    dstDeparser.close();
    
    PROGRAM_TRACE("Copied deparser.sv");
    
    return true;
}

// ==========================================
// Build Program
// ==========================================

bool SVProgram::build() {
    if (!toplevel) {
        P4::error("No toplevel block provided");
        return false;
    }
    
    auto pack = toplevel->getMain();
    if (!pack) {
        P4::error("No main package found");
        return false;
    }
    
    PROGRAM_DEBUG("Main package: " << pack->getName().toString());
    
    if (!program) {
        program = toplevel->getProgram();
        if (!program) {
            P4::error("No P4Program found in toplevel block");
            return false;
        }
    }
        
    extractConstants(); 

    // Process all objects in the program
    for (auto obj : program->objects) {
        if (auto p = obj->to<IR::P4Parser>()) {
            PROGRAM_TRACE("Found parser: " << p->name);
            
            if (p->name.string().find("Parser") != std::string::npos) {
                auto pb = new IR::ParserBlock(p, p->type, p);
                parser = new SVParser(this, pb, typeMap, refMap);
                
                if (!parser->build()) {
                    if (g_verbose) {
                        std::cerr << "WARNING: Parser build failed" << std::endl;
                    }
                } else {
                    parserConfig = parser->getParserConfig();
                    PROGRAM_TRACE("Parser configuration: 0b" << parser->getParserConfigString());
                }
            }
            
        } else if (auto c = obj->to<IR::P4Control>()) {
            PROGRAM_TRACE("Found control: " << c->name);
            
            if (c->name == "MyIngress") {
                PROGRAM_DEBUG("Building ingress control");
                
                auto cb = new IR::ControlBlock(c, c->type, c);
                ingress = new SVControl(this, cb, typeMap, refMap);
                ingress->setIsIngress(true);
                
                if (!ingress->build()) {
                    if (g_verbose) {
                        std::cerr << "WARNING: Ingress build failed" << std::endl;
                    }
                }
                
                controlConfig = ingress->extractConfiguration();
                PROGRAM_TRACE("Control configuration extracted");
                
            } else if (c->name == "MyEgress") {
                PROGRAM_DEBUG("Building egress control");
                
                auto cb = new IR::ControlBlock(c, c->type, c);
                egress = new SVControl(this, cb, typeMap, refMap);
                egress->setIsIngress(false);
                
                if (!egress->build()) {
                    if (g_verbose) {
                        std::cerr << "WARNING: Egress build failed" << std::endl;
                    }
                }
                
                ControlConfig egressConfig = egress->extractConfiguration();
                controlConfig.egressConfig |= egressConfig.egressConfig;
                
                PROGRAM_TRACE("Egress configuration merged: 0x" << std::hex 
                            << (int)controlConfig.egressConfig << std::dec);
                
            } else if (c->name == "MyDeparser") {
                PROGRAM_DEBUG("Building deparser");
                
                auto cb = new IR::ControlBlock(c, c->type, c);
                deparser = new SVDeparser(this, cb);
                
                if (!deparser->build()) {
                    if (g_verbose) {
                        std::cerr << "WARNING: Deparser build failed" << std::endl;
                    }
                } else {
                    deparserConfig = deparser->getDeparserConfig();
                    PROGRAM_TRACE("Deparser configuration: 0x" << std::hex 
                                << deparserConfig << std::dec);
                }
            }
        }
    }

    // Create defaults only if components weren't found
    if (!parser) {
        if (g_verbose) {
            std::cerr << "WARNING: No parser found, creating default" << std::endl;
        }
        parser = new SVParser(this, nullptr, typeMap, refMap);
        parser->build();
        parserConfig = parser->getParserConfig();
    }
    
    if (!ingress) {
        if (g_verbose) {
            std::cerr << "WARNING: No ingress found, creating default" << std::endl;
        }
        ingress = new SVControl(this, nullptr, typeMap, refMap);
        ingress->setIsIngress(true);
        ingress->build();
    }
    
    if (!egress) {
        if (g_verbose) {
            std::cerr << "WARNING: No egress found, creating default" << std::endl;
        }
        egress = new SVControl(this, nullptr, typeMap, refMap);
        egress->setIsIngress(false);
        egress->build();
    }
    
    if (!deparser) {
        if (g_verbose) {
            std::cerr << "WARNING: No deparser found, creating default" << std::endl;
        }
        deparser = new SVDeparser(this, nullptr);
        deparser->build();
        deparserConfig = deparser->getDeparserConfig();
    }
    
    pipelineConfig.stageCount = 4;
    PROGRAM_TRACE("Pipeline stages: " << pipelineConfig.stageCount);
    
    // NOTE: Configuration summary now printed in backend.cpp
    // Old duplicate summary removed
    
    return true;
}

// ==========================================
// Extract Constants
// ==========================================

void SVProgram::extractConstants() {
    PROGRAM_TRACE("Extracting P4 constants");
    
    if (!program) return;
    
    for (auto obj : program->objects) {
        if (auto constant = obj->to<IR::Declaration_Constant>()) {
            PROGRAM_TRACE("    Found Declaration_Constant: " << constant->name);
            
            const IR::Expression* init = constant->initializer;
            
            // Unwrap Cast if present
            if (auto cast = init->to<IR::Cast>()) {
                init = cast->expr;
            }
            
            if (auto expr = init->to<IR::Constant>()) {
                int64_t value = expr->asInt();
                constants[constant->name] = value;
                PROGRAM_TRACE("    Value: " << value);
                
                if (constant->name == "ECN_THRESHOLD") {
                    ecnThreshold = expr->asUnsigned();
                }
            }
        }
    }
    
    PROGRAM_TRACE("Extracted " << constants.size() << " constants");
}

}  // namespace SV