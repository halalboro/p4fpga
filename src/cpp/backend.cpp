#include "common.h"
#include "backend.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <map>
#include <string>

#include "ir/ir.h"
#include "lib/error.h"
#include "lib/nullstream.h"
#include "lib/cstring.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/toP4/toP4.h"
#include "program.h"
#include "type.h"
#include "options.h"
#include "bsvprogram.h"

namespace SV {

void Backend::run(const SVOptions& options,
                  const IR::ToplevelBlock* toplevel,
                  P4::ReferenceMap* refMap,
                  P4::TypeMap* typeMap) {
    
    // Create type factory (if needed)
    FPGATypeFactory::createFactory(typeMap);
    
    // Build the program representation
    SVProgram svprog(toplevel, refMap, typeMap);
    if (!svprog.build()) {
        P4::error("SVProgram build failed");
        return;
    }
    
    if (options.outputDir.isNullOrEmpty()) {
        P4::error("Must specify output directory with --output-dir");
        return;
    }
    
    // Fix: Add .c_str() for cstring to path conversion
    boost::filesystem::path dir(options.outputDir.c_str());
    
    // Create directory if it doesn't exist
    if (!boost::filesystem::exists(dir)) {
        boost::filesystem::create_directories(dir);
    }
    
    // Create SystemVerilog code generator
    SVCodeGen codegen;
    svprog.emit(codegen);
    
    // Define output files for SystemVerilog
    std::map<std::string, std::string> outputFiles = {
        {"top.sv",         codegen.getTopModule()},
        {"parser.sv",      codegen.getParserModule()},
        {"ingress.sv",     codegen.getIngressModule()},
        {"egress.sv",      codegen.getEgressModule()},
        {"deparser.sv",    codegen.getDeparserModule()},
        {"tables.sv",      codegen.getTablesModule()},
        {"actions.sv",     codegen.getActionsModule()},
        {"types.svh",      codegen.getTypeDefinitions()},
        {"interfaces.svh", codegen.getInterfaces()}
    };
    
    // Write all output files
    // Fix: Use iterator instead of structured binding for C++11 compatibility
    for (auto it = outputFiles.begin(); it != outputFiles.end(); ++it) {
        const std::string& filename = it->first;
        const std::string& content = it->second;
        
        boost::filesystem::path filepath = dir / filename;
        std::ofstream out(filepath.string());  // Use .string() for path
        
        if (!out) {
            P4::error("Failed to open file %1%", filepath.string());
            continue;
        }
        
        out << content;
        out.close();
        LOG1("Generated " << filepath.string());
    }
    
    // Generate testbench if requested (check if option exists)
    if (options.generateTestbench) {
        boost::filesystem::path tbFile = dir / "testbench.sv";
        std::ofstream tb(tbFile.string());
        
        if (tb) {
            tb << codegen.getTestbench();
            tb.close();
            LOG1("Generated testbench: " << tbFile.string());
        }
    }
    
    // Generate Makefile for simulation
    boost::filesystem::path makeFile = dir / "Makefile";
    std::ofstream make(makeFile.string());
    
    if (make) {
        make << codegen.getMakefile();
        make.close();
        LOG1("Generated Makefile: " << makeFile.string());
    }
    
    LOG1("Backend processing complete. Generated " << outputFiles.size() << " files.");
}

}  // namespace SV