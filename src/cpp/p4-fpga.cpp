#include "common.h"
#include <stdio.h>
#include <string>
#include <iostream>
#include "ir/ir.h"
#include "lib/log.h"
#include "lib/crash.h"
#include "lib/exceptions.h"
#include "lib/compile_context.h"
#include "lib/gc.h"
#include "lib/error.h"
#include "midend.h"
#include "options.h"
#include "backend.h"
#include "frontends/common/parseInput.h"
#include "frontends/p4/frontend.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "lib/cstring.h"

int main(int argc, char *const argv[]) {
    setup_gc_logging();
    P4::setup_signals();
    
    P4::AutoCompileContext autoContext(new SV::SVContext());
    auto& options = SV::SVContext::get().options();
    
    // Set version info BEFORE processing options (important!)
    options.langVersion = P4::CompilerOptions::FrontendVersion::P4_16;
    options.compilerVersion = P4::cstring("1.0.0");
    
    if (options.process(argc, argv) != nullptr) {
        options.setInputFile();
    }
    
    if (P4::errorCount() > 0) {
        return 1;
    }
    
    //auto hook = options.getDebugHook();
    
    // Parse P4 file
    std::cerr << "Parsing P4 file..." << std::endl;
    auto program = P4::parseP4File(options);
    if (program == nullptr || P4::errorCount() > 0) {
        P4::error("Failed to parse P4 file");
        return 1;
    }
    std::cerr << "Parse successful" << std::endl;
    
    // Run frontend
    try {
        std::cerr << "Running frontend..." << std::endl;
        P4::FrontEnd frontend;
        //frontend.addDebugHook(hook);
        program = frontend.run(options, program, nullptr);
        std::cerr << "Frontend complete" << std::endl;
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Frontend error: " << bug.what() << std::endl;
        return 1;
    } catch (const std::exception &e) {
        std::cerr << "Frontend std exception: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Frontend unknown exception" << std::endl;
        return 1;
    }
    
    if (program == nullptr || P4::errorCount() > 0) {
        P4::error("Frontend processing failed");
        return 1;
    }
    
    // Run midend
    std::cerr << "Running midend..." << std::endl;
    const P4::IR::ToplevelBlock* toplevel = nullptr;
    SV::MidEnd midend;
    try {
        toplevel = midend.run(options, program);
        if (P4::errorCount() > 0) {
            P4::error("Midend processing failed");
            return 1;
        }
        std::cerr << "Midend complete" << std::endl;
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Midend error: " << bug.what() << std::endl;
        return 1;
    }
    
    if (toplevel == nullptr || P4::errorCount() > 0) {
        P4::error("Failed to create toplevel block");
        return 1;
    }
    
    // Run backend
    std::cerr << "Running backend..." << std::endl;
    SV::Backend backend(&midend.refMap, &midend.typeMap);
    try {
        backend.run(options, toplevel, &midend.refMap, &midend.typeMap);
        std::cerr << "Backend complete" << std::endl;
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Backend error: " << bug.what() << std::endl;
        return 1;
    }
    
    if (P4::errorCount() > 0) {
        P4::error("Backend processing failed");
        return 1;
    }
    
    LOG1("Compilation complete. Error count: " << P4::errorCount());
    return P4::errorCount() > 0 ? 1 : 0;
}