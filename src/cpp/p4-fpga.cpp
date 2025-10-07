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
#include "frontend.h"  
#include "frontends/common/parseInput.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "lib/cstring.h"

int main(int argc, char *const argv[]) {
    setup_gc_logging();
    P4::setup_signals();
    
    P4::AutoCompileContext autoContext(new SV::SVContext());
    auto& options = SV::SVContext::get().options();
    
    options.langVersion = P4::CompilerOptions::FrontendVersion::P4_16;
    options.compilerVersion = P4::cstring("1.0.0");
    
    if (options.process(argc, argv) != nullptr) {
        options.setInputFile();
    }
    
    if (P4::errorCount() > 0) {
        return 1;
    }
    
    // Parse P4 file
    std::cerr << "Parsing P4 file..." << std::endl;
    auto program = P4::parseP4File(options);
    if (program == nullptr || P4::errorCount() > 0) {
        P4::error("Failed to parse P4 file");
        return 1;
    }
    std::cerr << "Parse successful" << std::endl;

    // **EXTRACT parser state DATA from raw AST (before transformations)**
    std::cerr << "\n=== Extracting parser state data from raw AST ===" << std::endl;
    
    for (auto obj : program->objects) {
        if (auto parser = obj->to<P4::IR::P4Parser>()) {
            std::cerr << "Found parser: " << parser->name << std::endl;
            std::cerr << "  states.size() = " << parser->states.size() << std::endl;
            
            std::vector<SV::ExtractedParserState> extractedStates;
            
            for (auto state : parser->states) {
                if (!state) {
                    std::cerr << "  Warning: null state" << std::endl;
                    continue;
                }
                
                std::cerr << "  Extracting data from state: " << state->name << std::endl;
                
                SV::ExtractedParserState extracted(state->name);
                
                // Mark special states
                if (state->name == "start") {
                    extracted.isStart = true;
                    std::cerr << "    (start state)" << std::endl;
                }
                if (state->name == "accept" || state->name == "reject") {
                    extracted.isAccept = true;
                    std::cerr << "    (accept/reject state)" << std::endl;
                }
                
                // Extract header names from extract() calls
                std::cerr << "    Components: " << state->components.size() << std::endl;
                for (auto component : state->components) {
                    if (!component) continue;
                    
                    if (auto methodCall = component->to<P4::IR::MethodCallStatement>()) {
                        auto method = methodCall->methodCall;
                        if (!method) continue;
                        
                        std::string methodName = method->method->toString().string();
                        if (methodName.find("extract") != std::string::npos) {
                            if (method->arguments && method->arguments->size() > 0) {
                                auto arg = method->arguments->at(0);
                                if (arg && arg->expression) {
                                    // Extract just the header name
                                    P4::cstring headerName = arg->expression->toString();
                                    extracted.extractedHeaders.push_back(headerName);
                                    std::cerr << "      Extracts: " << headerName << std::endl;
                                }
                            }
                        }
                    }
                }
                
                // Extract transitions
                if (state->selectExpression) {
                    std::cerr << "    Has selectExpression" << std::endl;
                    
                    if (auto select = state->selectExpression->to<P4::IR::SelectExpression>()) {
                        std::cerr << "      Select with " << select->selectCases.size() << " cases" << std::endl;
                        
                        for (auto selectCase : select->selectCases) {
                            if (!selectCase) continue;
                            
                            if (auto nextState = selectCase->state->to<P4::IR::PathExpression>()) {
                                P4::cstring nextStateName = nextState->path->name;
                                
                                if (selectCase->keyset->is<P4::IR::DefaultExpression>()) {
                                    extracted.transitions[P4::cstring("default")] = nextStateName;
                                    std::cerr << "        default -> " << nextStateName << std::endl;
                                } else {
                                    P4::cstring condition = selectCase->keyset->toString();
                                    extracted.transitions[condition] = nextStateName;
                                    std::cerr << "        " << condition << " -> " << nextStateName << std::endl;
                                }
                            }
                        }
                    } else if (auto path = state->selectExpression->to<P4::IR::PathExpression>()) {
                        P4::cstring nextStateName = path->path->name;
                        extracted.transitions[P4::cstring("always")] = nextStateName;
                        std::cerr << "      Unconditional -> " << nextStateName << std::endl;
                    }
                } else {
                    std::cerr << "    No selectExpression" << std::endl;
                }
                
                extractedStates.push_back(extracted);
            }
            
            if (!extractedStates.empty()) {
                SV::g_extractedParserStates[parser->name] = extractedStates;
                std::cerr << "Extracted data from " << extractedStates.size() 
                         << " states for parser " << parser->name << std::endl;
            }
        }
    }
    
    std::cerr << "=== Parser state extraction complete ===" << std::endl << std::endl;

    // Run frontend
    SV::FrontEnd frontend;
    try {
        std::cerr << "Running frontend..." << std::endl;
        program = frontend.run(options, program);
        std::cerr << "Frontend complete" << std::endl;
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Frontend error: " << bug.what() << std::endl;
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

    midend.refMap = frontend.getRefMap();
    midend.typeMap = frontend.getTypeMap();
    
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
    SV::Backend backend(midend.refMap, midend.typeMap);
    try {
        backend.run(options, toplevel, midend.refMap, midend.typeMap);
        std::cerr << "Backend complete" << std::endl;
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Backend error: " << bug.what() << std::endl;
        return 1;
    }
        
    LOG1("Compilation complete. Error count: " << P4::errorCount());
    return P4::errorCount() > 0 ? 1 : 0;
}