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

// Helper function to recursively scan for if-statements
void scanForIfStatements(const P4::IR::Node* node, const P4::cstring& controlName, int& count) {
    if (!node) return;
    
    if (auto ifStmt = node->to<P4::IR::IfStatement>()) {
        count++;
        
        std::cerr << "╔═══════════════════════════════════════════╗" << std::endl;
        std::cerr << "║  IF-ELSE #" << count << " in " << controlName << std::endl;
        std::cerr << "╚═══════════════════════════════════════════╝" << std::endl;
        std::cerr << "  Condition: " << ifStmt->condition << std::endl;
        
        if (ifStmt->ifTrue) {
            std::cerr << "  True:  " << ifStmt->ifTrue->node_type_name();
            
            // Try to get action name if it's a method call
            if (auto block = ifStmt->ifTrue->to<P4::IR::BlockStatement>()) {
                if (block->components.size() > 0) {
                    if (auto methodCall = block->components[0]->to<P4::IR::MethodCallStatement>()) {
                        if (auto path = methodCall->methodCall->method->to<P4::IR::PathExpression>()) {
                            std::cerr << " → " << path->path->name;
                        }
                    }
                }
            }
            std::cerr << std::endl;
        }
        
        if (ifStmt->ifFalse) {
            std::cerr << "  False: " << ifStmt->ifFalse->node_type_name();
            
            // Try to get action name
            if (auto block = ifStmt->ifFalse->to<P4::IR::BlockStatement>()) {
                if (block->components.size() > 0) {
                    if (auto methodCall = block->components[0]->to<P4::IR::MethodCallStatement>()) {
                        if (auto path = methodCall->methodCall->method->to<P4::IR::PathExpression>()) {
                            std::cerr << " → " << path->path->name;
                        }
                    }
                }
            }
            std::cerr << std::endl;
        }
        
        std::cerr << "───────────────────────────────────────────" << std::endl;
        
        // Recursively scan branches for nested if-statements
        scanForIfStatements(ifStmt->ifTrue, controlName, count);
        scanForIfStatements(ifStmt->ifFalse, controlName, count);
    }
    
    // Scan block statements
    if (auto block = node->to<P4::IR::BlockStatement>()) {
        for (auto component : block->components) {
            scanForIfStatements(component, controlName, count);
        }
    }
}

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
    if (SV::g_verbose) {
        std::cerr << "Parsing P4 file..." << std::endl;
    }
    
    auto program = P4::parseP4File(options);
    if (program == nullptr || P4::errorCount() > 0) {
        P4::error("Failed to parse P4 file");
        return 1;
    }
    
    if (SV::g_verbose) {
        std::cerr << "Parse successful" << std::endl;
    }

    // ==========================================
    // Extract parser state data from raw AST (before transformations)
    // ==========================================
    if (SV::g_verbose) {
        std::cerr << "\n=== Extracting parser state data from raw AST ===" << std::endl;
    }
    
    for (auto obj : program->objects) {
        if (auto parser = obj->to<P4::IR::P4Parser>()) {
            if (SV::g_verbose) {
                std::cerr << "Found parser: " << parser->name << std::endl;
                std::cerr << "  states.size() = " << parser->states.size() << std::endl;
            }
            
            std::vector<SV::ExtractedParserState> extractedStates;
            
            for (auto state : parser->states) {
                if (!state) {
                    if (SV::g_verbose) {
                        std::cerr << "  Warning: null state" << std::endl;
                    }
                    continue;
                }
                
                if (SV::g_verbose) {
                    std::cerr << "  Extracting data from state: " << state->name << std::endl;
                }
                
                SV::ExtractedParserState extracted(state->name);
                
                // Mark special states
                if (state->name == "start") {
                    extracted.isStart = true;
                    if (SV::g_verbose) {
                        std::cerr << "    (start state)" << std::endl;
                    }
                }
                if (state->name == "accept" || state->name == "reject") {
                    extracted.isAccept = true;
                    if (SV::g_verbose) {
                        std::cerr << "    (accept/reject state)" << std::endl;
                    }
                }
                
                // Extract header names from extract() calls
                if (SV::g_verbose) {
                    std::cerr << "    Components: " << state->components.size() << std::endl;
                }
                
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
                                    
                                    if (SV::g_verbose) {
                                        std::cerr << "      Extracts: " << headerName << std::endl;
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Extract transitions
                if (state->selectExpression) {
                    if (SV::g_verbose) {
                        std::cerr << "    Has selectExpression" << std::endl;
                    }
                    
                    if (auto select = state->selectExpression->to<P4::IR::SelectExpression>()) {
                        if (SV::g_verbose) {
                            std::cerr << "      Select with " << select->selectCases.size() << " cases" << std::endl;
                        }
                        
                        for (auto selectCase : select->selectCases) {
                            if (!selectCase) continue;
                            
                            if (auto nextState = selectCase->state->to<P4::IR::PathExpression>()) {
                                P4::cstring nextStateName = nextState->path->name;
                                
                                if (selectCase->keyset->is<P4::IR::DefaultExpression>()) {
                                    extracted.transitions[P4::cstring("default")] = nextStateName;
                                    if (SV::g_verbose) {
                                        std::cerr << "        default -> " << nextStateName << std::endl;
                                    }
                                } else {
                                    P4::cstring condition = selectCase->keyset->toString();
                                    extracted.transitions[condition] = nextStateName;
                                    if (SV::g_verbose) {
                                        std::cerr << "        " << condition << " -> " << nextStateName << std::endl;
                                    }
                                }
                            }
                        }
                    } else if (auto path = state->selectExpression->to<P4::IR::PathExpression>()) {
                        P4::cstring nextStateName = path->path->name;
                        extracted.transitions[P4::cstring("always")] = nextStateName;
                        if (SV::g_verbose) {
                            std::cerr << "      Unconditional -> " << nextStateName << std::endl;
                        }
                    }
                } else {
                    if (SV::g_verbose) {
                        std::cerr << "    No selectExpression" << std::endl;
                    }
                }
                
                extractedStates.push_back(extracted);
            }
            
            if (!extractedStates.empty()) {
                SV::g_extractedParserStates[parser->name] = extractedStates;
                if (SV::g_verbose) {
                    std::cerr << "Extracted data from " << extractedStates.size() 
                             << " states for parser " << parser->name << std::endl;
                }
            }
        }
    }
    
    if (SV::g_verbose) {
        std::cerr << "=== Parser state extraction complete ===" << std::endl << std::endl;
    }

    // ==========================================
    // PHASE 3a: Detect if-else statements in raw AST
    // ==========================================
    if (SV::g_verbose) {
        std::cerr << "\n=== Phase 3a: Scanning for control flow ===" << std::endl;
    }
    
    int ifElseCount = 0;
    
    for (auto obj : program->objects) {
        if (auto control = obj->to<P4::IR::P4Control>()) {
            if (!control->body) continue;
            
            if (SV::g_verbose) {
                std::cerr << "Scanning control: " << control->name << std::endl;
            }
            
            // Recursively scan for if-statements (including nested ones)
            scanForIfStatements(control->body, control->name, ifElseCount);
        }
    }
    
    if (ifElseCount > 0) {
        std::cerr << "\n[Phase 3a] Found " << ifElseCount << " if-else statement(s)" << std::endl;
        std::cerr << "[Phase 3a] These will be compiled as-is (no hardware support yet)" << std::endl;
    } else {
        if (SV::g_verbose) {
            std::cerr << "[Phase 3a] No if-else statements found (table-based logic only)" << std::endl;
        }
    }
    
    std::cerr << "=== Phase 3a complete ===" << std::endl << std::endl;

    // Run frontend
    if (SV::g_verbose) {
        std::cerr << "Running frontend..." << std::endl;
    }
    
    SV::FrontEnd frontend;
    try {
        program = frontend.run(options, program);
        if (SV::g_verbose) {
            std::cerr << "Frontend complete" << std::endl;
        }
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Frontend error: " << bug.what() << std::endl;
        return 1;
    }
    
    if (program == nullptr || P4::errorCount() > 0) {
        P4::error("Frontend processing failed");
        return 1;
    }
       
    // Run midend
    if (SV::g_verbose) {
        std::cerr << "Running midend..." << std::endl;
    }
    
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
        if (SV::g_verbose) {
            std::cerr << "Midend complete" << std::endl;
        }
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Midend error: " << bug.what() << std::endl;
        return 1;
    }
    
    if (toplevel == nullptr || P4::errorCount() > 0) {
        P4::error("Failed to create toplevel block");
        return 1;
    }
    
    // Run backend
    if (SV::g_verbose) {
        std::cerr << "Running backend..." << std::endl;
    }
    
    SV::Backend backend(midend.refMap, midend.typeMap);
    try {
        backend.run(options, toplevel, midend.refMap, midend.typeMap);
        if (SV::g_verbose) {
            std::cerr << "Backend complete" << std::endl;
        }
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Backend error: " << bug.what() << std::endl;
        return 1;
    }
        
    LOG1("Compilation complete. Error count: " << P4::errorCount());
    return P4::errorCount() > 0 ? 1 : 0;
}