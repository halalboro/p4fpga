/*
 * P4-FPGA Compiler - Main Entry Point
 *
 * Orchestrates the compilation pipeline from P4 source to SystemVerilog HDL:
 *   Phase 0: Parse P4 source file
 *   Phase 1: Extract parser states from raw AST
 *   Phase 2: Detect control flow patterns (if-else statements)
 *   Phase 3: Run P4C frontend (type checking, semantic analysis)
 *   Phase 4: Run P4C midend (IR transformations, optimizations)
 *   Phase 5: Run backend (SystemVerilog code generation)
 */

#include "common.h"
#include "midend.h"
#include "options.h"
#include "backend.h"
#include "frontend.h"

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
#include "lib/cstring.h"
#include "frontends/common/parseInput.h"
#include "frontends/p4/evaluator/evaluator.h"

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Recursively scan AST for if-statements and extract simple patterns
 * that can be mapped to hardware conditional logic.
 */
void scanForIfStatements(const P4::IR::Node* node, const P4::cstring& controlName, int& count) {
    if (!node) return;
    
    if (auto ifStmt = node->to<P4::IR::IfStatement>()) {
        count++;

        P4::cstring trueActionName;
        P4::cstring falseActionName;

        // Extract action name from true branch if it's a method call
        if (ifStmt->ifTrue) {
            if (auto block = ifStmt->ifTrue->to<P4::IR::BlockStatement>()) {
                if (block->components.size() > 0) {
                    if (auto methodCall = block->components[0]->to<P4::IR::MethodCallStatement>()) {
                        if (auto path = methodCall->methodCall->method->to<P4::IR::PathExpression>()) {
                            trueActionName = path->path->name;
                        }
                    }
                }
            }
        }

        // Extract action name from false branch
        if (ifStmt->ifFalse) {
            if (auto block = ifStmt->ifFalse->to<P4::IR::BlockStatement>()) {
                if (block->components.size() > 0) {
                    if (auto methodCall = block->components[0]->to<P4::IR::MethodCallStatement>()) {
                        if (auto path = methodCall->methodCall->method->to<P4::IR::PathExpression>()) {
                            falseActionName = path->path->name;
                        }
                    }
                }
            }
        }

        // Store if-else info for backend hardware generation
        // Only store simple if-else patterns with action calls
        if (!trueActionName.isNullOrEmpty()) {
            // Check if this is a simple comparison we can handle in hardware
            if (auto equ = ifStmt->condition->to<P4::IR::Equ>()) {
                SV::g_detectedIfElse.emplace_back(
                    controlName,
                    ifStmt->condition,
                    trueActionName,
                    falseActionName
                );

                if (SV::g_verbose) {
                    std::cerr << "Detected if-else #" << count << " in " << controlName
                              << ": " << trueActionName;
                    if (!falseActionName.isNullOrEmpty()) {
                        std::cerr << " / " << falseActionName;
                    }
                    std::cerr << std::endl;
                }
            }
        }
        
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

// =============================================================================
// Main Entry Point
// =============================================================================

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

    // -------------------------------------------------------------------------
    // Phase 0: Parse P4 Source File
    // -------------------------------------------------------------------------
    if (SV::g_verbose) {
        std::cerr << "[Phase 0] Parsing P4 source file..." << std::endl;
    }

    auto program = P4::parseP4File(options);
    if (program == nullptr || P4::errorCount() > 0) {
        P4::error("Failed to parse P4 file");
        return 1;
    }

    if (SV::g_verbose) {
        std::cerr << "[Phase 0] Complete" << std::endl;
    }

    // -------------------------------------------------------------------------
    // Phase 1: Extract Parser States from Raw AST
    // Before IR transformations, capture original parser structure
    // -------------------------------------------------------------------------
    if (SV::g_verbose) {
        std::cerr << "[Phase 1] Extracting parser state data..." << std::endl;
    }

    for (auto obj : program->objects) {
        if (auto parser = obj->to<P4::IR::P4Parser>()) {
            std::vector<SV::ExtractedParserState> extractedStates;

            for (auto state : parser->states) {
                if (!state) continue;

                SV::ExtractedParserState extracted(state->name);

                // Mark special states
                if (state->name == "start") {
                    extracted.isStart = true;
                }
                if (state->name == "accept" || state->name == "reject") {
                    extracted.isAccept = true;
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
                                    P4::cstring headerName = arg->expression->toString();
                                    extracted.extractedHeaders.push_back(headerName);
                                }
                            }
                        }
                    }
                }
                
                // Extract state transitions
                if (state->selectExpression) {
                    if (auto select = state->selectExpression->to<P4::IR::SelectExpression>()) {
                        for (auto selectCase : select->selectCases) {
                        if (!selectCase) continue;
                        
                        if (auto nextState = selectCase->state->to<P4::IR::PathExpression>()) {
                            P4::cstring nextStateName = nextState->path->name;
                            
                            if (selectCase->keyset->is<P4::IR::DefaultExpression>()) {
                                extracted.transitions[P4::cstring("default")] = nextStateName;
                            } else {
                                // Try to resolve constant value
                                P4::cstring condition;
                                uint64_t numericValue = 0;
                                bool hasNumericValue = false;
                                
                                if (auto constant = selectCase->keyset->to<P4::IR::Constant>()) {
                                    numericValue = constant->asUint64();
                                    hasNumericValue = true;
                                    condition = selectCase->keyset->toString();
                                } else if (auto path = selectCase->keyset->to<P4::IR::PathExpression>()) {
                                    P4::cstring constName = path->path->name;
                                    condition = constName;

                                    // Resolve named constants
                                    for (auto obj : program->objects) {
                                        if (auto decl = obj->to<P4::IR::Declaration_Constant>()) {
                                            if (decl->name == constName) {
                                                if (auto initConst = decl->initializer->to<P4::IR::Constant>()) {
                                                    numericValue = initConst->asUint64();
                                                    hasNumericValue = true;
                                                }
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    condition = selectCase->keyset->toString();
                                }

                                extracted.transitions[condition] = nextStateName;

                                // Store numeric ethertype for custom headers (> 0x0800)
                                if (hasNumericValue && numericValue > 0x0800) {
                                    extracted.ethertypeValues[nextStateName] = numericValue;
                                }
                            }
                        }
                    }
                    } else if (auto path = state->selectExpression->to<P4::IR::PathExpression>()) {
                        P4::cstring nextStateName = path->path->name;
                        extracted.transitions[P4::cstring("always")] = nextStateName;
                    }
                }
                
                extractedStates.push_back(extracted);
            }
            
            if (!extractedStates.empty()) {
                SV::g_extractedParserStates[parser->name] = extractedStates;
            }
        }
    }

    if (SV::g_verbose) {
        std::cerr << "[Phase 1] Complete" << std::endl;
    }

    // -------------------------------------------------------------------------
    // Phase 2: Detect Control Flow Patterns
    // Scan for if-else statements that can be mapped to hardware
    // -------------------------------------------------------------------------
    if (SV::g_verbose) {
        std::cerr << "[Phase 2] Scanning for control flow patterns..." << std::endl;
    }

    int ifElseCount = 0;
    for (auto obj : program->objects) {
        if (auto control = obj->to<P4::IR::P4Control>()) {
            if (control->body) {
                scanForIfStatements(control->body, control->name, ifElseCount);
            }
        }
    }

    if (SV::g_verbose) {
        std::cerr << "[Phase 2] Complete (" << ifElseCount << " if-else statements detected)" << std::endl;
    }

    // -------------------------------------------------------------------------
    // Phase 3: Run Frontend (Type Checking & Semantic Analysis)
    // -------------------------------------------------------------------------
    if (SV::g_verbose) {
        std::cerr << "[Phase 3] Running frontend..." << std::endl;
    }
    
    SV::FrontEnd frontend;
    try {
        program = frontend.run(options, program);
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Frontend error: " << bug.what() << std::endl;
        return 1;
    }

    if (program == nullptr || P4::errorCount() > 0) {
        P4::error("Frontend processing failed");
        return 1;
    }

    if (SV::g_verbose) {
        std::cerr << "[Phase 3] Complete" << std::endl;
    }

    // -------------------------------------------------------------------------
    // Phase 4: Run Midend (IR Transformations & Optimizations)
    // -------------------------------------------------------------------------
    if (SV::g_verbose) {
        std::cerr << "[Phase 4] Running midend..." << std::endl;
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
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Midend error: " << bug.what() << std::endl;
        return 1;
    }

    if (toplevel == nullptr || P4::errorCount() > 0) {
        P4::error("Failed to create toplevel block");
        return 1;
    }

    if (SV::g_verbose) {
        std::cerr << "[Phase 4] Complete" << std::endl;
    }

    // -------------------------------------------------------------------------
    // Phase 5: Run Backend (SystemVerilog Code Generation)
    // -------------------------------------------------------------------------
    if (SV::g_verbose) {
        std::cerr << "[Phase 5] Running backend..." << std::endl;
    }

    SV::Backend backend(midend.refMap, midend.typeMap);
    try {
        backend.run(options, toplevel, midend.refMap, midend.typeMap);
    } catch (const P4::Util::P4CExceptionBase &bug) {
        std::cerr << "Backend error: " << bug.what() << std::endl;
        return 1;
    }

    if (SV::g_verbose) {
        std::cerr << "[Phase 5] Complete" << std::endl;
        std::cerr << "\nCompilation successful!" << std::endl;
    }

    return P4::errorCount() > 0 ? 1 : 0;
}