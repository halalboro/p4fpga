#include "common.h"
#include "control.h"
#include "table.h"
#include "action.h"
#include "analyzer.h"
#include "lib/log.h"
#include "bsvprogram.h"
#include <sstream>

namespace SV {

// Constructor implementation
SVControl::SVControl(SVProgram* program,
                     const IR::ControlBlock* block,
                     const TypeMap* typeMap,
                     const ReferenceMap* refMap) :
    program(program), 
    controlBlock(block), 
    typeMap(typeMap), 
    refMap(refMap),
    totalStages(0),
    cfg(nullptr) {
    
    if (block && block->container) {
        p4control = block->container;
        controlName = p4control->name;
        isIngress = (controlName.string().find("ingress") != std::string::npos ||
                    controlName.string().find("Ingress") != std::string::npos);
    } else {
        controlName = cstring("unknown");
        isIngress = false;
        P4::error("SVControl created with invalid control block");
    }
}

// Destructor
SVControl::~SVControl() {
    // Clean up allocated memory
    for (auto& p : svTables) {
        delete p.second;
    }
    for (auto& p : svActions) {
        delete p.second;
    }
    for (auto stage : pipelineStages) {
        delete stage;
    }
    if (cfg) {
        delete cfg;
    }
}

bool SVControl::build() {
    LOG1("Building control block: " << controlName);
    
    if (!controlBlock || !controlBlock->container) {
        LOG1("Warning: Invalid control block, using empty control");
        cfg = new ControlFlowGraph();
        totalStages = 0;
        return true;
    }
    
    extractTables();
    extractActions();
    
    
    cfg = new ControlFlowGraph();
    LOG1("Note: Skipping CFG analysis due to incomplete IR");
    
    analyzePipeline();
    assignPipelineStages();
    
    LOG1("Control block " << controlName << " built successfully");
    return true;
}

void SVControl::emitIfStatement(CodeBuilder* builder, const IR::IfStatement* ifStmt) {
    if (!ifStmt) return;
    
    std::stringstream ss;
    
    // Determine which stage this condition applies to
    int stageNum = 0;  // For now, assume stage 0
    
    // Translate the condition
    std::string condition = translateCondition(ifStmt->condition, stageNum);
    
    builder->appendLine("// Conditional execution");
    ss.str("");
    ss << "if (" << condition << ") begin";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    // The table lookup is already handled by table instances,
    // but we need to gate it with the condition
    builder->appendLine("// Enable table lookup only if condition is true");
    builder->appendLine("// This would require modifying table lookup_valid signal");
    
    builder->decreaseIndent();
    builder->appendLine("end");
}

std::string SVControl::translateCondition(const IR::Expression* condition, int stageNum) {
    std::stringstream ss;
    
    if (!condition) {
        return "1'b1";  // Always true as default
    }
    
    // Check for isValid() method call
    if (auto methodCall = condition->to<IR::MethodCallExpression>()) {
        auto methodName = methodCall->method->toString().string();
        if (methodName.find("isValid") != std::string::npos) {
            // Extract what header we're checking
            if (methodCall->method->is<IR::Member>()) {
                auto member = methodCall->method->to<IR::Member>();
                if (member->expr->is<IR::Member>()) {
                    auto parent = member->expr->to<IR::Member>();
                    // hdr.ipv4.isValid() pattern
                    ss << "stage" << stageNum << "_headers." 
                       << parent->member.toString() << "_valid";
                    return ss.str();
                }
            }
        }
    }
    
    // Default
    return "1'b1";
}

void SVControl::extractTables() {
    if (!controlBlock || !controlBlock->container) {
        LOG1("Warning: Invalid control block in extractTables");
        return;
    }
    
    // Extract all tables from the control block
    for (auto decl : p4control->controlLocals) {
        if (auto table = decl->to<IR::P4Table>()) {
            std::cerr << "Found table in control: " << table->name << std::endl;
            
            auto svTable = new SVTable(this, table);
            
            std::cerr << "Calling svTable->build() for " << table->name << std::endl;
            svTable->build();
            std::cerr << "After build, matchType = " << (int)svTable->getMatchType() << std::endl;
            
            svTables[table->name] = svTable;  
        }
    }
    
    // Track table-action relationships
    for (auto& p : svTables) {  
        auto tableName = p.first;
        auto svTable = p.second;
        auto p4table = svTable->getP4Table();
        
        if (p4table && p4table->getActionList()) {
            for (auto actionElem : p4table->getActionList()->actionList) {
                if (auto elem = actionElem->to<IR::ActionListElement>()) {
                    if (elem->expression) {
                        if (auto method = elem->expression->to<IR::MethodCallExpression>()) {
                            if (method->method) {
                                auto actionName = method->method->toString();
                                action_to_table[actionName].insert(tableName);
                            }
                        } else if (auto path = elem->expression->to<IR::PathExpression>()) {
                            if (path->path) {
                                auto actionName = path->path->name;
                                action_to_table[actionName].insert(tableName);
                            }
                        }
                    }
                }
            }
        }
    }
    
    LOG1("Extracted " << svTables.size() << " tables");
}

void SVControl::extractActions() {
    std::cerr << "Extracting actions from control: " << controlName << std::endl;
    
    if (!p4control) {
        LOG1("Warning: No P4Control in extractActions");
        return;
    }
    
    // Extract all actions from the control block
    for (auto decl : p4control->controlLocals) {
        if (auto action = decl->to<IR::P4Action>()) {
            std::cerr << "  Found action: " << action->name << std::endl;
            
            auto svAction = new SVAction(this, action);
            
            // SET TypeMap before building
            svAction->setTypeMap(typeMap);
            svAction->build();
            
            svActions[action->name] = svAction;
            
            // Debug: print parameters
            std::cerr << "    Parameters: " << action->parameters->parameters.size() << std::endl;
            for (auto param : action->parameters->parameters) {
                std::cerr << "      - " << param->name << " : ";
                if (param->type) {
                    std::cerr << param->type->toString();
                }
                std::cerr << std::endl;
            }
        }
    }
    
    LOG1("Extracted " << svActions.size() << " actions");
}

void SVControl::analyzePipeline() {
    // Analyze dependencies and determine pipeline stages
    // Simplified: each table gets its own stage for now
    totalStages = svTables.size();
    if (totalStages == 0) {
        totalStages = 1;  // At least one stage for pass-through
    }
    LOG1("Control " << controlName << " has " << totalStages << " pipeline stages");
}

void SVControl::assignPipelineStages() {
    // Assign tables to pipeline stages
    // Simplified: sequential assignment
    int stageNum = 0;
    for (auto& p : svTables) {
        auto name = p.first;
        auto svTable = p.second;
        
        auto stage = new PipelineStage(stageNum++);
        stage->tables.push_back(svTable);
        
        // Add associated actions
        auto p4table = svTable->getP4Table();
        if (p4table) {
            auto actionList = p4table->getActionList();
            if (actionList) {
                for (auto action : actionList->actionList) {
                    if (auto elem = action->to<IR::ActionListElement>()) {
                        if (elem->expression) {
                            cstring actionName;
                            
                            if (auto method = elem->expression->to<IR::MethodCallExpression>()) {
                                if (method->method) {
                                    actionName = method->method->toString();
                                }
                            } else if (auto path = elem->expression->to<IR::PathExpression>()) {
                                if (path->path) {
                                    actionName = path->path->name;
                                }
                            }
                            
                            if (actionName && svActions.count(actionName)) {
                                auto svAction = svActions[actionName];
                                // IMPORTANT: Set the table association
                                svAction->setAssociatedTable(name);
                                stage->actions.push_back(svAction);
                            }
                        }
                    }
                }
            }
        }
        
        pipelineStages.push_back(stage);
    }
    
    LOG1("Assigned " << pipelineStages.size() << " pipeline stages");
}

void SVControl::emit(SVCodeGen& codegen) {
    CodeBuilder* builder = isIngress ? 
        codegen.getIngressBuilder() : 
        codegen.getEgressBuilder();
    
    emitModule(builder);
}

void SVControl::emitModule(CodeBuilder* builder) {
    std::stringstream ss;
    
    // Module header
    builder->appendLine("//");
    ss << "// " << (isIngress ? "Ingress" : "Egress") << " Pipeline Module";
    builder->appendLine(ss.str());
    builder->appendLine("//");
    builder->newline();
    
    builder->appendLine("`include \"types.svh\"");
    builder->newline();
    
    // Module declaration
    ss.str("");
    ss << "module " << (isIngress ? "ingress" : "egress") << "_pipeline #(";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    builder->appendLine("parameter DATA_WIDTH = 512");
    builder->decreaseIndent();
    builder->appendLine(") (");
    builder->increaseIndent();
    
    // Clock and reset
    builder->appendLine("input  logic                      clk,");
    builder->appendLine("input  logic                      rst_n,");
    builder->newline();
    
    // Input interface
    builder->appendLine("// Input from previous stage");
    builder->appendLine("input  headers_t                  in_headers,");
    builder->appendLine("input  metadata_t                 in_metadata,");
    builder->appendLine("input  logic                      in_valid,");
    builder->appendLine("output logic                      in_ready,");
    builder->newline();
    
    // Output interface
    builder->appendLine("// Output to next stage");
    builder->appendLine("output headers_t                  out_headers,");
    builder->appendLine("output metadata_t                 out_metadata,");
    builder->appendLine("output logic                      out_valid,");
    builder->appendLine("input  logic                      out_ready");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Pipeline registers
    emitPipelineRegisters(builder);
    builder->newline();
    
    // Table instances
    emitTableInstances(builder);
    builder->newline();
    
    // Action logic
    emitActionLogic(builder);
    builder->newline();
    
    // Control flow
    emitControlFlow(builder);
    
    builder->appendLine("endmodule");
}

void SVControl::emitPipelineRegisters(CodeBuilder* builder) {
    std::stringstream ss;
    builder->appendLine("// Pipeline stage registers");
    
    for (int i = 0; i <= totalStages; i++) {
        ss.str("");
        ss << "headers_t   stage" << i << "_headers;";
        builder->appendLine(ss.str());
        
        ss.str("");
        ss << "metadata_t  stage" << i << "_metadata;";
        builder->appendLine(ss.str());
        
        ss.str("");
        ss << "logic       stage" << i << "_valid;";
        builder->appendLine(ss.str());
        
        ss.str("");
        ss << "logic       stage" << i << "_ready;";
        builder->appendLine(ss.str());
        
        if (i < totalStages) {
            builder->newline();
        }
    }
    
    builder->newline();
    builder->appendLine("// Connect input to stage 0");
    builder->appendLine("assign stage0_headers = in_headers;");
    builder->appendLine("assign stage0_metadata = in_metadata;");
    builder->appendLine("assign stage0_valid = in_valid;");
    builder->appendLine("assign in_ready = stage0_ready;");
    builder->newline();
    
    ss.str("");
    ss << "// Connect stage " << totalStages << " to output";
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "assign out_headers = stage" << totalStages << "_headers;";
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "assign out_metadata = stage" << totalStages << "_metadata;";
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "assign out_valid = stage" << totalStages << "_valid;";
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "assign stage" << totalStages << "_ready = out_ready;";
    builder->appendLine(ss.str());
    
    // Generate pipeline registers between stages if there are stages
    if (totalStages > 0) {
        builder->newline();
        builder->appendLine("// Pipeline registers");
        
        for (int i = 0; i < totalStages; i++) {
            ss.str("");
            ss << "// Stage " << i << " -> Stage " << (i+1);
            builder->appendLine(ss.str());
            
            builder->appendLine("always_ff @(posedge clk) begin");
            builder->increaseIndent();
            builder->appendLine("if (!rst_n) begin");
            builder->increaseIndent();
            
            ss.str("");
            ss << "stage" << (i+1) << "_valid <= 1'b0;";
            builder->appendLine(ss.str());
            
            builder->decreaseIndent();
            
            ss.str("");
            ss << "end else if (stage" << (i+1) << "_ready) begin";
            builder->appendLine(ss.str());
            builder->increaseIndent();
            
            ss.str("");
            ss << "stage" << (i+1) << "_headers <= stage" << i << "_headers;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "stage" << (i+1) << "_metadata <= stage" << i << "_metadata;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "stage" << (i+1) << "_valid <= stage" << i << "_valid;";
            builder->appendLine(ss.str());
            
            builder->decreaseIndent();
            builder->appendLine("end");
            builder->decreaseIndent();
            builder->appendLine("end");
            builder->newline();
            
            // Ready signal flows backward
            ss.str("");
            ss << "assign stage" << i << "_ready = stage" << (i+1) << "_ready || !stage" << (i+1) << "_valid;";
            builder->appendLine(ss.str());
            
            if (i < totalStages - 1) {
                builder->newline();
            }
        }
    }
}

void SVControl::emitTableInstances(CodeBuilder* builder) {
    if (svTables.empty()) {
        builder->appendLine("// No tables in this control block");
        return;
    }
    
    std::stringstream ss;
    builder->appendLine("// Table instances");
    
    int stageNum = 0;
    for (auto stage : pipelineStages) {
        for (auto svTable : stage->tables) {
            auto tableName = svTable->getName();
            
            ss.str("");
            ss << "// Table: " << tableName;
            builder->appendLine(ss.str());
            
            // Table lookup signals
            ss.str("");
            ss << "logic [" << (svTable->getKeyWidth()-1) << ":0] table_" << tableName << "_key;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "logic table_" << tableName << "_key_valid;";
            builder->appendLine(ss.str());
            
            // ADD: Conditional lookup signal
            ss.str("");
            ss << "logic table_" << tableName << "_enable;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "logic table_" << tableName << "_hit;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "logic [7:0] table_" << tableName << "_action_id;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "logic [" << (svTable->getActionDataWidth()-1) << ":0] table_" << tableName << "_action_data;";
            builder->appendLine(ss.str());
            builder->newline();
            
            // ADD: Table enable logic based on control flow
            builder->appendLine("// Table enable logic based on control flow");
            builder->appendLine("always_comb begin");
            builder->increaseIndent();
            
            // Check if this is the ipv4_lpm table that needs IPv4 validity check
            if (tableName == "ipv4_lpm") {
                ss.str("");
                ss << "table_" << tableName << "_enable = stage" << stageNum 
                   << "_headers.ipv4_valid && stage" << stageNum << "_valid;";
                builder->appendLine(ss.str());
            } else {
                ss.str("");
                ss << "table_" << tableName << "_enable = stage" << stageNum << "_valid;";
                builder->appendLine(ss.str());
            }
            
            builder->decreaseIndent();
            builder->appendLine("end");
            builder->newline();
            
            // Table module instance
            ss.str("");
            ss << "table_" << tableName << " table_" << tableName << "_inst (";
            builder->appendLine(ss.str());
            builder->increaseIndent();
            
            builder->appendLine(".clk(clk),");
            builder->appendLine(".rst_n(rst_n),");
            
            ss.str("");
            ss << ".lookup_key(table_" << tableName << "_key),";
            builder->appendLine(ss.str());
            
            // MODIFIED: Use the conditional enable signal
            ss.str("");
            ss << ".lookup_valid(table_" << tableName << "_enable),";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << ".lookup_ready(stage" << (stageNum+1) << "_ready),";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << ".hit(table_" << tableName << "_hit),";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << ".action_id(table_" << tableName << "_action_id),";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << ".action_data(table_" << tableName << "_action_data)";
            builder->appendLine(ss.str());
            
            builder->decreaseIndent();
            builder->appendLine(");");
            builder->newline();
            
            // Key extraction from headers/metadata
            ss.str("");
            ss << "// Extract key for table " << tableName;
            builder->appendLine(ss.str());
            
            builder->appendLine("always_comb begin");
            builder->increaseIndent();
            
            ss.str("");
            ss << "table_" << tableName << "_key = '0;";
            builder->appendLine(ss.str());
            
            // Generate key extraction based on table keys
            auto p4table = svTable->getP4Table();
            if (p4table) {
                auto keys = p4table->getKey();
                if (keys != nullptr && keys->keyElements.size() > 0) {
                    int offset = 0;
                    for (auto key : keys->keyElements) {
                        auto element = key->to<IR::KeyElement>();
                        if (element && element->expression) {
                            if (auto member = element->expression->to<IR::Member>()) {
                                // Check if it's a nested member (e.g., headers.ipv4.dstAddr)
                                std::string fieldPath;
                                if (member->expr->is<IR::Member>()) {
                                    auto parent = member->expr->to<IR::Member>();
                                    fieldPath = parent->member.toString() + "." + member->member.toString();
                                } else {
                                    fieldPath = member->member.toString();
                                }
                                
                                ss.str("");
                                ss << "table_" << tableName << "_key[" << (offset+31) << ":" << offset 
                                   << "] = stage" << stageNum << "_headers." << fieldPath << ";";
                                builder->appendLine(ss.str());
                                offset += 32;
                            }
                        }
                    }
                } else {
                    builder->appendLine("// No keys defined for this table");
                }
            }
            
            builder->decreaseIndent();
            builder->appendLine("end");
            builder->newline();
        }
        stageNum++;
    }
}

void SVControl::emitActionLogic(CodeBuilder* builder) {
    if (svTables.empty()) {
        builder->appendLine("// No pipeline stages to emit actions for");
        return;
    }
    
    builder->appendLine("// Action execution logic");
    
    int stageNum = 0;
    for (auto stage : pipelineStages) {
        for (auto svTable : stage->tables) {
            auto tableName = svTable->getName();
            
            std::stringstream ss;
            ss << "// Actions for table " << tableName;
            builder->appendLine(ss.str());
            
            builder->appendLine("always_comb begin");
            builder->increaseIndent();
            
            // Default: pass through from previous stage to next stage
            ss.str("");
            ss << "stage" << (stageNum+1) << "_headers = stage" << stageNum << "_headers;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "stage" << (stageNum+1) << "_metadata = stage" << stageNum << "_metadata;";
            builder->appendLine(ss.str());
            builder->newline();
            
            // Apply actions based on table hit
            ss.str("");
            ss << "if (table_" << tableName << "_hit) begin";
            builder->appendLine(ss.str());
            builder->increaseIndent();
            
            ss.str("");
            ss << "case (table_" << tableName << "_action_id)";
            builder->appendLine(ss.str());
            builder->increaseIndent();
            
            // Get action list from table
            auto actionList = svTable->getActionList();
            if (actionList) {
                int actionIndex = 0;
                for (auto actionElem : actionList->actionList) {
                    if (auto elem = actionElem->to<IR::ActionListElement>()) {
                        cstring actionName;
                        
                        if (auto path = elem->expression->to<IR::PathExpression>()) {
                            actionName = path->path->name;
                        } else if (auto method = elem->expression->to<IR::MethodCallExpression>()) {
                            actionName = method->method->toString();
                        }
                        
                        if (actionName && svActions.count(actionName)) {
                            auto svAction = svActions[actionName];
                            
                            // Emit the action case
                            ss.str("");
                            ss << "8'd" << actionIndex << ": begin  // " << actionName;
                            builder->appendLine(ss.str());
                            builder->increaseIndent();
                            
                            // FIX: Use emitExecute() instead of emit()
                            // Pass the stage prefix (e.g., "stage0")
                            ss.str("");
                            ss << "stage" << stageNum;
                            svAction->emitExecute(builder, ss.str());
                            
                            builder->decreaseIndent();
                            builder->appendLine("end");
                        } else {
                            ss.str("");
                            ss << "8'd" << actionIndex << ": begin  // " << actionName;
                            builder->appendLine(ss.str());
                            builder->increaseIndent();
                            builder->appendLine("// Action not found");
                            builder->decreaseIndent();
                            builder->appendLine("end");
                        }
                        
                        actionIndex++;
                    }
                }
            }
            
            builder->appendLine("default: begin");
            builder->increaseIndent();
            builder->appendLine("// No action");
            builder->decreaseIndent();
            builder->appendLine("end");
            
            builder->decreaseIndent();
            builder->appendLine("endcase");
            
            builder->decreaseIndent();
            builder->appendLine("end");
            
            builder->decreaseIndent();
            builder->appendLine("end");
            builder->newline();
        }
        stageNum++;
    }
    
    builder->newline();
}

void SVControl::emitControlFlow(CodeBuilder* builder) {
    builder->appendLine("// Control flow logic");
    
    if (!controlBlock || !controlBlock->container || !controlBlock->container->body) {
        builder->appendLine("// No control flow to implement");
        return;
    }
    
    std::stringstream ss;
    
    // Parse the apply block to extract control flow
    auto body = controlBlock->container->body;
    
    // For each statement in the body, generate appropriate control logic
    for (auto stmt : body->components) {
        if (auto ifStmt = stmt->to<IR::IfStatement>()) {
            emitIfStatement(builder, ifStmt);
        } else if (auto methodCall = stmt->to<IR::MethodCallStatement>()) {
            // Check if it's a table.apply()
            if (auto expr = methodCall->methodCall) {
                auto method = expr->method->toString().string();
                if (method.find("apply") != std::string::npos) {
                    // This is handled by table instances already
                    builder->appendLine("// Table apply handled by table instance");
                }
            }
        }
    }
}

}  // namespace SV