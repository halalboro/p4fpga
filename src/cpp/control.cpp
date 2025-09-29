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
    totalStages(0) {
    
    p4control = block->container;
    controlName = p4control->name;
    isIngress = (controlName.string().find("ingress") != std::string::npos);
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
}

bool SVControl::build() {
    LOG1("Building control block: " << controlName);
    
    // Extract tables and actions from IR
    extractTables();
    extractActions();
    
    // Build control flow graph
    ControlGraphBuilder cgBuilder;
    controlBlock->container->body->apply(cgBuilder);
    cfg = cgBuilder.cfg;
    
    // Analyze pipeline and assign stages
    analyzePipeline();
    assignPipelineStages();
    
    return true;
}

void SVControl::extractTables() {
    // Extract all tables from the control block
    for (auto decl : controlBlock->container->controlLocals) {
        if (auto table = decl->to<IR::P4Table>()) {
            auto svTable = new SVTable(this, table);
            svTables[table->name] = svTable;
            LOG2("Found table: " << table->name);
            
            // Track table-action relationships
            for (auto action : table->getActionList()->actionList) {
                if (auto elem = action->to<IR::ActionListElement>()) {
                    if (auto method = elem->expression->to<IR::MethodCallExpression>()) {
                        auto actionName = method->method->toString();
                        action_to_table[actionName].insert(table->name);
                    }
                }
            }
        }
    }
}

void SVControl::extractActions() {
    // Extract all actions from the control block
    for (auto decl : controlBlock->container->controlLocals) {
        if (auto action = decl->to<IR::P4Action>()) {
            auto svAction = new SVAction(this, action);
            svActions[action->name] = svAction;
            LOG2("Found action: " << action->name);
        }
    }
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
        for (auto action : p4table->getActionList()->actionList) {
            if (auto elem = action->to<IR::ActionListElement>()) {
                if (auto method = elem->expression->to<IR::MethodCallExpression>()) {
                    auto actionName = method->method->toString();
                    if (svActions.count(actionName)) {
                        stage->actions.push_back(svActions[actionName]);
                    }
                }
            }
        }
        
        pipelineStages.push_back(stage);
    }
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
        builder->newline();
    }
    
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
    builder->newline();
    
    // Generate pipeline registers between stages
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
        builder->newline();
    }
}

void SVControl::emitTableInstances(CodeBuilder* builder) {
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
            
            ss.str("");
            ss << ".lookup_valid(stage" << stageNum << "_valid),";
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
            auto keys = p4table->getKey();
            if (keys != nullptr) {
                int offset = 0;
                for (auto key : keys->keyElements) {
                    auto element = key->to<IR::KeyElement>();
                    if (element && element->expression->is<IR::Member>()) {
                        auto member = element->expression->to<IR::Member>();
                        // Simplified: assume key comes from headers
                        ss.str("");
                        ss << "table_" << tableName << "_key[" << (offset+31) << ":" << offset 
                           << "] = stage" << stageNum << "_headers." << member->member << ";";
                        builder->appendLine(ss.str());
                        offset += 32;  // Simplified: assume 32-bit fields
                    }
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
    std::stringstream ss;
    builder->appendLine("// Action execution logic");
    
    int stageNum = 0;
    for (auto stage : pipelineStages) {
        for (auto svTable : stage->tables) {
            auto tableName = svTable->getName();
            
            ss.str("");
            ss << "// Actions for table " << tableName;
            builder->appendLine(ss.str());
            
            builder->appendLine("always_comb begin");
            builder->increaseIndent();
            
            // Default: pass through
            ss.str("");
            ss << "stage" << (stageNum+1) << "_headers = stage" << stageNum << "_headers;";
            builder->appendLine(ss.str());
            
            ss.str("");
            ss << "stage" << (stageNum+1) << "_metadata = stage" << stageNum << "_metadata;";
            builder->appendLine(ss.str());
            builder->newline();
            
            ss.str("");
            ss << "if (table_" << tableName << "_hit) begin";
            builder->appendLine(ss.str());
            builder->increaseIndent();
            
            ss.str("");
            ss << "case (table_" << tableName << "_action_id)";
            builder->appendLine(ss.str());
            builder->increaseIndent();
            
            // Generate cases for each action
            int actionId = 0;
            for (auto svAction : stage->actions) {
                auto actionName = svAction->getName();
                
                ss.str("");
                ss << "8'd" << actionId << ": begin  // " << actionName;
                builder->appendLine(ss.str());
                builder->increaseIndent();
                
                ss.str("");
                ss << "// Execute action " << actionName;
                builder->appendLine(ss.str());
                
                // Action implementation would be called here
                // svAction->emitExecute(builder, "stage" + std::to_string(stageNum));
                
                builder->decreaseIndent();
                builder->appendLine("end");
                actionId++;
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
}

void SVControl::emitControlFlow(CodeBuilder* builder) {
    builder->appendLine("// Control flow logic");
    builder->appendLine("// TODO: Implement conditional execution based on metadata");
    builder->newline();
}

}  // namespace SV