#include "common.h"
#include "table.h"
#include "control.h"
#include "program.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

bool SVTable::build() {
    LOG2("Building table: " << tableName);
    
    extractKeys();
    extractActions();
    determineMatchType();
    
    // Get table size from properties
    if (p4table->properties) {
        for (auto prop : p4table->properties->properties) {
            if (prop->name == "size") {
                if (auto expr = prop->value->to<IR::ExpressionValue>()) {
                    if (auto constant = expr->expression->to<IR::Constant>()) {
                        tableSize = constant->asInt();
                    }
                }
            }
        }
    }
    
    // Calculate action data width (simplified)
    actionDataWidth = 64;  // Default, should calculate from action parameters
    
    LOG2("Table " << tableName << " built: keyWidth=" << keyWidth 
         << " tableSize=" << tableSize);
    
    return true;
}

void SVTable::extractKeys() {
    auto keys = p4table->getKey();
    if (keys != nullptr) {
        for (auto key : keys->keyElements) {
            auto element = key->to<IR::KeyElement>();
            if (element && element->expression->is<IR::Member>()) {
                auto member = element->expression->to<IR::Member>();
                auto type = control->getProgram()->typeMap->getType(member, true);
                
                int fieldSize = 32;  // Default
                if (type && type->template is<IR::Type_Bits>()) {
                    fieldSize = type->template to<IR::Type_Bits>()->size;
                }
                
                // Store field info
                keyFields.push_back(std::make_pair(nullptr, fieldSize));
                keyWidth += fieldSize;
            }
        }
    }
    LOG3("Table " << tableName << " key width: " << keyWidth);
}

void SVTable::extractActions() {
    auto actionList = p4table->getActionList();
    if (actionList && actionList->actionList.size() > 0) {
        for (auto action : actionList->actionList) {
            if (auto elem = action->to<IR::ActionListElement>()) {
                if (auto expr = elem->expression->to<IR::MethodCallExpression>()) {
                    auto actionName = expr->method->toString();
                    actionNames.push_back(actionName);
                    LOG3("Table " << tableName << " action: " << actionName);
                } else if (auto path = elem->expression->to<IR::PathExpression>()) {
                    auto actionName = path->path->name;
                    actionNames.push_back(actionName);
                    LOG3("Table " << tableName << " action: " << actionName);
                }
            }
        }
    }
    
    // Get default action
    if (p4table->getDefaultAction()) {
        defaultAction = cstring("NoAction");  // Simplified
    }
}

void SVTable::determineMatchType() {
    auto keys = p4table->getKey();
    if (keys != nullptr && !keys->keyElements.empty()) {
        auto firstKey = keys->keyElements.at(0)->to<IR::KeyElement>();
        if (firstKey && firstKey->matchType) {
            auto matchKind = firstKey->matchType->toString().string();
            
            if (matchKind.find("exact") != std::string::npos) {
                matchType = MatchType::EXACT;
            } else if (matchKind.find("lpm") != std::string::npos) {
                matchType = MatchType::LPM;
            } else if (matchKind.find("ternary") != std::string::npos) {
                matchType = MatchType::TERNARY;
            } else if (matchKind.find("range") != std::string::npos) {
                matchType = MatchType::RANGE;
            }
        }
    }
    LOG3("Table " << tableName << " match type: " << static_cast<int>(matchType));
}

void SVTable::emit(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("//");
    ss << "// Table: " << tableName;
    builder->appendLine(ss.str());
    builder->appendLine("//");
    builder->newline();
    
    ss.str("");
    ss << "module table_" << tableName << " #(";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    ss.str("");
    ss << "parameter KEY_WIDTH = " << getKeyWidth() << ",";
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "parameter ACTION_WIDTH = " << getActionDataWidth() << ",";
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "parameter TABLE_SIZE = " << tableSize;
    builder->appendLine(ss.str());
    
    builder->decreaseIndent();
    builder->appendLine(") (");
    builder->increaseIndent();
    
    // Interface
    builder->appendLine("input  logic                      clk,");
    builder->appendLine("input  logic                      rst_n,");
    builder->newline();
    builder->appendLine("// Lookup interface");
    builder->appendLine("input  logic [KEY_WIDTH-1:0]     lookup_key,");
    builder->appendLine("input  logic                      lookup_valid,");
    builder->appendLine("output logic                      lookup_ready,");
    builder->newline();
    builder->appendLine("// Result interface");
    builder->appendLine("output logic                      hit,");
    builder->appendLine("output logic [7:0]                action_id,");
    builder->appendLine("output logic [ACTION_WIDTH-1:0]  action_data");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
    
    // Implementation based on match type
    switch (matchType) {
        case MatchType::EXACT:
            emitExactMatchTable(builder);
            break;
        case MatchType::LPM:
            emitLPMTable(builder);
            break;
        case MatchType::TERNARY:
            emitTernaryTable(builder);
            break;
        default:
            emitExactMatchTable(builder);  // Default to exact
    }
    
    builder->appendLine("endmodule");
}

void SVTable::emitExactMatchTable(CodeBuilder* builder) {
    builder->appendLine("// Exact match table implementation");
    builder->newline();
    
    // Memory arrays
    builder->appendLine("// Table storage");
    builder->appendLine("logic [KEY_WIDTH-1:0]    table_keys    [0:TABLE_SIZE-1];");
    builder->appendLine("logic [7:0]              table_actions [0:TABLE_SIZE-1];");
    builder->appendLine("logic [ACTION_WIDTH-1:0] table_data    [0:TABLE_SIZE-1];");
    builder->appendLine("logic                    table_valid   [0:TABLE_SIZE-1];");
    builder->newline();
    
    // Initialize table
    builder->appendLine("// Initialize table (should be filled by control plane)");
    builder->appendLine("initial begin");
    builder->increaseIndent();
    builder->appendLine("for (int i = 0; i < TABLE_SIZE; i++) begin");
    builder->increaseIndent();
    builder->appendLine("table_valid[i] = 1'b0;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    // Lookup logic
    builder->appendLine("// Parallel lookup (simplified - real design would use CAM)");
    builder->appendLine("integer i;");
    builder->appendLine("always_ff @(posedge clk) begin");
    builder->increaseIndent();
    builder->appendLine("if (!rst_n) begin");
    builder->increaseIndent();
    builder->appendLine("hit <= 1'b0;");
    builder->appendLine("action_id <= 8'b0;");
    builder->appendLine("action_data <= '0;");
    builder->decreaseIndent();
    builder->appendLine("end else if (lookup_valid) begin");
    builder->increaseIndent();
    builder->appendLine("hit <= 1'b0;");
    builder->appendLine("for (i = 0; i < TABLE_SIZE; i = i + 1) begin");
    builder->increaseIndent();
    builder->appendLine("if (table_valid[i] && table_keys[i] == lookup_key) begin");
    builder->increaseIndent();
    builder->appendLine("hit <= 1'b1;");
    builder->appendLine("action_id <= table_actions[i];");
    builder->appendLine("action_data <= table_data[i];");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    builder->appendLine("// Always ready (no backpressure for now)");
    builder->appendLine("assign lookup_ready = 1'b1;");
}

void SVTable::emitLPMTable(CodeBuilder* builder) {
    builder->appendLine("// LPM table implementation");
    builder->appendLine("// TODO: Implement longest prefix matching logic");
    builder->newline();
    emitExactMatchTable(builder);  // Fallback to exact for now
}

void SVTable::emitTernaryTable(CodeBuilder* builder) {
    builder->appendLine("// Ternary (TCAM) table implementation");
    builder->appendLine("// TODO: Implement TCAM logic with masks");
    builder->newline();
    emitExactMatchTable(builder);  // Fallback to exact for now
}

}  // namespace SV