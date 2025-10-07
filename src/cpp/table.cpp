#include "common.h"
#include "table.h"
#include "control.h"
#include "program.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

bool SVTable::build() {
    std::cerr << "\n=== SVTable::build() called for table: " << tableName << " ===" << std::endl;
    
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
    
    std::cerr << "Table " << tableName << " built successfully" << std::endl;
    std::cerr << "  keyWidth=" << keyWidth << std::endl;
    std::cerr << "  tableSize=" << tableSize << std::endl;
    std::cerr << "  matchType=" << (int)matchType << std::endl;
    std::cerr << "=== End SVTable::build() ===" << std::endl << std::endl;
    
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
    // Default to EXACT
    matchType = MatchType::EXACT;
    
    std::cerr << "determineMatchType() for table: " << tableName << std::endl;
    
    auto keys = p4table->getKey();
    if (keys == nullptr) {
        std::cerr << "  No keys found, using EXACT" << std::endl;
        return;
    }
    
    if (keys->keyElements.empty()) {
        std::cerr << "  No key elements, using EXACT" << std::endl;
        return;
    }
    
    std::cerr << "  Found " << keys->keyElements.size() << " key elements" << std::endl;
    
    // Check each key element for match type
    for (auto keyElement : keys->keyElements) {
        auto key = keyElement->to<IR::KeyElement>();
        if (!key) {
            std::cerr << "  Warning: keyElement is not a KeyElement" << std::endl;
            continue;
        }
        
        if (!key->matchType) {
            std::cerr << "  Warning: key has no matchType" << std::endl;
            continue;
        }
        
        // Get the match type as a path expression
        std::cerr << "  Key matchType node type: " << key->matchType->node_type_name() << std::endl;
        
        // The matchType is a PathExpression pointing to the match kind
        if (auto pathExpr = key->matchType->to<IR::PathExpression>()) {
            cstring matchKindName = pathExpr->path->name;
            std::cerr << "  Match kind name: " << matchKindName << std::endl;
            
            if (matchKindName == "lpm") {
                matchType = MatchType::LPM;
                std::cerr << "  Detected LPM match type!" << std::endl;
                break;
            } else if (matchKindName == "ternary") {
                matchType = MatchType::TERNARY;
                std::cerr << "  Detected TERNARY match type!" << std::endl;
                break;
            } else if (matchKindName == "range") {
                matchType = MatchType::RANGE;
                std::cerr << "  Detected RANGE match type!" << std::endl;
            } else if (matchKindName == "exact") {
                std::cerr << "  Detected EXACT match type" << std::endl;
                // matchType already set to EXACT
            } else {
                std::cerr << "  Unknown match kind: " << matchKindName << std::endl;
            }
        } else {
            // Try as string (fallback)
            std::string matchKindStr = key->matchType->toString().string();
            std::cerr << "  Match kind string: " << matchKindStr << std::endl;
            
            if (matchKindStr.find("lpm") != std::string::npos) {
                matchType = MatchType::LPM;
                std::cerr << "  Detected LPM from string!" << std::endl;
                break;
            } else if (matchKindStr.find("ternary") != std::string::npos) {
                matchType = MatchType::TERNARY;
                std::cerr << "  Detected TERNARY from string!" << std::endl;
                break;
            } else if (matchKindStr.find("range") != std::string::npos) {
                matchType = MatchType::RANGE;
                std::cerr << "  Detected RANGE from string!" << std::endl;
            }
        }
    }
    
    std::cerr << "  Final match type: " << (int)matchType 
              << " (EXACT=0, LPM=1, TERNARY=2, RANGE=3)" << std::endl;
    
    LOG3("Table " << tableName << " match type: " << 
         (matchType == MatchType::LPM ? "LPM" :
          matchType == MatchType::TERNARY ? "TERNARY" :
          matchType == MatchType::RANGE ? "RANGE" : "EXACT"));
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
      
    std::cerr << "Emitting table " << tableName 
              << " with match type: " << (int)matchType 
              << " (LPM=" << (int)MatchType::LPM << ")" << std::endl;
    
    // Implementation based on match type
    switch (matchType) {
        case MatchType::EXACT:
            std::cerr << "  Using EXACT match implementation" << std::endl;
            emitExactMatchTable(builder);
            break;
        case MatchType::LPM:
            std::cerr << "  Using LPM implementation" << std::endl;
            emitLPMTable(builder);
            break;
        case MatchType::TERNARY:
            std::cerr << "  Using TERNARY implementation" << std::endl;
            emitTernaryTable(builder);
            break;
        default:
            std::cerr << "  Using default EXACT implementation" << std::endl;
            emitExactMatchTable(builder);
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
    builder->appendLine("// LPM (Longest Prefix Match) table implementation");
    builder->newline();
    
    // Memory arrays with prefix lengths
    builder->appendLine("// Table storage with prefix lengths");
    builder->appendLine("logic [KEY_WIDTH-1:0]    table_keys    [0:TABLE_SIZE-1];");
    builder->appendLine("logic [5:0]              table_prefix_len [0:TABLE_SIZE-1];");
    builder->appendLine("logic [7:0]              table_actions [0:TABLE_SIZE-1];");
    builder->appendLine("logic [ACTION_WIDTH-1:0] table_data    [0:TABLE_SIZE-1];");
    builder->appendLine("logic                    table_valid   [0:TABLE_SIZE-1];");
    builder->newline();
    
    // Initialize table
    builder->appendLine("// Initialize table");
    builder->appendLine("initial begin");
    builder->increaseIndent();
    builder->appendLine("for (int i = 0; i < TABLE_SIZE; i++) begin");
    builder->increaseIndent();
    builder->appendLine("table_valid[i] = 1'b0;");
    builder->appendLine("table_prefix_len[i] = 6'd0;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    // LPM lookup logic
    builder->appendLine("// LPM lookup");
    builder->appendLine("integer i;");
    builder->appendLine("logic [5:0] best_match_len;");
    builder->appendLine("logic [7:0] best_action_id;");
    builder->appendLine("logic [ACTION_WIDTH-1:0] best_action_data;");
    builder->appendLine("logic found_match;");
    builder->appendLine("logic [KEY_WIDTH-1:0] mask;");
    builder->newline();
    
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
    
    builder->appendLine("best_match_len = 6'd0;");
    builder->appendLine("best_action_id = 8'd0;");
    builder->appendLine("best_action_data = '0;");
    builder->appendLine("found_match = 1'b0;");
    builder->newline();
    
    builder->appendLine("for (i = 0; i < TABLE_SIZE; i = i + 1) begin");
    builder->increaseIndent();
    builder->appendLine("if (table_valid[i]) begin");
    builder->increaseIndent();
    
    builder->appendLine("// Create mask for prefix length");
    builder->appendLine("mask = (table_prefix_len[i] == 6'd32) ? '1 : ('1 << (32 - table_prefix_len[i]));");
    builder->newline();
    
    builder->appendLine("// Check if prefix matches and is longer than current best");
    builder->appendLine("if (((lookup_key[31:0] & mask) == (table_keys[i][31:0] & mask)) &&");
    builder->appendLine("    (table_prefix_len[i] >= best_match_len)) begin");
    builder->increaseIndent();
    builder->appendLine("best_match_len = table_prefix_len[i];");
    builder->appendLine("best_action_id = table_actions[i];");
    builder->appendLine("best_action_data = table_data[i];");
    builder->appendLine("found_match = 1'b1;");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    builder->appendLine("hit <= found_match;");
    builder->appendLine("action_id <= best_action_id;");
    builder->appendLine("action_data <= best_action_data;");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    builder->appendLine("assign lookup_ready = 1'b1;");
}

void SVTable::emitTernaryTable(CodeBuilder* builder) {
    builder->appendLine("// Ternary (TCAM) table implementation");
    builder->appendLine("// TODO: Implement TCAM logic with masks");
    builder->newline();
    emitExactMatchTable(builder);  // Fallback to exact for now
}

}  // namespace SV