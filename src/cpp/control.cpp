// control.cpp

#include "common.h"
#include "control.h"
#include "table.h"
#include "action.h"
#include "program.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

SVControl::SVControl(SVProgram* program,
                     const IR::ControlBlock* block,
                     const TypeMap* typeMap,
                     const ReferenceMap* refMap) :
    program(program), 
    controlBlock(block), 
    typeMap(typeMap), 
    refMap(refMap),
    isIngress(false) {
    
    if (block && block->container) {
        p4control = block->container;
        controlName = p4control->name;
        isIngress = (controlName.string().find("ingress") != std::string::npos ||
                    controlName.string().find("Ingress") != std::string::npos);
    } else {
        p4control = nullptr;
        controlName = cstring("unknown");
    }
}

SVControl::~SVControl() {
    for (auto& p : svTables) {
        delete p.second;
    }
    for (auto& p : svActions) {
        delete p.second;
    }
}

bool SVControl::build() {
    LOG1("Building control block: " << controlName);
    
    if (!controlBlock || !controlBlock->container) {
        LOG1("Warning: Invalid control block, using empty control");
        return true;
    }
    
    extractTables();
    extractActions();
    
    LOG1("Control block " << controlName << " built successfully");
    return true;
}

void SVControl::extractTables() {
    if (!p4control) return;
    
    for (auto decl : p4control->controlLocals) {
        if (auto table = decl->to<IR::P4Table>()) {
            LOG2("Found table: " << table->name);
            
            auto svTable = new SVTable(this, table);
            svTable->build();
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
                    cstring actionName;
                    
                    if (auto path = elem->expression->to<IR::PathExpression>()) {
                        actionName = path->path->name;
                    } else if (auto method = elem->expression->to<IR::MethodCallExpression>()) {
                        actionName = method->method->toString();
                    }
                    
                    if (actionName) {
                        action_to_table[actionName].insert(tableName);
                    }
                }
            }
        }
    }
    
    LOG1("Extracted " << svTables.size() << " tables");
}

void SVControl::extractActions() {
    if (!p4control) return;
    
    for (auto decl : p4control->controlLocals) {
        if (auto action = decl->to<IR::P4Action>()) {
            LOG2("Found action: " << action->name);
            
            auto svAction = new SVAction(this, action);
            svAction->setTypeMap(typeMap);
            svAction->build();
            
            svActions[action->name] = svAction;
        }
    }
    
    LOG1("Extracted " << svActions.size() << " actions");
}

void SVControl::emit(SVCodeGen& codegen) {
    // Only emit for ingress (combine ingress+egress later if needed)
    if (!isIngress) {
        LOG1("Skipping emission for egress (will be combined with ingress)");
        return;
    }
    
    auto builder = codegen.getIngressBuilder();
    
    emitModuleHeader(builder);
    emitPortDeclarations(builder);
    emitInternalSignals(builder);
    emitTableStructDefinition(builder);
    emitTableStorage(builder);
    emitTableLookupLogic(builder);
    emitActionExecutionLogic(builder);
    emitChecksumUpdateLogic(builder);
    emitStatisticsCounters(builder);
    
    // CHANGED: Call simple control instead of AXI-Lite
    emitSimpleTableControl(builder);
    
    // Output assignments
    builder->appendLine("// Pipeline outputs");
    builder->appendLine("assign m_axis_tdata = data_d3;");
    builder->appendLine("assign m_axis_tvalid = valid_d3;");
    builder->appendLine("assign m_axis_tkeep = keep_d3;");
    builder->appendLine("assign m_axis_tlast = last_d3;");
    builder->appendLine("assign m_axis_drop = drop_d2;");
    builder->appendLine("assign m_axis_egress_port = egress_port_d2;");
    builder->newline();
    
    builder->appendLine("endmodule");
}

void SVControl::emitModuleHeader(CodeBuilder* builder) {
    builder->appendLine("//");
    builder->appendLine("// P4 Pipeline Module");
    builder->appendLine("// Combines: Table Lookup + Actions + Checksum + Statistics");
    builder->appendLine("//");
    builder->newline();
}

void SVControl::emitPortDeclarations(CodeBuilder* builder) {
    std::stringstream ss;
    
    builder->appendLine("module control #(");  
    builder->increaseIndent();
    builder->appendLine("parameter DATA_WIDTH = 512,");
    builder->appendLine("parameter TABLE_SIZE = 1024");
    builder->decreaseIndent();
    builder->appendLine(") (");
    builder->increaseIndent();
    
    // Clock and reset
    builder->appendLine("input  logic                     aclk,");
    builder->appendLine("input  logic                     aresetn,");
    builder->newline();
    
    // AXI-Stream input
    builder->appendLine("// AXI-Stream input (from parser)");
    builder->appendLine("input  logic [DATA_WIDTH-1:0]   s_axis_tdata,");
    builder->appendLine("input  logic                     s_axis_tvalid,");
    builder->appendLine("output logic                     s_axis_tready,");
    builder->appendLine("input  logic [DATA_WIDTH/8-1:0] s_axis_tkeep,");
    builder->appendLine("input  logic                     s_axis_tlast,");
    builder->newline();
    
    // Parsed header inputs (from parser)
    builder->appendLine("// Parsed headers (from parser)");
    auto parsedFields = getRequiredParsedFields();
    for (auto& field : parsedFields) {
        ss.str("");
        if (field.second == 1) {
            ss << "input  logic                     " << field.first << ",";
        } else {
            ss << "input  logic [" << (field.second - 1) << ":0]             " 
               << field.first << ",";
        }
        builder->appendLine(ss.str());
    }
    builder->newline();
    
    // AXI-Stream output
    builder->appendLine("// AXI-Stream output (to deparser)");
    builder->appendLine("output logic [DATA_WIDTH-1:0]   m_axis_tdata,");
    builder->appendLine("output logic                     m_axis_tvalid,");
    builder->appendLine("input  logic                     m_axis_tready,");
    builder->appendLine("output logic [DATA_WIDTH/8-1:0] m_axis_tkeep,");
    builder->appendLine("output logic                     m_axis_tlast,");
    builder->appendLine("output logic                     m_axis_drop,");
    builder->appendLine("output logic [8:0]              m_axis_egress_port,");
    builder->newline();
    
    // CHANGED: Simple control interface instead of AXI-Lite
    builder->appendLine("// Simple table control interface");
    builder->appendLine("input  logic                        table_write_enable,");
    builder->appendLine("input  logic [9:0]                 table_write_addr,");
    builder->appendLine("input  logic                        table_entry_valid,");
    builder->appendLine("input  logic [31:0]                table_entry_prefix,");
    builder->appendLine("input  logic [5:0]                 table_entry_prefix_len,");
    builder->appendLine("input  logic [2:0]                 table_entry_action,");
    builder->appendLine("input  logic [47:0]                table_entry_dst_mac,");
    builder->appendLine("input  logic [8:0]                 table_entry_egress_port,");
    builder->newline();
    
    // CHANGED: Statistics to 32-bit
    builder->appendLine("// Statistics outputs");
    builder->appendLine("output logic [31:0]             packet_count,");
    builder->appendLine("output logic [31:0]             dropped_count,");
    builder->appendLine("output logic [31:0]             forwarded_count");
    
    builder->decreaseIndent();
    builder->appendLine(");");
    builder->newline();
}

std::vector<std::pair<cstring, int>> SVControl::getRequiredParsedFields() {
    std::vector<std::pair<cstring, int>> fields;
    
    // Always need these for basic.p4
    fields.push_back({cstring("ethernet_valid"), 1});
    fields.push_back({cstring("ethernet_dstAddr"), 48});
    fields.push_back({cstring("ethernet_srcAddr"), 48});
    fields.push_back({cstring("ethernet_etherType"), 16});
    
    fields.push_back({cstring("ipv4_valid"), 1});
    fields.push_back({cstring("ipv4_version"), 4});
    fields.push_back({cstring("ipv4_ihl"), 4});
    fields.push_back({cstring("ipv4_diffserv"), 8});
    fields.push_back({cstring("ipv4_totalLen"), 16});
    fields.push_back({cstring("ipv4_identification"), 16});
    fields.push_back({cstring("ipv4_flags"), 3});
    fields.push_back({cstring("ipv4_fragOffset"), 13});
    fields.push_back({cstring("ipv4_ttl"), 8});
    fields.push_back({cstring("ipv4_protocol"), 8});
    fields.push_back({cstring("ipv4_hdrChecksum"), 16});
    fields.push_back({cstring("ipv4_srcAddr"), 32});
    fields.push_back({cstring("ipv4_dstAddr"), 32});
    
    return fields;
}

void SVControl::emitInternalSignals(CodeBuilder* builder) {
    builder->appendLine("// Pipeline stage registers");
    builder->appendLine("logic [DATA_WIDTH-1:0]      data_d1, data_d2, data_d3;");
    builder->appendLine("logic [DATA_WIDTH/8-1:0]    keep_d1, keep_d2, keep_d3;");
    builder->appendLine("logic                        last_d1, last_d2, last_d3;");
    builder->appendLine("logic                        valid_d1, valid_d2, valid_d3;");
    builder->newline();
    
    builder->appendLine("// LPM lookup results");
    builder->appendLine("logic                        lpm_hit_d1;");
    builder->appendLine("logic [2:0]                 lpm_action_id_d1;");
    builder->appendLine("logic [127:0]               lpm_action_data_d1;  // Max action params");
    builder->newline();
    
    builder->appendLine("// Action execution state");
    builder->appendLine("logic                        drop_d2;");
    builder->appendLine("logic [8:0]                 egress_port_d2;");
    builder->appendLine("logic                        header_modified_d2;");
    builder->newline();
    
    builder->appendLine("// Backpressure");
    builder->appendLine("assign s_axis_tready = !valid_d3 || m_axis_tready;");
    builder->newline();
}

void SVControl::emitTableStructDefinition(CodeBuilder* builder) {
    builder->appendLine("// LPM table entry structure");
    builder->appendLine("typedef struct packed {");
    builder->increaseIndent();
    builder->appendLine("logic        valid;");
    builder->appendLine("logic [31:0] prefix;");
    builder->appendLine("logic [5:0]  prefix_len;");
    builder->appendLine("logic [2:0]  action_id;");
    builder->appendLine("logic [47:0] param_dst_mac;");
    builder->appendLine("logic [8:0]  param_egress_port;");
    builder->decreaseIndent();
    builder->appendLine("} lpm_entry_t;");
    builder->newline();
}

void SVControl::emitTableStorage(CodeBuilder* builder) {
    builder->appendLine("// Table storage");
    builder->appendLine("lpm_entry_t lpm_table [0:TABLE_SIZE-1];");
    builder->newline();
    
    builder->appendLine("// Table initialization");
    builder->appendLine("initial begin");
    builder->increaseIndent();
    builder->appendLine("for (int i = 0; i < TABLE_SIZE; i++) begin");
    builder->increaseIndent();
    builder->appendLine("lpm_table[i].valid = 1'b0;");
    builder->appendLine("lpm_table[i].action_id = 3'd0;  // Default: drop");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
}

void SVControl::emitTableLookupLogic(CodeBuilder* builder) {
    builder->appendLine("// ============================================");
    builder->appendLine("// Stage 1: LPM Table Lookup");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("always_ff @(posedge aclk) begin");
    builder->increaseIndent();
    
    builder->appendLine("if (!aresetn) begin");
    builder->increaseIndent();
    builder->appendLine("valid_d1 <= 1'b0;");
    builder->appendLine("lpm_hit_d1 <= 1'b0;");
    builder->decreaseIndent();
    
    builder->appendLine("end else if (!valid_d2 || m_axis_tready) begin");
    builder->increaseIndent();
    
    builder->appendLine("// Pipeline advance");
    builder->appendLine("valid_d1 <= s_axis_tvalid;");
    builder->appendLine("data_d1 <= s_axis_tdata;");
    builder->appendLine("keep_d1 <= s_axis_tkeep;");
    builder->appendLine("last_d1 <= s_axis_tlast;");
    builder->newline();
    
    builder->appendLine("if (s_axis_tvalid && ipv4_valid) begin");
    builder->increaseIndent();
    
    builder->appendLine("// LPM longest prefix match");
    builder->appendLine("logic [5:0] best_match_len;");
    builder->appendLine("logic [2:0] best_action_id;");
    builder->appendLine("logic [47:0] best_dst_mac;");
    builder->appendLine("logic [8:0] best_egress_port;");
    builder->appendLine("logic [31:0] mask;");
    builder->appendLine("logic found;");
    builder->newline();
    
    builder->appendLine("found = 1'b0;");
    builder->appendLine("best_match_len = 6'd0;");
    builder->appendLine("best_action_id = 3'd0;  // Default drop");
    builder->appendLine("best_dst_mac = 48'h0;");
    builder->appendLine("best_egress_port = 9'd0;");
    builder->newline();
    
    builder->appendLine("for (int i = 0; i < TABLE_SIZE; i++) begin");
    builder->increaseIndent();
    builder->appendLine("if (lpm_table[i].valid) begin");
    builder->increaseIndent();
    
    // CORRECTED MASK CALCULATION
    builder->appendLine("// Create prefix mask (CORRECTED)");
    builder->appendLine("if (lpm_table[i].prefix_len == 6'd0)");
    builder->increaseIndent();
    builder->appendLine("mask = 32'h0;");
    builder->decreaseIndent();
    builder->appendLine("else if (lpm_table[i].prefix_len == 6'd32)");
    builder->increaseIndent();
    builder->appendLine("mask = 32'hFFFFFFFF;");
    builder->decreaseIndent();
    builder->appendLine("else");
    builder->increaseIndent();
    builder->appendLine("mask = ~(32'hFFFFFFFF >> lpm_table[i].prefix_len);");
    builder->decreaseIndent();
    builder->newline();
    
    builder->appendLine("// Check if prefix matches");
    builder->appendLine("if ((ipv4_dstAddr & mask) == (lpm_table[i].prefix & mask)) begin");
    builder->increaseIndent();
    builder->appendLine("// Select longest match");
    builder->appendLine("if (lpm_table[i].prefix_len >= best_match_len) begin");
    builder->increaseIndent();
    builder->appendLine("found = 1'b1;");
    builder->appendLine("best_match_len = lpm_table[i].prefix_len;");
    builder->appendLine("best_action_id = lpm_table[i].action_id;");
    builder->appendLine("best_dst_mac = lpm_table[i].param_dst_mac;");
    builder->appendLine("best_egress_port = lpm_table[i].param_egress_port;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    builder->appendLine("lpm_hit_d1 <= found;");
    builder->appendLine("lpm_action_id_d1 <= best_action_id;");
    builder->appendLine("lpm_action_data_d1[47:0] <= best_dst_mac;");
    builder->appendLine("lpm_action_data_d1[56:48] <= best_egress_port;");
    
    builder->decreaseIndent();
    builder->appendLine("end else begin");
    builder->increaseIndent();
    builder->appendLine("// No IPv4, no lookup");
    builder->appendLine("lpm_hit_d1 <= 1'b0;");
    builder->appendLine("lpm_action_id_d1 <= 3'd0;  // Drop");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
}

void SVControl::emitActionExecutionLogic(CodeBuilder* builder) {
    builder->appendLine("// ============================================");
    builder->appendLine("// Stage 2: Action Execution");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("always_ff @(posedge aclk) begin");
    builder->increaseIndent();
    
    builder->appendLine("if (!aresetn) begin");
    builder->increaseIndent();
    builder->appendLine("valid_d2 <= 1'b0;");
    builder->appendLine("drop_d2 <= 1'b0;");
    builder->appendLine("header_modified_d2 <= 1'b0;");
    builder->decreaseIndent();
    
    builder->appendLine("end else if (!valid_d3 || m_axis_tready) begin");
    builder->increaseIndent();
    
    builder->appendLine("// Pipeline advance");
    builder->appendLine("valid_d2 <= valid_d1;");
    builder->appendLine("data_d2 <= data_d1;");
    builder->appendLine("keep_d2 <= keep_d1;");
    builder->appendLine("last_d2 <= last_d1;");
    builder->newline();
    
    builder->appendLine("if (valid_d1 && lpm_hit_d1) begin");
    builder->increaseIndent();
    
    builder->appendLine("case (lpm_action_id_d1)");
    builder->increaseIndent();
    
    // Action 0: ipv4_forward
    builder->appendLine("3'd0: begin  // ipv4_forward");
    builder->increaseIndent();
    builder->appendLine("drop_d2 <= 1'b0;");
    builder->appendLine("header_modified_d2 <= 1'b1;");
    builder->appendLine("egress_port_d2 <= lpm_action_data_d1[56:48];");
    builder->newline();
    
    builder->appendLine("// Modify Ethernet headers");
    builder->appendLine("data_d2[47:0] <= lpm_action_data_d1[47:0];        // New dst MAC");
    builder->appendLine("data_d2[95:48] <= ethernet_dstAddr;                // src = old dst");
    builder->newline();
    
    builder->appendLine("// Decrement TTL");
    builder->appendLine("if (ipv4_ttl > 8'd0) begin");
    builder->increaseIndent();
    builder->appendLine("data_d2[183:176] <= ipv4_ttl - 8'd1;");
    builder->decreaseIndent();
    builder->appendLine("end else begin");
    builder->increaseIndent();
    builder->appendLine("// TTL expired, drop packet");
    builder->appendLine("drop_d2 <= 1'b1;");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    // Action 1: drop
    builder->appendLine("3'd1: begin  // drop");
    builder->increaseIndent();
    builder->appendLine("drop_d2 <= 1'b1;");
    builder->appendLine("header_modified_d2 <= 1'b0;");
    builder->appendLine("egress_port_d2 <= 9'd0;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    // Action 2: NoAction
    builder->appendLine("3'd2: begin  // NoAction");
    builder->increaseIndent();
    builder->appendLine("drop_d2 <= 1'b0;");
    builder->appendLine("header_modified_d2 <= 1'b0;");
    builder->appendLine("egress_port_d2 <= 9'd0;");
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
    
    builder->appendLine("default: begin");
    builder->increaseIndent();
    builder->appendLine("// Unknown action, drop for safety");
    builder->appendLine("drop_d2 <= 1'b1;");
    builder->appendLine("header_modified_d2 <= 1'b0;");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("endcase");
    
    builder->decreaseIndent();
    builder->appendLine("end else begin");
    builder->increaseIndent();
    builder->appendLine("// No hit, drop");
    builder->appendLine("drop_d2 <= 1'b1;");
    builder->appendLine("header_modified_d2 <= 1'b0;");
    builder->appendLine("egress_port_d2 <= 9'd0;");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
}

void SVControl::emitChecksumUpdateLogic(CodeBuilder* builder) {
    builder->appendLine("// ============================================");
    builder->appendLine("// Stage 3: IPv4 Checksum Recalculation");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("always_ff @(posedge aclk) begin");
    builder->increaseIndent();
    
    builder->appendLine("if (!aresetn) begin");
    builder->increaseIndent();
    builder->appendLine("valid_d3 <= 1'b0;");
    builder->decreaseIndent();
    
    builder->appendLine("end else if (m_axis_tready || !valid_d3) begin");
    builder->increaseIndent();
    
    builder->appendLine("// Pipeline advance");
    builder->appendLine("valid_d3 <= valid_d2;");
    builder->appendLine("data_d3 <= data_d2;");
    builder->appendLine("keep_d3 <= keep_d2;");
    builder->appendLine("last_d3 <= last_d2;");
    builder->newline();
    
    builder->appendLine("if (valid_d2 && header_modified_d2 && ipv4_valid && !drop_d2) begin");
    builder->increaseIndent();
    
    builder->appendLine("// Zero out old checksum");
    builder->appendLine("data_d3[207:192] <= 16'h0;");
    builder->newline();
    
    builder->appendLine("// Sum all 16-bit words in IPv4 header");
    builder->appendLine("logic [31:0] sum;");
    builder->appendLine("sum = 32'h0;");
    builder->newline();
    
    builder->appendLine("// Add each 16-bit field (skip checksum field at [207:192])");
    builder->appendLine("sum = sum + {16'h0, data_d2[127:112]};   // Version+IHL+Diffserv");
    builder->appendLine("sum = sum + {16'h0, data_d2[143:128]};   // Total Length");
    builder->appendLine("sum = sum + {16'h0, data_d2[159:144]};   // Identification");
    builder->appendLine("sum = sum + {16'h0, data_d2[175:160]};   // Flags+FragOffset");
    builder->appendLine("sum = sum + {16'h0, data_d2[191:176]};   // TTL+Protocol");
    builder->appendLine("// Skip [207:192] (checksum field itself)");
    builder->appendLine("sum = sum + {16'h0, data_d2[223:208]};   // Src Addr [15:0]");
    builder->appendLine("sum = sum + {16'h0, data_d2[239:224]};   // Src Addr [31:16]");
    builder->appendLine("sum = sum + {16'h0, data_d2[255:240]};   // Dst Addr [15:0]");
    builder->appendLine("sum = sum + {16'h0, data_d2[271:256]};   // Dst Addr [31:16]");
    builder->newline();
    
    builder->appendLine("// Fold 32-bit sum to 16-bit with carry");
    builder->appendLine("logic [31:0] fold;");
    builder->appendLine("fold = sum[15:0] + {16'h0, sum[31:16]};   // First fold");
    builder->appendLine("fold = fold[15:0] + {16'h0, fold[31:16]}; // Add carry");
    builder->newline();
    
    builder->appendLine("// One's complement and insert");
    builder->appendLine("data_d3[207:192] <= ~fold[15:0];");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
}

void SVControl::emitStatisticsCounters(CodeBuilder* builder) {
    // CHANGED: 32-bit counters instead of 64-bit
    builder->appendLine("// ============================================");
    builder->appendLine("// Statistics Counters (32-bit)");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("always_ff @(posedge aclk) begin");
    builder->increaseIndent();
    
    builder->appendLine("if (!aresetn) begin");
    builder->increaseIndent();
    builder->appendLine("packet_count <= 32'd0;");
    builder->appendLine("dropped_count <= 32'd0;");
    builder->appendLine("forwarded_count <= 32'd0;");
    builder->decreaseIndent();
    
    builder->appendLine("end else begin");
    builder->increaseIndent();
    
    builder->appendLine("if (valid_d3 && last_d3 && (m_axis_tready || !m_axis_tvalid)) begin");
    builder->increaseIndent();
    builder->appendLine("packet_count <= packet_count + 32'd1;");
    builder->newline();
    
    builder->appendLine("if (drop_d2) begin");
    builder->increaseIndent();
    builder->appendLine("dropped_count <= dropped_count + 32'd1;");
    builder->decreaseIndent();
    builder->appendLine("end else begin");
    builder->increaseIndent();
    builder->appendLine("forwarded_count <= forwarded_count + 32'd1;");
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
}

// NEW METHOD: Simple table control
void SVControl::emitSimpleTableControl(CodeBuilder* builder) {
    LOG2("Emitting simple table control interface");
    
    builder->appendLine("// ============================================");
    builder->appendLine("// Simple Table Control Interface");
    builder->appendLine("// ============================================");
    builder->newline();
    
    builder->appendLine("// Table write logic");
    builder->appendLine("always_ff @(posedge aclk) begin");
    builder->increaseIndent();
    
    builder->appendLine("if (table_write_enable) begin");
    builder->increaseIndent();
    
    builder->appendLine("lpm_table[table_write_addr].valid <= table_entry_valid;");
    builder->appendLine("lpm_table[table_write_addr].prefix <= table_entry_prefix;");
    builder->appendLine("lpm_table[table_write_addr].prefix_len <= table_entry_prefix_len;");
    builder->appendLine("lpm_table[table_write_addr].action_id <= table_entry_action;");
    builder->appendLine("lpm_table[table_write_addr].param_dst_mac <= table_entry_dst_mac;");
    builder->appendLine("lpm_table[table_write_addr].param_egress_port <= table_entry_egress_port;");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    
    builder->decreaseIndent();
    builder->appendLine("end");
    builder->newline();
}

ControlConfig SVControl::extractConfiguration() {
    LOG1("Extracting control configuration for submodules");
    
    ControlConfig config;
    
    // Default values
    config.matchType = 1;        // LPM by default
    config.actionConfig = 0x07;  // Forward + Drop + Modify by default
    config.tableSize = 1024;
    config.keyWidth = 32;
    
    // Extract from tables
    if (!svTables.empty()) {
        // Get first table (assume single table for now)
        auto firstTable = svTables.begin()->second;
        
        // Get match type from table 
        config.matchType = static_cast<uint8_t>(firstTable->getMatchType());
        
        // Get table size
        config.tableSize = static_cast<uint32_t>(firstTable->getTableSize());
        
        // Get key width
        config.keyWidth = static_cast<uint32_t>(firstTable->getKeyWidth());
        
        LOG2("  Match type: " << (int)config.matchType);
        LOG2("  Table size: " << config.tableSize);
        LOG2("  Key width: " << config.keyWidth);
    }
    
    // Extract action types from actions
    config.actionConfig = 0;
    for (const auto& actionPair : svActions) {
        cstring actionName = actionPair.first;
        
        // Determine action type bits
        if (actionName == "ipv4_forward" || 
            actionName == "forward" ||
            actionName.string().find("forward") != std::string::npos) {
            config.actionConfig |= 0x01;  // Bit 0: Forward
            config.actionConfig |= 0x04;  // Bit 2: Modify header
        }
        
        if (actionName == "drop" || 
            actionName.string().find("drop") != std::string::npos) {
            config.actionConfig |= 0x02;  // Bit 1: Drop
        }
        
        if (actionName.string().find("encap") != std::string::npos) {
            config.actionConfig |= 0x08;  // Bit 3: Encap
        }
        
        if (actionName.string().find("decap") != std::string::npos) {
            config.actionConfig |= 0x10;  // Bit 4: Decap
        }
        
        if (actionName.string().find("hash") != std::string::npos) {
            config.actionConfig |= 0x20;  // Bit 5: Hash
        }
    }
    
    // Default to Forward+Drop+Modify if no actions found
    if (config.actionConfig == 0) {
        config.actionConfig = 0x07;
    }
    
    LOG1("Configuration extracted:");
    LOG1("  Match type: " << (int)config.matchType 
         << " (0=Exact, 1=LPM, 2=Ternary, 3=Range)");
    LOG1("  Action config: 0x" << std::hex << (int)config.actionConfig << std::dec);
    LOG1("  Table size: " << config.tableSize);
    LOG1("  Key width: " << config.keyWidth);
    
    return config;
}

}  // namespace SV