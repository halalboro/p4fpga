// match_engine.sv
// Generic table matching engine supporting multiple match types
// Configurable via MATCH_TYPE parameter

module match #(
    // ==========================================
    // Configuration Parameters
    // ==========================================
    parameter MATCH_TYPE = 1,        // 0=Exact, 1=LPM, 2=Ternary, 3=Range
    parameter KEY_WIDTH = 32,
    parameter TABLE_SIZE = 1024,
    parameter ACTION_DATA_WIDTH = 128,
    parameter DATA_WIDTH = 512
) (
    input  wire                           aclk,
    input  wire                           aresetn,
    
    // ==========================================
    // Lookup Interface
    // ==========================================
    input  wire [KEY_WIDTH-1:0]           lookup_key,
    input  wire [KEY_WIDTH-1:0]           lookup_key_mask,    // For ternary
    input  wire                           lookup_valid,
    output reg                            lookup_ready,
    
    // ADDED: Header validity preservation
    input  wire                           ipv4_valid_in,
    
    // ADDED: Header fields pass-through
    input  wire [47:0]                    eth_dst_addr_in,
    input  wire [47:0]                    eth_src_addr_in,
    input  wire [7:0]                     ipv4_ttl_in,
    
    // ADDED: Packet data pass-through
    input  wire [DATA_WIDTH-1:0]          packet_data_in,
    input  wire [DATA_WIDTH/8-1:0]        packet_keep_in,
    input  wire                           packet_last_in,
    
    // ==========================================
    // Match Results
    // ==========================================
    output reg                            match_hit,
    output reg  [2:0]                     match_action_id,
    output reg  [ACTION_DATA_WIDTH-1:0]   match_action_data,
    output reg                            match_valid,
    
    // ADDED: Preserved outputs
    output reg                            ipv4_valid_out,
    output reg  [47:0]                    eth_dst_addr_out,
    output reg  [47:0]                    eth_src_addr_out,
    output reg  [7:0]                     ipv4_ttl_out,
    output reg  [DATA_WIDTH-1:0]          packet_data_out,
    output reg  [DATA_WIDTH/8-1:0]        packet_keep_out,
    output reg                            packet_last_out,
    
    // ==========================================
    // Table Programming Interface
    // ==========================================
    input  wire                           table_write_enable,
    input  wire [$clog2(TABLE_SIZE)-1:0]  table_write_addr,
    input  wire                           table_entry_valid,
    input  wire [KEY_WIDTH-1:0]           table_entry_key,
    input  wire [KEY_WIDTH-1:0]           table_entry_mask,     // For LPM/Ternary
    input  wire [5:0]                     table_entry_prefix_len, // For LPM
    input  wire [2:0]                     table_entry_action_id,
    input  wire [ACTION_DATA_WIDTH-1:0]   table_entry_action_data
);

    // ==========================================
    // Table Entry Structure
    // ==========================================
    typedef struct packed {
        logic                           valid;
        logic [KEY_WIDTH-1:0]          key;
        logic [KEY_WIDTH-1:0]          mask;           // For Ternary/LPM
        logic [5:0]                    prefix_len;     // For LPM
        logic [2:0]                    action_id;
        logic [ACTION_DATA_WIDTH-1:0]  action_data;
    } table_entry_t;
    
    // ==========================================
    // Table Storage
    // ==========================================
    table_entry_t table_mem [0:TABLE_SIZE-1];
    
    // ==========================================
    // ADDED: Pipeline registers for pass-through
    // ==========================================
    reg                           ipv4_valid_d1;
    reg  [47:0]                   eth_dst_d1;
    reg  [47:0]                   eth_src_d1;
    reg  [7:0]                    ipv4_ttl_d1;
    reg  [DATA_WIDTH-1:0]         packet_data_d1;
    reg  [DATA_WIDTH/8-1:0]       packet_keep_d1;
    reg                           packet_last_d1;
    reg                           lookup_valid_d1;
    
    // ==========================================
    // Internal Signals
    // ==========================================
    reg  [KEY_WIDTH-1:0] match_mask;
    reg                  entry_matches;
    
    // ==========================================
    // Table Initialization
    // ==========================================
    initial begin
        for (int i = 0; i < TABLE_SIZE; i++) begin
            table_mem[i].valid = 1'b0;
            table_mem[i].action_id = 3'd1;  // Default: drop
        end
    end
    
    // ==========================================
    // Table Write Logic
    // ==========================================
    always_ff @(posedge aclk) begin
        if (table_write_enable) begin
            table_mem[table_write_addr].valid       <= table_entry_valid;
            table_mem[table_write_addr].key         <= table_entry_key;
            table_mem[table_write_addr].mask        <= table_entry_mask;
            table_mem[table_write_addr].prefix_len  <= table_entry_prefix_len;
            table_mem[table_write_addr].action_id   <= table_entry_action_id;
            table_mem[table_write_addr].action_data <= table_entry_action_data;
        end
    end
    
    // ==========================================
    // ADDED: Stage 1 - Register inputs
    // ==========================================
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            ipv4_valid_d1  <= 1'b0;
            lookup_valid_d1 <= 1'b0;
        end else if (lookup_ready) begin
            ipv4_valid_d1   <= ipv4_valid_in;
            eth_dst_d1      <= eth_dst_addr_in;
            eth_src_d1      <= eth_src_addr_in;
            ipv4_ttl_d1     <= ipv4_ttl_in;
            packet_data_d1  <= packet_data_in;
            packet_keep_d1  <= packet_keep_in;
            packet_last_d1  <= packet_last_in;
            lookup_valid_d1 <= lookup_valid;
        end
    end
    
    // ==========================================
    // Lookup Logic (Combinational)
    // ==========================================
    always_comb begin
        lookup_ready = 1'b1;  // Always ready for combinational lookup
    end
    
    // ==========================================
    // CHANGED: Match Logic (Uses registered inputs)
    // ==========================================
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            match_hit         <= 1'b0;
            match_action_id   <= 3'd1;  // Default drop
            match_action_data <= '0;
            match_valid       <= 1'b0;
            ipv4_valid_out    <= 1'b0;
        end else begin
            match_valid     <= lookup_valid_d1;
            ipv4_valid_out  <= ipv4_valid_d1;        // ADDED: Preserve validity
            eth_dst_addr_out <= eth_dst_d1;          // ADDED: Preserve headers
            eth_src_addr_out <= eth_src_d1;
            ipv4_ttl_out     <= ipv4_ttl_d1;
            packet_data_out  <= packet_data_d1;      // ADDED: Preserve packet
            packet_keep_out  <= packet_keep_d1;
            packet_last_out  <= packet_last_d1;
            
            if (lookup_valid_d1) begin
                // Default: no match
                match_hit        <= 1'b0;
                match_action_id  <= 3'd1;  // Drop
                match_action_data <= '0;
                
                case (MATCH_TYPE)
                    // ==========================================
                    // EXACT MATCH
                    // ==========================================
                    0: begin
                        for (int i = 0; i < TABLE_SIZE; i++) begin
                            if (table_mem[i].valid && 
                                (lookup_key == table_mem[i].key)) begin
                                match_hit         <= 1'b1;
                                match_action_id   <= table_mem[i].action_id;
                                match_action_data <= table_mem[i].action_data;
                            end
                        end
                    end
                    
                    // ==========================================
                    // LPM (Longest Prefix Match)
                    // ==========================================
                    1: begin
                        automatic logic [5:0] best_match_len = 6'd0;
                        automatic logic found = 1'b0;
                        
                        for (int i = 0; i < TABLE_SIZE; i++) begin
                            if (table_mem[i].valid) begin
                                // Calculate mask from prefix length
                                if (table_mem[i].prefix_len == 6'd0)
                                    match_mask = '0;
                                else if (table_mem[i].prefix_len >= KEY_WIDTH)
                                    match_mask = '1;
                                else
                                    match_mask = ~((1 << (KEY_WIDTH - table_mem[i].prefix_len)) - 1);
                                
                                // Check if prefix matches
                                if ((lookup_key & match_mask) == (table_mem[i].key & match_mask)) begin
                                    // Select longest match
                                    if (table_mem[i].prefix_len >= best_match_len) begin
                                        found             = 1'b1;
                                        best_match_len    = table_mem[i].prefix_len;
                                        match_action_id   = table_mem[i].action_id;
                                        match_action_data = table_mem[i].action_data;
                                    end
                                end
                            end
                        end
                        
                        match_hit <= found;
                    end
                    
                    // ==========================================
                    // TERNARY MATCH
                    // ==========================================
                    2: begin
                        for (int i = 0; i < TABLE_SIZE; i++) begin
                            if (table_mem[i].valid) begin
                                // Apply mask to both key and lookup
                                if ((lookup_key & table_mem[i].mask) == 
                                    (table_mem[i].key & table_mem[i].mask)) begin
                                    match_hit         <= 1'b1;
                                    match_action_id   <= table_mem[i].action_id;
                                    match_action_data <= table_mem[i].action_data;
                                end
                            end
                        end
                    end
                    
                    // ==========================================
                    // RANGE MATCH
                    // ==========================================
                    3: begin
                        for (int i = 0; i < TABLE_SIZE; i++) begin
                            if (table_mem[i].valid) begin
                                // Range: key <= lookup <= mask
                                if ((lookup_key >= table_mem[i].key) && 
                                    (lookup_key <= table_mem[i].mask)) begin
                                    match_hit         <= 1'b1;
                                    match_action_id   <= table_mem[i].action_id;
                                    match_action_data <= table_mem[i].action_data;
                                end
                            end
                        end
                    end
                    
                    default: begin
                        match_hit <= 1'b0;
                    end
                endcase
            end
        end
    end

endmodule