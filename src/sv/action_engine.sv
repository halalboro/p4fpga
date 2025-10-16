// action_engine.sv
// Generic action execution engine
// Supports multiple action types via configuration

module action #(
    // ==========================================
    // Configuration Parameters
    // ==========================================
    parameter DATA_WIDTH = 512,
    parameter ACTION_DATA_WIDTH = 128,
    
    // Action configuration bitmask
    // [0] = FORWARD
    // [1] = DROP
    // [2] = MODIFY_HEADER
    // [3] = ENCAP
    // [4] = DECAP
    // [5] = HASH
    parameter [7:0] ACTION_CONFIG = 8'b00000111  // Forward, Drop, Modify
) (
    input  wire                           aclk,
    input  wire                           aresetn,
    
    // ==========================================
    // Packet Input
    // ==========================================
    input  wire [DATA_WIDTH-1:0]          packet_in,
    input  wire                           packet_valid,
    output reg                            packet_ready,
    
    // ==========================================
    // Action Control
    // ==========================================
    input  wire [2:0]                     action_id,
    input  wire [ACTION_DATA_WIDTH-1:0]   action_data,
    input  wire                           action_valid,
    
    // ==========================================
    // Header Fields (for modification)
    // ==========================================
    input  wire [47:0]                    eth_dst_addr,
    input  wire [47:0]                    eth_src_addr,
    input  wire [7:0]                     ipv4_ttl,
    input  wire [31:0]                    ipv4_src_addr,
    input  wire [31:0]                    ipv4_dst_addr,
    
    // ==========================================
    // Packet Output
    // ==========================================
    output reg  [DATA_WIDTH-1:0]          packet_out,
    output reg                            packet_out_valid,
    input  wire                           packet_out_ready,
    
    // ==========================================
    // Action Results
    // ==========================================
    output reg                            drop,
    output reg  [8:0]                     egress_port,
    output reg                            header_modified
);

    // ==========================================
    // Action ID Definitions
    // ==========================================
    localparam ACTION_FORWARD       = 3'd0;
    localparam ACTION_DROP          = 3'd1;
    localparam ACTION_NOACTION      = 3'd2;
    localparam ACTION_ENCAP         = 3'd3;
    localparam ACTION_DECAP         = 3'd4;
    localparam ACTION_HASH_SELECT   = 3'd5;
    
    // ==========================================
    // Configuration Bits
    // ==========================================
    localparam ENABLE_FORWARD       = ACTION_CONFIG[0];
    localparam ENABLE_DROP          = ACTION_CONFIG[1];
    localparam ENABLE_MODIFY_HEADER = ACTION_CONFIG[2];
    localparam ENABLE_ENCAP         = ACTION_CONFIG[3];
    localparam ENABLE_DECAP         = ACTION_CONFIG[4];
    localparam ENABLE_HASH          = ACTION_CONFIG[5];
    
    // ==========================================
    // Internal Signals
    // ==========================================
    reg [DATA_WIDTH-1:0] modified_packet;
    
    // ==========================================
    // Backpressure
    // ==========================================
    always_comb begin
        packet_ready = packet_out_ready;
    end
    
    // ==========================================
    // Action Execution
    // ==========================================
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            packet_out       <= '0;
            packet_out_valid <= 1'b0;
            drop             <= 1'b0;
            egress_port      <= 9'd0;
            header_modified  <= 1'b0;
        end else if (packet_ready) begin
            packet_out_valid <= packet_valid && action_valid;
            
            if (packet_valid && action_valid) begin
                // Default: pass through
                modified_packet  = packet_in;
                drop             = 1'b0;
                egress_port      = 9'd0;
                header_modified  = 1'b0;
                
                case (action_id)
                    // ==========================================
                    // FORWARD Action
                    // ==========================================
                    ACTION_FORWARD: begin
                        if (ENABLE_FORWARD && ENABLE_MODIFY_HEADER) begin
                            // Modify Ethernet destination MAC
                            modified_packet[47:0] = action_data[47:0];  // New dst MAC
                            
                            // Swap source MAC (old dst becomes new src)
                            modified_packet[95:48] = eth_dst_addr;
                            
                            // Decrement TTL
                            if (ipv4_ttl > 8'd0) begin
                                modified_packet[183:176] = ipv4_ttl - 8'd1;
                            end else begin
                                drop = 1'b1;  // TTL expired
                            end
                            
                            egress_port     = action_data[56:48];
                            header_modified = 1'b1;
                        end
                    end
                    
                    // ==========================================
                    // DROP Action
                    // ==========================================
                    ACTION_DROP: begin
                        if (ENABLE_DROP) begin
                            drop = 1'b1;
                        end
                    end
                    
                    // ==========================================
                    // NOACTION
                    // ==========================================
                    ACTION_NOACTION: begin
                        // Pass through unchanged
                        drop            = 1'b0;
                        header_modified = 1'b0;
                    end
                    
                    // ==========================================
                    // ENCAP Action (for tunneling)
                    // ==========================================
                    ACTION_ENCAP: begin
                        if (ENABLE_ENCAP) begin
                            // Shift packet and prepend tunnel header
                            // Implementation depends on tunnel type
                            // Placeholder for now
                            header_modified = 1'b1;
                        end
                    end
                    
                    // ==========================================
                    // DECAP Action (for tunneling)
                    // ==========================================
                    ACTION_DECAP: begin
                        if (ENABLE_DECAP) begin
                            // Remove outer header
                            // Implementation depends on tunnel type
                            // Placeholder for now
                            header_modified = 1'b1;
                        end
                    end
                    
                    // ==========================================
                    // HASH_SELECT Action (for load balancing)
                    // ==========================================
                    ACTION_HASH_SELECT: begin
                        if (ENABLE_HASH) begin
                            // Use hash to select egress port
                            // Simple hash: XOR of src/dst addresses
                            automatic logic [31:0] hash_val;
                            hash_val = ipv4_src_addr ^ ipv4_dst_addr;
                            egress_port = hash_val[8:0];
                            header_modified = 1'b0;
                        end
                    end
                    
                    default: begin
                        // Unknown action: drop for safety
                        drop = 1'b1;
                    end
                endcase
                
                packet_out = modified_packet;
            end
        end
    end

endmodule