// stats_engine.sv
// Generic statistics and counter engine
// Supports packet counters, byte counters, and registers

module stats #(
    // ==========================================
    // Configuration Parameters
    // ==========================================
    parameter NUM_PORTS = 16,
    parameter NUM_REGISTERS = 8,
    parameter COUNTER_WIDTH = 32
) (
    input  wire                           aclk,
    input  wire                           aresetn,
    
    // ==========================================
    // Packet Events
    // ==========================================
    input  wire                           packet_valid,
    input  wire                           packet_last,
    input  wire                           packet_drop,
    input  wire [15:0]                    packet_length,
    input  wire [8:0]                     egress_port,
    
    // ==========================================
    // Global Statistics Outputs
    // ==========================================
    output reg  [COUNTER_WIDTH-1:0]       packet_count,
    output reg  [COUNTER_WIDTH-1:0]       dropped_count,
    output reg  [COUNTER_WIDTH-1:0]       forwarded_count,
    output reg  [COUNTER_WIDTH-1:0]       byte_count,
    
    // ==========================================
    // Per-Port Statistics
    // ==========================================
    output reg  [NUM_PORTS-1:0][COUNTER_WIDTH-1:0] port_packet_count,
    output reg  [NUM_PORTS-1:0][COUNTER_WIDTH-1:0] port_byte_count,
    
    // ==========================================
    // User Registers (for P4 register arrays)
    // ==========================================
    input  wire                           reg_write_enable,
    input  wire [$clog2(NUM_REGISTERS)-1:0] reg_write_addr,
    input  wire [COUNTER_WIDTH-1:0]       reg_write_data,
    output reg  [NUM_REGISTERS-1:0][COUNTER_WIDTH-1:0] user_registers
);

    // ==========================================
    // Statistics Update Logic
    // ==========================================
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            packet_count    <= '0;
            dropped_count   <= '0;
            forwarded_count <= '0;
            byte_count      <= '0;
            port_packet_count <= '0;
            port_byte_count   <= '0;
            user_registers    <= '0;
        end else begin
            // ==========================================
            // Update on Last Beat of Packet
            // ==========================================
            if (packet_valid && packet_last) begin
                // Global packet count
                packet_count <= packet_count + 1;
                
                // Byte count
                byte_count <= byte_count + packet_length;
                
                if (packet_drop) begin
                    // Dropped packet
                    dropped_count <= dropped_count + 1;
                end else begin
                    // Forwarded packet
                    forwarded_count <= forwarded_count + 1;
                    
                    // Per-port statistics
                    if (egress_port < NUM_PORTS) begin
                        port_packet_count[egress_port] <= port_packet_count[egress_port] + 1;
                        port_byte_count[egress_port]   <= port_byte_count[egress_port] + packet_length;
                    end
                end
            end
            
            // ==========================================
            // User Register Writes
            // ==========================================
            if (reg_write_enable && reg_write_addr < NUM_REGISTERS) begin
                user_registers[reg_write_addr] <= reg_write_data;
            end
        end
    end

endmodule