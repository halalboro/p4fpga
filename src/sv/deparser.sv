// generic_deparser.sv
// Configurable packet deparser for P4 applications
// Single parameter controls all deparsing behavior

module generic_deparser #(
    // ==========================================
    // Data Width Parameters
    // ==========================================
    parameter DATA_WIDTH = 512,
    parameter KEEP_WIDTH = DATA_WIDTH/8,
    
    // ==========================================
    // Deparser Configuration (Single Parameter)
    // Bit assignment:
    // [0]   : EMIT_ETHERNET
    // [1]   : EMIT_VLAN
    // [2]   : EMIT_IPV4
    // [3]   : EMIT_IPV6
    // [4]   : EMIT_TCP
    // [5]   : EMIT_UDP
    // [6]   : EMIT_VXLAN
    // [7]   : UPDATE_IPV4_CHECKSUM
    // [8]   : UPDATE_TCP_CHECKSUM
    // [9]   : UPDATE_UDP_CHECKSUM
    // [15:10]: Reserved
    // ==========================================
    parameter [15:0] DEPARSER_CONFIG = 16'b0010000101  // Default: Eth + IPv4 + UDP
) (
    input  wire                      aclk,
    input  wire                      aresetn,
    
    // ==========================================
    // Modified Header Fields - Ethernet
    // ==========================================
    input  wire [47:0]               eth_dst_addr,
    input  wire [47:0]               eth_src_addr,
    input  wire [15:0]               eth_ether_type,
    input  wire                      eth_valid,
    
    // ==========================================
    // Modified Header Fields - VLAN
    // ==========================================
    input  wire [2:0]                vlan_pcp,
    input  wire                      vlan_dei,
    input  wire [11:0]               vlan_vid,
    input  wire [15:0]               vlan_ether_type,
    input  wire                      vlan_valid,
    
    // ==========================================
    // Modified Header Fields - IPv4
    // ==========================================
    input  wire [3:0]                ipv4_version,
    input  wire [3:0]                ipv4_ihl,
    input  wire [7:0]                ipv4_tos,
    input  wire [15:0]               ipv4_total_len,
    input  wire [15:0]               ipv4_identification,
    input  wire [2:0]                ipv4_flags,
    input  wire [12:0]               ipv4_frag_offset,
    input  wire [7:0]                ipv4_ttl,
    input  wire [7:0]                ipv4_protocol,
    input  wire [15:0]               ipv4_hdr_checksum,
    input  wire [31:0]               ipv4_src_addr,
    input  wire [31:0]               ipv4_dst_addr,
    input  wire                      ipv4_valid,
    
    // ==========================================
    // Modified Header Fields - IPv6
    // ==========================================
    input  wire [3:0]                ipv6_version,
    input  wire [7:0]                ipv6_traffic_class,
    input  wire [19:0]               ipv6_flow_label,
    input  wire [15:0]               ipv6_payload_len,
    input  wire [7:0]                ipv6_next_hdr,
    input  wire [7:0]                ipv6_hop_limit,
    input  wire [127:0]              ipv6_src_addr,
    input  wire [127:0]              ipv6_dst_addr,
    input  wire                      ipv6_valid,
    
    // ==========================================
    // Modified Header Fields - TCP
    // ==========================================
    input  wire [15:0]               tcp_src_port,
    input  wire [15:0]               tcp_dst_port,
    input  wire [31:0]               tcp_seq_no,
    input  wire [31:0]               tcp_ack_no,
    input  wire [3:0]                tcp_data_offset,
    input  wire [2:0]                tcp_reserved,
    input  wire [8:0]                tcp_flags,
    input  wire [15:0]               tcp_window,
    input  wire [15:0]               tcp_checksum,
    input  wire [15:0]               tcp_urgent_ptr,
    input  wire                      tcp_valid,
    
    // ==========================================
    // Modified Header Fields - UDP
    // ==========================================
    input  wire [15:0]               udp_src_port,
    input  wire [15:0]               udp_dst_port,
    input  wire [15:0]               udp_length,
    input  wire [15:0]               udp_checksum,
    input  wire                      udp_valid,
    
    // ==========================================
    // Modified Header Fields - VXLAN
    // ==========================================
    input  wire [7:0]                vxlan_flags,
    input  wire [23:0]               vxlan_reserved,
    input  wire [23:0]               vxlan_vni,
    input  wire [7:0]                vxlan_reserved2,
    input  wire                      vxlan_valid,
    
    // ==========================================
    // Packet Payload Input
    // ==========================================
    input  wire [DATA_WIDTH-1:0]     payload_data,
    input  wire [KEEP_WIDTH-1:0]     payload_keep,
    input  wire                      payload_valid,
    input  wire                      payload_last,
    
    // ==========================================
    // Control Signals
    // ==========================================
    input  wire                      drop_packet,
    
    // ==========================================
    // Output Packet Stream (AXI-Stream)
    // ==========================================
    output reg  [DATA_WIDTH-1:0]     m_axis_tdata,
    output reg  [KEEP_WIDTH-1:0]     m_axis_tkeep,
    output reg                       m_axis_tvalid,
    output reg                       m_axis_tlast,
    input  wire                      m_axis_tready
);

    // ==========================================
    // Local Parameters - Extract Config Bits
    // ==========================================
    localparam EMIT_ETHERNET          = DEPARSER_CONFIG[0];
    localparam EMIT_VLAN              = DEPARSER_CONFIG[1];
    localparam EMIT_IPV4              = DEPARSER_CONFIG[2];
    localparam EMIT_IPV6              = DEPARSER_CONFIG[3];
    localparam EMIT_TCP               = DEPARSER_CONFIG[4];
    localparam EMIT_UDP               = DEPARSER_CONFIG[5];
    localparam EMIT_VXLAN             = DEPARSER_CONFIG[6];
    localparam UPDATE_IPV4_CHECKSUM   = DEPARSER_CONFIG[7];
    localparam UPDATE_TCP_CHECKSUM    = DEPARSER_CONFIG[8];
    localparam UPDATE_UDP_CHECKSUM    = DEPARSER_CONFIG[9];
    
    // ==========================================
    // Internal Signals
    // ==========================================
    reg  [DATA_WIDTH-1:0]  output_buffer;
    reg  [10:0]            byte_offset;
    reg  [2:0]             deparse_state;
    reg  [15:0]            calculated_checksum;
    
    // State machine states
    localparam STATE_IDLE       = 3'd0;
    localparam STATE_ETHERNET   = 3'd1;
    localparam STATE_L3         = 3'd2;
    localparam STATE_L4         = 3'd3;
    localparam STATE_CHECKSUM   = 3'd4;
    localparam STATE_PAYLOAD    = 3'd5;
    localparam STATE_OUTPUT     = 3'd6;
    
    // ==========================================
    // IPv4 Checksum Calculation Function
    // ==========================================
    function [15:0] calculate_ipv4_checksum;
        input [159:0] ipv4_header;
        reg [31:0] sum;
        integer i;
        begin
            sum = 32'd0;
            for (i = 0; i < 10; i = i + 1) begin
                if (i != 5) begin
                    sum = sum + ipv4_header[i*16 +: 16];
                end
            end
            while (sum[31:16] != 0) begin
                sum = sum[15:0] + sum[31:16];
            end
            calculate_ipv4_checksum = ~sum[15:0];
        end
    endfunction
    
    // ==========================================
    // Main Deparser State Machine
    // ==========================================
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            m_axis_tvalid   <= 1'b0;
            m_axis_tlast    <= 1'b0;
            m_axis_tdata    <= {DATA_WIDTH{1'b0}};
            m_axis_tkeep    <= {KEEP_WIDTH{1'b0}};
            deparse_state   <= STATE_IDLE;
            byte_offset     <= 11'd0;
            output_buffer   <= {DATA_WIDTH{1'b0}};
            
        end else begin
            case (deparse_state)
                
                // ==========================================
                STATE_IDLE: begin
                    if (payload_valid && !drop_packet) begin
                        output_buffer <= {DATA_WIDTH{1'b0}};
                        byte_offset   <= 11'd0;
                        m_axis_tvalid <= 1'b0;
                        deparse_state <= STATE_ETHERNET;
                    end
                end
                
                // ==========================================
                STATE_ETHERNET: begin
                    if (EMIT_ETHERNET && eth_valid) begin
                        output_buffer[47:0]   <= eth_dst_addr;
                        output_buffer[95:48]  <= eth_src_addr;
                        
                        if (EMIT_VLAN && vlan_valid) begin
                            output_buffer[111:96]  <= 16'h8100;
                            output_buffer[114:112] <= vlan_pcp;
                            output_buffer[115]     <= vlan_dei;
                            output_buffer[127:116] <= vlan_vid;
                            output_buffer[143:128] <= vlan_ether_type;
                            byte_offset <= 11'd18;
                        end else begin
                            output_buffer[111:96] <= eth_ether_type;
                            byte_offset <= 11'd14;
                        end
                        
                        deparse_state <= STATE_L3;
                    end else begin
                        deparse_state <= STATE_L3;
                    end
                end
                
                // ==========================================
                STATE_L3: begin
                    if (EMIT_IPV4 && ipv4_valid) begin
                        output_buffer[byte_offset*8 +: 4]     <= ipv4_version;
                        output_buffer[byte_offset*8+4 +: 4]   <= ipv4_ihl;
                        output_buffer[byte_offset*8+8 +: 8]   <= ipv4_tos;
                        output_buffer[byte_offset*8+16 +: 16] <= ipv4_total_len;
                        output_buffer[byte_offset*8+32 +: 16] <= ipv4_identification;
                        output_buffer[byte_offset*8+48 +: 3]  <= ipv4_flags;
                        output_buffer[byte_offset*8+51 +: 13] <= ipv4_frag_offset;
                        output_buffer[byte_offset*8+64 +: 8]  <= ipv4_ttl;
                        output_buffer[byte_offset*8+72 +: 8]  <= ipv4_protocol;
                        output_buffer[byte_offset*8+96 +: 32] <= ipv4_src_addr;
                        output_buffer[byte_offset*8+128 +: 32] <= ipv4_dst_addr;
                        
                        byte_offset <= byte_offset + 11'd20;
                        deparse_state <= UPDATE_IPV4_CHECKSUM ? STATE_CHECKSUM : STATE_L4;
                        
                    end else if (EMIT_IPV6 && ipv6_valid) begin
                        output_buffer[byte_offset*8 +: 4]     <= ipv6_version;
                        output_buffer[byte_offset*8+4 +: 8]   <= ipv6_traffic_class;
                        output_buffer[byte_offset*8+12 +: 20] <= ipv6_flow_label;
                        output_buffer[byte_offset*8+32 +: 16] <= ipv6_payload_len;
                        output_buffer[byte_offset*8+48 +: 8]  <= ipv6_next_hdr;
                        output_buffer[byte_offset*8+56 +: 8]  <= ipv6_hop_limit;
                        output_buffer[byte_offset*8+64 +: 128] <= ipv6_src_addr;
                        output_buffer[byte_offset*8+192 +: 128] <= ipv6_dst_addr;
                        
                        byte_offset <= byte_offset + 11'd40;
                        deparse_state <= STATE_L4;
                        
                    end else begin
                        deparse_state <= STATE_L4;
                    end
                end
                
                // ==========================================
                STATE_CHECKSUM: begin
                    if (UPDATE_IPV4_CHECKSUM && ipv4_valid) begin
                        calculated_checksum <= calculate_ipv4_checksum(
                            output_buffer[(byte_offset-20)*8 +: 160]
                        );
                        output_buffer[(byte_offset-20)*8+80 +: 16] <= calculated_checksum;
                    end
                    deparse_state <= STATE_L4;
                end
                
                // ==========================================
                STATE_L4: begin
                    if (EMIT_TCP && tcp_valid) begin
                        output_buffer[byte_offset*8 +: 16]    <= tcp_src_port;
                        output_buffer[byte_offset*8+16 +: 16] <= tcp_dst_port;
                        output_buffer[byte_offset*8+32 +: 32] <= tcp_seq_no;
                        output_buffer[byte_offset*8+64 +: 32] <= tcp_ack_no;
                        output_buffer[byte_offset*8+96 +: 4]  <= tcp_data_offset;
                        output_buffer[byte_offset*8+100 +: 3] <= tcp_reserved;
                        output_buffer[byte_offset*8+103 +: 9] <= tcp_flags;
                        output_buffer[byte_offset*8+112 +: 16] <= tcp_window;
                        output_buffer[byte_offset*8+128 +: 16] <= tcp_checksum;
                        output_buffer[byte_offset*8+144 +: 16] <= tcp_urgent_ptr;
                        
                        byte_offset <= byte_offset + 11'd20;
                        deparse_state <= STATE_PAYLOAD;
                        
                    end else if (EMIT_UDP && udp_valid) begin
                        output_buffer[byte_offset*8 +: 16]   <= udp_src_port;
                        output_buffer[byte_offset*8+16 +: 16] <= udp_dst_port;
                        output_buffer[byte_offset*8+32 +: 16] <= udp_length;
                        output_buffer[byte_offset*8+48 +: 16] <= udp_checksum;
                        
                        byte_offset <= byte_offset + 11'd8;
                        
                        if (EMIT_VXLAN && vxlan_valid) begin
                            output_buffer[byte_offset*8+64 +: 8]   <= vxlan_flags;
                            output_buffer[byte_offset*8+72 +: 24]  <= vxlan_reserved;
                            output_buffer[byte_offset*8+96 +: 24]  <= vxlan_vni;
                            output_buffer[byte_offset*8+120 +: 8]  <= vxlan_reserved2;
                            byte_offset <= byte_offset + 11'd8;
                        end
                        
                        deparse_state <= STATE_PAYLOAD;
                        
                    end else begin
                        deparse_state <= STATE_PAYLOAD;
                    end
                end
                
                // ==========================================
                STATE_PAYLOAD: begin
                    output_buffer[byte_offset*8 +: (DATA_WIDTH - byte_offset*8)] <= 
                        payload_data[0 +: (DATA_WIDTH - byte_offset*8)];
                    
                    deparse_state <= STATE_OUTPUT;
                end
                
                // ==========================================
                STATE_OUTPUT: begin
                    if (m_axis_tready || !m_axis_tvalid) begin
                        m_axis_tdata  <= output_buffer;
                        m_axis_tkeep  <= {KEEP_WIDTH{1'b1}};
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast  <= payload_last;
                        
                        if (payload_last) begin
                            deparse_state <= STATE_IDLE;
                        end
                    end
                end
                
            endcase
        end
    end

endmodule