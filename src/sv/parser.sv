// generic_parser.sv
// Configurable packet parser for P4 applications
// Single parameter controls all parsing behavior

module generic_parser #(
    // ==========================================
    // Data Width Parameters
    // ==========================================
    parameter DATA_WIDTH = 512,
    parameter KEEP_WIDTH = DATA_WIDTH/8,
    
    // ==========================================
    // Parser Configuration (Single Parameter)
    // Bit assignment:
    // [0]   : PARSE_ETHERNET
    // [1]   : PARSE_VLAN
    // [2]   : PARSE_IPV4
    // [3]   : PARSE_IPV6
    // [4]   : PARSE_TCP
    // [5]   : PARSE_UDP
    // [6]   : PARSE_VXLAN
    // [7]   : Reserved
    // ==========================================
    parameter [7:0] PARSER_CONFIG = 8'b00100101  // Default: Eth + IPv4 + UDP
) (
    input  wire                      aclk,
    input  wire                      aresetn,
    
    // ==========================================
    // Input Packet Stream (AXI-Stream)
    // ==========================================
    input  wire [DATA_WIDTH-1:0]     s_axis_tdata,
    input  wire [KEEP_WIDTH-1:0]     s_axis_tkeep,
    input  wire                      s_axis_tvalid,
    input  wire                      s_axis_tlast,
    output reg                       s_axis_tready,
    
    // ==========================================
    // Parsed Header Fields - Ethernet
    // ==========================================
    output reg  [47:0]               eth_dst_addr,
    output reg  [47:0]               eth_src_addr,
    output reg  [15:0]               eth_ether_type,
    output reg                       eth_valid,
    
    // ==========================================
    // Parsed Header Fields - VLAN (802.1Q)
    // ==========================================
    output reg  [2:0]                vlan_pcp,
    output reg                       vlan_dei,
    output reg  [11:0]               vlan_vid,
    output reg  [15:0]               vlan_ether_type,
    output reg                       vlan_valid,
    
    // ==========================================
    // Parsed Header Fields - IPv4
    // ==========================================
    output reg  [3:0]                ipv4_version,
    output reg  [3:0]                ipv4_ihl,
    output reg  [7:0]                ipv4_tos,
    output reg  [15:0]               ipv4_total_len,
    output reg  [15:0]               ipv4_identification,
    output reg  [2:0]                ipv4_flags,
    output reg  [12:0]               ipv4_frag_offset,
    output reg  [7:0]                ipv4_ttl,
    output reg  [7:0]                ipv4_protocol,
    output reg  [15:0]               ipv4_hdr_checksum,
    output reg  [31:0]               ipv4_src_addr,
    output reg  [31:0]               ipv4_dst_addr,
    output reg                       ipv4_valid,
    
    // ==========================================
    // Parsed Header Fields - IPv6
    // ==========================================
    output reg  [3:0]                ipv6_version,
    output reg  [7:0]                ipv6_traffic_class,
    output reg  [19:0]               ipv6_flow_label,
    output reg  [15:0]               ipv6_payload_len,
    output reg  [7:0]                ipv6_next_hdr,
    output reg  [7:0]                ipv6_hop_limit,
    output reg  [127:0]              ipv6_src_addr,
    output reg  [127:0]              ipv6_dst_addr,
    output reg                       ipv6_valid,
    
    // ==========================================
    // Parsed Header Fields - TCP
    // ==========================================
    output reg  [15:0]               tcp_src_port,
    output reg  [15:0]               tcp_dst_port,
    output reg  [31:0]               tcp_seq_no,
    output reg  [31:0]               tcp_ack_no,
    output reg  [3:0]                tcp_data_offset,
    output reg  [2:0]                tcp_reserved,
    output reg  [8:0]                tcp_flags,
    output reg  [15:0]               tcp_window,
    output reg  [15:0]               tcp_checksum,
    output reg  [15:0]               tcp_urgent_ptr,
    output reg                       tcp_valid,
    
    // ==========================================
    // Parsed Header Fields - UDP
    // ==========================================
    output reg  [15:0]               udp_src_port,
    output reg  [15:0]               udp_dst_port,
    output reg  [15:0]               udp_length,
    output reg  [15:0]               udp_checksum,
    output reg                       udp_valid,
    
    // ==========================================
    // Parsed Header Fields - VXLAN
    // ==========================================
    output reg  [7:0]                vxlan_flags,
    output reg  [23:0]               vxlan_reserved,
    output reg  [23:0]               vxlan_vni,
    output reg  [7:0]                vxlan_reserved2,
    output reg                       vxlan_valid,
    
    // ==========================================
    // Packet Metadata
    // ==========================================
    output reg  [15:0]               packet_length,
    output reg  [DATA_WIDTH-1:0]     payload_data,
    output reg  [KEEP_WIDTH-1:0]     payload_keep,
    output reg                       payload_valid,
    output reg                       payload_last
);

    // ==========================================
    // Local Parameters - Extract Config Bits
    // ==========================================
    localparam PARSE_ETHERNET = PARSER_CONFIG[0];
    localparam PARSE_VLAN     = PARSER_CONFIG[1];
    localparam PARSE_IPV4     = PARSER_CONFIG[2];
    localparam PARSE_IPV6     = PARSER_CONFIG[3];
    localparam PARSE_TCP      = PARSER_CONFIG[4];
    localparam PARSE_UDP      = PARSER_CONFIG[5];
    localparam PARSE_VXLAN    = PARSER_CONFIG[6];
    
    // ==========================================
    // Internal Signals
    // ==========================================
    reg  [DATA_WIDTH-1:0]  packet_buffer;
    reg  [10:0]            byte_offset;
    reg  [2:0]             parse_state;
    
    // State machine states
    localparam STATE_IDLE       = 3'd0;
    localparam STATE_ETHERNET   = 3'd1;
    localparam STATE_L3         = 3'd2;
    localparam STATE_L4         = 3'd3;
    localparam STATE_PAYLOAD    = 3'd4;
    localparam STATE_DONE       = 3'd5;
    
    // Protocol constants
    localparam ETHERTYPE_IPV4   = 16'h0800;
    localparam ETHERTYPE_IPV6   = 16'h86DD;
    localparam ETHERTYPE_VLAN   = 16'h8100;
    localparam IPPROTO_TCP      = 8'd6;
    localparam IPPROTO_UDP      = 8'd17;
    localparam UDP_PORT_VXLAN   = 16'd4789;
    
    // ==========================================
    // Main Parser State Machine
    // ==========================================
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            // Reset all outputs
            eth_valid       <= 1'b0;
            vlan_valid      <= 1'b0;
            ipv4_valid      <= 1'b0;
            ipv6_valid      <= 1'b0;
            tcp_valid       <= 1'b0;
            udp_valid       <= 1'b0;
            vxlan_valid     <= 1'b0;
            payload_valid   <= 1'b0;
            s_axis_tready   <= 1'b0;
            parse_state     <= STATE_IDLE;
            byte_offset     <= 11'd0;
            
        end else begin
            case (parse_state)
                
                // ==========================================
                STATE_IDLE: begin
                    s_axis_tready <= 1'b1;
                    if (s_axis_tvalid && s_axis_tready) begin
                        packet_buffer <= s_axis_tdata;
                        byte_offset   <= 11'd0;
                        
                        // Clear all valid flags
                        eth_valid     <= 1'b0;
                        vlan_valid    <= 1'b0;
                        ipv4_valid    <= 1'b0;
                        ipv6_valid    <= 1'b0;
                        tcp_valid     <= 1'b0;
                        udp_valid     <= 1'b0;
                        vxlan_valid   <= 1'b0;
                        payload_valid <= 1'b0;
                        
                        parse_state   <= STATE_ETHERNET;
                    end
                end
                
                // ==========================================
                STATE_ETHERNET: begin
                    if (PARSE_ETHERNET) begin
                        // Parse Ethernet header (14 bytes)
                        eth_dst_addr   <= packet_buffer[47:0];
                        eth_src_addr   <= packet_buffer[95:48];
                        eth_ether_type <= packet_buffer[111:96];
                        eth_valid      <= 1'b1;
                        byte_offset    <= 11'd14;
                        
                        // Check for VLAN tag
                        if (packet_buffer[111:96] == ETHERTYPE_VLAN && PARSE_VLAN) begin
                            vlan_pcp        <= packet_buffer[114:112];
                            vlan_dei        <= packet_buffer[115];
                            vlan_vid        <= packet_buffer[127:116];
                            vlan_ether_type <= packet_buffer[143:128];
                            vlan_valid      <= 1'b1;
                            byte_offset     <= byte_offset + 11'd4;
                        end else begin
                            vlan_valid <= 1'b0;
                        end
                        
                        parse_state <= STATE_L3;
                    end else begin
                        eth_valid   <= 1'b0;
                        parse_state <= STATE_L3;
                    end
                end
                
                // ==========================================
                STATE_L3: begin
                    if (PARSE_IPV4 && 
                        ((vlan_valid && vlan_ether_type == ETHERTYPE_IPV4) ||
                         (!vlan_valid && eth_ether_type == ETHERTYPE_IPV4))) begin
                        
                        // Parse IPv4 header (20 bytes minimum)
                        ipv4_version        <= packet_buffer[byte_offset*8 +: 4];
                        ipv4_ihl            <= packet_buffer[byte_offset*8+4 +: 4];
                        ipv4_tos            <= packet_buffer[byte_offset*8+8 +: 8];
                        ipv4_total_len      <= packet_buffer[byte_offset*8+16 +: 16];
                        ipv4_identification <= packet_buffer[byte_offset*8+32 +: 16];
                        ipv4_flags          <= packet_buffer[byte_offset*8+48 +: 3];
                        ipv4_frag_offset    <= packet_buffer[byte_offset*8+51 +: 13];
                        ipv4_ttl            <= packet_buffer[byte_offset*8+64 +: 8];
                        ipv4_protocol       <= packet_buffer[byte_offset*8+72 +: 8];
                        ipv4_hdr_checksum   <= packet_buffer[byte_offset*8+80 +: 16];
                        ipv4_src_addr       <= packet_buffer[byte_offset*8+96 +: 32];
                        ipv4_dst_addr       <= packet_buffer[byte_offset*8+128 +: 32];
                        ipv4_valid          <= 1'b1;
                        
                        byte_offset <= byte_offset + 11'd20;
                        parse_state <= STATE_L4;
                        
                    end else if (PARSE_IPV6 && 
                                 ((vlan_valid && vlan_ether_type == ETHERTYPE_IPV6) ||
                                  (!vlan_valid && eth_ether_type == ETHERTYPE_IPV6))) begin
                        
                        // Parse IPv6 header (40 bytes)
                        ipv6_version       <= packet_buffer[byte_offset*8 +: 4];
                        ipv6_traffic_class <= packet_buffer[byte_offset*8+4 +: 8];
                        ipv6_flow_label    <= packet_buffer[byte_offset*8+12 +: 20];
                        ipv6_payload_len   <= packet_buffer[byte_offset*8+32 +: 16];
                        ipv6_next_hdr      <= packet_buffer[byte_offset*8+48 +: 8];
                        ipv6_hop_limit     <= packet_buffer[byte_offset*8+56 +: 8];
                        ipv6_src_addr      <= packet_buffer[byte_offset*8+64 +: 128];
                        ipv6_dst_addr      <= packet_buffer[byte_offset*8+192 +: 128];
                        ipv6_valid         <= 1'b1;
                        
                        byte_offset <= byte_offset + 11'd40;
                        parse_state <= STATE_L4;
                        
                    end else begin
                        ipv4_valid  <= 1'b0;
                        ipv6_valid  <= 1'b0;
                        parse_state <= STATE_PAYLOAD;
                    end
                end
                
                // ==========================================
                STATE_L4: begin
                    if (PARSE_TCP && ipv4_valid && ipv4_protocol == IPPROTO_TCP) begin
                        // Parse TCP header (20 bytes minimum)
                        tcp_src_port    <= packet_buffer[byte_offset*8 +: 16];
                        tcp_dst_port    <= packet_buffer[byte_offset*8+16 +: 16];
                        tcp_seq_no      <= packet_buffer[byte_offset*8+32 +: 32];
                        tcp_ack_no      <= packet_buffer[byte_offset*8+64 +: 32];
                        tcp_data_offset <= packet_buffer[byte_offset*8+96 +: 4];
                        tcp_reserved    <= packet_buffer[byte_offset*8+100 +: 3];
                        tcp_flags       <= packet_buffer[byte_offset*8+103 +: 9];
                        tcp_window      <= packet_buffer[byte_offset*8+112 +: 16];
                        tcp_checksum    <= packet_buffer[byte_offset*8+128 +: 16];
                        tcp_urgent_ptr  <= packet_buffer[byte_offset*8+144 +: 16];
                        tcp_valid       <= 1'b1;
                        
                        byte_offset <= byte_offset + 11'd20;
                        parse_state <= STATE_PAYLOAD;
                        
                    end else if (PARSE_UDP && ipv4_valid && ipv4_protocol == IPPROTO_UDP) begin
                        // Parse UDP header (8 bytes)
                        udp_src_port <= packet_buffer[byte_offset*8 +: 16];
                        udp_dst_port <= packet_buffer[byte_offset*8+16 +: 16];
                        udp_length   <= packet_buffer[byte_offset*8+32 +: 16];
                        udp_checksum <= packet_buffer[byte_offset*8+48 +: 16];
                        udp_valid    <= 1'b1;
                        
                        byte_offset <= byte_offset + 11'd8;
                        
                        // Check for VXLAN
                        if (PARSE_VXLAN && udp_dst_port == UDP_PORT_VXLAN) begin
                            vxlan_flags     <= packet_buffer[byte_offset*8+64 +: 8];
                            vxlan_reserved  <= packet_buffer[byte_offset*8+72 +: 24];
                            vxlan_vni       <= packet_buffer[byte_offset*8+96 +: 24];
                            vxlan_reserved2 <= packet_buffer[byte_offset*8+120 +: 8];
                            vxlan_valid     <= 1'b1;
                            byte_offset     <= byte_offset + 11'd8;
                        end
                        
                        parse_state <= STATE_PAYLOAD;
                        
                    end else begin
                        tcp_valid   <= 1'b0;
                        udp_valid   <= 1'b0;
                        parse_state <= STATE_PAYLOAD;
                    end
                end
                
                // ==========================================
                STATE_PAYLOAD: begin
                    // Forward remaining packet as payload
                    payload_data  <= packet_buffer >> (byte_offset * 8);
                    payload_keep  <= s_axis_tkeep;
                    payload_valid <= 1'b1;
                    payload_last  <= s_axis_tlast;
                    
                    packet_length <= ipv4_valid ? ipv4_total_len : 
                                     ipv6_valid ? ipv6_payload_len : 16'd0;
                    
                    parse_state <= STATE_DONE;
                end
                
                // ==========================================
                STATE_DONE: begin
                    payload_valid <= 1'b0;
                    parse_state   <= STATE_IDLE;
                end
                
            endcase
        end
    end

endmodule