`timescale 1ns / 1ps

module tb_user;

    // ==========================================
    // Parameters
    // ==========================================
    parameter DATA_WIDTH = 512;
    parameter KEEP_WIDTH = DATA_WIDTH/8;
    parameter CLK_PERIOD = 10;
    
    // ==========================================
    // Clock and Reset
    // ==========================================
    logic aclk;
    logic aresetn;
    
    initial begin
        aclk = 0;
        forever #(CLK_PERIOD/2) aclk = ~aclk;
    end
    
    // ==========================================
    // Parser Interface
    // ==========================================
    logic [DATA_WIDTH-1:0]     s_axis_tdata;
    logic [KEEP_WIDTH-1:0]     s_axis_tkeep;
    logic                      s_axis_tvalid;
    logic                      s_axis_tlast;
    wire                       s_axis_tready;
    
    // ==========================================
    // Parser Outputs
    // ==========================================
    wire [47:0]  eth_dst_addr, eth_src_addr;
    wire [15:0]  eth_ether_type;
    wire         eth_valid;
    wire [3:0]   ipv4_version, ipv4_ihl;
    wire [7:0]   ipv4_ttl, ipv4_protocol;
    wire [31:0]  ipv4_src_addr, ipv4_dst_addr;
    wire [5:0]   ipv4_diffserv;
    wire [1:0]   ipv4_ecn;
    wire         ipv4_valid;
    wire [15:0]  ipv4_total_len;
    wire [15:0]  ipv4_identification;
    wire [2:0]   ipv4_flags;
    wire [12:0]  ipv4_frag_offset;
    wire [15:0]  ipv4_hdr_checksum;
    wire [15:0]  tcp_src_port, tcp_dst_port;
    wire [31:0]  tcp_seq_no, tcp_ack_no;
    wire [3:0]   tcp_data_offset;
    wire [2:0]   tcp_reserved;
    wire [8:0]   tcp_flags;
    wire [15:0]  tcp_window;
    wire [15:0]  tcp_checksum;
    wire [15:0]  tcp_urgent_ptr;
    wire         tcp_valid;
    
    // Payload from parser
    wire [DATA_WIDTH-1:0] payload_data;
    wire [KEEP_WIDTH-1:0] payload_keep;
    wire                  payload_valid;
    wire                  payload_last;
    wire [15:0]           packet_length;
    wire [8:0]            ingress_port;
    
    // ==========================================
    // Match-Action Outputs
    // ==========================================
    wire [DATA_WIDTH-1:0] ma_packet_out;
    wire [KEEP_WIDTH-1:0] ma_packet_keep;
    wire                  ma_packet_last;
    wire                  ma_packet_valid;
    wire                  ma_drop;
    wire [8:0]            ma_egress_port;
    wire [5:0]            ma_ipv4_diffserv;
    wire [1:0]            ma_ipv4_ecn;
    wire [7:0]            ma_ipv4_ttl;
    wire                  ma_ecn_marked;
    wire                  ma_header_modified;
    wire [47:0]           ma_eth_dst_addr;
    wire [47:0]           ma_eth_src_addr;
    wire                  ma_packet_ready;

    // ==========================================
    // Table Programming Signals
    // ==========================================
    logic                 table_write_enable;
    logic [9:0]           table_write_addr;
    logic                 table_entry_valid;
    logic [31:0]          table_entry_prefix;
    logic [5:0]           table_entry_prefix_len;
    logic [2:0]           table_entry_action;
    logic [127:0]         table_entry_action_data;

    // ==========================================
    // Deparser Outputs
    // ==========================================
    wire [DATA_WIDTH-1:0] deparser_data;
    wire [KEEP_WIDTH-1:0] deparser_keep;
    wire                  deparser_valid;
    wire                  deparser_last;
    wire                  deparser_ready;

    // Statistics
    wire [31:0] packet_count;
    wire [31:0] dropped_count;
    wire [31:0] forwarded_count;
    
    // Egress port delayed
    logic [8:0] egress_port_d;
    always_ff @(posedge aclk) begin
        egress_port_d <= ma_egress_port;
    end
    
    // ==========================================
    // Parser Instance
    // ==========================================
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .KEEP_WIDTH(KEEP_WIDTH),
        .PARSER_CONFIG(8'b00010101)  // Ethernet + IPv4 + TCP
    ) parser_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tkeep(s_axis_tkeep),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tlast(s_axis_tlast),
        .s_axis_tready(s_axis_tready),
        
        // Ethernet
        .eth_dst_addr(eth_dst_addr),
        .eth_src_addr(eth_src_addr),
        .eth_ether_type(eth_ether_type),
        .eth_valid(eth_valid),
        
        // VLAN (unused)
        .vlan_pcp(), .vlan_dei(), .vlan_vid(), 
        .vlan_ether_type(), .vlan_valid(),
        
        // IPv4
        .ipv4_version(ipv4_version),
        .ipv4_ihl(ipv4_ihl),
        .ipv4_diffserv(ipv4_diffserv),
        .ipv4_ecn(ipv4_ecn),
        .ipv4_total_len(ipv4_total_len),
        .ipv4_identification(ipv4_identification),
        .ipv4_flags(ipv4_flags),
        .ipv4_frag_offset(ipv4_frag_offset),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(ipv4_hdr_checksum),
        .ipv4_src_addr(ipv4_src_addr),
        .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),
        
        // IPv6 (unused)
        .ipv6_version(), .ipv6_traffic_class(), .ipv6_flow_label(),
        .ipv6_payload_len(), .ipv6_next_hdr(), .ipv6_hop_limit(),
        .ipv6_src_addr(), .ipv6_dst_addr(), .ipv6_valid(),
        
        // TCP
        .tcp_src_port(tcp_src_port),
        .tcp_dst_port(tcp_dst_port),
        .tcp_seq_no(tcp_seq_no),
        .tcp_ack_no(tcp_ack_no),
        .tcp_data_offset(tcp_data_offset),
        .tcp_reserved(tcp_reserved),
        .tcp_flags(tcp_flags),
        .tcp_window(tcp_window),
        .tcp_checksum(tcp_checksum),
        .tcp_urgent_ptr(tcp_urgent_ptr),
        .tcp_valid(tcp_valid),
        
        // UDP (unused)
        .udp_src_port(), .udp_dst_port(), .udp_length(), 
        .udp_checksum(), .udp_valid(),
        
        // VXLAN (unused)
        .vxlan_flags(), .vxlan_reserved(), .vxlan_vni(), 
        .vxlan_reserved2(), .vxlan_valid(),
        
        // Payload
        .payload_data(payload_data),
        .payload_keep(payload_keep),
        .payload_valid(payload_valid),
        .payload_last(payload_last),
        .packet_length(packet_length),
        .ingress_port(ingress_port)
    );
    
    // ==========================================
    // Match-Action Instance
    // ==========================================
    match_action #(
        .DATA_WIDTH(DATA_WIDTH),
        .METADATA_WIDTH(14),          // ecmp_select is 14 bits
        .TABLE_SIZE(1024),
        .KEY_WIDTH(32),
        .ACTION_DATA_WIDTH(128),
        .ACTION_CONFIG(8'b00000111),  // FORWARD, DROP, MODIFY_HEADER
        .EGRESS_CONFIG(8'b00000000),  // No egress processing
        .ECN_THRESHOLD(19'd10),
        .NUM_REGISTERS(1024)
    ) match_action_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        
        // Metadata
        .metadata_in(14'd0),
        .metadata_out(),
        
        // Packet input
        .packet_in(payload_data),
        .packet_keep_in(payload_keep),
        .packet_last_in(payload_last),
        .packet_valid_in(payload_valid),
        .packet_ready_out(),
        
        // Header fields
        .ipv4_valid(ipv4_valid),
        .eth_dst_addr(eth_dst_addr),
        .eth_src_addr(eth_src_addr),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_src_addr(ipv4_src_addr),
        .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_src_port(tcp_src_port),
        .ipv4_dst_port(tcp_dst_port),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_diffserv(ipv4_diffserv),
        .ipv4_ecn(ipv4_ecn),
        
        // Control inputs
        .packet_length(packet_length),
        .ingress_port_in(9'd1),
        .mcast_grp(),
        .enq_qdepth(19'd5),
        .egress_port_id(egress_port_d),
        
        // Packet output
        .packet_out(ma_packet_out),
        .packet_keep_out(ma_packet_keep),
        .packet_last_out(ma_packet_last),
        .packet_valid_out(ma_packet_valid),
        .packet_ready_in(deparser_ready),
        
        // Modified header outputs
        .out_ipv4_diffserv(ma_ipv4_diffserv),
        .out_ipv4_ecn(ma_ipv4_ecn),
        .out_ipv4_ttl(ma_ipv4_ttl),
        
        // Control outputs
        .drop(ma_drop),
        .egress_port(ma_egress_port),
        .header_modified(ma_header_modified),
        .ecn_marked(ma_ecn_marked),
        
        // Modified Ethernet outputs
        .out_eth_dst_addr(ma_eth_dst_addr),
        .out_eth_src_addr(ma_eth_src_addr),

        // Table programming interface
        .table_write_enable(table_write_enable),
        .table_write_addr(table_write_addr),
        .table_entry_valid(table_entry_valid),
        .table_entry_key(table_entry_prefix),
        .table_entry_prefix_len(table_entry_prefix_len),
        .table_entry_action(table_entry_action),
        .table_entry_action_data(table_entry_action_data),
        
        // Statistics
        .packet_count(packet_count),
        .dropped_count(dropped_count),
        .forwarded_count(forwarded_count)
    );

    // ==========================================
    // Deparser Instance
    // ==========================================
    deparser #(
        .DATA_WIDTH(DATA_WIDTH),
        .KEEP_WIDTH(KEEP_WIDTH),
        .DEPARSER_CONFIG(16'h0095)  // Eth + IPv4 + TCP + checksum
    ) deparser_inst (
        .aclk(aclk),
        .aresetn(aresetn),

        // Ethernet inputs (modified by match_action)
        .eth_dst_addr(ma_eth_dst_addr),
        .eth_src_addr(ma_eth_src_addr),
        .eth_ether_type(eth_ether_type),
        .eth_valid(eth_valid),

        // VLAN inputs (unused)
        .vlan_pcp(3'b0),
        .vlan_dei(1'b0),
        .vlan_vid(12'b0),
        .vlan_ether_type(16'b0),
        .vlan_valid(1'b0),

        // IPv4 inputs (mix of pass-through and modified fields)
        .ipv4_version(ipv4_version),
        .ipv4_ihl(ipv4_ihl),
        .ipv4_diffserv(ma_ipv4_diffserv),   // Modified by match_action
        .ipv4_ecn(ma_ipv4_ecn),             // Modified by match_action
        .ipv4_total_len(ipv4_total_len),
        .ipv4_identification(ipv4_identification),
        .ipv4_flags(ipv4_flags),
        .ipv4_frag_offset(ipv4_frag_offset),
        .ipv4_ttl(ma_ipv4_ttl),             // Modified by match_action
        .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(ipv4_hdr_checksum),
        .ipv4_src_addr(ipv4_src_addr),
        .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),

        // IPv6 inputs (unused)
        .ipv6_version(4'b0),
        .ipv6_traffic_class(8'b0),
        .ipv6_flow_label(20'b0),
        .ipv6_payload_len(16'b0),
        .ipv6_next_hdr(8'b0),
        .ipv6_hop_limit(8'b0),
        .ipv6_src_addr(128'b0),
        .ipv6_dst_addr(128'b0),
        .ipv6_valid(1'b0),

        // TCP inputs (pass through from parser)
        .tcp_src_port(tcp_src_port),
        .tcp_dst_port(tcp_dst_port),
        .tcp_seq_no(tcp_seq_no),
        .tcp_ack_no(tcp_ack_no),
        .tcp_data_offset(tcp_data_offset),
        .tcp_reserved(tcp_reserved),
        .tcp_flags(tcp_flags),
        .tcp_window(tcp_window),
        .tcp_checksum(tcp_checksum),
        .tcp_urgent_ptr(tcp_urgent_ptr),
        .tcp_valid(tcp_valid),

        // UDP inputs (unused)
        .udp_src_port(16'b0),
        .udp_dst_port(16'b0),
        .udp_length(16'b0),
        .udp_checksum(16'b0),
        .udp_valid(1'b0),

        // VXLAN inputs (unused)
        .vxlan_flags(8'b0),
        .vxlan_reserved(24'b0),
        .vxlan_vni(24'b0),
        .vxlan_reserved2(8'b0),
        .vxlan_valid(1'b0),

        // Payload input from pipeline
        .s_axis_tdata(ma_packet_out),
        .s_axis_tkeep(ma_packet_keep),
        .s_axis_tvalid(ma_packet_valid),
        .s_axis_tlast(ma_packet_last),
        .s_axis_tready(deparser_ready),

        // Control input
        .drop_packet(ma_drop),

        // External output
        .m_axis_tdata(deparser_data),
        .m_axis_tkeep(deparser_keep),
        .m_axis_tvalid(deparser_valid),
        .m_axis_tlast(deparser_last),
        .m_axis_tready(1'b1)  // Always ready in testbench
    );

    // ==========================================
    // Test Tasks
    // ==========================================

    // Program LPM table entry for routing
    // action: 0=forward, 1=drop, 2=modify_header
    // action_data format: [47:0]=dmac, [95:48]=smac, [103:96]=egress_port
    task automatic program_lpm_entry(
        input [9:0]   addr,
        input [31:0]  prefix,
        input [5:0]   prefix_len,
        input [2:0]   action_id,
        input [127:0] action_data
    );
        begin
            @(posedge aclk);
            table_write_enable     = 1'b1;
            table_write_addr       = addr;
            table_entry_valid      = 1'b1;
            table_entry_prefix     = prefix;
            table_entry_prefix_len = prefix_len;
            table_entry_action     = action_id;
            table_entry_action_data = action_data;
            @(posedge aclk);
            table_write_enable = 1'b0;
            @(posedge aclk);
        end
    endtask

    // Send TCP packet with specified 5-tuple
    task automatic send_tcp_packet(
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [15:0] src_port,
        input [15:0] dst_port,
        input [15:0] pkt_len
    );
        begin
            @(posedge aclk);
            s_axis_tdata = '0;
            
            // Ethernet header (14 bytes)
            s_axis_tdata[47:0]    = 48'h001122334455;   // dst MAC
            s_axis_tdata[95:48]   = 48'haabbccddeeff;   // src MAC
            s_axis_tdata[111:96]  = 16'h0800;           // EtherType: IPv4
            
            // IPv4 header (20 bytes, starting at byte 14)
            s_axis_tdata[115:112] = 4'h4;              // version
            s_axis_tdata[119:116] = 4'h5;              // IHL
            s_axis_tdata[125:120] = 6'd0;              // DSCP
            s_axis_tdata[127:126] = 2'b00;             // ECN
            s_axis_tdata[143:128] = pkt_len;           // total length
            s_axis_tdata[159:144] = 16'h1234;          // identification
            s_axis_tdata[175:160] = 16'h4000;          // flags + frag offset
            s_axis_tdata[183:176] = 8'd64;             // TTL
            s_axis_tdata[191:184] = 8'd6;              // protocol (TCP)
            s_axis_tdata[207:192] = 16'h0000;          // checksum
            s_axis_tdata[239:208] = src_ip;            // src IP
            s_axis_tdata[271:240] = dst_ip;            // dst IP
            
            // TCP header (20 bytes, starting at byte 34)
            s_axis_tdata[287:272] = src_port;          // src port
            s_axis_tdata[303:288] = dst_port;          // dst port
            s_axis_tdata[335:304] = 32'h00000001;      // seq no
            s_axis_tdata[367:336] = 32'h00000000;      // ack no
            s_axis_tdata[371:368] = 4'h5;              // data offset
            s_axis_tdata[374:372] = 3'b000;            // reserved
            s_axis_tdata[383:375] = 9'h002;            // flags (SYN)
            s_axis_tdata[399:384] = 16'hFFFF;          // window
            s_axis_tdata[415:400] = 16'h0000;          // checksum
            s_axis_tdata[431:416] = 16'h0000;          // urgent ptr
            
            s_axis_tkeep  = {KEEP_WIDTH{1'b1}};
            s_axis_tvalid = 1'b1;
            s_axis_tlast  = 1'b1;
            
            @(posedge aclk);
            while (!s_axis_tready) @(posedge aclk);
            s_axis_tvalid = 1'b0;
            s_axis_tlast  = 1'b0;
        end
    endtask
    
    // ==========================================
    // Test Sequence
    // ==========================================
    initial begin
        $display("========================================");
        $display("  Load Balance (ECMP) Testbench");
        $display("  Testing 5-tuple hash-based routing");
        $display("========================================");

        // Initialize
        aresetn = 0;
        s_axis_tdata = '0;
        s_axis_tkeep = '0;
        s_axis_tvalid = 0;
        s_axis_tlast = 0;

        // Initialize table programming signals
        table_write_enable = 1'b0;
        table_write_addr = 10'd0;
        table_entry_valid = 1'b0;
        table_entry_prefix = 32'd0;
        table_entry_prefix_len = 6'd0;
        table_entry_action = 3'd0;
        table_entry_action_data = 128'd0;

        repeat(10) @(posedge aclk);
        aresetn = 1;
        $display("[%0t] Reset released", $time);
        repeat(5) @(posedge aclk);

        // ========================================
        // Phase 0: Program LPM routing table
        // ========================================
        $display("\n[Phase 0] Programming LPM routing table");

        // Entry 0: 10.0.0.0/8 -> forward action (action=0)
        // action_data: dmac=00:11:22:33:44:55, smac=aa:bb:cc:dd:ee:ff, egress_port=1
        // Note: prefix in little-endian format (parser outputs little-endian IPs)
        program_lpm_entry(
            10'd0,                           // addr
            32'h0000000A,                    // prefix: 10.0.0.0 in little-endian
            6'd8,                            // prefix_len: /8
            3'd0,                            // action: forward
            {24'd0, 8'd1, 48'haabbccddeeff, 48'h001122334455}  // egress_port=1, smac, dmac
        );
        $display("[%0t] Programmed entry 0: 10.0.0.0/8 -> port 1", $time);

        // Entry 1: 192.168.1.0/24 -> forward action
        // Note: prefix in little-endian format
        program_lpm_entry(
            10'd1,                           // addr
            32'h0001A8C0,                    // prefix: 192.168.1.0 in little-endian
            6'd24,                           // prefix_len: /24
            3'd0,                            // action: forward
            {24'd0, 8'd2, 48'h112233445566, 48'h665544332211}  // egress_port=2, smac, dmac
        );
        $display("[%0t] Programmed entry 1: 192.168.1.0/24 -> port 2", $time);

        // Entry 2: Default route 0.0.0.0/0 -> forward to port 3
        program_lpm_entry(
            10'd2,                           // addr
            32'h00000000,                    // prefix: 0.0.0.0
            6'd0,                            // prefix_len: /0 (default)
            3'd0,                            // action: forward
            {24'd0, 8'd3, 48'h000000000003, 48'h000000000001}  // egress_port=3
        );
        $display("[%0t] Programmed entry 2: 0.0.0.0/0 (default) -> port 3", $time);

        repeat(5) @(posedge aclk);
        $display("[%0t] Table programming complete\n", $time);

        // ========================================
        // Phase 1: Same flow -> same egress port
        // ========================================
        $display("\n[Phase 1] Same flow (same 5-tuple) -> same egress port");
        
        // Send 3 packets with identical 5-tuple
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd1234, 16'd80, 16'd100);
        repeat(25) @(posedge aclk);
        
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd1234, 16'd80, 16'd100);
        repeat(25) @(posedge aclk);
        
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd1234, 16'd80, 16'd100);
        repeat(25) @(posedge aclk);
        
        // ========================================
        // Phase 2: Different flows -> potentially different ports
        // ========================================
        $display("\n[Phase 2] Different flows (different 5-tuples)");
        
        // Flow A: src_port=1000
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd1000, 16'd80, 16'd200);
        repeat(25) @(posedge aclk);
        
        // Flow B: src_port=2000
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd2000, 16'd80, 16'd200);
        repeat(25) @(posedge aclk);
        
        // Flow C: src_port=3000
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd3000, 16'd80, 16'd200);
        repeat(25) @(posedge aclk);
        
        // Flow D: src_port=4000
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd4000, 16'd80, 16'd200);
        repeat(25) @(posedge aclk);
        
        // ========================================
        // Phase 3: Different dst IPs
        // ========================================
        $display("\n[Phase 3] Different destination IPs");
        
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd5000, 16'd443, 16'd150);
        repeat(25) @(posedge aclk);
        
        send_tcp_packet(32'hC0A80101, 32'h0A000002, 16'd5000, 16'd443, 16'd150);
        repeat(25) @(posedge aclk);
        
        send_tcp_packet(32'hC0A80101, 32'h0A000003, 16'd5000, 16'd443, 16'd150);
        repeat(25) @(posedge aclk);
        
        send_tcp_packet(32'hC0A80101, 32'h0A000004, 16'd5000, 16'd443, 16'd150);
        repeat(25) @(posedge aclk);
        
        // ========================================
        // Phase 4: Verify flow affinity
        // ========================================
        $display("\n[Phase 4] Verify flow affinity (repeat Phase 1 flow)");
        
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd1234, 16'd80, 16'd100);
        repeat(25) @(posedge aclk);
        
        send_tcp_packet(32'hC0A80101, 32'h0A000001, 16'd1234, 16'd80, 16'd100);
        repeat(25) @(posedge aclk);
        
        // ========================================
        // Summary
        // ========================================
        repeat(30) @(posedge aclk);
        $display("\n========================================");
        $display("  Final Statistics");
        $display("========================================");
        $display("  Total packets:   %0d", packet_count);
        $display("  Dropped packets: %0d", dropped_count);
        $display("  Forwarded:       %0d", forwarded_count);
        $display("========================================\n");
        
        $finish;
    end
    
    // ==========================================
    // Monitor: Parser outputs
    // ==========================================
    always @(posedge aclk) begin
        if (payload_valid) begin
            $display("[%0t] Parser: ipv4=%b tcp=%b src=%h:%0d dst=%h:%0d", 
                     $time, ipv4_valid, tcp_valid,
                     ipv4_src_addr, tcp_src_port,
                     ipv4_dst_addr, tcp_dst_port);
        end
    end
    
    // ==========================================
    // Monitor: Match-action ECMP routing
    // ==========================================
    always @(posedge aclk) begin
        if (ma_packet_valid) begin
            $display("[%0t] ECMP: egress_port=%0d drop=%b ttl=%0d",
                     $time, ma_egress_port, ma_drop, ma_ipv4_ttl);
        end
    end

    // ==========================================
    // Monitor: Deparser output
    // ==========================================
    always @(posedge aclk) begin
        if (deparser_valid) begin
            $display("[%0t] Deparser: valid=%b last=%b",
                     $time, deparser_valid, deparser_last);
        end
    end
    
    // ==========================================
    // Waveform dump
    // ==========================================
    initial begin
        $dumpfile("tb_load_balance.vcd");
        $dumpvars(0, tb_user);
    end

endmodule