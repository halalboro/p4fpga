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
    
    // Custom headers from parser
    wire [7:0]   probe_hop_cnt;
    wire         probe_valid;
    wire [0:0]   probe_data_bos [0:9];
    wire [6:0]   probe_data_swid [0:9];
    wire [7:0]   probe_data_port [0:9];
    wire [31:0]  probe_data_byte_cnt [0:9];
    wire [47:0]  probe_data_last_time [0:9];
    wire [47:0]  probe_data_cur_time [0:9];
    wire         probe_data_valid [0:9];
    wire [7:0]   probe_fwd_egress_spec [0:9];
    wire         probe_fwd_valid [0:9];
    
    // Payload from parser
    wire [DATA_WIDTH-1:0] payload_data;
    wire [KEEP_WIDTH-1:0] payload_keep;
    wire                  payload_valid;
    wire                  payload_last;
    wire [15:0]           packet_length;
    wire [8:0]            ingress_port;
    
    // ==========================================
    // Stack Pointers (feedback from match_action)
    // ==========================================
    logic [3:0] probe_data_ptr;
    logic [3:0] probe_data_ptr_next;
    logic [3:0] probe_fwd_ptr;
    logic [3:0] probe_fwd_ptr_next;
    
    // Register stack pointer feedback
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn) begin
            probe_data_ptr <= 4'd0;
            probe_fwd_ptr <= 4'd0;
        end else begin
            probe_data_ptr <= probe_data_ptr_next;
            probe_fwd_ptr <= probe_fwd_ptr_next;
        end
    end
    
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

    // ==========================================
    // Table Programming Signals
    // ==========================================
    logic        table_wr_en;
    logic [9:0]  table_wr_addr;
    logic        table_entry_valid;
    logic [31:0] table_entry_prefix;
    logic [5:0]  table_entry_prefix_len;
    logic [2:0]  table_entry_action;
    logic [47:0] table_entry_dst_mac;
    logic [8:0]  table_entry_egress_port;
    
    // Pipeline outputs for custom headers
    wire [7:0]   pipeline_probe_hop_cnt;
    wire         pipeline_probe_valid;
    wire [0:0]   pipeline_probe_data_bos [0:9];
    wire [6:0]   pipeline_probe_data_swid [0:9];
    wire [7:0]   pipeline_probe_data_port [0:9];
    wire [31:0]  pipeline_probe_data_byte_cnt [0:9];
    wire [47:0]  pipeline_probe_data_last_time [0:9];
    wire [47:0]  pipeline_probe_data_cur_time [0:9];
    wire         pipeline_probe_data_valid [0:9];
    wire [7:0]   pipeline_probe_fwd_egress_spec [0:9];
    wire         pipeline_probe_fwd_valid [0:9];

    // Statistics
    wire [31:0] packet_count;
    wire [31:0] dropped_count;
    wire [31:0] forwarded_count;
    
    // Egress port delayed (as in generated code)
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
        .PARSER_CONFIG(8'b10000101)
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
        .ipv4_identification(), 
        .ipv4_flags(), 
        .ipv4_frag_offset(),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(),
        .ipv4_src_addr(ipv4_src_addr),
        .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),
        
        // IPv6 (unused)
        .ipv6_version(), .ipv6_traffic_class(), .ipv6_flow_label(),
        .ipv6_payload_len(), .ipv6_next_hdr(), .ipv6_hop_limit(),
        .ipv6_src_addr(), .ipv6_dst_addr(), .ipv6_valid(),
        
        // TCP (unused)
        .tcp_src_port(), .tcp_dst_port(), .tcp_seq_no(), .tcp_ack_no(),
        .tcp_data_offset(), .tcp_reserved(), .tcp_flags(), .tcp_window(),
        .tcp_checksum(), .tcp_urgent_ptr(), .tcp_valid(),
        
        // UDP (unused)
        .udp_src_port(), .udp_dst_port(), .udp_length(), 
        .udp_checksum(), .udp_valid(),
        
        // VXLAN (unused)
        .vxlan_flags(), .vxlan_reserved(), .vxlan_vni(), 
        .vxlan_reserved2(), .vxlan_valid(),
        
        // Custom headers
        .probe_hop_cnt(probe_hop_cnt),
        .probe_valid(probe_valid),
        .probe_data_bos(probe_data_bos),
        .probe_data_byte_cnt(probe_data_byte_cnt),
        .probe_data_cur_time(probe_data_cur_time),
        .probe_data_last_time(probe_data_last_time),
        .probe_data_port(probe_data_port),
        .probe_data_swid(probe_data_swid),
        .probe_data_valid(probe_data_valid),
        .probe_fwd_egress_spec(probe_fwd_egress_spec),
        .probe_fwd_valid(probe_fwd_valid),
        
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
        .METADATA_WIDTH(8),
        .TABLE_SIZE(1024),
        .KEY_WIDTH(32),
        .ACTION_DATA_WIDTH(128),
        .ACTION_CONFIG(8'b00000111),
        .EGRESS_CONFIG(8'b00100101),  // ENABLE_EGRESS | ENABLE_STATEFUL | ENABLE_PUSH_FRONT
        .ECN_THRESHOLD(19'd10),
        .NUM_REGISTERS(1024)
    ) match_action_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        
        // Metadata
        .metadata_in(8'd0),
        .metadata_out(),
        
        // Stack pointer feedback
        .probe_data_ptr_in(probe_data_ptr),
        .probe_data_ptr_out(probe_data_ptr_next),
        .probe_fwd_ptr_in(probe_fwd_ptr),
        .probe_fwd_ptr_out(probe_fwd_ptr_next),
        
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
        .ipv4_src_port(16'd0),
        .ipv4_dst_port(16'd0),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_diffserv(ipv4_diffserv),
        .ipv4_ecn(ipv4_ecn),
        
        // Custom headers (single header + stacks)
        .probe_hop_cnt(probe_hop_cnt),
        .probe_valid(probe_valid),
        .probe_data_bos(probe_data_bos),
        .probe_data_byte_cnt(probe_data_byte_cnt),
        .probe_data_cur_time(probe_data_cur_time),
        .probe_data_last_time(probe_data_last_time),
        .probe_data_port(probe_data_port),
        .probe_data_swid(probe_data_swid),
        .probe_data_valid(probe_data_valid),
        .probe_fwd_egress_spec(probe_fwd_egress_spec),
        .probe_fwd_valid(probe_fwd_valid),
        
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
        .packet_ready_in(1'b1),
        
        // Pipeline custom header outputs
        .out_probe_hop_cnt(pipeline_probe_hop_cnt),
        .out_probe_valid(pipeline_probe_valid),
        .out_probe_data_bos(pipeline_probe_data_bos),
        .out_probe_data_byte_cnt(pipeline_probe_data_byte_cnt),
        .out_probe_data_cur_time(pipeline_probe_data_cur_time),
        .out_probe_data_last_time(pipeline_probe_data_last_time),
        .out_probe_data_port(pipeline_probe_data_port),
        .out_probe_data_swid(pipeline_probe_data_swid),
        .out_probe_data_valid(pipeline_probe_data_valid),
        .out_probe_fwd_egress_spec(pipeline_probe_fwd_egress_spec),
        .out_probe_fwd_valid(pipeline_probe_fwd_valid),
        
        // Modified header outputs
        .out_ipv4_diffserv(ma_ipv4_diffserv),
        .out_ipv4_ecn(ma_ipv4_ecn),
        .out_ipv4_ttl(ma_ipv4_ttl),
        .out_eth_dst_addr(),
        .out_eth_src_addr(),

        // Control outputs
        .drop(ma_drop),
        .egress_port(ma_egress_port),
        .header_modified(ma_header_modified),
        .ecn_marked(ma_ecn_marked),
        
        // Table programming
        .table_write_enable(table_wr_en),
        .table_write_addr(table_wr_addr),
        .table_entry_valid(table_entry_valid),
        .table_entry_key(table_entry_prefix),
        .table_entry_prefix_len(table_entry_prefix_len),
        .table_entry_action(table_entry_action),
        // action_data format: [103:96]=egress_port, [95:48]=src_mac, [47:0]=dst_mac
        .table_entry_action_data({24'd0, table_entry_egress_port[7:0], 48'haabbccddeeff, table_entry_dst_mac}),
        
        // Statistics
        .packet_count(packet_count),
        .dropped_count(dropped_count),
        .forwarded_count(forwarded_count)
    );
    
    // ==========================================
    // Test Tasks
    // ==========================================

    // Configure routing table entry
    task automatic configure_route(
        input [9:0]  addr,
        input [31:0] prefix,
        input [5:0]  prefix_len,
        input [2:0]  action,
        input [47:0] dst_mac,
        input [8:0]  port
    );
        begin
            @(posedge aclk);
            table_wr_en           <= 1'b1;
            table_wr_addr         <= addr;
            table_entry_valid     <= 1'b1;
            table_entry_prefix    <= prefix;
            table_entry_prefix_len <= prefix_len;
            table_entry_action    <= action;
            table_entry_dst_mac   <= dst_mac;
            table_entry_egress_port <= port;
            @(posedge aclk);
            table_wr_en <= 1'b0;
            $display("[%0t] Configured route: %h/%0d -> port %0d (action=%0d)",
                     $time, prefix, prefix_len, port, action);
        end
    endtask

    // Send standard IPv4 packet
    task automatic send_ipv4_packet(input [31:0] dst_ip, input [15:0] pkt_len);
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
            s_axis_tdata[143:128] = {pkt_len[7:0], pkt_len[15:8]};  // total length (network byte order)
            s_axis_tdata[159:144] = 16'h1234;          // identification
            s_axis_tdata[175:160] = 16'h4000;          // flags + frag offset
            s_axis_tdata[183:176] = 8'd64;             // TTL
            s_axis_tdata[191:184] = 8'd6;              // protocol (TCP)
            s_axis_tdata[207:192] = 16'h0000;          // checksum
            s_axis_tdata[239:208] = 32'hC0A80101;      // src IP
            s_axis_tdata[271:240] = dst_ip;            // dst IP
            
            s_axis_tkeep  = {KEEP_WIDTH{1'b1}};
            s_axis_tvalid = 1'b1;
            s_axis_tlast  = 1'b1;
            
            @(posedge aclk);
            while (!s_axis_tready) @(posedge aclk);
            s_axis_tvalid = 1'b0;
            s_axis_tlast  = 1'b0;
            
            $display("[%0t] Sent IPv4 packet: dst=%h, len=%0d", $time, dst_ip, pkt_len);
        end
    endtask
    
    // Send probe packet (triggers egress byte counting)
    task automatic send_probe_packet(input [7:0] hop_cnt);
        begin
            @(posedge aclk);
            s_axis_tdata = '0;
            
            // Ethernet header
            s_axis_tdata[47:0]    = 48'h001122334455;   // dst MAC
            s_axis_tdata[95:48]   = 48'haabbccddeeff;   // src MAC
            s_axis_tdata[111:96]  = 16'h0812;           // EtherType: Probe (0x0812)
            
            // Probe header (1 byte: hop_cnt)
            s_axis_tdata[119:112] = hop_cnt;
            
            s_axis_tkeep  = {KEEP_WIDTH{1'b1}};
            s_axis_tvalid = 1'b1;
            s_axis_tlast  = 1'b1;
            
            @(posedge aclk);
            while (!s_axis_tready) @(posedge aclk);
            s_axis_tvalid = 1'b0;
            s_axis_tlast  = 1'b0;
            
            $display("[%0t] Sent Probe packet: hop_cnt=%0d", $time, hop_cnt);
        end
    endtask
    
    // ==========================================
    // Test Sequence
    // ==========================================
    initial begin
        $display("========================================");
        $display("  Link Monitor Testbench");
        $display("  Testing egress byte counting");
        $display("========================================");

        // Initialize
        aresetn = 0;
        s_axis_tdata = '0;
        s_axis_tkeep = '0;
        s_axis_tvalid = 0;
        s_axis_tlast = 0;

        // Initialize table programming signals
        table_wr_en = 0;
        table_wr_addr = 0;
        table_entry_valid = 0;
        table_entry_prefix = 0;
        table_entry_prefix_len = 0;
        table_entry_action = 0;
        table_entry_dst_mac = 0;
        table_entry_egress_port = 0;

        repeat(10) @(posedge aclk);
        aresetn = 1;
        $display("[%0t] Reset released", $time);
        repeat(5) @(posedge aclk);

        // ========================================
        // Configure Routing Table
        // ========================================
        $display("\n[Setup] Configuring routing table...");
        // Route for 10.0.0.0/8 -> forward to port 1
        // Prefix in little-endian format to match parser output
        configure_route(
            .addr(0),
            .prefix(32'h0000000A),    // 10.0.0.0 in little-endian
            .prefix_len(8),
            .action(3'd0),            // ipv4_forward
            .dst_mac(48'h001122334455),
            .port(1)
        );

        // Route for 192.168.1.0/24 -> forward to port 2
        // Prefix in little-endian format to match parser output
        configure_route(
            .addr(1),
            .prefix(32'h0001A8C0),    // 192.168.1.0 in little-endian
            .prefix_len(24),
            .action(3'd0),            // ipv4_forward
            .dst_mac(48'hAABBCCDDEEFF),
            .port(2)
        );

        repeat(5) @(posedge aclk);

        // ========================================
        // Phase 1: Accumulate bytes (100+200+150=450)
        // ========================================
        $display("\n[Phase 1] Sending 3 IPv4 packets to accumulate bytes");
        send_ipv4_packet(32'h0A000001, 16'd100);
        repeat(20) @(posedge aclk);
        
        send_ipv4_packet(32'h0A000001, 16'd200);
        repeat(20) @(posedge aclk);
        
        send_ipv4_packet(32'h0A000001, 16'd150);
        repeat(20) @(posedge aclk);
        
        $display("  Expected byte_cnt: 450");
        
        // ========================================
        // Phase 2: Probe triggers capture
        // Per P4: hop_cnt is incremented in ingress, BOS=1 when new_hop_cnt==1
        // ========================================
        $display("\n[Phase 2] Sending probe (hop_cnt=0) - should capture byte_cnt=450, BOS=1");
        send_probe_packet(8'd0);
        repeat(40) @(posedge aclk);
        
        // ========================================
        // Phase 3: New accumulation (300+250=550)
        // ========================================
        $display("\n[Phase 3] Sending 2 more IPv4 packets");
        send_ipv4_packet(32'h0A000002, 16'd300);
        repeat(20) @(posedge aclk);
        
        send_ipv4_packet(32'h0A000002, 16'd250);
        repeat(20) @(posedge aclk);
        
        $display("  Expected byte_cnt: 550");
        
        // ========================================
        // Phase 4: Second probe
        // Per P4: hop_cnt=1 arrives, incremented to 2, BOS=0 (not first hop)
        // ========================================
        $display("\n[Phase 4] Sending probe (hop_cnt=1) - should capture byte_cnt=550, BOS=0");
        send_probe_packet(8'd1);
        repeat(40) @(posedge aclk);
        
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
            $display("[%0t] Parser: ipv4=%b probe=%b hop_cnt=%0d pkt_len=%0d", 
                     $time, ipv4_valid, probe_valid, probe_hop_cnt, packet_length);
        end
    end
    
    // ==========================================
    // Monitor: Match-action output
    // ==========================================
    always @(posedge aclk) begin
        if (ma_packet_valid) begin
            $display("[%0t] Match-Action: drop=%b egress_port=%0d ecn_marked=%b match_hit=%b action_id=%0d",
                     $time, ma_drop, ma_egress_port, ma_ecn_marked,
                     match_action_inst.match_hit, match_action_inst.match_action_id);
        end
    end

    // Debug: Monitor match module internals
    always @(posedge aclk) begin
        if (match_action_inst.match_valid) begin
            $display("[%0t] Match DEBUG: lookup_key=%h match_hit=%b action_id=%0d",
                     $time, match_action_inst.match_inst.lookup_key_d1,
                     match_action_inst.match_hit, match_action_inst.match_action_id);
        end
    end
    
    // ==========================================
    // Waveform dump
    // ==========================================
    initial begin
        $dumpfile("tb_link_monitor.vcd");
        $dumpvars(0, tb_user);
    end

endmodule