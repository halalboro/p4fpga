`timescale 1ns / 1ps

module tb_user;
    // Clock and reset
    logic aclk = 1'b1;
    logic aresetn = 1'b0;
    
    localparam CLK_PERIOD = 4ns;
    always #(CLK_PERIOD/2) aclk = ~aclk;
    
    initial begin
        aresetn = 1'b0;
        #100ns aresetn = 1'b1;
    end

    localparam DATA_WIDTH = 512;
    localparam KEEP_WIDTH = DATA_WIDTH/8;
    localparam [18:0] ECN_THRESHOLD = 19'd10;
    
    // AXI-Stream interfaces
    logic [DATA_WIDTH-1:0]   s_axis_tdata;
    logic [KEEP_WIDTH-1:0]   s_axis_tkeep;
    logic                    s_axis_tvalid;
    logic                    s_axis_tlast;
    logic                    s_axis_tready;
    
    logic [DATA_WIDTH-1:0]   m_axis_tdata;
    logic [KEEP_WIDTH-1:0]   m_axis_tkeep;
    logic                    m_axis_tvalid;
    logic                    m_axis_tlast;
    logic                    m_axis_tready;
    
    // Table programming
    logic        table_wr_en;
    logic [9:0]  table_wr_addr;
    logic        table_entry_valid;
    logic [31:0] table_entry_prefix;
    logic [5:0]  table_entry_prefix_len;
    logic [2:0]  table_entry_action;
    logic [47:0] table_entry_dst_mac;
    logic [8:0]  table_entry_egress_port;
    
    // Egress control - configurable queue depth
    logic [18:0] enq_qdepth;
    
    // Statistics
    logic [31:0] packet_count;
    logic [31:0] dropped_count;
    logic [31:0] forwarded_count;
    logic        ecn_marked;
    
    // Test tracking
    int packets_sent = 0;
    int packets_received = 0;
    int ecn_marked_count = 0;

    // ============================================
    // DUT Pipeline
    // ============================================
    
    // Parser signals
    logic        ethernet_valid;
    logic [47:0] eth_dst_addr, eth_src_addr;
    logic [15:0] eth_type;
    logic        ipv4_valid;
    logic [3:0]  ipv4_version, ipv4_ihl;
    logic [5:0]  ipv4_diffserv;
    logic [1:0]  ipv4_ecn;
    logic [15:0] ipv4_totalLen, ipv4_identification;
    logic [2:0]  ipv4_flags;
    logic [12:0] ipv4_fragOffset;
    logic [7:0]  ipv4_ttl, ipv4_protocol;
    logic [15:0] ipv4_hdrChecksum;
    logic [31:0] ipv4_src_addr, ipv4_dst_addr;
    
    logic [DATA_WIDTH-1:0]  parser_payload_data;
    logic [KEEP_WIDTH-1:0]  parser_payload_keep;
    logic                   parser_payload_valid, parser_payload_last, parser_payload_ready;
    logic [15:0]            parser_packet_length;
    logic [8:0]             parser_ingress_port;
    
    // Pipeline signals
    logic [DATA_WIDTH-1:0]  pipeline_data;
    logic [KEEP_WIDTH-1:0]  pipeline_keep;
    logic                   pipeline_last, pipeline_valid, pipeline_ready, pipeline_drop;
    logic [8:0]             pipeline_egress_port, pipeline_egress_port_d;
    logic                   pipeline_header_modified;
    logic [5:0]             pipeline_ipv4_diffserv;
    logic [1:0]             pipeline_ipv4_ecn;
    logic [7:0]             pipeline_ipv4_ttl;

    // Parser
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .PARSER_CONFIG(8'b00000101)  // Ethernet + IPv4
    ) parser_inst (
        .aclk(aclk), .aresetn(aresetn),
        .s_axis_tdata(s_axis_tdata), .s_axis_tkeep(s_axis_tkeep),
        .s_axis_tvalid(s_axis_tvalid), .s_axis_tlast(s_axis_tlast),
        .s_axis_tready(s_axis_tready),
        .eth_dst_addr(eth_dst_addr), .eth_src_addr(eth_src_addr),
        .eth_ether_type(eth_type), .eth_valid(ethernet_valid),
        .vlan_pcp(), .vlan_dei(), .vlan_vid(), .vlan_ether_type(), .vlan_valid(),
        .ipv4_version(ipv4_version), .ipv4_ihl(ipv4_ihl),
        .ipv4_diffserv(ipv4_diffserv), .ipv4_ecn(ipv4_ecn),
        .ipv4_total_len(ipv4_totalLen), .ipv4_identification(ipv4_identification),
        .ipv4_flags(ipv4_flags), .ipv4_frag_offset(ipv4_fragOffset),
        .ipv4_ttl(ipv4_ttl), .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(ipv4_hdrChecksum),
        .ipv4_src_addr(ipv4_src_addr), .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),
        .ipv6_version(), .ipv6_traffic_class(), .ipv6_flow_label(),
        .ipv6_payload_len(), .ipv6_next_hdr(), .ipv6_hop_limit(),
        .ipv6_src_addr(), .ipv6_dst_addr(), .ipv6_valid(),
        .tcp_src_port(), .tcp_dst_port(), .tcp_seq_no(), .tcp_ack_no(),
        .tcp_data_offset(), .tcp_reserved(), .tcp_flags(), .tcp_window(),
        .tcp_checksum(), .tcp_urgent_ptr(), .tcp_valid(),
        .udp_src_port(), .udp_dst_port(), .udp_length(), .udp_checksum(), .udp_valid(),
        .vxlan_flags(), .vxlan_reserved(), .vxlan_vni(), .vxlan_reserved2(), .vxlan_valid(),
        .payload_data(parser_payload_data), .payload_keep(parser_payload_keep),
        .payload_valid(parser_payload_valid), .payload_last(parser_payload_last),
        .packet_length(parser_packet_length), .ingress_port(parser_ingress_port)
    );

    always_ff @(posedge aclk) pipeline_egress_port_d <= pipeline_egress_port;

    // Match-Action with ECN marking enabled
    match_action #(
        .DATA_WIDTH(DATA_WIDTH),
        .TABLE_SIZE(1024),
        .KEY_WIDTH(32),
        .ACTION_CONFIG(8'b00000111),
        .EGRESS_CONFIG(8'b00000011),  // ENABLE_EGRESS + ENABLE_ECN_MARKING
        .ECN_THRESHOLD(ECN_THRESHOLD)
    ) match_action_inst (
        .aclk(aclk), .aresetn(aresetn),
        .metadata_in(64'd0), .metadata_out(),
        .packet_in(parser_payload_data), .packet_keep_in(parser_payload_keep),
        .packet_last_in(parser_payload_last), .packet_valid_in(parser_payload_valid),
        .packet_ready_out(parser_payload_ready), .ingress_port_in(parser_ingress_port),
        .ipv4_valid(ipv4_valid),
        .eth_dst_addr(eth_dst_addr), .eth_src_addr(eth_src_addr),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_src_addr(ipv4_src_addr), .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_src_port(16'd0), .ipv4_dst_port(16'd0),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_diffserv(ipv4_diffserv), .ipv4_ecn(ipv4_ecn),
        .packet_length(parser_packet_length),
        .mcast_grp(),
        .enq_qdepth(enq_qdepth),  // Configurable queue depth
        .egress_port_id(pipeline_egress_port_d),
        .packet_out(pipeline_data), .packet_keep_out(pipeline_keep),
        .packet_last_out(pipeline_last), .packet_valid_out(pipeline_valid),
        .packet_ready_in(pipeline_ready),
        .out_ipv4_diffserv(pipeline_ipv4_diffserv),
        .out_ipv4_ecn(pipeline_ipv4_ecn),
        .out_ipv4_ttl(pipeline_ipv4_ttl),
        .drop(pipeline_drop), .egress_port(pipeline_egress_port),
        .header_modified(pipeline_header_modified),
        .ecn_marked(ecn_marked),
        .table_write_enable(table_wr_en), .table_write_addr(table_wr_addr),
        .table_entry_valid(table_entry_valid), .table_entry_key(table_entry_prefix),
        .table_entry_prefix_len(table_entry_prefix_len),
        .table_entry_action(table_entry_action),
        .table_entry_action_data({table_entry_egress_port, 71'h0, table_entry_dst_mac}),
        .packet_count(packet_count), .dropped_count(dropped_count),
        .forwarded_count(forwarded_count)
    );

    // Deparser
    deparser #(
        .DATA_WIDTH(DATA_WIDTH),
        .DEPARSER_CONFIG(16'h0085)  // Ethernet + IPv4 + checksum update
    ) deparser_inst (
        .aclk(aclk), .aresetn(aresetn),
        .eth_dst_addr(eth_dst_addr), .eth_src_addr(eth_src_addr),
        .eth_ether_type(eth_type), .eth_valid(ethernet_valid),
        .vlan_pcp(3'b0), .vlan_dei(1'b0), .vlan_vid(12'b0),
        .vlan_ether_type(16'b0), .vlan_valid(1'b0),
        .ipv4_version(ipv4_version), .ipv4_ihl(ipv4_ihl),
        .ipv4_diffserv(pipeline_ipv4_diffserv),
        .ipv4_ecn(pipeline_ipv4_ecn),
        .ipv4_total_len(ipv4_totalLen), .ipv4_identification(ipv4_identification),
        .ipv4_flags(ipv4_flags), .ipv4_frag_offset(ipv4_fragOffset),
        .ipv4_ttl(pipeline_ipv4_ttl), .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(ipv4_hdrChecksum),
        .ipv4_src_addr(ipv4_src_addr), .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),
        .ipv6_version(4'd0), .ipv6_traffic_class(8'd0), .ipv6_flow_label(20'd0),
        .ipv6_payload_len(16'd0), .ipv6_next_hdr(8'd0), .ipv6_hop_limit(8'd0),
        .ipv6_src_addr(128'd0), .ipv6_dst_addr(128'd0), .ipv6_valid(1'b0),
        .tcp_src_port(16'd0), .tcp_dst_port(16'd0), .tcp_seq_no(32'd0),
        .tcp_ack_no(32'd0), .tcp_data_offset(4'd0), .tcp_reserved(3'd0),
        .tcp_flags(9'd0), .tcp_window(16'd0), .tcp_checksum(16'd0),
        .tcp_urgent_ptr(16'd0), .tcp_valid(1'b0),
        .udp_src_port(16'd0), .udp_dst_port(16'd0), .udp_length(16'd0),
        .udp_checksum(16'd0), .udp_valid(1'b0),
        .vxlan_flags(8'd0), .vxlan_reserved(24'd0), .vxlan_vni(24'd0),
        .vxlan_reserved2(8'd0), .vxlan_valid(1'b0),
        .s_axis_tdata(pipeline_data), .s_axis_tkeep(pipeline_keep),
        .s_axis_tvalid(pipeline_valid), .s_axis_tlast(pipeline_last),
        .s_axis_tready(pipeline_ready),
        .drop_packet(pipeline_drop),
        .m_axis_tdata(m_axis_tdata), .m_axis_tkeep(m_axis_tkeep),
        .m_axis_tvalid(m_axis_tvalid), .m_axis_tlast(m_axis_tlast),
        .m_axis_tready(m_axis_tready)
    );

    // ============================================
    // Tasks
    // ============================================
    
    task configure_route(
        input [9:0]  addr,
        input [31:0] prefix,
        input [5:0]  prefix_len,
        input [2:0]  action_id,
        input [47:0] dst_mac,
        input [8:0]  egress_port
    );
        @(posedge aclk);
        table_wr_en           <= 1'b1;
        table_wr_addr         <= addr;
        table_entry_valid     <= 1'b1;
        table_entry_prefix    <= prefix;
        table_entry_prefix_len <= prefix_len;
        table_entry_action    <= action_id;
        table_entry_dst_mac   <= dst_mac;
        table_entry_egress_port <= egress_port;
        @(posedge aclk);
        table_wr_en <= 1'b0;
        @(posedge aclk);
    endtask

    task send_ipv4_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [7:0]  ttl,
        input [1:0]  ecn_bits
    );
        logic [DATA_WIDTH-1:0] packet;

        packet = '0;
        // Ethernet
        packet[47:0]   = dst_mac;
        packet[95:48]  = src_mac;
        packet[111:96] = 16'h0800;
        // IPv4
        packet[115:112] = 4'd4;      // version
        packet[119:116] = 4'd5;      // ihl
        packet[127:122] = 6'd0;      // DSCP
        packet[121:120] = ecn_bits;  // ECN
        packet[143:128] = 16'd40;    // total len
        packet[175:160] = 16'h0000;  // identification
        packet[178:176] = 3'b010;    // flags
        packet[191:179] = 13'd0;     // frag offset
        packet[199:192] = ttl;       // TTL
        packet[207:200] = 8'd6;      // protocol (TCP)
        packet[223:208] = 16'h0000;  // checksum
        packet[239:208] = src_ip;    // src IP at correct offset
        packet[271:240] = dst_ip;    // dst IP at correct offset
        
        @(posedge aclk);
        s_axis_tvalid <= 1'b1;
        s_axis_tdata  <= packet;
        s_axis_tkeep  <= {KEEP_WIDTH{1'b1}};
        s_axis_tlast  <= 1'b1;
        
        wait(s_axis_tready);
        @(posedge aclk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        
        packets_sent++;
    endtask

    // Output monitor
    always @(posedge aclk) begin
        if (m_axis_tvalid && m_axis_tready && m_axis_tlast) begin
            automatic logic [1:0] recv_ecn;
            recv_ecn = m_axis_tdata[121:120];
            packets_received++;
            
            if (recv_ecn == 2'b11)
                ecn_marked_count++;
            
            $display("[%0t] Recv pkt #%0d: ECN=%b", $time, packets_received, recv_ecn);
        end
    end
    
    // Debug: Parser outputs
    always @(posedge aclk) begin
        if (parser_inst.payload_valid) begin
            $display("[%0t] PARSER: ipv4_valid=%b ecn=%b diffserv=%b", 
                    $time, ipv4_valid, ipv4_ecn, ipv4_diffserv);
        end
    end

    // Debug: Match module outputs
    always @(posedge aclk) begin
        if (match_action_inst.match_valid) begin
            $display("[%0t] MATCH: ecn_out=%b action_id=%0d", 
                    $time, match_action_inst.match_ipv4_ecn, 
                    match_action_inst.match_action_id);
        end
    end

    // Debug: Action module inputs and ECN marking decision
    always @(posedge aclk) begin
        if (match_action_inst.action_inst.packet_valid && 
            match_action_inst.action_inst.action_valid) begin
            $display("[%0t] ACTION: ecn_in=%b qdepth=%0d threshold=%0d ENABLE_ECN=%b ipv4_valid=%b", 
                    $time,
                    match_action_inst.action_inst.ipv4_ecn_in,
                    match_action_inst.action_inst.enq_qdepth,
                    ECN_THRESHOLD,
                    match_action_inst.action_inst.ENABLE_ECN_MARKING,
                    match_action_inst.action_inst.ipv4_valid);
        end
    end

    // Debug: Action module outputs
    always @(posedge aclk) begin
        if (pipeline_valid && pipeline_ready) begin
            $display("[%0t] ACTION OUT: ecn_out=%b ecn_marked=%b drop=%b", 
                    $time, pipeline_ipv4_ecn, ecn_marked, pipeline_drop);
        end
    end

    // ============================================
    // Main Test
    // ============================================
    initial begin
        s_axis_tvalid = 0;
        s_axis_tdata  = 0;
        s_axis_tkeep  = 0;
        s_axis_tlast  = 0;
        m_axis_tready = 1;
        table_wr_en   = 0;
        enq_qdepth    = 19'd15;  // Above threshold (10)
        
        @(posedge aresetn);
        repeat(10) @(posedge aclk);
        
        $display("\n========== ECN Marking Testbench ==========\n");
        $display("ECN_THRESHOLD = %0d", ECN_THRESHOLD);
        
        // Configure route for 192.168.1.0/24 in little-endian format
        // Parser outputs little-endian IPs, so 192.168.1.x -> 0x__01A8C0
        configure_route(0, 32'h0001A8C0, 24, 3'd0, 48'hAABBCCDDEEFF, 9'd1);  
        
        // ----------------------------------------
        // Test 1: ECN=01 (ECT(1)), qdepth > threshold -> mark to 11
        // ----------------------------------------
        $display("\n--- Test 1: ECN=01, qdepth=%0d (>threshold) -> should mark ---", enq_qdepth);
        send_ipv4_packet(48'hFFFF_FFFF_FFFF, 48'h1111_1111_1111,
                        32'hC0A80001, 32'hC0A80164, 8'd64, 2'b01);
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 2: ECN=10 (ECT(0)), qdepth > threshold -> mark to 11
        // ----------------------------------------
        $display("\n--- Test 2: ECN=10, qdepth=%0d (>threshold) -> should mark ---", enq_qdepth);
        send_ipv4_packet(48'hFFFF_FFFF_FFFF, 48'h2222_2222_2222,
                        32'hC0A80002, 32'hC0A80164, 8'd64, 2'b10);
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 3: ECN=00 (Not ECN-Capable), qdepth > threshold -> NO mark
        // ----------------------------------------
        $display("\n--- Test 3: ECN=00 (not ECN-capable), qdepth=%0d -> should NOT mark ---", enq_qdepth);
        send_ipv4_packet(48'hFFFF_FFFF_FFFF, 48'h3333_3333_3333,
                        32'hC0A80003, 32'hC0A80164, 8'd64, 2'b00);
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 4: ECN=11 (CE already), qdepth > threshold -> stays 11
        // ----------------------------------------
        $display("\n--- Test 4: ECN=11 (already CE), qdepth=%0d -> stays 11 ---", enq_qdepth);
        send_ipv4_packet(48'hFFFF_FFFF_FFFF, 48'h4444_4444_4444,
                        32'hC0A80004, 32'hC0A80164, 8'd64, 2'b11);
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 5: ECN=01, qdepth < threshold -> NO mark
        // ----------------------------------------
        enq_qdepth = 19'd5;  // Below threshold
        $display("\n--- Test 5: ECN=01, qdepth=%0d (<threshold) -> should NOT mark ---", enq_qdepth);
        send_ipv4_packet(48'hFFFF_FFFF_FFFF, 48'h5555_5555_5555,
                        32'hC0A80005, 32'hC0A80164, 8'd64, 2'b01);
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 6: ECN=10, qdepth = threshold (exactly) -> mark
        // ----------------------------------------
        enq_qdepth = ECN_THRESHOLD;
        $display("\n--- Test 6: ECN=10, qdepth=%0d (=threshold) -> should mark ---", enq_qdepth);
        send_ipv4_packet(48'hFFFF_FFFF_FFFF, 48'h6666_6666_6666,
                        32'hC0A80006, 32'hC0A80164, 8'd64, 2'b10);
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 7: ECN=01, qdepth = threshold-1 -> NO mark
        // ----------------------------------------
        enq_qdepth = ECN_THRESHOLD - 1;
        $display("\n--- Test 7: ECN=01, qdepth=%0d (<threshold) -> should NOT mark ---", enq_qdepth);
        send_ipv4_packet(48'hFFFF_FFFF_FFFF, 48'h7777_7777_7777,
                        32'hC0A80007, 32'hC0A80164, 8'd64, 2'b01);
        repeat(30) @(posedge aclk);
        
        // Summary
        repeat(50) @(posedge aclk);
        $display("\n========== Summary ==========");
        $display("Packets sent:     %0d", packets_sent);
        $display("Packets received: %0d", packets_received);
        $display("ECN marked:       %0d", ecn_marked_count);
        $display("Total processed:  %0d", packet_count);
        $display("Forwarded:        %0d", forwarded_count);
        $display("Dropped:          %0d", dropped_count);
        
        // Expected: 3 marked (tests 1, 2, 6), test 4 already 11
        $finish;
    end

endmodule