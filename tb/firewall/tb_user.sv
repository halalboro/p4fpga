`timescale 1ns / 1ps

module tb_user;
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
    
    // Ingress port - key for direction detection
    logic [8:0]  ingress_port;
    
    // Statistics
    logic [31:0] packet_count, dropped_count, forwarded_count;
    logic        pipeline_drop;
    
    int packets_sent = 0;
    int packets_received = 0;

    // Pipeline signals
    logic        ethernet_valid;
    logic [47:0] eth_dst_addr, eth_src_addr;
    logic [15:0] eth_type;
    logic        ipv4_valid, tcp_valid, udp_valid;
    logic [3:0]  ipv4_version, ipv4_ihl;
    logic [5:0]  ipv4_diffserv;
    logic [1:0]  ipv4_ecn;
    logic [15:0] ipv4_totalLen, ipv4_identification;
    logic [2:0]  ipv4_flags;
    logic [12:0] ipv4_fragOffset;
    logic [7:0]  ipv4_ttl, ipv4_protocol;
    logic [15:0] ipv4_hdrChecksum;
    logic [31:0] ipv4_src_addr, ipv4_dst_addr;
    logic [15:0] tcp_src_port, tcp_dst_port;
    
    logic [DATA_WIDTH-1:0]  parser_payload_data;
    logic [KEEP_WIDTH-1:0]  parser_payload_keep;
    logic                   parser_payload_valid, parser_payload_last, parser_payload_ready;
    logic [15:0]            parser_packet_length;
    logic [8:0]             parser_ingress_port;
    
    logic [DATA_WIDTH-1:0]  pipeline_data;
    logic [KEEP_WIDTH-1:0]  pipeline_keep;
    logic                   pipeline_last, pipeline_valid, pipeline_ready;
    logic [8:0]             pipeline_egress_port, pipeline_egress_port_d;
    logic                   pipeline_header_modified;
    logic [5:0]             pipeline_ipv4_diffserv;
    logic [1:0]             pipeline_ipv4_ecn;
    logic [7:0]             pipeline_ipv4_ttl;
    logic [15:0]            l4_src_port, l4_dst_port;

    // Parser
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .PARSER_CONFIG(8'b00010101)  // Ethernet + IPv4 + TCP
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
        .tcp_src_port(tcp_src_port), .tcp_dst_port(tcp_dst_port),
        .tcp_seq_no(), .tcp_ack_no(), .tcp_data_offset(), .tcp_reserved(),
        .tcp_flags(), .tcp_window(), .tcp_checksum(), .tcp_urgent_ptr(),
        .tcp_valid(tcp_valid),
        .udp_src_port(), .udp_dst_port(), .udp_length(), .udp_checksum(), .udp_valid(udp_valid),
        .vxlan_flags(), .vxlan_reserved(), .vxlan_vni(), .vxlan_reserved2(), .vxlan_valid(),
        .payload_data(parser_payload_data), .payload_keep(parser_payload_keep),
        .payload_valid(parser_payload_valid), .payload_last(parser_payload_last),
        .packet_length(parser_packet_length), .ingress_port(parser_ingress_port)
    );

    // L4 port selection
    always_comb begin
        if (tcp_valid) begin
            l4_src_port = tcp_src_port;
            l4_dst_port = tcp_dst_port;
        end else begin
            l4_src_port = 16'h0;
            l4_dst_port = 16'h0;
        end
    end

    always_ff @(posedge aclk) pipeline_egress_port_d <= pipeline_egress_port;

    // Match-Action with bloom filter
    match_action #(
        .DATA_WIDTH(DATA_WIDTH),
        .TABLE_SIZE(1024),
        .KEY_WIDTH(32),
        .ACTION_CONFIG(8'b00000111),
        .EGRESS_CONFIG(8'b00000100),  // ENABLE_STATEFUL
        .NUM_REGISTERS(1024)
    ) match_action_inst (
        .aclk(aclk), .aresetn(aresetn),
        .metadata_in(64'd0), .metadata_out(),
        .packet_in(parser_payload_data), .packet_keep_in(parser_payload_keep),
        .packet_last_in(parser_payload_last), .packet_valid_in(parser_payload_valid),
        .packet_ready_out(parser_payload_ready), .ingress_port_in(ingress_port),
        .ipv4_valid(ipv4_valid),
        .eth_dst_addr(eth_dst_addr), .eth_src_addr(eth_src_addr),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_src_addr(ipv4_src_addr), .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_src_port(l4_src_port), .ipv4_dst_port(l4_dst_port),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_diffserv(ipv4_diffserv), .ipv4_ecn(ipv4_ecn),
        .packet_length(parser_packet_length),
        .mcast_grp(),
        .enq_qdepth(19'd0),
        .egress_port_id(pipeline_egress_port_d),
        .packet_out(pipeline_data), .packet_keep_out(pipeline_keep),
        .packet_last_out(pipeline_last), .packet_valid_out(pipeline_valid),
        .packet_ready_in(pipeline_ready),
        .out_ipv4_diffserv(pipeline_ipv4_diffserv),
        .out_ipv4_ecn(pipeline_ipv4_ecn),
        .out_ipv4_ttl(pipeline_ipv4_ttl),
        .drop(pipeline_drop), .egress_port(pipeline_egress_port),
        .header_modified(pipeline_header_modified), .ecn_marked(),
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
        .DEPARSER_CONFIG(16'h0095)  // Ethernet + IPv4 + TCP
    ) deparser_inst (
        .aclk(aclk), .aresetn(aresetn),
        .eth_dst_addr(eth_dst_addr), .eth_src_addr(eth_src_addr),
        .eth_ether_type(eth_type), .eth_valid(ethernet_valid),
        .vlan_pcp(3'b0), .vlan_dei(1'b0), .vlan_vid(12'b0),
        .vlan_ether_type(16'b0), .vlan_valid(1'b0),
        .ipv4_version(ipv4_version), .ipv4_ihl(ipv4_ihl),
        .ipv4_diffserv(pipeline_ipv4_diffserv), .ipv4_ecn(pipeline_ipv4_ecn),
        .ipv4_total_len(ipv4_totalLen), .ipv4_identification(ipv4_identification),
        .ipv4_flags(ipv4_flags), .ipv4_frag_offset(ipv4_fragOffset),
        .ipv4_ttl(pipeline_ipv4_ttl), .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(ipv4_hdrChecksum),
        .ipv4_src_addr(ipv4_src_addr), .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),
        .ipv6_version(4'd0), .ipv6_traffic_class(8'd0), .ipv6_flow_label(20'd0),
        .ipv6_payload_len(16'd0), .ipv6_next_hdr(8'd0), .ipv6_hop_limit(8'd0),
        .ipv6_src_addr(128'd0), .ipv6_dst_addr(128'd0), .ipv6_valid(1'b0),
        .tcp_src_port(tcp_src_port), .tcp_dst_port(tcp_dst_port),
        .tcp_seq_no(32'd0), .tcp_ack_no(32'd0), .tcp_data_offset(4'd5),
        .tcp_reserved(3'd0), .tcp_flags(9'd0), .tcp_window(16'd0),
        .tcp_checksum(16'd0), .tcp_urgent_ptr(16'd0), .tcp_valid(tcp_valid),
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

    // Tasks
    task configure_route(
        input [9:0]  addr,
        input [31:0] prefix,
        input [5:0]  prefix_len,
        input [2:0]  action_id,
        input [47:0] dst_mac,
        input [8:0]  egress_p
    );
        @(posedge aclk);
        table_wr_en           <= 1'b1;
        table_wr_addr         <= addr;
        table_entry_valid     <= 1'b1;
        table_entry_prefix    <= prefix;
        table_entry_prefix_len <= prefix_len;
        table_entry_action    <= action_id;
        table_entry_dst_mac   <= dst_mac;
        table_entry_egress_port <= egress_p;
        @(posedge aclk);
        table_wr_en <= 1'b0;
        @(posedge aclk);
    endtask

    task send_tcp_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [15:0] src_port_tcp,
        input [15:0] dst_port_tcp,
        input [8:0]  in_port
    );
        logic [DATA_WIDTH-1:0] packet;
        
        ingress_port = in_port;
        
        packet = '0;
        // Ethernet (14 bytes)
        packet[47:0]   = dst_mac;
        packet[95:48]  = src_mac;
        packet[111:96] = 16'h0800;
        // IPv4 (20 bytes) starting at byte 14
        packet[115:112] = 4'd4;       // version
        packet[119:116] = 4'd5;       // ihl
        packet[127:120] = 8'd0;       // tos
        packet[143:128] = 16'd60;     // total len
        packet[159:144] = 16'h0000;   // identification
        packet[175:160] = 16'h4000;   // flags + frag
        packet[183:176] = 8'd64;      // TTL
        packet[191:184] = 8'd6;       // protocol (TCP)
        packet[207:192] = 16'h0000;   // checksum
        packet[239:208] = src_ip;     // src IP
        packet[271:240] = dst_ip;     // dst IP
        // TCP (20 bytes) starting at byte 34
        packet[287:272] = src_port_tcp;  // src port
        packet[303:288] = dst_port_tcp;  // dst port
        packet[335:304] = 32'd0;      // seq
        packet[367:336] = 32'd0;      // ack
        packet[371:368] = 4'd5;       // data offset
        packet[375:372] = 4'd0;       // reserved
        packet[383:376] = 8'd0;       // flags
        packet[399:384] = 16'd8192;   // window
        packet[415:400] = 16'd0;      // checksum
        packet[431:416] = 16'd0;      // urgent
        
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
            packets_received++;
            $display("[%0t] Recv pkt #%0d", $time, packets_received);
        end
    end

    // Debug: Parser outputs
    always @(posedge aclk) begin
        if (parser_payload_valid) begin
            $display("[%0t] PARSER: ipv4_valid=%b protocol=%0d src=%h dst=%h sport=%0d dport=%0d", 
                    $time, ipv4_valid, ipv4_protocol, ipv4_src_addr, ipv4_dst_addr, 
                    l4_src_port, l4_dst_port);
        end
    end

    // Debug: Pipeline output
    always @(posedge aclk) begin
        if (pipeline_valid) begin
            $display("[%0t] PIPELINE: valid=%b drop=%b", $time, pipeline_valid, pipeline_drop);
        end
    end

    // Debug: Deparser
    always @(posedge aclk) begin
        if (deparser_inst.s_axis_tvalid) begin
            $display("[%0t] DEPARSER: input_valid=%b drop_packet=%b state=%0d", 
                    $time, deparser_inst.s_axis_tvalid, deparser_inst.drop_packet,
                    deparser_inst.deparse_state);
        end
    end

    // Monitor bloom filter writes
    initial begin
        forever begin
            @(posedge aclk);
            if (match_action_inst.packet_valid_in && 
                match_action_inst.ipv4_valid && 
                match_action_inst.ipv4_protocol == 8'd6 &&
                match_action_inst.direction == 1'b0) begin
                $display("[%0t] BLOOM WRITE: pos1=%0d, pos2=%0d (outbound packet)", $time,
                        match_action_inst.reg_pos_one,
                        match_action_inst.reg_pos_two);
            end
        end
    end

    // Main test
    initial begin
        s_axis_tvalid = 0;
        s_axis_tdata  = 0;
        s_axis_tkeep  = 0;
        s_axis_tlast  = 0;
        m_axis_tready = 1;
        table_wr_en   = 0;
        ingress_port  = 9'd1;
        
        @(posedge aresetn);
        repeat(10) @(posedge aclk);
        
        $display("\n========== Firewall Bloom Filter Testbench ==========\n");
        $display("Direction: port 0 = external (inbound), port 1+ = internal (outbound)");

        // Fixed (byte-swapped to match parser output):
        configure_route(0, 32'h0001A8C0, 24, 3'd0, 48'hAABBCCDDEEFF, 9'd1);  // 192.168.1.0/24 swapped
        configure_route(1, 32'h0001000A, 24, 3'd0, 48'h112233445566, 9'd0);  // 10.0.1.0/24 swapped
        
        // ----------------------------------------
        // Test 1: Inbound without prior outbound -> DROP
        // ----------------------------------------
        $display("\n--- Test 1: Inbound TCP without prior connection -> DROP ---");
        send_tcp_packet(48'hFFFFFFFFFFFF, 48'h1111_1111_1111,
                       32'h0A000101, 32'hC0A80164,  // 10.0.1.1 -> 192.168.1.100
                       16'd12345, 16'd80,
                       9'd0);  // Inbound (port 0)
        repeat(40) @(posedge aclk);

        // ----------------------------------------
        // Test 2: Outbound TCP -> records in bloom filter
        // ----------------------------------------
        $display("\n--- Test 2: Outbound TCP (internal->external) -> FORWARD + record ---");
        send_tcp_packet(48'hFFFFFFFFFFFF, 48'h2222_2222_2222,
                       32'hC0A80164, 32'h0A000101,  // 192.168.1.100 -> 10.0.1.1
                       16'd80, 16'd12345,
                       9'd1);  // Outbound (port 1)
        repeat(40) @(posedge aclk);

        // ----------------------------------------
        // Test 3: Inbound reply (same flow reversed) -> FORWARD
        // ----------------------------------------
        $display("\n--- Test 3: Inbound reply (matching flow) -> FORWARD ---");
        send_tcp_packet(48'hFFFFFFFFFFFF, 48'h3333_3333_3333,
                       32'h0A000101, 32'hC0A80164,  // 10.0.1.1 -> 192.168.1.100
                       16'd12345, 16'd80,
                       9'd0);  // Inbound (port 0)
        repeat(40) @(posedge aclk);

        // ----------------------------------------
        // Test 4: Different inbound flow -> DROP
        // ----------------------------------------
        $display("\n--- Test 4: Different inbound flow (no outbound) -> DROP ---");
        send_tcp_packet(48'hFFFFFFFFFFFF, 48'h4444_4444_4444,
                       32'h0A000102, 32'hC0A80164,  // 10.0.1.2 -> 192.168.1.100
                       16'd54321, 16'd443,
                       9'd0);  // Inbound (port 0)
        repeat(40) @(posedge aclk);

        // ----------------------------------------
        // Test 5: Another outbound + matching inbound
        // ----------------------------------------
        $display("\n--- Test 5: New outbound -> FORWARD ---");
        send_tcp_packet(48'hFFFFFFFFFFFF, 48'h5555_5555_5555,
                       32'hC0A80165, 32'h0A000103,  // 192.168.1.101 -> 10.0.1.3
                       16'd8080, 16'd22,
                       9'd1);  // Outbound
        repeat(40) @(posedge aclk);

        $display("\n--- Test 6: Matching inbound reply -> FORWARD ---");
        send_tcp_packet(48'hFFFFFFFFFFFF, 48'h6666_6666_6666,
                       32'h0A000103, 32'hC0A80165,  // 10.0.1.3 -> 192.168.1.101
                       16'd22, 16'd8080,
                       9'd0);  // Inbound
        repeat(40) @(posedge aclk);

        // Summary
        repeat(50) @(posedge aclk);
        $display("\n========== Summary ==========");
        $display("Packets sent:     %0d", packets_sent);
        $display("Packets received: %0d", packets_received);
        $display("Total processed:  %0d", packet_count);
        $display("Forwarded:        %0d", forwarded_count);
        $display("Dropped:          %0d", dropped_count);
        
        // Expected: 4 forwarded (tests 2,3,5,6), 2 dropped (tests 1,4)        
        $finish;
    end

endmodule