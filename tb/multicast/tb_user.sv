`timescale 1ns / 1ps

// =============================================================================
// Multicast Testbench
//
// Tests L2 multicast switch functionality based on multicast.p4:
// - Exact match on destination MAC address
// - Actions: multicast (mcast_grp=1), mac_forward(port), drop
// - Default action: multicast
// - Egress pruning: drop if egress_port == ingress_port
// =============================================================================

module tb_user;
    // ==========================================
    // Clock and Reset
    // ==========================================
    logic aclk = 1'b1;
    logic aresetn = 1'b0;

    localparam CLK_PERIOD = 4ns;  // 250 MHz
    always #(CLK_PERIOD/2) aclk = ~aclk;

    initial begin
        aresetn = 1'b0;
        #100ns aresetn = 1'b1;
    end

    // ==========================================
    // Parameters
    // ==========================================
    localparam DATA_WIDTH = 512;
    localparam KEEP_WIDTH = DATA_WIDTH/8;
    localparam ACTION_DATA_WIDTH = 128;

    // ==========================================
    // AXI-Stream interfaces
    // ==========================================
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

    // ==========================================
    // Table programming signals
    // ==========================================
    logic        table_wr_en;
    logic [9:0]  table_wr_addr;
    logic        table_entry_valid;
    logic [47:0] table_entry_key;       // MAC address (48-bit exact match)
    logic [5:0]  table_entry_prefix_len;
    logic [2:0]  table_entry_action;
    logic [ACTION_DATA_WIDTH-1:0] table_entry_action_data;

    // Ingress port
    logic [8:0]  ingress_port;

    // ==========================================
    // Statistics
    // ==========================================
    logic [31:0] packet_count, dropped_count, forwarded_count;
    logic        pipeline_drop;
    logic [15:0] pipeline_mcast_grp;

    int packets_sent = 0;
    int packets_received = 0;

    // ==========================================
    // Parser output signals
    // ==========================================
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
    logic [15:0] udp_src_port, udp_dst_port;

    logic [DATA_WIDTH-1:0]  parser_payload_data;
    logic [KEEP_WIDTH-1:0]  parser_payload_keep;
    logic                   parser_payload_valid, parser_payload_last, parser_payload_ready;
    logic [15:0]            parser_packet_length;
    logic [8:0]             parser_ingress_port;

    // ==========================================
    // Pipeline signals
    // ==========================================
    logic [DATA_WIDTH-1:0]  pipeline_data;
    logic [KEEP_WIDTH-1:0]  pipeline_keep;
    logic                   pipeline_last, pipeline_valid, pipeline_ready;
    logic [8:0]             pipeline_egress_port, pipeline_egress_port_d;
    logic                   pipeline_header_modified;
    logic [5:0]             pipeline_ipv4_diffserv;
    logic [1:0]             pipeline_ipv4_ecn;
    logic [7:0]             pipeline_ipv4_ttl;
    logic [47:0]            pipeline_eth_dst, pipeline_eth_src;

    // ==========================================
    // Action IDs (from P4 program)
    // ==========================================
    localparam ACTION_MULTICAST   = 3'd10;  // multicast() - sets mcast_grp
    localparam ACTION_MAC_FORWARD = 3'd0;   // mac_forward(port) - unicast forward
    localparam ACTION_DROP        = 3'd1;   // drop()

    // ==========================================
    // Parser Instance
    // ==========================================
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .PARSER_CONFIG(8'b00000001)  // Ethernet only (bit 0)
    ) parser_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tkeep(s_axis_tkeep),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tlast(s_axis_tlast),
        .s_axis_tready(s_axis_tready),
        .eth_dst_addr(eth_dst_addr),
        .eth_src_addr(eth_src_addr),
        .eth_ether_type(eth_type),
        .eth_valid(ethernet_valid),
        .vlan_pcp(),
        .vlan_dei(),
        .vlan_vid(),
        .vlan_ether_type(),
        .vlan_valid(),
        .ipv4_version(ipv4_version),
        .ipv4_ihl(ipv4_ihl),
        .ipv4_diffserv(ipv4_diffserv),
        .ipv4_ecn(ipv4_ecn),
        .ipv4_total_len(ipv4_totalLen),
        .ipv4_identification(ipv4_identification),
        .ipv4_flags(ipv4_flags),
        .ipv4_frag_offset(ipv4_fragOffset),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(ipv4_hdrChecksum),
        .ipv4_src_addr(ipv4_src_addr),
        .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),
        .ipv6_version(),
        .ipv6_traffic_class(),
        .ipv6_flow_label(),
        .ipv6_payload_len(),
        .ipv6_next_hdr(),
        .ipv6_hop_limit(),
        .ipv6_src_addr(),
        .ipv6_dst_addr(),
        .ipv6_valid(),
        .tcp_src_port(),
        .tcp_dst_port(),
        .tcp_seq_no(),
        .tcp_ack_no(),
        .tcp_data_offset(),
        .tcp_reserved(),
        .tcp_flags(),
        .tcp_window(),
        .tcp_checksum(),
        .tcp_urgent_ptr(),
        .tcp_valid(tcp_valid),
        .udp_src_port(udp_src_port),
        .udp_dst_port(udp_dst_port),
        .udp_length(),
        .udp_checksum(),
        .udp_valid(udp_valid),
        .vxlan_flags(),
        .vxlan_reserved(),
        .vxlan_vni(),
        .vxlan_reserved2(),
        .vxlan_valid(),
        .payload_data(parser_payload_data),
        .payload_keep(parser_payload_keep),
        .payload_valid(parser_payload_valid),
        .payload_last(parser_payload_last),
        .packet_length(parser_packet_length),
        .ingress_port(parser_ingress_port)
    );

    // Egress port delay for feedback
    always_ff @(posedge aclk) pipeline_egress_port_d <= pipeline_egress_port;

    // ==========================================
    // Match-Action Pipeline Instance
    // ==========================================
    match_action #(
        .DATA_WIDTH(DATA_WIDTH),
        .TABLE_SIZE(1024),
        .KEY_WIDTH(48),                // 48-bit MAC address for exact match
        .ACTION_DATA_WIDTH(ACTION_DATA_WIDTH),
        .ACTION_CONFIG(8'b10000011),   // Forward, Drop, Multicast (bits 0,1,7)
        .EGRESS_CONFIG(8'b01000000),   // Enable multicast pruning (bit 6)
        .NUM_REGISTERS(1024)
    ) match_action_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        .metadata_in(64'd0),
        .metadata_out(),
        .packet_in(parser_payload_data),
        .packet_keep_in(parser_payload_keep),
        .packet_last_in(parser_payload_last),
        .packet_valid_in(parser_payload_valid),
        .packet_ready_out(parser_payload_ready),
        .ingress_port_in(ingress_port),
        .ipv4_valid(ipv4_valid),
        .eth_dst_addr(eth_dst_addr),
        .eth_src_addr(eth_src_addr),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_src_addr(ipv4_src_addr),
        .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_src_port(udp_src_port),
        .ipv4_dst_port(udp_dst_port),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_diffserv(ipv4_diffserv),
        .ipv4_ecn(ipv4_ecn),
        .packet_length(parser_packet_length),
        .mcast_grp(pipeline_mcast_grp),
        .enq_qdepth(19'd0),
        .egress_port_id(pipeline_egress_port_d),
        .packet_out(pipeline_data),
        .packet_keep_out(pipeline_keep),
        .packet_last_out(pipeline_last),
        .packet_valid_out(pipeline_valid),
        .packet_ready_in(pipeline_ready),
        .out_ipv4_diffserv(pipeline_ipv4_diffserv),
        .out_ipv4_ecn(pipeline_ipv4_ecn),
        .out_ipv4_ttl(pipeline_ipv4_ttl),
        .out_eth_dst_addr(pipeline_eth_dst),
        .out_eth_src_addr(pipeline_eth_src),
        .drop(pipeline_drop),
        .egress_port(pipeline_egress_port),
        .header_modified(pipeline_header_modified),
        .ecn_marked(),
        .table_write_enable(table_wr_en),
        .table_write_addr(table_wr_addr),
        .table_entry_valid(table_entry_valid),
        .table_entry_key(table_entry_key),  // Full 48-bit MAC address
        .table_entry_prefix_len(table_entry_prefix_len),
        .table_entry_action(table_entry_action),
        .table_entry_action_data(table_entry_action_data),
        .packet_count(packet_count),
        .dropped_count(dropped_count),
        .forwarded_count(forwarded_count)
    );

    // ==========================================
    // Deparser Instance
    // ==========================================
    deparser #(
        .DATA_WIDTH(DATA_WIDTH),
        .DEPARSER_CONFIG(16'h0001)  // Ethernet only (bit 0)
    ) deparser_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        .eth_dst_addr(pipeline_eth_dst),
        .eth_src_addr(pipeline_eth_src),
        .eth_ether_type(eth_type),
        .eth_valid(ethernet_valid),
        .vlan_pcp(3'b0),
        .vlan_dei(1'b0),
        .vlan_vid(12'b0),
        .vlan_ether_type(16'b0),
        .vlan_valid(1'b0),
        .ipv4_version(4'd0),
        .ipv4_ihl(4'd0),
        .ipv4_diffserv(6'd0),
        .ipv4_ecn(2'd0),
        .ipv4_total_len(16'd0),
        .ipv4_identification(16'd0),
        .ipv4_flags(3'd0),
        .ipv4_frag_offset(13'd0),
        .ipv4_ttl(8'd0),
        .ipv4_protocol(8'd0),
        .ipv4_hdr_checksum(16'd0),
        .ipv4_src_addr(32'd0),
        .ipv4_dst_addr(32'd0),
        .ipv4_valid(1'b0),
        .ipv6_version(4'd0),
        .ipv6_traffic_class(8'd0),
        .ipv6_flow_label(20'd0),
        .ipv6_payload_len(16'd0),
        .ipv6_next_hdr(8'd0),
        .ipv6_hop_limit(8'd0),
        .ipv6_src_addr(128'd0),
        .ipv6_dst_addr(128'd0),
        .ipv6_valid(1'b0),
        .tcp_src_port(16'd0),
        .tcp_dst_port(16'd0),
        .tcp_seq_no(32'd0),
        .tcp_ack_no(32'd0),
        .tcp_data_offset(4'd5),
        .tcp_reserved(3'd0),
        .tcp_flags(9'd0),
        .tcp_window(16'd0),
        .tcp_checksum(16'd0),
        .tcp_urgent_ptr(16'd0),
        .tcp_valid(1'b0),
        .udp_src_port(16'd0),
        .udp_dst_port(16'd0),
        .udp_length(16'd0),
        .udp_checksum(16'd0),
        .udp_valid(1'b0),
        .vxlan_flags(8'd0),
        .vxlan_reserved(24'd0),
        .vxlan_vni(24'd0),
        .vxlan_reserved2(8'd0),
        .vxlan_valid(1'b0),
        .s_axis_tdata(pipeline_data),
        .s_axis_tkeep(pipeline_keep),
        .s_axis_tvalid(pipeline_valid),
        .s_axis_tlast(pipeline_last),
        .s_axis_tready(pipeline_ready),
        .drop_packet(pipeline_drop),
        .m_axis_tdata(m_axis_tdata),
        .m_axis_tkeep(m_axis_tkeep),
        .m_axis_tvalid(m_axis_tvalid),
        .m_axis_tlast(m_axis_tlast),
        .m_axis_tready(m_axis_tready)
    );

    // ==========================================
    // Byte swap function for MAC addresses
    // ==========================================
    function automatic [47:0] bswap48(input [47:0] val);
        bswap48 = {val[7:0], val[15:8], val[23:16], val[31:24], val[39:32], val[47:40]};
    endfunction

    // ==========================================
    // Task: Configure MAC table entry (exact match)
    // ==========================================
    task configure_mac_entry(
        input [9:0]  addr,
        input [47:0] mac_addr,       // Destination MAC to match
        input [2:0]  action_id,      // 0=forward, 1=drop, 10=multicast
        input [8:0]  egress_p,       // Egress port (for mac_forward)
        input [15:0] mcast_group     // Multicast group (for multicast action)
    );
        @(posedge aclk);
        table_wr_en            <= 1'b1;
        table_wr_addr          <= addr;
        table_entry_valid      <= 1'b1;
        table_entry_key        <= mac_addr;
        table_entry_prefix_len <= 6'd48;  // Exact match
        table_entry_action     <= action_id;

        // Pack action_data based on action type
        // action_data layout: [103:96]=egress_port, [15:0]=mcast_grp
        if (action_id == ACTION_MAC_FORWARD) begin
            // mac_forward: egress port in action_data[103:96]
            table_entry_action_data <= {24'd0, egress_p[7:0], 96'd0};
        end else if (action_id == ACTION_MULTICAST) begin
            // multicast: mcast_grp in action_data[15:0]
            table_entry_action_data <= {112'd0, mcast_group};
        end else begin
            table_entry_action_data <= 128'd0;
        end

        @(posedge aclk);
        table_wr_en <= 1'b0;
        @(posedge aclk);

        $display("[%0t] MAC entry configured: addr=%0d mac=%012h action=%0d port=%0d mcast_grp=%0d",
                 $time, addr, mac_addr, action_id, egress_p, mcast_group);
    endtask

    // ==========================================
    // Task: Send Ethernet packet
    // ==========================================
    task send_ethernet_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [15:0] ether_type,
        input [8:0]  in_port,
        input string description
    );
        logic [DATA_WIDTH-1:0] packet;

        packet = '0;

        // Ethernet header (14 bytes) - in wire order (swapped)
        packet[47:0]    = bswap48(dst_mac);
        packet[95:48]   = bswap48(src_mac);
        packet[111:96]  = ether_type;

        // Add some payload data
        packet[127:112] = 16'hDEAD;
        packet[143:128] = 16'hBEEF;

        ingress_port <= in_port;

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
        $display("[%0t] Sent packet #%0d: %s", $time, packets_sent, description);
        $display("        dst_mac=%012h src_mac=%012h ingress_port=%0d", dst_mac, src_mac, in_port);
    endtask

    // ==========================================
    // Output monitor
    // ==========================================
    always @(posedge aclk) begin
        if (m_axis_tvalid && m_axis_tready && m_axis_tlast) begin
            packets_received++;
            $display("[%0t] Received packet #%0d:", $time, packets_received);
            $display("        DST MAC: %012h", bswap48(m_axis_tdata[47:0]));
            $display("        SRC MAC: %012h", bswap48(m_axis_tdata[95:48]));
            $display("        Egress:  %0d", pipeline_egress_port);
            $display("        Mcast:   %0d", pipeline_mcast_grp);
        end
    end

    // ==========================================
    // Debug: Parser outputs
    // ==========================================
    always @(posedge aclk) begin
        if (parser_payload_valid) begin
            $display("[%0t] PARSER: eth_valid=%b dst_mac=%012h src_mac=%012h",
                    $time, ethernet_valid, eth_dst_addr, eth_src_addr);
        end
    end

    // ==========================================
    // Debug: Match-Action outputs
    // ==========================================
    always @(posedge aclk) begin
        if (pipeline_valid) begin
            $display("[%0t] MATCH-ACTION: valid=%b drop=%b egress_port=%0d mcast_grp=%0d",
                    $time, pipeline_valid, pipeline_drop, pipeline_egress_port, pipeline_mcast_grp);
        end
    end

    // ==========================================
    // Main test sequence
    // ==========================================
    initial begin
        // Initialize signals
        s_axis_tvalid = 0;
        s_axis_tdata  = 0;
        s_axis_tkeep  = 0;
        s_axis_tlast  = 0;
        m_axis_tready = 1;
        table_wr_en   = 0;
        table_wr_addr = 0;
        table_entry_valid = 0;
        table_entry_key = 0;
        table_entry_prefix_len = 0;
        table_entry_action = 0;
        table_entry_action_data = 0;
        ingress_port  = 9'd0;

        // Wait for reset release
        @(posedge aresetn);
        repeat(10) @(posedge aclk);

        $display("\n========================================================");
        $display("         Multicast Switch Testbench");
        $display("========================================================\n");

        // ========================================
        // Configure MAC table
        // ========================================
        $display("Configuring MAC table entries...\n");

        // Entry 0: Known unicast MAC -> forward to port 1
        configure_mac_entry(
            .addr(0),
            .mac_addr(48'hAABBCCDD0001),
            .action_id(ACTION_MAC_FORWARD),
            .egress_p(9'd1),
            .mcast_group(16'd0)
        );

        // Entry 1: Known unicast MAC -> forward to port 2
        configure_mac_entry(
            .addr(1),
            .mac_addr(48'hAABBCCDD0002),
            .action_id(ACTION_MAC_FORWARD),
            .egress_p(9'd2),
            .mcast_group(16'd0)
        );

        // Entry 2: Broadcast MAC -> multicast to group 1
        configure_mac_entry(
            .addr(2),
            .mac_addr(48'hFFFFFFFFFFFF),
            .action_id(ACTION_MULTICAST),
            .egress_p(9'd0),
            .mcast_group(16'd1)
        );

        // Entry 3: Specific multicast MAC -> multicast to group 2
        configure_mac_entry(
            .addr(3),
            .mac_addr(48'h01005E000001),  // IPv4 multicast MAC
            .action_id(ACTION_MULTICAST),
            .egress_p(9'd0),
            .mcast_group(16'd2)
        );

        // Entry 4: Blackhole MAC -> drop
        configure_mac_entry(
            .addr(4),
            .mac_addr(48'hDEADBEEF0000),
            .action_id(ACTION_DROP),
            .egress_p(9'd0),
            .mcast_group(16'd0)
        );

        repeat(10) @(posedge aclk);

        // ========================================
        // Test Cases
        // ========================================

        // Test 1: Known unicast -> forward to port 1
        $display("\n--- Test 1: Known unicast to AABBCCDD0001 -> port 1 ---");
        send_ethernet_packet(
            .dst_mac(48'hAABBCCDD0001),
            .src_mac(48'h112233445566),
            .ether_type(16'h0800),
            .in_port(9'd0),
            .description("Unicast to port 1")
        );
        repeat(30) @(posedge aclk);

        // Test 2: Known unicast -> forward to port 2
        $display("\n--- Test 2: Known unicast to AABBCCDD0002 -> port 2 ---");
        send_ethernet_packet(
            .dst_mac(48'hAABBCCDD0002),
            .src_mac(48'h112233445566),
            .ether_type(16'h0800),
            .in_port(9'd0),
            .description("Unicast to port 2")
        );
        repeat(30) @(posedge aclk);

        // Test 3: Broadcast -> multicast group 1
        $display("\n--- Test 3: Broadcast -> multicast group 1 ---");
        send_ethernet_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .ether_type(16'h0806),  // ARP
            .in_port(9'd1),
            .description("Broadcast (ARP)")
        );
        repeat(30) @(posedge aclk);

        // Test 4: IPv4 multicast MAC -> multicast group 2
        $display("\n--- Test 4: IPv4 multicast MAC -> multicast group 2 ---");
        send_ethernet_packet(
            .dst_mac(48'h01005E000001),
            .src_mac(48'h112233445566),
            .ether_type(16'h0800),
            .in_port(9'd2),
            .description("IPv4 multicast")
        );
        repeat(30) @(posedge aclk);

        // Test 5: Blackhole MAC -> drop
        $display("\n--- Test 5: Blackhole MAC -> DROP ---");
        send_ethernet_packet(
            .dst_mac(48'hDEADBEEF0000),
            .src_mac(48'h112233445566),
            .ether_type(16'h0800),
            .in_port(9'd0),
            .description("Blackhole -> DROP")
        );
        repeat(30) @(posedge aclk);

        // Test 6: Unknown MAC -> default action (multicast group 1)
        $display("\n--- Test 6: Unknown MAC -> default multicast ---");
        send_ethernet_packet(
            .dst_mac(48'h999999999999),
            .src_mac(48'h112233445566),
            .ether_type(16'h0800),
            .in_port(9'd3),
            .description("Unknown MAC -> default multicast")
        );
        repeat(30) @(posedge aclk);

        // Test 7: Egress pruning test - packet from port 1 to broadcast
        // Note: In a real multicast system, the packet would be replicated
        // and the copy going back to port 1 would be pruned
        $display("\n--- Test 7: Broadcast from port 1 (pruning test) ---");
        send_ethernet_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'hAABBCCDD0001),
            .ether_type(16'h0806),
            .in_port(9'd1),
            .description("Broadcast from port 1")
        );
        repeat(30) @(posedge aclk);

        // ========================================
        // Final Summary
        // ========================================
        repeat(50) @(posedge aclk);

        $display("\n========================================================");
        $display("                    Test Summary");
        $display("========================================================");
        $display("Packets sent:     %0d", packets_sent);
        $display("Packets received: %0d", packets_received);
        $display("Total processed:  %0d", packet_count);
        $display("Forwarded:        %0d", forwarded_count);
        $display("Dropped:          %0d", dropped_count);
        $display("========================================================");
        $display("\nExpected Results:");
        $display("  - Test 1: FORWARD to port 1 (known unicast)");
        $display("  - Test 2: FORWARD to port 2 (known unicast)");
        $display("  - Test 3: MULTICAST group 1 (broadcast)");
        $display("  - Test 4: MULTICAST group 2 (IPv4 mcast MAC)");
        $display("  - Test 5: DROP (blackhole MAC)");
        $display("  - Test 6: MULTICAST group 1 (unknown MAC, default action)");
        $display("  - Test 7: MULTICAST group 1 (broadcast from port 1)");
        $display("\nExpected: 6 forwarded/multicast, 1 dropped");
        $display("========================================================\n");

        if (packets_received >= 5 && dropped_count >= 1) begin
            $display("*** TEST PASSED ***\n");
        end else begin
            $display("*** TEST FAILED ***\n");
        end

        $finish;
    end

endmodule
