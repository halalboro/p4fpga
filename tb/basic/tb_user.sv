`timescale 1ns / 1ps

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
    logic [31:0] table_entry_prefix;
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
    // Parser Instance
    // ==========================================
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .PARSER_CONFIG(8'b00100101)  // Ethernet + IPv4 + UDP
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
        .KEY_WIDTH(32),                // 32-bit IPv4 address for LPM
        .ACTION_DATA_WIDTH(ACTION_DATA_WIDTH),
        .ACTION_CONFIG(8'b00000111),   // Forward, Drop, Modify
        .EGRESS_CONFIG(8'b00000000),   // Basic routing (no special egress features)
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
        .mcast_grp(),
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
        .table_entry_key(table_entry_prefix),
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
        .DEPARSER_CONFIG(16'h0025)  // Ethernet + IPv4 + UDP
    ) deparser_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        .eth_dst_addr(eth_dst_addr),
        .eth_src_addr(eth_src_addr),
        .eth_ether_type(eth_type),
        .eth_valid(ethernet_valid),
        .vlan_pcp(3'b0),
        .vlan_dei(1'b0),
        .vlan_vid(12'b0),
        .vlan_ether_type(16'b0),
        .vlan_valid(1'b0),
        .ipv4_version(ipv4_version),
        .ipv4_ihl(ipv4_ihl),
        .ipv4_diffserv(pipeline_ipv4_diffserv),
        .ipv4_ecn(pipeline_ipv4_ecn),
        .ipv4_total_len(ipv4_totalLen),
        .ipv4_identification(ipv4_identification),
        .ipv4_flags(ipv4_flags),
        .ipv4_frag_offset(ipv4_fragOffset),
        .ipv4_ttl(pipeline_ipv4_ttl),
        .ipv4_protocol(ipv4_protocol),
        .ipv4_hdr_checksum(ipv4_hdrChecksum),
        .ipv4_src_addr(ipv4_src_addr),
        .ipv4_dst_addr(ipv4_dst_addr),
        .ipv4_valid(ipv4_valid),
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
        .udp_src_port(udp_src_port),
        .udp_dst_port(udp_dst_port),
        .udp_length(16'd8),
        .udp_checksum(16'd0),
        .udp_valid(udp_valid),
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
    // Task: Configure routing table entry
    // action_data layout: [103:96]=egress_port, [95:48]=src_mac (unused), [47:0]=dst_mac
    // ==========================================
    task configure_route(
        input [9:0]  addr,
        input [31:0] prefix,        // Little-endian IP prefix
        input [5:0]  prefix_len,
        input [2:0]  action_id,     // 0=forward, 1=drop
        input [47:0] dst_mac,
        input [8:0]  egress_p
    );
        @(posedge aclk);
        table_wr_en            <= 1'b1;
        table_wr_addr          <= addr;
        table_entry_valid      <= 1'b1;
        table_entry_prefix     <= prefix;
        table_entry_prefix_len <= prefix_len;
        table_entry_action     <= action_id;
        // Pack action_data: [103:96]=egress_port, [47:0]=dst_mac
        table_entry_action_data <= {24'd0, egress_p[7:0], 48'd0, dst_mac};
        @(posedge aclk);
        table_wr_en <= 1'b0;
        @(posedge aclk);
        $display("[%0t] Route configured: prefix=%08h/%0d action=%0d port=%0d dst_mac=%012h",
                 $time, prefix, prefix_len, action_id, egress_p, dst_mac);
    endtask

    // ==========================================
    // Task: Send UDP packet
    // ==========================================
    task send_udp_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [7:0]  ttl_val,
        input [15:0] src_port_udp,
        input [15:0] dst_port_udp,
        input string description
    );
        logic [DATA_WIDTH-1:0] packet;

        packet = '0;

        // Ethernet header (14 bytes)
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = 16'h0800;  // IPv4

        // IPv4 header (20 bytes) starting at byte 14
        packet[115:112] = 4'd4;       // version
        packet[119:116] = 4'd5;       // ihl
        packet[127:120] = 8'h00;      // tos (diffserv + ecn)
        packet[143:128] = 16'd28;     // total length (20 + 8 = 28 bytes)
        packet[159:144] = 16'h0001;   // identification
        packet[175:160] = 16'h4000;   // flags + frag offset (DF bit set)
        packet[183:176] = ttl_val;    // TTL
        packet[191:184] = 8'd17;      // protocol (UDP)
        packet[207:192] = 16'h0000;   // checksum (placeholder)
        packet[239:208] = src_ip;     // src IP (wire order)
        packet[271:240] = dst_ip;     // dst IP (wire order)

        // UDP header (8 bytes) starting at byte 34
        packet[287:272] = src_port_udp;
        packet[303:288] = dst_port_udp;
        packet[319:304] = 16'd8;      // UDP length
        packet[335:320] = 16'd0;      // UDP checksum

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
        $display("        src_ip=%08h dst_ip=%08h ttl=%0d", src_ip, dst_ip, ttl_val);
    endtask

    // ==========================================
    // Output monitor
    // ==========================================
    always @(posedge aclk) begin
        if (m_axis_tvalid && m_axis_tready && m_axis_tlast) begin
            packets_received++;
            $display("[%0t] Received packet #%0d:", $time, packets_received);
            $display("        DST MAC: %012h", m_axis_tdata[47:0]);
            $display("        SRC MAC: %012h", m_axis_tdata[95:48]);
            $display("        TTL:     %0d", m_axis_tdata[183:176]);
            $display("        Egress:  %0d", pipeline_egress_port);
        end
    end

    // ==========================================
    // Debug: Parser outputs
    // ==========================================
    always @(posedge aclk) begin
        if (parser_payload_valid) begin
            $display("[%0t] PARSER: ipv4_valid=%b dst_ip=%08h src_ip=%08h ttl=%0d",
                    $time, ipv4_valid, ipv4_dst_addr, ipv4_src_addr, ipv4_ttl);
        end
    end

    // ==========================================
    // Debug: Match-Action outputs
    // ==========================================
    always @(posedge aclk) begin
        if (pipeline_valid) begin
            $display("[%0t] MATCH-ACTION: valid=%b drop=%b egress_port=%0d ttl=%0d",
                    $time, pipeline_valid, pipeline_drop, pipeline_egress_port, pipeline_ipv4_ttl);
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
        table_entry_prefix = 0;
        table_entry_prefix_len = 0;
        table_entry_action = 0;
        table_entry_action_data = 0;
        ingress_port  = 9'd0;

        // Wait for reset release
        @(posedge aresetn);
        repeat(10) @(posedge aclk);

        $display("\n========================================================");
        $display("         Basic Router Testbench - LPM Routing");
        $display("========================================================\n");

        // ========================================
        // Configure routing table
        // IP prefixes in BIG-ENDIAN (network order) format to match parser output
        // Parser uses bswap32() converting wire order to network order
        // So 192.168.1.0 = 0xC0A80100 in network order
        // ========================================
        $display("Configuring routing table with LPM entries...\n");

        // Route 1: 192.168.1.0/24 -> forward to port 1
        configure_route(
            .addr(0),
            .prefix(32'hC0A80100),     // 192.168.1.0 in big-endian (network order)
            .prefix_len(6'd24),
            .action_id(3'd0),          // FORWARD
            .dst_mac(48'hAABBCCDD0001),
            .egress_p(9'd1)
        );

        // Route 2: 10.0.0.0/8 -> drop (blackhole)
        configure_route(
            .addr(1),
            .prefix(32'h0A000000),     // 10.0.0.0 in big-endian
            .prefix_len(6'd8),
            .action_id(3'd1),          // DROP
            .dst_mac(48'h000000000000),
            .egress_p(9'd0)
        );

        // Route 3: 172.16.0.0/12 -> forward to port 2
        configure_route(
            .addr(2),
            .prefix(32'hAC100000),     // 172.16.0.0 in big-endian
            .prefix_len(6'd12),
            .action_id(3'd0),          // FORWARD
            .dst_mac(48'hAABBCCDD0002),
            .egress_p(9'd2)
        );

        // Route 4: 192.168.2.0/24 -> forward to port 3 (more specific route)
        configure_route(
            .addr(3),
            .prefix(32'hC0A80200),     // 192.168.2.0 in big-endian
            .prefix_len(6'd24),
            .action_id(3'd0),          // FORWARD
            .dst_mac(48'hAABBCCDD0003),
            .egress_p(9'd3)
        );

        // Route 5: 8.8.8.0/24 -> forward to port 4 (default gateway route)
        configure_route(
            .addr(4),
            .prefix(32'h08080800),     // 8.8.8.0 in big-endian
            .prefix_len(6'd24),
            .action_id(3'd0),          // FORWARD
            .dst_mac(48'hAABBCCDD0004),
            .egress_p(9'd4)
        );

        repeat(10) @(posedge aclk);

        // ========================================
        // Test Cases
        // ========================================

        // Test 1: Packet to 192.168.1.100 -> should forward to port 1, TTL decremented
        $display("\n--- Test 1: 192.168.1.100 (matches /24, forward to port 1) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0102A8C0),     // 192.168.2.1 (little-endian)
            .dst_ip(32'h6401A8C0),     // 192.168.1.100 (little-endian)
            .ttl_val(8'd64),
            .src_port_udp(16'd12345),
            .dst_port_udp(16'd80),
            .description("to 192.168.1.100 -> port 1")
        );
        repeat(30) @(posedge aclk);

        // Test 2: Packet to 10.1.2.3 -> should be dropped (blackhole)
        $display("\n--- Test 2: 10.1.2.3 (matches /8 blackhole, drop) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),     // 192.168.1.1 (little-endian)
            .dst_ip(32'h0302010A),     // 10.1.2.3 (little-endian)
            .ttl_val(8'd64),
            .src_port_udp(16'd12345),
            .dst_port_udp(16'd443),
            .description("to 10.1.2.3 -> DROP")
        );
        repeat(30) @(posedge aclk);

        // Test 3: Packet to 172.16.5.10 -> should forward to port 2
        $display("\n--- Test 3: 172.16.5.10 (matches /12, forward to port 2) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),     // 192.168.1.1 (little-endian)
            .dst_ip(32'h0A0510AC),     // 172.16.5.10 (little-endian)
            .ttl_val(8'd64),
            .src_port_udp(16'd12345),
            .dst_port_udp(16'd8080),
            .description("to 172.16.5.10 -> port 2")
        );
        repeat(30) @(posedge aclk);

        // Test 4: Packet to 192.168.2.50 -> should forward to port 3
        $display("\n--- Test 4: 192.168.2.50 (matches /24, forward to port 3) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),     // 192.168.1.1 (little-endian)
            .dst_ip(32'h3202A8C0),     // 192.168.2.50 (little-endian)
            .ttl_val(8'd64),
            .src_port_udp(16'd54321),
            .dst_port_udp(16'd22),
            .description("to 192.168.2.50 -> port 3")
        );
        repeat(30) @(posedge aclk);

        // Test 5: Packet to 8.8.8.8 -> should forward to port 4
        $display("\n--- Test 5: 8.8.8.8 (matches /24, forward to port 4) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),     // 192.168.1.1 (little-endian)
            .dst_ip(32'h08080808),     // 8.8.8.8 (little-endian)
            .ttl_val(8'd64),
            .src_port_udp(16'd12345),
            .dst_port_udp(16'd53),
            .description("to 8.8.8.8 -> port 4")
        );
        repeat(30) @(posedge aclk);

        // Test 6: Packet with TTL=1 -> should be dropped after decrement
        $display("\n--- Test 6: TTL=1 packet (should drop after TTL decrement) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),     // 192.168.1.1 (little-endian)
            .dst_ip(32'h6401A8C0),     // 192.168.1.100 (little-endian)
            .ttl_val(8'd1),            // TTL=1 -> will expire
            .src_port_udp(16'd12345),
            .dst_port_udp(16'd80),
            .description("TTL=1 -> DROP")
        );
        repeat(30) @(posedge aclk);

        // Test 7: Packet to unknown destination (no route match) -> should drop
        $display("\n--- Test 7: 1.2.3.4 (no route match, default drop) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),     // 192.168.1.1 (little-endian)
            .dst_ip(32'h04030201),     // 1.2.3.4 (little-endian)
            .ttl_val(8'd64),
            .src_port_udp(16'd12345),
            .dst_port_udp(16'd80),
            .description("to 1.2.3.4 -> DROP (no match)")
        );
        repeat(30) @(posedge aclk);

        // Test 8: Packet with TTL=0 -> should be dropped immediately
        $display("\n--- Test 8: TTL=0 packet (should drop immediately) ---");
        send_udp_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),     // 192.168.1.1 (little-endian)
            .dst_ip(32'h6401A8C0),     // 192.168.1.100 (little-endian)
            .ttl_val(8'd0),            // TTL=0 -> should drop
            .src_port_udp(16'd12345),
            .dst_port_udp(16'd80),
            .description("TTL=0 -> DROP")
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
        $display("  - Test 1: FORWARD (port 1) - 192.168.1.100 matches /24");
        $display("  - Test 2: DROP - 10.1.2.3 matches blackhole /8");
        $display("  - Test 3: FORWARD (port 2) - 172.16.5.10 matches /12");
        $display("  - Test 4: FORWARD (port 3) - 192.168.2.50 matches /24");
        $display("  - Test 5: FORWARD (port 4) - 8.8.8.8 matches /24");
        $display("  - Test 6: DROP - TTL=1 expires");
        $display("  - Test 7: DROP - 1.2.3.4 no route match");
        $display("  - Test 8: DROP - TTL=0");
        $display("\nExpected: 4 forwarded, 4 dropped");
        $display("========================================================\n");

        if (packets_received == 4 && forwarded_count == 4 && dropped_count == 4) begin
            $display("*** TEST PASSED ***\n");
        end else begin
            $display("*** TEST FAILED ***\n");
        end

        $finish;
    end

endmodule
