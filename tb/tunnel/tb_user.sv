`timescale 1ns / 1ps

// =============================================================================
// Tunnel Testbench
//
// Tests myTunnel encapsulation and forwarding.
// myTunnel header: {proto_id[15:0], dst_id[15:0]} = 32 bits = 4 bytes
//
// P4 Logic:
//   - If ipv4.isValid() && !myTunnel.isValid():
//       Apply ipv4_lpm table (L3 forwarding with TTL decrement)
//   - If myTunnel.isValid():
//       Apply myTunnel_exact table (tunnel forwarding by dst_id)
//
// EtherTypes:
//   - 0x1212 = TYPE_MYTUNNEL (tunnel encapsulated)
//   - 0x0800 = TYPE_IPV4 (regular IPv4)
//
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

    // EtherTypes
    localparam [15:0] ETHERTYPE_MYTUNNEL = 16'h1212;
    localparam [15:0] ETHERTYPE_IPV4 = 16'h0800;

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
    logic [31:0] table_entry_key;
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

    // myTunnel header from parser
    logic        myTunnel_valid;
    logic [15:0] myTunnel_proto_id;
    logic [15:0] myTunnel_dst_id;

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
    logic [15:0]            pipeline_mcast_grp;

    // myTunnel output from match_action
    logic        out_myTunnel_valid;
    logic [15:0] out_myTunnel_proto_id;
    logic [15:0] out_myTunnel_dst_id;

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
        // myTunnel custom header
        .myTunnel_proto_id(myTunnel_proto_id),
        .myTunnel_dst_id(myTunnel_dst_id),
        .myTunnel_valid(myTunnel_valid),
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
        .KEY_WIDTH(32),                // 32-bit for IPv4 LPM or 16-bit tunnel dst_id
        .ACTION_DATA_WIDTH(ACTION_DATA_WIDTH),
        .ACTION_CONFIG(8'b00000111),   // Forward, Drop, Modify
        .EGRESS_CONFIG(8'b00000000),
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
        // myTunnel inputs
        .myTunnel_dst_id(myTunnel_dst_id),
        .myTunnel_proto_id(myTunnel_proto_id),
        .myTunnel_valid(myTunnel_valid),
        .mcast_grp(pipeline_mcast_grp),
        .enq_qdepth(19'd0),
        .egress_port_id(pipeline_egress_port_d),
        .packet_out(pipeline_data),
        .packet_keep_out(pipeline_keep),
        .packet_last_out(pipeline_last),
        .packet_valid_out(pipeline_valid),
        .packet_ready_in(pipeline_ready),
        // myTunnel outputs
        .out_myTunnel_dst_id(out_myTunnel_dst_id),
        .out_myTunnel_proto_id(out_myTunnel_proto_id),
        .out_myTunnel_valid(out_myTunnel_valid),
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
        .table_entry_key(table_entry_key),
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
        .eth_dst_addr(pipeline_eth_dst),
        .eth_src_addr(pipeline_eth_src),
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
        // myTunnel
        .myTunnel_proto_id(out_myTunnel_proto_id),
        .myTunnel_dst_id(out_myTunnel_dst_id),
        .myTunnel_valid(out_myTunnel_valid),
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
    // Task: Configure IPv4 LPM table entry
    // ==========================================
    task configure_ipv4_route(
        input [9:0]  addr,
        input [31:0] prefix,
        input [5:0]  prefix_len,
        input [2:0]  action_id,     // 0=forward, 1=drop
        input [47:0] dst_mac,
        input [8:0]  egress_p
    );
        @(posedge aclk);
        table_wr_en            <= 1'b1;
        table_wr_addr          <= addr;
        table_entry_valid      <= 1'b1;
        table_entry_key        <= prefix;
        table_entry_prefix_len <= prefix_len;
        table_entry_action     <= action_id;
        table_entry_action_data <= {24'd0, egress_p[7:0], 48'd0, dst_mac};
        @(posedge aclk);
        table_wr_en <= 1'b0;
        @(posedge aclk);
        $display("[%0t] IPv4 route: prefix=%08h/%0d action=%0d port=%0d",
                 $time, prefix, prefix_len, action_id, egress_p);
    endtask

    // ==========================================
    // Task: Configure tunnel table entry (exact match on dst_id)
    // ==========================================
    task configure_tunnel_route(
        input [9:0]  addr,
        input [15:0] dst_id,
        input [2:0]  action_id,     // 0=forward, 1=drop
        input [8:0]  egress_p
    );
        @(posedge aclk);
        table_wr_en            <= 1'b1;
        table_wr_addr          <= addr;
        table_entry_valid      <= 1'b1;
        table_entry_key        <= {16'd0, dst_id};  // 16-bit dst_id in lower bits
        table_entry_prefix_len <= 6'd16;            // Exact match
        table_entry_action     <= action_id;
        // For tunnel forward, only egress port matters
        table_entry_action_data <= {24'd0, egress_p[7:0], 96'd0};
        @(posedge aclk);
        table_wr_en <= 1'b0;
        @(posedge aclk);
        $display("[%0t] Tunnel route: dst_id=%0d action=%0d port=%0d",
                 $time, dst_id, action_id, egress_p);
    endtask

    // ==========================================
    // Task: Send regular IPv4 packet (no tunnel)
    // ==========================================
    task send_ipv4_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [7:0]  ttl_val,
        input string description
    );
        logic [DATA_WIDTH-1:0] packet;

        packet = '0;

        // Ethernet header (14 bytes)
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = ETHERTYPE_IPV4;  // 0x0800

        // IPv4 header (20 bytes) starting at byte 14
        packet[115:112] = 4'd4;       // version
        packet[119:116] = 4'd5;       // ihl
        packet[127:120] = 8'h00;      // tos
        packet[143:128] = 16'd20;     // total length
        packet[159:144] = 16'h0001;   // identification
        packet[175:160] = 16'h4000;   // flags + frag offset
        packet[183:176] = ttl_val;    // TTL
        packet[191:184] = 8'd17;      // protocol (UDP)
        packet[207:192] = 16'h0000;   // checksum
        packet[239:208] = src_ip;     // src IP
        packet[271:240] = dst_ip;     // dst IP

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
        $display("[%0t] Sent IPv4 packet #%0d: %s", $time, packets_sent, description);
        $display("        dst_ip=%08h ttl=%0d", dst_ip, ttl_val);
    endtask

    // ==========================================
    // Task: Send tunneled packet (myTunnel + IPv4)
    // ==========================================
    task send_tunnel_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [15:0] tunnel_dst_id,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [7:0]  ttl_val,
        input string description
    );
        logic [DATA_WIDTH-1:0] packet;

        packet = '0;

        // Ethernet header (14 bytes)
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = ETHERTYPE_MYTUNNEL;  // 0x1212

        // myTunnel header (4 bytes) at byte 14
        // Format: {proto_id[15:0], dst_id[15:0]}
        packet[127:112] = ETHERTYPE_IPV4;      // proto_id = 0x0800 (inner is IPv4)
        packet[143:128] = tunnel_dst_id;       // dst_id

        // IPv4 header (20 bytes) starting at byte 18 (after myTunnel)
        packet[147:144] = 4'd4;       // version
        packet[151:148] = 4'd5;       // ihl
        packet[159:152] = 8'h00;      // tos
        packet[175:160] = 16'd20;     // total length
        packet[191:176] = 16'h0001;   // identification
        packet[207:192] = 16'h4000;   // flags + frag offset
        packet[215:208] = ttl_val;    // TTL
        packet[223:216] = 8'd17;      // protocol (UDP)
        packet[239:224] = 16'h0000;   // checksum
        packet[271:240] = src_ip;     // src IP
        packet[303:272] = dst_ip;     // dst IP

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
        $display("[%0t] Sent TUNNEL packet #%0d: %s", $time, packets_sent, description);
        $display("        tunnel_dst_id=%0d inner_dst_ip=%08h ttl=%0d", tunnel_dst_id, dst_ip, ttl_val);
    endtask

    // ==========================================
    // Output monitor
    // ==========================================
    always @(posedge aclk) begin
        if (m_axis_tvalid && m_axis_tready && m_axis_tlast) begin
            packets_received++;
            $display("[%0t] Received packet #%0d:", $time, packets_received);
            $display("        DST MAC:     %012h", m_axis_tdata[47:0]);
            $display("        SRC MAC:     %012h", m_axis_tdata[95:48]);
            $display("        EtherType:   %04h", m_axis_tdata[111:96]);
            $display("        Egress Port: %0d", pipeline_egress_port);
        end
    end

    // ==========================================
    // Debug: Parser outputs
    // ==========================================
    always @(posedge aclk) begin
        if (parser_payload_valid) begin
            $display("[%0t] PARSER: ipv4_valid=%b myTunnel_valid=%b dst_id=%0d dst_ip=%08h",
                    $time, ipv4_valid, myTunnel_valid, myTunnel_dst_id, ipv4_dst_addr);
        end
    end

    // ==========================================
    // Debug: Match-Action outputs
    // ==========================================
    always @(posedge aclk) begin
        if (pipeline_valid) begin
            $display("[%0t] MATCH-ACTION: drop=%b egress_port=%0d ttl=%0d",
                    $time, pipeline_drop, pipeline_egress_port, pipeline_ipv4_ttl);
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
        $display("         Tunnel Testbench - myTunnel Forwarding");
        $display("========================================================\n");
        $display("Testing myTunnel encapsulation (EtherType 0x1212)");
        $display("myTunnel header: {proto_id, dst_id} = 32 bits\n");

        // ========================================
        // Configure IPv4 LPM table (for non-tunneled packets)
        // ========================================
        $display("Configuring IPv4 LPM table...\n");

        // Route 1: 192.168.1.0/24 -> forward to port 1
        configure_ipv4_route(
            .addr(0),
            .prefix(32'hC0A80100),     // 192.168.1.0
            .prefix_len(6'd24),
            .action_id(3'd0),          // FORWARD
            .dst_mac(48'hAABBCCDD0001),
            .egress_p(9'd1)
        );

        // Route 2: 10.0.0.0/8 -> forward to port 2
        configure_ipv4_route(
            .addr(1),
            .prefix(32'h0A000000),     // 10.0.0.0
            .prefix_len(6'd8),
            .action_id(3'd0),          // FORWARD
            .dst_mac(48'hAABBCCDD0002),
            .egress_p(9'd2)
        );

        // ========================================
        // Configure tunnel table (exact match on dst_id)
        // ========================================
        $display("\nConfiguring Tunnel table...\n");

        // Tunnel 100 -> port 3
        configure_tunnel_route(
            .addr(10),
            .dst_id(16'd100),
            .action_id(3'd0),          // FORWARD
            .egress_p(9'd3)
        );

        // Tunnel 200 -> port 4
        configure_tunnel_route(
            .addr(11),
            .dst_id(16'd200),
            .action_id(3'd0),          // FORWARD
            .egress_p(9'd4)
        );

        // Tunnel 300 -> port 5
        configure_tunnel_route(
            .addr(12),
            .dst_id(16'd300),
            .action_id(3'd0),          // FORWARD
            .egress_p(9'd5)
        );

        repeat(10) @(posedge aclk);

        // ========================================
        // Test Cases
        // ========================================

        // Test 1: Regular IPv4 packet to 192.168.1.100 -> forward to port 1, TTL decremented
        $display("\n--- Test 1: Regular IPv4 (no tunnel) to 192.168.1.100 ---");
        send_ipv4_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0A000001),      // 10.0.0.1
            .dst_ip(32'h6401A8C0),      // 192.168.1.100 (little-endian)
            .ttl_val(8'd64),
            .description("IPv4 to 192.168.1.100 -> port 1")
        );
        repeat(40) @(posedge aclk);

        // Test 2: Tunneled packet with dst_id=100 -> forward to port 3
        $display("\n--- Test 2: Tunnel dst_id=100 -> port 3 ---");
        send_tunnel_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .tunnel_dst_id(16'd100),
            .src_ip(32'h0A000001),
            .dst_ip(32'h0A000002),
            .ttl_val(8'd64),
            .description("Tunnel 100 -> port 3")
        );
        repeat(40) @(posedge aclk);

        // Test 3: Tunneled packet with dst_id=200 -> forward to port 4
        $display("\n--- Test 3: Tunnel dst_id=200 -> port 4 ---");
        send_tunnel_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .tunnel_dst_id(16'd200),
            .src_ip(32'h0A000001),
            .dst_ip(32'h0A000003),
            .ttl_val(8'd64),
            .description("Tunnel 200 -> port 4")
        );
        repeat(40) @(posedge aclk);

        // Test 4: Tunneled packet with dst_id=300 -> forward to port 5
        $display("\n--- Test 4: Tunnel dst_id=300 -> port 5 ---");
        send_tunnel_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .tunnel_dst_id(16'd300),
            .src_ip(32'h0A000001),
            .dst_ip(32'h0A000004),
            .ttl_val(8'd64),
            .description("Tunnel 300 -> port 5")
        );
        repeat(40) @(posedge aclk);

        // Test 5: Tunneled packet with unknown dst_id=999 -> DROP (default action)
        $display("\n--- Test 5: Tunnel dst_id=999 (no match) -> DROP ---");
        send_tunnel_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .tunnel_dst_id(16'd999),
            .src_ip(32'h0A000001),
            .dst_ip(32'h0A000005),
            .ttl_val(8'd64),
            .description("Tunnel 999 -> DROP")
        );
        repeat(40) @(posedge aclk);

        // Test 6: Regular IPv4 packet to 10.1.2.3 -> forward to port 2
        $display("\n--- Test 6: Regular IPv4 to 10.1.2.3 -> port 2 ---");
        send_ipv4_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'hC0A80101),      // 192.168.1.1
            .dst_ip(32'h0302010A),      // 10.1.2.3 (little-endian)
            .ttl_val(8'd64),
            .description("IPv4 to 10.1.2.3 -> port 2")
        );
        repeat(40) @(posedge aclk);

        // Test 7: Regular IPv4 with TTL=1 -> DROP (TTL expires)
        $display("\n--- Test 7: Regular IPv4 TTL=1 -> DROP ---");
        send_ipv4_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0A000001),
            .dst_ip(32'h6401A8C0),      // 192.168.1.100
            .ttl_val(8'd1),
            .description("IPv4 TTL=1 -> DROP")
        );
        repeat(40) @(posedge aclk);

        // Test 8: Regular IPv4 to unknown dest -> DROP (no route)
        $display("\n--- Test 8: Regular IPv4 to 1.2.3.4 (no route) -> DROP ---");
        send_ipv4_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .src_ip(32'h0A000001),
            .dst_ip(32'h04030201),      // 1.2.3.4 (little-endian)
            .ttl_val(8'd64),
            .description("IPv4 to 1.2.3.4 -> DROP")
        );
        repeat(40) @(posedge aclk);

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
        $display("  - Test 1: FORWARD (port 1) - Regular IPv4 to 192.168.1.100");
        $display("  - Test 2: FORWARD (port 3) - Tunnel dst_id=100");
        $display("  - Test 3: FORWARD (port 4) - Tunnel dst_id=200");
        $display("  - Test 4: FORWARD (port 5) - Tunnel dst_id=300");
        $display("  - Test 5: DROP - Tunnel dst_id=999 (no match)");
        $display("  - Test 6: FORWARD (port 2) - Regular IPv4 to 10.1.2.3");
        $display("  - Test 7: DROP - Regular IPv4 TTL=1 expires");
        $display("  - Test 8: DROP - Regular IPv4 to 1.2.3.4 (no route)");
        $display("\nExpected: 5 forwarded, 3 dropped");
        $display("========================================================\n");

        if (packets_received == 5 && dropped_count == 3) begin
            $display("*** TEST PASSED ***\n");
        end else begin
            $display("*** TEST FAILED ***\n");
        end

        $finish;
    end

endmodule
