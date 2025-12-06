`timescale 1ns / 1ps

// =============================================================================
// Source Routing Testbench
//
// Tests source-routed packets using srcRoute header stack.
// Each srcRoute entry has:
//   - bos (1 bit): Bottom of Stack indicator
//   - port (15 bits): Egress port for this hop
//
// P4 Logic:
//   - If srcRoutes[0].isValid():
//       - If srcRoutes[0].bos == 1: Set etherType to IPv4 (0x0800)
//       - Pop srcRoutes[0] and forward to srcRoutes[0].port
//       - If ipv4.isValid(): Decrement TTL
//   - Else: Drop packet
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
    localparam MAX_HOPS = 9;

    // EtherTypes
    localparam [15:0] ETHERTYPE_SRCROUTING = 16'h1234;
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
    // Table programming signals (not used for source routing)
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

    // srcRoutes stack from parser
    logic [0:0]  srcRoutes_bos [0:MAX_HOPS-1];
    logic [14:0] srcRoutes_port [0:MAX_HOPS-1];
    logic        srcRoutes_valid [0:MAX_HOPS-1];

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

    // srcRoutes stack output from match_action
    logic [0:0]  out_srcRoutes_bos [0:MAX_HOPS-1];
    logic [14:0] out_srcRoutes_port [0:MAX_HOPS-1];
    logic        out_srcRoutes_valid [0:MAX_HOPS-1];
    logic [3:0]  srcRoutes_ptr_out;

    // ==========================================
    // Parser Instance
    // ==========================================
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .PARSER_CONFIG(8'b10100101)  // Ethernet + IPv4 + UDP + srcRoutes (bit 7)
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
        // srcRoutes stack
        .srcRoutes_bos(srcRoutes_bos),
        .srcRoutes_port(srcRoutes_port),
        .srcRoutes_valid(srcRoutes_valid),
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
        .KEY_WIDTH(32),
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
        // srcRoutes stack inputs
        .srcRoutes_bos(srcRoutes_bos),
        .srcRoutes_port(srcRoutes_port),
        .srcRoutes_valid(srcRoutes_valid),
        .srcRoutes_ptr_in(4'd0),
        .srcRoutes_ptr_out(srcRoutes_ptr_out),
        .mcast_grp(pipeline_mcast_grp),
        .enq_qdepth(19'd0),
        .egress_port_id(pipeline_egress_port_d),
        .packet_out(pipeline_data),
        .packet_keep_out(pipeline_keep),
        .packet_last_out(pipeline_last),
        .packet_valid_out(pipeline_valid),
        .packet_ready_in(pipeline_ready),
        // srcRoutes stack outputs
        .out_srcRoutes_bos(out_srcRoutes_bos),
        .out_srcRoutes_port(out_srcRoutes_port),
        .out_srcRoutes_valid(out_srcRoutes_valid),
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
        .DEPARSER_CONFIG(16'h0425)  // Ethernet + IPv4 + srcRoutes (bit 10)
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
        // srcRoutes stack
        .srcRoutes_ptr(srcRoutes_ptr_out),
        .srcRoutes_bos(out_srcRoutes_bos),
        .srcRoutes_port(out_srcRoutes_port),
        .srcRoutes_valid(out_srcRoutes_valid),
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
    // Task: Send source-routed packet
    // srcRoute format: {bos[0], port[14:0]} = 16 bits = 2 bytes per hop
    // ==========================================
    task send_src_routed_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [7:0]  ttl_val,
        input int    num_hops,
        input [14:0] hop_ports [0:8],  // Up to 9 hops
        input string description
    );
        logic [DATA_WIDTH-1:0] packet;
        int byte_offset;
        int i;

        packet = '0;

        // Ethernet header (14 bytes)
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = ETHERTYPE_SRCROUTING;  // 0x1234

        byte_offset = 14;  // After Ethernet header

        // Source routing stack (2 bytes per hop)
        for (i = 0; i < num_hops; i++) begin
            logic [0:0] bos_bit;
            logic [14:0] port_val;
            logic [15:0] srcRoute_entry;

            bos_bit = (i == num_hops - 1) ? 1'b1 : 1'b0;  // Last hop has BOS=1
            port_val = hop_ports[i];
            // Format: bit 0 = bos, bits 15:1 = port (little endian in packet)
            srcRoute_entry = {port_val, bos_bit};

            packet[byte_offset*8 +: 16] = srcRoute_entry;
            byte_offset = byte_offset + 2;
        end

        // IPv4 header (20 bytes) after srcRoutes
        // Use indexed part-select (+:) for variable byte_offset
        packet[(byte_offset)*8 +: 4]   = 4'd4;       // version (bits 3:0)
        packet[(byte_offset)*8 + 4 +: 4] = 4'd5;    // ihl (bits 7:4)
        packet[(byte_offset + 1)*8 +: 8] = 8'h00;   // tos
        packet[(byte_offset + 2)*8 +: 16] = 16'd20; // total length
        packet[(byte_offset + 4)*8 +: 16] = 16'h0001; // identification
        packet[(byte_offset + 6)*8 +: 16] = 16'h4000; // flags + frag offset
        packet[(byte_offset + 8)*8 +: 8] = ttl_val;   // TTL
        packet[(byte_offset + 9)*8 +: 8] = 8'd17;     // protocol (UDP)
        packet[(byte_offset + 10)*8 +: 16] = 16'h0000; // checksum
        packet[(byte_offset + 12)*8 +: 32] = src_ip;   // src IP
        packet[(byte_offset + 16)*8 +: 32] = dst_ip;   // dst IP

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
        $display("        num_hops=%0d first_port=%0d ttl=%0d", num_hops, hop_ports[0], ttl_val);
    endtask

    // ==========================================
    // Task: Send non-source-routed packet (no srcRoutes header)
    // ==========================================
    task send_regular_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [7:0]  ttl_val,
        input string description
    );
        logic [DATA_WIDTH-1:0] packet;

        packet = '0;

        // Ethernet header (14 bytes) - NO srcRoutes (etherType = IPv4)
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = ETHERTYPE_IPV4;  // 0x0800 - regular IPv4, no source routing

        // IPv4 header at byte 14
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
        $display("[%0t] Sent packet #%0d: %s", $time, packets_sent, description);
        $display("        Regular IPv4 (no srcRoutes) ttl=%0d", ttl_val);
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
            $display("[%0t] PARSER: eth_type=%04h ipv4_valid=%b srcRoutes[0].valid=%b srcRoutes[0].bos=%b srcRoutes[0].port=%0d",
                    $time, eth_type, ipv4_valid, srcRoutes_valid[0], srcRoutes_bos[0], srcRoutes_port[0]);
        end
    end

    // ==========================================
    // Debug: Match-Action outputs
    // ==========================================
    always @(posedge aclk) begin
        if (pipeline_valid) begin
            $display("[%0t] MATCH-ACTION: drop=%b egress_port=%0d srcRoutes_ptr=%0d",
                    $time, pipeline_drop, pipeline_egress_port, srcRoutes_ptr_out);
        end
    end

    // ==========================================
    // Main test sequence
    // ==========================================
    initial begin
        logic [14:0] hop_ports [0:8];

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

        // Initialize hop_ports array
        for (int i = 0; i < 9; i++) hop_ports[i] = 15'd0;

        // Wait for reset release
        @(posedge aresetn);
        repeat(10) @(posedge aclk);

        $display("\n========================================================");
        $display("         Source Routing Testbench");
        $display("========================================================\n");
        $display("Testing source-routed packets with srcRoute header stack.");
        $display("Each srcRoute entry: {port[14:0], bos[0]}");
        $display("P4 Logic: Pop front srcRoute, forward to port, decrement TTL\n");

        // ========================================
        // Test Cases
        // ========================================

        // Test 1: Single hop (BOS=1), forward to port 1
        $display("\n--- Test 1: Single hop (port=1, BOS=1) ---");
        hop_ports[0] = 15'd1;
        send_src_routed_packet(
            .dst_mac(48'hAABBCCDD0001),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),      // 192.168.1.1
            .dst_ip(32'h0201A8C0),      // 192.168.1.2
            .ttl_val(8'd64),
            .num_hops(1),
            .hop_ports(hop_ports),
            .description("Single hop -> port 1")
        );
        repeat(40) @(posedge aclk);

        // Test 2: Two hops, forward to first port (port=2)
        $display("\n--- Test 2: Two hops (port=2 -> port=3) ---");
        hop_ports[0] = 15'd2;
        hop_ports[1] = 15'd3;
        send_src_routed_packet(
            .dst_mac(48'hAABBCCDD0002),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0301A8C0),
            .ttl_val(8'd64),
            .num_hops(2),
            .hop_ports(hop_ports),
            .description("Two hops -> port 2 (first)")
        );
        repeat(40) @(posedge aclk);

        // Test 3: Three hops, forward to first port (port=5)
        $display("\n--- Test 3: Three hops (port=5 -> port=6 -> port=7) ---");
        hop_ports[0] = 15'd5;
        hop_ports[1] = 15'd6;
        hop_ports[2] = 15'd7;
        send_src_routed_packet(
            .dst_mac(48'hAABBCCDD0005),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0401A8C0),
            .ttl_val(8'd64),
            .num_hops(3),
            .hop_ports(hop_ports),
            .description("Three hops -> port 5 (first)")
        );
        repeat(40) @(posedge aclk);

        // Test 4: Large port number (port=500)
        $display("\n--- Test 4: Large port number (port=500) ---");
        hop_ports[0] = 15'd500;
        send_src_routed_packet(
            .dst_mac(48'hAABBCCDD0500),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0501A8C0),
            .ttl_val(8'd64),
            .num_hops(1),
            .hop_ports(hop_ports),
            .description("Large port number 500")
        );
        repeat(40) @(posedge aclk);

        // Test 5: TTL=1 packet (should still forward but TTL becomes 0)
        $display("\n--- Test 5: TTL=1 (TTL decrements to 0) ---");
        hop_ports[0] = 15'd1;
        send_src_routed_packet(
            .dst_mac(48'hAABBCCDD0001),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0601A8C0),
            .ttl_val(8'd1),
            .num_hops(1),
            .hop_ports(hop_ports),
            .description("TTL=1 -> port 1")
        );
        repeat(40) @(posedge aclk);

        // Test 6: Packet without srcRoutes (regular IPv4) -> should DROP
        $display("\n--- Test 6: Regular IPv4 (no srcRoutes) -> DROP ---");
        send_regular_packet(
            .dst_mac(48'hAABBCCDD0001),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0701A8C0),
            .ttl_val(8'd64),
            .description("No srcRoutes -> DROP")
        );
        repeat(40) @(posedge aclk);

        // Test 7: Maximum hops (9 hops)
        $display("\n--- Test 7: Maximum hops (9) -> port 10 (first) ---");
        hop_ports[0] = 15'd10;
        hop_ports[1] = 15'd11;
        hop_ports[2] = 15'd12;
        hop_ports[3] = 15'd13;
        hop_ports[4] = 15'd14;
        hop_ports[5] = 15'd15;
        hop_ports[6] = 15'd16;
        hop_ports[7] = 15'd17;
        hop_ports[8] = 15'd18;
        send_src_routed_packet(
            .dst_mac(48'hAABBCCDD0010),
            .src_mac(48'h112233445566),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0801A8C0),
            .ttl_val(8'd64),
            .num_hops(9),
            .hop_ports(hop_ports),
            .description("9 hops -> port 10 (first)")
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
        $display("  - Test 1: FORWARD (port 1) - Single hop with BOS=1");
        $display("  - Test 2: FORWARD (port 2) - First of two hops");
        $display("  - Test 3: FORWARD (port 5) - First of three hops");
        $display("  - Test 4: FORWARD (port 500) - Large port number");
        $display("  - Test 5: FORWARD (port 1) - TTL=1 decrements to 0");
        $display("  - Test 6: DROP - No srcRoutes header (regular IPv4)");
        $display("  - Test 7: FORWARD (port 10) - First of 9 hops");
        $display("\nExpected: 6 forwarded, 1 dropped");
        $display("========================================================\n");

        if (packets_received == 6 && dropped_count == 1) begin
            $display("*** TEST PASSED ***\n");
        end else begin
            $display("*** TEST FAILED ***\n");
        end

        $finish;
    end

endmodule
