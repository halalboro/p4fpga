`timescale 1ns / 1ps

// =============================================================================
// MRI (Multi-hop Route Inspection / INT) Testbench
//
// Tests In-band Network Telemetry functionality:
// - IPv4 packets with MRI option (option=31)
// - Egress table executes add_swtrace action
// - Adds switch trace (swid, qdepth) to packet
// - Updates: mri.count++, ipv4.ihl+2, optionLength+8, totalLen+8
//
// P4 Logic:
// - Ingress: ipv4_lpm table -> ipv4_forward action (set egress port, MAC swap, TTL--)
// - Egress: if mri.isValid(): swtrace table -> add_swtrace action
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

    // EtherType
    localparam [15:0] ETHERTYPE_IPV4 = 16'h0800;

    // IPv4 Option for MRI
    localparam [4:0] IPV4_OPTION_MRI = 5'd31;

    // Action IDs
    localparam [2:0] ACTION_IPV4_FORWARD = 3'd0;
    localparam [2:0] ACTION_DROP = 3'd1;
    localparam [2:0] ACTION_NOACTION = 3'd2;

    // Egress Action IDs
    localparam [2:0] EGRESS_ACTION_ADD_SWTRACE = 3'd0;
    localparam [2:0] EGRESS_ACTION_NOACTION = 3'd1;

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
    // Ingress Table Programming Signals
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
    logic [15:0] udp_src_port, udp_dst_port;

    // IPv4 Option from parser
    logic [0:0]  ipv4_option_copyFlag;
    logic [1:0]  ipv4_option_optClass;
    logic [4:0]  ipv4_option_option;
    logic [7:0]  ipv4_option_optionLength;
    logic        ipv4_option_valid;

    // MRI header from parser
    logic [15:0] mri_count;
    logic        mri_valid;

    // swtraces stack from parser
    logic [31:0] swtraces_qdepth [0:MAX_HOPS-1];
    logic [31:0] swtraces_swid [0:MAX_HOPS-1];
    logic        swtraces_valid [0:MAX_HOPS-1];

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

    // MRI outputs from match_action
    logic [15:0]            out_mri_count;
    logic [3:0]             out_ipv4_ihl;
    logic [7:0]             out_ipv4_option_length;
    logic [15:0]            out_ipv4_total_len;
    logic [31:0]            out_swtraces_0_swid;
    logic [31:0]            out_swtraces_0_qdepth;
    logic                   out_swtraces_0_valid;

    // IPv4 Option outputs
    logic [0:0]             out_ipv4_option_copyFlag;
    logic [1:0]             out_ipv4_option_optClass;
    logic [4:0]             out_ipv4_option_option;
    logic [7:0]             out_ipv4_option_optionLength;
    logic                   out_ipv4_option_valid;

    // swtraces outputs
    logic [31:0]            out_swtraces_qdepth [0:MAX_HOPS-1];
    logic [31:0]            out_swtraces_swid [0:MAX_HOPS-1];
    logic                   out_swtraces_valid [0:MAX_HOPS-1];

    // Stack pointer
    logic [3:0]             swtraces_ptr_in;
    logic [3:0]             swtraces_ptr_out;

    // Egress control
    logic [18:0]            enq_qdepth;
    logic [18:0]            deq_qdepth;

    // ==========================================
    // Parser Instance
    // ==========================================
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .PARSER_CONFIG(16'b0000011110000101)  // Eth + IPv4 + ipv4_option + mri + swtraces
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
        .tcp_valid(),
        .udp_src_port(udp_src_port),
        .udp_dst_port(udp_dst_port),
        .udp_length(),
        .udp_checksum(),
        .udp_valid(),
        .vxlan_flags(),
        .vxlan_reserved(),
        .vxlan_vni(),
        .vxlan_reserved2(),
        .vxlan_valid(),
        // IPv4 Option
        .ipv4_option_copyFlag(ipv4_option_copyFlag),
        .ipv4_option_optClass(ipv4_option_optClass),
        .ipv4_option_option(ipv4_option_option),
        .ipv4_option_optionLength(ipv4_option_optionLength),
        .ipv4_option_valid(ipv4_option_valid),
        // MRI header
        .mri_count(mri_count),
        .mri_valid(mri_valid),
        // swtraces stack
        .swtraces_qdepth(swtraces_qdepth),
        .swtraces_swid(swtraces_swid),
        .swtraces_valid(swtraces_valid),
        .payload_data(parser_payload_data),
        .payload_keep(parser_payload_keep),
        .payload_valid(parser_payload_valid),
        .payload_last(parser_payload_last),
        .packet_length(parser_packet_length),
        .ingress_port(parser_ingress_port)
    );

    // Egress port delay for feedback
    always_ff @(posedge aclk) pipeline_egress_port_d <= pipeline_egress_port;

    // Stack pointer feedback
    always_ff @(posedge aclk or negedge aresetn) begin
        if (!aresetn)
            swtraces_ptr_in <= 4'd0;
        else if (pipeline_valid)
            swtraces_ptr_in <= swtraces_ptr_out;
    end

    // ==========================================
    // Match-Action Pipeline Instance
    // ==========================================
    match_action #(
        .DATA_WIDTH(DATA_WIDTH),
        .METADATA_WIDTH(64),
        .TABLE_SIZE(1024),
        .KEY_WIDTH(32),
        .ACTION_DATA_WIDTH(ACTION_DATA_WIDTH),
        .ACTION_CONFIG(8'b00000111),   // Forward, Drop, Modify
        .EGRESS_CONFIG(8'b00110001),   // ENABLE_EGRESS | ENABLE_EGRESS_TABLE | ENABLE_PUSH_FRONT
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
        // IPv4 Option inputs
        .ipv4_option_copyFlag(ipv4_option_copyFlag),
        .ipv4_option_optClass(ipv4_option_optClass),
        .ipv4_option_option(ipv4_option_option),
        .ipv4_option_optionLength(ipv4_option_optionLength),
        .ipv4_option_valid(ipv4_option_valid),
        // MRI inputs
        .mri_count(mri_count),
        .mri_valid(mri_valid),
        // swtraces inputs
        .swtraces_qdepth(swtraces_qdepth),
        .swtraces_swid(swtraces_swid),
        .swtraces_valid(swtraces_valid),
        // MRI-specific inputs
        .ipv4_ihl(ipv4_ihl),
        .ipv4_total_len(ipv4_totalLen),
        // Stack pointer
        .swtraces_ptr_in(swtraces_ptr_in),
        .swtraces_ptr_out(swtraces_ptr_out),
        // Egress control
        .mcast_grp(pipeline_mcast_grp),
        .enq_qdepth(enq_qdepth),
        .deq_qdepth(deq_qdepth),
        .egress_port_id(pipeline_egress_port_d),
        // Packet output
        .packet_out(pipeline_data),
        .packet_keep_out(pipeline_keep),
        .packet_last_out(pipeline_last),
        .packet_valid_out(pipeline_valid),
        .packet_ready_in(pipeline_ready),
        // IPv4 Option outputs
        .out_ipv4_option_copyFlag(out_ipv4_option_copyFlag),
        .out_ipv4_option_optClass(out_ipv4_option_optClass),
        .out_ipv4_option_option(out_ipv4_option_option),
        .out_ipv4_option_optionLength(out_ipv4_option_optionLength),
        .out_ipv4_option_valid(out_ipv4_option_valid),
        // MRI outputs
        .out_mri_count(out_mri_count),
        .out_ipv4_ihl(out_ipv4_ihl),
        .out_ipv4_option_length(out_ipv4_option_length),
        .out_ipv4_total_len(out_ipv4_total_len),
        .out_swtraces_0_swid(out_swtraces_0_swid),
        .out_swtraces_0_qdepth(out_swtraces_0_qdepth),
        .out_swtraces_0_valid(out_swtraces_0_valid),
        // swtraces outputs
        .out_swtraces_qdepth(out_swtraces_qdepth),
        .out_swtraces_swid(out_swtraces_swid),
        .out_swtraces_valid(out_swtraces_valid),
        // Modified header outputs
        .out_ipv4_diffserv(pipeline_ipv4_diffserv),
        .out_ipv4_ecn(pipeline_ipv4_ecn),
        .out_ipv4_ttl(pipeline_ipv4_ttl),
        .out_eth_dst_addr(pipeline_eth_dst),
        .out_eth_src_addr(pipeline_eth_src),
        .drop(pipeline_drop),
        .egress_port(pipeline_egress_port),
        .header_modified(pipeline_header_modified),
        .ecn_marked(),
        // Table programming
        .table_write_enable(table_wr_en),
        .table_write_addr(table_wr_addr),
        .table_entry_valid(table_entry_valid),
        .table_entry_key(table_entry_key),
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
        .DEPARSER_CONFIG(16'b0001110010000101)  // Eth + IPv4 + checksum + ipv4_option + mri + swtraces
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
        .ipv4_ihl(out_ipv4_ihl),
        .ipv4_diffserv(pipeline_ipv4_diffserv),
        .ipv4_ecn(pipeline_ipv4_ecn),
        .ipv4_total_len(out_ipv4_total_len),
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
        .udp_src_port(16'd0),
        .udp_dst_port(16'd0),
        .udp_length(16'd8),
        .udp_checksum(16'd0),
        .udp_valid(1'b0),
        .vxlan_flags(8'd0),
        .vxlan_reserved(24'd0),
        .vxlan_vni(24'd0),
        .vxlan_reserved2(8'd0),
        .vxlan_valid(1'b0),
        // IPv4 Option
        .ipv4_option_copyFlag(out_ipv4_option_copyFlag),
        .ipv4_option_optClass(out_ipv4_option_optClass),
        .ipv4_option_option(out_ipv4_option_option),
        .ipv4_option_optionLength(out_ipv4_option_length),
        .ipv4_option_valid(out_ipv4_option_valid),
        // MRI header
        .mri_count(out_mri_count),
        .mri_valid(mri_valid),
        // swtraces stack
        .swtraces_ptr(swtraces_ptr_out),
        .swtraces_qdepth(out_swtraces_qdepth),
        .swtraces_swid(out_swtraces_swid),
        .swtraces_valid(out_swtraces_valid),
        // Payload input
        .s_axis_tdata(pipeline_data),
        .s_axis_tkeep(pipeline_keep),
        .s_axis_tvalid(pipeline_valid),
        .s_axis_tlast(pipeline_last),
        .s_axis_tready(pipeline_ready),
        .drop_packet(pipeline_drop),
        // Output packet
        .m_axis_tdata(m_axis_tdata),
        .m_axis_tkeep(m_axis_tkeep),
        .m_axis_tvalid(m_axis_tvalid),
        .m_axis_tlast(m_axis_tlast),
        .m_axis_tready(m_axis_tready)
    );

    // ==========================================
    // Task: Send MRI packet with switch traces
    // ==========================================
    task send_mri_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [31:0] src_ip,
        input [31:0] dst_ip,
        input [7:0]  ttl_val,
        input [15:0] existing_count,  // Number of existing swtraces
        input string description
    );
        logic [DATA_WIDTH-1:0] packet;
        int byte_offset;
        int i;
        logic [3:0] ihl_val;
        logic [7:0] option_len;
        logic [15:0] total_len;

        packet = '0;

        // Calculate header sizes
        // IHL = 5 (base) + 1 (ipv4_option 2B) + 1 (mri 2B) + existing_count*2 (switch_t 8B each = 2 words)
        ihl_val = 4'd5 + 4'd1 + 4'd1 + existing_count[3:0] * 2;
        // Option length = 2 (mri header) + existing_count * 8 (switch_t)
        option_len = 8'd4 + existing_count[7:0] * 8;  // 4 = 2B option + 2B mri
        // Total length = IHL*4 + payload (assume 0 payload for test)
        total_len = {12'd0, ihl_val} * 4;

        // Ethernet header (14 bytes)
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = ETHERTYPE_IPV4;

        byte_offset = 14;  // After Ethernet header

        // IPv4 header (20 bytes minimum)
        packet[(byte_offset)*8 +: 4]     = 4'd4;          // version
        packet[(byte_offset)*8 + 4 +: 4] = ihl_val;       // ihl
        packet[(byte_offset + 1)*8 +: 8] = 8'h00;         // diffserv + ecn
        packet[(byte_offset + 2)*8 +: 16] = {total_len[7:0], total_len[15:8]};  // total length (network order)
        packet[(byte_offset + 4)*8 +: 16] = 16'h0001;     // identification
        packet[(byte_offset + 6)*8 +: 16] = 16'h4000;     // flags + frag offset
        packet[(byte_offset + 8)*8 +: 8]  = ttl_val;      // TTL
        packet[(byte_offset + 9)*8 +: 8]  = 8'd17;        // protocol (UDP)
        packet[(byte_offset + 10)*8 +: 16] = 16'h0000;    // checksum
        packet[(byte_offset + 12)*8 +: 32] = src_ip;      // src IP
        packet[(byte_offset + 16)*8 +: 32] = dst_ip;      // dst IP

        byte_offset = byte_offset + 20;  // After base IPv4 header

        // IPv4 Option header (2 bytes)
        // copyFlag=1, optClass=0, option=31 (MRI)
        packet[(byte_offset)*8 +: 8] = {2'b00, 1'b1, IPV4_OPTION_MRI};  // copyFlag|optClass|option
        packet[(byte_offset + 1)*8 +: 8] = option_len;                   // optionLength

        byte_offset = byte_offset + 2;

        // MRI header (2 bytes)
        packet[(byte_offset)*8 +: 16] = {existing_count[7:0], existing_count[15:8]};  // count (network order)

        byte_offset = byte_offset + 2;

        // Existing switch traces (8 bytes each: swid + qdepth)
        for (i = 0; i < existing_count; i++) begin
            // swid (4 bytes)
            packet[(byte_offset)*8 +: 32] = 32'h00000000 + i + 1;  // swid = 1, 2, 3...
            byte_offset = byte_offset + 4;
            // qdepth (4 bytes)
            packet[(byte_offset)*8 +: 32] = 32'h00000064 * (i + 1);  // qdepth = 100, 200, 300...
            byte_offset = byte_offset + 4;
        end

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
        $display("        ihl=%0d total_len=%0d option_len=%0d mri_count=%0d ttl=%0d",
                ihl_val, total_len, option_len, existing_count, ttl_val);
    endtask

    // ==========================================
    // Task: Send regular IPv4 packet (no MRI)
    // ==========================================
    task send_regular_ipv4_packet(
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
        packet[111:96]  = ETHERTYPE_IPV4;

        // IPv4 header at byte 14 (IHL=5, no options)
        packet[115:112] = 4'd4;       // version
        packet[119:116] = 4'd5;       // ihl (no options)
        packet[127:120] = 8'h00;      // tos
        packet[143:128] = 16'd40;     // total length (20B header + 20B payload)
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
        $display("        Regular IPv4 (no MRI) ttl=%0d", ttl_val);
    endtask

    // ==========================================
    // Task: Configure ingress LPM table entry
    // ==========================================
    task configure_ingress_route(
        input [9:0]  addr,
        input [31:0] prefix,
        input [5:0]  prefix_len,
        input [2:0]  action_id,
        input [47:0] dst_mac,
        input [8:0]  egress_port
    );
        // action_data format for ipv4_forward: [56:48]=port, [47:0]=dstAddr
        logic [ACTION_DATA_WIDTH-1:0] action_data;
        action_data = '0;
        action_data[47:0] = dst_mac;
        action_data[56:48] = egress_port;

        @(posedge aclk);
        table_wr_en           <= 1'b1;
        table_wr_addr         <= addr;
        table_entry_valid     <= 1'b1;
        table_entry_key       <= prefix;
        table_entry_prefix_len <= prefix_len;
        table_entry_action    <= action_id;
        table_entry_action_data <= action_data;

        @(posedge aclk);
        table_wr_en <= 1'b0;

        $display("[%0t] Configured ingress route: %h/%0d -> port %0d (action=%0d)",
                 $time, prefix, prefix_len, egress_port, action_id);
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
            $display("        IPv4 IHL:    %0d", m_axis_tdata[119:116]);
            $display("        Egress Port: %0d", pipeline_egress_port);
        end
    end

    // ==========================================
    // Debug: Parser outputs
    // ==========================================
    always @(posedge aclk) begin
        if (parser_payload_valid) begin
            $display("[%0t] PARSER: ipv4_valid=%b mri_valid=%b mri_count=%0d ipv4_ihl=%0d",
                    $time, ipv4_valid, mri_valid, mri_count, ipv4_ihl);
        end
    end

    // ==========================================
    // Debug: Match-Action MRI outputs
    // ==========================================
    always @(posedge aclk) begin
        if (pipeline_valid && mri_valid) begin
            $display("[%0t] MRI OUTPUT: mri_count=%0d->%0d ipv4_ihl=%0d->%0d total_len=%0d->%0d",
                    $time, mri_count, out_mri_count, ipv4_ihl, out_ipv4_ihl,
                    ipv4_totalLen, out_ipv4_total_len);
            $display("        swtraces[0]: swid=%0d qdepth=%0d valid=%b",
                    out_swtraces_0_swid, out_swtraces_0_qdepth, out_swtraces_0_valid);
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
        enq_qdepth    = 19'd0;
        deq_qdepth    = 19'd100;  // Simulated queue depth

        // Wait for reset release
        @(posedge aresetn);
        repeat(10) @(posedge aclk);

        $display("\n========================================================");
        $display("           MRI (INT) Testbench");
        $display("========================================================\n");
        $display("Testing In-band Network Telemetry functionality.");
        $display("P4 Logic:");
        $display("  - Ingress: ipv4_lpm -> ipv4_forward (MAC swap, TTL--)");
        $display("  - Egress: if mri.isValid(): add_swtrace");
        $display("    - mri.count++");
        $display("    - push_front swtraces[0]");
        $display("    - swtraces[0].swid = table_param, qdepth = deq_qdepth");
        $display("    - ipv4.ihl+2, optionLength+8, totalLen+8\n");

        // ========================================
        // Configure Ingress Table (ipv4_lpm)
        // ========================================
        $display("\n--- Configuring Ingress LPM Table ---");

        // Route for 10.0.0.0/8 -> forward to port 1
        configure_ingress_route(
            .addr(0),
            .prefix(32'h0000000A),    // 10.0.0.0 in little-endian
            .prefix_len(8),
            .action_id(ACTION_IPV4_FORWARD),
            .dst_mac(48'hAABBCCDDEE01),
            .egress_port(9'd1)
        );

        // Route for 192.168.1.0/24 -> forward to port 2
        configure_ingress_route(
            .addr(1),
            .prefix(32'h0001A8C0),    // 192.168.1.0 in little-endian
            .prefix_len(24),
            .action_id(ACTION_IPV4_FORWARD),
            .dst_mac(48'hAABBCCDDEE02),
            .egress_port(9'd2)
        );

        repeat(10) @(posedge aclk);

        // ========================================
        // Test Cases
        // ========================================

        // Test 1: MRI packet with 0 existing traces (first hop)
        $display("\n--- Test 1: MRI packet with 0 traces (first hop) ---");
        $display("Expected: mri_count 0->1, ihl 7->9, totalLen 28->36");
        deq_qdepth = 19'd150;  // Switch queue depth
        send_mri_packet(
            .dst_mac(48'h001122334455),
            .src_mac(48'hAABBCCDDEEFF),
            .src_ip(32'h0101A8C0),      // 192.168.1.1
            .dst_ip(32'h0201A8C0),      // 192.168.1.2
            .ttl_val(8'd64),
            .existing_count(16'd0),
            .description("MRI packet - first hop")
        );
        repeat(50) @(posedge aclk);

        // Test 2: MRI packet with 1 existing trace (second hop)
        $display("\n--- Test 2: MRI packet with 1 trace (second hop) ---");
        $display("Expected: mri_count 1->2, ihl 9->11, totalLen 36->44");
        deq_qdepth = 19'd200;
        send_mri_packet(
            .dst_mac(48'h001122334455),
            .src_mac(48'hAABBCCDDEEFF),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0201A8C0),
            .ttl_val(8'd63),
            .existing_count(16'd1),
            .description("MRI packet - second hop")
        );
        repeat(50) @(posedge aclk);

        // Test 3: MRI packet with 2 existing traces (third hop)
        $display("\n--- Test 3: MRI packet with 2 traces (third hop) ---");
        $display("Expected: mri_count 2->3, ihl 11->13, totalLen 44->52");
        deq_qdepth = 19'd50;
        send_mri_packet(
            .dst_mac(48'h001122334455),
            .src_mac(48'hAABBCCDDEEFF),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0201A8C0),
            .ttl_val(8'd62),
            .existing_count(16'd2),
            .description("MRI packet - third hop")
        );
        repeat(50) @(posedge aclk);

        // Test 4: Regular IPv4 packet (no MRI) - should NOT trigger add_swtrace
        $display("\n--- Test 4: Regular IPv4 (no MRI) ---");
        $display("Expected: No MRI processing, just forwarding");
        send_regular_ipv4_packet(
            .dst_mac(48'h001122334455),
            .src_mac(48'hAABBCCDDEEFF),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0201A8C0),
            .ttl_val(8'd64),
            .description("Regular IPv4 - no MRI")
        );
        repeat(50) @(posedge aclk);

        // Test 5: MRI packet to different destination
        $display("\n--- Test 5: MRI packet to 10.x.x.x network ---");
        deq_qdepth = 19'd300;
        send_mri_packet(
            .dst_mac(48'h001122334455),
            .src_mac(48'hAABBCCDDEEFF),
            .src_ip(32'h0101A8C0),
            .dst_ip(32'h0100000A),      // 10.0.0.1
            .ttl_val(8'd64),
            .existing_count(16'd0),
            .description("MRI to 10.0.0.1")
        );
        repeat(50) @(posedge aclk);

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
        $display("  - Test 1: MRI count 0->1, new swtrace added (swid from egress table)");
        $display("  - Test 2: MRI count 1->2, new swtrace pushed in front");
        $display("  - Test 3: MRI count 2->3, new swtrace pushed in front");
        $display("  - Test 4: Regular IPv4 forwarded, no MRI processing");
        $display("  - Test 5: MRI packet forwarded to port 1");
        $display("\nExpected: 5 forwarded, 0 dropped");
        $display("========================================================\n");

        if (packets_received >= 4 && dropped_count == 0) begin
            $display("*** TEST PASSED ***\n");
        end else begin
            $display("*** TEST FAILED ***\n");
        end

        $finish;
    end

    // ==========================================
    // Waveform dump
    // ==========================================
    initial begin
        $dumpfile("tb_mri.vcd");
        $dumpvars(0, tb_user);
    end

endmodule
