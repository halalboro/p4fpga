`timescale 1ns / 1ps

module tb_user;
    // Clock and reset
    logic aclk = 1'b1;
    logic aresetn = 1'b0;
    
    // Timing parameters
    localparam CLK_PERIOD = 4ns;  // 250 MHz
    localparam RST_PERIOD = 100ns;
    
    always #(CLK_PERIOD/2) aclk = ~aclk;

    initial begin
        aresetn = 1'b0;
        #(RST_PERIOD) aresetn = 1'b1;
    end

    // Parameters
    localparam DATA_WIDTH = 512;
    localparam KEEP_WIDTH = DATA_WIDTH/8;
    
    // P4Calc protocol constants
    localparam [7:0]  P4CALC_P     = 8'h50;   // 'P'
    localparam [7:0]  P4CALC_4     = 8'h34;   // '4'
    localparam [7:0]  P4CALC_VER   = 8'h01;   // v0.1
    localparam [15:0] P4CALC_ETYPE = 16'h1234;
    
    // Operation codes
    localparam [7:0]  OP_ADD   = 8'h2b;  // '+'
    localparam [7:0]  OP_SUB   = 8'h2d;  // '-'
    localparam [7:0]  OP_AND   = 8'h26;  // '&'
    localparam [7:0]  OP_OR    = 8'h7c;  // '|'
    localparam [7:0]  OP_XOR   = 8'h5e;  // '^'
    
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
    
    // Statistics
    logic [31:0] packet_count;
    logic [31:0] dropped_count;
    logic [31:0] forwarded_count;
    
    // Test control
    int packets_sent = 0;
    int packets_received = 0;
    int tests_passed = 0;
    int tests_failed = 0;

    // ============================================
    // DUT - Instantiate pipeline components
    // ============================================
    
    // Parser signals
    logic                    ethernet_valid;
    logic [47:0]             eth_dst_addr;
    logic [47:0]             eth_src_addr;
    logic [15:0]             eth_type;
    logic                    ipv4_valid;
    logic [7:0]              ipv4_ttl;
    logic [5:0]              ipv4_diffserv;
    logic [1:0]              ipv4_ecn;
    
    // p4calc header signals
    logic [7:0]              p4calc_p;
    logic [7:0]              p4calc_four;
    logic [7:0]              p4calc_ver;
    logic [7:0]              p4calc_op;
    logic [31:0]             p4calc_operand_a;
    logic [31:0]             p4calc_operand_b;
    logic [31:0]             p4calc_res;
    logic                    p4calc_valid;
    
    // Pipeline signals
    logic [7:0]              pipeline_p4calc_p;
    logic [7:0]              pipeline_p4calc_four;
    logic [7:0]              pipeline_p4calc_ver;
    logic [7:0]              pipeline_p4calc_op;
    logic [31:0]             pipeline_p4calc_operand_a;
    logic [31:0]             pipeline_p4calc_operand_b;
    logic [31:0]             pipeline_p4calc_res;
    logic                    pipeline_p4calc_valid;
    
    logic [DATA_WIDTH-1:0]   parser_payload_data;
    logic [KEEP_WIDTH-1:0]   parser_payload_keep;
    logic                    parser_payload_valid;
    logic                    parser_payload_last;
    logic                    parser_payload_ready;
    logic [15:0]             parser_packet_length;
    logic [8:0]              parser_ingress_port;
    
    logic [DATA_WIDTH-1:0]   pipeline_data;
    logic [KEEP_WIDTH-1:0]   pipeline_keep;
    logic                    pipeline_last;
    logic                    pipeline_valid;
    logic                    pipeline_ready;
    logic                    pipeline_drop;
    logic [8:0]              pipeline_egress_port;
    logic                    pipeline_header_modified;
    logic [5:0]              pipeline_ipv4_diffserv;
    logic [1:0]              pipeline_ipv4_ecn;
    logic [7:0]              pipeline_ipv4_ttl;
    logic [47:0]             pipeline_eth_dst_addr;
    logic [47:0]             pipeline_eth_src_addr;

    // Parser Instance
    parser #(
        .DATA_WIDTH(DATA_WIDTH),
        .KEEP_WIDTH(KEEP_WIDTH),
        .PARSER_CONFIG(8'b10000001)  // Ethernet + p4calc custom header
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
        
        .ipv4_version(),
        .ipv4_ihl(),
        .ipv4_diffserv(ipv4_diffserv),
        .ipv4_ecn(ipv4_ecn),
        .ipv4_total_len(),
        .ipv4_identification(),
        .ipv4_flags(),
        .ipv4_frag_offset(),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_protocol(),
        .ipv4_hdr_checksum(),
        .ipv4_src_addr(),
        .ipv4_dst_addr(),
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
        
        .udp_src_port(),
        .udp_dst_port(),
        .udp_length(),
        .udp_checksum(),
        .udp_valid(),
        
        .vxlan_flags(),
        .vxlan_reserved(),
        .vxlan_vni(),
        .vxlan_reserved2(),
        .vxlan_valid(),
        
        .p4calc_p(p4calc_p),
        .p4calc_four(p4calc_four),
        .p4calc_ver(p4calc_ver),
        .p4calc_op(p4calc_op),
        .p4calc_operand_a(p4calc_operand_a),
        .p4calc_operand_b(p4calc_operand_b),
        .p4calc_res(p4calc_res),
        .p4calc_valid(p4calc_valid),
        
        .payload_data(parser_payload_data),
        .payload_keep(parser_payload_keep),
        .payload_valid(parser_payload_valid),
        .payload_last(parser_payload_last),
        .packet_length(parser_packet_length),
        .ingress_port(parser_ingress_port)
    );

    // Match-Action Pipeline
    match_action #(
        .DATA_WIDTH(DATA_WIDTH),
        .METADATA_WIDTH(64),
        .TABLE_SIZE(16),
        .KEY_WIDTH(32),
        .ACTION_DATA_WIDTH(128),
        .ACTION_CONFIG(8'b00000111),
        .EGRESS_CONFIG(8'b00000000),
        .ECN_THRESHOLD(19'd10)
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
        .ingress_port_in(parser_ingress_port),
        
        .ipv4_valid(ipv4_valid),
        .eth_dst_addr(eth_dst_addr),
        .eth_src_addr(eth_src_addr),
        .ipv4_ttl(ipv4_ttl),
        .ipv4_src_addr(32'd0),
        .ipv4_dst_addr(32'd0),
        .ipv4_src_port(16'd0),
        .ipv4_dst_port(16'd0),
        .ipv4_protocol(8'd0),
        .ipv4_diffserv(ipv4_diffserv),
        .ipv4_ecn(ipv4_ecn),
        
        .p4calc_p(p4calc_p),
        .p4calc_four(p4calc_four),
        .p4calc_ver(p4calc_ver),
        .p4calc_op(p4calc_op),
        .p4calc_operand_a(p4calc_operand_a),
        .p4calc_operand_b(p4calc_operand_b),
        .p4calc_res(p4calc_res),
        .p4calc_valid(p4calc_valid),
        
        .packet_length(parser_packet_length),
        .mcast_grp(),
        
        .enq_qdepth(19'd0),
        .egress_port_id(9'd0),
        
        .packet_out(pipeline_data),
        .packet_keep_out(pipeline_keep),
        .packet_last_out(pipeline_last),
        .packet_valid_out(pipeline_valid),
        .packet_ready_in(pipeline_ready),
        .out_p4calc_p(pipeline_p4calc_p),
        .out_p4calc_four(pipeline_p4calc_four),
        .out_p4calc_ver(pipeline_p4calc_ver),
        .out_p4calc_op(pipeline_p4calc_op),
        .out_p4calc_operand_a(pipeline_p4calc_operand_a),
        .out_p4calc_operand_b(pipeline_p4calc_operand_b),
        .out_p4calc_res(pipeline_p4calc_res),
        .out_p4calc_valid(pipeline_p4calc_valid),
        .out_eth_dst_addr(pipeline_eth_dst_addr),
        .out_eth_src_addr(pipeline_eth_src_addr),
        
        .out_ipv4_diffserv(pipeline_ipv4_diffserv),
        .out_ipv4_ecn(pipeline_ipv4_ecn),
        .out_ipv4_ttl(pipeline_ipv4_ttl),
        
        .drop(pipeline_drop),
        .egress_port(pipeline_egress_port),
        .header_modified(pipeline_header_modified),
        .ecn_marked(),
        .table_write_enable(1'b0),
        .table_write_addr(10'd0),
        .table_entry_valid(1'b0),
        .table_entry_key(32'd0),
        .table_entry_prefix_len(6'd0),
        .table_entry_action(3'd0),
        .table_entry_action_data(128'd0),
        
        .packet_count(packet_count),
        .dropped_count(dropped_count),
        .forwarded_count(forwarded_count)
    );

    // Deparser Instance
    deparser #(
        .DATA_WIDTH(DATA_WIDTH),
        .KEEP_WIDTH(KEEP_WIDTH),
        .DEPARSER_CONFIG(16'b0000010000000001)  // Ethernet + p4calc custom
    ) deparser_inst (
        .aclk(aclk),
        .aresetn(aresetn),
        
        .eth_dst_addr(pipeline_eth_dst_addr),
        .eth_src_addr(pipeline_eth_src_addr),
        .eth_ether_type(eth_type),
        .eth_valid(ethernet_valid),
        
        .vlan_pcp(3'b0),
        .vlan_dei(1'b0),
        .vlan_vid(12'b0),
        .vlan_ether_type(16'b0),
        .vlan_valid(1'b0),
        
        .ipv4_version(4'd0),
        .ipv4_ihl(4'd0),
        .ipv4_diffserv(pipeline_ipv4_diffserv),
        .ipv4_ecn(pipeline_ipv4_ecn),
        .ipv4_total_len(16'd0),
        .ipv4_identification(16'd0),
        .ipv4_flags(3'd0),
        .ipv4_frag_offset(13'd0),
        .ipv4_ttl(pipeline_ipv4_ttl),
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
        .tcp_data_offset(4'd0),
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
        
        .p4calc_p(pipeline_p4calc_p),
        .p4calc_four(pipeline_p4calc_four),
        .p4calc_ver(pipeline_p4calc_ver),
        .p4calc_op(pipeline_p4calc_op),
        .p4calc_operand_a(pipeline_p4calc_operand_a),
        .p4calc_operand_b(pipeline_p4calc_operand_b),
        .p4calc_res(pipeline_p4calc_res),
        .p4calc_valid(pipeline_p4calc_valid),
        
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

    // ============================================
    // Task: Send P4Calc packet
    // ============================================
    task send_p4calc_packet(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [7:0]  op,
        input [31:0] operand_a,
        input [31:0] operand_b
    );
        logic [DATA_WIDTH-1:0] packet;
        
        packet = '0;
        
        // Ethernet header (14 bytes)
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = P4CALC_ETYPE;
        
        // p4calc header (16 bytes) - starts at byte 14
        packet[119:112] = P4CALC_P;        // p
        packet[127:120] = P4CALC_4;        // four
        packet[135:128] = P4CALC_VER;      // ver
        packet[143:136] = op;              // op
        packet[175:144] = operand_a;       // operand_a
        packet[207:176] = operand_b;       // operand_b
        packet[239:208] = 32'd0;           // res (initially 0)
        
        @(posedge aclk);
        s_axis_tvalid <= 1'b1;
        s_axis_tdata  <= packet;
        s_axis_tkeep  <= 64'h0000_0000_3FFF_FFFF;  // 30 bytes
        s_axis_tlast  <= 1'b1;
        
        wait(s_axis_tready);
        @(posedge aclk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        
        packets_sent++;
        $display("[%0t] Sent P4Calc: op=%c(0x%02h) A=%0d B=%0d", 
                 $time, op, op, operand_a, operand_b);
    endtask

    // ============================================
    // Task: Send invalid packet (wrong ethertype)
    // ============================================
    task send_invalid_ethertype(
        input [47:0] dst_mac,
        input [47:0] src_mac
    );
        logic [DATA_WIDTH-1:0] packet;
        
        packet = '0;
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = 16'h0800;  // IPv4 instead of P4CALC
        
        @(posedge aclk);
        s_axis_tvalid <= 1'b1;
        s_axis_tdata  <= packet;
        s_axis_tkeep  <= 64'h0000_0000_0000_3FFF;
        s_axis_tlast  <= 1'b1;
        
        wait(s_axis_tready);
        @(posedge aclk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        
        packets_sent++;
        $display("[%0t] Sent invalid ethertype packet (should drop)", $time);
    endtask

    // ============================================
    // Task: Send invalid p4calc header
    // ============================================
    task send_invalid_p4calc_header(
        input [47:0] dst_mac,
        input [47:0] src_mac
    );
        logic [DATA_WIDTH-1:0] packet;
        
        packet = '0;
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = P4CALC_ETYPE;
        
        // Invalid p4calc header (wrong magic)
        packet[119:112] = 8'h00;  // Wrong 'p'
        packet[127:120] = 8'h00;  // Wrong '4'
        packet[135:128] = 8'h00;  // Wrong version
        
        @(posedge aclk);
        s_axis_tvalid <= 1'b1;
        s_axis_tdata  <= packet;
        s_axis_tkeep  <= 64'h0000_0000_3FFF_FFFF;
        s_axis_tlast  <= 1'b1;
        
        wait(s_axis_tready);
        @(posedge aclk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        
        packets_sent++;
        $display("[%0t] Sent invalid p4calc header (should drop)", $time);
    endtask

    // ============================================
    // Task: Send unknown operation
    // ============================================
    task send_unknown_op(
        input [47:0] dst_mac,
        input [47:0] src_mac,
        input [7:0]  bad_op
    );
        logic [DATA_WIDTH-1:0] packet;
        
        packet = '0;
        packet[47:0]    = dst_mac;
        packet[95:48]   = src_mac;
        packet[111:96]  = P4CALC_ETYPE;
        
        packet[119:112] = P4CALC_P;
        packet[127:120] = P4CALC_4;
        packet[135:128] = P4CALC_VER;
        packet[143:136] = bad_op;  // Unknown operation
        packet[175:144] = 32'd100;
        packet[207:176] = 32'd50;
        packet[239:208] = 32'd0;
        
        @(posedge aclk);
        s_axis_tvalid <= 1'b1;
        s_axis_tdata  <= packet;
        s_axis_tkeep  <= 64'h0000_0000_3FFF_FFFF;
        s_axis_tlast  <= 1'b1;
        
        wait(s_axis_tready);
        @(posedge aclk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        
        packets_sent++;
        $display("[%0t] Sent unknown op 0x%02h (should drop)", $time, bad_op);
    endtask

    // ============================================
    // Output monitor with result verification
    // ============================================
    logic [31:0] expected_result;
    logic [7:0]  last_op;
    logic [31:0] last_a, last_b;
    
    always @(posedge aclk) begin
        if (m_axis_tvalid && m_axis_tready && m_axis_tlast) begin
            automatic logic [31:0] recv_result;
            automatic logic [47:0] recv_dst_mac;
            automatic logic [47:0] recv_src_mac;
            
            recv_dst_mac = m_axis_tdata[47:0];
            recv_src_mac = m_axis_tdata[95:48];
            recv_result  = m_axis_tdata[239:208];
            
            packets_received++;
            $display("[%0t] Received packet #%0d:", $time, packets_received);
            $display("  DST MAC: %012h", recv_dst_mac);
            $display("  SRC MAC: %012h", recv_src_mac);
            $display("  Result:  %0d (0x%08h)", recv_result, recv_result);
        end
    end

    // ============================================
    // Main test sequence
    // ============================================
    initial begin
        // Initialize
        s_axis_tvalid = 0;
        s_axis_tdata  = 0;
        s_axis_tkeep  = 0;
        s_axis_tlast  = 0;
        m_axis_tready = 1;
        
        // Wait for reset
        @(posedge aresetn);
        repeat(10) @(posedge aclk);
        
        $display("\n========================================");
        $display("P4 Calculator Testbench");
        $display("========================================\n");
        
        // ----------------------------------------
        // Test 1: Addition
        // ----------------------------------------
        $display("\n--- Test 1: Addition (100 + 50 = 150) ---");
        send_p4calc_packet(
            .dst_mac(48'hFFFFFFFFFFFF),
            .src_mac(48'h112233445566),
            .op(OP_ADD),
            .operand_a(32'd100),
            .operand_b(32'd50)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 2: Subtraction
        // ----------------------------------------
        $display("\n--- Test 2: Subtraction (200 - 75 = 125) ---");
        send_p4calc_packet(
            .dst_mac(48'hAABBCCDDEEFF),
            .src_mac(48'h665544332211),
            .op(OP_SUB),
            .operand_a(32'd200),
            .operand_b(32'd75)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 3: Bitwise AND
        // ----------------------------------------
        $display("\n--- Test 3: AND (0xFF00FF00 & 0x0F0F0F0F = 0x0F000F00) ---");
        send_p4calc_packet(
            .dst_mac(48'h001122334455),
            .src_mac(48'hAABBCCDDEEFF),
            .op(OP_AND),
            .operand_a(32'hFF00FF00),
            .operand_b(32'h0F0F0F0F)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 4: Bitwise OR
        // ----------------------------------------
        $display("\n--- Test 4: OR (0xF0F0F0F0 | 0x0F0F0F0F = 0xFFFFFFFF) ---");
        send_p4calc_packet(
            .dst_mac(48'h112233445566),
            .src_mac(48'h778899AABBCC),
            .op(OP_OR),
            .operand_a(32'hF0F0F0F0),
            .operand_b(32'h0F0F0F0F)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 5: Bitwise XOR
        // ----------------------------------------
        $display("\n--- Test 5: XOR (0xAAAAAAAA ^ 0x55555555 = 0xFFFFFFFF) ---");
        send_p4calc_packet(
            .dst_mac(48'hDEADBEEFCAFE),
            .src_mac(48'hCAFEBABE1234),
            .op(OP_XOR),
            .operand_a(32'hAAAAAAAA),
            .operand_b(32'h55555555)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 6: Edge case - Add with overflow
        // ----------------------------------------
        $display("\n--- Test 6: Addition overflow (0xFFFFFFFF + 1) ---");
        send_p4calc_packet(
            .dst_mac(48'h111111111111),
            .src_mac(48'h222222222222),
            .op(OP_ADD),
            .operand_a(32'hFFFFFFFF),
            .operand_b(32'd1)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 7: Subtraction underflow
        // ----------------------------------------
        $display("\n--- Test 7: Subtraction underflow (0 - 1) ---");
        send_p4calc_packet(
            .dst_mac(48'h333333333333),
            .src_mac(48'h444444444444),
            .op(OP_SUB),
            .operand_a(32'd0),
            .operand_b(32'd1)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 8: Unknown operation (should drop)
        // ----------------------------------------
        $display("\n--- Test 8: Unknown operation '*' (should drop) ---");
        send_unknown_op(
            .dst_mac(48'h555555555555),
            .src_mac(48'h666666666666),
            .bad_op(8'h2A)  // '*'
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 9: Invalid ethertype (should drop)
        // ----------------------------------------
        $display("\n--- Test 9: Invalid ethertype (should drop) ---");
        send_invalid_ethertype(
            .dst_mac(48'h777777777777),
            .src_mac(48'h888888888888)
        );
        repeat(30) @(posedge aclk);
        
        // ----------------------------------------
        // Test 10: Zero operands
        // ----------------------------------------
        $display("\n--- Test 10: Zero operands (0 + 0 = 0) ---");
        send_p4calc_packet(
            .dst_mac(48'h999999999999),
            .src_mac(48'hAAAAAAAAAA),
            .op(OP_ADD),
            .operand_a(32'd0),
            .operand_b(32'd0)
        );
        repeat(30) @(posedge aclk);
        
        // Final summary
        repeat(50) @(posedge aclk);
        $display("\n========================================");
        $display("Test Summary");
        $display("========================================");
        $display("Packets sent:     %0d", packets_sent);
        $display("Packets received: %0d", packets_received);
        $display("Total processed:  %0d", packet_count);
        $display("Forwarded:        %0d", forwarded_count);
        $display("Dropped:          %0d", dropped_count);
        $display("========================================\n");
        
        // Expected: 7 forwarded (valid ops), 3 dropped (unknown op, invalid ethertype, invalid header)
        $finish;
    end

endmodule