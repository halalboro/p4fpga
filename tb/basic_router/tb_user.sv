`timescale 1ns / 1ps
import lynxTypes::*;

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

   // AXI-Stream interfaces for router
   AXI4SR #(.AXI4S_DATA_BITS(512)) axis_router_in ();
   AXI4SR #(.AXI4S_DATA_BITS(512)) axis_router_out ();
   
   // AXI-Lite control interface
   AXI4L axi_ctrl ();
   
   // Router control signals
   logic [31:0] packet_count;
   logic [31:0] dropped_count;
   logic [31:0] forwarded_count;
   logic [8:0]  egress_port;

   // DUT instantiation
   basic_router #(
       .DATA_WIDTH(512),
       .TABLE_SIZE(1024)
   ) inst_router (
       .aclk(aclk),
       .aresetn(aresetn),
       
       // AXI-Stream input
       .s_axis_tdata(axis_router_in.tdata),
       .s_axis_tvalid(axis_router_in.tvalid),
       .s_axis_tready(axis_router_in.tready),
       .s_axis_tkeep(axis_router_in.tkeep),
       .s_axis_tlast(axis_router_in.tlast),
       
       // AXI-Stream output
       .m_axis_tdata(axis_router_out.tdata),
       .m_axis_tvalid(axis_router_out.tvalid),
       .m_axis_tready(axis_router_out.tready),
       .m_axis_tkeep(axis_router_out.tkeep),
       .m_axis_tlast(axis_router_out.tlast),
       .m_axis_tdest(egress_port),
       
       // Table management (direct signals)
       .table_write_enable(table_wr_en),
       .table_write_addr(table_wr_addr),
       .table_entry_valid(table_entry_valid),
       .table_entry_prefix(table_entry_prefix),
       .table_entry_prefix_len(table_entry_prefix_len),
       .table_entry_action(table_entry_action),
       .table_entry_dst_mac(table_entry_dst_mac),
       .table_entry_egress_port(table_entry_egress_port),
       
       // Statistics
       .packet_count(packet_count),
       .dropped_count(dropped_count),
       .forwarded_count(forwarded_count)
   );
   
   // Table control signals
   logic        table_wr_en;
   logic [9:0]  table_wr_addr;
   logic        table_entry_valid;
   logic [31:0] table_entry_prefix;
   logic [5:0]  table_entry_prefix_len;
   logic [2:0]  table_entry_action;
   logic [47:0] table_entry_dst_mac;
   logic [8:0]  table_entry_egress_port;

   // Test control
   int packet_sent_count = 0;
   int packet_recv_count = 0;

   // Task to configure routing table entry
   task configure_route(
       input [9:0]  addr,
       input [31:0] prefix,
       input [5:0]  prefix_len,
       input [2:0]  action,
       input [47:0] dst_mac,
       input [8:0]  port
   );
       @(posedge aclk);
       table_wr_addr <= addr;
       table_entry_valid <= 1'b1;
       table_entry_prefix <= prefix;
       table_entry_prefix_len <= prefix_len;
       table_entry_action <= action;
       table_entry_dst_mac <= dst_mac;
       table_entry_egress_port <= port;
       table_wr_en <= 1'b1;
       @(posedge aclk);
       table_wr_en <= 1'b0;
       @(posedge aclk);
       $display("[%0t] Configured route: %08h/%0d -> action=%0d port=%0d", 
                $time, prefix, prefix_len, action, port);
   endtask

   // Task to send IPv4 packet
   task send_ipv4_packet(
       input [47:0] dst_mac,
       input [47:0] src_mac,
       input [31:0] src_ip,
       input [31:0] dst_ip,
       input [7:0]  ttl,
       input [7:0]  protocol
   );
       logic [511:0] packet;
       
       packet = '0;
       
       // Ethernet header
       packet[47:0]    = dst_mac;
       packet[95:48]   = src_mac;
       packet[111:96]  = 16'h0800;  // IPv4
       
       // IPv4 header
       packet[115:112] = 4'd4;       // Version
       packet[119:116] = 4'd5;       // IHL
       packet[127:120] = 8'h00;      // DSCP
       packet[143:128] = 16'd20;     // Total length
       packet[159:144] = 16'h0001;   // ID
       packet[162:160] = 3'b010;     // Flags
       packet[175:163] = 13'd0;      // Frag offset
       packet[183:176] = ttl;
       packet[191:184] = protocol;
       packet[207:192] = 16'h0000;   // Checksum (will be ignored)
       packet[239:208] = src_ip;
       packet[271:240] = dst_ip;
       
       @(posedge aclk);
       axis_router_in.tvalid <= 1'b1;
       axis_router_in.tdata <= packet;
       axis_router_in.tkeep <= 64'h0000_0000_0FFF_FFFF;  // 34 bytes
       axis_router_in.tlast <= 1'b1;
       
       wait(axis_router_in.tready);
       @(posedge aclk);
       axis_router_in.tvalid <= 1'b0;
       axis_router_in.tlast <= 1'b0;
       
       packet_sent_count++;
       $display("[%0t] Sent packet #%0d: src=%08h dst=%08h ttl=%0d", 
                $time, packet_sent_count, src_ip, dst_ip, ttl);
   endtask

   // Output monitor
   always @(posedge aclk) begin
       if (axis_router_out.tvalid && axis_router_out.tready && axis_router_out.tlast) begin
           packet_recv_count++;
           $display("[%0t] Received packet #%0d:", $time, packet_recv_count);
           $display("  DST MAC: %012h", axis_router_out.tdata[47:0]);
           $display("  SRC MAC: %012h", axis_router_out.tdata[95:48]);
           $display("  DST IP:  %08h", axis_router_out.tdata[271:240]);
           $display("  TTL:     %0d", axis_router_out.tdata[183:176]);
           $display("  Port:    %0d", egress_port);
       end
   end

   // Statistics monitor
   always @(posedge aclk) begin
       static int last_packet_count = 0;
       if (packet_count != last_packet_count) begin
           $display("[%0t] Stats: Total=%0d Forwarded=%0d Dropped=%0d", 
                    $time, packet_count, forwarded_count, dropped_count);
           last_packet_count = packet_count;
       end
   end

   // Main test sequence
   initial begin
       // Initialize
       axis_router_in.tvalid = 0;
       axis_router_in.tdata = 0;
       axis_router_in.tkeep = 0;
       axis_router_in.tlast = 0;
       axis_router_out.tready = 1;
       
       table_wr_en = 0;
       table_wr_addr = 0;
       table_entry_valid = 0;
       table_entry_prefix = 0;
       table_entry_prefix_len = 0;
       table_entry_action = 0;
       table_entry_dst_mac = 0;
       table_entry_egress_port = 0;
       
       // Wait for reset
       @(posedge aresetn);
       repeat(10) @(posedge aclk);
       
       $display("\n========================================");
       $display("Basic Router Testbench");
       $display("========================================\n");
       
       // Configure routing table
       $display("Configuring routing table...");
       configure_route(
           .addr(0),
           .prefix(32'hC0A80100),     // 192.168.1.0/24
           .prefix_len(24),
           .action(3'd1),              // FORWARD
           .dst_mac(48'h001122334455),
           .port(1)
       );
       
       configure_route(
           .addr(1),
           .prefix(32'h0A000000),     // 10.0.0.0/8
           .prefix_len(8),
           .action(3'd0),              // DROP
           .dst_mac(48'h0),
           .port(0)
       );
       
       configure_route(
           .addr(2),
           .prefix(32'hAC100000),     // 172.16.0.0/12
           .prefix_len(12),
           .action(3'd1),              // FORWARD
           .dst_mac(48'hAABBCCDDEEFF),
           .port(2)
       );
       
       repeat(10) @(posedge aclk);
       
       // Test cases
       $display("\n--- Test 1: Packet to 192.168.1.100 (should forward) ---");
       send_ipv4_packet(
           .dst_mac(48'hFFFFFFFFFFFF),
           .src_mac(48'h112233445566),
           .src_ip(32'hC0A80101),
           .dst_ip(32'hC0A80164),
           .ttl(64),
           .protocol(8'h11)
       );
       repeat(20) @(posedge aclk);
       
       $display("\n--- Test 2: Packet to 10.1.2.3 (should drop) ---");
       send_ipv4_packet(
           .dst_mac(48'hFFFFFFFFFFFF),
           .src_mac(48'h112233445566),
           .src_ip(32'hC0A80101),
           .dst_ip(32'h0A010203),
           .ttl(64),
           .protocol(8'h11)
       );
       repeat(20) @(posedge aclk);
       
       $display("\n--- Test 3: Packet to 172.16.5.10 (should forward) ---");
       send_ipv4_packet(
           .dst_mac(48'hFFFFFFFFFFFF),
           .src_mac(48'h112233445566),
           .src_ip(32'hC0A80101),
           .dst_ip(32'hAC10050A),
           .ttl(64),
           .protocol(8'h11)
       );
       repeat(20) @(posedge aclk);
       
       $display("\n--- Test 4: Packet to 8.8.8.8 (no match, should drop) ---");
       send_ipv4_packet(
           .dst_mac(48'hFFFFFFFFFFFF),
           .src_mac(48'h112233445566),
           .src_ip(32'hC0A80101),
           .dst_ip(32'h08080808),
           .ttl(64),
           .protocol(8'h11)
       );
       repeat(20) @(posedge aclk);
       
       $display("\n--- Test 5: TTL=1 packet (should drop after decrement) ---");
       send_ipv4_packet(
           .dst_mac(48'hFFFFFFFFFFFF),
           .src_mac(48'h112233445566),
           .src_ip(32'hC0A80101),
           .dst_ip(32'hC0A80164),
           .ttl(1),
           .protocol(8'h11)
       );
       repeat(20) @(posedge aclk);
       
       // Final summary
       repeat(50) @(posedge aclk);
       $display("\n========================================");
       $display("Test Summary");
       $display("========================================");
       $display("Packets sent:     %0d", packet_sent_count);
       $display("Packets received: %0d", packet_recv_count);
       $display("Total processed:  %0d", packet_count);
       $display("Forwarded:        %0d", forwarded_count);
       $display("Dropped:          %0d", dropped_count);
       $display("========================================\n");
       
       $finish;
   end
endmodule