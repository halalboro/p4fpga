// backend.cpp

#include "common.h"
#include "backend.h"
#include <boost/filesystem.hpp>
#include <fstream>
#include <map>
#include <string>
#include "ir/ir.h"
#include "lib/error.h"
#include "lib/nullstream.h"
#include "lib/cstring.h"
#include "lib/log.h"
#include "frontends/p4/evaluator/evaluator.h"
#include "frontends/p4/toP4/toP4.h"
#include "program.h"
#include "type.h"
#include "options.h"
#include "bsvprogram.h"

namespace SV {

bool Backend::copyTemplates(const std::string& outputDir) {
    LOG1("Copying  parser/deparser templates from src/sv/");
    
    // Ensure hdl directory exists
    boost::filesystem::path hdlDir = boost::filesystem::path(outputDir) / "hdl";
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }
    
    // Source paths (relative to build directory)
    boost::filesystem::path srcDir = "../src/sv";
    boost::filesystem::path srcParserPath = srcDir / "parser.sv";
    boost::filesystem::path srcDeparserPath = srcDir / "deparser.sv";
    
    // Destination paths
    boost::filesystem::path dstParserPath = hdlDir / "parser.sv";
    boost::filesystem::path dstDeparserPath = hdlDir / "deparser.sv";
    
    // Check if source files exist
    if (!boost::filesystem::exists(srcParserPath)) {
        P4::error(" parser template not found: %s", srcParserPath.string().c_str());
        std::cerr << "ERROR: Cannot find parser.sv at: " << srcParserPath.string() << std::endl;
        std::cerr << "       Please ensure the template exists in src/sv/" << std::endl;
        return false;
    }
    
    if (!boost::filesystem::exists(srcDeparserPath)) {
        P4::error(" deparser template not found: %s", srcDeparserPath.string().c_str());
        std::cerr << "ERROR: Cannot find _deparser.sv at: " << srcDeparserPath.string() << std::endl;
        std::cerr << "       Please ensure the template exists in src/sv/" << std::endl;
        return false;
    }
    
    try {
        // Copy parser.sv
        boost::filesystem::copy_file(
            srcParserPath,
            dstParserPath,
            boost::filesystem::copy_option::overwrite_if_exists
        );
        LOG1("Copied parser.sv to " << dstParserPath.string());
        
        // Copy _deparser.sv
        boost::filesystem::copy_file(
            srcDeparserPath,
            dstDeparserPath,
            boost::filesystem::copy_option::overwrite_if_exists
        );
        LOG1("Copied deparser.sv to " << dstDeparserPath.string());
        
    } catch (const boost::filesystem::filesystem_error& e) {
        P4::error("Failed to copy templates: %s", e.what());
        std::cerr << "ERROR: Failed to copy templates: " << e.what() << std::endl;
        return false;
    }
    
    return true;
}

bool Backend::copySubmodules(const std::string& outputDir) {
    LOG1("Copying submodules from src/sv/");
    
    // Ensure hdl directory exists
    boost::filesystem::path hdlDir = boost::filesystem::path(outputDir) / "hdl";
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }
    
    // Source directory
    boost::filesystem::path srcDir = "../src/sv";
    
    // Define source -> destination mapping
    // Source files have "_engine" suffix, destination files don't
    std::map<std::string, std::string> submodules = {
        {"match_engine.sv", "match.sv"},
        {"action_engine.sv", "action.sv"},
        {"stats_engine.sv", "stats.sv"}
    };
    
    // Copy each submodule
    for (const auto& pair : submodules) {
        boost::filesystem::path srcPath = srcDir / pair.first;
        boost::filesystem::path dstPath = hdlDir / pair.second;
        
        // Check if source exists
        if (!boost::filesystem::exists(srcPath)) {
            P4::error("Submodule not found: %s", srcPath.string().c_str());
            std::cerr << "ERROR: Cannot find " << pair.first << " at: " << srcPath.string() << std::endl;
            std::cerr << "       Please ensure the submodule exists in src/sv/" << std::endl;
            return false;
        }
        
        try {
            // Copy file
            boost::filesystem::copy_file(
                srcPath,
                dstPath,
                boost::filesystem::copy_option::overwrite_if_exists
            );
            LOG1("Copied " << pair.first << " to " << dstPath.string());
            
        } catch (const boost::filesystem::filesystem_error& e) {
            P4::error("Failed to copy %s: %s", pair.first.c_str(), e.what());
            std::cerr << "ERROR: Failed to copy " << pair.first << ": " << e.what() << std::endl;
            return false;
        }
    }
    
    return true;
}


bool Backend::run(const SVOptions& options,
                  const IR::ToplevelBlock* toplevel,
                  P4::ReferenceMap* refMap,
                  P4::TypeMap* typeMap) {
    
    LOG1("Starting P4-to-SystemVerilog compilation");
    
    // Create type factory
    FPGATypeFactory::createFactory(typeMap);
    
    // Build the program representation
    LOG1("Building program representation");
    SVProgram svprog(toplevel, refMap, typeMap);
    if (!svprog.build()) {
        P4::error("SVProgram build failed");
        std::cerr << "ERROR: SVProgram build failed" << std::endl;
        return false;
    }
    
    if (options.outputDir.isNullOrEmpty()) {
        P4::error("Must specify output directory with --output-dir");
        return false;
    }
    
    // Extract base name from input P4 file
    std::string p4FileName = options.file.string();
    std::string baseName = "router";  // Default fallback
    
    // Extract filename without path and extension
    size_t lastSlash = p4FileName.find_last_of("/\\");
    if (lastSlash != std::string::npos) {
        p4FileName = p4FileName.substr(lastSlash + 1);
    }
    
    size_t lastDot = p4FileName.find_last_of(".");
    if (lastDot != std::string::npos) {
        baseName = p4FileName.substr(0, lastDot);
    } else {
        baseName = p4FileName;
    }
    
    LOG1("Base name for generated modules: " << baseName);
    
    // Create directory structure
    LOG1("Creating output directory structure");
    boost::filesystem::path outputDir(options.outputDir.c_str());
    boost::filesystem::path hdlDir = outputDir / "hdl";
    
    if (!boost::filesystem::exists(outputDir)) {
        boost::filesystem::create_directories(outputDir);
    }
    if (!boost::filesystem::exists(hdlDir)) {
        boost::filesystem::create_directories(hdlDir);
    }
    
    if (!copyTemplates(options.outputDir.string())) {
        P4::error("Failed to copy templates");
        std::cerr << "ERROR: Failed to copy templates" << std::endl;
        return false;
    }
    
    if (!copySubmodules(options.outputDir.string())) {
        P4::error("Failed to copy submodules");
        std::cerr << "ERROR: Failed to copy submodules" << std::endl;
        return false;
    }

    // Create SystemVerilog code generator
    LOG1("Generating SystemVerilog code");
    SVCodeGen codegen;
    svprog.emit(codegen);
    
    // Generate control slave module with dynamic name
    LOG1("Generating control slave module");
    svprog.emitControlSlave(options.outputDir.string(), baseName);
    
    // Define output files with dynamic names
    std::map<std::string, std::string> hdlFiles = {
        {baseName + ".sv", codegen.getTopModule()}  // Top-level → <name>.sv
    };
    
    // Track if any file write fails
    bool allFilesWritten = true;
    
    // Write all HDL files to hdl/ subdirectory
    for (auto it = hdlFiles.begin(); it != hdlFiles.end(); ++it) {
        const std::string& filename = it->first;
        const std::string& content = it->second;
        boost::filesystem::path filepath = hdlDir / filename;
        
        std::ofstream out(filepath.string());
        if (!out) {
            P4::error("Failed to open file %1%", filepath.string());
            std::cerr << "ERROR: Failed to open file: " << filepath.string() << std::endl;
            allFilesWritten = false;
            continue;
        }
        
        out << content;
        out.close();
        LOG1("Generated " << filepath.string());
    }
    
    // Generate vfpga_top.svh template in root output directory
    boost::filesystem::path vfpgaTemplate = outputDir / "vfpga_top.svh";
    std::ofstream vfpga(vfpgaTemplate.string());
    if (vfpga) {
        emitVFPGATemplate(vfpga, baseName);  // Pass baseName
        vfpga.close();
        LOG1("Generated " << vfpgaTemplate.string());
    } else {
        P4::error("Failed to create vfpga_top.svh");
        std::cerr << "ERROR: Failed to create vfpga_top.svh" << std::endl;
        allFilesWritten = false;
    }
    
    // Generate init_ip.tcl in root output directory
    boost::filesystem::path tclScript = outputDir / "init_ip.tcl";
    std::ofstream tcl(tclScript.string());
    if (tcl) {
        emitVivadoTCL(tcl);  // Pass baseName
        tcl.close();
        LOG1("Generated " << tclScript.string());
    } else {
        P4::error("Failed to create init_ip.tcl");
        std::cerr << "ERROR: Failed to create init_ip.tcl" << std::endl;
        allFilesWritten = false;
    }
    
    return allFilesWritten;
}

void Backend::emitVFPGATemplate(std::ofstream& vfpga, const std::string& baseName) {
    vfpga << "/**\n";
    vfpga << " * VFPGA TOP Template\n";
    vfpga << " * Generated by POS Compiler\n";
    vfpga << " *\n";
    vfpga << " * Module: " << baseName << "\n";
    vfpga << " *\n";
    
    vfpga << "import lynxTypes::*;\n\n";
    
    vfpga << "// Internal router interfaces\n";
    vfpga << "AXI4S #(.AXI4S_DATA_BITS(AXI_DATA_BITS)) axis_router_in ();\n";
    vfpga << "AXI4S #(.AXI4S_DATA_BITS(AXI_DATA_BITS)) axis_router_out ();\n\n";
    
    vfpga << "// Control signals\n";
    vfpga << "logic axi_ctrl_write_enable;\n";
    vfpga << "logic [9:0] axi_ctrl_write_addr;\n";
    vfpga << "logic axi_ctrl_entry_valid;\n";
    vfpga << "logic [31:0] axi_ctrl_entry_prefix;\n";
    vfpga << "logic [5:0] axi_ctrl_entry_prefix_len;\n";
    vfpga << "logic [2:0] axi_ctrl_entry_action;\n";
    vfpga << "logic [47:0] axi_ctrl_entry_dst_mac;\n";
    vfpga << "logic [8:0] axi_ctrl_entry_egress_port;\n";
    vfpga << "logic [31:0] packet_count;\n";
    vfpga << "logic [31:0] dropped_count;\n";
    vfpga << "logic [31:0] forwarded_count;\n\n";
    
    vfpga << "// ============================================\n";
    vfpga << "// Connect incoming RDMA to router input\n";
    vfpga << "// ============================================\n";
    vfpga << "assign axis_router_in.tvalid = axis_rrsp_recv[0].tvalid;\n";
    vfpga << "assign axis_router_in.tdata = axis_rrsp_recv[0].tdata;\n";
    vfpga << "assign axis_router_in.tkeep = axis_rrsp_recv[0].tkeep;\n";
    vfpga << "assign axis_router_in.tlast = axis_rrsp_recv[0].tlast;\n";
    vfpga << "assign axis_rrsp_recv[0].tready = axis_router_in.tready;\n\n";
    
    vfpga << "// ============================================\n";
    vfpga << "// " << baseName << " Instance\n";
    vfpga << "// ============================================\n";
    vfpga << baseName << " #(\n";
    vfpga << "    .DATA_WIDTH(AXI_DATA_BITS),\n";
    vfpga << "    .TABLE_SIZE(1024)\n";
    vfpga << ") inst_" << baseName << " (\n";
    vfpga << "    .aclk(aclk),\n";
    vfpga << "    .aresetn(aresetn),\n\n";
    
    vfpga << "    // Packet I/O\n";
    vfpga << "    .s_axis_tdata(axis_router_in.tdata),\n";
    vfpga << "    .s_axis_tvalid(axis_router_in.tvalid),\n";
    vfpga << "    .s_axis_tready(axis_router_in.tready),\n";
    vfpga << "    .s_axis_tkeep(axis_router_in.tkeep),\n";
    vfpga << "    .s_axis_tlast(axis_router_in.tlast),\n\n";
    
    vfpga << "    .m_axis_tdata(axis_router_out.tdata),\n";
    vfpga << "    .m_axis_tvalid(axis_router_out.tvalid),\n";
    vfpga << "    .m_axis_tready(axis_router_out.tready),\n";
    vfpga << "    .m_axis_tkeep(axis_router_out.tkeep),\n";
    vfpga << "    .m_axis_tlast(axis_router_out.tlast),\n";
    vfpga << "    .m_axis_tdest(),\n\n";
    
    vfpga << "    // Control interface\n";
    vfpga << "    .table_write_enable(axi_ctrl_write_enable),\n";
    vfpga << "    .table_write_addr(axi_ctrl_write_addr),\n";
    vfpga << "    .table_entry_valid(axi_ctrl_entry_valid),\n";
    vfpga << "    .table_entry_prefix(axi_ctrl_entry_prefix),\n";
    vfpga << "    .table_entry_prefix_len(axi_ctrl_entry_prefix_len),\n";
    vfpga << "    .table_entry_action(axi_ctrl_entry_action),\n";
    vfpga << "    .table_entry_dst_mac(axi_ctrl_entry_dst_mac),\n";
    vfpga << "    .table_entry_egress_port(axi_ctrl_entry_egress_port),\n\n";
    
    vfpga << "    // Statistics\n";
    vfpga << "    .packet_count(packet_count),\n";
    vfpga << "    .dropped_count(dropped_count),\n";
    vfpga << "    .forwarded_count(forwarded_count)\n";
    vfpga << ");\n\n";
    
    vfpga << "// ============================================\n";
    vfpga << "// Control Slave\n";
    vfpga << "// ============================================\n";
    vfpga << baseName << "_slave inst_ctrl_slave (\n";
    vfpga << "    .aclk(aclk),\n";
    vfpga << "    .aresetn(aresetn),\n";
    vfpga << "    .axi_ctrl(axi_ctrl),\n";
    vfpga << "    .table_write_enable(axi_ctrl_write_enable),\n";
    vfpga << "    .table_write_addr(axi_ctrl_write_addr),\n";
    vfpga << "    .table_entry_valid(axi_ctrl_entry_valid),\n";
    vfpga << "    .table_entry_prefix(axi_ctrl_entry_prefix),\n";
    vfpga << "    .table_entry_prefix_len(axi_ctrl_entry_prefix_len),\n";
    vfpga << "    .table_entry_action(axi_ctrl_entry_action),\n";
    vfpga << "    .table_entry_dst_mac(axi_ctrl_entry_dst_mac),\n";
    vfpga << "    .table_entry_egress_port(axi_ctrl_entry_egress_port)\n";
    vfpga << ");\n\n";
    
    vfpga << "// ============================================\n";
    vfpga << "// Connect router output to RDMA send\n";
    vfpga << "// ============================================\n";
    vfpga << "assign axis_rrsp_send[0].tvalid = axis_router_out.tvalid;\n";
    vfpga << "assign axis_rrsp_send[0].tdata = axis_router_out.tdata;\n";
    vfpga << "assign axis_rrsp_send[0].tkeep = axis_router_out.tkeep;\n";
    vfpga << "assign axis_rrsp_send[0].tlast = axis_router_out.tlast;\n";
    vfpga << "assign axis_router_out.tready = axis_rrsp_send[0].tready;\n\n";
    
    vfpga << "// ============================================\n";
    vfpga << "// Tie-off Unused Interfaces\n";
    vfpga << "// ============================================\n";
    vfpga << "always_comb begin\n";
    vfpga << "    notify.tie_off_m();\n";
    vfpga << "    sq_rd.tie_off_m();\n";
    vfpga << "    sq_wr.tie_off_m();\n";
    vfpga << "    cq_rd.tie_off_s();\n";
    vfpga << "    cq_wr.tie_off_s();\n";
    vfpga << "    rq_rd.tie_off_s();\n";
    vfpga << "    rq_wr.tie_off_s();\n";
    vfpga << "    axis_card_recv[0].tie_off_s();\n";
    vfpga << "    axis_card_send[0].tie_off_m();\n";
    vfpga << "    axis_rreq_recv[0].tie_off_s();\n";
    vfpga << "    axis_rreq_send[0].tie_off_m();\n";
    vfpga << "end\n";
}

void Backend::emitVivadoTCL(std::ofstream& out) {

}

}  // namespace SV