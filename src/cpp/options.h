#ifndef EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_OPTIONS_H_
#define EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_OPTIONS_H_

#include "common.h"
#include "frontends/common/options.h"
#include "frontends/common/parser_options.h"
#include <string>

namespace SV {

class SVOptions : public CompilerOptions {
public:
    // Output directory for generated SystemVerilog files
    cstring outputDir;
    // Generate testbench
    bool generateTestbench = false;
    // Target FPGA platform
    cstring targetPlatform;
    // Clock frequency (for timing annotations)
    unsigned clockFrequency = 250;
    
    SVOptions() : outputDir("."), targetPlatform("xilinx") {
        registerOption("--output-dir", "dir",
                      [this](const char* arg) {
                          outputDir = cstring(arg);
                          return true;
                      },
                      "Directory for SystemVerilog output files");
        
        registerOption("--testbench", nullptr,
                      [this](const char*) {
                          generateTestbench = true;
                          return true;
                      },
                      "Generate SystemVerilog testbench");
        
        registerOption("--fpga-target", "platform",
                      [this](const char* arg) {
                          targetPlatform = cstring(arg);
                          return true;
                      },
                      "Target FPGA platform (generic, xilinx, intel)");
        
        registerOption("--clock-freq", "mhz",
                      [this](const char* arg) {
                          clockFrequency = std::stoi(arg);
                          return true;
                      },
                      "Clock frequency in MHz (default: 250)");
    }
};

// Use the provided template for context
using SVContext = P4::P4CContextWithOptions<SVOptions>;

using FPGAOptions = SVOptions;

} // namespace SV

#endif