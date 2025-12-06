/*
 * P4-FPGA Compiler - Common Implementation
 *
 * Global variable definitions for compiler-wide state.
 */

#include "common.h"

namespace SV {
    // Global verbose flag (controlled by --verb option)
    bool g_verbose = false;

    // Global storage for detected if-else statements across control blocks
    std::vector<IfElseInfo> g_detectedIfElse;

    // Global storage for parser states extracted from raw AST
    std::map<P4::cstring, std::vector<ExtractedParserState>> g_extractedParserStates;
}