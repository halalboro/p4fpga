// common.cpp
#include "common.h"

namespace SV {
    // Global verbose flag (controlled by --verb option)
    bool g_verbose = false;

    std::vector<IfElseInfo> g_detectedIfElse;
}