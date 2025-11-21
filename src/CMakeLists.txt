set(P4SV_BACKEND_SRCS
    cpp/action.cpp
    cpp/backend.cpp
    cpp/bsvprogram.cpp
    cpp/common.cpp
    cpp/control.cpp
    cpp/deparser.cpp
    cpp/midend.cpp
    cpp/parser.cpp
    cpp/program.cpp
    cpp/string_utils.cpp
    cpp/table.cpp
    cpp/type.cpp
    cpp/controlflow.cpp
)

set(P4SV_BACKEND_HDRS
    cpp/action.h
    cpp/backend.h
    cpp/bsvprogram.h
    cpp/common.h 
    cpp/control.h
    cpp/deparser.h
    cpp/midend.h
    cpp/options.h
    cpp/parser.h
    cpp/program.h
    cpp/string_utils.h
    cpp/table.h 
    cpp/type.h
    cpp/controlflow.h
)


# Main executable source
set(P4C_P4SV_SRCS
    cpp/p4-fpga.cpp
)

# Create backend library
add_library(p4sv_backend STATIC ${P4SV_BACKEND_SRCS})

# Add dependencies
add_dependencies(p4sv_backend frontend-parser-gen genIR)

# Include directories
target_include_directories(p4sv_backend
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/cpp
  ${P4C_BINARY_DIR} # For generated IR headers
  ${P4C_SOURCE_DIR} # For p4c headers
  ${CMAKE_BINARY_DIR}/p4c/frontends
  ${CMAKE_BINARY_DIR}/p4c/frontends/parsers/p4
  ${CMAKE_BINARY_DIR}/p4c/frontends/parsers/v1
)

# Find required packages
find_package(Boost REQUIRED COMPONENTS system filesystem)

# Create executable
add_executable(p4c-sv ${P4C_P4SV_SRCS})
add_dependencies(p4c-sv frontend-parser-gen)

# Link libraries
target_link_libraries(p4c-sv
  p4sv_backend
  frontend
  ir
  midend
  ${P4C_LIBRARIES}
  ${P4C_LIB_DEPS}
  ${Boost_LIBRARIES}
  -labsl_hash
  -labsl_city
  -labsl_cord
  -labsl_strings
  -labsl_raw_hash_set
  -lgc
  -lpthread
  -ldl
)

# Include directories for executable
target_include_directories(p4c-sv
  PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/cpp
  ${Boost_INCLUDE_DIRS}
  ${P4C_BINARY_DIR}
  ${P4C_SOURCE_DIR}
  ${CMAKE_BINARY_DIR}/p4c/frontends
  ${CMAKE_BINARY_DIR}/p4c/frontends/parsers/p4
  ${CMAKE_BINARY_DIR}/p4c/frontends/parsers/v1
)

# Install the executable
install(TARGETS p4c-sv
    RUNTIME DESTINATION ${P4C_RUNTIME_OUTPUT_DIRECTORY}
)

# Optional: Install headers if needed
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cpp/
    DESTINATION ${P4C_INSTALL_PREFIX}/include/p4c-sv
    FILES_MATCHING PATTERN "*.h"
)

# Set C++ standard (p4c uses C++17)
set_target_properties(p4sv_backend PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

set_target_properties(p4c-sv PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)