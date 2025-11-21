#ifndef EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_STRUCT_H_
#define EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_STRUCT_H_

#include "common.h"
#include <map>
#include <vector>

namespace SV {

class SVProgram;

class StructCodeGen : public Inspector {
public:
    StructCodeGen(const SVProgram* program, CodeBuilder* builder) :
        program(program), builder(builder) {}
    
    bool preorder(const IR::Type_Header* header) override;
    bool preorder(const IR::Type_Struct* strct) override;
    void emit();
    
private:
    const SVProgram* program;
    CodeBuilder* builder;
    std::map<cstring, const IR::Type_Header*> header_map;
    std::map<cstring, const IR::Type_Struct*> struct_map;
};

class HeaderCodeGen : public Inspector {
public:
    HeaderCodeGen(CodeBuilder* builder) :
        builder(builder) {}
    
    bool preorder(const IR::StructField* field) override;
    bool preorder(const IR::Type_Header* header) override;
    
private:
    CodeBuilder* builder;
    std::vector<cstring> headers;
};

}  // namespace SV

#endif