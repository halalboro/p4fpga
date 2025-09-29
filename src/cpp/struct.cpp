#include "common.h"
#include "struct.h"
#include "parser.h"
#include "control.h"
#include "ir/ir.h"
#include "string_utils.h"
#include <sstream>

namespace SV {

bool StructCodeGen::preorder(const IR::Type_Header* hdr) {
    cstring name = hdr->name;
    cstring header_type = SnakeCase(name);  // Use snake_case for SV
    
    auto it = header_map.find(name);
    if (it != header_map.end()) {
        // already in map, skip
        return false;
    }
    header_map.emplace(name, hdr);
    
    std::stringstream ss;
    
    // Generate SystemVerilog struct
    ss << "// Header type: " << name;
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "typedef struct packed {";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    int header_width = 0;
    for (auto f : hdr->fields) {
        if (f->type->is<IR::Type_Bits>()) {
            int size = f->type->to<IR::Type_Bits>()->size;
            cstring field_name = f->name;
            
            ss.str("");
            ss << "logic [" << (size-1) << ":0] " << field_name << ";";
            builder->appendLine(ss.str());
            
            header_width += size;
        } else if (f->type->is<IR::Type_Boolean>()) {
            cstring field_name = f->name;
            builder->appendLine("logic " + field_name.string() + ";"); 
            header_width += 1;
        }
    }
    
    builder->decreaseIndent();
    ss.str("");
    ss << "} " << header_type << "_t;";
    builder->appendLine(ss.str());
    builder->newline();
    
    // Generate conversion function
    ss.str("");
    ss << "function " << header_type << "_t extract_" << header_type 
       << "(input logic [" << (header_width-1) << ":0] data);";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    ss.str("");
    ss << header_type << "_t result;";
    builder->appendLine(ss.str());
    
    // Extract fields from data
    int offset = 0;
    for (auto f : hdr->fields) {
        if (f->type->is<IR::Type_Bits>()) {
            int size = f->type->to<IR::Type_Bits>()->size;
            cstring field_name = f->name;
            
            ss.str("");
            ss << "result." << field_name << " = data[" << (offset + size - 1) << ":" << offset << "];";
            builder->appendLine(ss.str());
            
            offset += size;
        }
    }
    
    builder->appendLine("return result;");
    builder->decreaseIndent();
    builder->appendLine("endfunction");
    builder->newline();
    
    return false;
}

bool StructCodeGen::preorder(const IR::Type_Struct* strct) {
    cstring name = strct->name;
    cstring struct_type = SnakeCase(name);
    
    auto it = struct_map.find(name);
    if (it != struct_map.end()) {
        // already processed
        return false;
    }
    struct_map.emplace(name, strct);
    
    std::stringstream ss;
    
    // Generate SystemVerilog struct
    ss << "// Struct type: " << name;
    builder->appendLine(ss.str());
    
    ss.str("");
    ss << "typedef struct packed {";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    int struct_width = 0;
    for (auto f : strct->fields) {
        if (f->type->is<IR::Type_Bits>()) {
            int size = f->type->to<IR::Type_Bits>()->size;
            cstring field_name = f->name;
            
            ss.str("");
            ss << "logic [" << (size-1) << ":0] " << field_name << ";";
            builder->appendLine(ss.str());
            
            struct_width += size;
        } else if (f->type->is<IR::Type_Boolean>()) {
            cstring field_name = f->name;
            builder->appendLine("logic " + field_name.string() + ";");  // Fixed: toString() -> string()
            struct_width += 1;
        } else if (auto nested = f->type->to<IR::Type_Name>()) {
            // Handle nested types
            cstring field_name = f->name;
            cstring type_name = SnakeCase(nested->path->name);
            
            ss.str("");
            ss << type_name << "_t " << field_name << ";";
            builder->appendLine(ss.str());
        }
    }
    
    builder->decreaseIndent();
    ss.str("");
    ss << "} " << struct_type << "_t;";
    builder->appendLine(ss.str());
    builder->newline();
    
    // Generate initialization function
    ss.str("");
    ss << "function " << struct_type << "_t init_" << struct_type << "();";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    ss.str("");
    ss << struct_type << "_t result;";
    builder->appendLine(ss.str());
    
    builder->appendLine("result = '0;  // Initialize all fields to 0");
    builder->appendLine("return result;");
    
    builder->decreaseIndent();
    builder->appendLine("endfunction");
    builder->newline();
    
    return false;
}

bool HeaderCodeGen::preorder(const IR::StructField* field) {
    std::stringstream ss;
    cstring field_name = field->getName();
    
    if (field->type->is<IR::Type_Header>()) {
        auto hdr = field->type->to<IR::Type_Header>();
        cstring header_type = SnakeCase(hdr->name);
        
        // Header with validity bit
        ss << header_type << "_t " << field_name << ";";
        builder->appendLine(ss.str());
        
        ss.str("");
        ss << "logic " << field_name << "_valid;";
        builder->appendLine(ss.str());
        
    } else if (auto bits = field->type->to<IR::Type_Bits>()) {
        int size = bits->size;
        
        ss << "logic [" << (size-1) << ":0] " << field_name << ";";
        builder->appendLine(ss.str());
    }
    
    return false;
}

bool HeaderCodeGen::preorder(const IR::Type_Header* hdr) {
    // Handled by StructCodeGen
    return false;
}


void StructCodeGen::emit() {
    // Any final emission logic
}

}  // namespace SV