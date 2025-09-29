#include "common.h"
#include "type.h"
#include "bsvprogram.h"
#include "string_utils.h"
#include <sstream>

namespace SV {

FPGATypeFactory* FPGATypeFactory::instance = nullptr;

FPGAType* FPGATypeFactory::create(const IR::Type* type) {
    CHECK_NULL(type);
    CHECK_NULL(typeMap);
    
    FPGAType* result = nullptr;
    
    if (type->is<IR::Type_Boolean>()) {
        result = new FPGABoolType();
    } else if (type->is<IR::Type_Bits>()) {
        result = new FPGAScalarType(type->to<IR::Type_Bits>());
    } else if (type->is<IR::Type_StructLike>()) {
        result = new FPGAStructType(type->to<IR::Type_StructLike>());
    } else if (type->is<IR::Type_Typedef>()) {
        auto canon = typeMap->getType(type);
        result = create(canon);
        auto path = new IR::Path(type->to<IR::Type_Typedef>()->name);
        result = new FPGATypeName(new IR::Type_Name(Util::SourceInfo(), path), result);
    } else if (type->is<IR::Type_Name>()) {
        auto canon = typeMap->getType(type);
        result = create(canon);
        result = new FPGATypeName(type->to<IR::Type_Name>(), result);
    } else {
        P4::error("Type %1% unsupported by FPGA", type);
    }
    
    return result;
}

void FPGABoolType::emit(SVCodeGen& codegen) {
    auto builder = codegen.getTypesBuilder();
    builder->append("logic");
}

void FPGABoolType::declare(SVCodeGen& codegen, cstring id, bool asPointer) {
    auto builder = codegen.getTypesBuilder();
    builder->append("logic ");
    builder->append(id);
}

std::string FPGAScalarType::getSVType() const {
    std::stringstream ss;
    if (width == 1) {
        ss << "logic";
    } else {
        ss << "logic ";
        if (isSigned) ss << "signed ";
        ss << "[" << (width-1) << ":0]";
    }
    return ss.str();
}

void FPGAScalarType::emit(SVCodeGen& codegen) {
    auto builder = codegen.getTypesBuilder();
    builder->append(getSVType());
}

void FPGAScalarType::declare(SVCodeGen& codegen, cstring id, bool asPointer) {
    auto builder = codegen.getTypesBuilder();
    builder->append(getSVType());
    builder->append(" ");
    builder->append(id);
}

FPGAStructType::FPGAStructType(const IR::Type_StructLike* strct) : FPGAType(strct) {
    if (strct->is<IR::Type_Struct>()) {
        kind = cstring("struct");
    } else if (strct->is<IR::Type_Header>()) {
        kind = cstring("header");
    } else {
        BUG("Unexpected struct type %1%", strct);
    }
    
    name = SnakeCase(strct->name);
    width = 0;
    implWidth = 0;
    
    for (auto f : strct->fields) {
        auto type = FPGATypeFactory::instance->create(f->type);
        auto wt = dynamic_cast<IHasWidth*>(type);
        if (wt == nullptr) {
            P4::error("FPGA: Unsupported type in struct %1%", f->type);
        } else {
            width += wt->widthInBits();
            implWidth += wt->implementationWidthInBits();
        }
        fields.push_back(new FPGAField(type, f));
    }
}

void FPGAStructType::declare(SVCodeGen& codegen, cstring id, bool asPointer) {
    auto builder = codegen.getTypesBuilder();
    builder->append(name);
    builder->append("_t ");
    builder->append(id);
}

void FPGAStructType::emit(SVCodeGen& codegen) {
    auto builder = codegen.getTypesBuilder();
    std::stringstream ss;
    
    // Comment
    ss << "// " << (kind == "header" ? "Header" : "Struct") << " type: " << type->toString();
    builder->appendLine(ss.str());
    
    // Typedef struct packed
    ss.str("");
    ss << "typedef struct packed {";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    // Emit fields
    for (auto f : fields) {
        auto fieldType = f->type;
        builder->emitIndent();
        
        // Get the SystemVerilog type string
        std::string svType = fieldType->getSVType();
        builder->append(svType);
        builder->append(" ");
        builder->append(f->field->name);
        builder->append(";");
        
        // Add comment with original P4 type
        builder->append("  // ");
        builder->append(f->field->type->toString());
        builder->newline();
    }
    
    // If it's a header, add validity bit
    if (kind == "header") {
        builder->emitIndent();
        builder->append("logic _valid;  // Header validity");
        builder->newline();
    }
    
    builder->decreaseIndent();
    ss.str("");
    ss << "} " << name << "_t;";
    builder->appendLine(ss.str());
    builder->newline();
    
    // Generate initialization function
    ss.str("");
    ss << "function " << name << "_t init_" << name << "();";
    builder->appendLine(ss.str());
    builder->increaseIndent();
    
    ss.str("");
    ss << name << "_t result;";
    builder->appendLine(ss.str());
    
    builder->appendLine("result = '0;");
    if (kind == "header") {
        builder->appendLine("result._valid = 1'b0;");
    }
    builder->appendLine("return result;");
    
    builder->decreaseIndent();
    builder->appendLine("endfunction");
    builder->newline();
}

void FPGATypeName::declare(SVCodeGen& codegen, cstring id, bool asPointer) {
    canonical->declare(codegen, id, asPointer);
}

unsigned FPGATypeName::widthInBits() {
    auto wt = dynamic_cast<IHasWidth*>(canonical);
    if (wt == nullptr) {
        P4::error("Type %1% does not have a fixed width", typeName);
        return 0;
    }
    return wt->widthInBits();
}

unsigned FPGATypeName::implementationWidthInBits() {
    auto wt = dynamic_cast<IHasWidth*>(canonical);
    if (wt == nullptr) {
        P4::error("Type %1% does not have a fixed width", typeName);
        return 0;
    }
    return wt->implementationWidthInBits();
}

}  // namespace SV