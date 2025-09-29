#ifndef EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_TYPE_H_
#define EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_TYPE_H_

#include "common.h"
#include "lib/algorithm.h"
#include "ir/ir.h"

namespace SV {

class SVCodeGen; // Forward declaration

// Interface for types with width
class IHasWidth {
public:
    virtual ~IHasWidth() {}
    virtual unsigned widthInBits() = 0;
    virtual unsigned implementationWidthInBits() = 0;
};

// Base class for FPGA types
class FPGAType : public FPGAObject {
protected:
    explicit FPGAType(const IR::Type* type) : type(type) {}
    
public:
    const IR::Type* type;
    virtual void emit(SVCodeGen& codegen) = 0;
    virtual void declare(SVCodeGen& codegen, cstring id, bool asPointer) = 0;
    virtual std::string getSVType() const = 0;
};

class FPGATypeFactory {
private:
    const P4::TypeMap* typeMap;
    explicit FPGATypeFactory(const P4::TypeMap* typeMap) : typeMap(typeMap) {}
    
public:
    static FPGATypeFactory* instance;
    static void createFactory(const P4::TypeMap* typeMap) { 
        FPGATypeFactory::instance = new FPGATypeFactory(typeMap); 
    }
    FPGAType* create(const IR::Type* type);
};

class FPGABoolType : public FPGAType, public IHasWidth {
public:
    FPGABoolType() : FPGAType(IR::Type_Boolean::get()) {}
    void emit(SVCodeGen& codegen) override;
    void declare(SVCodeGen& codegen, cstring id, bool asPointer) override;
    std::string getSVType() const override { return "logic"; }
    unsigned widthInBits() override { return 1; }
    unsigned implementationWidthInBits() override { return 1; }
};

class FPGAScalarType : public FPGAType, public IHasWidth {
public:
    const unsigned width;
    const bool isSigned;
    
    explicit FPGAScalarType(const IR::Type_Bits* bits) :
        FPGAType(bits), width(bits->size), isSigned(bits->isSigned) {}
        
    void emit(SVCodeGen& codegen) override;
    void declare(SVCodeGen& codegen, cstring id, bool asPointer) override;
    std::string getSVType() const override;
    unsigned widthInBits() override { return width; }
    unsigned implementationWidthInBits() override { return width; }
};

class FPGATypeName : public FPGAType, public IHasWidth {
    const IR::Type_Name* typeName;
    FPGAType* canonical;
    
public:
    FPGATypeName(const IR::Type_Name* type, FPGAType* canonical) :
        FPGAType(type), typeName(type), canonical(canonical) {}
        
    void emit(SVCodeGen& codegen) override { canonical->emit(codegen); }
    void declare(SVCodeGen& codegen, cstring id, bool asPointer) override;
    std::string getSVType() const override { return canonical->getSVType(); }
    unsigned widthInBits() override;
    unsigned implementationWidthInBits() override;
};

class FPGAStructType : public FPGAType, public IHasWidth {
public:
    class FPGAField {
    public:
        FPGAType* type;
        const IR::StructField* field;
        
        FPGAField(FPGAType* type, const IR::StructField* field) :
            type(type), field(field) {}
    };
    
    cstring kind;
    cstring name;
    std::vector<FPGAField*> fields;
    unsigned width;
    unsigned implWidth;
    
    explicit FPGAStructType(const IR::Type_StructLike* strct);
    ~FPGAStructType() {
        for (auto f : fields) delete f;
    }
    
    void declare(SVCodeGen& codegen, cstring id, bool asPointer) override;
    void emit(SVCodeGen& codegen) override;
    std::string getSVType() const override { return name.string() + "_t"; }
    unsigned widthInBits() override { return width; }
    unsigned implementationWidthInBits() override { return width; }
};

}  // namespace SV

#endif /* EXTENSIONS_CPP_LIBP4FPGA_INCLUDE_TYPE_H_ */