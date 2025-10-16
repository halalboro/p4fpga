#ifndef P4FPGA_BSVPROGRAM_H
#define P4FPGA_BSVPROGRAM_H

#include "common.h"
#include <string>

namespace SV {

class SVCodeGen {
public:
    SVCodeGen() {}
    virtual ~SVCodeGen() {}
    
    // Builder getters
    CodeBuilder* getParserBuilder() { return &parserBuilder; }
    CodeBuilder* getIngressBuilder() { return &ingressBuilder; }
    CodeBuilder* getEgressBuilder() { return &egressBuilder; }
    CodeBuilder* getDeparserBuilder() { return &deparserBuilder; }
    CodeBuilder* getTopBuilder() { return &topBuilder; }
    CodeBuilder* getTypesBuilder() { return &typesBuilder; }
    CodeBuilder* getInterfacesBuilder() { return &interfacesBuilder; }
    CodeBuilder* getTablesBuilder() { return &tablesBuilder; }
    CodeBuilder* getActionsBuilder() { return &actionsBuilder; }
    CodeBuilder* getPipelineBuilder() { return &ingressBuilder; }  
    
    // Module getters
    std::string getTopModule() const { return topBuilder.toString(); }
    std::string getParserModule() const { return parserBuilder.toString(); }
    std::string getIngressModule() const { return ingressBuilder.toString(); }
    std::string getEgressModule() const { return egressBuilder.toString(); }
    std::string getDeparserModule() const { return deparserBuilder.toString(); }
    std::string getTablesModule() const { return tablesBuilder.toString(); }
    std::string getActionsModule() const { return actionsBuilder.toString(); }
    std::string getTypeDefinitions() const { return typesBuilder.toString(); }
    std::string getInterfaces() const { return interfacesBuilder.toString(); }
    
    // These are now implemented in the .cpp file
    std::string getTestbench() const;
    std::string getMakefile() const;
    
    // Helper methods (implemented in .cpp)
    void emitHeader(CodeBuilder* builder, const std::string& moduleName);
    void emitAxiStreamInterface(CodeBuilder* builder,
                                const std::string& name,
                                bool isMaster);
    void emitPipelineStage(CodeBuilder* builder, int stage);
    
private:
    CodeBuilder parserBuilder;
    CodeBuilder ingressBuilder;    // Separate builder for ingress
    CodeBuilder egressBuilder;     // Separate builder for egress
    CodeBuilder deparserBuilder;
    CodeBuilder topBuilder;
    CodeBuilder typesBuilder;
    CodeBuilder interfacesBuilder;
    CodeBuilder tablesBuilder;     // Added for tables
    CodeBuilder actionsBuilder;    // Added for actions
};

}  // namespace SV

#endif