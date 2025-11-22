#ifndef P4FPGA_CODEGEN_H
#define P4FPGA_CODEGEN_H

#include "common.h"
#include <string>
#include <fstream>
#include <sstream>

namespace SV {

class SVParser;
class SVControl;

class SVCodeGen {
public:
    SVCodeGen() {}
    virtual ~SVCodeGen() {}
    
    // ==========================================
    // Builder Accessors
    // ==========================================
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
    
    // ==========================================
    // Module Getters
    // ==========================================
    std::string getTopModule() const { return topBuilder.toString(); }
    std::string getParserModule() const { return parserBuilder.toString(); }
    std::string getIngressModule() const { return ingressBuilder.toString(); }
    std::string getEgressModule() const { return egressBuilder.toString(); }
    std::string getDeparserModule() const { return deparserBuilder.toString(); }
    std::string getTablesModule() const { return tablesBuilder.toString(); }
    std::string getActionsModule() const { return actionsBuilder.toString(); }
    std::string getTypeDefinitions() const { return typesBuilder.toString(); }
    std::string getInterfaces() const { return interfacesBuilder.toString(); }
        
    // ==========================================
    // Template Processing (Main Entry Points)
    // ==========================================
    std::string readTemplate(const std::string& templateName);
    void processParserTemplate(const SVParser* parser, const std::string& outputPath);
    void processDeparserTemplate(const SVParser* parser, const std::string& outputPath);
    void processTopTemplate(const SVParser* parser, const std::string& outputPath);
    
    // ==========================================
    // Parser Code Generators 
    // ==========================================
    std::string generateCustomHeaderPorts(const SVParser* parser);
    std::string generateCustomHeaderLocalparams(const SVParser* parser);
    std::string generateCustomStateDefinition(const SVParser* parser);
    std::string generateStateValue(const SVParser* parser, const std::string& stateName);
    std::string generateCustomHeaderEthertypes(const SVParser* parser);
    std::string generateCustomHeaderReset(const SVParser* parser);
    std::string generateCustomHeaderClear(const SVParser* parser);
    std::string generateCustomHeaderEthertypeCheck(const SVParser* parser);
    std::string generateCustomHeaderState(const SVParser* parser);
    std::string generateCustomHeaderInternalSignals(const SVParser* parser);
    
    // ==========================================
    // Deparser Code Generators
    // ==========================================
    std::string generateCustomHeaderInputs(const SVParser* parser);
    std::string generateCustomHeaderEmit(const SVParser* parser);
    std::string generateCustomHeaderBuildLogic(const SVParser* parser);
    std::string generateDeparserStackPointerInputs(const SVParser* parser);
    
    // ==========================================
    // Top Code Generators
    // ==========================================
    std::string generateCustomHeaderSignals(const SVParser* parser);
    std::string generateCustomHeaderPipelineSignals(const SVParser* parser);
    std::string generateParserCustomHeaderPorts(const SVParser* parser);
    std::string generatePipelineCustomHeaderInputs(const SVParser* parser);
    std::string generatePipelineCustomHeaderOutputs(const SVParser* parser);
    std::string generateDeparserCustomHeaderPorts(const SVParser* parser);

    // Stack operation generators
    std::string generateStackPointerSignals(const SVParser* parser);
    std::string generateStackPointerLogic(
        const std::map<cstring, SVAction*>& actions,
        const std::map<int, cstring>& actionIdMap
    );
    
    // ==========================================
    // Utility Methods
    // ==========================================
    static void replaceAll(std::string& str, const std::string& from, const std::string& to);
    static void writeToFile(const std::string& content, const std::string& filepath);
    static std::string getTemplateDir();
    
private:
    CodeBuilder parserBuilder;
    CodeBuilder ingressBuilder;
    CodeBuilder egressBuilder;
    CodeBuilder deparserBuilder;
    CodeBuilder topBuilder;
    CodeBuilder typesBuilder;
    CodeBuilder interfacesBuilder;
    CodeBuilder tablesBuilder;
    CodeBuilder actionsBuilder;
};

}  // namespace SV

#endif // P4FPGA_CODEGEN_H