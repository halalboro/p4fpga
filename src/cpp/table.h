#ifndef P4FPGA_TABLE_H
#define P4FPGA_TABLE_H

#include "common.h"
#include <vector>
#include <utility>

namespace SV {

class SVControl;
class SVAction;

class SVTable {
public:
    enum class MatchType {
        EXACT,
        LPM,
        TERNARY,
        RANGE
    };
    
private:
    SVControl* control;
    const IR::P4Table* p4table;
    cstring tableName;
    
    // Table properties
    MatchType matchType;
    int keyWidth;
    int actionDataWidth;
    int tableSize;
    
    // Key and action info
    std::vector<std::pair<const IR::StructField*, int>> keyFields;
    std::vector<cstring> actionNames;
    cstring defaultAction;
    
    void extractKeys();
    void extractActions();
    void determineMatchType();
    
    void emitExactMatchTable(CodeBuilder* builder);
    void emitLPMTable(CodeBuilder* builder);
    void emitTernaryTable(CodeBuilder* builder);
    
public:
    SVTable(SVControl* ctrl, const IR::P4Table* tbl) :
        control(ctrl), 
        p4table(tbl), 
        tableName(tbl->name),
        matchType(MatchType::EXACT),
        keyWidth(0),
        actionDataWidth(0),
        tableSize(1024) {}
    
    bool build();
    void emit(CodeBuilder* builder);
    
    // Getters
    cstring getName() const { return tableName; }
    const IR::P4Table* getP4Table() const { return p4table; }
    int getKeyWidth() const { return keyWidth > 0 ? keyWidth : 256; }
    int getActionDataWidth() const { return actionDataWidth > 0 ? actionDataWidth : 128; }
    int getTableSize() const { return tableSize; }
    MatchType getMatchType() const { return matchType; }
    const IR::ActionList* getActionList() const { return p4table->getActionList(); }
};

}  // namespace SV

#endif