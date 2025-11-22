#ifndef P4FPGA_TABLE_H
#define P4FPGA_TABLE_H

#include "common.h"
#include <vector>
#include <utility>

namespace SV {

class SVControl;
class SVAction;

struct ConstTableEntry {
    std::vector<cstring> keyValues;
    cstring actionName;
    std::vector<cstring> actionArgs;
};

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
    bool hasConstEntries_;
    std::vector<ConstTableEntry> constEntries_;
    void extractConstEntries(const IR::Property* prop);
    
    // Key and action info 
    std::vector<std::pair<cstring, int>> keyFields; 
    std::vector<cstring> actionNames;
    cstring defaultAction;
    
    void extractKeys();
    void extractActions();
    void determineMatchType();

public:
    SVTable(SVControl* ctrl, const IR::P4Table* tbl) :
        control(ctrl), 
        p4table(tbl), 
        tableName(tbl->name),
        matchType(MatchType::EXACT),
        keyWidth(0),
        actionDataWidth(0),
        tableSize(1024),
        hasConstEntries_(false) {}
    
    bool build();
    void emit(CodeBuilder* builder);
    
    bool hasConstEntries() const { return hasConstEntries_; }
    const std::vector<ConstTableEntry>& getConstEntries() const { 
        return constEntries_; 
    }
    
    // Get key field names 
    std::vector<cstring> getKeyFieldNames() const {
        std::vector<cstring> names;
        for (const auto& keyField : keyFields) {
            names.push_back(keyField.first);  
        }
        return names;
    }
    
    // Getters
    cstring getName() const { return tableName; }
    const IR::P4Table* getP4Table() const { return p4table; }
    int getKeyWidth() const { return keyWidth > 0 ? keyWidth : 256; }
    int getActionDataWidth() const { return actionDataWidth > 0 ? actionDataWidth : 128; }
    int getTableSize() const { return tableSize; }
    MatchType getMatchType() const { return matchType; }
    const IR::ActionList* getActionList() const { return p4table->getActionList(); }
    
    // Get match type as string
    std::string getMatchTypeString() const {
        switch (matchType) {
            case MatchType::LPM:     return "lpm";
            case MatchType::TERNARY: return "ternary";
            case MatchType::RANGE:   return "range";
            default:                 return "exact";
        }
    }
};

}  // namespace SV

#endif  // P4FPGA_TABLE_H