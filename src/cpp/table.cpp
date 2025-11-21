#include "common.h"
#include "table.h"
#include "control.h"
#include "program.h"
#include "lib/log.h"
#include <sstream>

namespace SV {

// ==========================================
// Debug Control
// ==========================================
#define TABLE_INFO(msg)    std::cerr << "[Table] " << msg << std::endl
#define TABLE_SUCCESS(msg) std::cerr << "[✓] " << msg << std::endl
#define TABLE_ERROR(msg)   std::cerr << "[ERROR] " << msg << std::endl

#define TABLE_DEBUG(msg) if (SV::g_verbose) std::cerr << "  " << msg << std::endl
#define TABLE_TRACE(msg) if (SV::g_verbose) std::cerr << "    " << msg << std::endl

// ==========================================
// Build Table
// ==========================================

bool SVTable::build() {
    TABLE_DEBUG("Building table: " << tableName);
    
    extractKeys();
    extractActions();
    determineMatchType();
    
    // Get table size from properties
    if (p4table->properties) {
        for (auto prop : p4table->properties->properties) {
            if (prop->name == "size") {
                if (auto expr = prop->value->to<IR::ExpressionValue>()) {
                    if (auto constant = expr->expression->to<IR::Constant>()) {
                        tableSize = constant->asInt();
                    }
                }
            }
        }
    }
    
    // Calculate action data width (simplified)
    actionDataWidth = 64;  // Default, should calculate from action parameters
    
    // Concise summary (always shown)
    std::string matchTypeStr = 
        (matchType == MatchType::LPM) ? "lpm" :
        (matchType == MatchType::TERNARY) ? "ternary" :
        (matchType == MatchType::RANGE) ? "range" : "exact";
    
#if DEBUG_TABLE_VERBOSE
    TABLE_SUCCESS("Table " << tableName << ": " 
                  << matchTypeStr << ", "
                  << keyWidth << "-bit key, "
                  << tableSize << " entries, "
                  << actionNames.size() << " actions");
#endif
    
    return true;
}

// ==========================================
// Extract Keys
// ==========================================

void SVTable::extractKeys() {
    TABLE_TRACE("Extracting keys from table: " << tableName);
    
    auto keys = p4table->getKey();
    if (keys != nullptr) {
        for (auto key : keys->keyElements) {
            auto element = key->to<IR::KeyElement>();
            if (element && element->expression->is<IR::Member>()) {
                auto member = element->expression->to<IR::Member>();
                auto type = control->getProgram()->typeMap->getType(member, true);
                
                int fieldSize = 32;  // Default
                if (type && type->template is<IR::Type_Bits>()) {
                    fieldSize = type->template to<IR::Type_Bits>()->size;
                }
                
                // Store field info
                keyFields.push_back(std::make_pair(nullptr, fieldSize));
                keyWidth += fieldSize;
                
                TABLE_TRACE("Key field: " << member->member << " (" << fieldSize << " bits)");
            }
        }
    }
    
    TABLE_TRACE("Total key width: " << keyWidth << " bits");
}

// ==========================================
// Extract Actions
// ==========================================

void SVTable::extractActions() {
    TABLE_TRACE("Extracting actions from table: " << tableName);
    
    auto actionList = p4table->getActionList();
    if (actionList && actionList->actionList.size() > 0) {
        for (auto action : actionList->actionList) {
            if (auto elem = action->to<IR::ActionListElement>()) {
                cstring actionName;
                
                if (auto expr = elem->expression->to<IR::MethodCallExpression>()) {
                    actionName = expr->method->toString();
                } else if (auto path = elem->expression->to<IR::PathExpression>()) {
                    actionName = path->path->name;
                }
                
                if (!actionName.isNullOrEmpty()) {
                    actionNames.push_back(actionName);
                    TABLE_TRACE("Action: " << actionName);
                }
            }
        }
    }
    
    // Get default action
    if (p4table->getDefaultAction()) {
        defaultAction = cstring("NoAction");  // Simplified
        TABLE_TRACE("Default action: " << defaultAction);
    }
}

// ==========================================
// Determine Match Type
// ==========================================

void SVTable::determineMatchType() {
    // Default to EXACT
    matchType = MatchType::EXACT;
    
    TABLE_TRACE("Determining match type for table: " << tableName);
    
    auto keys = p4table->getKey();
    if (keys == nullptr || keys->keyElements.empty()) {
        TABLE_TRACE("No keys found, using EXACT");
        return;
    }
    
    TABLE_TRACE("Checking " << keys->keyElements.size() << " key elements");
    
    // Check each key element for match type
    for (auto keyElement : keys->keyElements) {
        auto key = keyElement->to<IR::KeyElement>();
        if (!key || !key->matchType) {
            continue;
        }
        
        // The matchType is a PathExpression pointing to the match kind
        if (auto pathExpr = key->matchType->to<IR::PathExpression>()) {
            cstring matchKindName = pathExpr->path->name;
            
            if (matchKindName == "lpm") {
                matchType = MatchType::LPM;
                TABLE_TRACE("Detected LPM match type");
                break;
            } else if (matchKindName == "ternary") {
                matchType = MatchType::TERNARY;
                TABLE_TRACE("Detected TERNARY match type");
                break;
            } else if (matchKindName == "range") {
                matchType = MatchType::RANGE;
                TABLE_TRACE("Detected RANGE match type");
                break;
            } else if (matchKindName == "exact") {
                TABLE_TRACE("Detected EXACT match type");
            }
        } else {
            // Try as string (fallback)
            std::string matchKindStr = key->matchType->toString().string();
            
            if (matchKindStr.find("lpm") != std::string::npos) {
                matchType = MatchType::LPM;
                TABLE_TRACE("Detected LPM from string");
                break;
            } else if (matchKindStr.find("ternary") != std::string::npos) {
                matchType = MatchType::TERNARY;
                TABLE_TRACE("Detected TERNARY from string");
                break;
            } else if (matchKindStr.find("range") != std::string::npos) {
                matchType = MatchType::RANGE;
                TABLE_TRACE("Detected RANGE from string");
                break;
            }
        }
    }
}

}  // namespace SV