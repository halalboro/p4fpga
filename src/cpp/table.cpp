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
    
    // NEW: Check for const entries
    for (auto prop : p4table->properties->properties) {
        if (prop->name == "entries") {
            TABLE_DEBUG("Table " << tableName << " has const entries");
            hasConstEntries_ = true;
            extractConstEntries(prop);
        }
    }

    return true;
}

void SVTable::extractConstEntries(const IR::Property* prop) {
    TABLE_DEBUG("entries property value type: " << prop->value->node_type_name());
    
    auto entriesList = prop->value->to<IR::EntriesList>();
    if (!entriesList) {
        TABLE_DEBUG("Failed to cast to EntriesList");
        return;
    }
    
    TABLE_DEBUG("EntriesList has " << entriesList->entries.size() << " entries");
    
    for (auto entry : entriesList->entries) {
        TABLE_DEBUG("  Processing entry, keys type: " << entry->keys->node_type_name());
        
        ConstTableEntry constEntry;
        
        // Extract key values
        if (auto keyTuple = entry->keys->to<IR::ListExpression>()) {
            TABLE_DEBUG("    Keys is ListExpression with " << keyTuple->components.size() << " components");
            for (auto key : keyTuple->components) {
                TABLE_DEBUG("      Key component type: " << key->node_type_name());
                if (auto constant = key->to<IR::Constant>()) {
                    constEntry.keyValues.push_back(cstring::to_cstring(constant->value));
                } else if (auto pathExpr = key->to<IR::PathExpression>()) {
                    cstring constName = pathExpr->path->name.name;
                    TABLE_DEBUG("      PathExpression name: " << constName);
                    
                    // First try refMap
                    auto decl = control->getProgram()->refMap->getDeclaration(pathExpr->path);
                    if (decl) {
                        TABLE_DEBUG("      refMap found declaration: " << decl->node_type_name());
                        if (auto constDecl = decl->to<IR::Declaration_Constant>()) {
                            const IR::Expression* init = constDecl->initializer;
                            // Unwrap Cast if present
                            if (auto cast = init->to<IR::Cast>()) {
                                init = cast->expr;
                            }
                            if (auto val = init->to<IR::Constant>()) {
                                constEntry.keyValues.push_back(cstring::to_cstring(val->value));
                                TABLE_DEBUG("      Resolved via refMap to: " << val->value);
                            }
                        }
                    } else {
                        TABLE_DEBUG("      refMap returned null, trying constants map");
                        // Fallback: use program's extracted constants
                        const auto& constants = control->getProgram()->getConstants();
                        TABLE_DEBUG("      Constants map size: " << constants.size());
                        auto it = constants.find(constName);
                        if (it != constants.end()) {
                            constEntry.keyValues.push_back(cstring::to_cstring(it->second));
                            TABLE_DEBUG("      Resolved via constants map: " << it->second);
                        } else {
                            TABLE_DEBUG("      Constant NOT found: " << constName);
                        }
                    }
                }
            }
        } else if (auto constant = entry->keys->to<IR::Constant>()) {
            TABLE_DEBUG("    Keys is Constant");
            constEntry.keyValues.push_back(cstring::to_cstring(constant->value));
        } else if (auto pathExpr = entry->keys->to<IR::PathExpression>()) {
            // Single key as named constant
            cstring constName = pathExpr->path->name.name;
            TABLE_DEBUG("    Keys is PathExpression: " << constName);
            
            // First try refMap
            auto decl = control->getProgram()->refMap->getDeclaration(pathExpr->path);
            if (decl) {
                TABLE_DEBUG("    refMap found declaration: " << decl->node_type_name());
                if (auto constDecl = decl->to<IR::Declaration_Constant>()) {
                    const IR::Expression* init = constDecl->initializer;
                    // Unwrap Cast if present
                    if (auto cast = init->to<IR::Cast>()) {
                        init = cast->expr;
                    }
                    if (auto val = init->to<IR::Constant>()) {
                        constEntry.keyValues.push_back(cstring::to_cstring(val->value));
                        TABLE_DEBUG("    Resolved via refMap to: " << val->value);
                    }
                }
            } else {
                TABLE_DEBUG("    refMap returned null, trying constants map");
                // Fallback: use program's extracted constants
                const auto& constants = control->getProgram()->getConstants();
                TABLE_DEBUG("    Constants map size: " << constants.size());
                auto it = constants.find(constName);
                if (it != constants.end()) {
                    constEntry.keyValues.push_back(cstring::to_cstring(it->second));
                    TABLE_DEBUG("    Resolved via constants map: " << it->second);
                } else {
                    TABLE_DEBUG("    Constant NOT found: " << constName);
                }
            }
        } else {
            TABLE_DEBUG("    Keys is neither ListExpression nor Constant nor PathExpression");
        }
        
        TABLE_DEBUG("    keyValues size: " << constEntry.keyValues.size());
        
        // Extract action
        if (auto actionCall = entry->action->to<IR::MethodCallExpression>()) {
            auto pathExpr = actionCall->method->to<IR::PathExpression>();
            if (pathExpr) {
                constEntry.actionName = pathExpr->path->name.name;
                
                // Extract action arguments
                for (auto arg : *actionCall->arguments) {
                    if (auto argConst = arg->expression->to<IR::Constant>()) {
                        constEntry.actionArgs.push_back(
                            cstring::to_cstring(argConst->value));
                    }
                }
            }
        }
        
        if (!constEntry.keyValues.empty()) {
            constEntries_.push_back(constEntry);
            TABLE_DEBUG("  Const entry: " << constEntry.keyValues[0] 
                          << " -> " << constEntry.actionName);
        }
    }
    
    TABLE_DEBUG("Extracted " << constEntries_.size() << " const entries");
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

                // Build the full field path (e.g., "ethernet.dstAddr" from "hdr.ethernet.dstAddr")
                // The member->expr points to the header (e.g., hdr.ethernet)
                std::string fullFieldName = member->member.string();
                if (auto headerMember = member->expr->to<IR::Member>()) {
                    // This is a nested member like hdr.ethernet.dstAddr
                    // headerMember->member gives us "ethernet"
                    fullFieldName = headerMember->member.string() + "." + member->member.string();
                }

                // Store field info with full path
                keyFields.push_back(std::make_pair(cstring(fullFieldName), fieldSize));
                keyWidth += fieldSize;


                TABLE_TRACE("Key field: " << fullFieldName << " (" << fieldSize << " bits)");
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