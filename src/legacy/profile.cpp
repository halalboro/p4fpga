#include "common.h"
#include "profile.h"
#include <cmath>
#include <sstream>

namespace SV {

bool DoResourceEstimation::preorder(const IR::P4Control* control) {
    if (control->name == "ingress" || control->name == "egress") {
        for (auto s : control->controlLocals) {
            visit(s);
        }
    }
    return false;
}

bool DoResourceEstimation::preorder(const IR::P4Table* table) {
    int size = 0;
    
    // Extract table properties
    if (table->properties) {
        for (auto p : table->properties->properties) {
            if (auto prop = p->to<IR::Property>()) {
                if (prop->name == "size") {
                    if (auto expr_value = prop->value->to<IR::ExpressionValue>()) {
                        if (auto constant = expr_value->expression->to<IR::Constant>()) {
                            size = constant->asInt();
                        }
                    }
                } else if (prop->name == "default_action") {
                    // Handle default action if needed
                } else {
                    visit(prop->value);
                }
            }
        }
    }
    
    // Write profile information if profiler is available
    if (profiler) {
        profiler->writeTableProfile(size, width_bit, table_type.c_str(), table->name.string());
    }
    
    LOG3("Table " << table->name << ": size=" << size 
         << " width=" << width_bit << " type=" << table_type);
    
    // Reset temporary variables
    width_bit = 0;
    table_type = cstring("exact");
    
    return false;
}

bool DoResourceEstimation::preorder(const IR::ActionList* action) {
    if (action->actionList.size() > 0) {
        width_bit += static_cast<int>(std::ceil(std::log2(action->actionList.size())));
    }
    return false;
}

bool DoResourceEstimation::preorder(const IR::Key* key) {
    int width = 0;
    cstring type = cstring("exact");
    
    if (key->keyElements.size() > 0) {
        for (auto k : key->keyElements) {
            if (auto e = k->to<IR::KeyElement>()) {
                auto t = typeMap->getType(e->expression, true);
                if (t && t->is<IR::Type_Bits>()) {
                    auto tb = t->to<IR::Type_Bits>();
                    width += tb->width_bits();
                    
                    if (e->matchType && e->matchType->is<IR::PathExpression>()) {
                        auto matchType = e->matchType->to<IR::PathExpression>();
                        if (matchType->path->name == "ternary") {
                            type = cstring("ternary");
                        } else if (matchType->path->name == "lpm") {
                            type = cstring("lpm");
                        }
                    }
                }
            }
        }
    }
    
    table_type = type;
    width_bit += width;
    
    return false;
}

}  // namespace SV