#ifndef _BACKENDS_P4_RESOURCE_H_
#define _BACKENDS_P4_RESOURCE_H_

#include "common.h"
#include "ir/ir.h"
#include "frontends/p4/typeChecking/typeChecker.h"
#include "frontends/p4/methodInstance.h"
#include "frontends/common/resolveReferences/resolveReferences.h"
#include <cmath>
#include <fstream>

namespace SV {

// Simple profiler for resource estimation
class ResourceProfiler {
public:
    std::ofstream profileFile;
    
    ResourceProfiler(const std::string& filename = "resource_profile.txt") {
        profileFile.open(filename);
    }
    
    ~ResourceProfiler() {
        if (profileFile.is_open()) {
            profileFile.close();
        }
    }
    
    void writeTableProfile(int size, int width, const std::string& type, const std::string& name) {
        if (profileFile.is_open()) {
            profileFile << size << " " << width << " " << type << " " << name << std::endl;
        }
    }
};

class DoResourceEstimation : public Inspector {
    // temporary variables to pass values
    cstring table_name;
    cstring table_type;
    int width_bit;
    int table_size;
    
    ResourceProfiler* profiler;
    const ReferenceMap* refMap;
    const TypeMap* typeMap;
    
public:
    DoResourceEstimation(const ReferenceMap* refMap, 
                        const TypeMap* typeMap, 
                        ResourceProfiler* profiler = nullptr) :
        refMap(refMap), 
        typeMap(typeMap), 
        profiler(profiler),
        table_type("exact"),
        width_bit(0),
        table_size(0) {
        CHECK_NULL(refMap); 
        CHECK_NULL(typeMap);
        setName("DoResourceEstimation");
    }
    
    bool preorder(const IR::P4Table* table) override;
    bool preorder(const IR::P4Control* control) override;
    bool preorder(const IR::ActionList* actions) override;
    bool preorder(const IR::Key* key) override;
};

class ResourceEstimation : public PassManager {
public:
    ResourceEstimation(ReferenceMap* refMap, TypeMap* typeMap, ResourceProfiler* profiler = nullptr) {
        passes.push_back(new TypeChecking(refMap, typeMap));
        passes.push_back(new DoResourceEstimation(refMap, typeMap, profiler));
        setName("Resource Estimation");
    }
};

}  // namespace SV

#endif /* _BACKENDS_P4_RESOURCE_H_ */