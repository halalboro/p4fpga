#ifndef _BACKENDS_SV_ANALYZER_H_
#define _BACKENDS_SV_ANALYZER_H_

#include "common.h"
#include "ir/visitor.h"

namespace SV {

// Control Flow Graph for analyzing control blocks
class CFG {
public:
    class Node;
    
    class Edge {
    public:
        Node* endpoint;
        cstring label;  // Condition for this edge
        
        Edge(Node* n, cstring l) : endpoint(n), label(l) {}
    };
    
    class Node {
    public:
        const IR::Node* node;  // Can be table, action, or if statement
        std::vector<Edge*> successors;
        cstring name;
        
        explicit Node(const IR::Node* n) : node(n) {
            if (auto table = n->to<IR::P4Table>()) {
                name = table->name;  // Fixed: removed toString()
            } else if (auto action = n->to<IR::P4Action>()) {
                name = action->name;  // Fixed: removed toString()
            } else {
                name = cstring("node");  // Fixed: proper cstring construction
            }
        }
    };
    
    Node* entryNode = nullptr;
    Node* exitNode = nullptr;
    std::map<const IR::Node*, Node*> nodeMap;
    
    void addNode(const IR::Node* n);
    void addEdge(const IR::Node* from, const IR::Node* to, cstring label = cstring());
    bool checkForCycles() const;
    ~CFG();  // Destructor to clean up memory
};

// Visitor to build control flow graph
class ControlGraphBuilder : public Inspector {
public:
    CFG* cfg;
    CFG::Node* currentNode = nullptr;
    
    ControlGraphBuilder() {
        cfg = new CFG();
        setName("ControlGraphBuilder");
    }
    
    ~ControlGraphBuilder() {
        // Note: Don't delete cfg here as it's passed to the control
    }
    
    bool preorder(const IR::BlockStatement* block) override;
    bool preorder(const IR::IfStatement* stmt) override;
    bool preorder(const IR::MethodCallExpression* expr) override;
    bool preorder(const IR::SwitchStatement* stmt) override;
};

}  // namespace SV

#endif