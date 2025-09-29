#include "common.h"
#include "analyzer.h"
#include "lib/log.h"

namespace SV {

// CFG Implementation
void CFG::addNode(const IR::Node* n) {
    if (nodeMap.find(n) == nodeMap.end()) {
        nodeMap[n] = new Node(n);
    }
}

void CFG::addEdge(const IR::Node* from, const IR::Node* to, cstring label) {
    addNode(from);
    addNode(to);
    auto edge = new Edge(nodeMap[to], label);
    nodeMap[from]->successors.push_back(edge);
}

bool CFG::checkForCycles() const {
    // Simplified cycle detection - would need DFS in production
    return false;
}

CFG::~CFG() {
    // Clean up allocated memory
    for (auto& pair : nodeMap) {
        for (auto edge : pair.second->successors) {
            delete edge;
        }
        delete pair.second;
    }
}

// ControlGraphBuilder Implementation
bool ControlGraphBuilder::preorder(const IR::BlockStatement* block) {
    LOG3("CFG: Processing block statement");
    
    // Process each statement in the block
    for (auto stmt : block->components) {
        visit(stmt);
    }
    
    return false;  // Don't visit children again
}

bool ControlGraphBuilder::preorder(const IR::IfStatement* stmt) {
    LOG3("CFG: Processing if statement");
    
    // Create nodes for then/else branches
    auto ifNode = new CFG::Node(stmt);
    cfg->addNode(stmt);
    
    if (currentNode) {
        cfg->addEdge(currentNode->node, stmt, cstring("condition"));  // Fixed: proper cstring
    }
    
    // Process then branch
    auto savedNode = currentNode;
    currentNode = ifNode;
    visit(stmt->ifTrue);
    
    // Process else branch if exists
    if (stmt->ifFalse) {
        currentNode = ifNode;
        visit(stmt->ifFalse);
    }
    
    currentNode = savedNode;
    return false;
}

bool ControlGraphBuilder::preorder(const IR::MethodCallExpression* expr) {
    std::string methodName = expr->method->toString().string();  // Get as std::string
    LOG3("CFG: Processing method call: " << methodName);
    
    // Track table apply() calls
    if (methodName.find("apply") != std::string::npos) {  // Fixed: use std::string methods
        cfg->addNode(expr);
        if (currentNode) {
            cfg->addEdge(currentNode->node, expr, cstring("apply"));  // Fixed: proper cstring
        }
        currentNode = cfg->nodeMap[expr];
    }
    
    return false;
}

bool ControlGraphBuilder::preorder(const IR::SwitchStatement* stmt) {
    LOG3("CFG: Processing switch statement");
    
    auto switchNode = new CFG::Node(stmt);
    cfg->addNode(stmt);
    
    if (currentNode) {
        cfg->addEdge(currentNode->node, stmt, cstring("switch"));  // Fixed: proper cstring
    }
    
    // Process each case
    for (auto switchCase : stmt->cases) {
        auto savedNode = currentNode;
        currentNode = switchNode;
        if (switchCase->statement) {
            visit(switchCase->statement);
        }
        currentNode = savedNode;
    }
    
    return false;
}

}  // namespace SV