#include "common.h"
#include "analyzer.h"
#include "lib/log.h"

namespace SV {

// ControlFlowGraph implementation

void ControlFlowGraph::addNode(const IR::Node* n) {
    if (nodeMap.find(n) == nodeMap.end()) {
        nodeMap[n] = new Node(n);
    }
}

void ControlFlowGraph::addEdge(const IR::Node* from, const IR::Node* to, cstring label) {
    addNode(from);
    addNode(to);
    auto edge = new Edge(nodeMap[to], label);
    nodeMap[from]->successors.push_back(edge);
}

bool ControlFlowGraph::checkForCycles() const {
    // TODO: Implement cycle detection
    return false;
}

// ControlGraphBuilder implementation

bool ControlGraphBuilder::preorder(const IR::BlockStatement* block) {
    LOG3("ControlGraphBuilder visiting block statement");
    // Process each statement in the block
    for (auto stmt : block->components) {
        visit(stmt);
    }
    return false;  // Already visited children
}

bool ControlGraphBuilder::preorder(const IR::IfStatement* stmt) {
    LOG3("ControlGraphBuilder visiting if statement");
    
    // Create a node for the if statement
    cfg->addNode(stmt);
    
    if (currentNode) {
        cfg->addEdge(currentNode->node, stmt, cstring(""));
    }
    
    // Create a dummy node for the if statement itself
    auto ifNode = new ControlFlowGraph::Node(stmt);
    
    // Visit then branch
    currentNode = ifNode;
    if (stmt->ifTrue) {
        visit(stmt->ifTrue);
    }
    
    // Visit else branch if it exists
    if (stmt->ifFalse) {
        currentNode = ifNode;
        visit(stmt->ifFalse);
    }
    
    return false;  // Already visited children
}

bool ControlGraphBuilder::preorder(const IR::MethodCallExpression* expr) {
    LOG3("ControlGraphBuilder visiting method call expression");
    
    // Check if this is a table apply
    if (expr->method->toString() == "apply") {
        cfg->addNode(expr);
        
        if (currentNode) {
            cfg->addEdge(currentNode->node, expr, cstring(""));
        }
        
        currentNode = cfg->nodeMap[expr];
    }
    
    return false;
}

bool ControlGraphBuilder::preorder(const IR::SwitchStatement* stmt) {
    LOG3("ControlGraphBuilder visiting switch statement");
    
    // Create a node for the switch
    cfg->addNode(stmt);
    
    if (currentNode) {
        cfg->addEdge(currentNode->node, stmt, cstring(""));
    }
    
    // Create node for the switch statement
    auto switchNode = new ControlFlowGraph::Node(stmt);
    
    // Visit each case
    for (auto switchCase : stmt->cases) {
        currentNode = switchNode;
        
        if (switchCase->statement) {
            // Add edge with case label
            cstring label = switchCase->label->toString();
            visit(switchCase->statement);
        }
    }
    
    return false;  // Already visited children
}

}  // namespace SV