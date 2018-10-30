//
// Implementation some of algorithms related to Trees and Graphs
// to learn C++.
//
// Author : icecube27
//

#include <iostream>
#include <vector>

namespace i27_cci {

  //
  // Tree node class implementation
  //
  class Node {
    private:
      static int global_index;

    public:
      int index;
      std::vector<Node*> children;

      Node() {
	index = global_index++;
      }

      // 
      // Add a children to a node
      //
      void add_children(Node* t_node) {

	// The node cannot be his own child
	if (t_node->index == index)
	  return;

	// The node cannot have to same children
	bool is_children = false;
	for (Node* n : children) {
	  if (n->index == t_node->index) {
	    is_children = true;
	    break;
	  }
	}

	if (is_children)
	  return;

	children.push_back(t_node);
      }

      //
      // Print information about a node
      //
      void print_info() {
	printf("Node %d:\n", index);
	for (Node* n: children) {
	  printf("  - Node %d\n", n->index);
	}
      }
  };

  // 
  // Generate a random graph containing n nodes
  // 
  std::vector<Node*> generate_random_graph(const int n) {
    std::vector<Node*> node_vector;

    for (int i = 0; i < n; i++) {
      node_vector.push_back(new Node());
    }

    std::srand(time(0));
    for (int i = 0; i < n; i++) {
      for (int j = 0; j < rand() % n; j++) {
	node_vector[i]->add_children(node_vector[rand() % n]);
      }
    }

    return node_vector;
  }

  // 
  // List the elements reachable from the given node using a DFS search
  //
  void list_dfs_recursive(Node* t_node, std::vector<int>& visited) {
    // Check if the node has already been visited
    for (int i : visited) {
      if (t_node->index == i)
	return;
    }

    // Print the information about the current node
    printf("Node %d\n", t_node->index);
    visited.push_back(t_node->index);

    // Visit the children
    for (Node* n : t_node->children) {
      list_dfs_recursive(n, visited);
    }
  }

  void list_dfs(Node* t_node) {
    std::vector<int> visited;
    list_dfs_recursive(t_node, visited);
  }
}

// Init the static variable i27_cci::Node::global_index
int i27_cci::Node::global_index = 0;

//
// Main function
//
int main(int argc, char* argv[]) {
  using namespace i27_cci;

  puts("[+] Generating and printing a graph:");
  std::vector<Node*> node_vector = generate_random_graph(10);
  for (Node* n: node_vector) {
    n->print_info();
  }

  puts("[+] Displaying graph using DFS from node 0:");
  list_dfs(node_vector[0]);

  return 0;
}
