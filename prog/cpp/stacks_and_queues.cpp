//
// Implementation some of algorithms related to Stacks and Queues
// to learn C++.
//
// Author : icecube27
//

#include <iostream>

namespace i27_cci {

  // 
  // Node class implementation
  //
  class Node {
    public:
      int value;
      Node* next = nullptr;

      Node(int t_value) : value(t_value) {}
      ~Node() {}
  };

  //
  // Stack class implementation
  //
  class Stack {
    private:
      Node* m_top = nullptr;
      int length = 0;

    public:
      // Default constructor
      Stack() {}

      // Default destructor
      ~Stack() {
	if (!isempty()) delete m_top;
      }

      // Returns True if the stack is empty, else False
      bool isempty() {
	return m_top == nullptr;
      }

      // Pop an element from the stack
      Node* pop() {
	if (isempty()) {
	  return nullptr; // if the stack is empty
	} else {
	  Node* tmp_node = m_top;
	  m_top = m_top->next;
	  return tmp_node;
	} 
      }

      // Push an element on the stack
      void push(Node* t_node) {
	if (isempty()) {
	  t_node->next = nullptr;
	  m_top = t_node;
	} else {
	  t_node->next = m_top;
	  m_top = t_node;
	}
      }

      // Get the top element from the stack
      Node* peek() {
	return m_top;
      }
  };

  //
  // Queue class implement (from two Stacks)
  //
  class QueueStack {
    private:
      Stack* m_s1 = nullptr;
      Stack* m_s2 = nullptr;

    public:
      // Default constructor
      QueueStack() {
	m_s1 = new Stack();
	m_s2 = new Stack();
      }

      // Default destructor
      ~QueueStack() {
	if (!isempty()) {
	  delete m_s1;
	  delete m_s2;
	}
      }

      // Return True is the queue is empty, else False
      bool isempty() {
	return m_s1->isempty();
      }

      // Add an element in the queue
      void add(Node *t_node) {
	if (m_s1 == nullptr) {
	  m_s1->push(t_node);
	} else {
	  // Transfert the elements from the main stack to the second stack
	  while (!m_s1->isempty()) {
	    m_s2->push(m_s1->pop());
	  }

	  // Insert the new element into the main stack
	  m_s1->push(t_node);

	  // Re-transfert the elements from the second stack to the main stack
	  while (!m_s2->isempty()) {
	    m_s1->push(m_s2->pop());
	  }
	}
      }

      // Remove on element from the queue
      void remove() {
	m_s1->pop();
      }

      // Return the first element of the queue
      Node* peek() {
	return m_s1->pop();
      }
  };

  class LinkedStack {
    public:
      Stack* stack = nullptr;
      LinkedStack* next = nullptr;
      unsigned int m_size = 0;
      unsigned int m_num = 0;

      LinkedStack() {
	stack = new Stack();
      }	

      LinkedStack(LinkedStack* t_next) 
	: next(t_next)
      {
	stack = new Stack();
	m_num = t_next->m_num + 1;
      }
  };

  //
  // SetOfStacks class implementation
  //
  class SetOfStacks {
    private:
      LinkedStack* m_linked_stack = nullptr;
      static const unsigned int MAX_ELEMENTS = 10;

    public:
      SetOfStacks() {
	m_linked_stack = new LinkedStack();
      }

      ~SetOfStacks() {
	if (m_linked_stack) delete m_linked_stack;
      }

      bool isempty() {
	return (m_linked_stack->stack->isempty() && m_linked_stack->next == nullptr);
      }

      void push(Node* t_node) {
	// If the number of elements is too big to fit in a stack
	if (MAX_ELEMENTS <= m_linked_stack->m_size) {
	  LinkedStack* new_linked_stack = new LinkedStack(m_linked_stack);
	  m_linked_stack = new_linked_stack;
	}

	m_linked_stack->stack->push(t_node);
	++m_linked_stack->m_size;
      }

      Node* pop() {
	if (m_linked_stack == nullptr) {
	  return nullptr;
	} else {
	  // If current stack is empty
	  if (m_linked_stack->m_size == 0) {
	   
	    // If there is a next stack
	    if (m_linked_stack->next) {
	      LinkedStack* old_linked_stack = m_linked_stack;

	      m_linked_stack = m_linked_stack->next;
	      --m_linked_stack->m_size;
	      delete old_linked_stack;
	      return m_linked_stack->stack->pop();
	    } else {
	      return nullptr;
	    }
	  } else {
	    --m_linked_stack->m_size;
	    return m_linked_stack->stack->pop();
	  }
	}
      }
  };

  // 
  // Generate a stack filled with n random elements
  //
  Stack* generate_random_stack(const int n) {
    Stack* stack = new Stack();

    if (!stack) {
      printf("[error] Stack()");
      exit(-1);
    }

    std::srand(time(0));

    for (int i = 0; i < n; i++) {
      stack->push(new Node(rand() % 1000));
    }

    return stack;
  }

  // 
  // Pop an print all the elements from a stack
  //
  void pop_and_print_stack(Stack* stack) {
    printf("Printing stack elements:\n");

    while (!stack->isempty()) {
      printf("%d ", stack->pop()->value);
    }

    puts("");
  }

  // 
  // Sort the given stack
  //
  void sort_stack(Stack* stack) {
    Stack* tmp_stack = new Stack();
    int count;

    if (!stack) {
      printf("[error] Stack()");
      exit(-1);
    }

    // Count the number of element
    count = 0;
    while (!stack->isempty()) {
      tmp_stack->push(stack->pop());
      ++count;
    }

    // Reset the stack in its initial state
    while (!tmp_stack->isempty()) stack->push(tmp_stack->pop());

    for (int i = count; i > 0; --i) {
      Node* max_node = nullptr;
      Node* current_node = nullptr;

      for (int j = 0; j < i; ++j) {
        current_node = stack->pop();

	if (max_node == nullptr) {
          max_node = current_node;
	} else {

	  // If the max value or first value is found
          if (max_node->value < current_node->value) {
	    tmp_stack->push(max_node);
	    max_node = current_node;
	  } else {
	    tmp_stack->push(current_node);
	  }
	}
      }

      // Once the max of the remaining value is found it is push on the stack
      stack->push(max_node);

      while (!tmp_stack->isempty()) stack->push(tmp_stack->pop());
    }
  }

  // 
  // Generate a queue filled with n random elements
  //
  QueueStack* generate_random_queue(const int n) {
    QueueStack* queue = new QueueStack();

    if (!queue) {
      printf("[error] QueueStack()\n");
      exit(-1);
    }

    std::srand(time(0));

    for (int i = 0; i < n; i++) {
      queue->add(new Node(rand() % 1000));
    }

    return queue;
  }

  // 
  // Pop and print all the elements from a queue
  //
  void pop_and_print_queue(QueueStack* queue) {
    printf("Printing queue elements:\n");

    while (!queue->isempty()) {
      printf("%d ", queue->peek()->value);
    }

    puts("");
  }

  // 
  // Generate a set of stack filled with n random elements
  //
  template<typename T>
  T* generate_random_xstack(const int n) {
    T* e = new T();

    if (!e) {
      printf("[error] ()\n");
      exit(-1);
    }

    std::srand(time(0));

    for (int i = 0; i < n; i++) {
      e->push(new Node(rand() % 1000));
    }

    return e;
  }

  // 
  // Pop and print all the elements from a xxx
  //
  template<typename T>
  void pop_and_print(T* e) {
    printf("Printing set of %s elements:\n", typeid(e).name());

    while (!e->isempty()) {
      printf("%d ", e->pop()->value);
    }

    puts("");
  }
}

//
// Main function
//
int main(int argc, char* argv[]) {
  using namespace i27_cci;

  // Test the stack functions
  //Stack* stack = generate_random_stack(10);
  Stack* stack = generate_random_xstack<Stack>(10);
  sort_stack(stack);
  pop_and_print(stack);
  //pop_and_print_stack(stack);

  // Test the queue functions
  QueueStack* queue = generate_random_queue(10);
  pop_and_print_queue(queue);

  // Test the set of stack functions
  //SetOfStacks* setofstacks = generate_random_setofstack(10);
  SetOfStacks* setofstacks = generate_random_xstack<SetOfStacks>(10);
  pop_and_print(setofstacks);
  //pop_and_print_setofstack(setofstacks);

  return 0;
}
