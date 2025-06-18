# C++: 模板 (Templates)

**泛型编程 (Generic Programming)** 是 C++ 的另一大支柱（与过程式编程、面向对象编程并列）。其核心思想是编写**与类型无关**的代码。你只需要编写一次算法或数据结构，就可以将其应用于任何符合要求的类型，而无需为每种类型都重写一遍。

C++ 通过**模板 (Templates)** 来实现泛型编程。模板是创建通用函数和通用类的蓝图。

## 1. 函数模板 (Function Templates)

假设你需要一个函数来交换两个变量的值。你可能需要为 `int`, `double`, `std::string` 等多种类型分别编写一个 `swap` 函数，像这样：

```cpp
void swap_int(int& a, int& b) { /* ... */ }
void swap_double(double& a, double& b) { /* ... */ }
// ...
```
这显然非常繁琐。函数模板解决了这个问题。

**语法:**
```cpp
template <typename T>
// or template <class T>
// 'typename' 和 'class' 在这里是等价的
return-type function_name(parameters) {
    // 函数体，可以使用类型 T
}
```
- `template <typename T>`: 模板参数声明。`T` 是一个占位符，代表一个任意的类型。你也可以用其他名字，但 `T` 是一个惯例。

**示例：一个通用的 `swap` 函数模板**
```cpp
#include <iostream>
#include <string>

template <typename T>
void swap_generic(T& a, T& b) {
    T temp = a;
    a = b;
    b = temp;
}

int main() {
    int x = 5, y = 10;
    swap_generic(x, y);
    std::cout << "x: " << x << ", y: " << y << std::endl; // 输出: x: 10, y: 5

    double d1 = 3.14, d2 = 6.28;
    swap_generic(d1, d2);
    std::cout << "d1: " << d1 << ", d2: " << d2 << std::endl; // 输出: d1: 6.28, d2: 3.14

    std::string s1 = "Hello", s2 = "World";
    swap_generic(s1, s2);
    std::cout << "s1: " << s1 << ", s2: " << s2 << std::endl; // 输出: s1: World, s2: Hello

    return 0;
}
```

### 模板实例化 (Instantiation)

当你用具体类型（如 `int`）调用一个函数模板时，编译器会根据模板为你**自动生成**一个该类型的函数版本。这个过程称为**模板实例化**。例如，当你调用 `swap_generic(x, y)` 时，编译器会生成一个 `swap_generic<int>` 的实例。

## 2. 类模板 (Class Templates)

与函数模板类似，类模板允许我们定义一个通用的类，其成员变量和成员函数的类型可以在创建类的对象时指定。标准模板库 (STL) 中的所有容器，如 `vector`, `map`, `list`，都是类模板。

**语法:**
```cpp
template <typename T>
class ClassName {
    // 类的定义，可以使用类型 T
private:
    T member;
};
```

**示例：一个简单的 `Stack` 类模板**
```cpp
#include <iostream>
#include <vector>
#include <stdexcept>

template <typename T>
class Stack {
public:
    void push(const T& item) {
        elements.push_back(item);
    }

    void pop() {
        if (is_empty()) {
            throw std::out_of_range("Stack is empty");
        }
        elements.pop_back();
    }

    T& top() {
        if (is_empty()) {
            throw std::out_of_range("Stack is empty");
        }
        return elements.back();
    }

    bool is_empty() const {
        return elements.empty();
    }

private:
    std::vector<T> elements;
};

int main() {
    // 实例化一个存储 int 的栈
    Stack<int> int_stack;
    int_stack.push(10);
    int_stack.push(20);
    std::cout << "Top of int_stack: " << int_stack.top() << std::endl; // 20
    int_stack.pop();
    std::cout << "Top of int_stack after pop: " << int_stack.top() << std::endl; // 10

    // 实例化一个存储 std::string 的栈
    Stack<std::string> string_stack;
    string_stack.push("Hello");
    string_stack.push("World");
    std::cout << "Top of string_stack: " << string_stack.top() << std::endl; // World

    return 0;
}
```

### 模板参数

模板可以接受多种类型的参数：
- **类型模板参数**: `template <typename T, typename U>`
- **非类型模板参数**: 可以是整数、指针、引用等。例如，标准库中的 `std::array` 就接受一个非类型模板参数来指定数组大小。
  `template <typename T, std::size_t N> class array;`

### 模板与头文件

由于模板是在**编译时**进行实例化的，编译器在实例化模板时需要看到模板的**完整定义**（而不仅仅是声明）。因此，模板的声明和实现**通常都放在头文件 (`.h` 或 `.hpp`) 中**，而不是像普通函数那样将实现放在 `.cpp` 文件中。

---

模板是 C++ 泛型编程的基石，它使得编写高度可复用和类型安全的代码成为可能。STL 的强大威力完全建立在模板之上。接下来，我们将正式介绍 [STL 简介](cpp-stl-introduction.md)。 