# 现代 C++: 新特性概览

除了智能指针和 Lambda 表达式，C++11、C++14、C++17 和 C++20 等现代标准还引入了大量其他重要特性，它们共同提升了 C++ 的开发效率、代码质量和语言表达能力。本节将概览其中一些关键的新特性。

## 1. `auto` 类型推导

`auto` 关键字指示编译器在编译时自动推断变量的类型。这可以极大地简化代码，尤其是在处理复杂的模板类型或迭代器时。

```cpp
#include <vector>
#include <string>
#include <map>

int main() {
    // 简化变量声明
    auto i = 42; // i 是 int
    auto d = 3.14; // d 是 double
    auto s = std::string("hello"); // s 是 std::string

    // 简化迭代器声明
    std::map<std::string, int> my_map;
    // 旧式写法
    // std::map<std::string, int>::iterator it = my_map.begin();
    // 使用 auto
    auto it = my_map.begin();
}
```

## 2. 基于范围的 `for` 循环 (Range-Based `for` Loop)

这是一种更简洁、更不易出错的遍历容器或序列的方式。它隐藏了迭代器的细节，使代码意图更清晰。

```cpp
#include <iostream>
#include <vector>
#include <map>

int main() {
    std::vector<int> numbers = {1, 2, 3, 4, 5};
    for (int n : numbers) {
        std::cout << n << " ";
    }
    std::cout << std::endl;

    std::map<int, std::string> student_map = {{1, "Alice"}, {2, "Bob"}};
    for (const auto& pair : student_map) {
        std::cout << "ID: " << pair.first << ", Name: " << pair.second << std::endl;
    }
}
```

## 3. `nullptr`

在 C++11 之前，空指针通常用 `0` 或 `NULL` 宏表示。`NULL` 本质上是 `0`，这会导致一些类型不明确的问题，尤其是在函数重载时。`nullptr` 是一个类型安全的空指针常量，其类型为 `std::nullptr_t`，可以明确地与整数 `0` 区分开。

```cpp
void func(int n) {}
void func(char* s) {}

int main() {
    // func(NULL); // 可能会有歧义，通常会调用 func(int)
    func(nullptr); // 明确调用 func(char*)
    return 0;
}
```

## 4. 移动语义 (Move Semantics) 和右值引用 (Rvalue References)

这是 C++11 中最深刻的变革之一。通过引入**右值引用**（以 `&&` 表示），C++ 能够区分**左值**（有持久身份的对象）和**右值**（临时的、即将销毁的对象）。

**移动语义**允许我们"窃取"右值对象的资源（如动态分配的内存、文件句柄等），而不是进行昂贵的复制。这极大地提升了涉及临时对象的性能。`std::move` 函数可以将一个左值强制转换为右值引用，从而触发移动操作。

```cpp
#include <vector>
#include <string>

int main() {
    std::string str1 = "this is a very long string";
    std::string str2;

    // 传统复制：会分配新内存并复制所有字符
    // str2 = str1; 

    // 移动：str2 直接接管 str1 内部的内存，str1 变为空。
    // 这是一个非常高效的操作。
    str2 = std::move(str1);

    // str1 现在处于一个有效的、但未指定的状态（通常是空的）

    std::vector<int> vec1 = {1, 2, 3};
    std::vector<int> vec2 = std::move(vec1); // vec2 接管 vec1 的数据
    return 0;
}
```
`unique_ptr` 的实现就完全依赖于移动语义。

## 5. `override` 和 `final`

这两个关键字用于控制虚函数的行为，提高代码的清晰度和安全性。

-   **`override`**: 明确指出一个成员函数意在覆盖（override）基类中的一个虚函数。如果基类中没有对应的虚函数，编译器会报错。这可以防止因函数签名不匹配而导致的意外错误。
-   **`final`**: 指定一个虚函数不能在派生类中被进一步覆盖，或者指定一个类不能被继承。

```cpp
class Base {
public:
    virtual void do_work() {}
    virtual void do_something() {}
};

class Derived : public Base {
public:
    // 明确覆盖，如果 Base::do_work 的签名改变，这里会编译失败
    void do_work() override {} 

    // virtual void do_work(int) override; // 错误：签名不匹配，无法覆盖

    // 这个函数不能在 Derived 的派生类中再被覆盖
    void do_something() final {} 
};

class FinalDerived final : public Derived {
    // void do_something() override {} // 错误：do_something 在 Derived 中是 final 的
};

// class MoreDerived : FinalDerived {}; // 错误：FinalDerived 是 final 类，不能被继承
```

## 6. 强类型枚举 (Strongly-Typed Enums)

传统的 C++ 枚举存在一些问题：它们的枚举值会泄漏到外部作用域，并且可以隐式地转换为整数。C++11 引入了 `enum class`（或 `enum struct`）来解决这些问题。

```cpp
// 传统枚举
enum Color { RED, GREEN, BLUE }; 
// int x = RED; // 隐式转换为 int
// enum Stoplight { RED, YELLOW, GREEN }; // 错误：RED 重定义

// 强类型枚举
enum class NewColor { RED, GREEN, BLUE };
// int y = NewColor::RED; // 错误：不能隐式转换为 int
// auto color_val = static_cast<int>(NewColor::RED); // 必须显式转换

enum class NewStoplight { RED, YELLOW, GREEN }; // OK：枚举值被限定在类作用域内

int main() {
    NewColor c = NewColor::RED;
    if (c == NewColor::RED) {
        // ...
    }
}
```

## 7. `std::thread` 和并发 API

C++11 在标准库层面提供了对多线程编程的支持，位于 `<thread>`, `<mutex>`, `<condition_variable>`, `<future>` 等头文件中。这使得编写跨平台的并发程序变得标准化。

## 总结

现代 C++ 的这些新特性（以及更多未提及的）共同构成了一个更加强大、安全和易用的编程语言。熟练运用这些特性是每一位现代 C++ 开发者的必备技能。 