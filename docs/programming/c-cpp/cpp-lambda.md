# 现代 C++: Lambda 表达式

Lambda 表达式（Lambda Expression）是 C++11 引入的最重要和最受欢迎的特性之一。它允许我们在需要函数对象的地方，以内联（inline）的方式定义一个匿名的、可调用的对象。这极大地简化了代码，尤其是在与 STL 算法配合使用时。

## 什么是 Lambda？

简单来说，Lambda 表达式就是一种创建**匿名函数对象**的便捷语法。

在 C++11 之前，如果我们需要一个简单的、只用一次的函数（例如，作为 `std::sort` 的自定义比较器），我们通常需要：
1.  在全局或类作用域内定义一个完整的函数。
2.  或者定义一个函数对象（一个重载了 `operator()` 的类/结构体）。

这两种方式都比较繁琐，代码可读性也不高。Lambda 表达式解决了这个问题，让我们可以就地定义函数逻辑。

## Lambda 表达式的语法

一个完整的 Lambda 表达式看起来像这样：

```cpp
[capture-list](parameter-list) mutable -> return-type {
    // 函数体
}
```

-   **`[capture-list]` (捕获列表)**: 这是 Lambda 最核心的部分。它定义了 Lambda 如何从其所在的外部作用域"捕获"变量。
    -   `[]`: 不捕获任何外部变量。
    -   `[=]`: 按值（by value）捕获所有外部变量。在 Lambda 内部，这些变量是只读的副本。
    -   `[&]`: 按引用（by reference）捕获所有外部变量。在 Lambda 内部，可以修改这些变量。
    -   `[this]`: 捕获当前对象的 `this` 指针。
    -   `[a, &b]`: 精确指定捕获列表，`a` 按值捕获，`b` 按引用捕获。
    -   `[=, &b]`: 默认按值捕获，但 `b` 按引用捕获。
    -   `[&, a]`: 默认按引用捕获，但 `a` 按值捕获。

-   **`(parameter-list)` (参数列表)**: 与普通函数的参数列表相同。如果 Lambda 不需要参数，可以省略括号。

-   **`mutable` (可选)**: 默认情况下，按值捕获的变量在 Lambda 内部是 `const` 的。如果希望能修改这些值的副本（注意，不影响外部变量），需要使用 `mutable` 关键字。

-   **`-> return-type` (可选)**: 指定 Lambda 的返回类型。在大多数情况下，编译器可以自动推断返回类型，所以可以省略。只有当函数体有多个返回语句且类型不一致时，才需要显式指定。

-   **`{ function-body }` (函数体)**: Lambda 的具体执行代码，与普通函数体一样。

### 基础示例

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>

int main() {
    std::vector<int> numbers = {5, 2, 8, 1, 9};

    // 1. 基本排序
    std::sort(numbers.begin(), numbers.end()); // 默认升序

    // 2. 使用 Lambda 实现降序排序
    std::sort(numbers.begin(), numbers.end(), [](int a, int b) {
        return a > b; // 返回 true 表示 a 应该在 b 前面
    });

    for (int n : numbers) {
        std::cout << n << " ";
    }
    std::cout << std::endl; // 输出: 9 8 5 2 1

    // 3. 捕获外部变量
    int threshold = 5;
    // 按值捕获 threshold
    int count = std::count_if(numbers.begin(), numbers.end(), [threshold](int n) {
        return n > threshold;
    });
    std::cout << "Numbers greater than " << threshold << ": " << count << std::endl; // 输出: 3

    // 4. 按引用捕获并修改外部变量
    int sum = 0;
    // 按引用捕获 sum
    std::for_each(numbers.begin(), numbers.end(), [&sum](int n) {
        sum += n;
    });
    std::cout << "Sum: " << sum << std::endl; // 输出: 25

    return 0;
}
```

## 泛型 Lambda (C++14)

从 C++14 开始，Lambda 的参数可以使用 `auto` 关键字，这使得我们可以定义**泛型 Lambda**，它可以处理不同类型的参数。

```cpp
#include <iostream>

int main() {
    auto add = [](auto a, auto b) {
        return a + b;
    };

    std::cout << add(5, 3) << std::endl;       // 输出: 8
    std::cout << add(1.5, 2.5) << std::endl;    // 输出: 4
    std::cout << add(std::string("hello"), std::string(" world")) << std::endl; // 输出: hello world

    return 0;
}
```

## Lambda 的本质

在底层，编译器会将 Lambda 表达式转换成一个唯一的、匿名的函数对象类。例如，这样一个 Lambda：

```cpp
int x = 10;
auto my_lambda = [x](int y) { return x + y; };
```

大致会被编译器翻译成类似这样的东西：

```cpp
class __Lambda_xyz_ {
private:
    const int x; // 按值捕获的变量成为类的成员

public:
    __Lambda_xyz_(int val) : x(val) {}

    // operator() 被重载，使其可调用
    int operator()(int y) const {
        return x + y;
    }
};

int x = 10;
auto my_lambda = __Lambda_xyz_(x);
```
理解这一点有助于我们明白捕获列表的工作原理：捕获的变量实际上是作为构造函数的参数传递给了这个匿名类的实例。

## 总结

Lambda 表达式是现代 C++ 中一个极其强大的工具：
- **简洁性**: 让我们能就地编写简短的函数逻辑，提高代码的可读性和紧凑性。
- **与 STL 的完美结合**: 是 `std::sort`, `std::find_if`, `std::for_each` 等算法的理想伴侣。
- **闭包**: 通过捕获列表，Lambda 可以"封闭"其创建时的上下文环境，这是一种称为"闭包"（Closure）的强大编程概念。
- **灵活性**: 泛型 Lambda 进一步增强了其通用性。

掌握 Lambda 是精通现代 C++ 的关键一步。 