# C++: 构造函数与析构函数

对象的**生命周期** (lifecycle) 包括创建、使用和销毁三个阶段。C++ 提供了两种特殊的成员函数来管理对象的生命周期：
- **构造函数 (Constructor)**: 在对象创建时自动被调用，用于初始化。
- **析构函数 (Destructor)**: 在对象销毁时自动被调用，用于清理。

## 1. 构造函数 (Constructor)

构造函数的主要任务是初始化对象的数据成员，确保对象在创建后立即可用，处于一个有效的状态。

**构造函数的特点:**
- 函数名与**类名完全相同**。
- **没有返回类型**，连 `void` 都没有。
- 在创建对象时自动被调用。
- 可以被重载（即一个类可以有多个不同参数的构造函数）。

### 默认构造函数

一个不接受任何参数的构造函数被称为**默认构造函数**。

```cpp
class Dog {
public:
    // 这是一个默认构造函数
    Dog() {
        name = "Unnamed";
        age = 0;
        std::cout << name << " has been created." << std::endl;
    }

    void bark() {
        std::cout << name << " says: Woof!" << std::endl;
    }
private:
    std::string name;
    int age;
};

int main() {
    Dog dog1; // 自动调用默认构造函数
    dog1.bark(); // 输出: Unnamed says: Woof!
    return 0;
}
```
**注意**: 如果你没有为类定义任何构造函数，编译器会自动为你生成一个公有的、空的默认构造函数。但只要你定义了**任何**一个构造函数，编译器就不再自动生成默认构造函数了。

### 带参数的构造函数

构造函数可以接受参数，从而在创建对象时就用指定的值来初始化它。

```cpp
class Rectangle {
public:
    // 带参数的构造函数
    Rectangle(double w, double h) {
        width = w;
        height = h;
    }
    
    double get_area() {
        return width * height;
    }
private:
    double width;
    double height;
};

int main() {
    // 创建对象时传递参数
    Rectangle rect1(10.0, 5.0);
    std::cout << "Area of rect1: " << rect1.get_area() << std::endl; // 输出: 50
    
    // Rectangle rect2; // 编译错误！因为定义了带参数的构造函数，
                      // 编译器不再提供默认构造函数。
}
```

### 成员初始化列表 (Member Initializer List)

C++ 提供了一种更推荐的初始化成员变量的方式：成员初始化列表。它在构造函数函数体执行**之前**执行，直接对成员进行**初始化**，而不是在函数体内进行**赋值**。

**语法:**
`Constructor(args) : member1(value1), member2(value2) { ... }`

**优点:**
- **效率更高**: 对于类类型的成员变量，直接初始化比先调用默认构造函数再赋值要高效。
- **必须使用**: 对于 `const` 成员和引用成员，它们必须在初始化列表中进行初始化，因为它们不能被赋值。

**示例:**
```cpp
class Rectangle {
public:
    // 使用成员初始化列表
    Rectangle(double w, double h) : width(w), height(h) {
        // 构造函数体可以是空的
        std::cout << "Rectangle created with width " << width << " and height " << height << std::endl;
    }
    
    double get_area() {
        return width * height;
    }
private:
    const double width; // const 成员
    const double height;
};
```

## 2. 析构函数 (Destructor)

析构函数在对象生命周期结束时（例如，函数返回导致栈上的对象被销毁，或者 `delete` 一个堆上的对象时）自动被调用。它的主要用途是执行清理工作，最常见的就是**释放对象在构造时或生命周期内动态分配的资源**。

**析构函数的特点:**
- 函数名是**类名前面加上一个波浪号 `~`**。
- **没有返回类型**，也没有参数。
- 一个类最多只能有一个析构函数。

**示例：使用析构函数释放内存**
```cpp
#include <iostream>

class DynamicArray {
public:
    // 构造函数: 分配动态内存
    DynamicArray(int size) : p_data(new int[size]), array_size(size) {
        std::cout << "Array of size " << size << " allocated." << std::endl;
    }

    // 析构函数: 释放动态内存
    ~DynamicArray() {
        std::cout << "Freeing array of size " << array_size << "." << std::endl;
        delete[] p_data; // 使用 delete[] 释放数组
        p_data = nullptr; // 好习惯
    }

private:
    int* p_data;
    int array_size;
};

void create_and_destroy() {
    std::cout << "Entering function." << std::endl;
    DynamicArray arr(10); // 构造函数被调用
    std::cout << "Leaving function." << std::endl;
} // 函数结束，arr 超出作用域，析构函数被自动调用

int main() {
    create_and_destroy();
    return 0;
}
```
**输出:**
```
Entering function.
Array of size 10 allocated.
Leaving function.
Freeing array of size 10.
```
这个例子清晰地展示了 RAII (Resource Acquisition Is Initialization，资源获取即初始化) 的思想，这是 C++ 中管理资源的核心模式。资源（如内存、文件句柄、网络连接）的生命周期与对象的生命周期绑定，构造函数获取资源，析构函数释放资源，从而大大减少了资源泄漏的风险。

---

掌握了对象的创建和销毁，我们就可以构建更复杂的对象关系了。下一步是学习面向对象的三大支柱之一：[继承](cpp-inheritance.md)。 