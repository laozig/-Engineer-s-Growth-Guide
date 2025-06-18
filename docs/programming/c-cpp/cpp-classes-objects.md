# C++: 类与对象

**类 (Class)** 是 C++ 面向对象编程 (Object-Oriented Programming, OOP) 的核心概念。它是一种用户自定义的类型，用于将**数据 (属性)** 和**操作这些数据的函数 (方法)** 捆绑在一起。

**对象 (Object)** 则是类的一个具体**实例 (instance)**。如果说 `class` 是一个"汽车"的设计蓝图，那么 `object` 就是根据这个蓝图制造出来的每一辆具体的"汽车"。

面向对象编程的核心思想是**封装 (Encapsulation)**、**继承 (Inheritance)** 和 **多态 (Polymorphism)**。本章我们首先关注封装。

## 1. 封装 (Encapsulation)

封装是将数据（成员变量）和操作这些数据的方法（成员函数）包装在一个单元（即类）中的机制。同时，通过访问控制，向外部隐藏对象工作的内部细节，只暴露必要的接口。这可以防止外部代码随意修改对象的内部状态，从而提高代码的安全性和可维护性。

## 2. 定义一个类

使用 `class` 关键字来定义一个类。

**语法:**
```cpp
class ClassName {
public:
    // 公有成员 (方法和属性)，外部可以访问
    // ...

private:
    // 私有成员 (方法和属性)，只能被类内部的成员函数访问
    // ...
}; // 注意：类定义末尾必须有分号
```

### 访问修饰符 (Access Specifiers)

- **`public`**: 公有成员。可以在类的外部被直接访问。它们构成了类的"接口"。
- **`private`**: 私有成员。只能被同一个类中的成员函数访问。它们是类的"内部实现细节"。默认情况下，类中的所有成员都是 `private` 的。
- **`protected`**: 保护成员。与 `private` 类似，但允许子类访问。这将在继承的章节中详细讨论。

**示例：定义一个 `Dog` 类**
```cpp
#include <iostream>
#include <string>

class Dog {
public:
    // 公有成员函数 (方法)，作为外部接口
    void set_name(std::string new_name) {
        // 成员函数可以访问私有成员
        name = new_name;
    }

    void bark() {
        std::cout << name << " says: Woof!" << std::endl;
    }
    
    int get_age() {
        return age;
    }
    
    void set_age(int new_age) {
        if (new_age > 0 && new_age < 30) {
            age = new_age;
        }
    }

private:
    // 私有成员变量 (属性)，被保护起来
    std::string name;
    int age;
};
```
在这个例子中，`name` 和 `age` 是私有的。外部代码不能直接修改它们，必须通过公有的 `set_name` 和 `set_age` 方法。`set_age` 方法还增加了一个有效性检查，这就是封装带来的好处：我们可以控制数据如何被修改。

## 3. 创建和使用对象

创建类的对象（实例化）就像声明一个普通变量一样。

```cpp
int main() {
    // 1. 创建一个 Dog 类的对象 my_dog
    Dog my_dog; 
    
    // 2. 使用点运算符 . 调用公有成员函数
    my_dog.set_name("Rex");
    my_dog.set_age(5);

    // 调用 bark 方法
    my_dog.bark(); // 输出: Rex says: Woof!

    // 读取年龄
    std::cout << "Rex's age is: " << my_dog.get_age() << std::endl; // 输出: 5

    // 下面的代码会产生编译错误，因为 name 和 age 是 private 的
    // my_dog.name = "Buddy"; // 错误!
    // int dog_age = my_dog.age; // 错误!

    return 0;
}
```

## 4. 将成员函数的实现分离

为了让类的定义更清晰，通常的做法是在类的定义中只保留函数的**声明**，而将函数的**实现**放在类的外部。这时，需要使用**作用域解析运算符 `::`** 来指明这个函数属于哪个类。

**头文件 (`Dog.h`)**
```cpp
#ifndef DOG_H
#define DOG_H

#include <string>

class Dog {
public:
    void set_name(std::string new_name);
    void bark();
    int get_age();
    void set_age(int new_age);

private:
    std::string name;
    int age;
};

#endif
```

**实现文件 (`Dog.cpp`)**
```cpp
#include "Dog.h" // 包含类的定义
#include <iostream>

// 使用 ClassName:: 来实现成员函数
void Dog::set_name(std::string new_name) {
    name = new_name;
}

void Dog::bark() {
    std::cout << name << " says: Woof!" << std::endl;
}

int Dog::get_age() {
    return age;
}

void Dog::set_age(int new_age) {
    if (new_age > 0 && new_age < 30) {
        age = new_age;
    }
}
```
这种将声明和实现分离的方式是 C++ 项目的标准实践。

---

我们已经了解了如何定义一个类并将其实例化为对象。但是，当一个对象被创建时，我们如何确保它处于一个有效的初始状态呢？这就是下一章要解决的问题：[构造函数与析构函数](cpp-constructors-destructors.md)。 