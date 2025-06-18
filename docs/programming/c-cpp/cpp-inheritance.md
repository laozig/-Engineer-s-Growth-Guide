# C++: 继承

继承 (Inheritance) 是面向对象编程的三大支柱之一（另外两个是封装和多态）。它允许我们创建一个新类（称为**子类**或**派生类**），该类可以获取一个已存在类（称为**基类**或**父类**）的属性和方法。

继承的核心思想是**代码复用**和建立**"是一个"(is-a)** 的关系。例如，`Dog` **是一个** `Animal`，`Car` **是一个** `Vehicle`。子类继承了基类的通用特性，并可以添加自己独有的特性或修改继承来的行为。

## 1. 定义派生类

**语法:**
```cpp
class BaseClass {
    // ...
};

class DerivedClass : access-specifier BaseClass {
    // ...
};
```
- **`DerivedClass`**: 派生类/子类
- **`BaseClass`**: 基类/父类
- **`access-specifier`**: 继承类型，可以是 `public`, `protected`, `private`。它决定了基类的成员在派生类中的访问级别。最常用的是 `public` 继承。

## 2. `public` 继承

`public` 继承建立了最直接的 "is-a" 关系。当使用 `public` 继承时：
- 基类的 `public` 成员在派生类中仍然是 `public`。
- 基类的 `protected` 成员在派生类中仍然是 `protected`。
- 基类的 `private` 成员**不能**被派生类直接访问。

**示例：`Animal` 和 `Dog`**
```cpp
#include <iostream>
#include <string>

// 基类 (Base Class)
class Animal {
public:
    Animal(std::string name) : name(name) {}

    void eat() {
        std::cout << name << " is eating." << std::endl;
    }
    void sleep() {
        std::cout << name << " is sleeping." << std::endl;
    }

protected:
    // Protected 成员可以被子类访问，但不能被外部访问
    std::string name;
};

// 派生类 (Derived Class)
class Dog : public Animal {
public:
    // 子类构造函数
    Dog(std::string name, std::string breed) 
        : Animal(name), breed(breed) {} // 调用基类的构造函数

    void bark() {
        // 子类可以访问基类的 protected 成员
        std::cout << name << " the " << breed << " says: Woof!" << std::endl;
    }

private:
    std::string breed; // 子类自己的成员
};

int main() {
    // 创建派生类对象
    Dog my_dog("Rex", "German Shepherd");

    // 调用从基类继承来的方法
    my_dog.eat();   // 输出: Rex is eating.
    my_dog.sleep(); // 输出: Rex is sleeping.

    // 调用派生类自己的方法
    my_dog.bark();  // 输出: Rex the German Shepherd says: Woof!

    // std::cout << my_dog.name; // 编译错误！name 在 Animal 中是 protected，
                               // 在 main 函数中（外部）无法访问。
    return 0;
}
```

## 3. 子类构造函数与基类构造函数

子类**不能**直接初始化从基类继承来的 `private` 或 `protected` 成员。初始化基类部分的任务必须由**基类的构造函数**来完成。

因此，子类的构造函数需要通过**成员初始化列表**来调用基类的构造函数，并将必要的参数传递给它。

`Dog(std::string name, std::string breed) : Animal(name), breed(breed) {}`

- `: Animal(name)`: 这部分明确地调用了 `Animal` 类的构造函数，并把 `name` 传递过去。
- `, breed(breed)`: 这部分初始化 `Dog` 类自己的成员 `breed`。

**构造顺序**: 当创建派生类对象时，会先调用**基类的构造函数**，然后再调用**派生类的构造函数**。
**析构顺序**: 对象销毁时则相反，先调用**派生类的析构函数**，再调用**基类的析构函数**。

## 4. `protected` 和 `private` 继承

除了 `public` 继承，还有 `protected` 和 `private` 继承，它们不太常用，主要用于实现一些特殊的设计模式。

- **`protected` 继承**: 基类的 `public` 和 `protected` 成员在派生类中都变成 `protected`。
- **`private` 继承**: 基类的 `public` 和 `protected` 成员在派生类中都变成 `private`。

这两种继承方式破坏了 "is-a" 关系，通常被看作是"**用......来实现**"(is-implemented-in-terms-of) 的关系。在现代 C++ 中，这种关系通常更倾向于使用**组合 (Composition)** 而非继承来实现。

## 5. 多重继承

C++ 允许一个派生类同时从多个基类继承。

**语法:**
```cpp
class Derived : public Base1, public Base2 {
    // ...
};
```
多重继承非常强大，但也可能导致一些复杂的问题，最著名的就是**菱形问题 (Diamond Problem)**。当一个类从两个（或更多）拥有共同基类的类继承时，就会出现菱形问题，导致派生类中存在共同基类的多个实例。这个问题可以通过**虚继承 (virtual inheritance)** 来解决。

由于其复杂性，许多现代 C++ 编程指南建议谨慎使用多重继承，优先考虑单继承和组合。

---

继承建立了类之间的层次关系，但要完全发挥其威力，还需要面向对象的第三大支柱：[多态](cpp-polymorphism.md)。 