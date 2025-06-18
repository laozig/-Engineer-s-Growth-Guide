# C++: 多态

多态 (Polymorphism) 源于希腊语，意为“多种形态”。在面向对象编程中，多态是继封装和继承之后的第三大支柱。它允许我们以一种通用的方式来处理不同类型的对象，即**用一个统一的接口（通常是基类指针或引用）来调用不同派生类中被重写的方法**。

多态是实现软件设计中"开闭原则"（对扩展开放，对修改关闭）的关键技术，它让我们的代码更具灵活性和可扩展性。

C++ 中的多态主要通过**虚函数 (Virtual Functions)** 来实现，这被称为**运行时多态 (Run-time Polymorphism)**。

## 1. 静态绑定 vs. 动态绑定

要理解多态，首先要区分两种函数调用绑定方式：

- **静态绑定 (Static Binding)** 或早期绑定 (Early Binding): 在**编译时**就确定要调用哪个函数。这是 C++ 中非虚函数的默认行为。编译器根据调用者（对象或指针）的**静态类型**来决定调用哪个函数。
- **动态绑定 (Dynamic Binding)** 或晚期绑定 (Late Binding): 在**运行时**才确定要调用哪个函数。这是通过虚函数实现的。程序会根据指针或引用所指向对象的**实际类型**来决定调用哪个函数。

## 2. 虚函数 (Virtual Functions)

在基类中，通过在成员函数声明前加上 `virtual` 关键字，就可以使该函数成为一个虚函数。

当派生类重写（重新实现）这个虚函数时，通过基类的指针或引用来调用该函数将会触发动态绑定。

**示例：**
```cpp
#include <iostream>

class Animal {
public:
    // 将 make_sound 声明为虚函数
    virtual void make_sound() {
        std::cout << "Some generic animal sound." << std::endl;
    }
};

class Dog : public Animal {
public:
    // 重写基类的虚函数
    void make_sound() override { // 'override' 关键字是可选但强烈推荐的
        std::cout << "Woof! Woof!" << std::endl;
    }
};

class Cat : public Animal {
public:
    // 重写基类的虚函数
    void make_sound() override {
        std::cout << "Meow!" << std::endl;
    }
};

// 这个函数接受一个指向 Animal 的指针
// 它不知道也不关心指针具体指向的是 Dog 还是 Cat
void play_sound(Animal* animal) {
    animal->make_sound(); // 动态绑定在这里发生
}

int main() {
    Animal generic_animal;
    Dog my_dog;
    Cat my_cat;

    // play_sound(&generic_animal); // 输出: Some generic animal sound.
    // play_sound(&my_dog);         // 输出: Woof! Woof!
    // play_sound(&my_cat);         // 输出: Meow!
    
    Animal* p_animal = &my_dog;
    p_animal->make_sound(); // 调用 Dog::make_sound
    
    p_animal = &my_cat;
    p_animal->make_sound(); // 调用 Cat::make_sound

    return 0;
}
```
在这个例子中，`play_sound` 函数是多态的完美体现。它只需要知道如何处理 `Animal`，而不需要为每一种新的动物类型（`Dog`, `Cat`, `Bird`...）编写一个新版本的函数。这就是多态带来的灵活性。

### `override` 关键字 (C++11)

在派生类中重写虚函数时，推荐使用 `override` 关键字。它有两个作用：
1.  **代码可读性**: 明确地告诉阅读代码的人，这个函数意在重写基类的虚函数。
2.  **编译器检查**: 如果基类中没有与该函数签名（函数名、参数、const 限定符）完全匹配的虚函数，编译器会报错。这可以防止因拼写错误或参数不匹配而导致的意外行为（你以为重写了，但实际上是定义了一个新函数）。

## 3. 抽象基类与纯虚函数

有时，我们希望定义一个基类，它只代表一个抽象概念，而不应该被实例化。例如，"形状"(Shape) 是一个抽象概念，而"圆形"(Circle) 和"矩形"(Rectangle) 是具体的形状。

在 C++ 中，可以通过**纯虚函数 (Pure Virtual Function)** 来创建一个**抽象基类 (Abstract Base Class)**。

- **纯虚函数**: 一个没有实现的虚函数。
- **抽象基类**: 至少包含一个纯虚函数的类。**抽象基类不能被实例化**。

**语法:**
`virtual return-type function_name(args) = 0;`
末尾的 `= 0` 告诉编译器这是一个纯虚函数。

**作用:**
抽象基类主要用于定义一个**接口 (interface)**。它强制所有派生类必须提供纯虚函数的具体实现，否则派生类也将成为一个抽象基类。

**示例：`Shape` 抽象基类**
```cpp
#include <iostream>

// Shape 是一个抽象基类
class Shape {
public:
    // 纯虚函数，定义了"任何形状都应该能计算面积"的接口
    virtual double get_area() = 0; 
};

class Circle : public Shape {
public:
    Circle(double r) : radius(r) {}
    
    // 必须实现基类的纯虚函数
    double get_area() override {
        return 3.14159 * radius * radius;
    }
private:
    double radius;
};

class Rectangle : public Shape {
public:
    Rectangle(double w, double h) : width(w), height(h) {}
    
    // 必须实现基类的纯虚函数
    double get_area() override {
        return width * height;
    }
private:
    double width, height;
};

int main() {
    // Shape my_shape; // 编译错误！不能创建抽象基类的对象

    Circle circle(10.0);
    Rectangle rect(5.0, 4.0);
    
    Shape* p_shape1 = &circle;
    Shape* p_shape2 = &rect;
    
    std::cout << "Area of circle: " << p_shape1->get_area() << std::endl;
    std::cout << "Area of rectangle: " << p_shape2->get_area() << std::endl;
    
    return 0;
}
```

---

多态是 C++ 中实现灵活、可扩展和可维护软件设计的核心机制。接下来，我们将学习 C++ 中另一种形式的多态——编译时多态，即[函数与运算符重载](cpp-overloading.md)。 