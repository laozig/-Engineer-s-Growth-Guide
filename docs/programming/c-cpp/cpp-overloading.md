# C++: 函数与运算符重载

**重载 (Overloading)** 是 C++ 中的一种**编译时多态 (Compile-time Polymorphism)**。它允许在同一个作用域内，给多个不同的函数（或运算符）赋予相同的名称，只要它们的**参数列表**（参数的数量、类型或顺序）不同即可。

编译器会根据你调用函数时提供的参数来决定到底执行哪个版本的函数。这使得我们可以用一个直观的名称来表示一组功能相似但处理不同数据类型的操作。

## 1. 函数重载 (Function Overloading)

函数重载允许我们定义多个同名函数。

**示例：一个 `add` 函数**
```cpp
#include <iostream>
#include <string>

// 版本 1: 两个整数相加
int add(int a, int b) {
    std::cout << "Calling int add(int, int)" << std::endl;
    return a + b;
}

// 版本 2: 两个 double 相加
double add(double a, double b) {
    std::cout << "Calling double add(double, double)" << std::endl;
    return a + b;
}

// 版本 3: 三个整数相加
int add(int a, int b, int c) {
    std::cout << "Calling int add(int, int, int)" << std::endl;
    return a + b + c;
}

// 版本 4: 两个字符串连接
std::string add(const std::string& a, const std::string& b) {
    std::cout << "Calling std::string add(const std::string&, const std::string&)" << std::endl;
    return a + b;
}

int main() {
    add(5, 10);          // 调用版本 1
    add(3.5, 2.7);       // 调用版本 2
    add(1, 2, 3);        // 调用版本 3
    add(std::string("Hello, "), std::string("World!")); // 调用版本 4
    return 0;
}
```
**注意**: 函数的**返回类型不能**作为重载的区分标准。两个只有返回类型不同的同名函数会导致编译错误。

## 2. 运算符重载 (Operator Overloading)

运算符重载是 C++ 一个非常强大的特性，它允许我们重新定义 C++ 中已有的运算符（如 `+`, `-`, `*`, `/`, `<<`, `>>`, `==` 等）在作用于我们自定义的类（或结构体）的对象时的行为。

通过运算符重载，我们可以让我们自定义的类型像内置类型（如 `int`, `double`）一样，以一种直观、自然的方式进行操作，从而极大地提高代码的可读性。

**语法:**
运算符重载通常被实现为类的成员函数或全局函数。

`返回类型 operator运算符(参数列表);`

**示例：为一个二维向量类 `Vector2D` 重载 `+` 和 `<<` 运算符**
```cpp
#include <iostream>

class Vector2D {
public:
    Vector2D(double x = 0.0, double y = 0.0) : x(x), y(y) {}

    // 成员变量
    double x, y;

    // 将 operator+ 重载为成员函数
    Vector2D operator+(const Vector2D& other) const {
        // this 指针指向左操作数 (e.g., v1)
        // other 是右操作数 (e.g., v2)
        return Vector2D(this->x + other.x, this->y + other.y);
    }
};

// 将 operator<< 重载为全局函数
// 因为左操作数是 std::ostream&，而不是 Vector2D 对象
// 需要声明为 friend 才能访问 Vector2D 的私有成员（如果 x,y 是 private 的话）
std::ostream& operator<<(std::ostream& os, const Vector2D& vec) {
    os << "(" << vec.x << ", " << vec.y << ")";
    return os;
}

int main() {
    Vector2D v1(2.0, 3.0);
    Vector2D v2(1.0, 5.0);

    // 1. 使用重载的 + 运算符
    Vector2D v3 = v1 + v2; // 直观！等价于 v1.operator+(v2)
    
    // 2. 使用重载的 << 运算符
    std::cout << "Vector v1: " << v1 << std::endl; // 直观！
    std::cout << "Vector v2: " << v2 << std::endl;
    std::cout << "Vector v3 (v1 + v2): " << v3 << std::endl;

    return 0;
}
```
**输出:**
```
Vector v1: (2, 3)
Vector v2: (1, 5)
Vector v3 (v1 + v2): (3, 8)
```

### 可重载与不可重载的运算符

- **几乎所有**运算符都可以被重载。
- **不可重载**的运算符只有少数几个：
    - `.` (成员访问)
    - `.*` (成员指针访问)
    - `::` (作用域解析)
    - `?:` (三元条件)
    - `sizeof`

### 重载为成员函数 vs. 全局函数

- **成员函数**: 当运算符的左操作数必须是该类的对象时（例如，一元运算符或 `+=` 这种赋值运算符），通常重载为成员函数。
- **全局函数**: 当运算符的左操作数是其他类型（如 `std::ostream`）或需要对两种不同类型进行对称操作时，通常重载为全局函数。如果全局函数需要访问类的私有成员，需要将其声明为类的**友元 (friend)**。

---

运算符重载让我们的自定义类型"活"了起来，使其能无缝地融入 C++ 的表达式语法中。至此，我们完成了面向对象编程部分的学习。

接下来，我们将进入 C++ 的另一个强大领域：泛型编程，从学习[模板 (Templates)](cpp-templates.md) 开始。 