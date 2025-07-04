# Java 面向对象编程 (OOP)

面向对象编程（Object-Oriented Programming, OOP）是 Java 的核心范式。它使用对象和类来组织和管理代码，使得软件开发更加模块化、灵活和可维护。本章节将介绍 Java OOP 的基本概念。

## 核心概念

Java OOP 主要围绕以下几个核心概念构建：

1.  **类 (Class)**
2.  **对象 (Object)**
3.  **封装 (Encapsulation)**
4.  **继承 (Inheritance)**
5.  **多态 (Polymorphism)**
6.  **抽象 (Abstraction)**

---

### 1. 类 (Class)

**类**是创建对象的蓝图或模板。它定义了一组属性（成员变量）和行为（方法），这些属性和行为是该类所有对象所共有的。

-   **成员变量 (Instance Variables)**：定义对象的状态。
-   **方法 (Methods)**：定义对象的行为。

**语法示例：**

```java
// 定义一个 Dog 类
public class Dog {
    // 成员变量
    String breed;
    int age;
    String color;

    // 方法
    void barking() {
        System.out.println("The dog is barking!");
    }

    void hungry() {
        System.out.println("The dog is hungry...");
    }

    void sleeping() {
        System.out.println("The dog is sleeping.");
    }
}
```

### 2. 对象 (Object)

**对象**是类的实例。当你根据一个类创建一个对象时，系统会为该对象分配内存来存储其状态（成员变量的值）。

**创建和使用对象：**

使用 `new` 关键字来创建类的对象。

```java
public class Main {
    public static void main(String[] args) {
        // 创建一个 Dog 类的对象
        Dog myDog = new Dog();

        // 访问和设置对象的属性
        myDog.breed = "Bulldog";
        myDog.age = 5;
        myDog.color = "brown";

        // 调用对象的方法
        System.out.println("My dog's breed is: " + myDog.breed);
        myDog.barking(); // 输出: The dog is barking!
    }
}
```

---

### 3. 封装 (Encapsulation)

**封装**是将数据（变量）和操作这些数据的代码（方法）捆绑到一个单元（类）中的机制。它也是一种数据隐藏的机制，限制外部直接访问对象的内部状态。

-   **实现方式**：
    1.  将类的成员变量声明为 `private`。
    2.  提供 `public` 的 `getter` 和 `setter` 方法来访问和修改这些私有变量。

**示例：**

```java
public class Person {
    private String name; // private 变量
    private int age;

    // public getter 方法
    public String getName() {
        return name;
    }

    // public setter 方法
    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        if (age > 0) { // 可以加入验证逻辑
            this.age = age;
        }
    }
}

public class Main {
    public static void main(String[] args) {
        Person person = new Person();
        person.setName("John");
        person.setAge(30);

        System.out.println("Name: " + person.getName()); // 正确访问
        // person.name = "John"; // 编译错误，无法直接访问 private 变量
    }
}
```

---

### 4. 继承 (Inheritance)

**继承**是一个对象（子类）获取另一个对象（父类）的属性和方法的过程。它支持代码重用，并能创建层次结构。

-   **父类 (Superclass/Parent Class)**：被继承的类。
-   **子类 (Subclass/Child Class)**：继承父类的类。
-   使用 `extends` 关键字来实现继承。

**示例：**

```java
// 父类
class Animal {
    void eat() {
        System.out.println("This animal eats food.");
    }
}

// 子类继承 Animal
class Dog extends Animal {
    void bark() {
        System.out.println("The dog barks.");
    }
}

public class Main {
    public static void main(String[] args) {
        Dog myDog = new Dog();
        myDog.eat();  // 调用从父类继承的方法
        myDog.bark(); // 调用自己的方法
    }
}
```

---

### 5. 多态 (Polymorphism)

**多态**（意为"多种形态"）允许我们以统一的方式处理不同类型的对象。在 Java 中，多态通常通过方法重写（Overriding）和方法重载（Overloading）来实现。

-   **方法重写 (Method Overriding)**：子类重新定义了父类中具有相同签名的方法。
-   **方法重载 (Method Overloading)**：在一个类中定义多个同名方法，但它们的参数列表不同。

**示例（方法重写）：**

```java
class Animal {
    public void makeSound() {
        System.out.println("Some generic animal sound");
    }
}

class Dog extends Animal {
    @Override // 注解表示这是一个重写方法
    public void makeSound() {
        System.out.println("Woof Woof");
    }
}

class Cat extends Animal {
    @Override
    public void makeSound() {
        System.out.println("Meow");
    }
}

public class Main {
    public static void main(String[] args) {
        Animal myAnimal = new Animal();
        Animal myDog = new Dog(); // Dog 对象被当做 Animal 类型引用
        Animal myCat = new Cat(); // Cat 对象被当做 Animal 类型引用

        myAnimal.makeSound(); // 输出: Some generic animal sound
        myDog.makeSound();    // 输出: Woof Woof (调用 Dog 的方法)
        myCat.makeSound();    // 输出: Meow (调用 Cat 的方法)
    }
}
```

---

### 6. 抽象 (Abstraction)

**抽象**是隐藏复杂的实现细节，只向用户展示必要的功能。它可以通过**抽象类**和**接口**来实现。

-   **抽象类 (Abstract Class)**：不能被实例化的类，可能包含抽象方法（没有方法体）。使用 `abstract` 关键字定义。
-   **接口 (Interface)**：一个完全抽象的蓝图，只包含常量和抽象方法。一个类可以实现多个接口。使用 `interface` 关键字定义。

**示例（抽象类）：**

```java
// 抽象类
abstract class Shape {
    String color;

    // 抽象方法（没有方法体）
    abstract double area();

    // 具体方法
    public String getColor() {
        return color;
    }
}

// 具体子类
class Circle extends Shape {
    double radius;

    @Override
    double area() {
        return Math.PI * radius * radius;
    }
}

public class Main {
    public static void main(String[] args) {
        // Shape shape = new Shape(); // 编译错误，不能实例化抽象类
        Circle circle = new Circle();
        circle.radius = 5.0;
        System.out.println("Area of circle: " + circle.area());
    }
}
```

**示例（接口）：**

```java
// 接口
interface Drawable {
    void draw(); // 默认是 public abstract
}

class Rectangle implements Drawable {
    public void draw() {
        System.out.println("Drawing a rectangle");
    }
}

class Main {
    public static void main(String[] args) {
        Drawable d = new Rectangle();
        d.draw();
    }
}
```
