# Java面向对象编程

Java是一种完全面向对象的编程语言，其设计理念围绕着对象和类展开。本文档详细介绍Java面向对象编程的核心概念和实践技巧。

## 目录

- [面向对象编程基础](#面向对象编程基础)
- [类与对象](#类与对象)
- [封装](#封装)
- [构造器](#构造器)
- [继承](#继承)
- [多态](#多态)
- [抽象类](#抽象类)
- [接口](#接口)
- [泛型](#泛型)
- [高级面向对象概念](#高级面向对象概念)
- [设计模式](#设计模式)
- [最佳实践](#最佳实践)

## 面向对象编程基础

面向对象编程（OOP）是一种以对象为中心的编程范式，它将数据和行为（方法）封装在对象中。Java作为一种纯面向对象语言，其核心理念包括：

### OOP的四大支柱

1. **封装**：隐藏对象的内部状态和实现细节，仅通过定义良好的接口暴露功能
2. **继承**：允许一个类继承另一个类的属性和方法，实现代码复用
3. **多态**：同一操作可以在不同类型的对象上有不同的行为
4. **抽象**：关注对象的核心特征而非具体实现

### 面向对象与面向过程的区别

| 面向对象编程 | 面向过程编程 |
|------------|------------|
| 以对象为中心 | 以过程/功能为中心 |
| 数据和方法组合在一起 | 数据和方法分离 |
| 高封装性 | 低封装性 |
| 易维护和扩展 | 难维护和扩展 |
| 运行效率相对较低 | 运行效率相对较高 |

### OOP的优势

- 模块化：对象可以单独维护
- 信息隐藏：实现细节被封装
- 代码重用：通过继承和组合
- 可扩展性：新对象可以从现有对象派生
- 更接近人类思维：以实体和关系建模

## 类与对象

类是创建对象的蓝图或模板，而对象是类的实例。

### 类的定义

```java
public class Person {
    // 字段（状态/属性）
    private String name;
    private int age;
    
    // 方法（行为）
    public void speak() {
        System.out.println(name + "正在说话");
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public String getName() {
        return name;
    }
    
    public void setAge(int age) {
        if (age > 0) {
            this.age = age;
        }
    }
    
    public int getAge() {
        return age;
    }
}
```

### 对象的创建与使用

```java
public class Main {
    public static void main(String[] args) {
        // 创建对象（实例化）
        Person person = new Person();
        
        // 设置对象属性
        person.setName("张三");
        person.setAge(25);
        
        // 调用对象方法
        System.out.println("姓名: " + person.getName());
        System.out.println("年龄: " + person.getAge());
        person.speak(); // 输出: 张三正在说话
    }
}
```

### 类与对象的关系

- 类是对象的模板，对象是类的实例
- 一个类可以有多个对象实例
- 对象占用内存空间，类不占用
- 对象有各自的状态（字段值），行为（方法）通常共享

### 引用变量

Java中的对象通过引用变量进行操作：

```java
Person p1 = new Person(); // p1是引用变量，指向堆内存中的Person对象
Person p2 = p1; // p2和p1指向同一个对象
p1.setName("李四");
System.out.println(p2.getName()); // 输出: 李四
```

引用变量的特点：
- 存储对象的内存地址，而非对象本身
- 可以指向null（不指向任何对象）
- 多个引用可以指向同一个对象

## 封装

封装是隐藏对象内部实现细节，仅通过公共接口与外部交互的机制。

### 访问修饰符

Java提供四种访问修饰符来控制类成员的可见性：

| 修饰符 | 类内部 | 同包 | 子类 | 其他包 |
|-------|-------|-----|-----|-------|
| private | ✓ | ✗ | ✗ | ✗ |
| default (无修饰符) | ✓ | ✓ | ✗ | ✗ |
| protected | ✓ | ✓ | ✓ | ✗ |
| public | ✓ | ✓ | ✓ | ✓ |

### 封装的实现

通过将字段设为私有，提供公共的getter和setter方法来实现封装：

```java
public class BankAccount {
    private String accountNumber;
    private double balance;
    private String ownerName;
    
    // Getter方法
    public String getAccountNumber() {
        return accountNumber;
    }
    
    public double getBalance() {
        return balance;
    }
    
    public String getOwnerName() {
        return ownerName;
    }
    
    // Setter方法
    public void setAccountNumber(String accountNumber) {
        this.accountNumber = accountNumber;
    }
    
    public void setOwnerName(String ownerName) {
        this.ownerName = ownerName;
    }
    
    // 注意：deposit和withdraw代替了直接设置balance的setter
    public void deposit(double amount) {
        if (amount > 0) {
            balance += amount;
            System.out.println("存款成功，当前余额: " + balance);
        } else {
            System.out.println("存款金额必须大于0");
        }
    }
    
    public void withdraw(double amount) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            System.out.println("取款成功，当前余额: " + balance);
        } else {
            System.out.println("取款失败，金额不合法或余额不足");
        }
    }
}
```

### 封装的好处

1. **数据隐藏**：保护对象不受外部干扰
2. **灵活性和可维护性**：实现细节可以更改而不影响使用方
3. **数据验证**：控制对数据的访问，确保数据有效
4. **安全性**：防止意外或恶意的数据修改

## 构造器

构造器是特殊的方法，用于在创建对象时初始化对象。

### 默认构造器

如果没有定义任何构造器，Java会提供一个无参数的默认构造器：

```java
public class SimpleClass {
    // 编译器会隐式添加:
    // public SimpleClass() {}
}

// 使用
SimpleClass obj = new SimpleClass(); // 调用默认构造器
```

### 自定义构造器

```java
public class Student {
    private String name;
    private int age;
    private String studentId;
    
    // 无参构造器
    public Student() {
        name = "未命名";
        age = 18;
        studentId = "未分配";
    }
    
    // 带参构造器
    public Student(String name, int age, String studentId) {
        this.name = name;
        this.age = age;
        this.studentId = studentId;
    }
    
    // 部分参数构造器
    public Student(String name) {
        this(name, 18, "未分配"); // 调用带三个参数的构造器
    }
    
    // Getter和Setter方法
    // ...
}
```

### 构造器重载

可以定义多个具有不同参数列表的构造器：

```java
public class Product {
    private String name;
    private double price;
    private int quantity;
    
    // 构造器1
    public Product() {
        name = "未命名产品";
        price = 0.0;
        quantity = 0;
    }
    
    // 构造器2
    public Product(String name, double price) {
        this.name = name;
        this.price = price;
        this.quantity = 0;
    }
    
    // 构造器3
    public Product(String name, double price, int quantity) {
        this.name = name;
        this.price = price;
        this.quantity = quantity;
    }
}
```

### this关键字

`this`关键字在构造器和方法中有多种用途：

1. **引用当前对象**：解决字段和参数同名问题

```java
public void setName(String name) {
    this.name = name; // this.name引用对象的字段，name是参数
}
```

2. **调用同类中的其他构造器**：必须是构造器的第一行

```java
public Rectangle() {
    this(0, 0); // 调用 Rectangle(width, height) 构造器
}

public Rectangle(double width, double height) {
    this.width = width;
    this.height = height;
}
```

### 静态初始化块与实例初始化块

除了构造器，Java还提供了初始化块来执行初始化代码：

```java
public class InitExample {
    private static int staticVar;
    private int instanceVar;
    
    // 静态初始化块：类加载时执行一次
    static {
        System.out.println("静态初始化块执行");
        staticVar = 100;
    }
    
    // 实例初始化块：每次创建对象时执行
    {
        System.out.println("实例初始化块执行");
        instanceVar = 200;
    }
    
    // 构造器
    public InitExample() {
        System.out.println("构造器执行");
    }
}
```

执行顺序：
1. 静态初始化块（类加载时）
2. 实例初始化块（创建对象时）
3. 构造器（创建对象时）

## 继承

继承是Java OOP的核心特性之一，它使得一个类（子类）可以获取另一个类（父类）的属性和方法。

### 继承的语法

使用`extends`关键字表示继承关系：

```java
// 父类
public class Animal {
    protected String name;
    protected int age;
    
    public void eat() {
        System.out.println(name + "正在进食");
    }
    
    public void sleep() {
        System.out.println(name + "正在睡觉");
    }
    
    // Getter和Setter
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public int getAge() {
        return age;
    }
    
    public void setAge(int age) {
        this.age = age;
    }
}

// 子类
public class Dog extends Animal {
    private String breed;
    
    public void bark() {
        System.out.println(name + "汪汪叫");
    }
    
    public String getBreed() {
        return breed;
    }
    
    public void setBreed(String breed) {
        this.breed = breed;
    }
}
```

### 继承的特点

1. **单继承**：Java只支持类的单继承，一个类只能有一个直接父类
2. **多层继承**：允许多层继承链，如A→B→C
3. **超类Object**：所有Java类都直接或间接继承自Object类
4. **构造器不被继承**：子类必须调用父类构造器
5. **私有成员不被继承**：父类的private成员在子类中不可直接访问

### 使用继承的类

```java
public class Main {
    public static void main(String[] args) {
        Dog dog = new Dog();
        dog.setName("小黑");
        dog.setAge(3);
        dog.setBreed("拉布拉多");
        
        // 调用继承自Animal的方法
        dog.eat();  // 输出: 小黑正在进食
        dog.sleep(); // 输出: 小黑正在睡觉
        
        // 调用Dog自己的方法
        dog.bark(); // 输出: 小黑汪汪叫
    }
}
```

### 子类构造器与super关键字

子类构造器必须调用父类构造器，若不显式调用，编译器会自动添加对父类无参构造器的调用：

```java
public class Animal {
    protected String name;
    
    public Animal() {
        System.out.println("Animal构造器被调用");
    }
    
    public Animal(String name) {
        this.name = name;
        System.out.println("Animal带参构造器被调用");
    }
}

public class Dog extends Animal {
    private String breed;
    
    public Dog() {
        // super(); 编译器自动添加
        System.out.println("Dog构造器被调用");
    }
    
    public Dog(String name, String breed) {
        super(name); // 显式调用父类的带参构造器
        this.breed = breed;
        System.out.println("Dog带参构造器被调用");
    }
}
```

`super`关键字的用途：
1. 调用父类构造器：`super()` 或 `super(参数)`
2. 访问父类的方法：`super.方法名()`
3. 访问父类的字段：`super.字段名`

### 方法重写（覆盖）

子类可以重写（override）父类的方法，提供自己的实现：

```java
public class Animal {
    public void makeSound() {
        System.out.println("动物发出声音");
    }
}

public class Dog extends Animal {
    @Override // 注解，表明这是重写方法
    public void makeSound() {
        System.out.println("汪汪汪");
    }
}

public class Cat extends Animal {
    @Override
    public void makeSound() {
        System.out.println("喵喵喵");
    }
}
```

重写方法的规则：
- 方法名、参数列表、返回类型必须与父类方法相同（返回类型可以是父类方法返回类型的子类型）
- 访问修饰符不能比父类方法更严格
- 不能抛出比父类方法更多的异常
- 使用`@Override`注解可以让编译器检查是否符合重写规则

### final关键字

`final`关键字可以防止继承和重写：

- `final`类不能被继承
- `final`方法不能被重写
- `final`字段不能被修改

```java
public final class FinalClass { // 不能被继承
    // ...
}

public class Parent {
    public final void finalMethod() { // 不能被重写
        // ...
    }
}
```

### 继承的优缺点

**优点**：
- 代码重用
- 建立类层次结构
- 支持多态

**缺点**：
- 增加耦合性
- 破坏封装性
- 可能导致脆弱的父类问题

## 多态

多态是指相同的操作或方法可以在不同类型的对象上有不同的行为。

### 多态的类型

1. **编译时多态（静态多态）**：方法重载
2. **运行时多态（动态多态）**：方法重写和动态绑定

### 方法重载（Overloading）

方法重载是指在同一个类中定义多个同名但参数不同的方法：

```java
public class Calculator {
    // 两个整数相加
    public int add(int a, int b) {
        return a + b;
    }
    
    // 三个整数相加（参数数量不同）
    public int add(int a, int b, int c) {
        return a + b + c;
    }
    
    // 两个双精度数相加（参数类型不同）
    public double add(double a, double b) {
        return a + b;
    }
    
    // 字符串连接（参数类型不同）
    public String add(String a, String b) {
        return a + b;
    }
}
```

重载方法的规则：
- 方法名必须相同
- 参数列表必须不同（类型、数量、顺序）
- 返回类型可以相同也可以不同，但仅返回类型不同不构成重载

### 动态绑定（Dynamic Binding）

Java使用动态绑定来实现运行时多态：

```java
public class Main {
    public static void main(String[] args) {
        Animal myAnimal = new Dog(); // 父类引用指向子类对象
        myAnimal.makeSound(); // 输出: 汪汪汪（调用子类Dog的方法）
        
        myAnimal = new Cat();
        myAnimal.makeSound(); // 输出: 喵喵喵（调用子类Cat的方法）
    }
}
```

### 向上转型与向下转型

**向上转型（Upcasting）**：子类对象赋值给父类引用

```java
Dog dog = new Dog();
Animal animal = dog; // 向上转型，自动进行
```

**向下转型（Downcasting）**：父类引用转换为子类引用

```java
Animal animal = new Dog();
Dog dog = (Dog) animal; // 向下转型，需要显式类型转换
dog.bark(); // 可以调用子类特有的方法

// 避免类型转换异常的安全做法
if (animal instanceof Dog) {
    Dog safeDog = (Dog) animal;
    safeDog.bark();
}

// Java 16+ 的模式匹配增强（预览特性）
if (animal instanceof Dog safeDog) {
    safeDog.bark();
}
```

### 多态的实例

下面是一个综合展示多态的例子：

```java
// 形状抽象类
abstract class Shape {
    public abstract double calculateArea();
    public abstract double calculatePerimeter();
}

// 圆形
class Circle extends Shape {
    private double radius;
    
    public Circle(double radius) {
        this.radius = radius;
    }
    
    @Override
    public double calculateArea() {
        return Math.PI * radius * radius;
    }
    
    @Override
    public double calculatePerimeter() {
        return 2 * Math.PI * radius;
    }
}

// 矩形
class Rectangle extends Shape {
    private double length;
    private double width;
    
    public Rectangle(double length, double width) {
        this.length = length;
        this.width = width;
    }
    
    @Override
    public double calculateArea() {
        return length * width;
    }
    
    @Override
    public double calculatePerimeter() {
        return 2 * (length + width);
    }
}

// 使用多态
public class Main {
    public static void main(String[] args) {
        Shape circle = new Circle(5);
        Shape rectangle = new Rectangle(4, 6);
        
        // 相同的方法调用，不同的实现
        System.out.println("圆形面积: " + circle.calculateArea());
        System.out.println("矩形面积: " + rectangle.calculateArea());
        
        System.out.println("圆形周长: " + circle.calculatePerimeter());
        System.out.println("矩形周长: " + rectangle.calculatePerimeter());
        
        // 处理一组不同的形状
        Shape[] shapes = {new Circle(3), new Rectangle(2, 4), new Circle(7)};
        double totalArea = 0;
        
        for (Shape shape : shapes) {
            totalArea += shape.calculateArea(); // 多态调用
        }
        
        System.out.println("总面积: " + totalArea);
    }
}
```

### 多态的优势

- **简单可扩展的代码**：无需修改现有代码即可添加新的派生类
- **动态行为**：根据运行时类型确定行为
- **可替换性**：符合里氏替换原则，子类可替换父类
- **接口统一**：通过共同的父类型处理不同的对象

## 抽象类

抽象类是一种特殊的类，它不能被实例化，只能被继承。

### 抽象类的定义

```java
public abstract class Animal {
    protected String name;
    protected int age;
    
    public abstract void makeSound();
    
    public void eat() {
        System.out.println(name + "正在进食");
    }
    
    public void sleep() {
        System.out.println(name + "正在睡觉");
    }
    
    // Getter和Setter
    public String getName() {
        return name;
    }
    
    public void setName(String name) {
        this.name = name;
    }
    
    public int getAge() {
        return age;
    }
    
    public void setAge(int age) {
        this.age = age;
    }
}
```

### 抽象类的特点

1. **不能被实例化**：不能创建抽象类的对象
2. **可以包含抽象方法**：抽象方法没有实现，必须在子类中实现
3. **可以包含具体方法**：具体方法有实现，可以被子类继承
4. **可以包含字段**：字段可以被子类继承

### 使用抽象类

```java
public class Main {
    public static void main(String[] args) {
        Animal myAnimal = new Dog();
        myAnimal.setName("小黑");
        myAnimal.setAge(3);
        
        // 调用继承自Animal的方法
        myAnimal.eat();  // 输出: 小黑正在进食
        myAnimal.sleep(); // 输出: 小黑正在睡觉
        
        // 调用Dog自己的方法
        if (myAnimal instanceof Dog) {
            Dog dog = (Dog) myAnimal;
            dog.bark(); // 输出: 小黑汪汪叫
        }
    }
}
```

## 接口

接口是一种特殊的类，它只包含抽象方法。接口用于实现多态和代码复用。

### 接口的定义

```java
public interface Flyable {
    void fly();
}
```

### 接口的特点

1. **只能包含抽象方法**：接口中的方法没有实现，必须在实现接口的类中实现
2. **可以包含常量**：接口中可以定义常量
3. **可以包含默认方法**：接口中可以定义默认方法
4. **可以包含静态方法**：接口中可以定义静态方法

### 实现接口

```java
public class Bird implements Flyable {
    @Override
    public void fly() {
        System.out.println("鸟在飞");
    }
}
```

### 接口与抽象类的区别

| 接口 | 抽象类 |
|------|--------|
| 只能包含抽象方法 | 可以包含具体方法 |
| 不能包含字段 | 可以包含字段 |
| 可以实现多个接口 | 只能继承一个类 |
| 不支持多继承 | 支持多继承 |

## 泛型

泛型是一种参数化类型的机制，它允许类、接口或方法在定义时不指定具体类型，而在使用时指定。

### 泛型的定义

```java
public class Box<T> {
    private T content;
    
    public void setContent(T content) {
        this.content = content;
    }
    
    public T getContent() {
        return content;
    }
}
```

### 泛型的特点

1. **类型安全**：在编译时检查类型，避免运行时类型错误
2. **代码重用**：通过泛型可以编写更通用的代码
3. **灵活性**：可以处理不同类型的数据

### 使用泛型

```java
public class Main {
    public static void main(String[] args) {
        Box<String> stringBox = new Box<>();
        stringBox.setContent("Hello");
        System.out.println(stringBox.getContent());
        
        Box<Integer> integerBox = new Box<>();
        integerBox.setContent(123);
        System.out.println(integerBox.getContent());
    }
}
```

## 高级面向对象概念

高级面向对象概念包括设计模式、最佳实践等。

### 设计模式

设计模式是一种解决特定问题的通用解决方案。

#### 单例模式

单例模式确保一个类只有一个实例，并提供一个访问它的全局访问点。

```java
public class Singleton {
    private static Singleton instance;
    
    private Singleton() {}
    
    public static Singleton getInstance() {
        if (instance == null) {
            instance = new Singleton();
        }
        return instance;
    }
}
```

#### 工厂模式

工厂模式提供了一种创建对象的方式，而无需指定具体的类。

```java
public class ShapeFactory {
    public Shape createShape(String shapeType) {
        if (shapeType == null) {
            return null;
        }
        if (shapeType.equalsIgnoreCase("CIRCLE")) {
            return new Circle();
        } else if (shapeType.equalsIgnoreCase("RECTANGLE")) {
            return new Rectangle();
        }
        return null;
    }
}
```

### 最佳实践

最佳实践包括代码重用、可维护性、可扩展性等。

#### 代码重用

通过继承和组合来实现代码重用。

```java
public class Main {
    public static void main(String[] args) {
        Dog dog = new Dog();
        dog.setName("小黑");
        dog.setAge(3);
        dog.setBreed("拉布拉多");
        
        // 调用继承自Animal的方法
        dog.eat();  // 输出: 小黑正在进食
        dog.sleep(); // 输出: 小黑正在睡觉
        
        // 调用Dog自己的方法
        dog.bark(); // 输出: 小黑汪汪叫
    }
}
```

#### 可维护性

通过封装和抽象来实现可维护性。

```java
public class BankAccount {
    private String accountNumber;
    private double balance;
    private String ownerName;
    
    // Getter方法
    public String getAccountNumber() {
        return accountNumber;
    }
    
    public double getBalance() {
        return balance;
    }
    
    public String getOwnerName() {
        return ownerName;
    }
    
    // Setter方法
    public void setAccountNumber(String accountNumber) {
        this.accountNumber = accountNumber;
    }
    
    public void setOwnerName(String ownerName) {
        this.ownerName = ownerName;
    }
    
    // 注意：deposit和withdraw代替了直接设置balance的setter
    public void deposit(double amount) {
        if (amount > 0) {
            balance += amount;
            System.out.println("存款成功，当前余额: " + balance);
        } else {
            System.out.println("存款金额必须大于0");
        }
    }
    
    public void withdraw(double amount) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            System.out.println("取款成功，当前余额: " + balance);
        } else {
            System.out.println("取款失败，金额不合法或余额不足");
        }
    }
}
```

#### 可扩展性

通过多态和接口来实现可扩展性。

```java
public class Main {
    public static void main(String[] args) {
        Animal myAnimal = new Dog();
        myAnimal.setName("小黑");
        myAnimal.setAge(3);
        
        // 调用继承自Animal的方法
        myAnimal.eat();  // 输出: 小黑正在进食
        myAnimal.sleep(); // 输出: 小黑正在睡觉
        
        // 调用Dog自己的方法
        if (myAnimal instanceof Dog) {
            Dog dog = (Dog) myAnimal;
            dog.bark(); // 输出: 小黑汪汪叫
        }
    }
}
``` 