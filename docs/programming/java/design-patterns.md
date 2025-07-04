# 常见设计模式 (Java 实现)

设计模式是在软件设计过程中，针对特定问题的一套经过验证的、可重用的解决方案。它们不是可以直接转换成代码的最终设计，而是一种描述在不同情况下如何解决问题的模板。

本章将介绍几种在 Java 开发中最常用、最重要的设计模式。

---

## 1. 创建型模式 (Creational Patterns)

这类模式关注对象的创建过程，旨在以一种灵活、解耦的方式创建对象。

### 1.1. 单例模式 (Singleton Pattern)

**意图**: 确保一个类只有一个实例，并提供一个全局访问点。
**应用场景**: 日志记录器、配置管理器、线程池、数据库连接池等。

**实现方式 (线程安全的懒汉式 - 静态内部类)**:
```java
public class Singleton {
    // 1. 私有化构造方法
    private Singleton() {}

    // 2. 使用静态内部类来持有单例实例
    //    JVM 保证了类加载的线程安全性
    private static class SingletonHolder {
        private static final Singleton INSTANCE = new Singleton();
    }

    // 3. 提供全局访问点
    public static Singleton getInstance() {
        return SingletonHolder.INSTANCE;
    }

    public void showMessage() {
        System.out.println("Hello from Singleton!");
    }
}
```
这是目前最推荐的一种实现方式，它结合了懒加载和线程安全，且实现简单。

### 1.2. 工厂方法模式 (Factory Method Pattern)

**意图**: 定义一个用于创建对象的接口，但让子类决定实例化哪一个类。工厂方法使一个类的实例化延迟到其子类。
**应用场景**: 当一个类不知道它所必须创建的对象的类时；当一个类希望由它的子类来指定它所创建的对象时。

```java
// 产品接口
interface Product {
    void use();
}

// 具体产品
class ConcreteProductA implements Product {
    public void use() { System.out.println("Using Product A"); }
}
class ConcreteProductB implements Product {
    public void use() { System.out.println("Using Product B"); }
}

// 工厂接口
interface Factory {
    Product createProduct();
}

// 具体工厂
class ConcreteFactoryA implements Factory {
    public Product createProduct() { return new ConcreteProductA(); }
}
class ConcreteFactoryB implements Factory {
    public Product createProduct() { return new ConcreteProductB(); }
}
```
**核心**: 将对象的创建从客户端代码中分离出来，客户端只依赖于工厂接口和产品接口。

### 1.3. 建造者模式 (Builder Pattern)

**意图**: 将一个复杂对象的构建与其表示分离，使得同样的构建过程可以创建不同的表示。
**应用场景**: 当一个对象的构造函数参数过多时；当需要分步骤、按需创建对象时。`StringBuilder` 就是一个典型的例子。

```java
public class Computer {
    // required parameters
    private String CPU;
    private String RAM;

    // optional parameters
    private String storage;
    private String graphicsCard;

    private Computer(Builder builder) {
        this.CPU = builder.CPU;
        this.RAM = builder.RAM;
        this.storage = builder.storage;
        this.graphicsCard = builder.graphicsCard;
    }

    // 静态内部 Builder 类
    public static class Builder {
        private String CPU;
        private String RAM;
        private String storage;
        private String graphicsCard;

        public Builder(String cpu, String ram) {
            this.CPU = cpu;
            this.RAM = ram;
        }

        public Builder setStorage(String storage) {
            this.storage = storage;
            return this; // 返回 this 以支持链式调用
        }

        public Builder setGraphicsCard(String graphicsCard) {
            this.graphicsCard = graphicsCard;
            return this;
        }

        public Computer build() {
            return new Computer(this);
        }
    }
}

// 使用
Computer comp = new Computer.Builder("Intel i9", "32GB")
                        .setStorage("1TB SSD")
                        .setGraphicsCard("NVIDIA RTX 4090")
                        .build();
```

---

## 2. 结构型模式 (Structural Patterns)

这类模式关注如何将类和对象组合成更大的结构。

### 2.1. 代理模式 (Proxy Pattern)

**意图**: 为其他对象提供一种代理以控制对这个对象的访问。
**应用场景**: 远程代理（如 RMI）、虚拟代理（按需加载大对象）、保护代理（控制访问权限）、智能引用（如 AOP 中的日志、事务）。

```java
// 主体接口
interface Image {
    void display();
}

// 真实主体
class RealImage implements Image {
    private String fileName;
    public RealImage(String fileName){
        this.fileName = fileName;
        loadFromDisk(fileName);
    }
    private void loadFromDisk(String fileName){
        System.out.println("Loading " + fileName);
    }
    public void display() {
        System.out.println("Displaying " + fileName);
    }
}

// 代理
class ProxyImage implements Image {
    private RealImage realImage;
    private String fileName;

    public ProxyImage(String fileName){
        this.fileName = fileName;
    }

    public void display() {
        if(realImage == null){
            realImage = new RealImage(fileName); // 懒加载
        }
        realImage.display();
    }
}
```

### 2.2. 装饰器模式 (Decorator Pattern)

**意图**: 动态地给一个对象添加一些额外的职责。就增加功能来说，装饰器模式相比生成子类更为灵活。
**应用场景**: Java I/O 类，如 `new BufferedReader(new FileReader("file.txt"))`。

```java
// 组件接口
interface Coffee {
    String getDescription();
    double getCost();
}

// 具体组件
class SimpleCoffee implements Coffee {
    public String getDescription() { return "Simple Coffee"; }
    public double getCost() { return 1.0; }
}

// 装饰器基类
abstract class CoffeeDecorator implements Coffee {
    protected final Coffee decoratedCoffee;
    public CoffeeDecorator(Coffee coffee) { this.decoratedCoffee = coffee; }
    public String getDescription() { return decoratedCoffee.getDescription(); }
    public double getCost() { return decoratedCoffee.getCost(); }
}

// 具体装饰器
class WithMilk extends CoffeeDecorator {
    public WithMilk(Coffee c) { super(c); }
    public String getDescription() { return super.getDescription() + ", with Milk"; }
    public double getCost() { return super.getCost() + 0.5; }
}
class WithSugar extends CoffeeDecorator {
    public WithSugar(Coffee c) { super(c); }
    public String getDescription() { return super.getDescription() + ", with Sugar"; }
    public double getCost() { return super.getCost() + 0.2; }
}

// 使用
Coffee coffee = new SimpleCoffee();
coffee = new WithMilk(coffee);
coffee = new WithSugar(coffee);
System.out.println(coffee.getDescription() + " $" + coffee.getCost());
```

---

## 3. 行为型模式 (Behavioral Patterns)

这类模式关注对象之间的通信和职责分配。

### 3.1. 策略模式 (Strategy Pattern)

**意图**: 定义一系列的算法,把它们一个个封装起来, 并且使它们可相互替换。
**应用场景**: 当你有许多相关的类，它们之间只有行为不同时；需要一种算法的变体。例如 `Collections.sort()` 方法接收一个 `Comparator`。

```java
// 策略接口
interface SortStrategy {
    void sort(int[] numbers);
}

// 具体策略
class BubbleSortStrategy implements SortStrategy {
    public void sort(int[] numbers) { /* ... */ System.out.println("Sorting with Bubble Sort"); }
}
class QuickSortStrategy implements SortStrategy {
    public void sort(int[] numbers) { /* ... */ System.out.println("Sorting with Quick Sort"); }
}

// 上下文
class SortedList {
    private SortStrategy strategy;
    public void setSortStrategy(SortStrategy strategy) { this.strategy = strategy; }
    public void sort(int[] numbers) { strategy.sort(numbers); }
}

// 使用
SortedList list = new SortedList();
list.setSortStrategy(new BubbleSortStrategy());
list.sort(new int[]{1, 5, 2}); // Sorting with Bubble Sort
list.setSortStrategy(new QuickSortStrategy());
list.sort(new int[]{1, 5, 2}); // Sorting with Quick Sort
```

### 3.2. 观察者模式 (Observer Pattern)

**意图**: 定义对象间的一种一对多的依赖关系，当一个对象的状态发生改变时，所有依赖于它的对象都得到通知并被自动更新。
**应用场景**: 事件监听器（如 Swing/AWT 中的 `ActionListener`），消息队列，MVC 架构中的模型和视图。

```java
import java.util.ArrayList;
import java.util.List;

// 主题（被观察者）
class Subject {
    private List<Observer> observers = new ArrayList<>();
    private int state;

    public int getState() { return state; }

    public void setState(int state) {
        this.state = state;
        notifyAllObservers();
    }

    public void attach(Observer observer){ observers.add(observer); }

    public void notifyAllObservers(){
        for (Observer observer : observers) {
            observer.update();
        }
    }
}

// 观察者接口
abstract class Observer {
    protected Subject subject;
    public abstract void update();
}

// 具体观察者
class BinaryObserver extends Observer {
    public BinaryObserver(Subject subject){
        this.subject = subject;
        this.subject.attach(this);
    }
    public void update() {
        System.out.println("Binary String: " + Integer.toBinaryString(subject.getState()));
    }
}

// 使用
Subject subject = new Subject();
new BinaryObserver(subject);
subject.setState(15); // "Binary String: 1111"
```
设计模式是前人智慧的结晶，合理地使用它们可以极大地提高代码的可维护性、可扩展性和可重用性。
