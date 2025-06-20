# Java 泛型 (Generics)

泛型是 Java SE 5.0 引入的一个重要特性，它允许在编译时检查类型安全，并且所有的强制转换都是自动和隐式的，提高了代码的可读性和健壮性。

## 1. 为什么需要泛型？

在泛型出现之前，Java 的集合类（如 `ArrayList`）只能存储 `Object` 类型的对象。这样做有两个主要问题：

1.  **类型不安全**: 你可以向集合中添加任何类型的对象，这可能在运行时导致 `ClassCastException`。
2.  **代码繁琐**: 从集合中取出元素时，必须手动进行强制类型转换。

```java
// 没有泛型的代码
List list = new ArrayList();
list.add("hello");
list.add(123); // 编译时没问题，但逻辑上是错误的

// 取出时需要强制转换，且可能失败
String text = (String) list.get(0);
Integer num = (Integer) list.get(1);
// String anotherText = (String) list.get(1); // 运行时抛出 ClassCastException
```

**泛型解决了这些问题**，它将类型的指定从运行时提前到了编译时。

```java
// 使用泛型
List<String> list = new ArrayList<>();
list.add("hello");
// list.add(123); // 编译错误！无法将 int 添加到 String 列表中

// 无需强制转换
String text = list.get(0);
```

---

## 2. 泛型类

我们可以定义自己的泛型类。类型参数（通常用单个大写字母表示，如 `T`）可以在整个类中使用，代表一个未知的类型。

**语法**: `class ClassName<T> { ... }`

-   `T`: Type (类型)
-   `E`: Element (元素，常用于集合)
-   `K`: Key (键)
-   `V`: Value (值)

**示例：一个泛型容器**

```java
public class Box<T> {
    private T t;

    public void set(T t) {
        this.t = t;
    }

    public T get() {
        return t;
    }

    public static void main(String[] args) {
        Box<String> stringBox = new Box<>();
        stringBox.set("Hello World");
        // stringBox.set(123); // 编译错误
        System.out.println(stringBox.get());

        Box<Integer> integerBox = new Box<>();
        integerBox.set(42);
        System.out.println(integerBox.get());
    }
}
```

---

## 3. 泛型方法

泛型不仅能用于类，还可以用于方法。泛型方法有自己的类型参数，独立于类可能有的任何类型参数。

**语法**: `<T> returnType methodName(T parameter) { ... }`

类型参数声明在返回类型之前。

```java
public class Util {
    // 这是一个泛型方法
    public static <T> void printArray(T[] inputArray) {
        for (T element : inputArray) {
            System.out.printf("%s ", element);
        }
        System.out.println();
    }

    public static void main(String[] args) {
        Integer[] intArray = { 1, 2, 3, 4, 5 };
        String[] stringArray = { "Hello", "World" };

        System.out.println("Integer Array contains:");
        printArray(intArray); // 编译器自动推断 T 是 Integer

        System.out.println("String Array contains:");
        printArray(stringArray); // 编译器自动推断 T 是 String
    }
}
```

---

## 4. 有界类型参数 (Bounded Type Parameters)

有时，你可能想限制传递给类型参数的类型。例如，一个操作数字的方法可能只希望接受 `Number` 或其子类的实例。这可以通过 **有界类型参数** 实现。

**语法**: `<T extends UpperBound>`

`extends` 在这里表示 `T` 应该是 `UpperBound` 的子类型（或者是 `UpperBound` 本身）。

```java
public class Stats<T extends Number> {
    private T[] nums;

    public Stats(T[] o) {
        nums = o;
    }

    public double average() {
        double sum = 0.0;
        for (int i = 0; i < nums.length; i++) {
            sum += nums[i].doubleValue(); // 调用 Number 类的方法
        }
        return sum / nums.length;
    }
}

// 使用
// Stats<String> stringStats = new Stats<>(); // 编译错误，String 不继承自 Number
Stats<Integer> integerStats = new Stats<>(new Integer[]{1, 2, 3, 4, 5});
System.out.println("Average is: " + integerStats.average());
```

---

## 5. 通配符 (Wildcards)

通配符 `?` 代表未知的类型。它主要用于方法参数，以增加方法的灵活性。

### 5.1. 上界通配符 (`? extends Type`)

表示一个未知的类型，但这个类型是 `Type` 的子类（或 `Type` 本身）。
**用途**: 当你只需要从集合中 **读取** (get) 数据，而不需要写入时，使用上界通配符。它保证了你取出的对象至少是 `Type` 类型的。这被称为 **GET/PRODUCER** 原则。

```java
// 这个方法可以接受 List<Integer>, List<Double>, List<Number>
public static void processNumbers(List<? extends Number> list) {
    for (Number n : list) {
        System.out.println(n.doubleValue());
    }
    // list.add(1); // 编译错误！因为我们不知道 list 的具体类型是什么，
                   // 可能是 List<Double>，不能添加 Integer。
}
```

### 5.2. 下界通配符 (`? super Type`)

表示一个未知的类型，但这个类型是 `Type` 的父类（或 `Type` 本身）。
**用途**: 当你只需要向集合中 **写入** (add) 数据，而不需要读取时，使用下界通配符。你可以安全地将 `Type` 及其子类的对象放入其中。这被称为 **PUT/CONSUMER** 原则。

```java
// 这个方法可以接受 List<Integer>, List<Number>, List<Object>
public static void addIntegers(List<? super Integer> list) {
    list.add(1);
    list.add(2);
    // Integer n = list.get(0); // 编译错误！因为 list 可能是 List<Object>，
                              // 取出的元素只能确保是 Object 类型。
}
```

### 5.3. 无界通配符 (`?`)

表示任意类型。`List<?>` 和 `List<Object>` 不同。你可以向 `List<Object>` 添加任何对象，但你不能向 `List<?>` 添加任何对象（`null` 除外），因为它代表的类型是未知的。

**用途**: 当你需要处理的类型不依赖于具体的类型参数时使用。例如，`List.size()` 或 `List.clear()` 方法。

---

## 6. 类型擦除 (Type Erasure)

Java 泛型是通过 **类型擦除** 来实现的。这意味着在 **编译后**，所有泛型类型信息都会被擦除。

-   `Box<String>` 变成了 `Box`。
-   `T` 被替换为它的上界（默认是 `Object`）。

这是为了向后兼容旧的、没有泛型的 Java 代码。但也带来了一些限制，例如：
-   不能创建泛型数组 (`new T[]`)。
-   不能创建泛型类型的实例 (`new T()`)。
-   `static` 字段或方法不能引用类的类型参数。
-   不能对泛型类型使用 `instanceof`。

理解类型擦除对于深入掌握泛型至关重要。
