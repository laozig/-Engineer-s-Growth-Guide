# 1.2 Java 基础：构建坚实的编程基石

掌握了开发环境，我们就正式踏入了 Java 编程的大门。本章将覆盖 Java 语言最核心、最基础的构建块。深刻理解这些概念，是编写任何复杂程序的先决条件。

## 1. 第一个 Java 程序：`Hello, World!`

让我们从编程界的传统开始。这个简单的程序将帮助我们理解一个基本的 Java 程序结构。

```java
// public class HelloWorld 是一个类定义，Java 中所有代码都必须写在类里面。
// HelloWorld 是类名，必须与文件名 (HelloWorld.java) 完全一致。
public class HelloWorld {

    // public static void main(String[] args) 是程序的主方法。
    // 它是程序的入口点，JVM 会从这里开始执行。
    public static void main(String[] args) {
        // System.out.println(...) 是一个标准的输出语句，用于在控制台打印信息。
        System.out.println("Hello, World!");
    }
}
```

**如何运行:**
1.  将以上代码保存为 `HelloWorld.java`。
2.  打开终端，使用 `javac` 命令编译它：`javac HelloWorld.java`。这会生成一个 `HelloWorld.class` 文件。
3.  使用 `java` 命令运行编译后的代码：`java HelloWorld`。
4.  您将在控制台看到输出：`Hello, World!`

---

## 2. 变量与数据类型

变量是用于存储数据的容器。在 Java 中，每个变量都必须有一个明确的 **数据类型**。

### 2.1. 基本数据类型 (Primitive Types)

Java 有 8 种基本数据类型，它们是语言内置的，并非对象。

| 类型      | 大小    | 描述         | 默认值 | 示例                  |
| :-------- | :------ | :----------- | :----- | :-------------------- |
| `byte`    | 1 字节  | 整数         | `0`    | `byte b = 100;`       |
| `short`   | 2 字节  | 整数         | `0`    | `short s = 30000;`    |
| `int`     | 4 字节  | 整数（最常用） | `0`    | `int i = 2000000000;` |
| `long`    | 8 字节  | 长整数       | `0L`   | `long l = 9000L;`     |
| `float`   | 4 字节  | 单精度浮点数 | `0.0f` | `float f = 3.14f;`    |
| `double`  | 8 字节  | 双精度浮点数 | `0.0d` | `double d = 3.14159;` |
| `char`    | 2 字节  | 单个字符     | `\u0000` | `char c = 'A';`       |
| `boolean` | 1 位    | 布尔值       | `false`| `boolean flag = true;`|

**注意**:
*   定义 `long` 类型变量时，建议在数值后加上 `L`。
*   定义 `float` 类型变量时，必须在数值后加上 `f`，因为小数默认是 `double` 类型。

### 2.2. 引用数据类型 (Reference Types)

除了基本类型外，其他所有类型都是引用类型，它们指向内存中的一个对象。
*   **类 (Class)**: 如我们自定义的 `HelloWorld`，或者 Java 提供的 `String`。
*   **接口 (Interface)**
*   **数组 (Array)**

```java
String greeting = "Hello, Java!"; // String 是一个非常常用的引用类型
int[] numbers = {1, 2, 3, 4, 5}; // 数组也是引用类型
```

### 2.3. 类型转换 (Type Casting)

*   **自动类型转换 (隐式)**:从小范围类型到大范围类型可以自动转换。
    `int i = 100; long l = i; // 自动转换`
*   **强制类型转换 (显式)**: 从大范围类型到小范围类型需要强制转换，可能导致精度丢失。
    `double d = 99.9; int i = (int) d; // 强制转换，i 的值为 99`

---

## 3. 运算符

运算符是用于执行计算和逻辑操作的特殊符号。

*   **算术运算符**: `+`, `-`, `*`, `/` (除), `%` (取模/取余)
*   **赋值运算符**: `=`, `+=`, `-=`, `*=`, `/=`
*   **关系运算符**: `==` (等于), `!=` (不等于), `>`, `<`, `>=`, `<=` (结果总是 `boolean` 值)
*   **逻辑运算符**: `&&` (逻辑与), `||` (逻辑或), `!` (逻辑非)
    *   `&&` 和 `||` 具有 **短路** 特性。例如 `a && b`，如果 `a` 为 `false`，则不会再计算 `b`。
*   **自增/自减运算符**: `++`, `--`
    *   `a++`: 先用 `a` 的值，再将 `a` 加 1。
    *   `++a`: 先将 `a` 加 1，再使用 `a` 的值。

---

## 4. 控制流

控制流语句决定了程序执行的顺序。

### 4.1. 条件语句

*   **`if-else`**:
    ```java
    int score = 85;
    if (score >= 90) {
        System.out.println("优秀");
    } else if (score >= 60) {
        System.out.println("及格");
    } else {
        System.out.println("不及格");
    }
    ```
*   **`switch`**: 适用于对固定几个值的判断。
    ```java
    int day = 3;
    String dayName;
    switch (day) {
        case 1: dayName = "星期一"; break;
        case 2: dayName = "星期二"; break;
        case 3: dayName = "星期三"; break;
        // ...
        default: dayName = "未知"; break;
    }
    // 从 Java 14 开始，可以使用更简洁的 switch 表达式
    String dayNameModern = switch (day) {
        case 1 -> "星期一";
        case 2 -> "星期二";
        // ...
        default -> "未知";
    };
    ```
    **注意**: `switch` 的 `case` 后面如果没有 `break`，会发生 **穿透** 现象，即继续执行下一个 `case` 的代码。

### 4.2. 循环语句

*   **`for` 循环**: 适用于已知循环次数的场景。
    ```java
    for (int i = 0; i < 5; i++) {
        System.out.println("当前数字: " + i);
    }
    ```
*   **增强 `for` 循环 (For-Each Loop)**: 用于遍历数组或集合。
    ```java
    int[] numbers = {10, 20, 30};
    for (int number : numbers) {
        System.out.println(number);
    }
    ```
*   **`while` 循环**: 先判断条件，再执行循环体。
    ```java
    int count = 0;
    while (count < 3) {
        System.out.println("循环中...");
        count++;
    }
    ```
*   **`do-while` 循环**: 先执行一次循环体，再判断条件。确保循环体至少执行一次。
    ```java
    int num = 5;
    do {
        System.out.println("这个至少会执行一次");
    } while (num < 3);
    ```

### 4.3. `break` 和 `continue`

*   `break`: 立即跳出并终止 **当前整个** 循环。
*   `continue`: 立即跳过 **当前本次** 循环，直接开始下一次循环。

---

## 5. 方法 (Methods)

方法是一段可重复使用的代码块，用于执行特定任务。

```java
public class Calculator {
    // 定义一个名为 add 的方法
    // public: 访问修饰符
    // int: 返回值类型
    // add: 方法名
    // (int a, int b): 参数列表
    public int add(int a, int b) {
        return a + b; // 返回计算结果
    }

    // 一个没有返回值的方法
    public void printMessage(String message) {
        System.out.println(message);
    }
}
```
**方法重载 (Overloading)**: 在同一个类中，允许存在多个同名方法，但它们的参数列表必须不同（参数个数、类型或顺序不同）。

---

## 6. 数组 (Arrays)

数组是用于存储固定大小的、同类型元素的集合。

```java
// 1. 声明并初始化
int[] scores = new int[10]; // 创建一个长度为 10 的 int 数组，默认值为 0
String[] names = {"张三", "李四", "王五"}; // 静态初始化

// 2. 访问元素（通过索引）
scores[0] = 99; // 索引从 0 开始
System.out.println(names[1]); // 输出 "李四"

// 3. 获取长度
System.out.println(scores.length); // 输出 10
```

---

## 7. 常用 API 预览

### `String` 类

`String` 对象是不可变的 (`immutable`)。
```java
String s1 = "hello";
String s2 = s1.toUpperCase(); // s1 的值仍然是 "hello", s2 的值是 "HELLO"

s1.length();      // 获取长度
s1.equals("HELLO"); // 比较内容 (区分大小写)
s1.equalsIgnoreCase("HELLO"); // 比较内容 (不区分大小写)
s1.contains("he"); // 是否包含子串
s1.substring(1, 3); // 截取子串 (从索引1到3，不包括3) -> "el"
```

### `StringBuilder` 类
当需要频繁修改字符串内容时，应使用 `StringBuilder`，因为它的效率更高。
```java
StringBuilder sb = new StringBuilder();
sb.append("Hello");
sb.append(", ");
sb.append("Java!");
String result = sb.toString(); // "Hello, Java!"
```

本章内容是 Java 编程的绝对核心，请务必反复练习，直到完全掌握。 