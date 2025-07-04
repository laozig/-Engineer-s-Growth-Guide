# Java 注解与反射

注解和反射是 Java 语言中两个强大但又高级的特性。它们共同为 Java 带来了动态性和元编程的能力，是许多现代框架（如 Spring, Hibernate）的基石。

## 1. 注解 (Annotation)

**注解**（也称为元数据）是添加到 Java 代码中的一种特殊"标签"，它本身不直接影响代码的执行，但可以被编译器或运行时环境读取和处理，从而实现某些特定的功能。

### 1.1. 内置注解

Java 提供了一些内置的注解：

-   `@Override`: 检查该方法是否是重写父类或实现接口的方 spé。如果不是，编译器会报错。
-   `@Deprecated`: 表示该方法或类已过时，不推荐使用。使用时编译器会发出警告。
-   `@SuppressWarnings`: 告诉编译器忽略指定的警告信息。
-   `@FunctionalInterface` (Java 8+): 标识一个接口是函数式接口（即只包含一个抽象方法）。

### 1.2. 自定义注解

我们可以创建自己的注解。使用 `@interface` 关键字来定义。

```java
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

// 1. 定义一个注解
@Target(ElementType.METHOD) // 指定该注解只能用于方法
@Retention(RetentionPolicy.RUNTIME) // 指定该注解在运行时可见，这样反射才能读取到
public @interface MyTest {
    // 可以定义注解的成员变量（也叫"元素"）
    String description() default "No description";
}
```

-   **元注解 (Meta-Annotations)**: 用于修饰其他注解的注解。
    -   `@Target`: 指定注解可以应用的目标元素类型（如类、方法、字段）。
    -   `@Retention`: 指定注解的生命周期。
        -   `RetentionPolicy.SOURCE`: 只在源码中保留，编译后丢弃。
        -   `RetentionPolicy.CLASS`: 保留在 `.class` 文件中，但 JVM 运行时不可见。
        -   `RetentionPolicy.RUNTIME`: 保留在运行时，可以通过反射读取。**这是最有用的策略。**

### 1.3. 使用注解

```java
public class MyTestFramework {

    @MyTest(description = "This is a test case.")
    public void testCase1() {
        // ... 测试逻辑 ...
        System.out.println("Executing testCase1");
    }

    @MyTest
    public void testCase2() {
        // ...
        System.out.println("Executing testCase2");
    }

    public void notATest() {
        // ...
    }
}
```

---

## 2. 反射 (Reflection)

**反射** 是 Java 提供的一种能力，允许程序在 **运行时** 动态地获取任意一个类的信息（如成员变量、构造方法、成员方法）并操作它们。

### 2.1. Class 对象

反射的入口点是 `java.lang.Class` 类的实例。每个加载到 JVM 中的类都有一个对应的 `Class` 对象。

获取 `Class` 对象的三种方式：

1.  **`ClassName.class`**: `Class<?> c1 = String.class;`
2.  **`instance.getClass()`**: `String s = "Hello"; Class<?> c2 = s.getClass();`
3.  **`Class.forName("fully.qualified.ClassName")`**: `Class<?> c3 = Class.forName("java.lang.String");` (会抛出 `ClassNotFoundException`)

### 2.2. 使用反射获取类信息

一旦有了 `Class` 对象，就可以探索类的内部结构。

```java
import java.lang.reflect.Method;
import java.lang.reflect.Field;

public class ReflectionDemo {
    public static void main(String[] args) throws Exception {
        Class<?> clazz = Class.forName("com.example.MyTestFramework");

        // 获取所有声明的方法
        for (Method method : clazz.getDeclaredMethods()) {
            System.out.println("Found method: " + method.getName());
        }
        
        // 获取所有声明的字段
        for (Field field : clazz.getDeclaredFields()) {
            System.out.println("Found field: " + field.getName());
        }
    }
}
```

### 2.3. 使用反射操作对象

反射最强大的地方在于可以动态地创建对象和调用方法。

-   **创建实例**: `clazz.getConstructor().newInstance()`
-   **调用方法**: `method.invoke(instance, args...)`
-   **访问字段**: `field.get(instance)` 和 `field.set(instance, value)`
    -   如果要访问私有成员，需要先调用 `member.setAccessible(true);` 来绕过访问权限检查。

---

## 3. 注解与反射的结合：实现一个测试框架

下面是一个简单的例子，演示了如何通过反射来查找并执行所有被 `@MyTest` 注解标记的方法。

```java
import java.lang.reflect.Method;

public class TestRunner {
    public static void main(String[] args) throws Exception {
        // 要测试的类的名字
        String className = "com.example.MyTestFramework";
        Class<?> clazz = Class.forName(className);

        // 创建实例
        Object instance = clazz.getConstructor().newInstance();

        // 遍历所有方法
        for (Method method : clazz.getDeclaredMethods()) {
            // 检查方法上是否有 @MyTest 注解
            if (method.isAnnotationPresent(MyTest.class)) {
                // 获取注解实例
                MyTest myTestAnnotation = method.getAnnotation(MyTest.class);
                System.out.println("--- Running Test ---");
                System.out.println("Description: " + myTestAnnotation.description());
                
                // 调用该方法
                method.invoke(instance);

                System.out.println("--- Test Finished ---");
            }
        }
    }
}
```

**输出**:
```
--- Running Test ---
Description: This is a test case.
Executing testCase1
--- Test Finished ---
--- Running Test ---
Description: No description
Executing testCase2
--- Test Finished ---
```

这个例子就是无数现代 Java 框架工作的缩影。它们通过扫描类路径，使用反射找到被特定注解标记的类、方法或字段，然后进行相应的处理（如依赖注入、路由映射、ORM 映射等）。

**警告**: 反射是一把双刃剑。它非常强大，但也破坏了封装性，并且性能开销较大。应仅在必要时使用，通常是在开发框架或需要高度动态性的通用库时。
