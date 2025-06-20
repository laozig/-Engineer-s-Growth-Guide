# JVM 虚拟机

Java 虚拟机 (Java Virtual Machine, JVM) 是 Java 实现"一次编译，到处运行"（Write Once, Run Anywhere）的核心。它是一个抽象的计算模型，提供了一个独立于底层硬件和操作系统的运行时环境。

## 1. JVM 体系结构

JVM 主要由以下几个部分组成：
1.  **类加载器 (Class Loader)**: 负责加载 `.class` 文件。
2.  **运行时数据区 (Runtime Data Areas)**: JVM 管理的内存区域。
3.  **执行引擎 (Execution Engine)**: 负责执行字节码。
4.  **本地方法接口 (Native Method Interface)**: 用于与本地（非 Java）代码交互。

```mermaid
graph TD
    subgraph "JVM"
        A[类加载器 Class Loader] --> B{运行时数据区<br/>Runtime Data Areas};
        C[执行引擎 Execution Engine] --> B;
        C --> D[本地方法接口<br/>Native Method Interface];
    end

    subgraph "运行时数据区"
        direction LR
        E[方法区<br/>Method Area] --- F[堆<br/>Heap];
        G[虚拟机栈<br/>VM Stack] --- H[本地方法栈<br/>Native Method Stack] --- I[程序计数器<br/>PC Register];
    end

    B --> E;
    B --> F;
    B --> G;
    B --> H;
    B --> I;

    subgraph "线程共享"
      E; F;
    end
    subgraph "线程私有"
      G; H; I;
    end
```

---

## 2. 运行时数据区详解

这是 JVM 内存管理的核心。

### 2.1. 线程私有区域

每个线程创建时都会分配这些区域。

-   **程序计数器 (PC Register)**:
    -   一块较小的内存空间，可以看作是当前线程所执行的字节码的行号指示器。
    -   如果线程正在执行的是一个 Java 方法，这个计数器记录的是正在执行的虚拟机字节码指令的地址；如果正在执行的是 Native 方法，这个计数器值则为空 (Undefined)。
    -   **此内存区域是唯一一个在 Java 虚拟机规范中没有规定任何 `OutOfMemoryError` 情况的区域。**

-   **Java 虚拟机栈 (Java Virtual Machine Stack)**:
    -   用于存储 **栈帧 (Stack Frame)**。每个方法在执行时都会创建一个栈帧。
    -   栈帧中包含：**局部变量表**、操作数栈、动态链接、方法返回地址等信息。
    -   我们常说的"栈内存"指的就是这里。
    -   可能抛出 `StackOverflowError` (线程请求的栈深度大于允许的深度) 和 `OutOfMemoryError`。

-   **本地方法栈 (Native Method Stack)**:
    -   与虚拟机栈类似，但它是为虚拟机使用到的 Native 方法服务的。

### 2.2. 线程共享区域

所有线程共享这些数据区域。

-   **堆 (Heap)**:
    -   JVM 所管理的内存中最大的一块。
    -   **几乎所有的对象实例以及数组都在这里分配内存。**
    -   是垃圾收集器 (GC) 管理的主要区域。
    -   可以细分为：新生代 (Young Generation) 和老年代 (Old Generation)。新生代又可以分为 Eden 区、From Survivor 区、To Survivor 区。

-   **方法区 (Method Area)**:
    -   用于存储已被虚拟机加载的 **类信息、常量、静态变量、即时编译器编译后的代码** 等数据。
    -   也称为"永久代"(Permanent Generation)（在 HotSpot JVM for JDK 7 及之前），但在 JDK 8 中被 **元空间 (Metaspace)** 取代，元空间使用的是本地内存，而不是 JVM 内存。

---

## 3. 垃圾收集 (Garbage Collection, GC)

GC 是 JVM 的一项核心功能，它自动管理内存，回收不再被任何引用指向的对象所占用的空间。

### 3.1. 如何判断对象已"死"？

1.  **引用计数法 (Reference Counting)**:
    -   给对象添加一个引用计数器，每当有一个地方引用它，计数器就加1；当引用失效，计数器就减1。
    -   **缺点**: 无法解决对象之间循环引用的问题。**Java 不使用此方法。**

2.  **可达性分析算法 (Reachability Analysis)**:
    -   通过一系列称为 "GC Roots" 的对象作为起始点，从这些节点开始向下搜索，搜索所走过的路径称为引用链。当一个对象到 GC Roots 没有任何引用链相连时，则证明此对象是不可用的。
    -   **Java 使用此方法。**
    -   **GC Roots** 包括：虚拟机栈中引用的对象、方法区中静态属性引用的对象、方法区中常量引用的对象、本地方法栈中 JNI 引用的对象等。

### 3.2. 常见 GC 算法

-   **标记-清除 (Mark-Sweep)**:
    -   首先标记出所有需要回收的对象，然后统一回收。
    -   **缺点**: 效率不高，会产生大量不连续的内存碎片。

-   **标记-复制 (Mark-Copy)**:
    -   将可用内存分为两块，每次只使用其中一块。当这一块内存用完，就将还存活着的对象复制到另一块上面，然后再把已使用过的内存空间一次清理掉。
    -   **优点**: 实现简单，运行高效，不会有碎片。
    -   **缺点**: 内存使用率低，代价是牺牲一半的内存。**常用于新生代 GC**。

-   **标记-整理 (Mark-Compact)**:
    -   标记过程与"标记-清除"一样，但后续步骤不是直接对可回收对象进行清理，而是让所有存活的对象都向一端移动，然后直接清理掉端边界以外的内存。
    -   **优点**: 解决了碎片问题。**常用于老年代 GC**。

### 3.3. 分代收集 (Generational Collection)

现代商业虚拟机普遍采用分代收集算法。它根据对象存活周期的不同将内存划分为几块，一般是新生代和老年代，然后根据各个年代的特点采用最适当的收集算法。

-   **新生代 (Young Generation)**: 大量对象创建后很快消亡。使用 **标记-复制** 算法。
-   **老年代 (Old Generation)**: 对象存活率高。使用 **标记-清除** 或 **标记-整理** 算法。

---

## 4. 类加载机制

类加载器负责将 `.class` 文件（字节码）加载到 JVM 的运行时数据区。

### 4.1. 类加载过程

1.  **加载 (Loading)**: 查找并加载类的二进制数据。
2.  **验证 (Verification)**: 确保被加载的类的正确性。
3.  **准备 (Preparation)**: 为类的静态变量分配内存，并将其初始化为默认值。
4.  **解析 (Resolution)**: 把类中的符号引用转换为直接引用。
5.  **初始化 (Initialization)**: 对类的静态变量，静态代码块执行初始化操作。

### 4.2. 双亲委派模型 (Parents Delegation Model)

这是 Java 推荐的类加载器工作模式。

-   **启动类加载器 (Bootstrap ClassLoader)**: 负责加载 `JAVA_HOME/lib` 目录下的核心库。
-   **扩展类加载器 (Extension ClassLoader)**: 负责加载 `JAVA_HOME/lib/ext` 目录下的扩展库。
-   **应用程序类加载器 (Application ClassLoader)**: 负责加载用户类路径 (Classpath) 上的类。

**工作过程**: 如果一个类加载器收到了类加载的请求，它首先不会自己去尝试加载这个类，而是把这个请求委派给父类加载器去完成。因此所有的加载请求最终都应该传送到顶层的启动类加载器中。只有当父加载器反馈自己无法完成这个加载请求时，子加载器才会尝试自己去加载。

**好处**: 避免类的重复加载，并保证 Java 核心库的类型安全（例如，防止用户自己写一个 `java.lang.String` 来替代系统核心的 `String`）。
