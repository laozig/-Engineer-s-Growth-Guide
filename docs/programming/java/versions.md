# 附录：Java 版本新特性 (8, 11, 17, 21+)

Java 在不断发展，自 Java 8 引入里程碑式的变革后，发布周期变为每六个月一个新版本，并且每两年（自 Java 17 起）发布一个新的长期支持（LTS）版本。了解这些新特性对于编写现代化、简洁和高效的 Java 代码至关重要。

本附录重点介绍自 Java 8 以来的主要 LTS 版本的新特性。

---

## 1. Java 8 (LTS) - 革命性的版本

Java 8 是继 Java 5 (引入泛型) 之后最重要的一个版本，它引入了函数式编程的理念。

-   **Lambda 表达式**:
    -   允许你将函数作为方法参数，或者将代码作为数据。极大地简化了匿名内部类的写法。
    -   `(parameters) -> expression` 或 `(parameters) -> { statements; }`
-   **Stream API**:
    -   对集合（Collection）进行链式、函数式操作的强大 API。支持 `filter`, `map`, `reduce`, `collect` 等操作。
    -   可以轻松实现并行处理 (`parallelStream()`)。
-   **接口的默认方法和静态方法**:
    -   允许在接口中提供方法的默认实现 (`default` 方法)，使得在不破坏现有实现类的情况下为接口添加新功能成为可能。
-   **`Optional` 类**:
    -   一个容器对象，可能包含也可能不包含非空值。旨在优雅地处理 `null` 值，避免 `NullPointerException`。
-   **新的日期和时间 API (`java.time`)**:
    -   一个全新的、不可变的、线程安全的日期时间处理库，全面取代了问题多多的 `java.util.Date` 和 `java.util.Calendar`。

---

## 2. Java 11 (LTS) - 稳健的改进

Java 11 是 Java 8 之后的第一个 LTS 版本，它在语言和 API 层面都带来了许多有用的改进。

-   **新的 `String` 方法**:
    -   `isBlank()`: 判断字符串是否为空白。
    -   `lines()`: 将字符串按行分隔符转换为 Stream。
    -   `strip()`, `stripLeading()`, `stripTrailing()`: 去除首尾空白（比 `trim()` 更智能，能识别 Unicode 空白字符）。
    -   `repeat(n)`: 将字符串重复 n 次。
-   **用于 Lambda 参数的局部变量语法 (`var`)**:
    -   可以在 Lambda 表达式的参数列表中使用 `var` 关键字，以保持与其他局部变量声明的一致性。
    -   `(@NonNull var s1, @Nullable var s2) -> s1 + s2`
-   **新的 `File` 方法**:
    -   `readString()` 和 `writeString()`: 简化了文件的读写操作。
-   **标准的 HTTP Client API (`java.net.http`)**:
    -   一个现代化的、支持同步和异步编程的 HTTP 客户端，用于取代老旧的 `HttpURLConnection`。
-   **启动单文件源代码程序**:
    -   可以直接通过 `java MyClass.java` 命令来运行一个单文件程序，无需先手动编译。

---

## 3. Java 17 (LTS) - 现代化的新特性

Java 17 带来了更多令人兴奋的语言特性，进一步提升了开发效率和代码可读性。

-   **Records (记录类)**:
    -   一种用于创建不可变数据载体的简洁语法。编译器会自动为你生成构造函数、`equals()`、`hashCode()`、`toString()` 以及字段的访问器。
    -   `public record Point(int x, int y) { }`
-   **Sealed Classes and Interfaces (密封类和接口)**:
    -   允许你限制哪些类或接口可以扩展或实现它们。这为领域建模提供了更强的控制力。
    -   与模式匹配结合使用，可以让编译器检查 `switch` 表达式是否覆盖了所有允许的子类型。
-   **Pattern Matching for `instanceof` (instanceof 的模式匹配)**:
    -   简化了 `instanceof` 类型检查和转换的写法。
    -   **旧**: `if (obj instanceof String) { String s = (String) obj; ... }`
    -   **新**: `if (obj instanceof String s) { ... }`
-   **Switch 表达式的增强**:
    -   `switch` 可以作为表达式返回值。
    -   可以使用箭头语法 (`->`)，无需 `break`。
    -   结合模式匹配，功能更加强大。

---

## 4. Java 21 (LTS) 及未来 (预览特性)

Java 21 带来了虚拟线程的最终版本，以及更多强大的预览特性，预示着 Java 未来的发展方向。

-   **Virtual Threads (虚拟线程)** - JEP 444:
    -   **最终版本**。这是一种由 JVM 管理的、极其轻量的线程，旨在显著提高高吞-吐量并发应用程序的编写、维护和可观测性。它使得传统的"一个请求一个线程"模型能够扩展到数百万个并发任务。
-   **Sequenced Collections (序列化集合)** - JEP 431:
    -   **最终版本**。为集合框架引入了新的接口，用于表示具有确定性出现顺序的集合。
-   **Scoped Values (作用域值)** - JEP 446 (预览):
    -   旨在在线程内和线程间共享不可变数据。是 `ThreadLocal` 变量的现代替代方案，尤其适用于虚拟线程。
-   **Structured Concurrency (结构化并发)** - JEP 453 (预览):
    -   通过将不同线程中运行的相关任务组视为单个工作单元来简化并发编程。
-   **Pattern Matching for `switch` (switch 的模式匹配)** - JEP 441:
    -   **最终版本**。进一步增强 `switch` 语句和表达式，允许对一个对象的多种模式进行测试。
-   **Unnamed Patterns and Variables (未命名模式和变量)** - JEP 443 (预览):
    -   当你需要一个变量但又不使用其值时，可以用下划线 (`_`) 代替，以提高代码清晰度。

保持对 Java 新版本的关注，并逐步在项目中采纳这些新特性，将使你的代码库保持现代化并充分利用 JVM 的最新优化。
