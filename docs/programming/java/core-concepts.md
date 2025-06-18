# 2. 核心概念回顾

在深入企业级框架和工具之前，稳固地掌握 Java 的核心概念是至关重要的。本章将快速回顾面向对象编程（OOP）、集合框架和并发编程基础，这些都是构建复杂、健壮应用的基础。

## 2.1. 面向对象编程 (OOP)

Java 是一种纯粹的面向对象编程语言。企业级开发中的所有框架，如 Spring，都构建在 OOP 原则之上。

### 封装 (Encapsulation)

-   **定义**: 将数据（属性）和操作数据的方法（行为）捆绑到一个单独的单元（类）中，并对外部隐藏内部实现细节。
-   **实现**: 使用 `private` 关键字限制对属性的直接访问，并通过 `public` 的 `getter` 和 `setter` 方法来暴露受控的访问点。
-   **企业级应用中的重要性**:
    -   **模块化**: 易于维护和理解。例如，一个 `UserService` 类封装了所有与用户相关的业务逻辑。
    -   **安全性**: 防止外部代码随意修改对象状态，保证数据一致性。

```java
public class User {
    private Long id;
    private String username;

    // Getter
    public String getUsername() {
        return username;
    }

    // Setter
    public void setUsername(String username) {
        if (username != null && !username.trim().isEmpty()) {
            this.username = username;
        }
    }
}
```

### 继承 (Inheritance)

-   **定义**: 一个类（子类）可以继承另一个类（父类）的属性和方法，从而实现代码复用。
-   **实现**: 使用 `extends` 关键字。
-   **企业级应用中的重要性**:
    -   **代码复用**: 创建一个基础的 `BaseController` 或 `BaseEntity`，让其他具体类继承通用行为。
    -   **多态**: 允许将子类对象视为父类类型，是框架实现松耦合的关键。

```java
// 父类
public abstract class BaseEntity {
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    // ... getters and setters
}

// 子类
public class Product extends BaseEntity {
    private String name;
    // ... Product-specific fields and methods
}
```

### 多态 (Polymorphism)

-   **定义**: 同一个接口或父类，使用不同的实例执行操作时，会产生不同的行为。
-   **实现**: 方法重写（Overriding）和接口实现（Implementing）。
-   **企业级应用中的重要性**:
    -   **松耦合和灵活性**: Spring 的依赖注入（DI）严重依赖多态。你可以轻松地将一个 `ServiceImpl` 替换为另一个实现了相同 `Service` 接口的类，而无需修改调用方的代码。
    -   **可扩展性**: 允许系统在不修改现有代码的情况下添加新功能。

```java
public interface PaymentGateway {
    void processPayment(BigDecimal amount);
}

public class PayPalGateway implements PaymentGateway {
    @Override
    public void processPayment(BigDecimal amount) {
        System.out.println("Processing payment with PayPal: " + amount);
    }
}

public class StripeGateway implements PaymentGateway {
    @Override
    public void processPayment(BigDecimal amount) {
        System.out.println("Processing payment with Stripe: " + amount);
    }
}

// 在服务中使用
public class OrderService {
    private final PaymentGateway paymentGateway;

    // 通过依赖注入传入具体的实现
    public OrderService(PaymentGateway paymentGateway) {
        this.paymentGateway = paymentGateway;
    }

    public void checkout(Order order) {
        paymentGateway.processPayment(order.getTotalAmount());
    }
}
```

## 2.2. 数据结构与集合框架

Java 集合框架（Java Collections Framework）提供了一套性能优良、使用方便的接口和类来处理对象组。

-   **`List`**: 有序集合，允许重复元素。
    -   `ArrayList`: 基于动态数组实现，查询快，增删慢。**最常用**。
    -   `LinkedList`: 基于双向链表实现，查询慢，增删快。
-   **`Set`**: 不允许重复元素的集合。
    -   `HashSet`: 基于哈希表实现，无序。
    -   `LinkedHashSet`: 维持插入顺序。
    -   `TreeSet`: 基于红黑树实现，元素自然排序或根据比较器排序。
-   **`Map`**: 存储键值对（Key-Value）的集合，键唯一。
    -   `HashMap`: 基于哈希表实现，无序。**最常用**。
    -   `LinkedHashMap`: 维持插入顺序或访问顺序。
    -   `TreeMap`: 根据键进行排序。
    -   `ConcurrentHashMap`: 线程安全的 `HashMap`，用于高并发环境。

**企业级应用选型建议**:
-   大多数情况下，使用 `ArrayList` 和 `HashMap`。
-   当需要保证元素唯一性时，使用 `HashSet`。
-   当需要排序时，使用 `TreeSet` 或 `TreeMap`。
-   在多线程环境下共享数据时，优先考虑 `ConcurrentHashMap`。

## 2.3. 并发编程基础

现代企业级应用通常是高并发的，需要同时处理大量用户请求。

-   **`Thread` 与 `Runnable`**: 创建和管理线程的基础。在现代 Java 中，我们很少直接创建 `Thread`，而是使用更高级的并发 API。
-   **Executor Framework**:
    -   **`ExecutorService`**: 线程池的管理接口，用于解耦任务提交和执行。
    -   **`Executors`**: 创建不同类型线程池的工厂类（如 `newFixedThreadPool`, `newCachedThreadPool`）。
    -   **`Future` 和 `Callable`**: `Callable` 用于有返回值的任务，`Future` 代表异步计算的结果。
-   **`synchronized` 关键字**: 提供简单的同步机制，确保同一时间只有一个线程可以访问特定代码块或方法。
-   **`java.util.concurrent` 包**:
    -   **Locks**: `ReentrantLock` 提供了比 `synchronized` 更灵活的锁机制。
    -   **Atomics**: `AtomicInteger`, `AtomicLong` 等原子类，通过 CAS (Compare-And-Swap) 操作保证单个变量的线程安全，性能通常优于锁。
    -   **Concurrent Collections**: 如 `ConcurrentHashMap`, `CopyOnWriteArrayList`。

**企业级应用实践**:
-   **使用线程池**: 避免频繁创建和销毁线程带来的开销。Spring Boot 已经为你自动配置了用于处理 Web 请求的线程池（如 Tomcat 的线程池）。
-   **优先使用 `java.util.concurrent`**: 这个包提供了比 `synchronized` 和 `wait/notify` 更高级、更可靠的并发工具。
-   **理解线程安全**: 明确哪些对象是线程安全的（如 Servlet 是单例多线程，其成员变量不安全），哪些不是。无状态服务（Stateless Service）是保证线程安全的最佳实践。

---

对这些核心概念的深入理解，将帮助你更好地学习和使用 Spring 等企业级框架，编写出更高质量、更易维护的代码。 