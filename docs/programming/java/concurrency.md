# Java 并发编程

并发编程是指在单个程序中同时执行多个独立任务的能力。现代处理器大多是多核的，利用并发可以充分发挥硬件性能，提高应用程序的响应能力和吞吐量。Java 提供了强大的内置支持来进行并发编程，主要集中在 `java.util.concurrent` (JUC) 包中。

## 1. 基本概念

-   **进程 (Process)**: 操作系统进行资源分配和调度的基本单位，是应用程序的运行实例。每个进程都有自己独立的内存空间。
-   **线程 (Thread)**: 进程中的一个执行单元，是 CPU 调度的最小单位。一个进程可以包含多个线程，它们共享进程的内存空间（堆、方法区），但每个线程有自己的程序计数器、虚拟机栈和本地方法栈。
-   **线程安全 (Thread Safety)**: 当多个线程访问某个类时，不管运行时环境如何调度，也不管这些线程如何交替执行，并且在主调代码中不需要任何额外的同步或协调，这个类都能表现出正确的行为，那么就称这个类是线程安全的。

---

## 2. 创建线程

创建线程主要有两种方式：

1.  **继承 `Thread` 类**:
    ```java
    class MyThread extends Thread {
        public void run() {
            System.out.println("MyThread is running.");
        }
    }
    // 启动
    MyThread t = new MyThread();
    t.start(); // 调用 start() 方法，而不是 run()
    ```

2.  **实现 `Runnable` 接口** (推荐):
    ```java
    class MyRunnable implements Runnable {
        public void run() {
            System.out.println("MyRunnable is running.");
        }
    }
    // 启动
    Thread t = new Thread(new MyRunnable());
    t.start();
    ```
    **推荐使用 `Runnable`**，因为它将任务（`Runnable`）与执行机制（`Thread`）解耦，并且 Java 不支持多重继承，实现接口更为灵活。

从 Java 8 开始，可以使用 Lambda 表达式简化：
```java
Thread t = new Thread(() -> System.out.println("Lambda is running."));
t.start();
```

---

## 3. 线程同步：`synchronized` 与 `volatile`

当多个线程共享数据时，必须进行同步以避免数据损坏和不一致。

### 3.1. `synchronized` 关键字

`synchronized` 提供了一种内置的锁机制，可以确保同一时刻只有一个线程可以执行某段代码或访问某个方法。

-   **同步实例方法**: `public synchronized void method() { ... }`
    -   锁是当前类的实例对象 (`this`)。

-   **同步静态方法**: `public static synchronized void method() { ... }`
    -   锁是当前类的 `Class` 对象。

-   **同步代码块**:
    ```java
    public void method() {
        // 锁可以是任何对象，通常是 this 或一个专门的 final 对象
        Object lock = new Object();
        synchronized(lock) {
            // ... 需要同步的代码 ...
        }
    }
    ```
`synchronized` 保证了 **原子性**、**可见性** 和 **有序性**。

### 3.2. `volatile` 关键字

`volatile` 是一个轻量级的同步机制，它只保证了 **可见性** 和一定程度的 **有序性**，但 **不保证原子性**。

-   **可见性**: 当一个线程修改了 `volatile` 变量的值，新值对其他线程是立即可见的。
-   **应用场景**: 通常用于一个线程写、多个线程读的场景，或者作为状态标记。

```java
private volatile boolean running = true;

public void stop() {
    running = false; // 线程A调用
}

public void work() {
    while (running) { // 线程B会立即看到 running 的变化
        // ...
    }
}
```

---

## 4. `java.util.concurrent` (JUC) 核心组件

`synchronized` 功能有限，JUC 包提供了更强大、更灵活的并发工具。

### 4.1. Lock 接口

`java.util.concurrent.locks.Lock` 提供了比 `synchronized` 更丰富的锁操作。

-   **`ReentrantLock`**: 一个可重入的互斥锁，功能与 `synchronized` 类似，但更灵活。
    -   可以尝试非阻塞地获取锁 (`tryLock()`)。
    -   可以响应中断。
    -   可以实现公平锁。

```java
private final ReentrantLock lock = new ReentrantLock();

public void performTask() {
    lock.lock(); // 获取锁
    try {
        // ... 保护的业务逻辑 ...
    } finally {
        lock.unlock(); // 必须在 finally 块中释放锁
    }
}
```

### 4.2. Executor 框架 (线程池)

频繁地创建和销毁线程开销很大。**线程池** 是一种管理和复用线程的机制，可以显著提高性能。

`ExecutorService`是线程池的核心接口。`Executors` 是一个工具类，提供了创建不同类型线程池的静态方法：

-   `Executors.newFixedThreadPool(int n)`: 创建一个固定大小的线程池。
-   `Executors.newCachedThreadPool()`: 创建一个可缓存的线程池，大小根据需要自动调整。
-   `Executors.newSingleThreadExecutor()`: 创建一个只有一个线程的线程池。

```java
// 创建一个固定大小的线程池
ExecutorService executor = Executors.newFixedThreadPool(10);

for (int i = 0; i < 100; i++) {
    executor.submit(() -> { // 提交任务
        System.out.println("Task running in thread: " + Thread.currentThread().getName());
    });
}

executor.shutdown(); // 关闭线程池
```

### 4.3. 原子类 (Atomic)

`java.util.concurrent.atomic` 包提供了一系列原子操作类，如 `AtomicInteger`、`AtomicLong`、`AtomicBoolean`。

它们利用了现代 CPU 的 **CAS (Compare-And-Swap)** 指令，可以在不使用锁的情况下，以非阻塞的方式实现线程安全的数据更新，性能通常比 `synchronized` 好。

```java
private AtomicInteger count = new AtomicInteger(0);

public void increment() {
    count.incrementAndGet(); // 原子地加1
}
```

### 4.4. 并发集合

`java.util.concurrent` 还提供了多种线程安全的集合类，性能远超于使用 `Collections.synchronized...` 包装的传统集合。

-   **`ConcurrentHashMap`**: 高性能的线程安全哈希表。它使用分段锁技术，允许多个线程同时读写不同的段，并发度很高。
-   **`CopyOnWriteArrayList`**: 线程安全的 `List`。写入时，它会复制一份底层数组，在新数组上修改，然后将引用指向新数组。**读操作完全无锁**，适合"读多写少"的场景。
-   **`BlockingQueue`**: 阻塞队列接口。当队列满时，尝试入队的线程会被阻塞；当队列空时，尝试出队的线程会被阻塞。是实现 **生产者-消费者** 模式的利器。

并发编程是一个庞大而深入的领域，掌握 JUC 包是成为 Java 高级开发者的必经之路。
