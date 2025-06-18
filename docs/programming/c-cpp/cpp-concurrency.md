# 现代 C++: 并发编程

从 C++11 开始，C++ 标准库正式引入了对多线程编程的原生支持。这意味着开发者可以编写跨平台的、标准化的并发代码，而无需依赖特定于操作系统的 API（如 POSIX Threads 或 Windows Threads）。本节将介绍 C++ 并发编程的基础构件。

相关的头文件主要有：
-   `<thread>`: 包含 `std::thread` 类及相关函数。
-   `<mutex>`: 包含互斥量（Mutex）相关的类，用于保护共享数据。
-   `<condition_variable>`: 包含条件变量，用于线程间的同步。
-   `<future>`: 提供了 `std::async`, `std::future`, `std::promise` 等工具，用于管理异步任务。
-   `<atomic>`: 包含了原子类型 `std::atomic`，用于无锁的原子操作。

## 1. `std::thread`

`std::thread` 是 C++ 线程库的核心。创建一个 `std::thread` 对象并为其提供一个可调用对象（函数、Lambda 表达式或函数对象），新的执行线程就会立即启动。

**关键操作**:
-   **`join()`**: 主线程等待子线程执行完毕。这是一个阻塞操作。一个 `joinable` 的线程**必须**在销毁前被 `join()` 或 `detach()`。
-   **`detach()`**: 将子线程从 `std::thread` 对象上分离，允许子线程独立执行。一旦分离，主线程就无法再与该子线程交互。

```cpp
#include <iostream>
#include <thread>
#include <chrono>

// 线程要执行的函数
void task(int id) {
    for (int i = 0; i < 5; ++i) {
        std::cout << "Task " << id << " is running, step " << i << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

int main() {
    std::cout << "Main thread started." << std::endl;

    // 创建并启动一个新线程
    std::thread t1(task, 1);

    // 使用 Lambda 表达式创建另一个线程
    std::thread t2([]() {
        std::cout << "Task 2 (from lambda) started." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "Task 2 (from lambda) finished." << std::endl;
    });

    // 等待 t1 线程执行完成
    t1.join();
    // 等待 t2 线程执行完成
    t2.join();

    std::cout << "Main thread finished." << std::endl;
    return 0;
}
```

## 2. 共享数据与竞争条件

当多个线程访问和修改同一个共享数据时，就会产生**竞争条件**（Race Condition），其结果取决于线程执行的时序，通常会导致程序错误和数据损坏。

```cpp
#include <iostream>
#include <thread>
#include <vector>

long long counter = 0;

void increment() {
    for (int i = 0; i < 100000; ++i) {
        counter++; // 危险！这不是原子操作
    }
}

int main() {
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.push_back(std::thread(increment));
    }

    for (auto& t : threads) {
        t.join();
    }

    // 结果几乎肯定不是 1,000,000
    std::cout << "Final counter value: " << counter << std::endl;
    return 0;
}
```
`counter++` 看似简单，但实际上至少包含三个步骤：1. 读取 `counter` 的值到寄存器；2. 寄存器中的值加一；3. 将新值写回 `counter`。多个线程的这三个步骤可能交错执行，导致更新丢失。

## 3. 使用互斥量 (`std::mutex`) 保护共享数据

**互斥量**（Mutex）是解决竞争条件最基本的工具。它确保在任何时刻，只有一个线程可以访问被保护的共享资源。

-   **`lock()`**: 获取锁。如果锁已被其他线程持有，则当前线程阻塞，直到获得锁。
-   **`unlock()`**: 释放锁。

为了简化互斥量的使用并确保在任何情况下（包括异常）都能正确释放锁，C++ 提供了 RAII 风格的锁守护（Lock Guards）。

-   **`std::lock_guard`**: 在构造时自动上锁，在析构时（离开作用域）自动解锁。这是最简单、最常用的锁机制。
-   **`std::unique_lock`**: 功能更强大的锁守护，支持延迟上锁、尝试上锁和移动所有权，常与条件变量配合使用。

### `std::lock_guard` 示例

```cpp
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>

long long counter = 0;
std::mutex mtx; // 创建一个互斥量

void safe_increment() {
    for (int i = 0; i < 100000; ++i) {
        std::lock_guard<std::mutex> guard(mtx); // 进入临界区，自动上锁
        counter++;
    } // 离开作用域，guard 被销毁，自动解锁
}

int main() {
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.push_back(std::thread(safe_increment));
    }

    for (auto& t : threads) {
        t.join();
    }

    // 结果总是 1,000,000
    std::cout << "Final counter value: " << counter << std::endl;
    return 0;
}
```

## 4. 原子操作 (`std::atomic`)

对于简单的计数器或标志位等场景，使用互斥量可能显得"过重"。`std::atomic` 提供了一种无锁（lock-free）的替代方案。

`std::atomic<T>` 将类型 `T` 的操作封装为不可分割的原子操作，确保在多线程环境下不会被打断。

```cpp
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>

// 使用原子类型
std::atomic<long long> atomic_counter = 0;

void atomic_increment() {
    for (int i = 0; i < 100000; ++i) {
        atomic_counter++; // 这是一个原子操作
    }
}

int main() {
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.push_back(std::thread(atomic_increment));
    }

    for (auto& t : threads) {
        t.join();
    }

    // 结果总是 1,000,000
    std::cout << "Final counter value: " << atomic_counter << std::endl;
    return 0;
}
```
当平台支持时，原子操作通常比使用互斥量更高效，但它们只适用于单一变量的简单操作。

## 总结

C++ 的并发支持是一个广阔的话题，还包括条件变量（`std::condition_variable`）用于更复杂的线程同步，以及 `std::future` 和 `std::async` 用于处理异步任务的返回值。

-   使用 `std::thread` 创建和管理线程。
-   识别共享数据，并使用 `std::mutex`（配合 `std::lock_guard`）来防止竞争条件。
-   对于简单的类型（如整数、布尔值、指针），优先考虑使用 `std::atomic` 以获得更好的性能。
-   始终确保 `join()` 或 `detach()` 你的线程，以避免程序异常终止。

掌握这些基础工具是编写正确、高效的现代 C++ 并发程序的起点。 