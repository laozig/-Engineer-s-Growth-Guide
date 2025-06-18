# Rust 并发编程

Rust 通过其所有权系统和类型系统在编译时就防止了许多并发编程中的常见错误，例如数据竞争。这使得编写安全且高效的并发代码成为可能，而无需担心传统多线程编程中的许多陷阱。Rust 的并发模型主要围绕两个核心概念展开：

1.  **线程 (Threads)**: 用于同时运行独立的代码片段。
2.  **消息传递 (Message Passing)**: 用于在线程之间安全地交换数据。
3.  **共享状态 (Shared State)**: 通过互斥锁（Mutex）和原子类型（Atomics）等同步原语来安全地访问共享内存。

## 1. 使用线程创建并发

`std::thread` 模块提供了创建新线程的功能。`thread::spawn` 函数接受一个闭包，并在一个新线程中执行它。

```rust
use std::thread;
use std::time::Duration;

fn main() {
    let handle = thread::spawn(|| {
        for i in 1..10 {
            println!("hi number {} from the spawned thread!", i);
            thread::sleep(Duration::from_millis(1));
        }
    });

    for i in 1..5 {
        println!("hi number {} from the main thread!", i);
        thread::sleep(Duration::from_millis(1));
    }

    // 等待子线程执行完毕
    handle.join().unwrap();
}
```

- **`thread::spawn`**: 创建一个新线程。它返回一个 `JoinHandle`，这是一个所有权值。
- **`handle.join()`**: 调用 `JoinHandle` 的 `join` 方法会阻塞当前线程，直到 `handle`所代表的线程执行完毕。

### 使用 `move` 关键字

当在子线程中使用来自主线程的数据时，需要使用 `move` 关键字来强制闭包获取其所使用值的所有权。

```rust
use std::thread;

fn main() {
    let v = vec![1, 2, 3];

    // `move` 关键字将 v 的所有权转移到子线程中
    let handle = thread::spawn(move || {
        println!("Here's a vector: {:?}", v);
    });

    // drop(v); // 此时 v 的所有权已经转移，主线程无法再使用它

    handle.join().unwrap();
}
```
这确保了子线程不会意外地引用一个可能被主线程释放的悬垂指针。

## 2. 使用消息传递在线程间通信

消息传递是一种流行的并发模型，其中线程通过发送和接收消息来进行通信，而不是共享内存。Rust 在标准库中提供了**通道 (Channel)** 来实现这一点。

一个通道包含一个**发送端 (Transmitter)** 和一个**接收端 (Receiver)**。

```rust
use std::sync::mpsc; // mpsc: multiple producer, single consumer
use std::thread;

fn main() {
    // 创建一个通道
    let (tx, rx) = mpsc::channel();

    // 克隆发送端，以便在多个线程中使用
    let tx1 = tx.clone();

    // 第一个子线程
    thread::spawn(move || {
        let vals = vec![
            String::from("hi"),
            String::from("from"),
            String::from("the"),
            String::from("thread"),
        ];
        for val in vals {
            tx1.send(val).unwrap();
        }
    });

    // 第二个子线程
    thread::spawn(move || {
        let vals = vec![
            String::from("more"),
            String::from("messages"),
            String::from("for"),
            String::from("you"),
        ];
        for val in vals {
            tx.send(val).unwrap();
        }
    });

    // 在主线程中接收消息
    for received in rx {
        println!("Got: {}", received);
    }
}
```

- **`mpsc::channel()`**: 创建一个异步通道，返回一个 `(Transmitter, Receiver)` 元组。
- **`tx.send(val)`**: 发送一个值。这个操作会取得 `val` 的所有权。
- **`rx.recv()`**: 阻塞地等待并接收一个值。它返回一个 `Result`。
- **`rx.try_recv()`**: 非阻塞地接收一个值。
- **迭代器**: `Receiver` 也可以被当作一个迭代器使用，它会在通道关闭时结束迭代。

## 3. 共享状态并发

虽然消息传递是一个很好的并发工具，但在某些情况下，共享内存可能更合适。Rust 提供了 `Mutex`（互斥锁）来保证在任意时刻只有一个线程可以访问某些数据。

### 使用 `Mutex<T>`

`Mutex<T>` 是一个智能指针。要访问它内部的数据，线程必须首先调用 `lock()` 方法来获取锁。这个调用会阻塞当前线程，直到锁可用为止。

`lock()` 方法返回一个 `MutexGuard`，这是一个智能指针，它实现了 `Deref` 和 `Drop`。当 `MutexGuard` 离开作用域时，锁会自动被释放。

```rust
use std::sync::{Mutex, Arc};
use std::thread;

fn main() {
    // 使用 Arc<Mutex<T>> 在多个线程间共享所有权并同步访问
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for _ in 0..10 {
        let counter = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            // 获取锁
            let mut num = counter.lock().unwrap();
            *num += 1;
            // 锁在这里被自动释放
        });
        handles.push(handle);
    }

    // 等待所有线程完成
    for handle in handles {
        handle.join().unwrap();
    }

    println!("Result: {}", *counter.lock().unwrap());
}
```

### `Arc<T>`: 原子引用计数

`Arc<T>` (Atomically Reference Counted) 是一个用于在多线程环境下安全共享所有权的智能指针。它类似于 `Rc<T>`，但使用原子操作来管理引用计数，因此是线程安全的。

- 当你需要在多个线程之间共享数据的所有权时，通常将 `Mutex<T>` 包装在 `Arc<T>` 中，即 `Arc<Mutex<T>>`。
- `Arc::clone()` 会增加引用计数，而不会进行深拷贝，这使得多个线程可以指向同一块内存。

## `Send` 和 `Sync` 特质

Rust 的类型系统通过 `Send` 和 `Sync` 这两个特质来强制执行并发安全保证。

- **`Send`**: 一个类型如果实现了 `Send` 特质，意味着它的所有权可以安全地在线程之间**转移**。几乎所有 Rust 的基本类型都是 `Send` 的（`Rc<T>` 是一个例外）。
- **`Sync`**: 一个类型如果实现了 `Sync` 特质，意味着它可以安全地在多个线程之间被**共享引用**（`&T`）。也就是说，如果 `T` 是 `Sync` 的，那么 `&T`就是 `Send` 的。

- 大多数基本类型都是 `Sync` 的。
- `Mutex<T>` 是 `Sync` 的。
- `Rc<T>` 不是 `Sync` 的。

这两个特质是自动派生的，你通常不需要手动实现它们。它们是 Rust 并发模型的核心组成部分，确保了所有在线程间共享和传递的数据都是线程安全的。

## 总结

- Rust 的并发模型强调**无畏并发 (Fearless Concurrency)**，通过编译时检查来防止数据竞争等常见错误。
- **`thread::spawn`** 用于创建新线程，`move` 关键字用于转移数据所有权。
- **消息传递** (`mpsc::channel`) 是一个避免共享内存的强大通信机制。
- **共享状态** (`Mutex` 和 `Arc`) 允许在多线程中安全地访问共享数据。
- **`Send` 和 `Sync`** 特质是 Rust 在类型系统中强制实现线程安全的基础。

通过这些工具，Rust 提供了一个既安全又高效的并发编程环境。 