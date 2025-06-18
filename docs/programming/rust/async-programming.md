# Rust 异步编程

异步编程是一种允许程序在等待耗时操作（如 I/O、网络请求）完成时，可以继续执行其他任务的编程模型。这大大提高了程序的并发能力和资源利用率。Rust 通过 `async`/`.await` 语法、`Future` 特质以及异步运行时（如 Tokio, async-std）提供了一套强大、安全且高效的异步编程范式。

## 核心概念

### 1. `async` 和 `.await`

- **`async`**:
  - `async` 关键字可以用于函数（`async fn`）和代码块（`async { ... }`）。
  - 当你用 `async` 标记一个函数时，它的返回类型不再是 `T`，而是一个实现了 `Future<Output = T>` 的匿名类型。
  - `async` 本身并不会执行任何代码，它只是创建一个**未来 (Future)**，这个未来描述了一个最终会产生结果的计算。

- **`.await`**:
  - `.await` 操作符用于等待一个 `Future` 的完成。
  - 它只能在 `async` 函数或块中使用。
  - 当你 `.await` 一个 `Future` 时，如果该 `Future` 尚未完成，当前任务会被**挂起**，允许异步运行时去执行其他任务。一旦 `Future` 准备好继续执行，运行时会**唤醒**该任务并从上次暂停的地方继续。

```rust
async fn do_something() -> String {
    // ... 模拟一些异步操作
    "done".to_string()
}

async fn main() {
    println!("Let's go!");
    
    // 调用 async fn 会返回一个 Future
    let future = do_something(); 
    
    // .await 会等待 Future 完成并获取其结果
    let result = future.await;
    
    println!("Result: {}", result);
}
```

### 2. `Future` 特质

`Future` 是 Rust 异步编程的核心。它是一个特质，代表一个可以被轮询（poll）直到完成的异步计算。

```rust
pub trait Future {
    type Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output>;
}
```

- **`poll` 方法**:
  - `poll` 方法是 `Future` 的核心。异步运行时会反复调用它来驱动 `Future` 向前执行。
  - **`Poll::Ready(value)`**: 表示 `Future` 已经完成，并返回其结果 `value`。
  - **`Poll::Pending`**: 表示 `Future` 尚未完成。当 `Future` 准备好再次被轮询时，它会通过 `Context` 中的 `Waker` 来通知运行时。

你通常不需要手动实现 `Future` 特质，因为 `async`/`.await` 语法会为你自动生成。

### 3. 异步运行时 (Async Runtime)

`async fn` 本身只是创建了一个 `Future`，它不会自己执行。你需要一个**异步运行时**来管理和执行这些 `Future`。

运行时负责：
- **执行器 (Executor)**: 维护一个任务队列，并不断轮询 `Future` 直到它们完成。
- **反应器 (Reactor)**: 处理外部 I/O 事件（如网络、文件系统），并在事件就绪时唤醒相应的任务。
- **任务调度**: 决定哪个任务在何时运行。

最流行的 Rust 异步运行时包括：
- **Tokio**: 目前社区最流行和功能最丰富的运行时，特别适合网络应用。
- **async-std**: 旨在提供一个与标准库 `std` 对应的异步版本。
- **smol**: 一个小巧、简单的运行时。

**使用 Tokio 示例**:
要在 `main` 函数中运行异步代码，你需要一个运行时。Tokio 提供了 `#[tokio::main]` 宏来简化这个过程。

```rust
// Cargo.toml
// tokio = { version = "1", features = ["full"] }

use tokio::time::{sleep, Duration};

async fn my_task(id: u32) {
    println!("Task {} started", id);
    sleep(Duration::from_secs(1)).await;
    println!("Task {} finished", id);
}

#[tokio::main]
async fn main() {
    let task1 = my_task(1);
    let task2 = my_task(2);

    // .await 会顺序执行
    // task1.await;
    // task2.await;

    // 使用 tokio::join! 可以并发执行多个 Future
    tokio::join!(task1, task2);
}
```
`#[tokio::main]` 宏会将 `async fn main` 转换成一个普通的 `fn main`，并在其中初始化 Tokio 运行时来执行异步代码。

## 并发执行 `Future`

仅仅使用 `.await` 会导致 `Future` 串行执行。为了实现并发，你需要使用运行时提供的工具。

- **`join!`**:
  - `tokio::join!` 或 `futures::join!` 宏可以同时等待多个 `Future`。
  - 它会并发地轮询所有传入的 `Future`，直到它们全部完成。

- **`tokio::spawn`**:
  - `tokio::spawn` 用于创建一个新的异步**任务 (Task)**。
  - 它会立即将 `Future` 提交给运行时调度器，使其在后台并发执行，而不会阻塞当前任务。
  - `spawn` 返回一个 `JoinHandle`，你可以用它来等待任务完成或中止任务。

```rust
#[tokio::main]
async fn main() {
    let handle = tokio::spawn(async {
        "This is running in the background"
    });

    // 在这里可以执行其他操作

    let result = handle.await.unwrap();
    println!("{}", result);
}
```

## `Pin` 和 `Unpin`

`Pin` 是 Rust 异步生态系统中一个比较复杂的概念，主要用于解决**自引用结构体 (Self-referential Structs)** 的问题。

- `async` 块生成的 `Future` 可能会在内部持有对自身字段的引用。
- 如果这个 `Future` 在内存中的地址被移动（例如，从栈移动到堆），这些内部引用就会失效，导致内存不安全。
- **`Pin<&mut T>`**: `Pin` 是一个智能指针，它将数据 "钉" 在内存中的特定位置，确保其地址不会改变。这使得创建自引用结构体成为可能。
- `poll` 方法的 `self` 参数是 `Pin<&mut Self>`，这保证了 `Future` 在被轮询期间不会被移动。

大多数情况下，你不需要直接与 `Pin` 交互。只有在编写需要与 C 库交互或手动实现复杂 `Future` 的底层库代码时，才需要深入理解它。

## `Stream` 特质

`Stream` 特质是 `Future` 的异步版本。它代表一个可以异步产生一系列值的序列。

```rust
pub trait Stream {
    type Item;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>>;
}
```

- `poll_next` 类似于 `Iterator` 的 `next` 方法，但它是异步的。
- `futures` crate 提供了 `StreamExt` 特质，为 `Stream` 提供了许多方便的适配器方法，如 `map`, `filter`, `next` 等。

## 总结

- **`async`/`.await`** 是 Rust 异步编程的语法基础，用于创建和等待 `Future`。
- **`Future`** 是一个代表异步计算的特质。
- **异步运行时**（如 Tokio）是执行和管理 `Future` 的必要组件。
- 使用 **`join!`** 或 **`spawn`** 可以实现 `Future` 的并发执行。
- **`Pin`** 是一个底层工具，用于保证 `Future` 在内存中的位置固定，以支持自引用。
- **`Stream`** 是异步版本的迭代器。

Rust 的异步编程模型旨在提供"零成本抽象"，即在不牺牲性能的前提下，提供高级、安全的并发编程能力。 