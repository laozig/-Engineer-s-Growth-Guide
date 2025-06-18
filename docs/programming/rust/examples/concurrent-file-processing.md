# 示例项目：并发文件处理器

在这个示例中，我们将构建一个程序，该程序会并发地读取多个文件，对每个文件的内容进行某种处理（例如，计算词频），然后将结果汇总起来。

这个项目旨在展示如何利用 Rust 的并发能力来加速 I/O 密集型任务。我们将使用 `std::thread` 来创建线程，并使用通道（`std::sync::mpsc`）在线程之间安全地传递数据。

## 1. 项目目标与设计

我们的程序将接收多个文件名作为命令行参数。

```bash
cargo run -- file1.txt file2.txt file3.txt
```

**设计思路**:
1.  **主线程**:
    -   解析命令行参数以获取文件列表。
    -   创建一个**通道 (Channel)** 用于接收来自工作线程的处理结果。
    -   为每个文件派生（spawn）一个**工作线程**。
    -   等待所有工作线程完成，并从通道中收集它们发送的结果。
    -   汇总所有结果并打印最终报告。
2.  **工作线程**:
    -   接收一个文件名作为输入。
    -   读取并处理该文件的内容（在本例中，我们简单地计算文件的行数）。
    -   通过通道将处理结果发送回主线程。

这种"派生-收集"（Fork-Join）模式是并行处理任务的经典模型。

## 2. 项目初始化

```bash
cargo new concurrent-file-processor
cd concurrent-file-processor
```

## 3. 单线程实现

在引入并发之前，我们先实现一个单线程的版本，以确保核心逻辑是正确的。

**`src/main.rs` 的单线程版本**:
```rust
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::error::Error;

// 数据处理逻辑
fn process_file(path: &str) -> Result<usize, io::Error> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    Ok(reader.lines().count())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        eprintln!("Usage: concurrent-file-processor <file1> [file2] ...");
        return Ok(());
    }

    let mut total_lines = 0;
    for file_path in args {
        match process_file(&file_path) {
            Ok(line_count) => {
                println!("{}: {} lines", file_path, line_count);
                total_lines += line_count;
            }
            Err(e) => {
                eprintln!("Error processing file {}: {}", file_path, e);
            }
        }
    }

    println!("--------------------");
    println!("Total lines: {}", total_lines);

    Ok(())
}
```
创建几个测试文件（`file1.txt`, `file2.txt`），然后运行 `cargo run -- file1.txt file2.txt` 来验证逻辑是否正确。

## 4. 引入并发

现在，我们将使用线程和通道来并行化文件处理。

**`src/main.rs` 的并发版本**:
```rust
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::thread;
use std::sync::mpsc; // mpsc: multiple producer, single consumer

// 处理结果的类型，可以是更复杂的结构体
// (文件名, 处理结果)
type JobResult = (String, Result<usize, String>);

// 数据处理逻辑保持不变
fn process_file(path: &str) -> Result<usize, io::Error> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    Ok(reader.lines().count())
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: concurrent-file-processor <file1> [file2] ...");
        return;
    }

    // 创建一个通道
    let (tx, rx) = mpsc::channel::<JobResult>();
    let mut handles = vec![];
    let num_files = args.len();

    // 为每个文件派生一个工作线程
    for file_path in args {
        let tx_clone = tx.clone(); // 克隆发送端
        
        let handle = thread::spawn(move || {
            let result = process_file(&file_path);
            let job_result = match result {
                Ok(count) => (file_path, Ok(count)),
                Err(e) => (file_path, Err(e.to_string())),
            };
            // 发送结果，即使是错误也发送
            tx_clone.send(job_result).unwrap();
        });
        handles.push(handle);
    }
    
    // 删除主线程的发送端，这很重要！
    // 当所有克隆的 tx 都被销毁后，rx 的迭代会自动结束
    drop(tx);

    // 收集并处理结果
    let mut total_lines = 0;
    println!("--- Processing Results ---");
    // 从通道接收 num_files 个结果
    for (path, result) in rx.iter().take(num_files) {
        match result {
            Ok(line_count) => {
                println!("{}: {} lines", path, line_count);
                total_lines += line_count;
            }
            Err(e) => {
                eprintln!("Error processing file {}: {}", path, e);
            }
        }
    }

    // 等待所有线程完成 (虽然此时它们应该已经完成了)
    for handle in handles {
        handle.join().unwrap();
    }
    
    println!("--------------------");
    println!("Total lines processed: {}", total_lines);
}
```
**代码解释**:
-   **`mpsc::channel()`**: 创建了一个多生产者、单消费者的通道。`tx` 是发送端，`rx` 是接收端。
-   **`tx.clone()`**: 在 `spawn` 闭包中使用 `move` 之前，我们需要为每个线程克隆发送端 `tx`。因为 `send` 方法会获取其所有权。
-   **`thread::spawn(move || { ... })`**: 创建一个新线程。`move` 关键字强制闭包获取它所使用的外部变量（`tx_clone` 和 `file_path`）的所有权。
-   **`tx_clone.send(...)`**: 工作线程通过克隆的发送端将结果发送回主线程。
-   **`drop(tx)`**: 这是一个关键步骤。`rx` 作为一个迭代器，只有在所有与之关联的 `tx`（发送端）都被销毁后，它才会停止阻塞并结束迭代。主线程持有的原始 `tx` 如果不被 `drop`，`rx` 将永远等待下去，导致死锁。
-   **`rx.iter().take(num_files)`**: 我们在主线程中迭代接收端。`iter()` 会阻塞，直到有消息传来或通道关闭。我们明确知道会收到 `num_files` 个结果。

## 5. 进一步优化：使用线程池

当文件数量非常多时，为每个文件都创建一个新线程可能会消耗大量系统资源并降低性能。在这种情况下，使用**线程池**是更好的选择。线程池会维护一个固定数量的工作线程，并将任务分发给它们。

`rayon` crate 是 Rust 中进行数据并行处理和使用线程池的绝佳选择。

**使用 `rayon` 的重构 (更简洁、更高效)**:

```bash
cargo add rayon
```

```rust
use std::env;
use std::fs;
use std::io::{self, BufRead};
use rayon::prelude::*; // 导入 Rayon 的并行迭代器

// ... process_file 函数保持不变 ...

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("Usage: concurrent-file-processor <file1> [file2] ...");
        return;
    }

    // 使用 Rayon 的并行迭代器
    let results: Vec<_> = args.par_iter()
        .map(|path| (path, process_file(path)))
        .collect();
    
    let mut total_lines = 0;
    println!("--- Processing Results ---");
    for (path, result) in results {
        match result {
            Ok(line_count) => {
                println!("{}: {} lines", path, line_count);
                total_lines += line_count;
            }
            Err(e) => {
                eprintln!("Error processing file {}: {}", path, e.to_string());
            }
        }
    }

    println!("--------------------");
    println!("Total lines processed: {}", total_lines);
}
```
**代码解释**:
-   **`.par_iter()`**: `rayon` 提供的扩展方法，它将一个普通的集合（如 `Vec`）转换成一个并行迭代器。
-   **`.map()`**: `map` 操作现在会在 `rayon` 内部的线程池上并行执行。
-   **`.collect()`**: 从并行迭代器收集结果。

`rayon` 的版本代码更短，更具声明性，并且通常比手动管理线程更高效，因为它会自动处理线程池的创建、任务调度和负载均衡。

## 总结

-   对于 I/O 密集型任务，并发能够显著提高程序性能。
-   手动使用 **`std::thread` 和通道**是理解并发原理的好方法，适用于对线程行为有精细控制需求的场景。
-   对于数据并行任务（对一个集合中的每个元素执行相同操作），**`rayon`** 提供了更高级、更易用且通常更高效的抽象。
-   在并发编程中，要特别注意**所有权**的转移（`move` 关键字）和**通道**的生命周期管理（`drop(tx)`），以避免死锁。 