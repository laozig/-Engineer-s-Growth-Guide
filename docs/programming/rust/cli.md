# Rust 命令行应用

Rust 是一种构建高性能、可靠且跨平台的命令行（CLI）应用的绝佳语言。它的强类型系统、内存安全保证、出色的性能以及丰富的生态系统（通过 Crates.io）使得开发复杂的 CLI 工具变得既简单又安全。

本指南将介绍构建一个功能完整的 CLI 应用所涉及的核心概念和常用库。

## 1. 核心概念

### 1.1. 解析命令行参数

任何 CLI 应用都需要处理用户传入的参数和选项。虽然你可以手动解析 `std::env::args()`，但这非常繁琐且容易出错。社区提供了许多强大的库来简化这个过程。

- **`clap` (Command Line Argument Parser)**:
  - `clap` 是 Rust 生态中最流行、功能最强大的命令行解析库。
  - 它支持复杂的子命令、各种类型的参数、选项、标志、参数验证、自动生成帮助信息和 shell 补全脚本等。
  - 推荐使用其**派生宏 (derive)** 功能，可以通过结构体来定义 CLI 的接口。

**使用 `clap` 的派生宏示例**:

```rust
// Cargo.toml
// clap = { version = "4.0", features = ["derive"] }

use clap::Parser;

/// 一个简单的程序，用于向上或向下转换文本
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// 要处理的文本
    #[arg(short, long)]
    text: String,

    /// 是否转换为小写
    #[arg(short, long, default_value_t = false)]
    lowercase: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.lowercase {
        println!("{}", cli.text.to_lowercase());
    } else {
        println!("{}", cli.text.to_uppercase());
    }
}
```
- **`#[derive(Parser)]`**: 为结构体实现 `Parser` 特质。
- **`Cli::parse()`**: 解析命令行参数并填充结构体实例。如果参数无效或用户请求帮助（`--help`），`clap` 会自动处理并退出程序。
- **文档注释**: `clap` 会将结构体和字段的文档注释用作帮助信息。

### 1.2. 处理 I/O

CLI 应用经常需要读写文件、标准输入/输出。

- **`std::io`**: Rust 标准库提供了 `Read` 和 `Write` 特质来处理 I/O 操作。
- **`std::fs`**: 用于文件系统操作，如打开、创建、读取和写入文件。
- **错误处理**: I/O 操作通常返回 `std::io::Result<T>`。使用 `?` 操作符可以方便地进行错误传播。

### 1.3. 组织代码结构

一个良好的 CLI 应用应该将核心逻辑与命令行接口分离。

- **`src/main.rs`**: 主要负责解析命令行参数，处理配置，并调用核心逻辑。
- **`src/lib.rs`**: 包含应用的核心功能，定义主要的结构体和函数。这样也使得你的核心逻辑可以被其他库或测试代码复用。

**示例项目结构**:
```
my_cli_app/
├── Cargo.toml
└── src/
    ├── main.rs   # CLI 接口和参数解析
    └── lib.rs      # 核心逻辑
```

## 2. 构建一个实用的 CLI 工具：`grep-lite`

让我们构建一个简化版的 `grep` 工具，它会在给定的文件中搜索指定的模式。

### 步骤 1: 项目设置

```bash
cargo new grep-lite
cd grep-lite
cargo add clap --features derive
```

### 步骤 2: 定义 CLI 接口 (`src/main.rs`)

```rust
use clap::Parser;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Parser, Debug)]
#[command(name = "grep-lite")]
#[command(author = "Your Name <you@example.com>")]
#[command(version = "1.0")]
#[command(about = "Searches for patterns in files", long_about = None)]
struct Cli {
    /// The pattern to look for
    pattern: String,

    /// The path to the file to search
    path: std::path::PathBuf,
}

fn main() {
    let cli = Cli::parse();
    
    // 打开文件，处理错误
    let file = File::open(&cli.path)
        .expect("Could not read file");
    
    let reader = BufReader::new(file);

    // 逐行读取并匹配
    for line_result in reader.lines() {
        let line = line_result.expect("Could not read line");
        if line.contains(&cli.pattern) {
            println!("{}", line);
        }
    }
}
```

### 步骤 3: 运行和测试

创建一个 `test.txt` 文件：
```txt
hello world
this is a test
find the pattern
another line
```

运行你的程序：
```bash
cargo run -- pattern test.txt
```
输出应为：
```
find the pattern
```

## 3. 增强 CLI 应用

### 3.1. 美化输出

使用 `colored` 或 `termcolor` 等库可以为你的输出添加颜色，使其更具可读性。

### 3.2. 交互式界面

`dialoguer` 库可以帮助你创建交互式的提示，如确认、选择和密码输入。

### 3.3. 错误处理

- 使用 `anyhow` 和 `thiserror` 这两个库可以极大地改善错误处理体验。
- `anyhow`: 提供了一个通用的 `anyhow::Result<T>`，方便你处理各种不同类型的错误。
- `thiserror`: 允许你为自己的错误类型轻松地实现 `std::error::Error` 特质。

**使用 `anyhow` 改进 `main` 函数**:
```rust
// ... (imports and struct definition)

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    let file = File::open(&cli.path)?;
    let reader = BufReader::new(file);

    for line_result in reader.lines() {
        let line = line_result?;
        if line.contains(&cli.pattern) {
            println!("{}", line);
        }
    }
    
    Ok(())
}
```
现在，任何 I/O 错误都会被 `?` 自动转换并传播，最终由 `main` 函数返回。

## 4. 发布与分发

- **`cargo install`**: 其他 Rust 开发者可以通过 `cargo install --path .` 或 `cargo install your-crate-name` (发布到 Crates.io后) 来安装你的工具。
- **打包**: 为了方便非 Rust 用户，你可以使用 `cargo-dist` 或手动为不同平台（Windows, macOS, Linux）构建二进制文件，并将其打包成 `.zip` 或 `.tar.gz` 文件。

## 总结

Rust 是构建健壮、高效 CLI 应用的理想选择。
- **`clap`** 提供了无与伦比的命令行参数解析能力。
- **标准库** (`std::io`, `std::fs`) 提供了坚实的 I/O 基础。
- **将逻辑与接口分离**是一种良好的工程实践。
- **`anyhow`** 和 **`thiserror`** 让错误处理变得简单。
- 生态系统中的其他库（如 `colored`, `dialoguer`）可以进一步增强用户体验。

通过结合这些工具和实践，你可以构建出专业级的命令行应用。 