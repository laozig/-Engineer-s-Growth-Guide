# 示例项目：简易命令行工具 `minigrep`

本示例将引导你创建一个经典的命令行工具 `minigrep` 的简化版本。`minigrep` 的功能是：接收一个查询字符串和一个文件名作为参数，然后读取文件内容，并打印出包含查询字符串的所有行。这个项目将综合运用前面学到的许多知识点，包括：

-   模块化代码组织
-   文件 I/O 操作
-   生命周期注解
-   编写测试
-   处理命令行参数
-   错误处理

## 1. 项目目标与设计

我们的 `minigrep` 工具需要能这样被调用：

```bash
cargo run -- a-query-string path/to/a/file.txt
```

**设计思路**:
1.  **`main.rs`**: 负责处理命令行参数的解析和错误处理的顶层逻辑。它将调用核心库来执行搜索任务。
2.  **`lib.rs`**: 包含 `minigrep` 的核心逻辑，即可测试的搜索函数。将核心逻辑与命令行接口分离是一种良好的实践。

## 2. 项目初始化

首先，创建一个新的二进制程序项目：

```bash
cargo new minigrep
cd minigrep
```

## 3. 解析命令行参数

我们将从 `std::env::args` 函数获取命令行参数。它返回一个迭代器，其中包含了程序名和所有用户传入的参数。

**`src/main.rs` 的初始版本**:
```rust
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // args[0] 是程序路径，args[1] 是查询，args[2] 是文件名
    let query = &args[1];
    let file_path = &args[2];

    println!("Searching for '{}'", query);
    println!("In file '{}'", file_path);
    // 接下来的步骤将添加文件读取和搜索逻辑
}
```
**运行**:
```bash
cargo run -- test poem.txt
# Searching for 'test'
# In file 'poem.txt'
```
这还很简陋（例如，没有处理参数不足的错误），但我们稍后会改进它。

## 4. 读取文件内容

接下来，我们使用 `std::fs::read_to_string` 来读取文件的内容。

**更新 `src/main.rs`**:
```rust
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    let query = &args[1];
    let file_path = &args[2];

    println!("Searching for '{}'", query);
    println!("In file '{}'", file_path);

    let contents = fs::read_to_string(file_path)
        .expect("Should have been able to read the file");

    println!("With text:\n{}", contents);
}
```
创建一个 `poem.txt` 文件并写入一些内容，然后再次运行 `cargo run`，你将看到文件的内容被打印出来。

## 5. 将逻辑提取到库中

为了更好的组织和可测试性，我们将核心逻辑（参数解析和搜索）移到 `src/lib.rs` 中。

**创建 `src/lib.rs`**:
```rust
use std::fs;
use std::error::Error;

// 定义一个配置结构体
pub struct Config {
    pub query: String,
    pub file_path: String,
}

impl Config {
    // 构造函数，用于解析参数
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        if args.len() < 3 {
            return Err("not enough arguments");
        }
        let query = args[1].clone();
        let file_path = args[2].clone();
        Ok(Config { query, file_path })
    }
}

// 运行搜索的核心函数
pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(config.file_path)?;
    
    for line in search(&config.query, &contents) {
        println!("{}", line);
    }

    Ok(())
}

// 搜索函数，返回包含查询的行
pub fn search<'a>(query: &str, contents: &'a str) -> Vec<&'a str> {
    let mut results = Vec::new();
    for line in contents.lines() {
        if line.contains(query) {
            results.push(line);
        }
    }
    results
}
```

**重构 `src/main.rs`**:
```rust
use std::env;
use std::process;

// 从我们的库中导入
use minigrep::{Config, run};

fn main() {
    let args: Vec<String> = env::args().collect();
    
    // 使用 Result 和 unwrap_or_else 来处理错误
    let config = Config::build(&args).unwrap_or_else(|err| {
        println!("Problem parsing arguments: {err}");
        process::exit(1);
    });

    println!("Searching for '{}'", config.query);
    println!("In file '{}'", config.file_path);

    // 处理 run 函数可能返回的错误
    if let Err(e) = run(config) {
        println!("Application error: {e}");
        process::exit(1);
    }
}
```
现在我们的 `main` 函数非常简洁，只负责设置和错误处理，而所有核心逻辑都在 `lib.rs` 中。

## 6. 为核心逻辑编写测试

分离逻辑的一大好处是易于测试。我们可以为 `search` 函数编写一个测试。

**在 `src/lib.rs` 末尾添加**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_result() {
        let query = "duct";
        let contents = "\
Rust:
safe, fast, productive.
Pick three.
Duct tape.";

        assert_eq!(vec!["safe, fast, productive."], search(query, contents));
    }
}
```
**运行测试**:
```bash
cargo test
```
**修正错误**: 上面的测试会失败！`search` 函数应该返回 `safe, fast, productive.` 这一行，因为 "pro**duct**ive" 包含了 "duct"。修改断言后，测试通过。这是一个很好的例子，说明测试可以帮助我们精确地定义和验证代码的行为。

*修正后的断言*: `assert_eq!(vec!["safe, fast, productive."], search(query, contents));`

## 7. 改进：不区分大小写的搜索

我们可以通过环境变量来控制搜索是否区分大小写。

1.  **更新 `Config`**: 添加一个 `ignore_case` 字段。
2.  **更新 `Config::build`**: 检查 `IGNORE_CASE` 环境变量。
3.  **更新 `run`**: 根据 `config.ignore_case` 调用不同的搜索函数。
4.  **创建新的 `search_case_insensitive` 函数**。

**更新后的 `src/lib.rs`**:
```rust
use std::fs;
use std::error::Error;
use std::env;

pub struct Config {
    pub query: String,
    pub file_path: String,
    pub ignore_case: bool,
}

impl Config {
    pub fn build(args: &[String]) -> Result<Config, &'static str> {
        // ... (检查参数数量的代码)
        let query = args[1].clone();
        let file_path = args[2].clone();
        // 检查环境变量
        let ignore_case = env::var("IGNORE_CASE").is_ok();

        Ok(Config { query, file_path, ignore_case })
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(config.file_path)?;

    let results = if config.ignore_case {
        search_case_insensitive(&config.query, &contents)
    } else {
        search(&config.query, &contents)
    };

    for line in results {
        println!("{}", line);
    }

    Ok(())
}

// ... (search 函数)

pub fn search_case_insensitive<'a>(query: &str, contents: &'a str) -> Vec<&'a str> {
    let query = query.to_lowercase();
    let mut results = Vec::new();

    for line in contents.lines() {
        if line.to_lowercase().contains(&query) {
            results.push(line);
        }
    }
    results
}

// ... (tests 模块，并为新函数添加测试)
```
**运行不区分大小写的搜索**:
```bash
IGNORE_CASE=1 cargo run -- to poem.txt
```

## 8. 将错误输出到标准错误流

最后，将错误信息输出到标准错误（`stderr`）而不是标准输出（`stdout`）是 CLI 工具的良好实践。

**更新 `src/main.rs`**:
```rust
// ...
// 使用 eprintln! 宏
let config = Config::build(&args).unwrap_or_else(|err| {
    eprintln!("Problem parsing arguments: {err}");
    process::exit(1);
});
// ...
if let Err(e) = run(config) {
    eprintln!("Application error: {e}");
    process::exit(1);
}
```

## 总结

通过这个 `minigrep` 项目，我们：
- 构建了一个完整的、可工作的命令行工具。
- 学习了如何将代码组织成 `main.rs` 和 `lib.rs`。
- 实践了文件 I/O、错误处理和测试驱动开发。
- 了解了如何处理命令行参数和环境变量。

这个项目是学习 Rust 的一个重要里程碑，它将许多独立的知识点串联成了一个有意义的整体。 