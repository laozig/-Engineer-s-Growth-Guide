# 示例项目：异步 HTTP 客户端

在这个示例中，我们将构建一个简单的异步 HTTP GET 客户端。这个客户端将接收一个 URL 作为命令行参数，发送一个 HTTP GET 请求，并打印出响应的状态码和内容。

这个项目将重点展示如何使用 Rust 的异步生态系统来处理网络 I/O，特别是 `tokio` 运行时和 `reqwest` 库。

## 1. 项目目标与设计

我们的目标是创建一个可以这样运行的程序：

```bash
cargo run -- https://www.rust-lang.org
```

程序应该：
1.  解析命令行参数以获取 URL。
2.  使用 `reqwest` 库异步地发送一个 GET 请求。
3.  等待响应。
4.  打印出响应的状态码和响应体（body）的内容。

我们将使用 `tokio` 作为我们的异步运行时，因为它与 `reqwest` 结合得非常好。

## 2. 项目初始化

首先，创建一个新的二进制程序项目，并添加所需的依赖：

```bash
cargo new http-client-example
cd http-client-example
cargo add reqwest
cargo add tokio --features full
```
-   `reqwest`: 一个高级、易于使用的 HTTP 客户端库。
-   `tokio`: 最流行的异步运行时。

## 3. 编写异步的 `main` 函数

由于我们要进行异步网络调用，我们的 `main` 函数需要是 `async` 的。我们将使用 `#[tokio::main]` 宏来设置运行时。

**`src/main.rs` 的初始版本**:
```rust
use std::env;

#[tokio::main]
async fn main() {
    let url = env::args().nth(1).expect("URL is required");

    println!("Fetching URL: {}", url);

    // 在这里我们将添加 HTTP 请求逻辑
}
```
`env::args().nth(1)` 用于获取第二个命令行参数（第一个是程序路径）。

## 4. 发送 HTTP 请求

`reqwest` 库使得发送 HTTP 请求变得异常简单。

**更新 `src/main.rs`**:
```rust
use std::env;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let url = env::args().nth(1).expect("URL is required");

    println!("Fetching URL: {}", url);

    // 发送 GET 请求并等待响应
    let response = reqwest::get(&url).await?;

    // 检查响应状态
    let status = response.status();
    println!("Status: {}", status);

    if status.is_success() {
        // 获取响应体文本
        let body = response.text().await?;
        println!("Body:\n{}", body);
    } else {
        println!("Request failed with status: {}", status);
    }

    Ok(())
}
```

**代码解释**:
-   **`main() -> Result<(), Box<dyn Error>>`**: 我们的 `main` 函数返回一个 `Result`，这允许我们使用 `?` 操作符来方便地传播错误。`Box<dyn Error>` 是一个通用的错误类型。
-   **`reqwest::get(&url)`**: 这个函数创建一个 `Future`，当这个 `Future` 被 `await` 时，它会异步地发送一个 GET 请求。
-   **`.await?`**: 我们在这里 `await` `reqwest::get` 返回的 `Future`。如果请求过程中发生错误（例如，DNS 解析失败、无法连接服务器），`?` 会将错误返回。
-   **`response.status()`**: 获取 HTTP 响应状态码。
-   **`response.text().await?`**: 这个方法也返回一个 `Future`。`await` 它会异步地将响应体读取为一个 `String`。

## 5. 运行客户端

现在，你可以运行你的 HTTP 客户端了：

```bash
# 获取 Rust 官网首页
cargo run -- https://www.rust-lang.org

# 尝试一个会返回 JSON 的 API
cargo run -- https://api.github.com/users/rust-lang

# 尝试一个不存在的页面
cargo run -- https://www.rust-lang.org/non-existent-page
```
观察每次运行时程序打印出的不同状态码和响应内容。

## 6. 构建更强大的客户端 (可选的改进)

### 6.1. 使用 `Client` 构建器

对于更复杂的应用（例如，需要设置自定义请求头、超时、代理或重用 TCP 连接），你应该使用 `reqwest::Client`。

```rust
use reqwest::Client;
use std::time::Duration;

// ...

async fn run_client() -> Result<(), Box<dyn Error>> {
    let url = env::args().nth(1).expect("URL is required");

    // 创建一个 Client 实例
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    
    // 使用 client 发送请求
    let response = client.get(&url).send().await?;

    // ... (处理响应的代码与之前相同)

    Ok(())
}

fn main() {
    if let Err(e) = tokio::runtime::Runtime::new().unwrap().block_on(run_client()) {
        eprintln!("Application error: {}", e);
    }
}
```

### 6.2. 处理 JSON

如果你的目标是与 JSON API 交互，`reqwest` 可以与 `serde_json` 无缝集成。

```rust
use serde::Deserialize;

// 定义一个与 JSON 响应匹配的结构体
#[derive(Deserialize, Debug)]
struct User {
    login: String,
    id: u32,
    node_id: String,
}

// ...
// 在你的异步函数中：
let user: User = reqwest::get("https://api.github.com/users/rust-lang")
    .await?
    .json() // .json() 会自动解析响应体为指定的类型
    .await?;

println!("{:#?}", user);
```
你需要将 `serde` 添加到你的 `Cargo.toml` 依赖中 (`cargo add serde --features derive`)。

## 7. 总结

这个简单的 HTTP 客户端项目展示了 Rust 异步生态的强大和易用性。
-   **`tokio`** 提供了一个健壮的异步运行时。
-   **`reqwest`** 将复杂的 HTTP 通信抽象成了一个简单、高级的 API。
-   **`async/await`** 语法使得编写非阻塞 I/O 代码就像编写同步代码一样直观。
-   结合 Rust 的**错误处理**机制 (`Result` 和 `?`)，你可以构建出既高效又可靠的网络应用。 