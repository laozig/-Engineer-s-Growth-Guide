# Rust Web 服务器

得益于其出色的性能、内存安全保证和强大的并发模型，Rust 是构建高性能、可靠的 Web 服务器和后端服务的理想选择。Rust 的异步生态系统，特别是 `Tokio` 运行时和像 `Axum`、`Actix Web` 等现代 Web 框架，为开发者提供了构建可扩展网络应用所需的一切工具。

本指南将重点介绍使用 `Axum` 框架来构建一个简单的 Web 服务器。`Axum` 是一个由 `Tokio` 团队开发的模块化、符合人体工程学的 Web 框架。

## 1. 核心概念

### 1.1. Web 框架的选择

Rust 社区有多个成熟的 Web 框架可供选择：

- **`Axum`**:
  - **优点**: 与 `Tokio` 生态系统无缝集成，设计哲学强调模块化和组合性，类型安全，并且不依赖宏。
  - **特点**: 将所有东西都建模为 `async` 函数（handler）、`Router` 和 `Layer` (中间件)，易于理解和扩展。

- **`Actix Web`**:
  - **优点**: 性能极高，采用 Actor 模型（尽管现代版本已不强制），功能丰富。
  - **特点**: 大量使用宏，学习曲线相对陡峭一些。

- **`Rocket`**:
  - **优点**: 语法非常直观和易于上手，对新手友好。
  - **特点**: 依赖于 Rust 的 nightly 版本（尽管最新版本正在努力稳定），路由和状态管理非常简单。

本指南选用 `Axum`，因为它与 `Tokio` 的紧密集成代表了现代 Rust Web 开发的主流方向。

### 1.2. 基本组成部分

一个典型的 `Axum` Web 应用由以下部分组成：

- **处理器 (Handler)**: 一个处理请求并返回响应的异步函数 (`async fn`)。
- **路由器 (Router)**: 用于将不同的 URL 路径和 HTTP 方法（GET, POST 等）分派到对应的处理器。
- **提取器 (Extractor)**: 从请求中提取数据的类型（如路径参数、JSON body、请求头等）。`Axum` 通过函数参数的类型来实现提取。
- **响应 (Response)**: 处理器返回的任何实现了 `IntoResponse` 特质的类型，如 `String`, `Html`, `Json` 等。
- **中间件 (Middleware/Layer)**: 用于在请求被处理器处理之前或之后执行共享逻辑，如日志记录、认证、压缩等。

## 2. 构建一个 "Hello, World!" 服务器

### 步骤 1: 项目设置

```bash
cargo new hello-axum
cd hello-axum
cargo add tokio --features full
cargo add axum
```

### 步骤 2: 编写代码 (`src/main.rs`)

```rust
use axum::{
    routing::get,
    Router,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // 构建我们的应用，定义一个路由
    let app = Router::new().route("/", get(handler));

    // 定义服务器地址
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);

    // 启动服务器
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// 定义我们的处理器
async fn handler() -> &'static str {
    "Hello, World!"
}
```

### 步骤 3: 运行服务器

```bash
cargo run
```
现在，在浏览器或使用 `curl` 访问 `http://127.0.0.1:3000`，你应该能看到 "Hello, World!"。

## 3. 增强功能

### 3.1. 路径参数提取

使用 `axum::extract::Path` 可以从 URL 中提取动态参数。

```rust
use axum::extract::Path;

// ... (main function is the same)

async fn greet_handler(Path(name): Path<String>) -> String {
    format!("Hello, {}!", name)
}

// 在 main 中更新路由
// let app = Router::new().route("/:name", get(greet_handler));
```
现在访问 `http://127.0.0.1:3000/your-name` 将会返回 "Hello, your-name!"。

### 3.2. 处理 JSON

`Axum` 提供了 `Json` 提取器和响应类型，可以方便地处理 JSON 数据。这需要 `serde` 和 `serde_json` 库。

```bash
cargo add serde --features derive
cargo add serde_json
```

```rust
use axum::{routing::post, Json};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct User {
    id: u64,
    name: String,
}

async fn create_user(Json(payload): Json<User>) -> Json<User> {
    // 在实际应用中，你会将 user 存入数据库
    println!("Received user: {:?}", payload);
    Json(payload) // 将接收到的 user 返回
}

// 在 main 中添加新路由
// let app = Router::new()
//     .route("/", get(handler))
//     .route("/users", post(create_user));
```
你可以使用 `curl` 来测试这个端点：
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"id": 1337, "name": "gemini"}' \
  http://127.0.0.1:3000/users
```

### 3.3. 共享状态

通常，你的处理器需要访问共享的资源，如数据库连接池或应用配置。`Axum` 推荐使用**依赖注入**的方式，通过扩展层（Layer）来实现。

```rust
use axum::{extract::State, http::StatusCode};
use std::sync::{Arc, Mutex};

// 一个简单的共享状态
struct AppState {
    counter: Mutex<i32>,
}

async fn counter_handler(State(state): State<Arc<AppState>>) -> String {
    let mut count = state.counter.lock().unwrap();
    *count += 1;
    count.to_string()
}

// 在 main 中创建并添加状态
// let shared_state = Arc::new(AppState { counter: Mutex::new(0) });
// let app = Router::new()
//     .route("/counter", get(counter_handler))
//     .with_state(shared_state);
```
`State` 提取器会从应用的扩展层中获取共享状态。使用 `Arc` 使得状态可以在多个线程间安全共享。

### 3.4. 错误处理

处理器可以返回 `Result<T, E>`，其中 `T` 和 `E` 都必须实现 `IntoResponse`。这允许你定义自定义的错误类型，并控制错误发生时返回的 HTTP 状态码和响应体。

```rust
// ... (定义一个自定义错误类型 AppError)
struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

// 处理器现在可以返回 Result
async fn my_handler() -> Result<String, AppError> {
    // ... 可能会出错的操作
    Ok("Success".to_string())
}
```

## 总结

- Rust，特别是结合 `Axum` 和 `Tokio`，为构建 Web 服务器提供了一个现代、高效且安全的平台。
- **`Axum`** 的核心是 `Router`、`Handler` 和 `Layer`。
- **提取器 (Extractor)** 通过函数参数类型实现，使得从请求中获取数据变得非常简单和类型安全。
- **`State` 提取器**和 `Arc` 是在处理器之间共享状态的常用模式。
- 通过实现 `IntoResponse`，可以对响应类型和错误处理进行精细控制。

随着生态系统的不断成熟，Rust 正在成为各种网络服务（从简单的 REST API 到复杂的分布式系统）的有力竞争者。 