# Rust语言学习指南

<div align="center">
  <img src="../../../assets/rust-logo.png" alt="Rust Logo" width="150">
</div>

> Rust是一门赋予每个人构建可靠且高效软件能力的语言。

## 学习路径

### 初学者路径
1. [安装与环境配置](installation.md) ✅
2. [语言基础](basics.md) ✅ 
3. [所有权系统](ownership.md) ✅
4. [结构体与枚举](structs-enums.md) ✅
5. [错误处理](error-handling.md) ✅
6. [包与模块](packages-modules.md) ✅

### 进阶学习
1. [特质(Trait)与多态](traits.md) ✅
2. [生命周期](lifetimes.md) ✅
3. [并发编程](concurrency.md) ✅
4. [智能指针](smart-pointers.md) ✅
5. [测试与文档](testing.md) ✅
6. [闭包与迭代器](closures-iterators.md) ✅

### 高级主题
1. [不安全Rust](unsafe.md) ✅
2. [高级特质](advanced-traits.md) ✅
3. [高级类型](advanced-types.md) ✅
4. [宏编程](macros.md) ✅
5. [异步编程](async-programming.md) ✅
6. [FFI与外部函数](ffi.md) ✅

### 实战应用
1. [命令行应用](cli.md) ✅
2. [Web服务器](web-server.md) ✅
3. [系统编程](systems-programming.md) ✅
4. [嵌入式开发](embedded.md) ✅
5. [WebAssembly](wasm.md) ✅
6. [图形与游戏开发](graphics-games.md) ✅

### 示例项目
1. [简易命令行工具](examples/cli-tool.md) ✅
2. [HTTP客户端](examples/http-client.md) ✅
3. [并发文件处理](examples/concurrent-file-processing.md) ✅
4. [数据序列化与反序列化](examples/serialization.md) ✅
5. [WebAssembly应用](examples/wasm-app.md) ✅

## Rust语言特点

- **内存安全**：无垃圾回收的内存安全保障
- **零成本抽象**：高级语言特性，不牺牲性能
- **并发安全**：编译时消除数据竞争
- **类型系统**：强大的类型系统和模式匹配
- **无运行时**：几乎没有运行时开销
- **C互操作性**：易于与C语言代码集成
- **跨平台**：支持多种平台和架构

## 学习资源

- [Rust官方网站](https://www.rust-lang.org/)
- [Rust程序设计语言（中文版）](https://kaisery.github.io/trpl-zh-cn/)
- [Rust标准库文档](https://doc.rust-lang.org/std/)
- [Rust by Example](https://doc.rust-lang.org/rust-by-example/)
- [Rust语言圣经](https://course.rs/about-book.html)

## 常用工具与框架

### Web框架
- [Rocket](https://rocket.rs/) - 简单直观的Web框架
- [Actix Web](https://actix.rs/) - 高性能Web框架
- [Axum](https://github.com/tokio-rs/axum) - 基于Tokio的Web框架

### 异步运行时
- [Tokio](https://tokio.rs/) - 异步运行时与网络库
- [async-std](https://async.rs/) - 异步标准库
- [smol](https://github.com/smol-rs/smol) - 小型异步运行时

### 数据处理
- [Serde](https://serde.rs/) - 序列化与反序列化框架
- [Diesel](https://diesel.rs/) - ORM与查询构建器
- [sqlx](https://github.com/launchbadge/sqlx) - 异步SQL库

### 命令行工具
- [clap](https://github.com/clap-rs/clap) - 命令行参数解析
- [structopt](https://github.com/TeXitoi/structopt) - 命令行参数解析
- [dialoguer](https://github.com/mitsuhiko/dialoguer) - 交互式命令行界面

## 开发环境

- [Visual Studio Code + rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
- [IntelliJ IDEA + Rust插件](https://www.jetbrains.com/rust/)
- [Vim/Neovim + rust.vim](https://github.com/rust-lang/rust.vim)

## 版本历史

- Rust 1.75 (2023年12月)
- Rust 1.70 (2023年6月)
- Rust 1.65 (2022年11月) - 引入GAT特性
- Rust 1.60 (2022年4月) - 引入cargo add命令
- Rust 1.56 (2021年10月) - Rust 2021版本
- Rust 1.50 (2021年2月)
- Rust 1.45 (2020年7月) - async/await稳定化
- Rust 1.39 (2019年11月) - async/await语法
- Rust 1.31 (2018年12月) - Rust 2018版本
- Rust 1.0 (2015年5月) - 第一个稳定版本 