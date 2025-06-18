# Rust FFI (外部函数接口)

FFI (Foreign Function Interface) 是一套允许一种编程语言调用另一种编程语言编写的函数或使用其数据类型的机制。Rust 提供了一流的 FFI 支持，使其能够与 C 语言库进行无缝交互，而不需要任何运行时开销。这是 Rust 成为系统编程语言的一个关键特性。

本指南将重点介绍如何在 Rust 中调用 C 函数，以及如何将 Rust 代码暴露给 C 调用。

## 核心概念

### 1. `extern` 关键字

`extern` 关键字是 FFI 的核心，它有两种主要用途：

- **`extern "C" { ... }`**: 用于声明外部库中定义的函数。这被称为**外部块 (Foreign Block)**。
- **`extern "C" fn ...`**: 用于定义一个可以被其他语言调用的函数，它会遵循 C 语言的 ABI (Application Binary Interface)。

`"C"` 部分是 ABI 的名称，它指定了函数调用时参数如何传递、返回值如何处理等底层细节。C ABI 是最通用的 ABI。

### 2. 与 C 库交互

要在 Rust 中调用 C 函数，你需要：
1.  找到 C 库的头文件 (`.h`)，了解函数签名和数据结构。
2.  在 Rust 代码中使用 `extern "C"` 块声明这些函数。
3.  确保 C 库被正确链接。

**示例：调用 C 标准库的 `abs` 函数**

```rust
// 声明 C 标准库中的 abs 函数
extern "C" {
    fn abs(input: i32) -> i32;
}

fn main() {
    let x = -10;
    
    // Rust 代码可以安全地调用 C 函数
    // 但必须在 unsafe 块中进行
    unsafe {
        let abs_x = abs(x);
        println!("The absolute value of {} is {}", x, abs_x);
    }
}
```

### 3. `unsafe` 关键字

调用任何外部函数都被认为是**不安全的 (unsafe)**，因为 Rust 编译器无法检查和保证外部代码的内存安全和正确性。因此，所有对外部函数的调用都必须包裹在 `unsafe` 块中。

`unsafe` 块是你向编译器承诺："我已阅读外部代码的文档，并确信我所做的调用是安全的。"

### 4. 数据类型映射

与 C 交互时，需要确保 Rust 的数据类型与 C 的数据类型兼容。`libc` crate 提供了 C 标准库中类型的别名，是进行 FFI 编程时的首选。

| C 类型            | Rust `libc` 类型     | Rust 等价类型 (多数情况)  |
| ----------------- | -------------------- | ------------------------- |
| `int`             | `libc::c_int`        | `i32`                     |
| `unsigned int`    | `libc::c_uint`       | `u32`                     |
| `long`            | `libc::c_long`       | `i64` or `i32` (依赖平台) |
| `char *` (只读)   | `*const libc::c_char`| `*const u8`               |
| `char *` (可写)   | `*mut libc::c_char`  | `*mut u8`                 |
| `float`           | `libc::c_float`      | `f32`                     |
| `double`          | `libc::c_double`     | `f64`                     |
| `struct MyStruct` | `MyStruct` (见下文)  | `struct MyStruct`         |
| `void *`          | `*mut libc::c_void`  | `*mut ()`                 |

### 5. 处理字符串

- **从 Rust 传递字符串到 C**:
  - C 语言中的字符串是以空字符（`\0`）结尾的字符数组。
  - Rust 的 `String` 和 `&str` 内部可能包含空字符，并且不是以空字符结尾。
  - 使用 `std::ffi::CString` 来创建一个与 C 兼容的、以空字符结尾的字符串。

- **从 C 接收字符串到 Rust**:
  - C 函数返回的 `*const c_char` 可以通过 `std::ffi::CStr` 来包装。
  - `CStr::from_ptr()` 会创建一个对 C 字符串的借用，然后你可以用 `.to_string_lossy()` 或 `.to_str()` 将其转换为 Rust 的 `String` 或 `&str`。

### 6. 处理结构体

要让 Rust 结构体与 C 结构体布局兼容，你需要使用 `#[repr(C)]` 属性。

```rust
#[repr(C)]
pub struct MyCStruct {
    pub num: i32,
    pub flag: bool,
}
```

`#[repr(C)]` 告诉编译器使用 C 语言的布局规则来排列结构体的字段，而不是 Rust 默认的（为了优化而可能重排字段）。

## 将 Rust 代码暴露给其他语言

你也可以编写 Rust 函数，使其能够被 C 代码或其他支持 C ABI 的语言调用。

1.  **定义 `extern "C" fn`**: 创建一个遵循 C ABI 的函数。
2.  **`#[no_mangle]`**: 使用 `#[no_mangle]` 属性来禁止编译器在编译时修改函数名，确保函数名在链接时是可预测的。
3.  **配置 `Cargo.toml`**: 将你的 crate 类型设置为 `cdylib` (动态库) 或 `staticlib` (静态库)，以便生成可以被 C 链接器使用的库文件。

**`Cargo.toml` 配置**:
```toml
[lib]
name = "my_rust_lib"
crate-type = ["cdylib"] # 或 ["staticlib"]
```

**`src/lib.rs` 示例**:
```rust
use std::os::raw::c_char;
use std::ffi::CString;

#[no_mangle]
pub extern "C" fn rust_function(name: *const c_char) -> *mut c_char {
    let c_str = unsafe { std::ffi::CStr::from_ptr(name) };
    let recipient = c_str.to_str().unwrap_or("world");
    let output = format!("Hello, {}!", recipient);
    
    // 将 Rust String 转换回 C 字符串
    let c_output = CString::new(output).unwrap();
    c_output.into_raw()
}

/// 一个用于释放 C 字符串内存的函数
#[no_mangle]
pub extern "C" fn free_c_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s);
    }
}
```
**重要**: 当你通过 FFI 传递内存（如 `CString::into_raw()`）时，所有权也随之转移。你必须提供一个相应的函数（如 `free_c_string`）来让调用者能够安全地释放这块内存，以避免内存泄漏。

## 总结

- **`extern "C"`**: 是与 C 语言交互的基石，用于声明外部函数或定义 C 兼容的函数。
- **`unsafe`**: 调用外部函数是不安全的，必须在 `unsafe` 块中进行。
- **类型映射**: 使用 `libc` crate 和 `#[repr(C)]` 来确保 Rust 和 C 之间的数据类型兼容。
- **字符串处理**: 使用 `CString` 和 `CStr` 来安全地处理 C 风格的字符串。
- **暴露 Rust API**:
  - 使用 `extern "C" fn` 和 `#[no_mangle]` 来定义可供 C 调用的函数。
  - 在 `Cargo.toml` 中设置 `crate-type` 为 `cdylib` 或 `staticlib`。
- **内存管理**: 跨 FFI 边界传递内存所有权时，必须提供释放内存的机制。

FFI 是 Rust 的一个强大功能，它使得 Rust 能够轻松地集成到现有的 C 生态系统中，无论是利用成熟的 C 库，还是用 Rust 为其他语言编写高性能模块。 