# Rust测试与文档

Rust拥有一流的内置支持，用于编写、运行测试和生成文档。这使得创建健壮、可靠且易于维护的软件变得更加简单。`cargo` 工具链是这一切的核心。

## 目录

- [编写测试](#编写测试)
- [运行测试 `cargo test`](#运行测试-cargo-test)
- [测试的组织](#测试的组织)
- [文档注释](#文档注释)
- [生成和查看文档 `cargo doc`](#生成和查看文档-cargo-doc)
- [总结](#总结)

---

## 编写测试

Rust中的测试本质上是用于验证代码是否按预期工作的函数。测试函数体通常执行三个操作：
1.  准备所需的数据或状态。
2.  调用需要测试的代码。
3.  断言（Assert）结果是否符合预期。

### 如何编写测试函数

- **`#[test]` 属性**: 将一个函数标记为测试函数。
- **`assert!` 宏**: 断言一个布尔表达式为`true`，如果为`false`则`panic`。
- **`assert_eq!` 和 `assert_ne!` 宏**: 分别断言两个表达式相等或不相等。它们在断言失败时能提供更详细的输出。

```rust
// 一个简单的待测试函数
pub fn add(left: usize, right: usize) -> usize {
    left + right
}

// Rust代码中的测试模块
#[cfg(test)]
mod tests {
    use super::*; // 引入外部模块的add函数

    #[test]
    fn exploration() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }

    #[test]
    fn another() {
        // 这个测试会失败
        // panic!("Make this test fail");
    }
}
```
- `#[cfg(test)]` 属性告诉编译器，只有在执行 `cargo test` 时才编译和运行 `tests` 模块中的代码。

### 测试 `panic!`

如果你想验证代码在特定条件下是否会如预期那样 `panic`，可以使用 `#[should_panic]` 属性。

```rust
pub struct Guess {
    value: i32,
}

impl Guess {
    pub fn new(value: i32) -> Guess {
        if value < 1 || value > 100 {
            panic!("Guess value must be between 1 and 100, got {}.", value);
        }
        Guess { value }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn greater_than_100() {
        Guess::new(200);
    }

    // 你还可以检查panic消息是否包含特定文本
    #[test]
    #[should_panic(expected = "less than or equal to 100")]
    fn greater_than_100_with_message() {
        Guess::new(200);
    }
}
```

### 使用 `Result<T, E>` 进行测试

测试函数也可以返回一个 `Result<T, E>`。这在需要使用 `?` 运算符的测试中非常方便。如果测试返回 `Ok(())` 则表示通过，返回 `Err` 则表示失败。

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() -> Result<(), String> {
        if 2 + 2 == 4 {
            Ok(())
        } else {
            Err(String::from("two plus two does not equal four"))
        }
    }
}
```

---

## 运行测试 `cargo test`

`cargo test` 命令会编译并运行项目中的所有测试。

### 常用命令和参数

- `cargo test`: 运行所有测试。
- `cargo test -- --test-threads=1`: 默认情况下，测试是并行运行的。此命令使测试串行执行，有助于处理共享状态或顺序依赖的问题。
- `cargo test -- --show-output`: 默认情况下，成功的测试不会打印任何输出。此命令会显示所有测试的标准输出。
- `cargo test <TEST_NAME>`: 只运行名称中包含 `<TEST_NAME>` 的测试。例如 `cargo test greater` 会运行 `greater_than_100` 和 `greater_than_100_with_message`。
- `cargo test -- --ignored`: 只运行被标记为 `#[ignore]` 的测试。
- `cargo test --test <INTEGRATION_TEST_FILENAME>`: 只运行指定的集成测试文件。

### 忽略某些测试

使用 `#[ignore]` 属性可以标记那些耗时较长或需要特殊环境的测试，使其在常规 `cargo test` 中被跳过。

```rust
#[test]
#[ignore]
fn expensive_test() {
    // a very time-consuming test
}
```

---

## 测试的组织

Rust社区通常将测试分为三类：**单元测试**、**集成测试**和**文档测试**。

### 1. 单元测试 (Unit Tests)

- **目的**: 测试最小的功能单元，通常是单个函数或模块，具有隔离性。
- **位置**: 与被测试的代码放在同一个文件（`src/lib.rs` 或 `src/main.rs` 等）的 `tests` 模块中。
- **特点**:
    - 使用 `#[cfg(test)]` 属性。
    - 可以测试私有函数。

### 2. 集成测试 (Integration Tests)

- **目的**: 测试库的公共API，验证多个部分是否能协同工作。
- **位置**: 放在项目根目录下的 `tests` 目录中。`Cargo` 会自动将该目录下的每个文件视为一个独立的Crate来编译和运行。
- **`tests/common.rs`**: 如果需要在多个集成测试文件之间共享代码，可以创建一个 `tests/common/mod.rs` 文件，然后在每个测试文件的开头使用 `mod common;` 来引入。

```
my_project/
├── Cargo.toml
├── src/
│   └── lib.rs
└── tests/
    ├── integration_test.rs
    └── common/
        └── mod.rs
```

**`tests/integration_test.rs` 示例:**
```rust
use my_project; // 引入你的库

mod common; // 引入共享模块

#[test]
fn it_adds_two() {
    common::setup();
    assert_eq!(4, my_project::add(2, 2));
}
```

### 3. 文档测试 (Documentation Tests)

- **目的**: 验证文档中的代码示例是否能够正常工作，确保文档与代码同步。
- **位置**: 写在文档注释的代码块中。
- `cargo test` 会自动执行这些测试。

---

## 文档注释

Rust非常重视代码文档。**文档注释**使用 `///`（而不是 `//`），并支持Markdown语法。它们用于描述函数、结构体、枚举等项的功能和用法。

```rust
/// Adds two to the number given.
///
/// # Examples
///
/// ```
/// let arg = 5;
/// let answer = my_crate::add_two(arg);
///
/// assert_eq!(7, answer);
/// ```
pub fn add_two(a: i32) -> i32 {
    a + 2
}
```

- **`///`**: 为紧随其后的项生成文档。
- **`//!`**: 为包含它的项（通常是模块或Crate）生成文档。常用于 `src/lib.rs` 或 `mod.rs` 的开头。
- **`# Examples`**: 一个常见的Markdown段落标题，用于提供用法示例。
- **代码块 ` ``` `**: `cargo doc` 会将其格式化为代码，`cargo test` 会将其作为文档测试来运行。

---

## 生成和查看文档 `cargo doc`

- `cargo doc`: 生成当前项目及其所有依赖的HTML文档。
- `cargo doc --open`: 生成文档并在浏览器中打开。
- `cargo doc --no-deps`: 只为当前Crate生成文档，不包括依赖。

生成的文档位于项目根目录下的 `target/doc` 目录中。

## 总结

- Rust的测试工具链集成在 `cargo` 中，简单易用。
- 通过 **`#[test]`** 属性编写测试，通过 **`assert!`** 宏系列进行断言。
- **单元测试**放在源代码的`tests`模块中，**集成测试**放在根目录的`tests`目录中。
- **`///` 文档注释**支持Markdown，并且代码示例会被自动测试。
- **`cargo test`** 和 **`cargo doc`** 是构建高质量Rust项目的两个核心命令。 