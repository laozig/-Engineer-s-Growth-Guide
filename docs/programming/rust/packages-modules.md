# Rust 包与模块系统

Rust 的模块系统是其代码组织的核心，旨在管理代码的复杂性、作用域和隐私。它允许开发者将代码库分割成逻辑单元，使得代码更易于导航、维护和重用。这个系统由几个关键概念组成：包（Packages）、Crates、模块（Modules）、路径（Paths）和 `use` 声明。

## 核心概念

### 1. 包 (Packages)

一个**包**是 Cargo 的一个功能，它允许你构建、测试和分享 crates。一个包包含一个 `Cargo.toml` 文件，该文件描述了如何构建这些 crates。

- **`Cargo.toml`**: 包的清单文件，定义了包的元数据、依赖项和构建配置。
- **功能**: 一个包可以包含多个二进制 crate 和一个可选的库 crate。
- **规则**:
  - 一个包必须包含零个或一个库 crate。
  - 一个包可以包含任意数量的二进制 crate。
  - 一个包必须至少包含一个 crate（无论是库 crate 还是二进制 crate）。

当你使用 `cargo new my-project` 创建一个新项目时，Cargo 会为你创建一个包。

### 2. Crates

一个 **Crate** 是 Rust 的编译单元。它要么是一个二进制文件（可执行文件），要么是一个库（可共享的代码）。

- **库 Crate (Library Crate)**:
  - 目的是提供可复用的功能。
  - 它的根文件通常是 `src/lib.rs`。
  - 编译后会生成一个 `.rlib` 文件，可以被其他项目链接。
  - 一个包最多只能有一个库 crate。

- **二进制 Crate (Binary Crate)**:
  - 目的是生成一个可执行程序。
  - 它的根文件通常是 `src/main.rs`。
  - `src/bin/` 目录下的每个 `.rs` 文件都会被编译成一个独立的二进制 crate。

`crate` 关键字在代码中也指代当前 crate 的根模块。

### 3. 模块 (Modules)

**模块**是 Rust 代码组织的基本单位，用于在 crate 内部控制作用域和代码隐私。你可以使用 `mod` 关键字来定义一个模块。

- **定义模块**:
  ```rust
  // src/lib.rs
  mod front_of_house {
      mod hosting {
          fn add_to_waitlist() {}
      }
  }
  ```

- **模块可以嵌套**: 如上例所示，`hosting` 模块嵌套在 `front_of_house` 模块中。

- **文件系统集成**:
  - Rust 编译器会从 crate 根文件（`src/lib.rs` 或 `src/main.rs`）开始查找模块。
  - 当编译器遇到 `mod my_module;` 声明时，它会查找以下文件：
    1.  `src/my_module.rs` (对于2018及之后版本)
    2.  `src/my_module/mod.rs` (旧版风格，仍然支持)

  **示例**:
  ```
  src/
  ├── lib.rs
  ├── front_of_house.rs
  └── front_of_house/
      └── hosting.rs
  ```

  `src/lib.rs` 中可以这样写:
  ```rust
  // src/lib.rs
  mod front_of_house; // 编译器会查找 src/front_of_house.rs

  pub fn eat_at_restaurant() {
      // ...
  }
  ```

  `src/front_of_house.rs` 中可以这样写:
  ```rust
  // src/front_of_house.rs
  pub mod hosting; // 编译器会查找 src/front_of_house/hosting.rs
  ```

  `src/front_of_house/hosting.rs` 中可以这样写:
  ```rust
  // src/front_of_house/hosting.rs
  pub fn add_to_waitlist() {}
  ```

## 路径 (Paths) 与作用域

**路径**用于命名和访问模块中的项（如函数、结构体、枚举等）。路径可以是**绝对路径**或**相对路径**。

- **绝对路径 (Absolute Path)**: 从 crate 根开始，使用 `crate` 关键字或 crate 名称。
- **相对路径 (Relative Path)**: 从当前模块开始，使用 `self`、`super` 或模块名。

```rust
mod front_of_house {
    pub mod hosting {
        pub fn add_to_waitlist() {}
    }
}

pub fn eat_at_restaurant() {
    // 绝对路径
    crate::front_of_house::hosting::add_to_waitlist();

    // 相对路径
    front_of_house::hosting::add_to_waitlist();
}
```

### `pub` 关键字与隐私

默认情况下，Rust 中的所有项（函数、模块、结构体等）都是私有的。要使其可见，需要使用 `pub` 关键字。

- **规则**:
  - `pub` 使项对父模块可见。
  - 如果要使一个项在整个包（crate）外都可见，需要在其所有父模块和它自身的定义前都加上 `pub`。
  - `pub` 也可以与模块一起使用，如 `pub mod ...`。
  - 结构体的字段默认是私有的，即使结构体本身是 `pub` 的。每个字段都需要单独标记为 `pub`。
  - 枚举的变体默认与枚举本身具有相同的可见性。如果枚举是 `pub` 的，其所有变体也都是 `pub` 的。

**示例**:
```rust
mod back_of_house {
    pub struct Breakfast {
        pub toast: String,
        seasonal_fruit: String, // 私有字段
    }

    impl Breakfast {
        pub fn summer(toast: &str) -> Breakfast {
            Breakfast {
                toast: String::from(toast),
                seasonal_fruit: String::from("peaches"),
            }
        }
    }
}

pub fn eat_at_restaurant() {
    let mut meal = back_of_house::Breakfast::summer("Rye");
    meal.toast = String::from("Wheat"); // 可以修改
    // meal.seasonal_fruit = String::from("blueberries"); // 错误：字段是私有的
}
```

## `use` 关键字

`use` 关键字用于将路径导入到当前作用域，从而避免重复写长路径。

- **基本用法**:
  ```rust
  use crate::front_of_house::hosting;
  // use self::front_of_house::hosting; // 也可以用相对路径

  pub fn eat_at_restaurant() {
      hosting::add_to_waitlist();
      hosting::add_to_waitlist();
  }
  ```

- **惯用方式**:
  - 对于函数，通常 `use` 到其父模块，然后通过 `module::function()` 调用。这有助于清晰地表明函数来源。
  - 对于结构体、枚举和其他项，通常 `use` 到其完整路径。

  ```rust
  use std::collections::HashMap; // 引入结构体

  fn main() {
      let mut map = HashMap::new();
      map.insert(1, 2);
  }
  ```

- **`as` 关键字重命名**:
  `use` 允许使用 `as` 关键字为引入的类型提供一个新的本地名称，以避免命名冲突。
  ```rust
  use std::fmt::Result;
  use std::io::Result as IoResult;

  fn function1() -> Result {
      // ...
  }

  fn function2() -> IoResult<()> {
      // ...
  }
  ```

- **`pub use` 重导出**:
  `pub use` 可以将一个项引入到当前作用域，并使其对外部代码也可见。这对于创建稳定的公共 API 非常有用。
  ```rust
  // src/lib.rs
  mod front_of_house {
      pub mod hosting {
          pub fn add_to_waitlist() {}
      }
  }

  pub use crate::front_of_house::hosting; // 重导出 hosting 模块

  pub fn eat_at_restaurant() {
      hosting::add_to_waitlist();
  }
  ```
  现在，使用这个库的代码可以直接通过 `my_crate::hosting` 访问 `hosting` 模块。

- **使用 `*` 通配符**:
  `*` 通配符可以导入一个路径下所有 `pub` 的项。
  ```rust
  use std::collections::*;
  ```
  **注意**: 通配符应谨慎使用，因为它可能引入不明确的名称，使代码难以理解。它在测试模块或 prelude 模块中比较常见。

## 模块组织最佳实践

1.  **Crate 根 (`src/main.rs` 或 `src/lib.rs`)**:
    - 声明顶层模块。
    - `use` 外部依赖。
    - `pub use` 重导出库的公共 API。
    - 包含最小的逻辑，主要用于连接各个模块。

2.  **模块文件分离**:
    - 当模块变大时，将其代码移入单独的文件 (`mod_name.rs`) 或目录 (`mod_name/mod.rs`)。
    - 使用 `mod mod_name;` 在父模块中声明它。

3.  **Prelude 模式**:
    - 创建一个 `prelude` 模块，`pub use` 所有最常用的类型和特质。
    - 库的使用者只需 `use my_crate::prelude::*;` 即可方便地获取所有常用项。

## 总结

Rust 的包与模块系统提供了一套强大而灵活的工具来组织代码。通过 `Packages` 和 `Crates` 管理项目和依赖，通过 `mod` 和 `use` 控制作用域和路径，开发者可以构建出清晰、可维护且可扩展的大型项目。理解这些概念是精通 Rust 并编写高质量代码的关键一步。 