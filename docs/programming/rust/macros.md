# Rust宏编程

宏（Macros）是Rust元编程的主要方式之一，它允许你在编译时编写能够生成Rust代码的代码。这是一种强大的技术，可以帮助你减少重复代码、创建领域特定语言（DSL）以及实现普通函数无法做到的功能。

Rust中有两种主要的宏：**声明式宏（Declarative Macros）**和**过程宏（Procedural Macros）**。

## 目录

- [宏与函数的区别](#宏与函数的区别)
- [声明式宏 `macro_rules!`](#声明式宏-macro_rules)
- [过程宏](#过程宏)
- [自定义派生宏 `#[derive]`](#自定义派生宏-derive)
- [类属性宏](#类属性宏)
- [类函数宏](#类函数宏)
- [总结](#总结)

---

## 宏与函数的区别

| 特性 | 函数 | 宏 |
|---|---|---|
| **参数数量** | 固定 | 可变 |
| **类型检查** | 调用前进行严格类型检查 | 在代码展开后才进行类型检查 |
| **代码所有权** | 调用时获取参数所有权或借用 | 可以在代码展开的位置生成新的代码 |
| **实现方式** | 只能实现一种签名 | 可以有多个匹配分支，类似`match` |
| **运行时间** | 运行时执行 | 编译时展开为源代码 |

---

## 声明式宏 `macro_rules!`

声明式宏，也称为"示例宏"（Macros by Example），使用`macro_rules!`来定义。它的结构类似于一个`match`表达式，通过匹配输入的模式来决定要生成的代码。

### 定义一个简单的宏

我们来创建一个类似于`println!`的宏，但用于向量。

```rust
// 定义一个名为 `vec_print!` 的宏
#[macro_export] // 将宏导出，使其在其他文件中可见
macro_rules! vec_print {
    // 匹配模式：一个表达式
    ( $x:expr ) => {
        // 生成的代码
        println!("vec!{:?} = {:?}", stringify!($x), $x);
    };
}

fn main() {
    let my_vec = vec![1, 2, 3];
    vec_print!(my_vec); // 输出: vec!(my_vec) = [1, 2, 3]
}
```

### 匹配多种模式

`macro_rules!`可以有多个匹配臂，用`;`分隔。

```rust
#[macro_export]
macro_rules! my_vec {
    // 匹配空输入
    () => {
        std::vec::Vec::new()
    };
    // 匹配一个或多个表达式，用逗号分隔
    ( $( $x:expr ),+ ) => {
        {
            let mut temp_vec = std::vec::Vec::new();
            $(
                temp_vec.push($x);
            )+
            temp_vec
        }
    };
}

fn main() {
    let v: Vec<u32> = my_vec!();
    println!("{:?}", v); // []

    let v2 = my_vec![1, 2, 3];
    println!("{:?}", v2); // [1, 2, 3]
}
```

- **`$()`**: 用于重复匹配。
- **`$x:expr`**: 匹配一个表达式，并将其捕获到变量`$x`中。
- **`+`**: 表示前面的模式可以匹配一次或多次。`*`表示零次或多次。
- **指示符（Designators）**: `:expr`是一种指示符，其他常见的还有`:ident` (标识符), `:ty` (类型), `:stmt` (语句), `:pat` (模式)等。

---

## 过程宏

过程宏（Procedural Macros）更像一个函数，它接收一串Token（`TokenStream`）作为输入，对其进行处理，然后返回另一串`TokenStream`作为输出。

过程宏必须定义在它们自己的、具有特殊crate类型的Crate中。在`Cargo.toml`中设置：
```toml
[lib]
proc-macro = true
```

有三种类型的过程宏：
1.  自定义派生宏
2.  类属性宏
3.  类函数宏

---

## 自定义派生宏 `#[derive]`

这是最常见的过和和宏。它允许你为结构体和枚举创建自定义的`#[derive]`属性。

**示例：创建一个`HelloWorld`派生宏**

1.  **创建宏Crate (`hello_macro`)**:
    ```toml
    # hello_macro/Cargo.toml
    [lib]
    proc-macro = true

    [dependencies]
    syn = "1.0"
    quote = "1.0"
    ```
    - `syn`: 用于将Rust代码的字符串解析成一个可以操作的数据结构。
    - `quote`: 将`syn`产生的数据结构转换回Rust代码。

2.  **编写宏代码**:
    ```rust
    // hello_macro/src/lib.rs
    extern crate proc_macro;

    use proc_macro::TokenStream;
    use quote::quote;
    use syn;

    #[proc_macro_derive(HelloWorld)]
    pub fn hello_world_derive(input: TokenStream) -> TokenStream {
        // 将输入的TokenStream解析成一个语法树
        let ast = syn::parse(input).unwrap();

        // 构建要生成的代码
        impl_hello_world(&ast)
    }

    fn impl_hello_world(ast: &syn::DeriveInput) -> TokenStream {
        let name = &ast.ident; // 获取类型的名称
        let gen = quote! {
            impl HelloWorld for #name {
                fn hello_world() {
                    // stringify! 将标识符转换为字符串
                    println!("Hello, Macro! My name is {}!", stringify!(#name));
                }
            }
        };
        gen.into()
    }
    ```

3.  **在主Crate中使用**:
    ```rust
    // main crate
    use hello_macro::HelloWorld; // 引入派生宏
    
    // 定义一个trait
    pub trait HelloWorld {
        fn hello_world();
    }
    
    #[derive(HelloWorld)] // 使用自定义派生宏
    struct Pancakes;

    fn main() {
        Pancakes::hello_world(); // 输出: Hello, Macro! My name is Pancakes!
    }
    ```

---

## 类属性宏

类属性宏允许你创建自定义的属性，用于附加到任何项上。它们比派生宏更灵活。

例如，一个Web框架可能会使用属性宏来定义路由：
```rust
// #[route(GET, "/")]
fn index() {
    // ...
}
```

### 定义

```rust
#[proc_macro_attribute]
pub fn route(attr: TokenStream, item: TokenStream) -> TokenStream {
    // attr: 宏属性的内容，即 (GET, "/")
    // item: 被附加属性的项，即 fn index() { ... }
    // ...
    item // 通常会返回原始的item，或者修改后的item
}
```

---

## 类函数宏

类函数宏的定义方式与声明式宏类似，但更灵活，因为你可以使用Rust代码来处理输入的`TokenStream`。

例如，一个将SQL语句直接嵌入并验证的宏：
```rust
let sql = sql!(SELECT * FROM posts WHERE id=1);
```

### 定义

```rust
#[proc_macro]
pub fn sql(input: TokenStream) -> TokenStream {
    // ... 解析和验证SQL ...
    // 返回一个包含结果的TokenStream
}
```

## 总结

- Rust提供两种宏系统：**声明式宏 (`macro_rules!`)** 和 **过程宏**。
- **声明式宏**通过模式匹配工作，适合简单的代码生成和DSL。
- **过程宏**接收并操作Token流，功能更强大，但实现也更复杂。
- 过程宏分为三种：**自定义派生宏**（如`#[derive(MyTrait)]`）、**类属性宏**（如`#[my_attribute]`）和**类函数宏**（如`my_macro!(...)`）。
- 编写过程宏通常需要`syn`和`quote`这两个强大的Crate来辅助解析和生成代码。

宏是Rust语言最强大的特性之一，善用宏可以极大地提升代码的表达力和可维护性。 