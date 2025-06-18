# Rust高级类型

Rust拥有一个非常强大和富有表现力的类型系统。除了我们已经熟悉的基本类型、结构体和枚举之外，Rust还提供了一些高级类型概念，用于在特定场景下增强类型安全、提高代码可读性和表达复杂的数据结构。

## 目录

- [Newtype模式回顾](#newtype模式回顾)
- [类型别名（Type Aliases）](#类型别名type-aliases)
- [Never类型 `!`](#never类型-)
- [动态大小类型（DSTs）与`Sized`特质](#动态大小类型dsts与sized特质)
- [总结](#总结)

---

## Newtype模式回顾

我们在"高级特质"一章中已经介绍了Newtype模式，它通过在一个元组结构体中包装一个现有类型来创建一个全新的、独立的类型。

```rust
struct Wrapper(Vec<String>);
```

这种模式的核心优势在于：
1.  **增强类型安全**: 即使内部类型相同，不同的Newtype也是完全不同的类型，可以防止逻辑错误。例如，`Meters(5)`和`Millimeters(5000)`是不同的类型，不能混用。
2.  **抽象化实现细节**: 可以隐藏内部类型的实现细节，只暴露你想公开的方法。
3.  **为外部类型实现外部特质**: 这是绕过孤儿规则（Orphan Rule）的主要手段。

---

## 类型别名（Type Aliases）

类型别名允许你为一个已有的类型提供一个新的名字。它使用`type`关键字。与Newtype不同，**类型别名并不会创建一个新类型**，它仅仅是原类型的同义词。

```rust
// `Kilometers` 现在是 `i32` 的一个别名
type Kilometers = i32;

fn main() {
    let x: i32 = 5;
    let y: Kilometers = 5;

    // x和y的类型完全相同，可以自由操作
    println!("x + y = {}", x + y);
}
```

### 主要用途

类型别名的主要用途是**减少重复**和**提高可读性**。当一个类型签名非常长且复杂时，为其创建一个别名可以大大简化代码。

考虑一个处理`Result`的例子：
```rust
// 不使用类型别名
fn process_item(item: Box<dyn Fn() + Send + 'static>) -> std::io::Result<()> {
    // ...
    Ok(())
}

// 使用类型别名
type Thunk = Box<dyn Fn() + Send + 'static>;
type IoResult<T> = std::io::Result<T>;

fn process_item_aliased(item: Thunk) -> IoResult<()> {
    // ...
    Ok(())
}
```
第二个版本显然更清晰、更易于维护。类型别名在泛型和复杂组合类型中尤其有用。

---

## Never类型 `!`

`!`，被称为"Never类型"或"空类型"，是一个特殊的类型，它表示一个永远不会返回值的计算。一个返回`!`的函数被称为**发散函数（Diverging Function）**。

### 发散函数

发散函数不会将控制权交还给调用者。例如：

- `panic!`宏：
  ```rust
  fn bar() -> ! {
      panic!("This function never returns!");
  }
  ```
- 无限循环：
  ```rust
  fn endless_loop() -> ! {
      loop {
          println!("and ever...");
      }
  }
  ```

### `!` 的用处

`!`可以被强制转换成任何其他类型。这在`match`表达式中非常有用，可以确保所有分支都返回相同的类型。

```rust
use std::io;
use std::io::Read;

fn main() {
    let mut buffer = String::new();
    
    let result: u32 = match io::stdin().read_to_string(&mut buffer) {
        Ok(_) => {
            // 尝试解析字符串为 u32
            match buffer.trim().parse() {
                Ok(num) => num, // 这个分支返回 u32
                Err(_) => {
                    // 如果解析失败，panic!
                    // panic! 的类型是 `!`
                    // `!` 会被强制转换为 u32，使得整个 match 表达式类型一致
                    panic!("Failed to parse input");
                }
            }
        },
        Err(_) => panic!("Failed to read from stdin"),
    };
    
    println!("You entered: {}", result);
}
```
如果没有`!`，我们就无法在`parse`失败的分支返回一个与`num`（`u32`类型）兼容的类型。

---

## 动态大小类型（DSTs）与`Sized`特质

Rust需要在编译时知道一个类型所占用的内存空间大小。然而，有些类型的大小只能在运行时确定，这些类型被称为**动态大小类型（Dynamically Sized Types, DSTs）**，有时也叫"不定长类型"。

最常见的DST是`str`（注意，不是`&str`）和特质对象（`dyn Trait`）。

- `str`: 一个字符串切片的大小取决于它包含的字符数，这在编译时是未知的。
- `dyn Trait`: 一个特质对象可以指向任何实现了该特质的类型，而这些类型的大小可能各不相同。

### 使用DSTs的规则

因为无法在编译时确定DST的大小，所以你不能直接创建DST类型的变量或将其作为函数参数/返回值：

```rust
// let s1: str = "Hello"; // 错误！
// fn takes_str(s: str) {} // 错误！
```

**规则**：我们必须始终将DST放在某种指针后面，如`&`, `Box`, `Rc`等。
- `&str`：包含一个指向字符串起始地址的指针和一个长度。它的大小是已知的（两个`usize`）。
- `Box<str>`：同理。
- `&dyn Trait`：包含一个指向具体数据的指针和一个指向该类型虚函数表（vtable）的指针。它的大小也是已知的。

### `Sized`特质

为了处理DSTs，Rust在编译时使用`Sized`特质来标记那些大小已知（在编译时）的类型。
- 几乎所有类型都默认实现了`Sized`特质。
- Rust会自动为所有泛型函数添加`Sized`约束。

`fn generic<T>(t: T)` 实际上被编译器处理为 `fn generic<T: Sized>(t: T)`。

如果你想编写一个可以接受DST的泛型函数，你需要使用特殊的`?Sized`语法来放宽这个约束。

```rust
// 这个函数可以接受任何类型 T，无论其大小是否在编译时可知
fn generic<T: ?Sized>(t: &T) {
    // 函数体
}

fn main() {
    let s: &str = "hello";
    let t: &dyn std::fmt::Debug = &5;
    
    generic(s); // T是str，一个DST
    generic(t); // T是dyn Debug，一个DST
}
```
`?Sized`意味着"T可能是`Sized`的，也可能不是"。因为`T`可能是DST，所以我们必须通过指针（这里是`&T`）来使用它。

## 总结

- **Newtype模式**通过创建新类型来增强类型安全和绕过孤儿规则。
- **类型别名**为长类型提供简短的同义词，提高代码可读性，但不会创建新类型。
- **Never类型 `!`** 代表永不返回的计算，对于类型推断和`match`表达式的完备性检查非常重要。
- **动态大小类型（DSTs）**如`str`和`dyn Trait`在编译时大小未知，必须通过指针（如`&`或`Box`）来使用。
- **`Sized`特质**和`?Sized`语法让你能够编写可以处理DSTs的泛型代码。

这些高级类型概念展示了Rust类型系统的深度和灵活性，使你能够以极高的安全性和效率处理复杂和动态的数据结构。 