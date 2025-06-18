# Rust高级特质

特质（Traits）是Rust最核心和强大的功能之一。在掌握了基础用法之后，本章将带你深入了解一些高级特质概念，它们能让你编写出更灵活、更具表现力且更符合人体工程学的API。

## 目录

- [关联类型（Associated Types）](#关联类型associated-types)
- [默认泛型类型参数](#默认泛型类型参数)
- [运算符重载](#运算符重载)
- [完全限定语法消除歧义](#完全限定语法消除歧义)
- [父特质（Supertraits）](#父特质supertraits)
- [Newtype模式与外部特质](#newtype模式与外部特质)
- [总结](#总结)

---

## 关联类型（Associated Types）

关联类型将一个类型占位符与特质关联起来，使得在实现该特质时需要指定具体的类型。它允许特质的方法签名使用这些占位符类型。

我们已经见过最经典的例子——`Iterator`特质：
```rust
pub trait Iterator {
    type Item; // `Item`是关联类型

    fn next(&mut self) -> Option<Self::Item>;
}
```
当为一个类型实现`Iterator`时，必须明确`Item`的具体类型。

### 为什么不用泛型？

你可能会问，为什么不这样定义`Iterator`：
```rust
pub trait Iterator<Item> {
    fn next(&mut self) -> Option<Item>;
}
```
这样做的问题在于，它允许一个类型多次为不同`Item`实现`Iterator`（例如，`impl Iterator<String> for MyType`和`impl Iterator<u32> for MyType`）。但在迭代器的场景下，我们希望一个类型只对应一种迭代出的元素类型。

**关联类型强制了这种一对一的关系**，简化了类型签名，因为你不再需要在任何地方都写`Iterator<Item>`。

---

## 默认泛型类型参数

在定义泛型类型时，你可以为泛型参数指定一个默认的具体类型。这在减少重复代码和简化常见用例方面非常有用。

标准库中的`Add`特质就是一个很好的例子：
```rust
use std::ops::Add;

trait Add<Rhs = Self> {
    type Output;
    fn add(self, rhs: Rhs) -> Self::Output;
}
```
- **`Rhs = Self`**: 这里`Rhs`（Right Hand Side，右操作数）是一个泛型参数，它的默认类型是`Self`，即实现`Add`特质的类型本身。
- 这意味着，当你写`a + b`时，编译器默认`b`和`a`是相同类型。

```rust
use std::ops::Add;

#[derive(Debug, PartialEq)]
struct Point {
    x: i32,
    y: i32,
}

// 我们没有指定 `Rhs`，所以它默认为 `Point`
impl Add for Point {
    type Output = Point;

    fn add(self, other: Point) -> Point {
        Point {
            x: self.x + other.x,
            y: self.y + other.y,
        }
    }
}

fn main() {
    assert_eq!(
        Point { x: 1, y: 0 } + Point { x: 2, y: 3 },
        Point { x: 3, y: 3 }
    );
}
```

---

## 运算符重载

Rust允许你通过实现`std::ops`中定义的特质来自定义运算符（如`+`, `*`, `-`）的行为。这被称为**运算符重载**。

例如，要重载`+`运算符，你需要为你的类型实现`Add`特质。

```rust
// 见上文 `Point` 的 `Add` 实现
```
你不能为任意类型实现任意特质（孤儿规则），也不能创建新的运算符。

---

## 完全限定语法消除歧义

当代码中存在多个同名方法时，Rust有时需要你更明确地指出要调用哪一个。这种情况通常发生在：
- 一个类型实现了多个具有同名方法的特质。
- 一个类型自身的方法与它所实现的特质的方法同名。

**完全限定语法**的格式如下：
`<Type as Trait>::function(receiver_if_method, ...)`

### 示例

```rust
trait Pilot {
    fn fly(&self);
}

trait Wizard {
    fn fly(&self);
}

struct Human;

impl Pilot for Human {
    fn fly(&self) {
        println!("This is your captain speaking.");
    }
}

impl Wizard for Human {
    fn fly(&self) {
        println!("Up!");
    }
}

impl Human {
    fn fly(&self) {
        println!("*waving arms furiously*");
    }
}

fn main() {
    let person = Human;
    
    // 默认调用类型自身的方法
    person.fly(); // *waving arms furiously*

    // 使用完全限定语法来调用特定特质的方法
    Pilot::fly(&person);   // This is your captain speaking.
    Wizard::fly(&person);  // Up!
    Human::fly(&person); // *waving arms furiously*
}
```
当特质方法没有`self`参数（即关联函数）时，也需要使用这种语法。

---

## 父特质（Supertraits）

有时，你希望一个特质的功能依赖于另一个特质。例如，一个用于在屏幕上绘制的`Display`特质可能需要其类型也实现了`Debug`特质以便于调试。

这可以通过在特质定义中指定**父特质**来实现。

```rust
use std::fmt;

// 要求实现 OutlinePrint 的类型也必须实现 fmt::Display
trait OutlinePrint: fmt::Display {
    fn outline_print(&self) {
        let output = self.to_string(); // to_string() 来自 Display 特质
        let len = output.len();
        println!("{}", "*".repeat(len + 4));
        println!("*{}*", " ".repeat(len + 2));
        println!("* {} *", output);
        println!("*{}*", " ".repeat(len + 2));
        println!("{}", "*".repeat(len + 4));
    }
}

struct Point {
    x: i32,
    y: i32,
}

// 必须先实现 Display
impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

// 现在可以实现 OutlinePrint 了
impl OutlinePrint for Point {}

fn main() {
    let p = Point {x: 1, y: 3};
    p.outline_print();
}
```
如果你尝试为一个没有实现`Display`的类型实现`OutlinePrint`，编译器会报错。

---

## Newtype模式与外部特质

我们之前提到过**孤儿规则（Orphan Rule）**：你只能在本地Crate中为本地类型实现本地特质。换句话说，你不能为外部类型（如`Vec<T>`）实现外部特质（如`Display`）。

**Newtype模式**可以绕过这个限制。它通过在一个只包含一个字段的元组结构体（Tuple Struct）中包装一个现有类型来创建一个新类型。

```rust
use std::fmt;

// `Wrapper` 是一个新的类型，它包装了一个 `Vec<String>`
struct Wrapper(Vec<String>);

// 我们可以为本地的 `Wrapper` 类型实现外部的 `Display` 特质
impl fmt::Display for Wrapper {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}]", self.0.join(", "))
    }
}

fn main() {
    let w = Wrapper(vec![String::from("hello"), String::from("world")]);
    println!("w = {}", w); // 输出: w = [hello, world]
}
```
这个模式非常有用，它允许你在不改变原始类型的情况下，为其添加新的行为或保证某些类型约束。

## 总结

- **关联类型**通过将类型占位符绑定到特质，强制实现一对一的类型关系，使API更简洁。
- **默认泛型参数**减少了样板代码，使泛型API在常见场景下更易用。
- **运算符重载**通过实现`ops`特质，让自定义类型也能使用熟悉的运算符。
- **完全限定语法**解决了方法命名冲突的问题。
- **父特质**允许你在一个特质中建立对另一个特质的依赖。
- **Newtype模式**是绕过孤儿规则、为外部类型实现外部特质的强大工具。

这些高级特质用法是Rust类型系统强大表现力的核心，善用它们可以构建出既安全又高度抽象的库。 