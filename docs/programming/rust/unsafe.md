# 不安全Rust (Unsafe Rust)

Rust通过其所有权系统和借用检查器在编译时提供了强大的内存安全保障。然而，在某些特定场景下，这些静态检查过于保守，或者需要与不受Rust管理的底层系统交互。为此，Rust提供了`unsafe`关键字，它允许程序员承担一部分保证内存安全的责任，以换取更大的灵活性和性能。

**`unsafe`并不意味着关闭所有安全检查，它只是允许你执行五类编译器无法静态保证安全的操作。**

## 目录

- [Unsafe超能力](#unsafe超能力)
- [使用`unsafe`块](#使用unsafe块)
- [解引用裸指针](#解引用裸指针)
- [调用不安全的函数或方法](#调用不安全的函数或方法)
- [访问或修改可变的静态变量](#访问或修改可变的静态变量)
- [实现不安全的特质](#实现不安全的特质)
- [创建安全的抽象](#创建安全的抽象)
- [总结](#总结)

---

## Unsafe超能力

在`unsafe`块或`unsafe`函数内部，你可以执行以下五种操作，这些操作在安全Rust中是不被允许的。我们称之为"Unsafe超能力"：

1.  **解引用裸指针（raw pointers）**
2.  **调用`unsafe`函数或方法**
3.  **访问或修改可变的静态变量**
4.  **实现`unsafe`特质**
5.  **访问`union`中的字段**

`unsafe`关键字并不会关闭借用检查器或Rust的其他安全检查。如果在`unsafe`块中使用了引用，它仍然会被检查。

---

## 使用`unsafe`块

`unsafe`块用于隔离那些编译器无法保证安全的代码。它的目的是告诉编译器："相信我，我知道我在这里做的事情是安全的。"

```rust
fn main() {
    let mut num = 5;

    // 创建裸指针
    // 创建裸指针是安全的，只有解引用它才是不安全的
    let r1 = &num as *const i32;
    let r2 = &mut num as *mut i32;

    unsafe {
        println!("r1 is: {}", *r1);
        println!("r2 is: {}", *r2);
    }
}
```

---

## 解引用裸指针

裸指针（`*const T` 和 `*mut T`）与引用的区别在于：
- **允许忽略借用规则**：可以同时拥有一个可变和一个不可变的裸指针，或者多个可变的裸指针。
- **不保证指向有效的内存**。
- **允许为空（null）**。
- **不实现任何自动清理**。

通过`unsafe`，你可以将这些指针解引用，直接读写内存。

```rust
fn main() {
    let address = 0x012345usize;
    let r = address as *const i32;

    // 访问任意内存地址是危险的！
    // 这可能导致段错误（segmentation fault）
    unsafe {
        // println!("r is: {}", *r);
    }
}
```

---

## 调用不安全的函数或方法

`unsafe`函数或方法是指在函数定义前加上`unsafe`关键字的函数。这表明该函数内部包含了一些需要调用者来维护其安全性的操作。

```rust
// 定义一个不安全的函数
unsafe fn dangerous() {
    println!("This is a dangerous function!");
}

fn main() {
    // 调用不安全的函数必须在`unsafe`块中进行
    unsafe {
        dangerous();
    }
}
```

### 外部函数接口（FFI）

与其它语言（如C语言）进行交互是`unsafe`最常见的用途之一。调用外部语言的函数本质上是不安全的，因为Rust编译器无法检查外部代码的安全性。

```rust
// 声明一个外部C函数`abs`
extern "C" {
    fn abs(input: i32) -> i32;
}

fn main() {
    unsafe {
        println!("Absolute value of -3 according to C: {}", abs(-3));
    }
}
```

---

## 访问或修改可变的静态变量

Rust允许创建全局变量，即**静态变量**。但如果一个静态变量是可变的，那么在多线程环境下访问它可能会导致数据竞争。因此，Rust规定对可变静态变量的读写必须在`unsafe`块中进行。

```rust
static mut COUNTER: u32 = 0;

fn add_to_count(inc: u32) {
    unsafe {
        COUNTER += inc;
    }
}

fn main() {
    add_to_count(3);

    unsafe {
        println!("COUNTER: {}", COUNTER); // 输出 COUNTER: 3
    }
}
```
**警告**：在多线程代码中，应优先使用线程安全的并发原语（如`Mutex`）来管理可变状态，而不是依赖可变静态变量。

---

## 实现不安全的特质

当一个特质中至少有一个方法包含编译器无法验证的不变式时，可以将该特质标记为`unsafe`。这意味着实现该特质的类型必须保证它满足这些不变式。

标准库中的 `Send` 和 `Sync` 就是 `unsafe` 的特质。编译器会自动为字段都是 `Send` 和 `Sync` 的类型派生它们，但你也可以手动实现它们，这需要一个 `unsafe impl` 块。

```rust
// MyType 不是自动 Sync 的
struct MyType {
    // ...
}

// 程序员保证 MyType 是线程安全的
unsafe impl Sync for MyType {
    // ...
}
```

---

## 创建安全的抽象

尽管`unsafe`允许我们执行不安全的操作，但我们的目标通常是将这些不安全的代码包装在一个**安全的抽象**中。一个良好的实践是，在模块或函数内部使用小范围的`unsafe`代码，并提供一个安全的公共API，其外部使用者无需编写任何`unsafe`代码。

例如，标准库中的`Vec<T>`的`split_at_mut`方法就是一个很好的例子。它在内部使用`unsafe`代码来操作裸指针以创建两个可变的切片，但它提供了一个完全安全的外部接口。

```rust
use std::slice;

fn my_split_at_mut(slice: &mut [i32], mid: usize) -> (&mut [i32], &mut [i32]) {
    let len = slice.len();
    let ptr = slice.as_mut_ptr();

    assert!(mid <= len);

    // 内部使用unsafe，但函数签名是安全的
    unsafe {
        (
            slice::from_raw_parts_mut(ptr, mid),
            slice::from_raw_parts_mut(ptr.add(mid), len - mid),
        )
    }
}
```

## 总结

- `unsafe`关键字让你能够执行五种编译器无法保证内存安全的操作。
- `unsafe`代码不意味着"不安全"，而是意味着**"程序员，请你来保证这部分代码的内存安全"**。
- 使用裸指针、调用FFI、修改可变静态变量等是`unsafe`的常见应用场景。
- `unsafe`的最佳实践是将其封装在小范围内，并提供一个安全的公共API。

通过`unsafe`，Rust在保证极高安全性的同时，也保留了进行底层系统编程和与外部世界高效交互的能力。 