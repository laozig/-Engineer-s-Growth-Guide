# Rust闭包与迭代器

闭包（Closures）和迭代器（Iterators）是Rust中函数式编程思想的核心体现。它们允许你编写出表达力强、高度抽象且性能优异的代码。掌握它们是编写地道、高效Rust代码的关键。

## 目录

- [闭包：可以捕获环境的匿名函数](#闭包可以捕获环境的匿名函数)
- [迭代器：处理元素序列](#迭代器处理元素序列)
- [性能对比：循环 vs. 迭代器](#性能对比循环-vs-迭代器)
- [总结](#总结)

---

## 闭包：可以捕获环境的匿名函数

闭包是你可以保存在变量里或作为参数传递给其他函数的匿名函数。与普通函数不同的是，闭包可以捕获并使用其定义所在作用域中的变量。

### 闭包语法

闭包的语法简洁明了：

```rust
fn main() {
    let expensive_closure = |num: u32| -> u32 {
        println!("calculating slowly...");
        std::thread::sleep(std::time::Duration::from_secs(2));
        num
    };
    
    // 调用闭包
    let result = expensive_closure(5);
    println!("Result: {}", result);
}
```

- **`|param1, param2, ...|`**: 定义闭包的参数列表。
- **`{ ... }`**: 闭包的函数体。
- **类型推断**: Rust编译器通常能自动推断闭包参数和返回值的类型，所以大部分时候你不需要显式标注。

### 捕获环境

闭包的强大之处在于它能"借用"或"拥有"其定义环境中的变量。

```rust
fn main() {
    let x = 4;
    
    // 这个闭包捕获了`x`的不可变引用
    let equal_to_x = |z| z == x;
    
    let y = 4;
    
    assert!(equal_to_x(y));
}
```

### 闭包与`Fn`系列特质

根据闭包如何捕获和处理环境中的变量，编译器会为它们自动实现`Fn`、`FnMut`或`FnOnce`中的一个或多个特质。这是函数在接收闭包作为参数时使用的特质约束。

1.  **`FnOnce`**:
    - 表示闭包**最多只能被调用一次**。
    - 它会**获取**被捕获变量的**所有权**。所有闭包都至少实现了这个特质。
    - 一个消耗了捕获变量的闭包只会实现`FnOnce`。

    ```rust
    fn fn_once_example<F>(func: F)
    where
        F: FnOnce(String) -> String,
    {
        // 这个闭包被调用一次，消耗了`s`
        println!("{}", func(String::from("hello")));
    }
    ```

2.  **`FnMut`**:
    - 表示闭包可以被**多次调用**，并且在调用时可以**可变地借用**环境中的值。
    - 它实现了`FnOnce`。

    ```rust
    fn fn_mut_example<F>(mut func: F)
    where
        F: FnMut(),
    {
        func(); // 可变地调用
        func();
    }

    let mut x = 5;
    let mut change_x = || x += 1; // 这个闭包可变地借用了x
    fn_mut_example(&mut change_x);
    println!("{}", x); // 输出 7
    ```

3.  **`Fn`**:
    - 表示闭包可以被**多次调用**，并且在调用时只**不可变地借用**环境中的值。
    - 它同时实现了`FnOnce`和`FnMut`。

    ```rust
    fn fn_example<F>(func: F)
    where
        F: Fn(),
    {
        func(); // 不可变地调用
        func();
    }
    ```

**`move`关键字**: 你可以在闭包前使用`move`关键字来强制闭包获取它所使用的环境变量的所有权。这在将闭包传递给新线程时非常有用，可以确保引用的有效性。

---

## 迭代器：处理元素序列

迭代器模式允许你对一个序列中的所有元素执行某些任务。在Rust中，迭代器是**惰性（lazy）**的，这意味着在你不消耗它们之前，它们不会做任何事情。

### `Iterator`特质

一个类型要成为迭代器，只需为其实现`Iterator`特质。这个特质的核心是`next`方法：

```rust
pub trait Iterator {
    type Item; // 关联类型，代表序列中的元素类型

    // `next`是唯一必须实现的方法
    fn next(&mut self) -> Option<Self::Item>;

    // 其他方法都有默认实现
}
```
`next`方法每次调用会返回迭代器中的下一个元素，并将其包装在`Some`中。当迭代结束时，它会返回`None`。

### `for`循环与`into_iter`

`for`循环是消耗迭代器最常见的方式之一。当你写 `for item in &collection` 时，Rust实际上会调用`collection.into_iter()`来创建一个迭代器。

```rust
fn main() {
    let v1 = vec![1, 2, 3];

    // v1_iter 是一个迭代器
    let v1_iter = v1.iter(); // .iter() 创建一个产生不可变引用的迭代器

    for val in v1_iter {
        println!("Got: {}", val);
    }
}
```
有三种主要的方式可以从集合创建迭代器：
- **`iter()`**: 在集合上迭代，产生不可变引用 `&T`。
- **`into_iter()`**: 迭代并获取集合中元素的所有权 `T`。
- **`iter_mut()`**: 迭代并产生可变引用 `&mut T`。

### 迭代器适配器

迭代器适配器是`Iterator`特质上的一些方法，它们会改变迭代器的行为。它们自身也返回一个新的迭代器，并且是惰性的。

最常用的适配器包括：

- **`map`**: 接受一个闭包，对迭代器中的每个元素应用这个闭包，并返回一个新的迭代器。

  ```rust
  let v1: Vec<i32> = vec![1, 2, 3];
  let v2: Vec<_> = v1.iter().map(|x| x + 1).collect(); // [2, 3, 4]
  ```

- **`filter`**: 接受一个返回布尔值的闭包，并创建一个只包含该闭包返回`true`的元素的新迭代器。

  ```rust
  let v1 = vec![1, 2, 3, 4, 5, 6];
  let evens: Vec<_> = v1.into_iter().filter(|x| x % 2 == 0).collect(); // [2, 4, 6]
  ```

### 消耗型适配器

消耗型适配器会驱动迭代过程，并消耗掉迭代器。`collect`就是一个例子。

- **`collect()`**: 消耗迭代器，并将结果收集到一个集合类型中。

- **`sum()`**: 消耗迭代器，计算所有元素的总和。

  ```rust
  let v1 = vec![1, 2, 3];
  let total: i32 = v1.iter().sum(); // 6
  ```

- **`find()`**: 接受一个闭包，返回第一个满足条件的元素的`Some`，或在没有找到时返回`None`。

  ```rust
  let names = vec!["Bob", "Frank", "Ferris"];
  let found = names.iter().find(|name| **name == "Ferris");
  assert_eq!(found, Some(&"Ferris"));
  ```

### 创建自定义迭代器

你也可以通过为一个结构体实现`Iterator`特质来创建你自己的迭代器。

```rust
struct Counter {
    count: u32,
}

impl Counter {
    fn new() -> Counter {
        Counter { count: 0 }
    }
}

impl Iterator for Counter {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count < 5 {
            self.count += 1;
            Some(self.count)
        } else {
            None
        }
    }
}

fn main() {
    let counter = Counter::new();
    for i in counter {
        println!("{}", i); // 1, 2, 3, 4, 5
    }
}
```

---

## 性能对比：循环 vs. 迭代器

一个常见的疑问是：使用迭代器和适配器是否比手写`for`循环慢？

答案是：**不会**。

Rust的迭代器是**零成本抽象（Zero-cost Abstraction）**的典范。编译器会将迭代器适配器链优化成与手写循环同样高效的底层机器码，有时甚至更优，因为它能更好地利用缓存和指令流水线。你既获得了高级语言的表达力，又没有牺牲底层控制的性能。

## 总结

- **闭包**是能捕获其环境的匿名函数，通过`Fn`系列特质实现灵活的函数式编程。
- **迭代器**提供了一种强大、安全且高效的方式来处理元素序列。
- 迭代器是**惰性**的，只有在被消耗时才会执行操作。
- **迭代器适配器**如`map`和`filter`可以链式调用，以声明式的方式构建复杂的数据处理流水线。
- Rust的**零成本抽象**确保了使用迭代器不会带来性能损失。 