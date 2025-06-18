# Rust智能指针

智能指针（Smart Pointers）是Rust中一类重要的数据结构，它们表现得像指针，但拥有额外的元数据和功能。与普通引用（`&`）不同，智能指针通常拥有它们所指向的数据，并可以通过实现特定的特质（如`Deref`和`Drop`）来赋予其特殊行为。

本文档将详细介绍Rust标准库中最常用和最重要的几种智能指针。

## 目录

- [什么是智能指针？](#什么是智能指针)
- [`Box<T>`：在堆上分配数据](#boxt在堆上分配数据)
- [通过`Deref`特质将智能指针视为常规引用](#通过deref特质将智能指针视为常规引用)
- [通过`Drop`特质自定义清理逻辑](#通过drop特质自定义清理逻辑)
- [`Rc<T>`：引用计数智能指针](#rct引用计数智能指针)
- [`RefCell<T>`与内部可变性模式](#refcellt与内部可变性模式)
- [总结](#总结)

---

## 什么是智能指针？

从根本上说，智能指针是实现了`Deref`和`Drop`特质的结构体。
- `Deref`特质允许智能指针的实例像引用一样被解引用。
- `Drop`特质允许你自定义当智能指针实例离开作用域时发生的行为，例如释放资源。

引用（`&`）和智能指针的一个关键区别是：引用仅仅是借用数据，而智能指针通常**拥有**它们指向的数据。

---

## `Box<T>`：在堆上分配数据

`Box<T>`是最简单直接的智能指针，它允许你将数据存储在**堆（Heap）**上，而在**栈（Stack）**上只保留一个指向堆数据的指针。

### 何时使用`Box<T>`？

1.  **当有一个在编译时无法确定大小的类型，但又想在需要确切大小的上下文中使用它时。**
    最典型的例子是递归类型。例如，一个列表可以是 `(元素, 指向下一个列表的指针)`。

    ```rust
    // 这个定义会报错，因为编译器无法确定 `List` 的大小
    // enum List {
    //     Cons(i32, List),
    //     Nil,
    // }

    // 使用 `Box` 来获得固定大小
    enum List {
        Cons(i32, Box<List>),
        Nil,
    }

    use crate::List::{Cons, Nil};

    fn main() {
        let list = Cons(1, Box::new(Cons(2, Box::new(Cons(3, Box::new(Nil))))));
    }
    ```

2.  **当有大量数据并希望转移所有权而不是复制它时。**
    `Box<T>`实现了`Drop`，当`Box`离开作用域时，它所指向的堆数据也会被清理。

3.  **当希望拥有一个值，但只关心它是否实现了某个特定的特质（即特质对象）时。**
    我们已经在并发和特质的文档中见过 `Box<dyn Trait>` 的用法。

---

## 通过`Deref`特质将智能指针视为常规引用

实现`Deref`特质使得我们可以自定义解引用运算符 `*` 的行为。

```rust
use std::ops::Deref;

struct MyBox<T>(T);

impl<T> MyBox<T> {
    fn new(x: T) -> MyBox<T> {
        MyBox(x)
    }
}

// 为 MyBox 实现 Deref
impl<T> Deref for MyBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn main() {
    let x = 5;
    let y = MyBox::new(x);

    assert_eq!(5, x);
    assert_eq!(5, *y); // *y 被编译器转换为 *(y.deref())
}
```

### 解引用强制转换（Deref Coercion）

解引用强制转换是Rust编译器提供的一种便利功能。如果一个类型`U`实现了`Deref<Target=T>`，那么`&U`类型的值可以被自动转换成`&T`。

这个转换是连续的，例如 `&String` -> `&str`。因为`String`实现了`Deref<Target=str>`。

```rust
fn hello(name: &str) {
    println!("Hello, {}!", name);
}

fn main() {
    let m = MyBox::new(String::from("Rust"));
    hello(&m); // &MyBox<String> -> &String -> &str
}
```

---

## 通过`Drop`特质自定义清理逻辑

`Drop`特质允许你在值即将离开作用域时执行一些代码，非常适合用于释放资源，如文件句柄、网络连接或内存。

```rust
struct CustomSmartPointer {
    data: String,
}

impl Drop for CustomSmartPointer {
    fn drop(&mut self) {
        println!("Dropping CustomSmartPointer with data `{}`!", self.data);
    }
}

fn main() {
    let c = CustomSmartPointer { data: String::from("my stuff") };
    let d = CustomSmartPointer { data: String::from("other stuff") };
    println!("CustomSmartPointers created.");
    // c和d会在这里以相反的顺序被drop
}
```

### 使用`std::mem::drop`提早丢弃值

有时你可能想在作用域结束前提早释放一个值。你不能直接调用`drop`方法，但可以使用标准库提供的`std::mem::drop`函数。

```rust
fn main() {
    let c = CustomSmartPointer { data: String::from("some data") };
    println!("CustomSmartPointer created.");
    drop(c); // 显式调用std::mem::drop
    println!("CustomSmartPointer dropped before the end of main.");
}
```

---

## `Rc<T>`：引用计数智能指针

`Rc<T>`（Reference Counted）允许多个所有者共同拥有同一份数据。它记录了指向数据的引用数量，只有当引用数量归零时，数据才会被清理。

**注意**：`Rc<T>`**只用于单线程场景**。在多线程中，你需要使用线程安全的`Arc<T>`。

```rust
use std::rc::Rc;

enum List {
    Cons(i32, Rc<List>),
    Nil,
}

use crate::List::{Cons, Nil};

fn main() {
    let a = Rc::new(Cons(5, Rc::new(Cons(10, Rc::new(Nil)))));
    println!("count after creating a = {}", Rc::strong_count(&a)); // 1

    // Rc::clone 只会增加引用计数，不会深拷贝数据
    let b = Cons(3, Rc::clone(&a));
    println!("count after creating b = {}", Rc::strong_count(&a)); // 2

    {
        let c = Cons(4, Rc::clone(&a));
        println!("count after creating c = {}", Rc::strong_count(&a)); // 3
    } // c 在此被销毁，引用计数减 1

    println!("count after c goes out of scope = {}", Rc::strong_count(&a)); // 2
}
```

---

## `RefCell<T>`与内部可变性模式

**内部可变性（Interior Mutability）**是Rust中的一种设计模式，它允许你在拥有不可变引用的情况下修改数据。这是通过在运行时而不是编译时检查借用规则来实现的。

`RefCell<T>`是实现内部可变性的主要类型之一。它适用于你确定代码满足借用规则，但编译器无法理解和保证的情况。

- **借用规则在运行时检查**：如果违反规则，程序会`panic`。
- **不可变值`RefCell<T>`**可以提供可变引用`&mut T`。
- **只用于单线程场景**。多线程下请使用`Mutex<T>`。

```rust
use std::cell::RefCell;

pub trait Messenger {
    fn send(&self, msg: &str);
}

struct LimitTracker<'a, T: Messenger> {
    messenger: &'a T,
    value: usize,
    max: usize,
}

impl<'a, T> LimitTracker<'a, T>
where
    T: Messenger,
{
    // ...
    pub fn set_value(&mut self, value: usize) {
        self.value = value;
        // ...
    }
}

// 一个模拟对象
struct MockMessenger {
    // 使用 RefCell 来实现内部可变性
    sent_messages: RefCell<Vec<String>>,
}

impl MockMessenger {
    fn new() -> MockMessenger {
        MockMessenger {
            sent_messages: RefCell::new(vec![]),
        }
    }
}

impl Messenger for MockMessenger {
    fn send(&self, message: &str) {
        // borrow_mut() 获取可变引用，如果违反借用规则则panic
        self.sent_messages.borrow_mut().push(String::from(message));
    }
}

fn main() {
    let mock_messenger = MockMessenger::new();
    // ...
    // `send`方法接收的是 &self (不可变引用)
    // 但它内部成功地修改了 `sent_messages`
    mock_messenger.send("test message"); 
    
    assert_eq!(mock_messenger.sent_messages.borrow().len(), 1);
}
```
`borrow()`返回一个智能指针`Ref<T>`，`borrow_mut()`返回`RefMut<T>`。`RefCell<T>`会记录当前有多少个活跃的`Ref`和`RefMut`，并在运行时强制执行借用规则（一个可变引用或多个不可变引用）。

### `Rc<T>` 和 `RefCell<T>` 结合使用

一个常见的模式是使用 `Rc<RefCell<T>>`，它允许你拥有多个所有者，并且每个所有者都可以修改数据。

## 总结

- `Box<T>`：用于在堆上分配值，适用于递归类型和特质对象。
- `Deref` trait：允许智能指针像引用一样工作，并启用解引用强制转换。
- `Drop` trait：在值离开作用域时自定义清理逻辑。
- `Rc<T>`：用于单线程中的多重所有权，通过引用计数管理生命周期。
- `RefCell<T>`：提供内部可变性，在运行时检查借用规则，允许在持有不可变引用时修改数据。

智能指针是Rust语言强大表现力和安全性的重要组成部分，深刻理解它们是编写高效、安全、地道Rust代码的关键。 