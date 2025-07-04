# Rust结构体与枚举

结构体和枚举是Rust中构建自定义类型的基础，它们与模式匹配结合使用时尤其强大。本文档详细介绍这些概念及其在Rust程序中的应用。

## 目录

- [结构体](#结构体)
- [结构体方法](#结构体方法)
- [枚举](#枚举)
- [Option和Result](#option和result)
- [模式匹配](#模式匹配)
- [代数数据类型](#代数数据类型)
- [结构体和枚举的内存布局](#结构体和枚举的内存布局)
- [实践应用](#实践应用)

## 结构体

结构体（Struct）是一种自定义数据类型，用于组合多个相关的值。

### 结构体定义

```rust
// 一个普通的结构体，所有字段都有命名
struct Person {
    name: String,
    age: u32,
    email: String,
}

// 元组结构体，字段没有命名，只有类型
struct Point(i32, i32, i32);

// 类单元结构体，没有任何字段
struct AlwaysEqual;
```

### 结构体实例化

```rust
// 实例化普通结构体
let person = Person {
    name: String::from("张三"),
    age: 25,
    email: String::from("zhangsan@example.com"),
};

// 实例化元组结构体
let origin = Point(0, 0, 0);

// 实例化单元结构体
let subject = AlwaysEqual;
```

### 访问结构体字段

```rust
// 使用点表示法访问字段
println!("姓名: {}", person.name);
println!("年龄: {}", person.age);

// 访问元组结构体字段
println!("坐标: ({}, {}, {})", origin.0, origin.1, origin.2);
```

### 结构体更新语法

```rust
// 使用已有实例的部分值创建新实例
let person2 = Person {
    email: String::from("lisi@example.com"),
    ..person // 其余字段从person复制
};

// 注意：这里发生了移动，现在person.name不再有效，因为String不实现Copy特质
// println!("{}", person.name); // 错误！
println!("{}", person.age);  // 正确，因为u32实现了Copy特质
```

### 结构体字段简写

当变量名与字段名相同时，可以使用简写语法：

```rust
fn build_person(name: String, age: u32) -> Person {
    Person {
        name, // 简写，等同于name: name
        age,  // 简写，等同于age: age
        email: String::from("default@example.com"),
    }
}
```

## 结构体方法

方法与函数类似，但它们与特定类型关联，并且第一个参数通常是`self`，表示调用该方法的实例。

### 定义方法

使用`impl`块为结构体定义方法：

```rust
impl Person {
    // 实例方法，接收不可变引用
    fn describe(&self) -> String {
        format!("{}，{}岁，邮箱: {}", self.name, self.age, self.email)
    }
    
    // 实例方法，接收可变引用
    fn have_birthday(&mut self) {
        self.age += 1;
    }
    
    // 关联函数（静态方法），不接收self
    fn new(name: String, age: u32, email: String) -> Person {
        Person { name, age, email }
    }
}

fn main() {
    // 使用关联函数创建实例
    let mut person = Person::new(
        String::from("李四"),
        30,
        String::from("lisi@example.com"),
    );
    
    // 调用方法
    println!("{}", person.describe());
    
    // 调用可变方法
    person.have_birthday();
    println!("生日后: {}", person.describe());
}
```

### 多个impl块

可以为一个类型定义多个`impl`块，这对于实现条件特质或组织代码很有用：

```rust
impl Person {
    // 基本方法
}

impl Person {
    // 更多方法
    fn full_name(&self, title: &str) -> String {
        format!("{} {}", title, self.name)
    }
}
```

### 为元组结构体定义方法

```rust
struct Point(f64, f64);

impl Point {
    fn distance_from_origin(&self) -> f64 {
        (self.0.powi(2) + self.1.powi(2)).sqrt()
    }
}

fn main() {
    let point = Point(3.0, 4.0);
    println!("到原点距离: {}", point.distance_from_origin());  // 输出: 5
}
```

## 枚举

枚举（Enum）是一种定义一组相关值的数据类型，每个值称为一个变体（variant）。

### 基本枚举定义

```rust
// 简单枚举
enum Direction {
    North,
    South,
    East,
    West,
}

// 带数据的枚举
enum Message {
    Quit,                       // 没有关联数据
    Move { x: i32, y: i32 },    // 匿名结构体
    Write(String),              // 包含一个字符串
    ChangeColor(i32, i32, i32), // 包含三个i32值
}
```

### 枚举实例化

```rust
let direction = Direction::North;

let messages = vec![
    Message::Quit,
    Message::Move { x: 10, y: 20 },
    Message::Write(String::from("Hello")),
    Message::ChangeColor(255, 0, 0),
];
```

### 为枚举定义方法

```rust
impl Message {
    fn call(&self) {
        // 处理不同类型的消息
        match self {
            Message::Quit => println!("退出"),
            Message::Move { x, y } => println!("移动到坐标: ({}, {})", x, y),
            Message::Write(text) => println!("文本消息: {}", text),
            Message::ChangeColor(r, g, b) => println!("颜色变为: RGB({},{},{})", r, g, b),
        }
    }
}

fn main() {
    let msg = Message::Write(String::from("Hello, Rust!"));
    msg.call();  // 输出: 文本消息: Hello, Rust!
}
```

### 带有值的枚举

每个枚举变体可以存储任意类型的数据：

```rust
enum WebEvent {
    PageLoad,                  // 没有数据
    KeyPress(char),            // 包含单个字符
    Click { x: i64, y: i64 },  // 匿名结构体
}

fn inspect(event: WebEvent) {
    match event {
        WebEvent::PageLoad => println!("页面已加载"),
        WebEvent::KeyPress(c) => println!("按下了按键: {}", c),
        WebEvent::Click { x, y } => println!("点击位置: ({}, {})", x, y),
    }
}

fn main() {
    let events = vec![
        WebEvent::PageLoad,
        WebEvent::KeyPress('c'),
        WebEvent::Click { x: 10, y: 20 },
    ];
    
    for event in events {
        inspect(event);
    }
}
```

## Option和Result

Rust标准库中包含两个非常重要的枚举类型：`Option`和`Result`。

### Option枚举

`Option<T>`表示一个可能存在也可能不存在的值，用于替代空值（null）：

```rust
// Option定义（标准库中）
enum Option<T> {
    Some(T),  // 包含值
    None,     // 不包含值
}

// 使用Option
fn find_user(id: u32) -> Option<String> {
    if id == 1 {
        Some(String::from("Alice"))
    } else {
        None
    }
}

fn main() {
    let user = find_user(1);
    
    // 使用match处理Option
    match user {
        Some(name) => println!("找到用户: {}", name),
        None => println!("未找到用户"),
    }
    
    // 使用if let处理Option
    if let Some(name) = find_user(2) {
        println!("找到用户: {}", name);
    } else {
        println!("未找到用户");
    }
    
    // 使用unwrap（不推荐，可能导致恐慌）
    // let name = find_user(1).unwrap();  // 如果是None，会导致程序崩溃
    
    // 使用unwrap_or提供默认值
    let name = find_user(2).unwrap_or(String::from("未知用户"));
    println!("用户: {}", name);
    
    // 使用map转换Option内的值
    let greeting = find_user(1).map(|name| format!("你好，{}!", name));
    println!("{:?}", greeting);
}
```

### Result枚举

`Result<T, E>`用于表示可能成功（返回T类型的值）或失败（返回E类型的错误）的操作：

```rust
// Result定义（标准库中）
enum Result<T, E> {
    Ok(T),    // 成功，包含值
    Err(E),   // 错误，包含错误信息
}

// 使用Result
fn parse_number(s: &str) -> Result<i32, std::num::ParseIntError> {
    s.parse()
}

fn main() {
    let numbers = vec!["42", "93", "不是数字", "8"];
    
    for &n in numbers.iter() {
        // 使用match处理Result
        match parse_number(n) {
            Ok(num) => println!("解析成功: {}", num),
            Err(e) => println!("解析失败: {}", e),
        }
        
        // 使用if let处理Result
        if let Ok(num) = parse_number(n) {
            println!("数字是: {}", num);
        }
        
        // 使用?操作符（只能在返回Result的函数中使用）
        // let num = parse_number(n)?; // 如果是Err，会提前返回错误
        
        // 使用unwrap_or_else提供默认值处理错误
        let num = parse_number(n).unwrap_or_else(|_| {
            println!("'{}' 不是有效数字，使用默认值", n);
            0
        });
        println!("处理后的数字: {}", num);
    }
}
```

### 组合Option和Result方法

Rust提供了许多有用的方法来处理`Option`和`Result`：

```rust
// Option方法
let opt1 = Some(5);
let opt2 = Some(10);
let none: Option<i32> = None;

// and_then: 当Option是Some时执行闭包
let result1 = opt1.and_then(|x| Some(x * 2));  // Some(10)
let result2 = none.and_then(|x| Some(x * 2));  // None

// or: 当Option是None时返回另一个Option
let result3 = none.or(opt2);  // Some(10)

// Result方法
let res1: Result<i32, &str> = Ok(5);
let res2: Result<i32, &str> = Err("错误");

// map: 转换Ok值
let mapped = res1.map(|x| x + 1);  // Ok(6)

// map_err: 转换Err值
let mapped_err = res2.map_err(|e| format!("发生错误: {}", e));  // Err("发生错误: 错误")

// 链式调用
let chained = parse_number("42")
    .map(|n| n * 2)
    .and_then(|n| Ok(n.to_string()));
```

## 模式匹配

模式匹配是Rust中强大的特性，特别适合结构体和枚举。

### match表达式

`match`允许将一个值与一系列模式进行比较，然后根据匹配的模式执行相应的代码：

```rust
enum Coin {
    Penny,
    Nickel,
    Dime,
    Quarter(UsState),  // 带有关联值
}

#[derive(Debug)]
enum UsState {
    Alabama,
    Alaska,
    // ...其他州
}

fn value_in_cents(coin: Coin) -> u8 {
    match coin {
        Coin::Penny => {
            println!("Lucky penny!");
            1
        }
        Coin::Nickel => 5,
        Coin::Dime => 10,
        Coin::Quarter(state) => {
            println!("来自{:?}的25分硬币", state);
            25
        }
    }
}
```

### 通配符和 `_` 占位符

```rust
match dice_roll {
    1 => move_player(),
    2 => move_back(),
    3 => something_else(),
    // _ 匹配任何未明确处理的值
    _ => reroll(),
}
```

### if let表达式

`if let`提供了一种简洁的方式来处理只关心一种模式的情况：

```rust
let config_max = Some(3u8);

// 使用match
match config_max {
    Some(max) => println!("最大值是{}", max),
    None => (), // 不做任何操作
}

// 使用if let（更简洁）
if let Some(max) = config_max {
    println!("最大值是{}", max);
}
```

### while let循环

类似于`if let`，`while let`允许在条件满足时进行循环：

```rust
let mut stack = Vec::new();
stack.push(1);
stack.push(2);
stack.push(3);

while let Some(top) = stack.pop() {
    println!("{}", top);
}
```

### let语句中的模式匹配

```rust
// 元组解构
let (x, y, z) = (1, 2, 3);
println!("x: {}, y: {}, z: {}", x, y, z);

// 结构体解构
let p = Point { x: 0, y: 7 };
let Point { x, y } = p;
```

### 函数参数中的模式匹配

```rust
fn print_coordinates(&(x, y): &(i32, i32)) {
    println!("当前坐标: ({}, {})", x, y);
}

fn main() {
    let point = (3, 5);
    print_coordinates(&point);
}
```

## 代数数据类型

结构体和枚举是实现代数数据类型（Algebraic Data Types, ADTs）的基础。

### 积类型（Product Types）

结构体是积类型的一个例子，表示多个值的组合：

```rust
struct Rectangle {
    width: u32,
    height: u32,
}
```

一个`Rectangle`同时包含`width`和`height`，可能的值是所有可能的`width`和`height`组合。

### 和类型（Sum Types）

枚举是和类型的一个例子，表示多个可能的值中的一个：

```rust
enum Shape {
    Circle(f64),               // 半径
    Rectangle(f64, f64),       // 宽和高
    Triangle(f64, f64, f64),   // 三边长度
}
```

一个`Shape`可以是`Circle`、`Rectangle`或`Triangle`中的一个，但不能同时是多个。

### 递归类型

枚举和结构体可以递归定义，非常适合表示树状结构：

```rust
enum JsonValue {
    Null,
    Boolean(bool),
    Number(f64),
    String(String),
    Array(Vec<JsonValue>),           // 递归：数组中包含JsonValue
    Object(HashMap<String, JsonValue>), // 递归：对象值是JsonValue
}
```

## 结构体和枚举的内存布局

了解结构体和枚举的内存布局对于优化程序很重要。

### 结构体内存布局

```rust
struct Point {
    x: i32, // 4字节
    y: i32, // 4字节
}
// Point大小为8字节

struct Foo {
    a: u8,  // 1字节
    b: u32, // 4字节
    c: u8,  // 1字节
}
// 实际大小可能不是1+4+1=6字节，而是12字节，因为内存对齐
```

### 结构体字段重排

编译器可能会重排结构体的字段以优化内存布局。如果需要特定布局，可以使用`#[repr(C)]`：

```rust
#[repr(C)]
struct AlignedFoo {
    a: u8,  // 1字节
    b: u32, // 4字节
    c: u8,  // 1字节
}
// 用#[repr(C)]保证布局与C兼容，不会进行字段重排
```

### 枚举的内存布局

枚举通常存储一个标签（指示当前变体）和足够大的内存来容纳最大的变体：

```rust
enum Message {
    Quit,                       // 0字节数据 + 标签
    Move { x: i32, y: i32 },    // 8字节数据 + 标签
    Write(String),              // 24字节（在64位系统上）+ 标签
    ChangeColor(u8, u8, u8),    // 3字节数据 + 标签
}
// 大小约为标签大小加上最大变体的大小（通常会有内存对齐）
```

### 优化枚举

Rust中的空枚举（如`Option<&T>`）可以通过空指针优化（null pointer optimization）来优化内存使用：

```rust
// 在许多平台上，这实际只需要一个指针的空间，而不是指针+标签
let x: Option<&u32> = None;
```

## 实践应用

结构体和枚举在实际编程中有广泛应用。

### 领域建模

使用结构体和枚举表示业务概念：

```rust
struct User {
    id: u64,
    username: String,
    email: String,
    active: bool,
}

enum Subscription {
    Free,
    Monthly(f64),
    Yearly(f64, f64), // 价格和折扣
}

struct Account {
    user: User,
    subscription: Subscription,
}
```

### 状态机

使用枚举表示不同状态：

```rust
enum State {
    Start,
    Processing {
        progress: f64,
        step: u32,
    },
    Finished(Result<String, Error>),
}

struct Job {
    id: u32,
    state: State,
}

impl Job {
    fn progress(&mut self, amount: f64) {
        match &mut self.state {
            State::Processing { progress, step } => {
                *progress += amount;
                if *progress >= 1.0 {
                    *step += 1;
                    *progress = 0.0;
                }
            }
            _ => {} // 在其他状态下不执行任何操作
        }
    }
}
```

### 命令模式

使用枚举表示不同命令：

```rust
enum Command {
    Create { name: String, size: usize },
    Delete { id: u64 },
    Move { id: u64, x: i32, y: i32 },
    Update { id: u64, name: Option<String>, size: Option<usize> },
}

fn process_command(cmd: Command) -> Result<(), Error> {
    match cmd {
        Command::Create { name, size } => {
            // 处理创建命令
            println!("创建: name={}, size={}", name, size);
            Ok(())
        }
        Command::Delete { id } => {
            // 处理删除命令
            println!("删除: id={}", id);
            Ok(())
        }
        Command::Move { id, x, y } => {
            // 处理移动命令
            println!("移动: id={}, x={}, y={}", id, x, y);
            Ok(())
        }
        Command::Update { id, name, size } => {
            // 处理更新命令
            println!("更新: id={}", id);
            if let Some(name) = name {
                println!("  新名称: {}", name);
            }
            if let Some(size) = size {
                println!("  新大小: {}", size);
            }
            Ok(())
        }
    }
}
```

### 解析器组合器

使用枚举表示语法树：

```rust
enum Expr {
    Number(f64),
    Add(Box<Expr>, Box<Expr>),
    Subtract(Box<Expr>, Box<Expr>),
    Multiply(Box<Expr>, Box<Expr>),
    Divide(Box<Expr>, Box<Expr>),
}

fn evaluate(expr: &Expr) -> Result<f64, String> {
    match expr {
        Expr::Number(n) => Ok(*n),
        Expr::Add(left, right) => {
            let left_val = evaluate(left)?;
            let right_val = evaluate(right)?;
            Ok(left_val + right_val)
        }
        Expr::Subtract(left, right) => {
            let left_val = evaluate(left)?;
            let right_val = evaluate(right)?;
            Ok(left_val - right_val)
        }
        Expr::Multiply(left, right) => {
            let left_val = evaluate(left)?;
            let right_val = evaluate(right)?;
            Ok(left_val * right_val)
        }
        Expr::Divide(left, right) => {
            let left_val = evaluate(left)?;
            let right_val = evaluate(right)?;
            if right_val == 0.0 {
                Err("除以零错误".to_string())
            } else {
                Ok(left_val / right_val)
            }
        }
    }
}

fn main() {
    // 构建表达式 (2 + 3) * (4 - 1)
    let expr = Expr::Multiply(
        Box::new(Expr::Add(
            Box::new(Expr::Number(2.0)),
            Box::new(Expr::Number(3.0)),
        )),
        Box::new(Expr::Subtract(
            Box::new(Expr::Number(4.0)),
            Box::new(Expr::Number(1.0)),
        )),
    );
    
    match evaluate(&expr) {
        Ok(result) => println!("计算结果: {}", result),
        Err(err) => println!("计算错误: {}", err),
    }
}
```

## 总结

结构体和枚举是Rust类型系统的基石，提供了强大的抽象能力：

- **结构体**用于将相关的值组合成一个有意义的整体
- **枚举**用于表示一组相关的可能值中的一个
- **模式匹配**提供了一种优雅的方式来处理复杂的数据结构
- **Option和Result**是Rust中最常用的枚举，分别解决了空值和错误处理问题
- **代数数据类型**使得代码更加类型安全和表达力丰富

通过组合结构体、枚举和模式匹配，Rust程序员可以创建出简洁、安全且易于理解的程序。这些概念不仅提高了代码的可读性，还让编译器能够在编译时捕获许多潜在的错误，减少了运行时bug的可能性。
