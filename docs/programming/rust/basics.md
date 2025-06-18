# Rust基础语法

本文档介绍Rust编程语言的基础语法和核心概念，为初学者提供快速入门指南。

## 目录

- [变量与常量](#变量与常量)
- [基本数据类型](#基本数据类型)
- [运算符](#运算符)
- [控制流](#控制流)
- [函数](#函数)
- [注释](#注释)
- [所有权系统介绍](#所有权系统介绍)

## 变量与常量

### 变量声明

在Rust中，变量默认是不可变的。使用`let`关键字声明变量：

```rust
// 不可变变量
let name = "张三";

// 可变变量需要使用mut关键字
let mut age = 30;
age = 31; // 正确：可以修改可变变量

// 重影（Shadowing）：使用相同名称声明新变量
let value = 5;
let value = value + 1; // value现在是6
let value = value * 2; // value现在是12
```

### 常量声明

常量使用`const`关键字声明，必须指定类型，且只能设置为常量表达式：

```rust
// 常量必须指定类型
const MAX_POINTS: u32 = 100_000;
const PI: f32 = 3.14159;
```

## 基本数据类型

### 整数类型

Rust有多种整数类型，区分有符号和无符号：

```rust
// 有符号整数（可以表示负数）
let a: i8 = -128;    // -128到127
let b: i16 = 32000;  // -32768到32767
let c: i32 = 2000000000; // 32位有符号整数（默认）
let d: i64 = 9000000000000000000; // 64位有符号整数
let e: i128 = 170141183460469231731687303715884105727; // 128位有符号整数

// 无符号整数（只能是正数）
let f: u8 = 255;     // 0到255
let g: u16 = 65000;  // 0到65535
let h: u32 = 4000000000; // 32位无符号整数
let i: u64 = 18000000000000000000; // 64位无符号整数

// 可自适应大小的整数
let j: isize = 9000; // 取决于系统架构（32位或64位）
let k: usize = 9000; // 取决于系统架构（32位或64位）
```

### 浮点类型

Rust支持两种浮点数类型：

```rust
let x: f32 = 3.14;       // 32位浮点数
let y: f64 = 3.141592653589793; // 64位浮点数（默认）
```

### 布尔类型

```rust
let is_active: bool = true;
let is_greater = 10 > 5; // is_greater是true
```

### 字符类型

Rust的字符类型使用单引号，支持Unicode：

```rust
let c: char = 'z';
let z: char = 'ℤ';
let emoji: char = '😻';
let chinese: char = '中';
```

### 字符串类型

Rust有两种主要的字符串类型：

```rust
// 字符串字面量 - 固定大小，不可变
let greeting = "你好，世界";

// String类型 - 可变，可增长
let mut message = String::from("你好");
message.push_str("，Rust！"); // message现在是"你好，Rust！"
```

### 复合类型

#### 元组（Tuple）

元组是固定长度的多类型元素集合：

```rust
// 声明元组
let person: (String, i32, bool) = (String::from("张三"), 30, true);

// 访问元组元素
let name = person.0; // "张三"
let age = person.1;  // 30
let is_student = person.2; // true

// 解构赋值
let (name, age, is_student) = person;
```

#### 数组（Array）

数组是固定长度的同类型元素集合：

```rust
// 声明数组
let numbers: [i32; 5] = [1, 2, 3, 4, 5];

// 创建包含相同值的数组
let zeros = [0; 10]; // 创建10个元素都是0的数组

// 访问数组元素
let first = numbers[0]; // 1
let second = numbers[1]; // 2
```

## 运算符

### 算术运算符

```rust
let a = 10;
let b = 3;

let sum = a + b;      // 加法: 13
let difference = a - b; // 减法: 7
let product = a * b;   // 乘法: 30
let quotient = a / b;  // 整数除法: 3
let remainder = a % b; // 取余: 1

// 自增和自减（Rust没有++和--运算符）
let mut c = 5;
c += 1; // 自增
c -= 1; // 自减
```

### 比较运算符

```rust
let a = 10;
let b = 5;

let equal = a == b;       // 等于: false
let not_equal = a != b;   // 不等于: true
let greater = a > b;      // 大于: true
let less = a < b;         // 小于: false
let greater_equal = a >= b; // 大于等于: true
let less_equal = a <= b;    // 小于等于: false
```

### 逻辑运算符

```rust
let condition1 = true;
let condition2 = false;

let and_result = condition1 && condition2; // 逻辑与: false
let or_result = condition1 || condition2;  // 逻辑或: true
let not_result = !condition1;             // 逻辑非: false
```

## 控制流

### if 条件表达式

```rust
let number = 6;

// 基本if语句
if number % 2 == 0 {
    println!("数字是偶数");
} else {
    println!("数字是奇数");
}

// if是表达式，可以赋值给变量
let result = if number > 0 {
    "正数"
} else if number < 0 {
    "负数"
} else {
    "零"
};
println!("数字是: {}", result);
```

### match 模式匹配

```rust
let code = 404;

match code {
    200 => println!("成功"),
    404 => println!("未找到"),
    401 | 403 => println!("权限错误"), // 多个模式
    400..=499 => println!("客户端错误"), // 范围
    _ => println!("其他状态码"), // 默认情况
}

// match也是表达式
let message = match code {
    200 => "OK",
    404 => "Not Found",
    _ => "Unknown",
};
```

### 循环

#### loop 循环

```rust
// 无限循环
let mut counter = 0;
let result = loop {
    counter += 1;
    
    if counter == 10 {
        break counter * 2; // 使用break返回值
    }
};
println!("结果是: {}", result); // 20
```

#### while 循环

```rust
let mut number = 3;
while number != 0 {
    println!("{}!", number);
    number -= 1;
}
println!("发射!");
```

#### for 循环

```rust
// 遍历范围
for i in 1..=5 {
    println!("{}次", i);
}

// 遍历数组/集合
let colors = ["红", "绿", "蓝"];
for color in colors.iter() {
    println!("颜色: {}", color);
}

// 使用enumerate()获取索引
for (index, value) in colors.iter().enumerate() {
    println!("索引 {} 的颜色是: {}", index, value);
}
```

## 函数

### 基本函数声明

```rust
// 无参数无返回值函数
fn say_hello() {
    println!("你好，世界！");
}

// 带参数的函数
fn greet(name: &str) {
    println!("你好，{}！", name);
}

// 带返回值的函数（使用->指定返回类型）
fn add(a: i32, b: i32) -> i32 {
    a + b // 注意：不加分号表示返回该表达式的值
}

// 带多个返回值（使用元组）
fn get_coordinates() -> (f64, f64) {
    (23.5, 45.2)
}
```

### 函数调用

```rust
// 调用函数
say_hello();
greet("张三");
let sum = add(5, 3); // 8

// 解构多返回值
let (latitude, longitude) = get_coordinates();
```

## 注释

Rust支持单行注释、多行注释和文档注释：

```rust
// 这是单行注释

/*
这是
多行注释
*/

/// 文档注释，用于生成文档
/// 这些注释将被包含在生成的API文档中
fn documented_function() {
    // 函数实现
}

//! 模块级文档注释
//! 用于描述整个模块或crate
```

## 所有权系统介绍

Rust的核心特性是其独特的所有权系统，这里做简单介绍：

### 所有权规则

1. Rust中每个值都有一个变量作为其所有者
2. 一次只能有一个所有者
3. 当所有者超出作用域，值将被丢弃

```rust
{
    // s不可用，尚未声明
    let s = String::from("hello"); // s有效
    
    // 可以对s进行操作
    
} // s的作用域结束，String会被自动释放
```

### 变量移动（Move）

```rust
let s1 = String::from("hello");
let s2 = s1; // s1的所有权移动到s2，s1不再可用

// println!("{}", s1); // 错误：s1的值已被移动

// 对于基本类型（栈上的简单数据），会自动拷贝，不会移动
let x = 5;
let y = x; // 复制x的值给y，x仍然可用
println!("x = {}, y = {}", x, y); // 正确
```

### 借用（Borrowing）

通过引用可以使用值而不获取所有权：

```rust
// 不可变借用
fn calculate_length(s: &String) -> usize {
    s.len()
} 

let s1 = String::from("hello");
let len = calculate_length(&s1); // 传递引用
// s1仍然可用

// 可变借用
fn change(s: &mut String) {
    s.push_str(", world");
}

let mut s1 = String::from("hello");
change(&mut s1); // 传递可变引用
println!("{}", s1); // "hello, world"
```

Rust的借用规则：
1. 任意时刻，只能有一个可变引用 或 多个不可变引用
2. 引用必须总是有效的

---

这些是Rust语言的基础语法和核心概念，了解这些内容后，建议进一步学习Rust的所有权、生命周期、错误处理、结构体和枚举等更多高级特性。 