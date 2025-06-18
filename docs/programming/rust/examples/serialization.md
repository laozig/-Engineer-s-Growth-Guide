# 示例项目：数据序列化与反序列化

在现代软件开发中，数据序列化与反序列化是不可或缺的一环。它允许我们将内存中的数据结构（如结构体、枚举等）转换为可以存储或传输的格式（如JSON、YAML、Bincode等），并能在需要时将其恢复为原始数据结构。Rust生态系统中最流行、功能最强大的序列化库是`serde`。

本示例将展示如何使用`serde`库对Rust数据结构进行JSON格式的序列化和反序列化。

## 项目目标

1.  定义一个Rust数据结构。
2.  使用`serde`将其序列化为JSON字符串。
3.  将JSON字符串反序列化回Rust数据结构。
4.  处理可能出现的错误。

## 技术栈

-   **Rust**: 核心编程语言
-   **`serde`**: 序列化与反序列化框架
-   **`serde_json`**: 为`serde`提供JSON格式支持

## 项目初始化

首先，我们需要在`Cargo.toml`中添加`serde`和`serde_json`依赖。`serde`需要启用`derive`特性来自动生成序列化和反序列化的代码。

```toml
[package]
name = "serialization_example"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

## 编写代码

### 1. 定义数据结构

我们将创建一个`User`结构体和一个`Role`枚举，并使用`#[derive(Serialize, Deserialize)]`宏来让`serde`为它们自动实现序列化和反序列化的功能。

`src/main.rs`:
```rust
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
enum Role {
    Admin,
    User,
    Guest,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: u32,
    username: String,
    email: String,
    is_active: bool,
    roles: Vec<Role>,
}

fn main() {
    // 后续代码将在这里添加
}
```

-   `#[derive(Serialize, Deserialize)]`: 这个属性宏告诉`serde`为`Role`和`User`自动生成`Serialize`和`Deserialize` trait的实现。
-   `use serde::{Serialize, Deserialize};`: 导入所需的trait。

### 2. 序列化：从Rust结构体到JSON

现在，我们创建一个`User`实例，并使用`serde_json::to_string_pretty`函数将其转换为格式化的JSON字符串。

```rust
// ... (之前的代码)

fn serialize_example() -> Result<(), serde_json::Error> {
    let user = User {
        id: 101,
        username: "coder".to_string(),
        email: "coder@example.com".to_string(),
        is_active: true,
        roles: vec![Role::Admin, Role::User],
    };

    // 序列化为格式化的JSON字符串
    let json_string = serde_json::to_string_pretty(&user)?;

    println!("--- 序列化示例 ---");
    println!("原始User结构体: \n{:#?}", user);
    println!("\n序列化后的JSON: \n{}", json_string);

    Ok(())
}

fn main() {
    if let Err(e) = serialize_example() {
        eprintln!("序列化失败: {}", e);
    }
}
```

-   `serde_json::to_string_pretty(&user)`: 将`user`实例序列化为一个易于阅读的JSON字符串。如果只需要紧凑的格式，可以使用`serde_json::to_string(&user)`。
-   `?` 操作符用于错误传播。如果序列化失败，函数将返回一个`Err`。

运行代码，你将看到如下输出：
```text
--- 序列化示例 ---
原始User结构体: 
User {
    id: 101,
    username: "coder",
    email: "coder@example.com",
    is_active: true,
    roles: [
        Admin,
        User,
    ],
}

序列化后的JSON: 
{
  "id": 101,
  "username": "coder",
  "email": "coder@example.com",
  "is_active": true,
  "roles": [
    "Admin",
    "User"
  ]
}
```

### 3. 反序列化：从JSON到Rust结构体

接下来，我们将一个JSON字符串反序列化回`User`结构体。

```rust
// ... (之前的代码)

fn deserialize_example() -> Result<(), serde_json::Error> {
    let json_data = r#"
    {
        "id": 202,
        "username": "tester",
        "email": "tester@example.com",
        "is_active": false,
        "roles": ["Guest"]
    }
    "#;

    // 从JSON字符串反序列化为User结构体
    let user: User = serde_json::from_str(json_data)?;

    println!("\n--- 反序列化示例 ---");
    println!("原始JSON字符串: \n{}", json_data.trim());
    println!("\n反序列化后的User结构体: \n{:#?}", user);

    Ok(())
}

fn main() {
    if let Err(e) = serialize_example() {
        eprintln!("序列化失败: {}", e);
    }
    println!(); // 添加空行以分隔输出
    if let Err(e) = deserialize_example() {
        eprintln!("反序列化失败: {}", e);
    }
}
```

-   `serde_json::from_str(json_data)`: 这个函数接收一个字符串切片，并尝试将其解析为一个指定类型（这里是`User`）的实例。Rust的类型推断会知道我们期望得到一个`User`。
-   `r#""#`是Rust的原始字符串字面量，允许我们方便地编写多行字符串而无需转义引号。

运行更新后的代码，你将看到反序列化的输出：
```text
--- 反序列化示例 ---
原始JSON字符串: 
{
    "id": 202,
    "username": "tester",
    "email": "tester@example.com",
    "is_active": false,
    "roles": ["Guest"]
}

反序列化后的User结构体: 
User {
    id: 202,
    username: "tester",
    email: "tester@example.com",
    is_active: false,
    roles: [
        Guest,
    ],
}
```

## 完整代码示例

`src/main.rs`:
```rust
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
enum Role {
    Admin,
    User,
    Guest,
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: u32,
    username: String,
    email: String,
    is_active: bool,
    roles: Vec<Role>,
}

fn serialize_example() -> Result<(), serde_json::Error> {
    let user = User {
        id: 101,
        username: "coder".to_string(),
        email: "coder@example.com".to_string(),
        is_active: true,
        roles: vec![Role::Admin, Role::User],
    };

    // 序列化为格式化的JSON字符串
    let json_string = serde_json::to_string_pretty(&user)?;

    println!("--- 序列化示例 ---");
    println!("原始User结构体: \n{:#?}", user);
    println!("\n序列化后的JSON: \n{}", json_string);

    Ok(())
}

fn deserialize_example() -> Result<(), serde_json::Error> {
    let json_data = r#"
    {
        "id": 202,
        "username": "tester",
        "email": "tester@example.com",
        "is_active": false,
        "roles": ["Guest"]
    }
    "#;

    // 从JSON字符串反序列化为User结构体
    let user: User = serde_json::from_str(json_data)?;

    println!("\n--- 反序列化示例 ---");
    println!("原始JSON字符串: \n{}", json_data.trim());
    println!("\n反序列化后的User结构体: \n{:#?}", user);

    Ok(())
}

fn main() {
    if let Err(e) = serialize_example() {
        eprintln!("序列化失败: {}", e);
    }
    println!(); // 添加空行以分隔输出
    if let Err(e) = deserialize_example() {
        eprintln!("反序列化失败: {}", e);
    }
}
```

## 总结

`serde`提供了一个极其强大且灵活的框架来处理Rust中的数据序列化与反序列化。通过简单的派生宏，我们可以轻松地为自定义类型添加对多种数据格式的支持。

这个例子展示了最常见的JSON用例，但`serde`生态系统还支持许多其他格式，例如：
-   **YAML**: `serde_yaml`
-   **TOML**: `toml`
-   **Bincode**: `bincode` (一种高效的二进制格式)
-   **CSV**: `csv`

`serde`的灵活性和高性能使其成为任何需要数据持久化或交换的Rust项目的首选。 