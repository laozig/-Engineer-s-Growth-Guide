# Go语言数据库操作

Go语言通过其标准库`database/sql`提供了一套简洁、通用的SQL（或类SQL）数据库操作接口。开发者可以配合特定的数据库驱动来连接和操作各种关系型数据库。

## 1. `database/sql`核心接口

`database/sql`包本身不包含任何数据库驱动，它只定义了一组接口。你需要导入一个第三方的驱动包来连接具体的数据库。

### 核心组件:
- **`sql.DB`**: 代表一个数据库连接池，管理着与数据库的连接。它是并发安全的。
- **`sql.Conn`**: 代表一个单独的数据库连接。
- **`sql.Tx`**: 代表一个数据库事务。
- **`sql.Stmt`**: 代表一个预处理语句（prepared statement）。
- **`sql.Rows`**: 代表一个查询结果集。
- **`sql.Result`**: 代表一个`Exec`操作（如`INSERT`, `UPDATE`, `DELETE`）的结果。

### 1.1 连接数据库
首先，需要导入`database/sql`包和一个数据库驱动。驱动包在导入时通常使用空白标识符`_`，因为我们只需要它的副作用——注册自己到`database/sql`中。

```go
package main

import (
    "database/sql"
    "log"

    _ "github.com/go-sql-driver/mysql" // 导入MySQL驱动
)

func main() {
    // dsn: Data Source Name
    dsn := "user:password@tcp(127.0.0.1:3306)/dbname"
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        log.Fatalf("failed to open database: %v", err)
    }
    defer db.Close() // 确保在程序结束时关闭连接池

    // 检查连接是否成功
    err = db.Ping()
    if err != nil {
        log.Fatalf("failed to connect to database: %v", err)
    }
    log.Println("Successfully connected to database!")
}
```
`sql.Open`并不会立即建立连接，它只是准备好连接池。`db.Ping()`可以用来验证数据库连接是否有效。

## 2. 查询数据

### 2.1 查询单行 (`QueryRow`)
`db.QueryRow`用于执行一个只返回最多一行的查询。

```go
type User struct {
    ID    int
    Name  string
    Email string
}

func findUserByID(db *sql.DB, id int) (*User, error) {
    var u User
    row := db.QueryRow("SELECT id, name, email FROM users WHERE id = ?", id)
    
    // Scan将查询结果的列映射到结构体字段
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, fmt.Errorf("user not found")
        }
        return nil, err
    }
    return &u, nil
}
```

### 2.2 查询多行 (`Query`)
`db.Query`用于执行返回多行的查询。

```go
func findAllUsers(db *sql.DB) ([]User, error) {
    rows, err := db.Query("SELECT id, name, email FROM users")
    if err != nil {
        return nil, err
    }
    defer rows.Close() // 非常重要：确保遍历结束后关闭rows

    var users []User
    for rows.Next() {
        var u User
        if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
            return nil, err
        }
        users = append(users, u)
    }

    // 检查遍历过程中是否发生错误
    if err := rows.Err(); err != nil {
        return nil, err
    }
    return users, nil
}
```

## 3. 修改数据 (`Exec`)

`INSERT`, `UPDATE`, `DELETE`等写操作使用`db.Exec`。

```go
func createUser(db *sql.DB, name, email string) (int64, error) {
    result, err := db.Exec("INSERT INTO users (name, email) VALUES (?, ?)", name, email)
    if err != nil {
        return 0, err
    }

    // 获取最后插入的ID
    lastInsertID, err := result.LastInsertId()
    if err != nil {
        return 0, err
    }

    // 获取受影响的行数
    // rowsAffected, err := result.RowsAffected()
    
    return lastInsertID, nil
}
```

## 4. 预处理语句 (Prepared Statements)

预处理语句可以提高性能并有效防止SQL注入攻击。
1.  **性能**: 数据库可以一次性解析SQL语句，后续执行时只需传递参数，减少了解析开销。
2.  **安全**: 参数是以独立的数据形式发送给数据库的，而不是作为SQL字符串的一部分，因此不会被解释为SQL命令。

```go
func preparedExample(db *sql.DB) {
    stmt, err := db.Prepare("SELECT id, name FROM users WHERE id = ?")
    if err != nil {
        log.Fatal(err)
    }
    defer stmt.Close()

    // 使用预处理语句查询
    row1 := stmt.QueryRow(1)
    // ... scan row1 ...

    row2 := stmt.QueryRow(2)
    // ... scan row2 ...
}
```

## 5. 事务 (Transactions)

事务用于将一组操作作为一个原子单元来执行，要么全部成功，要么全部失败。

```go
func transferMoney(db *sql.DB, fromID, toID int, amount float64) error {
    tx, err := db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback() // 关键：如果函数提前返回（如panic），事务会自动回滚

    // 1. 从付款人账户扣款
    _, err = tx.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, fromID)
    if err != nil {
        return err
    }

    // 2. 向收款人账户加款
    _, err = tx.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, toID)
    if err != nil {
        return err
    }

    // 3. 提交事务
    return tx.Commit()
}
```
`defer tx.Rollback()`是一个好习惯。如果后续的`tx.Commit()`成功执行，`Rollback`会返回一个错误（因为事务已结束），但这通常可以被忽略。

## 6. 流行的ORM与工具库

虽然`database/sql`很灵活，但在大型项目中，直接使用它可能会导致大量的重复代码（如`Scan`操作）。社区提供了一些优秀的库来简化数据库操作。

- **GORM**: 一个功能全面的ORM库，支持关联、钩子、预加载等高级功能。
- **sqlc**: 一个CLI工具，它可以根据你写的SQL查询语句，自动生成类型安全的Go代码。
- **SQLx**: `database/sql`的一个轻量级扩展，它保留了`database/sql`的API和语义，但增加了一些方便的功能，特别是将查询结果直接扫描到结构体中。

### SQLx示例
```go
import "github.com/jmoiron/sqlx"

// 注意：db是一个*sqlx.DB对象
func findUserWithSqlx(db *sqlx.DB, id int) (*User, error) {
    var u User
    err := db.Get(&u, "SELECT * FROM users WHERE id = ?", id)
    if err != nil {
        return nil, err
    }
    return &u, nil
}

func findAllUsersWithSqlx(db *sqlx.DB) ([]User, error) {
    var users []User
    err := db.Select(&users, "SELECT * FROM users")
    if err != nil {
        return nil, err
    }
    return users, nil
}
```
`sqlx`的`Get`和`Select`方法可以根据结构体的字段名（或`db`标签）自动匹配数据库列，大大简化了`Scan`操作。 