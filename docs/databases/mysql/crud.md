# 6. 增删改查 (CRUD)

CRUD 是四个基本数据库操作的缩写：创建 (Create)、读取 (Read)、更新 (Update) 和删除 (Delete)。这四个操作是与任何数据库交互的基础。在 SQL 中，它们分别对应 `INSERT`、`SELECT`、`UPDATE` 和 `DELETE` 语句。

在本章中，我们将使用一个名为 `employees` 的示例表。

```sql
-- 创建一个用于演示的 'employees' 表
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) UNIQUE,
    hire_date DATE NOT NULL,
    salary DECIMAL(10, 2)
);
```

## 1. 创建 (Create) - `INSERT`

`INSERT` 语句用于向表中添加新的行（记录）。

### 插入单行

最常见的形式是指定要插入的列和相应的值。

```sql
INSERT INTO employees (first_name, last_name, email, hire_date, salary)
VALUES ('Alice', 'Smith', 'alice.smith@example.com', '2023-01-15', 60000.00);
```

- `INSERT INTO employees (...)`: 指定要插入数据的表和列。
- `VALUES (...)`: 提供与列列表顺序对应的值。

如果提供的值与表中列的顺序完全一致，可以省略列列表，但不推荐这样做，因为这会使代码可读性变差且容易出错。

```sql
-- 不推荐的方式
INSERT INTO employees
VALUES (NULL, 'Bob', 'Johnson', 'bob.j@example.com', '2023-02-20', 65000.00);
-- 注意：id 是 AUTO_INCREMENT，所以我们插入 NULL 或根本不提它，让系统自动生成。
```

### 插入多行

可以在一个 `INSERT` 语句中插入多行，只需在 `VALUES` 关键字后提供多个由逗号分隔的值列表。

```sql
INSERT INTO employees (first_name, last_name, email, hire_date, salary)
VALUES
    ('Charlie', 'Brown', 'charlie.b@example.com', '2023-03-10', 70000.00),
    ('Diana', 'Green', 'diana.g@example.com', '2023-03-12', 72000.00),
    ('Ethan', 'White', 'ethan.w@example.com', '2023-04-01', 58000.00);
```
这种方式比多个单独的 `INSERT` 语句效率更高。

## 2. 读取 (Read) - `SELECT`

`SELECT` 语句用于从一个或多个表中检索数据。这是最常用、最复杂的 SQL 命令。本章只介绍基础用法，后续章节会深入讲解。

### 检索所有列

使用星号 `*` 可以检索表中的所有列。

```sql
-- 从 employees 表中读取所有记录的所有字段
SELECT * FROM employees;
```

### 检索指定列

为了提高效率和清晰度，最佳实践是只选择你需要的列。

```sql
-- 只读取员工的名字、姓氏和薪水
SELECT first_name, last_name, salary FROM employees;
```

### 使用 `WHERE` 子句进行条件筛选

`WHERE` 子句用于根据特定条件过滤记录。

```sql
-- 查找薪水高于 65000 的所有员工
SELECT * FROM employees
WHERE salary > 65000;

-- 查找姓氏为 'Smith' 的员工
SELECT * FROM employees
WHERE last_name = 'Smith';

-- 复合条件：查找 2023 年 3 月之后雇佣且薪水低于 60000 的员工
SELECT * FROM employees
WHERE hire_date > '2023-03-31' AND salary < 60000;
```

## 3. 更新 (Update) - `UPDATE`

`UPDATE` 语句用于修改表中的现有记录。

**至关重要**: `UPDATE` 语句**必须**带上 `WHERE` 子句！如果省略 `WHERE`，**表中的所有行都将被更新**，这通常是灾难性的。

```sql
-- 给 ID 为 3 的员工 (Charlie Brown) 涨薪
UPDATE employees
SET salary = 75000.00
WHERE id = 3;

-- 可以同时更新多个列
UPDATE employees
SET email = 'alice.smith.new@example.com', salary = 62000.00
WHERE first_name = 'Alice' AND last_name = 'Smith';
```
> 🔥 **安全提示**: 在执行 `UPDATE` 或 `DELETE` 之前，有一个很好的习惯是先用相同的 `WHERE` 子句写一个 `SELECT` 语句，以确保你选中的是要操作的正确记录。
> 例如，在执行上面的 `UPDATE` 前，先运行 `SELECT * FROM employees WHERE id = 3;` 来确认。

## 4. 删除 (Delete) - `DELETE`

`DELETE` 语句用于从表中删除一行或多行记录。

与 `UPDATE` 一样，`DELETE` 语句也**必须**带上 `WHERE` 子句，否则它将删除表中的**所有数据**。

```sql
-- 删除 ID 为 5 的员工 (Ethan White)
DELETE FROM employees
WHERE id = 5;

-- 删除所有薪水低于 60000 的员工
DELETE FROM employees
WHERE salary < 60000;
```

### 删除所有行

如果你确实想删除一个表中的所有行，但保留表结构，有两种方法：

1.  **`DELETE` (不带 `WHERE`)**
    ```sql
    DELETE FROM employees;
    ```
    - 这是一个 DML 操作，会逐行删除。
    - 如果表很大，速度会很慢。
    - 操作会被写入二进制日志，并且可以被回滚。

2.  **`TRUNCATE TABLE`**
    ```sql
    TRUNCATE TABLE employees;
    ```
    - 这是一个 DDL 操作，它通过删除并重新创建表的方式来实现，速度非常快。
    - 不能回滚。
    - 会重置 `AUTO_INCREMENT` 计数器。
    - 通常是清空表的首选方法。

掌握 CRUD 操作是进行任何数据库应用开发的基础。熟练运用这些命令，并时刻注意 `WHERE` 子句在 `UPDATE` 和 `DELETE` 中的重要性。 