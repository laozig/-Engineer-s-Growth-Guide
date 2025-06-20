# 15. 存储过程与函数

在PostgreSQL中，您可以创建自定义函数和存储过程，将复杂的业务逻辑、计算或数据操作封装在数据库服务器端。这有助于减少客户端和服务器之间的通信，提高代码的重用性和安全性。

## 函数 (Functions)

函数在PostgreSQL中是头等公民。它们接受参数，执行计算，并**返回一个值** (可以是标量值或一个表)。函数可以在`SELECT`语句中像内置函数一样被调用。

### 创建函数

默认的过程语言是`PL/pgSQL`，它是一种功能强大的块结构语言。

**示例1：一个简单的标量函数**
这个函数计算给定价格的税后总价。

```sql
CREATE OR REPLACE FUNCTION calculate_total_price(price NUMERIC, tax_rate NUMERIC)
RETURNS NUMERIC AS $$
BEGIN
    RETURN price * (1 + tax_rate);
END;
$$ LANGUAGE plpgsql;
```
- `CREATE OR REPLACE`: 如果函数已存在，则替换它。
- `RETURNS NUMERIC`: 指定函数返回的数据类型。
- `$$`: 这是"美元引用" (dollar quoting)，用于包围函数体，可以避免函数体内的单引号需要转义的问题。
- `LANGUAGE plpgsql`: 指定使用的过程语言。

**调用函数**:
```sql
SELECT calculate_total_price(100, 0.08);
-- > 108.00
```

**示例2：返回一个表的函数**
函数也可以返回一组行，表现得像一个表。

```sql
-- 创建一个返回某个部门所有员工的函数
CREATE OR REPLACE FUNCTION get_employees_by_department(dept_name VARCHAR)
RETURNS TABLE(id INT, name VARCHAR, salary INT) AS $$
BEGIN
    RETURN QUERY
    SELECT e.id, e.name, e.salary FROM employees e WHERE e.department = dept_name;
END;
$$ LANGUAGE plpgsql;
```
- `RETURNS TABLE(...)`: 定义了返回表的结构。
- `RETURN QUERY`: 执行一个查询并将其结果作为函数返回值。

**调用表返回函数**:
```sql
SELECT * FROM get_employees_by_department('Engineering');
```

## 存储过程 (Procedures)

存储过程与函数非常相似，但有一个关键区别：**存储过程不返回值**。它们主要用于执行数据修改操作，并且可以在其内部控制事务。

存储过程是自PostgreSQL 11版本起引入的。在之前的版本中，通常使用返回`void`的函数来模拟类似的行为。

### 创建过程

```sql
-- 创建一个给两位员工调薪的过程
CREATE OR REPLACE PROCEDURE adjust_salaries(
    emp1_id INT,
    emp1_new_salary INT,
    emp2_id INT,
    emp2_new_salary INT
)
LANGUAGE plpgsql
AS $$
BEGIN
    -- 更新第一位员工
    UPDATE employees SET salary = emp1_new_salary WHERE id = emp1_id;
    -- 更新第二位员工
    UPDATE employees SET salary = emp2_new_salary WHERE id = emp2_id;

    -- 可以在这里执行一些检查

    COMMIT; -- 过程可以控制自己的事务
END;
$$;
```

### 调用过程

使用`CALL`命令来执行一个存储过程。

```sql
CALL adjust_salaries(1, 62000, 2, 82000);
```

## 函数 vs. 过程

| 特性 | 函数 (Function) | 过程 (Procedure) |
| --- | --- | --- |
| **返回值** | **必须**返回一个值（可以是`void`）。 | **不能**有返回值。 |
| **调用方式** | 在SQL查询中调用（如 `SELECT my_func()`）。 | 使用 `CALL` 命令独立执行。 |
| **事务控制** | 不能在内部 `COMMIT` 或 `ROLLBACK`。它们在调用它们的查询的事务上下文中运行。 | 可以在内部 `COMMIT` 或 `ROLLBACK`，可以管理自己的事务。 |
| **主要用途** | 执行计算，返回数据，封装可重用的查询逻辑。 | 执行一系列数据修改操作，封装一个完整的业务流程。 |

## 安全性与 `SECURITY DEFINER`

默认情况下，函数和过程以`SECURITY INVOKER`的方式运行，这意味着它们以调用该函数的用户的权限执行。

有时，您希望函数以创建该函数的用户的权限运行，例如，允许某个受限用户通过一个受控的函数来更新一个他本没有权限写入的表。这时可以使用`SECURITY DEFINER`。

```sql
CREATE FUNCTION update_log(log_message TEXT) RETURNS void AS $$
BEGIN
    INSERT INTO audit_log (message) VALUES (log_message);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```
**警告**: `SECURITY DEFINER`非常强大，但也可能带来安全风险。必须谨慎使用，并确保函数内部的逻辑是安全的，能够防止SQL注入等攻击。

通过使用函数和存储过程，您可以将复杂的业务逻辑移到数据库层，从而构建更整洁、更模块化、更高效的应用程序。 