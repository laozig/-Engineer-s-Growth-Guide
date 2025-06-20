# 7. 数据操作语言 (DML)

数据操作语言 (Data Manipulation Language, DML) 用于管理数据库表中的数据。核心的DML命令包括 `INSERT`, `UPDATE`, `DELETE` 和 `SELECT`。我们在 [SQL基础](sql-basics.md) 章节已经介绍了它们的基本用法，本章将探讨一些更高级的DML特性。

## 高级插入 (INSERT)

### 从查询结果插入

您可以将一个 `SELECT` 查询的结果直接插入到另一个表中，前提是列的类型和顺序匹配。

```sql
-- 假设我们有一个 archived_employees 表，结构与 employees 相同
INSERT INTO archived_employees (id, name, department, salary, hire_date)
SELECT id, name, department, salary, hire_date
FROM employees
WHERE hire_date < '2020-01-01';
```

### `ON CONFLICT` 子句 (UPSERT)

PostgreSQL 提供了强大的 `ON CONFLICT` 子句，可以优雅地处理唯一键冲突。这通常被称为 "UPSERT" (Update or Insert)。

假设 `employees` 表的 `name` 列有一个唯一约束 (`UNIQUE`)。

```sql
-- 准备一个有唯一约束的表
ALTER TABLE employees ADD CONSTRAINT employees_name_key UNIQUE (name);

-- 尝试插入一个已存在的员工 'Alice'
INSERT INTO employees (name, department, salary, hire_date)
VALUES ('Alice', 'HR', 70000, '2022-01-01')
ON CONFLICT (name) -- 当 'name' 列发生冲突时
DO NOTHING; -- 什么也不做，静默忽略
```

更常见的场景是，如果记录已存在，则更新它。

```sql
INSERT INTO employees (name, department, salary, hire_date)
VALUES ('Alice', 'HR', 70000, '2022-01-01')
ON CONFLICT (name) -- 当 'name' 列发生冲突时
DO UPDATE SET
    salary = EXCLUDED.salary, -- 使用试图插入的新薪水
    hire_date = EXCLUDED.hire_date; -- EXCLUDED 伪表代表了试图插入的数据行
```

## 高级更新 (UPDATE)

### `UPDATE...FROM`

您可以使用另一个表的数据来更新一个表。

```sql
-- 假设有一个 salary_adjustments 表
CREATE TABLE salary_adjustments (
    employee_name VARCHAR(100) PRIMARY KEY,
    new_salary INT
);
INSERT INTO salary_adjustments VALUES ('Bob', 90000);

-- 使用 salary_adjustments 的数据来更新 employees 表
UPDATE employees
SET salary = sa.new_salary
FROM salary_adjustments sa
WHERE employees.name = sa.employee_name;
```

### `RETURNING` 子句

`UPDATE` (以及 `INSERT` 和 `DELETE`) 命令可以跟一个 `RETURNING` 子句，用于返回被修改后的行的值。

```sql
UPDATE employees
SET salary = salary * 1.10
WHERE department = 'Engineering'
RETURNING id, name, salary AS new_salary;
```
这会为工程部门的每位员工加薪10%，并立即返回他们的ID、姓名和新的薪水，非常适合需要知道操作结果的应用程序。

## 高级删除 (DELETE)

### `DELETE...USING`

类似于 `UPDATE...FROM`，您可以使用 `USING` 子句，根据另一个表的数据来决定删除哪些行。

```sql
-- 假设我们要删除所有在 'archived_employees' 表中存在的员工
DELETE FROM employees
USING archived_employees
WHERE employees.id = archived_employees.id;
```

### `RETURNING` 子句

`DELETE` 也可以使用 `RETURNING` 子句来查看哪些行被删除了。

```sql
DELETE FROM employees
WHERE hire_date < '2019-01-01'
RETURNING *; -- 返回所有被删除行的所有列
```

## 事务中的DML

所有DML操作在PostgreSQL中都是事务性的。这意味着您可以将多个DML语句组合在一个事务中，以确保它们要么全部成功，要么全部失败。

```sql
BEGIN; -- 开始一个事务

-- 从 Bob 的账户中扣除 1000
UPDATE accounts SET balance = balance - 1000 WHERE name = 'Bob';

-- 向 Alice 的账户中增加 1000
UPDATE accounts SET balance = balance + 1000 WHERE name = 'Alice';

COMMIT; -- 提交事务，使所有更改永久生效
```

如果在 `COMMIT` 之前发生任何错误，或者您执行了 `ROLLBACK`，那么事务中的所有操作都将被撤销。这是保证数据一致性的基石。

掌握这些高级DML技巧可以让您更高效地处理复杂的数据操作。接下来，我们将探讨数据库性能的核心：[索引与查询优化](indexing-query-optimization.md)。 