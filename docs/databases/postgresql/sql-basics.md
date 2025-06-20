# 4. SQL基础

SQL (Structured Query Language) 是与关系数据库通信的标准语言。本章将介绍使用PostgreSQL进行数据查询和操作所需的基础SQL命令。

我们将使用一个简单的`employees`表示例来进行演示。

```sql
CREATE TABLE employees (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    department VARCHAR(50),
    salary INT,
    hire_date DATE
);

INSERT INTO employees (name, department, salary, hire_date) VALUES
('Alice', 'HR', 60000, '2020-01-15'),
('Bob', 'Engineering', 80000, '2019-03-01'),
('Charlie', 'Engineering', 95000, '2018-07-23'),
('David', 'Sales', 72000, '2021-05-11'),
('Eve', 'Sales', 75000, '2020-11-30');
```

## 数据查询 (SELECT)

`SELECT` 语句用于从表中检索数据。

### 检索所有列

```sql
SELECT * FROM employees;
```

### 检索特定列

```sql
SELECT name, salary FROM employees;
```

### 使用 `WHERE` 子句进行过滤

`WHERE` 子句用于根据特定条件筛选记录。

```sql
-- 查询薪水大于 75000 的员工
SELECT * FROM employees WHERE salary > 75000;

-- 查询工程部门(Engineering)的所有员工
SELECT * FROM employees WHERE department = 'Engineering';
```

### 使用 `ORDER BY` 对结果排序

`ORDER BY` 用于对结果集进行升序 (`ASC`) 或降序 (`DESC`) 排序。

```sql
-- 按薪水降序排列
SELECT name, salary FROM employees ORDER BY salary DESC;

-- 按入职日期升序排列
SELECT name, hire_date FROM employees ORDER BY hire_date ASC; -- ASC是默认值
```

### 使用 `LIMIT` 限制返回行数

`LIMIT` 用于限制查询返回的记录数量。

```sql
-- 查询薪水最高的两位员工
SELECT name, salary FROM employees ORDER BY salary DESC LIMIT 2;
```

## 数据插入 (INSERT)

`INSERT INTO` 语句用于向表中添加新记录。

```sql
INSERT INTO employees (name, department, salary, hire_date)
VALUES ('Frank', 'HR', 55000, '2022-02-01');
```

## 数据更新 (UPDATE)

`UPDATE` 语句用于修改表中的现有记录。

**警告**: 如果省略 `WHERE` 子句，`UPDATE` 将会更新表中的所有记录！

```sql
-- 为 Alice 涨薪
UPDATE employees
SET salary = 65000
WHERE name = 'Alice';

-- 将所有销售部门的员工薪水提高5%
UPDATE employees
SET salary = salary * 1.05
WHERE department = 'Sales';
```

## 数据删除 (DELETE)

`DELETE` 语句用于从表中删除记录。

**警告**: 如果省略 `WHERE` 子句，`DELETE` 将会删除表中的所有记录！

```sql
-- 删除名为 Frank 的员工记录
DELETE FROM employees
WHERE name = 'Frank';
```

## 聚合函数

聚合函数对一组值进行计算，并返回单个值。

- `COUNT()`: 计算行数
- `SUM()`: 计算总和
- `AVG()`: 计算平均值
- `MAX()`: 找出最大值
- `MIN()`: 找出最小值

```sql
-- 计算员工总数
SELECT COUNT(*) FROM employees;

-- 计算工程部门的平均薪水
SELECT AVG(salary) FROM employees WHERE department = 'Engineering';
```

### 使用 `GROUP BY` 分组

`GROUP BY` 语句通常与聚合函数一起使用，以将结果集按一个或多个列进行分组。

```sql
-- 计算每个部门的员工人数和平均薪水
SELECT
    department,
    COUNT(*) AS number_of_employees,
    AVG(salary)::INT AS average_salary -- ::INT 是PostgreSQL特有的类型转换语法
FROM
    employees
GROUP BY
    department;
```

这些是SQL最基础的操作。在掌握它们之后，您就可以开始与PostgreSQL进行有效的数据交互了。下一章，我们将探讨 [PostgreSQL丰富的数据类型](data-types.md)。