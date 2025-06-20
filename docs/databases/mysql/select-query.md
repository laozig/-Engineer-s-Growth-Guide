# 7. SELECT 查询详解

`SELECT` 是 SQL 中功能最强大、最灵活的命令。除了基本的 `WHERE` 过滤，它还支持排序、限制返回行数、聚合数据等多种高级功能。本章将深入探讨这些高级查询技术。

我们将继续使用上一章的 `employees` 表，并假设已插入更多数据。

## 排序结果 - `ORDER BY`

`ORDER BY` 子句用于对结果集进行排序。

- `ASC`: 升序 (Ascending)，默认排序方式。
- `DESC`: 降序 (Descending)。

```sql
-- 按薪水从低到高排序
SELECT first_name, last_name, salary
FROM employees
ORDER BY salary ASC;

-- 按薪水从高到低排序
SELECT first_name, last_name, salary
FROM employees
ORDER BY salary DESC;

-- 按多个列排序：先按姓氏升序，如果姓氏相同，再按名字升序
SELECT first_name, last_name
FROM employees
ORDER BY last_name ASC, first_name ASC;
```

## 限制结果数量 - `LIMIT`

`LIMIT` 子句用于限制查询返回的行数，这对于分页查询至关重要。

```sql
-- 检索薪水最高的前 3 名员工
SELECT first_name, salary
FROM employees
ORDER BY salary DESC
LIMIT 3;
```

`LIMIT` 也可以接受两个参数：`LIMIT offset, count`。
- `offset`: 起始行的偏移量（第一行的偏移量是 0）。
- `count`: 要返回的行数。

```sql
-- 分页查询：获取第 2 页的数据，每页 5 条记录
-- (跳过前 5 条记录，然后取 5 条)
SELECT id, first_name
FROM employees
ORDER BY id
LIMIT 5, 5;
```

## 去除重复行 - `DISTINCT`

`DISTINCT` 关键字用于从结果集中移除重复的行。

```sql
-- 获取所有不同的姓氏
SELECT DISTINCT last_name FROM employees;
```

`DISTINCT` 也可以应用于多个列，此时它会基于这些列的组合来判断是否重复。

```sql
SELECT DISTINCT first_name, last_name FROM employees;
```

## 聚合函数 (Aggregate Functions)

聚合函数对一组值进行计算，并返回单个值。它们通常与 `GROUP BY` 子句一起使用。

- `COUNT()`: 计算行数。
- `SUM()`: 计算数值列的总和。
- `AVG()`: 计算数值列的平均值。
- `MAX()`: 找出列中的最大值。
- `MIN()`: 找出列中的最小值。

```sql
-- 计算公司总员工数
SELECT COUNT(*) FROM employees;

-- 计算 'Smith' 姓氏的员工数
SELECT COUNT(*) FROM employees WHERE last_name = 'Smith';

-- 计算公司年度总薪水支出
SELECT SUM(salary) FROM employees;

-- 查找最高薪水
SELECT MAX(salary) FROM employees;

-- 查找最低薪水
SELECT MIN(salary) FROM employees;

-- 计算平均薪水
SELECT AVG(salary) FROM employees;
```

## 分组数据 - `GROUP BY`

`GROUP BY` 子句通常与聚合函数一起使用，它将结果集按一个或多个列进行分组，对每个分组应用聚合函数。

```sql
-- 统计每个姓氏有多少员工
SELECT last_name, COUNT(*) AS number_of_employees
FROM employees
GROUP BY last_name;

-- 计算每个部门 (假设有个 department 列) 的平均薪水
SELECT department, AVG(salary) AS avg_salary
FROM employees
GROUP BY department;
```

**重要规则**: 当使用 `GROUP BY` 时，`SELECT` 列表中的所有非聚合函数列**必须**出现在 `GROUP BY` 子句中。

## 过滤分组 - `HAVING`

`WHERE` 子句在分组前过滤行，而 `HAVING` 子句在分组后过滤分组。`HAVING` 必须跟在 `GROUP BY` 之后。

```sql
-- 找出员工数超过 5 人的姓氏
SELECT last_name, COUNT(*)
FROM employees
GROUP BY last_name
HAVING COUNT(*) > 5;

-- 找出平均薪水超过 80000 的部门
SELECT department, AVG(salary)
FROM employees
GROUP BY department
HAVING AVG(salary) > 80000;
```

## 使用别名 - `AS`

`AS` 关键字用于为列或表指定一个临时的名称（别名），以提高查询的可读性。

```sql
-- 为列指定别名
SELECT
    first_name AS "名",
    last_name AS "姓",
    salary AS "薪水"
FROM employees;

-- 为表指定别名 (在 JOIN 查询中非常有用)
SELECT e.first_name, e.salary
FROM employees AS e
WHERE e.salary > 70000;
```

## `SELECT` 语句的逻辑执行顺序

理解 SQL 查询的逻辑执行顺序对于编写复杂查询至关重要。虽然我们编写的顺序是 `SELECT ... FROM ... WHERE ... GROUP BY ... HAVING ... ORDER BY ... LIMIT`，但数据库的逻辑处理顺序通常是：

1.  **`FROM`**: 确定要操作的表。
2.  **`WHERE`**: 过滤行。
3.  **`GROUP BY`**: 将行分组。
4.  **`HAVING`**: 过滤分组。
5.  **`SELECT`**: 选择要返回的列（并处理别名和聚合函数）。
6.  **`DISTINCT`**: 去除重复行。
7.  **`ORDER BY`**: 对结果进行排序。
8.  **`LIMIT`**: 限制返回的行数。

掌握这些 `SELECT` 的高级特性将使你能够从数据中提取出更有价值和更精确的信息。 