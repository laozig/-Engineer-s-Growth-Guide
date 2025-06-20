# 8. 连接查询 (JOINs)

在规范化的关系型数据库中，数据被分散在多个表中。`JOIN` 子句是 SQL 的核心功能之一，它用于根据相关列之间的关系，将多个表中的行组合起来。

为了演示 `JOIN`，我们需要至少两个相关的表。假设我们除了 `employees` 表外，还有一个 `departments` 表。

```sql
-- 创建 departments 表
CREATE TABLE departments (
    id INT PRIMARY KEY,
    name VARCHAR(100) NOT NULL
);

-- 插入一些部门数据
INSERT INTO departments (id, name) VALUES
(1, 'Engineering'),
(2, 'Human Resources'),
(3, 'Sales'),
(4, 'Marketing');

-- 为了关联两个表，我们需要在 employees 表中添加一个外键列
ALTER TABLE employees
ADD COLUMN department_id INT,
ADD CONSTRAINT fk_department
FOREIGN KEY (department_id) REFERENCES departments(id);

-- 更新员工数据，为他们分配部门
UPDATE employees SET department_id = 1 WHERE id IN (1, 3); -- Alice, Charlie
UPDATE employees SET department_id = 2 WHERE id = 2;       -- Bob
UPDATE employees SET department_id = 3 WHERE id = 4;       -- Diana
-- 注意：员工 Ethan (id=5) 已被删除，且我们有意不给所有员工分配部门，以演示外连接
```

## `INNER JOIN` (内连接)

`INNER JOIN` 是最常用的连接类型。它返回两个表中连接字段相匹配的行。如果某个员工没有部门 ID，或者某个部门没有员工，它们将不会出现在结果中。

```sql
SELECT
    e.first_name,
    e.last_name,
    d.name AS department_name
FROM
    employees AS e
INNER JOIN
    departments AS d ON e.department_id = d.id;
```

- `FROM employees AS e INNER JOIN departments AS d`: 指定要连接的两个表及其别名。
- `ON e.department_id = d.id`: 这是**连接条件**，它告诉数据库如何匹配两个表中的行。在这里，我们使用员工表中的 `department_id` 和部门表中的 `id` 进行匹配。

结果将只包含那些既有员工又有对应部门的记录。

![INNER JOIN](https://www.w3schools.com/sql/img_innerjoin.gif)

## `LEFT JOIN` (左外连接)

`LEFT JOIN` (或 `LEFT OUTER JOIN`) 返回左表（`FROM` 子句中提到的第一个表）中的**所有**行，以及右表中与连接条件匹配的行。如果右表中没有匹配项，则右表的列将显示为 `NULL`。

这对于查找"A 中有但 B 中没有"的数据非常有用。

```sql
-- 查询所有员工及其部门，即使某些员工没有分配部门
SELECT
    e.first_name,
    e.last_name,
    d.name AS department_name
FROM
    employees AS e
LEFT JOIN
    departments AS d ON e.department_id = d.id;
```
在这个查询结果中，所有在 `employees` 表中的员工都会被列出。如果某个员工的 `department_id` 是 `NULL` 或者没有在 `departments` 表中匹配到，`department_name` 这一列就会显示 `NULL`。

![LEFT JOIN](https://www.w3schools.com/sql/img_leftjoin.gif)

## `RIGHT JOIN` (右外连接)

`RIGHT JOIN` (或 `RIGHT OUTER JOIN`) 与 `LEFT JOIN` 相反。它返回右表中的**所有**行，以及左表中与连接条件匹配的行。如果左表中没有匹配项，则左表的列将显示为 `NULL`。

```sql
-- 查询所有部门及其员工，即使某些部门当前没有员工
SELECT
    e.first_name,
    e.last_name,
    d.name AS department_name
FROM
    employees AS e
RIGHT JOIN
    departments AS d ON e.department_id = d.id;
```
在这个查询结果中，'Marketing' 部门 (id=4) 将会出现在结果中，但其 `first_name` 和 `last_name` 列将为 `NULL`，因为它目前没有任何员工。

![RIGHT JOIN](https://www.w3schools.com/sql/img_rightjoin.gif)

> **实践提示**: 大多数情况下，`LEFT JOIN` 比 `RIGHT JOIN` 更常用，也更符合人的阅读习惯（从主表出发，连接辅助信息）。任何 `RIGHT JOIN` 都可以通过调换表的顺序重写为 `LEFT JOIN`。

## `FULL OUTER JOIN` (全外连接)

`FULL OUTER JOIN` 返回左表和右表中的所有行。当某一行在另一个表中没有匹配时，另一个表的列会显示为 `NULL`。它结合了 `LEFT JOIN` 和 `RIGHT JOIN` 的结果。

**注意**: MySQL 本身不直接支持 `FULL OUTER JOIN` 语法。但是，我们可以通过 `UNION` 结合 `LEFT JOIN` 和 `RIGHT JOIN` 来模拟它。

```sql
-- 模拟 MySQL 的 FULL OUTER JOIN
SELECT
    e.first_name, d.name AS department_name
FROM
    employees AS e
LEFT JOIN
    departments AS d ON e.department_id = d.id

UNION

SELECT
    e.first_name, d.name AS department_name
FROM
    employees AS e
RIGHT JOIN
    departments AS d ON e.department_id = d.id;
```
- `UNION` 操作符用于合并两个或多个 `SELECT` 语句的结果集，并自动去除重复的行。

## `CROSS JOIN` (交叉连接)

`CROSS JOIN` 返回左表中的每一行与右表中的每一行的笛卡尔积。结果集的大小将是 `左表行数 * 右表行数`。它很少被直接使用，除非在特定的数据生成或组合场景中。

```sql
SELECT e.first_name, d.name
FROM employees AS e
CROSS JOIN departments AS d;
```
这会为每个员工匹配所有部门，无论他们是否真的在该部门。

## 多表连接

你可以在一个查询中连接两个以上的表。

假设我们还有一个 `locations` 表：
```sql
CREATE TABLE locations (
    id INT PRIMARY KEY,
    city VARCHAR(50)
);
ALTER TABLE departments ADD COLUMN location_id INT;
-- ... 更新数据 ...
```

```sql
-- 查询每个员工、他所在的部门以及部门所在的城市
SELECT
    e.first_name,
    d.name AS department,
    l.city
FROM
    employees AS e
INNER JOIN
    departments AS d ON e.department_id = d.id
INNER JOIN
    locations AS l ON d.location_id = l.id;
```

掌握不同类型的 `JOIN` 是编写复杂、有意义查询的关键，它能让你将分散在整个数据库中的信息有效地整合在一起。 