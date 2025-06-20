# 11. 高级查询 (窗口函数, CTE)

当简单的`SELECT`、`WHERE`和`GROUP BY`不足以解决问题时，PostgreSQL提供了强大的高级查询工具，如窗口函数和公用表表达式(CTE)，它们能以更清晰、更高效的方式解决复杂的分析需求。

## 公用表表达式 (Common Table Expressions - CTE)

CTE，也称为`WITH`子句，允许您为一个复杂的子查询命名，然后在主查询中像引用一个临时表一样引用它。这极大地提高了复杂查询的可读性和模块化。

### 基本语法

```sql
WITH <cte_name> AS (
    -- CTE的定义查询
    SELECT ...
)
-- 主查询
SELECT ... FROM <cte_name>;
```

### 示例：查找每个部门薪水最高的员工

如果不使用CTE，这个查询可能需要子查询或自连接，比较复杂。使用CTE则非常清晰：

```sql
WITH department_max_salary AS (
    SELECT department, MAX(salary) as max_salary
    FROM employees
    GROUP BY department
)
SELECT
    e.name,
    e.department,
    e.salary
FROM
    employees e
JOIN
    department_max_salary dms ON e.department = dms.department AND e.salary = dms.max_salary;
```

### 递归CTE

递归CTE是CTE的杀手级特性，它能够引用自身，用于处理层级或图形结构的数据，例如组织架构、物料清单、社交网络关系等。

**示例：查找某个员工下的所有下属（递归）**
假设`employees`表有一个`manager_id`列，引用自身`id`。

```sql
-- 为了演示，先给表加上 manager_id
ALTER TABLE employees ADD COLUMN manager_id INT;
UPDATE employees SET manager_id = (SELECT id FROM employees WHERE name = 'Charlie') WHERE name IN ('Bob', 'Alice');
UPDATE employees SET manager_id = (SELECT id FROM employees WHERE name = 'Bob') WHERE name IN ('David', 'Eve');

-- 使用递归CTE查找'Charlie'的所有下属
WITH RECURSIVE subordinates AS (
    -- 初始成员 (非递归部分): 直接下属
    SELECT id, name, manager_id FROM employees WHERE id = (SELECT id FROM employees WHERE name = 'Charlie')
    UNION ALL
    -- 递归成员: 下属的下属
    SELECT e.id, e.name, e.manager_id
    FROM employees e
    JOIN subordinates s ON s.id = e.manager_id
)
SELECT * FROM subordinates;
```

## 窗口函数 (Window Functions)

窗口函数对与当前行相关的行集（即"窗口"）进行计算。与聚合函数不同，窗口函数在计算后**不会将多行合并为一行**，而是为结果集中的每一行返回一个值。

### 基本语法

```sql
<function_name>() OVER (
    [PARTITION BY <...>]  -- 分区子句 (可选)
    [ORDER BY <...>]     -- 排序子句 (可选)
    [<frame_clause>]     -- 窗口框架子句 (可选)
)
```
- `PARTITION BY`: 将行分成多个区（Partition），窗口函数在每个区内独立计算。类似于`GROUP BY`，但不会折叠行。
- `ORDER BY`: 定义分区内行的排序方式。
- `frame_clause`: 定义窗口的范围（例如，"当前行之前的三行到当前行之后的一行"）。

### 常用窗口函数

- **排名函数**: `ROW_NUMBER()`, `RANK()`, `DENSE_RANK()`
- **聚合函数**: `SUM()`, `AVG()`, `COUNT()`, `MAX()`, `MIN()` (作为窗口函数使用)
- **值函数**: `LAG()`, `LEAD()`, `FIRST_VALUE()`, `LAST_VALUE()`

### 示例1：为每个部门的员工按薪水排名

```sql
SELECT
    name,
    department,
    salary,
    RANK() OVER (PARTITION BY department ORDER BY salary DESC) as department_rank
FROM
    employees;
```
- `PARTITION BY department`: 按部门分区，排名将在每个部门内独立进行。
- `ORDER BY salary DESC`: 在每个部门内，按薪水降序排列。
- `RANK()`: 计算排名。如果薪水相同，排名会相同，但后续排名会跳跃（例如 1, 2, 2, 4）。使用`DENSE_RANK()`则不会跳跃（1, 2, 2, 3）。

### 示例2：计算每个员工薪水与部门平均薪水的差异

```sql
SELECT
    name,
    department,
    salary,
    AVG(salary) OVER (PARTITION BY department) as avg_dept_salary,
    salary - AVG(salary) OVER (PARTITION BY department) as diff_from_avg
FROM
    employees;
```
这里，`AVG(salary)`作为窗口函数，为`employees`表中的每一行都计算出其所在部门的平均薪水。

### 示例3：获取上一个入职员工的信息 (LAG)

```sql
SELECT
    name,
    hire_date,
    LAG(name, 1, 'N/A') OVER (ORDER BY hire_date) as previous_hire_name,
    LAG(hire_date, 1) OVER (ORDER BY hire_date) as previous_hire_date
FROM
    employees;
```
`LAG(column, offset, default)`函数可以获取在当前行之前的第`offset`行的`column`值。`LEAD()`则用于获取之后行的值。

窗口函数和CTE是现代SQL的强大工具，能够以优雅和高效的方式解决许多传统SQL难以处理的分析问题。下一章我们将探讨PostgreSQL对[JSONB与非结构化数据](jsonb.md)的强大支持。 