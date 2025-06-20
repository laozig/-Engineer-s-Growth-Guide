# 9. 子查询 (Subqueries)

子查询（也称为内部查询或嵌套查询）是嵌套在另一个 SQL 查询（外部查询）中的查询。子查询可以返回单个值（标量子查询）、单列（列子查询）或多行多列（表子查询），它们为构建复杂和动态的查询提供了强大的能力。

## 标量子查询 (Scalar Subquery)

标量子查询只返回单个值（一行一列）。它可以用于 `WHERE`、`SELECT` 或 `SET` 子句中任何需要单个值的地方。

**示例：查找薪水高于平均薪水的员工**

```sql
-- 1. 首先，找到公司的平均薪水
SELECT AVG(salary) FROM employees; -- 假设返回 67000

-- 2. 然后，用这个值去查找员工
SELECT first_name, salary
FROM employees
WHERE salary > 67000;
```

使用子查询可以将这两步合并为一步：

```sql
SELECT first_name, salary
FROM employees
WHERE salary > (SELECT AVG(salary) FROM employees);
```
这里的 `(SELECT AVG(salary) FROM employees)` 就是一个标量子查询，它在外部查询执行时先被计算，并返回一个单一的平均薪水值。

## 列子查询 (Column Subquery)

列子查询返回单列多行。它通常与 `IN`、`NOT IN`、`ANY` 或 `ALL` 操作符一起在 `WHERE` 子句中使用。

### 使用 `IN`

`IN` 操作符检查一个值是否存在于子查询返回的结果集中。

**示例：查找在 'Sales' 或 'Engineering' 部门工作的所有员工**

```sql
SELECT first_name, last_name
FROM employees
WHERE department_id IN (SELECT id FROM departments WHERE name IN ('Sales', 'Engineering'));
```
子查询 `(SELECT id FROM departments WHERE name IN ('Sales', 'Engineering'))` 返回了 'Sales' 和 'Engineering' 部门的 ID 列表（例如 `(1, 3)`），外部查询则利用这个列表来筛选 `employees` 表。

### 使用 `NOT IN`

`NOT IN` 则相反，用于查找不匹配子查询结果集中任何一个值的记录。

**示例：查找所有未分配到任何部门的员工** (虽然用 `IS NULL` 更直接，但这里用于演示)

```sql
SELECT first_name
FROM employees
WHERE id NOT IN (SELECT DISTINCT employee_id FROM assignments); -- 假设有另一个 'assignments' 表
```
> **⚠️ 注意**: 如果子查询的结果集中包含 `NULL` 值，`NOT IN` 的行为可能会出乎意料（通常不会返回任何行），因此使用时要特别小心。在这种情况下，`NOT EXISTS` 是一个更安全的选择。

### 使用 `ANY` 和 `ALL`

- `> ANY`: 大于子查询结果中的任意一个值（即大于最小值）。
- `< ANY`: 小于子查询结果中的任意一个值（即小于最大值）。
- `= ANY`: 等同于 `IN`。
- `> ALL`: 大于子查询结果中的所有值（即大于最大值）。
- `< ALL`: 小于子查询结果中的所有值（即小于最小值）。

**示例：查找薪水高于 'Sales' 部门任意一名员工薪水的员工**

```sql
SELECT first_name, salary
FROM employees
WHERE salary > ANY (SELECT salary FROM employees WHERE department_id = 3);
```

## 行子查询 (Row Subquery)

行子查询返回一行多列。它可以用于比较多个列。

**示例：查找与某个特定员工的部门和薪水都相同的其他员工**

```sql
SELECT first_name, department_id, salary
FROM employees
WHERE (department_id, salary) = (SELECT department_id, salary FROM employees WHERE id = 2);
```
这里，` (department_id, salary)` 这个行构造器与子查询返回的一行（包含两列）进行比较。

## 表子查询 (Table Subquery) / 派生表

当子查询返回多行多列时，它就像一个临时的表。这种子查询几乎总是出现在 `FROM` 子句中，被称为**派生表 (Derived Table)**。

**必须为派生表指定一个别名。**

**示例：查找每个部门的平均薪水，并将其与员工信息连接**

```sql
SELECT
    e.first_name,
    e.salary,
    dep_avg.avg_salary AS department_average_salary
FROM
    employees AS e
JOIN
    (SELECT department_id, AVG(salary) AS avg_salary FROM employees GROUP BY department_id) AS dep_avg
ON
    e.department_id = dep_avg.department_id;
```
在这个例子中，我们首先创建了一个名为 `dep_avg` 的派生表，该表包含了每个部门的 ID 和其平均薪水。然后，我们将 `employees` 表与这个派生表进行连接，以便在每一行员工信息旁边显示其所在部门的平均薪水。

## 相关子查询 (Correlated Subquery)

与前面的独立子查询不同，相关子查询的执行依赖于外部查询。外部查询的每一行都会触发一次子查询的执行。

**示例：查找每个部门中薪水最高的员工**

```sql
SELECT first_name, last_name, salary, department_id
FROM employees AS e1
WHERE salary = (
    SELECT MAX(salary)
    FROM employees AS e2
    WHERE e2.department_id = e1.department_id
);
```
- 对于外部查询 `e1` 的每一行，内部查询 `e2` 都会执行一次。
- `e2.department_id = e1.department_id` 是关键的**关联条件**。
- 内部查询的作用是：对于当前员工 `e1` 所在的部门，找出该部门的最高薪水。
- 外部查询的 `WHERE` 子句则判断当前员工 `e1` 的薪水是否等于他所在部门的最高薪水。

> **性能提示**: 相关子查询可能会导致性能问题，因为它们对外部查询的每一行都要执行一次。在很多情况下，使用 `JOIN` 或窗口函数 (Window Functions, MySQL 8.0+) 会有更好的性能。例如，上面的查询用窗口函数可以写得更高效。

## `EXISTS` 和 `NOT EXISTS`

`EXISTS` 操作符用于检查子查询是否返回了任何行。如果子查询至少返回一行，`EXISTS` 的结果为 `TRUE`；否则为 `FALSE`。`NOT EXISTS` 则相反。

`EXISTS` 通常比 `IN` 更高效，因为它找到匹配行后就会立即停止，而 `IN` 需要收集所有匹配结果。

**示例：查找至少有一名员工的部门**

```sql
SELECT name
FROM departments AS d
WHERE EXISTS (
    SELECT 1 FROM employees AS e WHERE e.department_id = d.id
);
```
- 对于 `departments` 表中的每个部门 `d`，子查询会去 `employees` 表中查找是否有员工属于该部门。
- `SELECT 1` 是一个惯用法，表示我们不关心子查询返回什么内容，只关心它是否返回了行。
- 只要子查询能找到至少一个员工，`EXISTS` 就为真，该部门就会被选中。

子查询是 SQL 中一个极其强大的工具，但也容易写出低效的查询。理解不同类型的子查询及其执行方式，并考虑是否有 `JOIN` 等替代方案，是写出高质量 SQL 的关键。 