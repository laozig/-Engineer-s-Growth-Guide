# 13. 视图 (Views)

视图（View）是一个虚拟表，其内容由一个 SQL 查询定义。它就像一个预存的 `SELECT` 语句，让你能够像查询真实表一样查询它。

视图本身不包含任何数据。它所显示的数据是从一个或多个基表（Base Table）中动态生成的。对视图的任何操作（如查询）最终都会被转换成对基表的操作。

## 为什么使用视图？

视图提供了多种好处：

1.  **简化复杂查询**:
    - 你可以将一个复杂的、多表连接的 `JOIN` 查询或带有复杂计算的查询封装在一个视图中。之后，只需对这个视图执行简单的 `SELECT *` 查询即可，极大地简化了日常操作。

2.  **增强安全性**:
    - 视图可以作为一种安全机制。你可以授权用户访问视图，而不是底层的基表。通过视图，你可以限制用户只能看到特定的行或列，从而隐藏敏感数据（如薪水、个人信息等）。

3.  **逻辑数据独立性**:
    - 视图提供了一层抽象。如果底层表的结构发生了变化（例如，一个列表被拆分成两个，或者列被重命名），你只需修改视图的定义，而使用该视图的应用程序代码可以保持不变。这提高了系统的可维护性。

## 创建视图

使用 `CREATE VIEW` 语句来创建视图。

**示例 1：创建一个隐藏薪水信息的员工视图**

```sql
CREATE VIEW employee_public_info AS
SELECT
    id,
    first_name,
    last_name,
    email,
    hire_date,
    department_id
FROM
    employees;
```
现在，你可以授权某个用户只能访问 `employee_public_info` 视图，这样他们就无法看到 `salary` 列。

```sql
-- 查询视图就像查询一个普通的表
SELECT * FROM employee_public_info WHERE hire_date > '2023-03-01';
```

**示例 2：创建一个显示员工及其部门名称的视图**

这个视图封装了一个 `JOIN` 操作。

```sql
CREATE VIEW employee_department_details AS
SELECT
    e.id AS employee_id,
    e.first_name,
    e.last_name,
    d.name AS department_name
FROM
    employees AS e
LEFT JOIN
    departments AS d ON e.department_id = d.id;
```

之后，当你需要员工及其部门信息时，不再需要每次都写 `LEFT JOIN`，只需：

```sql
SELECT * FROM employee_department_details WHERE employee_id = 1;
```

## 修改视图

使用 `ALTER VIEW` 语句来修改一个已存在的视图的定义。语法与 `CREATE VIEW` 类似。

```sql
-- 假设我们想给 employee_public_info 视图添加 hire_date 的年份
ALTER VIEW employee_public_info AS
SELECT
    id,
    first_name,
    last_name,
    email,
    YEAR(hire_date) AS hire_year -- 修改了定义
FROM
    employees;
```

或者，你也可以使用 `CREATE OR REPLACE VIEW`，它会在视图不存在时创建它，在视图存在时替换它。

```sql
CREATE OR REPLACE VIEW employee_public_info AS
-- ... 新的定义 ...
```

## 删除视图

使用 `DROP VIEW` 语句来删除一个或多个视图。

```sql
DROP VIEW IF EXISTS employee_public_info;
DROP VIEW IF EXISTS employee_department_details, employee_public_info;
```
删除视图不会影响基表中的数据。

## 可更新的视图 (Updatable Views)

在某些条件下，视图是**可更新的**，这意味着你可以对它使用 `INSERT`、`UPDATE` 和 `DELETE` 语句，这些操作会自动传递到基表。

一个视图是可更新的，必须满足以下（及其他一些）条件：
- `SELECT` 列表中没有使用 `DISTINCT`、聚合函数（`MAX`, `MIN`, `SUM`等）、`GROUP BY`、`HAVING`、`UNION` 等。
- 查询中只包含一个表，或者如果包含多个表，必须是特定类型的 `JOIN` 并且更新只涉及一个基表。
- `SELECT` 列表中的所有列都必须引用基表的真实列，不能是计算列。

**示例：一个可更新的视图**
```sql
CREATE VIEW engineering_employees AS
SELECT id, first_name, last_name, email, salary
FROM employees
WHERE department_id = 1; -- 假设 1 是 Engineering 部门
```

现在，你可以通过这个视图来更新 Engineering 部门的员工：
```sql
-- 给 Engineering 部门的 Alice 涨薪
UPDATE engineering_employees
SET salary = 65000
WHERE id = 1;
```
这个 `UPDATE` 操作会成功执行，并修改 `employees` 基表中的数据。

**`WITH CHECK OPTION`**
当你创建一个可更新视图时，可以添加 `WITH CHECK OPTION` 子句。这会阻止你插入或更新不符合视图 `WHERE` 子句条件的行。

```sql
CREATE OR REPLACE VIEW engineering_employees AS
SELECT id, first_name, last_name, email, salary, department_id
FROM employees
WHERE department_id = 1
WITH CHECK OPTION;
```
现在，以下操作将会**失败**，因为它试图将一个员工的部门 ID 更新为不等于 1 的值，这违反了视图的 `WHERE` 条件。
```sql
-- 这个操作会失败
UPDATE engineering_employees
SET department_id = 2
WHERE id = 1;
```
`WITH CHECK OPTION` 强制所有进入视图的数据行都必须满足视图的定义，从而保证了数据的一致性。

视图是简化数据库交互和增强安全性的强大工具，但需要注意其性能。因为每次查询视图都会重新执行其 underlying `SELECT` 语句，对于非常复杂的视图，可能会有性能开销。 