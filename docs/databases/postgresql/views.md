# 10. 视图与物化视图

视图是数据库中的一个重要概念，它允许我们将复杂的查询保存为虚拟表。这不仅能简化查询，还能提供一个抽象层，用于控制对底层数据的访问。

## 视图 (Views)

标准视图（通常简称为视图）是一个存储在数据库中的`SELECT`查询，它本身不存储任何数据。当您查询一个视图时，数据库会执行该视图定义的`SELECT`语句，并返回结果，就好像您在查询一个真实的表一样。

### 创建视图

假设我们经常需要查询工程部门(Engineering)薪水高于平均水平的员工。我们可以为此创建一个视图。

```sql
CREATE VIEW high_paid_engineers AS
SELECT
    id,
    name,
    salary
FROM
    employees
WHERE
    department = 'Engineering'
AND
    salary > (SELECT AVG(salary) FROM employees WHERE department = 'Engineering');
```

### 查询视图

创建后，您可以像查询普通表一样查询这个视图：

```sql
SELECT * FROM high_paid_engineers;

-- 也可以在视图上添加额外的条件
SELECT name FROM high_paid_engineers WHERE salary > 100000;
```

### 视图的优势

- **简化复杂性**: 将复杂的连接、聚合和计算逻辑封装在一个简单的视图中。
- **数据抽象**: 用户可以与视图交互，而无需关心底层表的复杂结构。
- **安全性**: 可以通过视图向用户暴露表的特定列和行，而不是整个表，从而实现更精细的访问控制。

### 视图的限制

- **性能**: 由于每次查询视图都会重新执行其底层的`SELECT`语句，对于非常复杂的查询，性能可能会成为瓶颈。
- **可更新性**: 只有简单的、满足特定条件的视图才是可更新的（即可以在其上执行`INSERT`, `UPDATE`, `DELETE`）。包含聚合、`GROUP BY`、`DISTINCT`等的复杂视图通常是只读的。

## 物化视图 (Materialized Views)

与标准视图不同，**物化视图会存储其查询结果**。它是一个真实存储在磁盘上的表，包含了其定义查询在某个时间点的数据快照。

### 创建物化视图

创建物化视图的语法与标准视图类似，只是多了`MATERIALIZED`关键字。

```sql
CREATE MATERIALIZED VIEW sales_summary AS
SELECT
    department,
    COUNT(*) as number_of_employees,
    SUM(salary) as total_salary,
    AVG(salary)::int as average_salary
FROM
    employees
GROUP BY
    department;
```

### 查询物化视图

查询物化视图与查询普通表或标准视图完全相同。但它的速度非常快，因为它直接从预先计算好的结果中读取数据，而不是执行复杂的聚合查询。

```sql
SELECT * FROM sales_summary WHERE department = 'Sales';
```

### 刷新物化视图

物化视图最大的特点是其数据不会自动更新。您必须手动或通过计划任务来**刷新**它，以反映底层基表的变化。

```sql
REFRESH MATERIALIZED VIEW sales_summary;
```

`REFRESH`命令会重新执行物化视图的定义查询，并用新的结果完全替换旧的数据。这是一个阻塞操作，在刷新期间视图不可用。

### 并发刷新 (PostgreSQL 9.4+)

为了避免在刷新期间锁定视图，PostgreSQL提供了并发刷新。

```sql
-- 首先，物化视图需要有一个唯一的索引
CREATE UNIQUE INDEX idx_sales_summary_dept ON sales_summary (department);

-- 然后可以进行并发刷新
REFRESH MATERIALIZED VIEW CONCURRENTLY sales_summary;
```
并发刷新会在后台创建一个临时的新版本，然后快速切换，对读查询的影响降到最低。

## 视图 vs. 物化视图

| 特性 | 标准视图 (View) | 物化视图 (Materialized View) |
| --- | --- | --- |
| **数据存储** | 不存储数据，是虚拟的。 | 存储查询结果，是物理存在的。 |
| **数据实时性** | 总是实时的，反映底层表的最新状态。 | 非实时的，数据是上次刷新时的快照。 |
| **查询性能** | 取决于底层查询的复杂性。 | 非常高，因为直接读取预计算结果。 |
| **维护成本** | 无需维护。 | 需要定期刷新来更新数据。 |
| **适用场景** | 简化复杂查询、安全控制、逻辑抽象。 | 缓存昂贵的、不要求实时性的查询结果，如报表、仪表盘。 |

选择使用标准视图还是物化视图，取决于您对数据实时性的要求和对查询性能的期望。这是在数据库设计中进行性能优化的一个重要权衡。 