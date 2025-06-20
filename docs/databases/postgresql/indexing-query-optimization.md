# 8. 索引与查询优化

索引是提高数据库查询性能的最重要工具。没有索引，数据库必须执行全表扫描（Full Table Scan），即逐行检查表中的每一条记录，以找到匹配的行。对于大表来说，这是非常低效的。

## 什么是索引？

索引是一种特殊的数据结构（最常见的是B-Tree），它存储了表中特定列的值以及指向原始数据行的指针。由于索引是排序的，数据库可以非常快速地（通常是对数时间复杂度）定位到所需的数据，类似于在一本排序好的书中通过目录查找章节。

### 创建索引

`CREATE INDEX` 命令用于在表的一列或多列上创建索引。

```sql
-- 在 employees 表的 name 列上创建一个B-Tree索引
CREATE INDEX idx_employees_name ON employees (name);

-- 在 department 和 salary 列上创建一个复合索引
CREATE INDEX idx_employees_dept_salary ON employees (department, salary);
```

## PostgreSQL支持的索引类型

PostgreSQL提供了多种索引类型，以适应不同的查询模式。

- **B-Tree**: 最通用的索引类型，适用于处理等于（`=`）和范围（`>`, `<`, `>=`, `<=`）查询。它是默认的索引类型。
- **Hash**: 仅适用于等值比较（`=`）。它通常比B-Tree更快，但在PostgreSQL中，由于其实现限制（例如不支持WAL日志），使用较少。
- **GiST (Generalized Search Tree)**: 通用搜索树。它不是一种索引类型，而是一个框架，可以在其中实现多种不同的索引策略。常用于索引几何数据类型（PostGIS）和全文搜索。
- **SP-GiST (Space-Partitioned GiST)**: 空间分区的GiST。支持更广泛的非平衡数据结构，如四叉树、k-d树。适用于特定的数据类型，如电话号码路由。
- **GIN (Generalized Inverted Index)**: 通用倒排索引。最适合索引包含多个值的列，例如数组（`integer[]`）或JSONB。它是全文搜索和`jsonb_path_ops`的首选。
- **BRIN (Block Range Index)**: 块范围索引。它存储每个块范围内值的摘要信息（最小值和最大值）。对于与表中物理存储顺序高度相关的大表（例如，按时间戳排序的日志表）非常有效，且索引体积非常小。

## 查询优化器与 `EXPLAIN`

当您执行一个SQL查询时，PostgreSQL的**查询优化器** (Query Planner) 会分析查询，并生成它认为最高效的执行计划。

`EXPLAIN` 命令是理解和优化查询性能的窗口。它会显示查询优化器选择的执行计划，而不会实际执行它。

```sql
EXPLAIN SELECT * FROM employees WHERE name = 'Charlie';
```

**输出示例**:
```
                                  QUERY PLAN
-------------------------------------------------------------------------------
 Index Scan using idx_employees_name on employees  (cost=0.28..8.29 rows=1 width=52)
   Index Cond: (name = 'Charlie'::text)
(2 rows)
```
- **Index Scan**: 表示查询优化器决定使用索引来查找数据。
- **cost=0.28..8.29**: 这是优化器估算的成本。第一个数字是启动成本（在返回第一行之前的成本），第二个数字是总成本。成本单位是任意的，但可用于比较不同计划的优劣。

如果 `name` 列上没有索引，执行计划可能会是这样：
```
                         QUERY PLAN
-------------------------------------------------------------
 Seq Scan on employees  (cost=0.00..15.50 rows=1 width=52)
   Filter: (name = 'Charlie'::text)
(2 rows)
```
- **Seq Scan** (Sequential Scan): 表示全表扫描。注意其总成本（15.50）远高于使用索引的成本（8.29）。

### `EXPLAIN ANALYZE`

`EXPLAIN ANALYZE` 会实际执行查询，并显示真实的执行时间和行数。这是最准确的分析工具，但要小心，因为它会执行查询（包括 `INSERT`, `UPDATE`, `DELETE`）。

```sql
EXPLAIN ANALYZE SELECT * FROM employees WHERE department = 'Engineering';
```

**输出示例**:
```
                                                    QUERY PLAN
-------------------------------------------------------------------------------------------------------------------
 Seq Scan on employees  (cost=0.00..15.50 rows=2 width=52) (actual time=0.012..0.013 rows=2 loops=1)
   Filter: (department = 'Engineering'::text)
   Rows Removed by Filter: 3
 Planning Time: 0.075 ms
 Execution Time: 0.030 ms
(5 rows)
```
- **actual time**: 实际的启动时间和总执行时间（毫秒）。
- **rows**: 该节点实际返回的行数。
- **loops**: 该计划节点执行的次数。

## 何时创建索引？

- **`WHERE` 子句中的列**: 经常用于筛选的列是索引的首选。
- **`JOIN` 操作的连接键**: 在 `ON` 子句中用于连接表的列（通常是外键）上创建索引至关重要。
- **`ORDER BY` 子句中的列**: 在用于排序的列上创建索引可以避免昂贵的排序操作。

## 索引的开销

索引并非没有成本。它们会：
- **占用磁盘空间**: 索引本身是需要存储的。
- **降低写性能**: 当您执行 `INSERT`, `UPDATE`, `DELETE` 操作时，数据库不仅需要修改表数据，还需要更新相关的索引，这会增加额外的开销。

因此，索引的设计需要在"提升读性能"和"降低写性能"之间找到平衡。不要盲目地为所有列创建索引。

理解索引的工作原理和如何使用 `EXPLAIN` 分析查询计划，是从"会用SQL"到"精通SQL"的关键一步。下一章，我们将深入探讨PostgreSQL如何处理 [事务与并发控制](transactions-concurrency.md)。 