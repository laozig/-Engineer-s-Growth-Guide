# 11. 索引 (Indexes)

索引是数据库中用于提高查询速度的特殊数据结构。你可以把索引想象成一本书的目录，它允许数据库引擎在不扫描整张表的情况下快速找到所需的行。虽然索引能极大地提升 `SELECT` 查询的性能，但它们也会增加 `INSERT`、`UPDATE` 和 `DELETE` 操作的开销，因为每次数据变动时，相关的索引也需要被更新。

## 索引是如何工作的？

大多数 MySQL 索引（如 `PRIMARY KEY`, `UNIQUE`, `INDEX`, 和 `FULLTEXT`）默认都使用 B-Tree（B树）数据结构进行存储。B-Tree 是一种自平衡的树，它能保持数据有序，并允许在对数时间内进行搜索、顺序访问、插入和删除。

当你在一个列上创建索引时，数据库会维护一个包含该列值和指向对应表行的指针的排序列表。当执行一个带有 `WHERE` 子句的查询时，数据库引擎可以利用这个索引，通过高效的 B-Tree 搜索算法快速定位到目标数据，而不是逐行扫描整个表（全表扫描）。

## 索引的类型

MySQL 提供了多种类型的索引，以适应不同的查询需求。

### 1. B-Tree 索引

这是最常见的索引类型，适用于全键值、键值范围和键前缀查找。

- **单列索引 (Single-column Index)**: 在单个列上创建的索引。
  ```sql
  CREATE INDEX idx_lastname ON employees (last_name);
  ```
- **复合索引 (Composite/Multi-column Index)**: 在两个或更多个列上创建的索引。
  ```sql
  CREATE INDEX idx_lastname_firstname ON employees (last_name, first_name);
  ```
  **最左前缀原则**: 对于复合索引，查询只有在使用到索引的第一个列（最左边的列）时，才能有效地利用该索引。例如，对于 `idx_lastname_firstname` 索引：
    - `WHERE last_name = 'Smith'` -> **能**使用索引。
    - `WHERE last_name = 'Smith' AND first_name = 'Alice'` -> **能**使用索引。
    - `WHERE first_name = 'Alice'` -> **不能**有效使用索引，因为没有使用最左边的 `last_name` 列。

- **主键索引 (Primary Key)**:
  - 一种特殊的唯一索引，不允许有 `NULL` 值。
  - 每个表只能有一个主键。
  - `PRIMARY KEY (id)`

- **唯一索引 (Unique Index)**:
  - 保证索引列中的所有值都是唯一的（`NULL` 值除外，`NULL` 可以出现多次）。
  - `UNIQUE INDEX idx_email ON employees (email);`

### 2. 哈希索引 (Hash Index)

- 只在 `Memory` 存储引擎中显式支持。
- 基于哈希表实现，只适用于精确匹配（`=` 或 `<=>`）的查询，不支持范围查询（如 `>`、`<`、`BETWEEN`）。
- 查询速度非常快，时间复杂度为 O(1)。

### 3. 全文索引 (Full-text Index)

- 用于在文本数据（`CHAR`, `VARCHAR`, `TEXT`）上进行全文搜索。
- 它可以查找单词或短语，而不仅仅是精确的字符串匹配。
- 使用 `MATCH() ... AGAINST()` 语法进行查询。
- 在 `MyISAM` 和 `InnoDB` (MySQL 5.6+) 中支持。
  ```sql
  CREATE FULLTEXT INDEX idx_article_content ON articles (content);

  -- 查询包含 'database' 或 'performance' 的文章
  SELECT * FROM articles WHERE MATCH(content) AGAINST('database performance');
  ```

### 4. 空间索引 (Spatial Index)

- 用于地理空间数据类型（如 `GEOMETRY`）。
- 允许你对地理空间数据执行高效的查询，如查找某个点附近的区域。

## 何时创建索引？

创建正确的索引是性能优化的关键，但滥用索引则会适得其反。

**应该创建索引的场景**:
1.  **`WHERE` 子句中频繁使用的列**: 这是最需要创建索引的地方。
2.  **`JOIN` 操作中的连接列**: 在 `ON` 子句中使用的列（通常是外键）上创建索引，可以极大地提高连接查询的性能。
3.  **`ORDER BY` 子句中使用的列**: 在排序列上创建索引可以避免数据库进行昂贵的"文件排序"操作。
4.  **`GROUP BY` 子句中使用的列**: 有助于分组操作。

**不应该创建索引的场景**:
1.  **频繁更新的列**: 每次更新都会导致索引的重建，增加开销。
2.  **基数（Cardinality）非常低的列**: 基数指的是列中唯一值的数量。如果一个列只有很少的几个值（如"性别"列，只有 '男'、'女'），索引的选择性就很差，数据库引擎可能宁愿选择全表扫描。
3.  **小型表**: 对于只有几百行的小型表，全表扫描的速度可能比使用索引更快。

## 如何查看查询是否使用了索引？

`EXPLAIN` 命令是你的好朋友。将它放在 `SELECT` 语句前面，MySQL 会返回它将如何执行这个查询的计划，而不是真正执行它。

```sql
EXPLAIN SELECT * FROM employees WHERE last_name = 'Smith';
```

在 `EXPLAIN` 的输出中，你需要关注以下几列：
- **`type`**: 显示了连接类型。`const`, `eq_ref`, `ref`, `range` 都是比较好的类型，表示使用了索引。`index` 表示索引扫描，`ALL` 表示全表扫描，是性能最差的情况，应尽量避免。
- **`key`**: 显示实际决定使用的索引。如果为 `NULL`，则表示没有使用索引。
- **`rows`**: 估计需要扫描的行数。这个数字越小越好。
- **`Extra`**: 包含额外信息。`Using index` 是一个好信号，表示查询可以直接从索引中获取所有需要的数据（覆盖索引），而无需访问表。`Using filesort` 表示需要进行外部排序，通常可以通过在排序列上加索引来优化。

## 管理索引

- **创建索引**:
  ```sql
  CREATE INDEX index_name ON table_name (column1, column2, ...);
  ALTER TABLE table_name ADD INDEX index_name (column1, ...);
  ```
- **查看索引**:
  ```sql
  SHOW INDEX FROM table_name;
  ```
- **删除索引**:
  ```sql
  DROP INDEX index_name ON table_name;
  ALTER TABLE table_name DROP INDEX index_name;
  ```

正确地设计和使用索引是一门艺术，需要对数据和查询模式有深入的理解。通过 `EXPLAIN` 不断地测试和调整，是通往高性能查询的必经之路。 