# MongoDB 查询性能分析 (`explain()`)

`explain()` 是 MongoDB 中一个至关重要的诊断工具。它能够提供关于查询执行过程的详细信息，帮助开发者和 DBA 理解查询是如何运行的，是否有效地使用了索引，以及性能瓶颈在哪里。

## `explain()` 的基本用法

`explain()` 方法可以附加在 `find()`, `update()`, `remove()`, `aggregate()` 等多种操作之后。

**语法**:
```javascript
db.collection.find(<query>).explain(<verbosityMode>)
```

### 执行模式 (Verbosity Modes)

`explain()` 接受一个可选的 "verbosity" 参数，用于控制输出的详细程度：

1.  **`"queryPlanner"` (默认模式)**
    -   只提供查询计划器的信息，显示 MongoDB 对查询评估后选择的获胜计划（winning plan）以及被拒绝的候选计划（rejected plans）。
    -   这是最常用的模式，用于快速判断查询是否使用了正确的索引。

2.  **`"executionStats"`**
    -   在 `"queryPlanner"` 的基础上，会**实际执行**查询（或一个部分样本），并返回获胜计划的执行统计信息。
    -   这是最详尽的分析模式，提供了诸如实际执行时间、返回的文档数、扫描的索引键数量等关键性能指标。

3.  **`"allPlansExecution"`**
    -   最为详尽的模式，它会执行并返回所有候选计划（包括获胜和被拒绝的）的执行统计信息。
    -   这个模式用于对不同索引策略进行深度比较，但因为它会执行多个计划，所以开销最大。

**建议**：从 `"queryPlanner"` 开始，如果需要更深入的性能数据，再使用 `"executionStats"`。

---

## 解读 `explain()` 的输出

我们将使用一个 `users` 集合进行演示，假设已在 `age` 和 `email` 字段上创建了索引。
`db.users.createIndex({ age: 1 })`
`db.users.createIndex({ email: 1 })`

**查询示例**:
```javascript
db.users.find({ age: { $gt: 30 }, email: "test@example.com" }).explain("executionStats")
```
`explain()` 的输出是一个复杂的 JSON 文档。我们需要关注其中的几个关键部分。

### `queryPlanner`

这部分描述了查询计划器是如何选择执行计划的。

-   **`winningPlan`**: 查询优化器选择的、用于执行查询的最佳计划。
-   **`rejectedPlans`**: 其他被考虑过但最终被拒绝的计划。

在 `winningPlan` 内部，你需要关注**执行阶段 (stages)**。一个计划是由多个阶段组成的树状结构。

#### 关键的执行阶段 (Stages)

-   **`COLLSCAN` (Collection Scan)**
    -   **含义**：全集合扫描。这是最坏的情况，意味着 MongoDB 必须逐个检查集合中的所有文档来找到匹配项。
    -   **诊断**：如果看到 `COLLSCAN`，通常表示你的查询没有利用到任何索引，需要立即优化（例如，为查询的字段添加索引）。

-   **`IXSCAN` (Index Scan)**
    -   **含义**：索引扫描。这是一个好的迹象，表示查询正在使用索引来定位文档。
    -   **诊断**：你需要进一步查看 `executionStats` 来确认索引扫描的效率。

-   **`FETCH`**
    -   **含义**：根据索引条目中的指针，去磁盘（或内存）中读取完整的文档。
    -   **诊断**：如果一个查询是**覆盖查询 (Covered Query)**，那么它的计划中将不会有 `FETCH` 阶段，因为所有需要的数据都已在索引中。没有 `FETCH` 是最高效的。

-   **`SORT`**
    -   **含义**：在内存中进行排序。
    -   **诊断**：如果 MongoDB 无法利用索引来进行排序，它就必须在内存中执行排序操作（`SORT` 阶段）。这可能会消耗大量内存，特别是对于大数据集。如果看到 `SORT`，应考虑创建能够支持排序的复合索引。

### `executionStats`

这部分提供了获胜计划在实际执行时的详细统计数据。

#### 关键的执行统计指标

-   **`executionSuccess`**: `true` 表示执行成功。
-   **`nReturned`**: 查询返回的文档数量。
-   **`executionTimeMillis`**: 查询的总执行时间（毫秒）。这是衡量性能最直观的指标。
-   **`totalKeysExamined`**: 扫描的**索引键**总数。
-   **`totalDocsExamined`**: 扫描的**文档**总数。

#### 理想的查询性能指标

一个高效的查询应该具备以下特征：

1.  **`totalKeysExamined` 约等于 `nReturned`**
    -   这意味着索引的效率非常高，扫描的每个索引键都对应一个最终结果。

2.  **`totalDocsExamined` 约等于 `nReturned`**
    -   这意味着 MongoDB 读取的每个文档都是最终结果的一部分，没有做多余的文档扫描。

3.  **`executionTimeMillis` 尽可能低**。

#### 不理想的查询性能指标

1.  **`totalDocsExamined` 远大于 `nReturned`**
    -   **问题**：这表明索引的选择性（selectivity）很差。MongoDB 使用索引找到了大量的候选文档，但之后不得不逐个检查它们，并丢弃大部分不符合查询条件的文档。
    -   **解决方案**：考虑创建一个更具选择性的复合索引。

2.  **`totalKeysExamined` 远大于 `nReturned`**
    -   **问题**：与上面类似，索引的选择性不高。
    -   **解决方案**：同上。

3.  **`winningPlan` 中出现 `COLLSCAN`**
    -   **问题**：查询没有使用索引。
    -   **解决方案**：为查询谓词中的字段添加索引。

4.  **`winningPlan` 中出现 `SORT` 阶段**
    -   **问题**：排序无法通过索引完成，需要消耗大量内存和 CPU。
    -   **解决方案**：创建能够覆盖排序字段的复合索引。

## 实践案例

**场景**：分析查询 `db.users.find({ status: "active" }).sort({ last_login: -1 })`

1.  **初次分析**: `...explain("executionStats")`
    -   **结果**：发现 `winningPlan` 是 `COLLSCAN`，然后是一个 `SORT` 阶段。`executionTimeMillis` 很高。
    -   **诊断**：查询没有使用索引，并且在内存中进行了代价高昂的排序。

2.  **优化尝试 1**: 创建单字段索引 `db.users.createIndex({ status: 1 })`
    -   **再次分析**：`winningPlan` 变成了 `IXSCAN` (在 `status` 索引上) + `FETCH` + `SORT`。
    -   **诊断**：`IXSCAN` 避免了全表扫描，但排序问题依然存在。

3.  **优化尝试 2**: 创建复合索引 `db.users.createIndex({ status: 1, last_login: -1 })`
    -   **再次分析**：`winningPlan` 变成了 `IXSCAN` (在复合索引上) + `FETCH`。`SORT` 阶段消失了！
    -   **诊断**：查询现在非常高效。它使用复合索引来筛选 `status`，并且直接从索引中按 `last_login` 的顺序获取数据，避免了内存排序。`executionTimeMillis` 大幅下降。

通过 `explain()`，你可以系统性地诊断和优化查询，这是 MongoDB 性能调优的必备技能。 