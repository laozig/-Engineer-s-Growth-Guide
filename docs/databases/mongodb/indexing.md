# MongoDB 索引策略与性能优化

索引是提升 MongoDB 查询性能最关键的手段。索引支持对查询的高效执行，使得 MongoDB 无需扫描集合中的每一个文档来找到匹配的结果。本章将深入探讨 MongoDB 的各种索引类型及其最佳实践。

## 目录
- [索引的基础](#索引的基础)
- [索引类型](#索引类型)
  - [单字段索引 (Single Field Index)](#单字段索引-single-field-index)
  - [复合索引 (Compound Index)](#复合索引-compound-index)
  - [多键索引 (Multikey Index)](#多键索引-multikey-index)
  - [文本索引 (Text Index)](#文本索引-text-index)
  - [地理空间索引 (Geospatial Index)](#地理空间索引-geospatial-index)
  - [唯一索引 (Unique Index)](#唯一索引-unique-index)
  - [TTL 索引 (Time-To-Live Index)](#ttl-索引-time-to-live-index)
- [索引属性](#索引属性)
  - [部分索引 (Partial Index)](#部分索引-partial-index)
  - [稀疏索引 (Sparse Index)](#稀疏索引-sparse-index)
- [管理索引](#管理索引)
  - [`createIndex()`](#createindex)
  - [`getIndexes()`](#getindexes)
  - [`dropIndex()`](#dropindex)
- [索引策略与最佳实践](#索引策略与最佳实践)
  - [ESR 法则 (Equality, Sort, Range)](#esr-法则-equality-sort-range)
  - [创建覆盖查询 (Covered Queries)](#创建覆盖查询-covered-queries)
  - [后台创建索引](#后台创建索引)

---

## 索引的基础

MongoDB 的索引在概念上类似于关系型数据库的索引。它们在集合级别上定义，并将索引字段的值存储在一个易于遍历的数据结构中（通常是 B-Tree）。这个数据结构包含了字段值的有序列表以及指向实际文档的指针。

当一个查询到来时，如果查询的字段上有索引，MongoDB 就可以利用索引快速定位到匹配的文档，而不是执行耗时的全集合扫描（Collection Scan）。

## 索引类型

### 单字段索引 (Single Field Index)
这是最常见的索引类型，基于单个字段的值进行索引。
- **排序顺序**：对于单字段索引，升序（`1`）或降序（`-1`）的排序并不影响查询性能，但会影响 `sort()` 操作的性能。

**示例**：在 `users` 集合的 `email` 字段上创建索引。
```javascript
db.users.createIndex({ email: 1 })
```
这个索引可以极大地加速对 `email` 字段的精确匹配和范围查询。

### 复合索引 (Compound Index)
当查询经常需要同时对多个字段进行筛选和排序时，应该使用复合索引。

**示例**：创建一个基于 `department` (升序) 和 `age` (降序) 的复合索引。
```javascript
db.users.createIndex({ department: 1, age: -1 })
```
**重要规则**：
1.  **字段顺序至关重要**：一个 `{ dept: 1, age: -1 }` 的索引，可以支持对 `dept` 的查询，也可以支持对 `dept` 和 `age` 的联合查询。但它**不能**有效地支持只对 `age` 的查询。
2.  **前缀支持**：复合索引可以支持其所有"前缀"字段的查询。例如，`{ a: 1, b: 1, c: 1 }` 的索引可以支持对 `a` 的查询，以及对 `a` 和 `b` 的查询。

### 多键索引 (Multikey Index)
当索引的字段是一个**数组**时，MongoDB 会自动创建一个多键索引。它会为数组中的**每一个元素**创建一条索引条目。

**示例**：在 `inventory` 集合的 `tags` 数组上创建索引。
```javascript
db.inventory.createIndex({ tags: 1 })
```
假设一个文档的 `tags` 是 `["red", "plain"]`，MongoDB 会为 "red" 和 "plain" 分别创建索引条目。这使得对数组元素的查询（如 `db.inventory.find({ tags: "red" })`）非常高效。

### 文本索引 (Text Index)
用于对字符串内容进行文本搜索。一个集合最多只能有一个文本索引。
-   它支持词干提取、停用词过滤和多语言搜索。
-   使用 `$text` 操作符进行查询。

**示例**：在 `articles` 集合的 `title` 和 `content` 字段上创建文本索引。
```javascript
db.articles.createIndex({ title: "text", content: "text" })

// 使用文本索引进行搜索
db.articles.find({ $text: { $search: "mongodb performance" } })
```

### 地理空间索引 (Geospatial Index)
用于高效地执行地理空间坐标数据的查询。
-   **2dsphere**：用于计算类地球球体上的几何形状（推荐）。
-   **2d**：用于在二维平面上计算距离。

### 唯一索引 (Unique Index)
确保索引字段的值在集合中是唯一的。如果尝试插入或更新一个会导致重复值的文档，操作会失败。`_id` 字段默认就有一个唯一的索引。

**示例**：确保 `email` 字段的唯一性。
```javascript
db.users.createIndex({ email: 1 }, { unique: true })
```

### TTL 索引 (Time-To-Live Index)
一种特殊的单字段索引，可以使 MongoDB 在指定的时间后自动从集合中删除文档。非常适合用于会话缓存、日志等有时效性数据的场景。
-   TTL 索引的字段必须是**日期类型**或包含日期值的数组。

**示例**：在 `sessions` 集合的 `lastAccessed` 字段上创建 TTL 索引，文档在最后访问 30 分钟后过期。
```javascript
db.sessions.createIndex({ lastAccessed: 1 }, { expireAfterSeconds: 1800 })
```

## 索引属性

### 部分索引 (Partial Index)
只对集合中满足特定筛选条件的文档创建索引。这可以减小索引的大小，降低创建和维护的开销。

**示例**：只为 `rating` 大于 8 的用户创建索引。
```javascript
db.users.createIndex(
  { email: 1 },
  { partialFilterExpression: { rating: { $gt: 8 } } }
)
```

### 稀疏索引 (Sparse Index)
只包含集合中**存在**被索引字段的文档条目。如果一个文档没有指定的字段，它就不会出现在稀疏索引中。唯一索引和稀疏索引可以结合使用，以保证字段存在时其值唯一，但允许字段不存在。

## 管理索引

### `createIndex()`
创建索引。在 MongoDB 4.2 之后，可以在前台或后台创建索引。
```javascript
db.collection.createIndex({ field: 1 }, { background: true }) // 后台创建
```

### `getIndexes()`
查看一个集合上的所有索引。
```javascript
db.collection.getIndexes()
```

### `dropIndex()`
删除一个指定的索引。
```javascript
db.collection.dropIndex("index_name") // 使用 getIndexes() 获取索引名称
```

## 索引策略与最佳实践

### ESR 法则 (Equality, Sort, Range)
设计复合索引时，一个广为流传的经验法则是遵循 ESR 顺序：
1.  **Equality (精确匹配)**：将用于精确匹配的字段放在最前面。
2.  **Sort (排序)**：其次，放置用于排序的字段。
3.  **Range (范围查询)**：最后，放置用于范围查询（如 `$gt`, `$lt`）的字段。

**示例**：对于查询 `db.users.find({ status: "active", age: { $gt: 25 } }).sort({ name: 1 })`，一个理想的索引是：
`{ status: 1, name: 1, age: 1 }`

### 创建覆盖查询 (Covered Queries)
一个查询如果能**仅通过索引**就返回所有需要的数据，而无需访问实际的文档，这个查询就被称为"覆盖查询"。这是最高效的查询类型。

**条件**：
1.  查询中涉及的所有字段，都包含在同一个索引中。
2.  查询返回的所有字段（投影），也都包含在这个索引中。
3.  查询的字段中没有一个是数组类型（多键索引不能完全覆盖）。

**示例**：
```javascript
db.users.createIndex({ department: 1, name: 1 })

// 这是一个覆盖查询
db.users.find(
  { department: "IT" },        // 查询字段在索引中
  { name: 1, _id: 0 }           // 返回字段在索引中
)
```

### 后台创建索引
在生产环境的已有大量数据的集合上创建索引时，务必使用**后台创建**模式 (`{ background: true }`)。虽然速度会慢一些，但这可以避免在创建索引期间阻塞数据库的所有其他操作。 