# MongoDB 聚合框架 (Aggregation Framework)

MongoDB 的聚合框架是一个强大的数据处理工具，它允许你对集合中的数据进行一系列的转换和计算，最终返回一个计算后的结果。这类似于 SQL 中的 `GROUP BY`、`JOIN` 和聚合函数（如 `SUM`, `AVG`）的组合，但功能远比此强大和灵活。

## 什么是聚合管道 (Aggregation Pipeline)？

聚合框架的核心是**管道（Pipeline）**的概念。一个聚合管道由一个或多个**阶段（Stage）**组成。每个阶段都会对输入的文档流进行某种操作，然后将结果作为输出传递给下一个阶段。

**数据流**：
`Collection -> Stage 1 -> Stage 2 -> Stage 3 -> ... -> Result`

**语法**：
`db.collection.aggregate([ <stage1>, <stage2>, ... ])`

---

## 常用聚合阶段 (Common Stages)

我们将使用一个 `orders` 集合进行演示：
```javascript
db.orders.insertMany([
  { _id: 1, cust_id: "A123", amount: 500, status: "A", items: ["apple", "banana"] },
  { _id: 2, cust_id: "A123", amount: 250, status: "A", items: ["orange"] },
  { _id: 3, cust_id: "B456", amount: 200, status: "A", items: ["apple", "grape"] },
  { _id: 4, cust_id: "A123", amount: 300, status: "D", items: ["cherry"] },
  { _id: 5, cust_id: "C789", amount: 150, status: "A", items: ["banana", "orange"] },
  { _id: 6, cust_id: "B456", amount: 75, status: "D", items: ["grape"] }
]);
```

### `$match`
**功能**：筛选文档。和 `find()` 方法一样，它使用标准的 MongoDB 查询语法。
**作用**：通常建议将 `$match` 放在管道的**最前面**，以便尽早地过滤掉不需要的文档，减少后续阶段的处理量。如果 `$match` 使用了索引，性能会更高。

**示例**：只处理状态为 "A" 的订单。
```javascript
db.orders.aggregate([
  { $match: { status: "A" } }
])
```

### `$group`
**功能**：根据指定的**分组键 (`_id`)** 对文档进行分组，并对每个分组执行聚合计算。
**作用**：这是聚合框架的核心，用于汇总数据。

**语法**：`{ $group: { _id: <expression>, <field1>: { <accumulator1>: <expression1> }, ... } }`
- `_id`: 定义分组的依据。可以是单个字段 (`"$cust_id"`)、一个常量 (`null` 表示对所有文档进行分组)，或一个复合文档。
- `<accumulator>`: 聚合操作符，如 `$sum`, `$avg`, `$min`, `$max`, `$push` 等。

**示例**：计算每个客户 (`cust_id`) 的总订单金额 (`totalAmount`) 和订单数量 (`orderCount`)。
```javascript
db.orders.aggregate([
  { $match: { status: "A" } },
  {
    $group: {
      _id: "$cust_id", // 按 cust_id 字段分组
      totalAmount: { $sum: "$amount" }, // 计算每个组的 amount 总和
      orderCount: { $sum: 1 } // 每个文档计为 1，累加得到数量
    }
  }
])
```
**结果**：
```json
[
  { "_id": "A123", "totalAmount": 750, "orderCount": 2 },
  { "_id": "C789", "totalAmount": 150, "orderCount": 1 },
  { "_id": "B456", "totalAmount": 200, "orderCount": 1 }
]
```

### `$project`
**功能**：重塑文档。用于包含、排除、重命名字段，或者通过计算创建新字段。
**作用**：控制输出文档的结构。

**示例**：在上面的结果基础上，将 `_id` 重命名为 `customer`，并新增一个 `averageAmount` 字段。
```javascript
db.orders.aggregate([
  { $match: { status: "A" } },
  {
    $group: {
      _id: "$cust_id",
      totalAmount: { $sum: "$amount" },
      orderCount: { $sum: 1 }
    }
  },
  {
    $project: {
      _id: 0, // 排除默认的 _id 字段
      customer: "$_id", // 将 _id 字段重命名为 customer
      totalAmount: 1, // 保留 totalAmount 字段
      averageAmount: { $divide: ["$totalAmount", "$orderCount"] } // 计算平均金额
    }
  }
])
```

### `$sort`
**功能**：根据指定字段对文档进行排序。
**作用**：控制输出结果的顺序。

**示例**：按总金额降序排列。
```javascript
db.orders.aggregate([
  // ... (match, group, project stages) ...
  { $sort: { totalAmount: -1 } } // -1 表示降序, 1 表示升序
])
```

### `$limit` 和 `$skip`
- `$limit`: 限制传递给下一阶段的文档数量。
- `$skip`: 跳过指定数量的文档。
**作用**：通常用于分页或获取 Top N 结果。

**示例**：获取总金额最高的前两位客户。
```javascript
db.orders.aggregate([
  // ... (match, group, project, sort stages) ...
  { $limit: 2 }
])
```

### `$unwind`
**功能**：**解构**数组字段。如果一个文档的数组字段包含 N 个元素，`$unwind` 会将该文档复制 N 份，每一份中的该字段都只包含数组的一个元素。
**作用**：将数组元素作为独立的文档进行处理，通常用于后续的 `$group` 操作。

**示例**：统计每种商品 (`items`) 出现的次数。
```javascript
db.orders.aggregate([
  { $match: { status: "A" } },
  { $unwind: "$items" }, // 将 items 数组拆分
  // 经过 $unwind 后，文档流会变成：
  // { _id: 1, ..., items: "apple" }
  // { _id: 1, ..., items: "banana" }
  // ...
  {
    $group: {
      _id: "$items", // 按拆分后的 items 字段分组
      count: { $sum: 1 }
    }
  },
  { $sort: { count: -1 } }
])
```

### `$lookup`
**功能**：实现**左外连接 (Left Outer Join)**。可以从另一个集合中查找匹配的文档，并将其合并到当前文档流中。
**作用**：关联不同集合的数据。

**示例**：假设我们有一个 `customers` 集合：
`db.customers.insertOne({ _id: "A123", name: "Alice" })`

将客户信息合并到订单中：
```javascript
db.orders.aggregate([
   { $match: { _id: 1 } },
   {
     $lookup: {
       from: "customers", // 要连接的目标集合
       localField: "cust_id", // 输入文档中的连接字段
       foreignField: "_id", // 目标集合中的连接字段
       as: "customer_info" // 输出的数组字段名
     }
   }
])
```
**结果**：
```json
{
  "_id": 1,
  "cust_id": "A123",
  "amount": 500,
  "status": "A",
  "items": ["apple", "banana"],
  "customer_info": [ // as 定义的字段
    { "_id": "A123", "name": "Alice" }
  ]
}
```

## 聚合管道优化

-   **尽早 `$match`**：将 `$match` 放在管道的最开始，如果能利用索引，效果最好。
-   **尽早 `$project`**：如果在后续阶段不再需要某些字段，可以提前用 `$project` 将它们移除，减少内存占用。
-   **注意 `$unwind` 和 `$sort` 的顺序**：如果在大数据集上先 `$unwind` 再 `$sort`，可能会消耗大量内存。考虑是否能先对部分数据排序或筛选。

聚合框架是 MongoDB 中一个极其强大的工具，掌握它可以帮助你完成复杂的数据分析和转换任务。 