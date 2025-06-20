# MongoDB 高级查询与投影

在掌握了基本的 CRUD 操作后，下一步是学习 MongoDB 强大的查询功能，以便更精确、更高效地从集合中检索数据。本章将重点介绍高级查询操作符和投影（Projection）的用法。

## 目录
- [查询操作符](#查询操作符)
  - [比较操作符](#比较操作符)
  - [逻辑操作符](#逻辑操作符)
  - [元素操作符](#元素操作符)
  - [求值操作符](#求值操作符)
  - [数组操作符](#数组操作符)
- [投影 (Projection)](#投影-projection)
  - [包含特定字段](#包含特定字段)
  - [排除特定字段](#排除特定字段)
  - [对数组进行投影](#对数组进行投影)

---

## 查询操作符

查询操作符以美元符号 `$` 开头，它们提供了超越简单键值匹配的复杂查询能力。

### 比较操作符

这些操作符用于比较字段的值。

-   `$eq` (Equal): 等于
-   `$ne` (Not Equal): 不等于
-   `$gt` (Greater Than): 大于
-   `$gte` (Greater Than or Equal): 大于等于
-   `$lt` (Less Than): 小于
-   `$lte` (Less Than or Equal): 小于等于
-   `$in`: 字段值在指定的数组中
-   `$nin`: 字段值不在指定的数组中

**示例**：查找 `inventory` 集合中，数量 (`qty`) 大于等于 20 且小于等于 50 的文档。
```javascript
db.inventory.find({ qty: { $gte: 20, $lte: 50 } })
```

**示例**：查找 `status` 为 "A" 或 "D" 的文档。
```javascript
db.inventory.find({ status: { $in: [ "A", "D" ] } })
```

### 逻辑操作符

这些操作符用于组合多个查询条件。

-   `$and`: 逻辑 "与"。连接多个查询子句，所有子句都必须为真。
-   `$or`: 逻辑 "或"。连接多个查询子句，至少一个子句为真即可。
-   `$nor`: 逻辑 "非或"。连接多个查询子句，所有子句都必须为假。
-   `$not`: 逻辑 "非"。反转指定操作符的查询结果。

**注意**：对于简单的 "与" 操作，通常不需要明确使用 `$and`。直接在查询文档中并列多个字段即可，例如 `db.inventory.find({ status: "A", qty: { $lt: 30 } })`。

**示例**：查找 `status` 为 "A" **或者** `qty` 小于 30 的文档。
```javascript
db.inventory.find({
  $or: [
    { status: "A" },
    { qty: { $lt: 30 } }
  ]
})
```

**示例**：查找 `price` 不大于 1.99 的文档。
```javascript
db.inventory.find({ price: { $not: { $gt: 1.99 } } })
```

### 元素操作符

-   `$exists`: 检查文档中是否存在某个字段。
-   `$type`: 检查字段的数据类型。

**示例**：查找所有**不包含** `qty` 字段的文档。
```javascript
db.inventory.find({ qty: { $exists: false } })
```

**示例**：查找 `price` 字段类型为 "double" (BSON 类型代码为 1) 的文档。
```javascript
db.inventory.find({ price: { $type: "double" } })
// 或者使用 BSON 类型代码
db.inventory.find({ price: { $type: 1 } })
```

### 求值操作符

-   `$regex`: 使用正则表达式进行模式匹配。
-   `$where`: 使用 JavaScript 表达式作为查询条件（性能较低，谨慎使用）。

**示例**：查找 `item` 字段以 "s" 开头的文档。
```javascript
db.inventory.find({ item: { $regex: /^s/ } })
```

### 数组操作符

-   `$all`: 匹配数组字段中包含所有指定元素的文档。
-   `$elemMatch`: 对数组中的**单个内嵌文档**应用多个查询条件。
-   `$size`: 匹配特定长度的数组。

**示例**：查找 `tags` 数组中既包含 "red" 又包含 "blank" 的文档。
```javascript
db.inventory.find({ tags: { $all: ["red", "blank"] } })
```

**示例**：查找 `results` 数组中**存在至少一个元素**，该元素的分数 (`score`) 大于等于 80 **且**小于 85。
```javascript
// $elemMatch 确保两个条件作用在同一个数组元素上
db.survey.find({
  results: {
    $elemMatch: { score: { $gte: 80 }, score: { $lt: 85 } }
  }
})
```

---

## 投影 (Projection)

投影是查询中的第二个参数，用于指定查询结果中应该返回哪些字段。这对于节省网络带宽和减少客户端处理开销非常重要。

### 包含特定字段

在投影文档中，将需要返回的字段设置为 `1` 或 `true`。`_id` 字段默认总是会被返回。

**示例**：只返回 `item` 和 `status` 字段。
```javascript
db.inventory.find(
  { status: "A" },
  { item: 1, status: 1 } // 投影文档
)
// _id 字段默认会返回
```

如果要**抑制 `_id` 字段**的返回，需要显式地将其设置为 `0`。
```javascript
db.inventory.find(
  { status: "A" },
  { item: 1, status: 1, _id: 0 }
)
```

### 排除特定字段

将需要排除的字段设置为 `0` 或 `false`。

**示例**：返回除了 `status` 和 `instock` 之外的所有字段。
```javascript
db.inventory.find(
  { status: "A" },
  { status: 0, instock: 0 }
)
```
**重要限制**：不能在同一个投影文档中混合使用包含（`1`）和排除（`0`）操作。唯一的例外是 `_id` 字段。

### 对数组进行投影

MongoDB 提供了几个操作符来对数组字段进行精细的投影控制。

-   `$elemMatch`: 返回数组中第一个匹配查询条件的元素。
-   `$slice`: 返回数组的一个子集（切片）。

**示例**：对于每个匹配的文档，只返回 `instock` 数组中第一个 `qty` 等于 5 的元素。
```javascript
db.inventory.find(
  {},
  {
    instock: { $elemMatch: { qty: 5 } }
  }
)
```

**示例**：只返回 `comments` 数组的最后 5 个元素。
```javascript
db.inventory.find(
  {},
  { comments: { $slice: -5 } }
)
```

通过组合使用这些高级查询操作符和投影，您可以构建出非常强大和精确的数据检索逻辑，从而满足各种复杂的业务需求。 