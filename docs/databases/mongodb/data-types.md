# MongoDB 数据类型与 `$type` 操作符

MongoDB (BSON) 支持比 JSON 更丰富的数据类型。理解这些数据类型对于有效的数据建模和查询至关重要。`$type` 操作符允许我们根据字段的数据类型来查询文档。

## BSON 数据类型

下表列出了 MongoDB 中常用的一些 BSON 数据类型，以及它们在 `mongosh` 中的表示和对应的数字/字符串别名（用于 `$type` 查询）。

| 数据类型         | 数字别名 | 字符串别名      | 示例 (`mongosh`) |
| :--------------- | :------- | :-------------- | :---------------------------------- |
| **Double**       | 1        | `"double"`      | `10.5` |
| **String**       | 2        | `"string"`      | `"Hello, MongoDB"` |
| **Object**       | 3        | `"object"`      | `{ "a": 1, "b": 2 }` |
| **Array**        | 4        | `"array"`       | `[1, "two", 3.0]` |
| **Binary data**  | 5        | `"binData"`     | `BinData(0, "SGVsbG8=")` |
| **ObjectId**     | 7        | `"objectId"`    | `ObjectId()` |
| **Boolean**      | 8        | `"bool"`        | `true` or `false` |
| **Date**         | 9        | `"date"`        | `new Date()` or `ISODate()` |
| **Null**         | 10       | `"null"`        | `null` |
| **32-bit integer** | 16       | `"int"`         | `NumberInt("10")` |
| **64-bit integer** | 18       | `"long"`        | `NumberLong("100")` |
| **Decimal128**   | 19       | `"decimal"`     | `NumberDecimal("10.99")` |
| **Timestamp**    | 17       | `"timestamp"`   | `Timestamp(1667208000, 1)` |


**注意：**
- 在 `mongosh` 中，所有数字默认被视为 `Double` 类型。要显式指定整数或长整数类型，需要使用 `NumberInt()` 或 `NumberLong()`。
- `Decimal128` 是用于高精度计算的十进制浮点类型，非常适合金融、科学计算等场景。

## `db.collection.find()` 中的 `$type` 操作符

`$type` 操作符用于筛选出字段值为特定 BSON 类型的文档。

**语法**：`db.collection.find({ field: { $type: <BSON type> } })`

`<BSON type>` 可以是上表中的**数字别名**或**字符串别名**。推荐使用字符串别名，因为可读性更好。

---

### `$type` 查询示例

假设我们有一个 `inventory` 集合，包含以下文档：
```javascript
db.inventory.insertMany([
  { item: "journal", qty: 25, price: 10.99 },
  { item: "notebook", qty: NumberInt(50), price: "8.50" },
  { item: "paper", qty: NumberLong(100), tags: ["office", "school"] },
  { item: "planner", price: NumberDecimal("25.00"), stock_date: new Date() },
  { item: "postcard", in_stock: true, notes: null }
])
```

**1. 查询 `price` 字段为 `string` 类型的文档**
```javascript
// 使用字符串别名 (推荐)
db.inventory.find({ price: { $type: "string" } })

// 使用数字别名
db.inventory.find({ price: { $type: 2 } })
```
**结果**：
```json
{ "_id": ..., "item": "notebook", "qty": 50, "price": "8.50" }
```

**2. 查询 `price` 字段为数值类型 (Double 或 Decimal) 的文档**

`$type` 接受一个类型别名数组，可以同时匹配多种类型。
```javascript
db.inventory.find({ price: { $type: ["double", "decimal"] } })
```
**结果**：
```json
{ "_id": ..., "item": "journal", "qty": 25, "price": 10.99 }
{ "_id": ..., "item": "planner", "price": NumberDecimal("25.00"), ... }
```

**3. 查询 `qty` 字段为 `int` 或 `long` 类型的文档**
```javascript
db.inventory.find({ qty: { $type: ["int", "long"] } })
```
**结果**：
```json
{ "_id": ..., "item": "notebook", "qty": 50, "price": "8.50" }
{ "_id": ..., "item": "paper", "qty": NumberLong(100), ... }
```

**4. 查询字段存在的各种情况**

- **查询 `tags` 字段存在的文档**：
  ```javascript
  db.inventory.find({ tags: { $exists: true } })
  ```

- **查询 `notes` 字段值为 `null` 的文档**：
  这会同时匹配值为 `null` 或**字段不存在**的文档。
  ```javascript
  db.inventory.find({ notes: null })
  ```

- **精确查询 `notes` 字段值为 `null` 类型的文档**：
  如果你只想找值为 `null` 的，而不是那些不存在该字段的文档，需要结合 `$type` 和 `$eq`。
  ```javascript
  db.inventory.find({ notes: { $type: "null" } })
  // 或者
  db.inventory.find({ notes: { $type: 10 } })
  ```
  **结果**：
  ```json
  { "_id": ..., "item": "postcard", "in_stock": true, "notes": null }
  ```

## 聚合管道中的 `$type`

`$type` 也可以在聚合框架中使用，作为聚合操作符。

**语法**：`{ $type: <expression> }`

它返回表达式对应值的 BSON 类型字符串。

**示例**：
创建一个新字段 `price_type` 来显示 `price` 字段的类型。
```javascript
db.inventory.aggregate([
  {
    $project: {
      item: 1,
      price: 1,
      price_type: { $type: "$price" }
    }
  }
])
```
**结果**：
```json
[
  { "_id": ..., "item": "journal", "price": 10.99, "price_type": "double" },
  { "_id": ..., "item": "notebook", "price": "8.50", "price_type": "string" },
  { "_id": ..., "item": "paper", "price_type": "missing" }, // price 字段不存在
  { "_id": ..., "item": "planner", "price": NumberDecimal("25.00"), "price_type": "decimal" },
  { "_id": ..., "item": "postcard", "price_type": "missing" }
]
```

掌握 MongoDB 的数据类型和 `$type` 操作符，对于处理异构数据和保证数据质量非常有帮助。 