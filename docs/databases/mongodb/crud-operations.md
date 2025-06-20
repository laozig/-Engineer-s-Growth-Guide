# MongoDB CRUD 操作：增删改查

CRUD (Create, Read, Update, Delete) 是数据库操作的核心。本指南将详细介绍如何在 MongoDB 中使用 `mongosh` 执行这些基本操作。我们将使用一个名为 `users` 的集合作为示例。

## 目录
- [准备工作：连接与数据](#准备工作连接与数据)
- [Create (创建/插入)](#create-创建插入)
  - [`insertOne()`](#insertone)
  - [`insertMany()`](#insertmany)
- [Read (读取/查询)](#read-读取查询)
  - [`find()`](#find)
  - [指定查询条件](#指定查询条件)
  - [使用查询操作符](#使用查询操作符)
  - [`findOne()`](#findone)
- [Update (更新)](#update-更新)
  - [`updateOne()`](#updateone)
  - [`updateMany()`](#updatemany)
  - [`replaceOne()`](#replaceone)
- [Delete (删除)](#delete-删除)
  - [`deleteOne()`](#deleteone)
  - [`deleteMany()`](#deletemany)

---

## 准备工作：连接与数据

首先，启动 `mongosh` 并连接到你的 MongoDB 实例。我们将使用一个名为 `practiceDB` 的数据库。

```javascript
// 启动 mongosh
// > mongosh

// 切换到 practiceDB 数据库
> use practiceDB

// 清理旧数据以便于演示
> db.users.deleteMany({})
```

## Create (创建/插入)

### `insertOne()`
用于向集合中插入单个文档。

**语法**：`db.collection.insertOne(document)`

**示例**：
```javascript
> db.users.insertOne({
    name: "Alice",
    age: 28,
    email: "alice@example.com",
    tags: ["developer", "mongodb"],
    join_date: new Date()
})
```
如果成功，会返回一个包含 `acknowledged: true` 和新文档的 `insertedId` 的对象。

### `insertMany()`
用于向集合中插入一个或多个文档（以数组形式提供）。

**语法**：`db.collection.insertMany([document1, document2, ...])`

**示例**：
```javascript
> db.users.insertMany([
    { name: "Bob", age: 35, email: "bob@example.com", tags: ["manager", "sql"] },
    { name: "Charlie", age: 28, email: "charlie@example.com", tags: ["developer", "react"] },
    { name: "Diana", age: 42, email: "diana@example.com", tags: ["designer"] }
])
```
如果成功，会返回一个包含 `acknowledged: true` 和新文档的 `insertedIds` 数组的对象。

---

## Read (读取/查询)

### `find()`
用于查询集合中符合条件的多个文档。

**语法**：`db.collection.find(query, projection)`
- `query` (可选): 查询条件文档。如果省略或传入 `{}`，则匹配所有文档。
- `projection` (可选): 指定返回文档中应包含或排除的字段。

**示例：查询所有用户**
```javascript
> db.users.find()
```
这会返回 `users` 集合中的所有文档。可以添加 `.pretty()` 使输出格式化，更易于阅读。
`> db.users.find().pretty()`

### 指定查询条件

**示例：查询年龄为 28 的所有用户**
```javascript
> db.users.find({ age: 28 })
```

**示例：查询名字为 "Bob" 的用户**
```javascript
> db.users.find({ name: "Bob" })
```

**示例：查询 tags 数组中包含 "developer" 的用户**
```javascript
> db.users.find({ tags: "developer" })
```

### 使用查询操作符

MongoDB 提供了丰富的查询操作符，通常以 `$` 开头。

- **`$gt`** (greater than - 大于), **`$lt`** (less than - 小于)
  **示例：查询年龄大于 30 的用户**
  ```javascript
  > db.users.find({ age: { $gt: 30 } })
  ```

- **`$in`** (in - 在数组中)
  **示例：查询名字是 "Alice" 或 "Diana" 的用户**
  ```javascript
  > db.users.find({ name: { $in: ["Alice", "Diana"] } })
  ```

- **`$and`** (逻辑与 - 默认行为), **`$or`** (逻辑或)
  **示例：查询年龄大于 30 并且是 `manager` 的用户** (隐式 AND)
  ```javascript
  > db.users.find({ age: { $gt: 30 }, tags: "manager" })
  ```
  **示例：查询年龄小于 30 或大于 40 的用户** (显式 OR)
  ```javascript
  > db.users.find({ $or: [ { age: { $lt: 30 } }, { age: { $gt: 40 } } ] })
  ```

### `findOne()`
只返回符合条件的第一个文档。如果找不到，则返回 `null`。

**语法**：`db.collection.findOne(query, projection)`

**示例：查找一个年龄为 28 的用户**
```javascript
> db.users.findOne({ age: 28 })
```

---

## Update (更新)

更新操作同样需要一个**查询条件**来定位要更新的文档，以及一个**更新文档**来描述如何修改。

### `updateOne()`
更新符合条件的第一个文档。

**语法**：`db.collection.updateOne(filter, update, options)`

**更新操作符 (`$set`, `$inc`, `$push` 等) 是必需的。**
- **`$set`**: 设置字段的值。
  **示例：更新 Alice 的年龄为 29**
  ```javascript
  > db.users.updateOne(
      { name: "Alice" },
      { $set: { age: 29 } }
  )
  ```
- **`$inc`**: 增加字段的值。
  **示例：将 Bob 的年龄增加 1 岁**
  ```javascript
  > db.users.updateOne(
      { name: "Bob" },
      { $inc: { age: 1 } }
  )
  ```
- **`$push`**: 向数组中添加一个元素。
  **示例：为 Charlie 添加一个新标签 "mongodb"**
  ```javascript
  > db.users.updateOne(
      { name: "Charlie" },
      { $push: { tags: "mongodb" } }
  )
  ```

### `updateMany()`
更新所有符合条件的文档。

**语法**：`db.collection.updateMany(filter, update, options)`

**示例：为所有 `developer` 添加一个 "active" 状态字段**
```javascript
> db.users.updateMany(
    { tags: "developer" },
    { $set: { status: "active" } }
)
```

### `replaceOne()`
用一个新的文档完全替换掉符合条件的第一个文档。

**示例：用一个新文档替换 Diana 的记录**
```javascript
> db.users.replaceOne(
    { name: "Diana" },
    { name: "Diana Prince", role: "hero", from: "Themyscira" }
)
```
**注意**：`replaceOne` 会删除所有旧字段（`_id` 除外）。

---

## Delete (删除)

### `deleteOne()`
删除符合条件的第一个文档。

**语法**：`db.collection.deleteOne(filter)`

**示例：删除名为 "Bob" 的用户**
```javascript
> db.users.deleteOne({ name: "Bob" })
```

### `deleteMany()`
删除所有符合条件的文档。

**语法**：`db.collection.deleteMany(filter)`

**示例：删除所有年龄大于 40 的用户**
```javascript
> db.users.deleteMany({ age: { $gt: 40 } })
```

**要删除一个集合中的所有文档，可以传入一个空文档 `{}` 作为查询条件：**
```javascript
> db.users.deleteMany({})
```
这会清空 `users` 集合，但集合本身和它的索引依然存在。 