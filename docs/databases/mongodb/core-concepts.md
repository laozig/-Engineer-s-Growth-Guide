# MongoDB 核心概念：文档、集合与 BSON

要理解 MongoDB，首先必须掌握其最基本的数据组织形式：文档（Document）、集合（Collection）以及其底层的数据格式 BSON。

## 目录
- [文档 (Document)](#文档-document)
  - [结构与示例](#结构与示例)
  - [文档的特点](#文档的特点)
- [集合 (Collection)](#集合-collection)
  - [动态模式 (Dynamic Schema)](#动态模式-dynamic-schema)
- [BSON (Binary JSON)](#bson-binary-json)
  - [为什么使用 BSON 而不是 JSON？](#为什么使用-bson-而不是-json)
- [数据库 (Database)](#数据库-database)
- [与关系型数据库的类比](#与关系型数据库的类比)
- [ObjectID](#objectid)

---

## 文档 (Document)

**文档**是 MongoDB 中数据的基本单元，其地位类似于关系型数据库中的"行"（Row）。一个文档是由多个"字段-值"对（field-value pairs）组成的有序数据结构，类似于 JSON 对象。

### 结构与示例

一个典型的 MongoDB 文档如下所示：
```json
{
  "_id": ObjectId("635f8d9a9ec4a6b4a5e3a8e1"),
  "title": "Introduction to MongoDB",
  "author": "John Doe",
  "published_date": ISODate("2023-10-27T10:00:00Z"),
  "pages": 250,
  "tags": ["NoSQL", "Database", "MongoDB"],
  "publisher": {
    "name": "Tech Books Inc.",
    "location": "New York"
  }
}
```

### 文档的特点

1.  **结构灵活**：一个集合中的文档不需要有相同的字段集合。这种灵活性使得数据模型的演变非常容易。
2.  **丰富的表现力**：字段的值可以是多种数据类型，包括字符串、数字、布尔值、日期，甚至可以是**数组**或**嵌套的子文档**（如上例中的 `publisher` 字段）。
3.  **大小限制**：单个 MongoDB 文档的最大大小为 16MB。这个限制是为了防止不良的 schema 设计（例如，无限增长的数组），并确保文档能够高效地在网络上传输和处理。

## 集合 (Collection)

**集合**是一组 MongoDB 文档的容器，其地位类似于关系型数据库中的"表"（Table）。集合存在于数据库中，并且不强制其内部的文档具有相同的结构。

### 动态模式 (Dynamic Schema)

集合的"动态模式"或"无模式"（Schemaless）是 MongoDB 的一个核心特性。这意味着：
-   你可以在向集合中插入第一个文档时隐式地创建该集合。
-   同一个集合中的两个文档可以有完全不同的字段。

**示例**：
下面这两个文档可以合法地存在于同一个名为 `products` 的集合中：
```json
// 文档 1
{
  "name": "Laptop",
  "brand": "Dell",
  "specs": { "cpu": "i7", "ram": "16GB" }
}

// 文档 2
{
  "name": "T-shirt",
  "brand": "Nike",
  "color": "Blue",
  "sizes": ["S", "M", "L"]
}
```
尽管这种灵活性很强大，但在实践中，通常一个集合内的文档会具有相似的结构。从 MongoDB 3.2 开始，引入了**模式验证（Schema Validation）**功能，允许你对集合的结构强制执行规则。

## BSON (Binary JSON)

尽管 MongoDB 的文档在形式上看起来像 JSON，但它们在数据库中是以 **BSON** 的格式存储的。BSON 是 "Binary JSON" 的缩写，是一种二进制序列化的数据格式。

### 为什么使用 BSON 而不是 JSON？

1.  **更丰富的数据类型**：BSON 在标准 JSON 的基础上增加了一些额外的数据类型，例如 `ObjectId`, `Date`, `Binary data`, `Int64` 等。这对于数据库操作至关重要。
2.  **可遍历性**：BSON 文档在设计上易于扫描和遍历。每个元素都带有长度前缀，使得数据库无需解析整个文档就能跳到指定的字段，这极大地提高了读取性能。
3.  **性能**：作为一种二进制格式，BSON 在编码和解码速度上通常比基于文本的 JSON 更快，也更节省空间（尽管不总是这样）。

## 数据库 (Database)

MongoDB 将多个集合组织在**数据库**中。一个 MongoDB 服务器实例可以承载多个独立的数据库，每个数据库都有自己的权限设置，并在磁盘上存储在不同的文件中。

一些特殊的数据库名称：
-   `admin`: 管理员数据库，用于存储用户、角色等管理信息。
-   `local`: 本地数据库，存储特定于单个服务器的数据，如复制集的 `oplog`。在复制集中，此数据库不会被复制。
-   `config`: 在分片环境中，配置数据库用于存储分片的元数据。

## 与关系型数据库的类比

为了帮助理解，下表将 MongoDB 的概念与传统 RDBMS 进行了类比：

| MongoDB        | 关系型数据库 (RDBMS) |
| :------------- | :------------------- |
| 数据库 (Database) | 数据库 (Database)  |
| **集合 (Collection)** | **表 (Table)**     |
| **文档 (Document)**   | **行 (Row)**       |
| **字段 (Field)**      | **列 (Column)**    |
- **索引 (Index)** | 索引 (Index) |
| `$lookup` (聚合操作) | `JOIN` |
| 内嵌文档 (Embedded Doc) | 一对一/一对多关系 |

## ObjectID

当你向 MongoDB 插入一个文档而没有提供 `_id` 字段时，MongoDB 会自动为你生成一个全局唯一的 `_id` 字段。这个字段的默认类型是 `ObjectId`。

一个 `ObjectId` 是一个 12 字节的值，其构成保证了在分布式系统中的高度唯一性：
-   **4 字节时间戳**：自 Unix 纪元以来的秒数。
-   **5 字节随机值**：通常是主机标识和进程 ID 的哈希。
-   **3 字节自增计数器**：在一个进程中保证唯一性。

由于时间戳是 `ObjectId` 的一部分，你可以根据 `_id` 对文档进行大致的时间排序。 