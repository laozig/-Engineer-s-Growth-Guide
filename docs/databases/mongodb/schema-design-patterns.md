# MongoDB 常见 Schema 设计模式

除了基本的内嵌与引用策略，MongoDB 社区还总结出了一系列行之有效的设计模式，用于解决特定的数据建模问题。这些模式可以帮助开发者构建更健壮、更可扩展、性能更好的应用。

## 目录
- [属性模式 (Attribute Pattern)](#属性模式-attribute-pattern)
- [桶模式 (Bucket Pattern)](#桶模式-bucket-pattern)
- [计算模式 (Computed Pattern)](#计算模式-computed-pattern)
- [文档版本模式 (Document Versioning Pattern)](#文档版本模式-document-versioning-pattern)
- [扩展引用模式 (Extended Reference Pattern)](#扩展引用模式-extended-reference-pattern)
- [多态模式 (Polymorphic Pattern)](#多态模式-polymorphic-pattern)
- [子集模式 (Subset Pattern)](#子集模式-subset-pattern)

---

## 属性模式 (Attribute Pattern)
**问题**：当一个集合中的文档有大量相似的字段，但这些字段的具体值在不同文档间差异很大，或者未来可能需要添加更多此类字段时，如果将它们全部作为顶级字段，会导致索引管理困难且文档结构冗长。

**解决方案**：将这些相似的属性组织成一个键值对（key-value）数组。

**示例**：一个存储不同产品规格的场景。

**反模式 (不推荐)**:
```json
{
  "product_id": "item123",
  "name": "T-Shirt",
  "size_us": "M",
  "size_eu": 40,
  "color_primary": "blue",
  "fabric_main": "cotton",
  "fabric_secondary": "polyester"
  // ... 可能还有上百个规格字段
}
```

**应用属性模式**:
```json
{
  "product_id": "item123",
  "name": "T-Shirt",
  "specs": [
    { "k": "size_us", "v": "M" },
    { "k": "size_eu", "v": 40 },
    { "k": "color", "v": "blue" },
    { "k": "fabric", "v": "cotton" }
  ]
}
```
**优点**：
-   **索引优化**：现在只需要在 `specs.k` 和 `specs.v` 上创建复合索引，就可以支持对任意规格的查询，而不是为每个可能的规格字段单独创建索引。
-   **查询简化**：查询特定属性变得更容易，例如查找所有蓝色的、M号的T恤。
-   **灵活性**：添加新的产品规格时，无需更改 schema，只需向 `specs` 数组添加新元素即可。

---

## 桶模式 (Bucket Pattern)

**问题**：对于高频率写入的场景，例如物联网（IoT）设备数据、实时分析数据等，为每一次事件创建一个独立的文档会导致文档数量激增，索引体积变大，从而影响查询性能。

**解决方案**：将一段时间内的数据（"桶"）聚合到一个文档中。

**示例**：一个传感器每分钟上报一次温度读数。

**反模式 (不推荐)**:
```json
// 每分钟都会插入一个这样的新文档
{ "sensor_id": "A1", "timestamp": ISODate("..."), "temperature": 25.1 }
{ "sensor_id": "A1", "timestamp": ISODate("..."), "temperature": 25.2 }
```

**应用桶模式**:
```json
// 每小时创建一个新文档（桶），每分钟更新一次
{
  "_id": "A1_20230101T10", // 按传感器和小时分组
  "sensor_id": "A1",
  "start_time": ISODate("2023-01-01T10:00:00Z"),
  "end_time": ISODate("2023-01-01T10:59:59Z"),
  "measurements": [
    { "timestamp": ISODate("...T10:00:00Z"), "temp": 25.1 },
    { "timestamp": ISODate("...T10:01:00Z"), "temp": 25.2 }
    // ... 58 more measurements
  ],
  "transaction_count": 60
}
```
**优点**：
-   **减少文档总数**：显著降低集合中的文档总量和索引大小。
-   **提高写入性能**：将多次 `insert` 操作变为一次 `insert` 和多次轻量级的 `update` (`$push`) 操作。
-   **优化读取**：获取一段时间内的数据（如一小时）只需要读取一个文档。

---

## 计算模式 (Computed Pattern)

**问题**：当某个值需要通过其他字段计算得出，并且这个计算结果被频繁读取时，如果在每次读取时都动态计算，会浪费大量的 CPU 资源。

**解决方案**：在**写入或更新**时就预先计算好结果，并将其作为一个字段存储在文档中。这是一种**空间换时间**的策略。

**示例**：一个电影数据库，需要频繁显示每部电影的平均评分。

**反模式 (读取时计算)**:
```json
{
  "movie_id": "m1",
  "ratings": [5, 4, 5, 3, 4] // 每次请求都需要计算平均值
}
```

**应用计算模式 (写入时计算)**:
```json
{
  "movie_id": "m1",
  "ratings": [5, 4, 5, 3, 4],
  "rating_stats": {
    "sum": 21,
    "count": 5,
    "average": 4.2 // 预先计算好的平均分
  }
}
// 当有新评分（如 5）加入时，原子性地更新
// db.movies.updateOne({_id: "m1"}, { $push: {ratings: 5}, $inc: {"rating_stats.sum": 5, "rating_stats.count": 1} })
// 然后再通过一次更新或在应用层重新计算平均值
```
**优点**：
-   **极大地提升读取性能**：避免了昂贵的实时聚合计算。
-   **简化查询**：可以直接对计算结果进行查询和排序。

---

## 文档版本模式 (Document Versioning Pattern)

**问题**：需要追踪文档的变更历史，例如在内容管理系统、审计日志或需要回滚到先前版本的场景中。

**解决方案**：为每个文档维护一个历史版本集合。

**示例**：一篇可编辑的文章。

**`articles` 集合 (只存当前版本)**:
```json
{
  "_id": "article123",
  "current_version": 3,
  "title": "My Awesome Article",
  "content": "Updated content here...",
  "last_updated": ISODate("...")
}
```
**`article_history` 集合 (存储历史版本)**:
```json
{ "_id": "v1_a123", "article_id": "article123", "version": 1, "content": "Initial content." },
{ "_id": "v2_a123", "article_id": "article123", "version": 2, "content": "Some revisions." },
{ "_id": "v3_a123", "article_id": "article123", "version": 3, "content": "Updated content here..." }
```
**优点**：
-   **保留完整的变更历史**：可以轻松查看、比较或回滚到任何历史版本。
-   **主文档保持轻量**：主集合只存储最新数据，保证了常规读取操作的性能。

---

## 扩展引用模式 (Extended Reference Pattern)

**问题**：当使用引用（Normalization）时，为了获取被引用文档的几个常用字段，每次都需要执行 `$lookup` 或额外的应用层查询，影响了性能。

**解决方案**：在使用引用的同时，将**最常用**的被引用文档的字段**冗余**一份到主文档中。这是**范式化和反范式化的折中**。

**示例**：一个博客平台，文章列表需要显示作者的名字，但不需要作者的所有信息。

**`articles` 集合**:
```json
{
  "_id": "article123",
  "title": "MongoDB Patterns",
  "author_id": "user88",
  "author_name": "Jane Doe" // 从 user 文档冗余过来的常用字段
}
```
**`users` 集合**:
```json
{
  "_id": "user88",
  "name": "Jane Doe",
  "email": "jane@example.com",
  "bio": "..."
}
```
**优点**：
-   **优化常见读取**：对于"显示文章列表及作者名"这类常见请求，无需进行 JOIN 操作，性能很高。
-   **保持数据规范性**：当需要完整的作者信息时（例如进入作者主页），仍然可以通过 `author_id` 去 `users` 集合中查找，避免了在文章中内嵌所有作者信息。

---

## 多态模式 (Polymorphic Pattern)

**问题**：需要在一个集合中存储不同 schema 结构的文档，但这些文档都属于同一个逻辑实体。

**解决方案**：在文档中增加一个字段（如 `type`）来标识其具体的结构，并根据这个字段来构建不同的应用逻辑。

**示例**：一个支付系统，需要记录不同支付方式的交易。

**`transactions` 集合**:
```json
// 信用卡支付
{
  "_id": "txn1",
  "type": "credit_card",
  "amount": 50.00,
  "card_last_four": "1234",
  "expiry": "12/25"
},
// PayPal 支付
{
  "_id": "txn2",
  "type": "paypal",
  "amount": 75.50,
  "paypal_email": "test@example.com"
}
```
**优点**：
-   **灵活性高**：可以轻松地在同一个集合中管理多种相关但结构不同的数据。
-   **简化集合管理**：无需为每种支付方式创建单独的集合。

---

## 子集模式 (Subset Pattern)

**问题**：一个文档中包含一个非常大的数组（例如，一个产品的所有评论），但通常的应用场景只是显示最近的几十条。完整加载整个文档会因为这个大数组而消耗大量内存和带宽。

**解决方案**：将数组的"子集"（例如，最近的 N 个元素）与主文档存储在一起，而将完整的数组存储在另一个集合中。

**示例**：产品和它的评论。

**`products` 集合 (存储热门子集)**:
```json
{
  "_id": "product1",
  "name": "Super Widget",
  "total_reviews": 5432,
  "reviews_subset": [ // 只存储最新的 5 条评论
    { "user": "A", "comment": "Great!", "date": ISODate("...") },
    { "user": "B", "comment": "Love it!", "date": ISODate("...") }
  ]
}
```
**`reviews` 集合 (存储所有评论)**:
```json
{ "review_id": "r1", "product_id": "product1", "comment": "..." },
{ "review_id": "r2", "product_id": "product1", "comment": "..." },
// ... 5430 more reviews
```
**优点**：
-   **优化常见用例**：快速加载产品页面时只返回少量数据，性能极佳。
-   **避免文档超限**：避免了主文档因数组无限增长而超过 16MB 的限制。
-   **按需加载**：当用户点击"查看所有评论"时，才需要去 `reviews` 集合中分页查询。

掌握这些设计模式，可以让你在面对复杂业务需求时，设计出更优雅、高效的 MongoDB Schema。 