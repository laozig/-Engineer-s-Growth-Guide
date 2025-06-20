# MongoDB 模式验证 (Schema Validation)

尽管 MongoDB 以其灵活的、无模式（schema-less）的特性而闻名，但这并不意味着数据可以无序地随意存储。在许多应用中，保证数据的结构一致性和类型正确性至关重要。MongoDB 从 3.2 版本开始引入了**模式验证（Schema Validation）**功能，允许在数据库层面为集合强制指定数据结构规则。

## 目录
- [什么是模式验证？](#什么是模式验证)
- [如何设置模式验证](#如何设置模式验证)
  - [使用 `$jsonSchema`](#使用-jsonschema)
  - [指定验证级别 (`validationLevel`)](#指定验证级别-validationlevel)
  - [指定验证操作 (`validationAction`)](#指定验证操作-validationaction)
- [常用验证操作符](#常用验证操作符)
  - [`bsonType`](#bsontype)
  - [`required`](#required)
  - [`properties` 和 `additionalProperties`](#properties-和-additionalproperties)
  - [`pattern`](#pattern)
  - [`minimum` / `maximum`](#minimum--maximum)
  - [`enum`](#enum)
- [管理模式验证](#管理模式验证)
  - [为已有集合添加验证](#为已有集合添加验证)
  - [查看集合的验证规则](#查看集合的验证规则)
  - [更新或移除验证](#更新或移除验证)
- [模式验证 vs 应用层验证](#模式验证-vs-应用层验证)

---

## 什么是模式验证？

模式验证是定义在**集合**级别的一系列规则。当对该集合执行插入（`insert`）或更新（`update`）操作时，MongoDB 会检查待写入的文档是否符合这些规则。

-   如果文档**符合**规则，操作成功。
-   如果文档**不符合**规则，MongoDB 将根据预设的 `validationAction` 拒绝操作或记录警告。

这为数据治理提供了一道坚实的防线，防止了因程序 bug 或非法操作导致 "脏数据" 进入数据库。

## 如何设置模式验证

模式验证在创建集合时通过 `db.createCollection()` 指定，或者为已有集合通过 `collMod` (collection modify) 命令添加。

### 使用 `$jsonSchema`

MongoDB 使用 **JSON Schema** 标准来定义验证规则。这是一个强大且被广泛采用的用于验证 JSON 文档结构的规范。

**示例**：创建一个 `students` 集合，并要求每个学生文档必须：
1.  包含 `name` 和 `year` 字段。
2.  `name` 必须是字符串。
3.  `year` 必须是 2017 到 3017 之间的整数。
4.  可以有一个可选的 `gpa` 字段，必须是数字。

```javascript
db.createCollection("students", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["name", "year"],
      properties: {
        name: {
          bsonType: "string",
          description: "must be a string and is required"
        },
        year: {
          bsonType: "int",
          minimum: 2017,
          maximum: 3017,
          description: "must be an integer in [ 2017, 3017 ] and is required"
        },
        gpa: {
          bsonType: ["double", "int"], // gpa 可以是浮点数或整数
          description: "can be a double or integer if the field exists"
        }
      }
    }
  }
})
```

### 指定验证级别 (`validationLevel`)

`validationLevel` 控制模式验证的严格程度，尤其是在为已有数据的集合添加验证规则时。

-   **`"strict"` (默认)**: 对所有插入和更新操作都应用验证规则。这是最严格的级别。
-   **`"moderate"`**:
    -   对所有**插入**操作应用验证。
    -   对**更新**操作，只对**符合**现有验证规则的文档应用验证。如果一个旧文档本身就不符合新规则，那么对它的更新操作将**不会**触发验证。这为处理历史遗留数据提供了灵活性。
-   **`"off"`**: 关闭验证。

### 指定验证操作 (`validationAction`)

`validationAction` 定义了当一个文档验证失败时，MongoDB 应该如何响应。

-   **`"error"` (默认)**: 拒绝写入操作，并向客户端返回一个错误。这是最常用的设置，可以有效防止脏数据写入。
-   **`"warn"`**: 允许写入操作，但在 MongoDB 的日志中记录一条警告信息。这通常用于测试或部署新验证规则的过渡阶段，以便观察哪些操作会违反规则，而不会中断现有应用。

**综合示例**:
```javascript
db.createCollection("contacts", {
   validator: { /* ... $jsonSchema ... */ },
   validationLevel: "moderate",
   validationAction: "warn"
})
```

---

## 常用验证操作符

以下是 `$jsonSchema` 中一些最常用的关键字：

-   **`bsonType`**: 指定字段的 BSON 数据类型，例如 `"string"`, `"int"`, `"double"`, `"object"`, `"array"`, `"bool"`, `"date"`, `"null"`。可以指定单个类型，也可以是类型数组。
-   **`required`**: 一个字符串数组，列出了在对象中必须存在的字段名。
-   **`properties` 和 `additionalProperties`**:
    -   `properties`: 一个对象，用于定义对象中每个字段的验证规则。
    -   `additionalProperties`: 一个布尔值。如果设为 `false`，则任何未在 `properties` 中明确定义的字段都将被视为非法，从而创建一个"封闭"的 schema。默认为 `true`。
-   **`pattern`**: 一个正则表达式字符串，字段的值必须与之匹配。仅适用于字符串类型。
-   **`minimum` / `maximum`**: 指定数字字段的最小值和最大值。`exclusiveMinimum` / `exclusiveMaximum` 则表示不包含边界值。
-   **`minItems` / `maxItems`**: 指定数组的最少和最多元素数量。
-   **`uniqueItems`**: 一个布尔值，如果为 `true`，则数组中的所有元素必须是唯一的。
-   **`enum`**: 一个数组，字段的值必须是该数组中定义的某个值。

**示例**：
```javascript
$jsonSchema: {
  bsonType: "object",
  required: ["username", "status"],
  additionalProperties: false, // 不允许其他顶级字段
  properties: {
    username: {
      bsonType: "string",
      pattern: "^[a-zA-Z0-9_]{3,16}$" // 3-16位的字母、数字、下划线
    },
    status: {
      enum: ["Active", "Inactive", "Pending"] // 状态必须是这三个值之一
    },
    tags: {
      bsonType: "array",
      minItems: 1,
      uniqueItems: true,
      items: { // 定义数组中每个元素的规则
        bsonType: "string"
      }
    }
  }
}
```

---

## 管理模式验证

### 为已有集合添加验证
使用 `collMod` 命令。
```javascript
db.runCommand({
  collMod: "students",
  validator: { /* ... $jsonSchema ... */ },
  validationLevel: "strict"
})
```

### 查看集合的验证规则
使用 `db.getCollectionInfos()`。
```javascript
db.getCollectionInfos({ name: "students" })
// 在返回结果的 options.validator 中查看
```

### 更新或移除验证
-   **更新**：再次调用 `collMod` 并提供新的 `validator` 对象即可覆盖旧规则。
-   **移除**：将 `validator` 设置为空对象 `{}`。
```javascript
db.runCommand({
  collMod: "students",
  validator: {}
})
```

## 模式验证 vs 应用层验证

-   **应用层验证**（例如在 Mongoose/ODM 中定义 Schema）依然非常重要。它能提供更早、更友好的用户反馈。
-   **数据库层模式验证**是最后一道防线。它确保了无论数据来自哪个应用、哪个脚本，甚至是管理员的手动修改，数据的基本一致性都得到保障。

在生产环境中，**两者结合**是最佳实践。依赖应用层验证来提升用户体验，同时利用数据库层验证来保证数据的最终完整性和安全性。 