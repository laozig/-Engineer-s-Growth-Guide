# 12. JSONB与非结构化数据

在现代Web应用中，处理半结构化或无结构数据（如JSON）已成为常态。PostgreSQL通过其强大的`JSON`和`JSONB`数据类型，将关系型数据库的稳定性和非关系型数据库的灵活性完美结合。

## `json` vs `jsonb`

PostgreSQL提供两种存储JSON数据的类型：

| 特性 | `json` | `jsonb` |
| --- | --- | --- |
| **存储格式** | 存储原始的、未经处理的JSON文本。 | 存储为分解后的**二进制格式**。 |
| **插入速度** | 更快，因为它只进行最基本的JSON有效性检查。 | 稍慢，因为它需要解析并转换JSON结构。 |
| **处理速度** | 更慢，每次查询时都需要重新解析整个JSON文本。 | **快得多**，因为JSON结构已被解析。 |
| **索引支持** | 有限。 | **非常强大**，支持GIN和B-Tree索引，可索引顶层键或整个文档路径。 |
| **格式保留** | 保留原始文本的所有细节，包括空格和重复的键。 | 不保留多余空格，键会按特定顺序排列，并且会去重（保留最后一个）。 |

**核心原则：除非您有特殊需求要保留JSON的原始文本格式，否则请始终使用 `jsonb`。** `jsonb` 提供了卓越的性能和强大的索引能力，是绝大多数应用场景的最佳选择。

## `jsonb` 的操作符

PostgreSQL为`jsonb`提供了一套丰富的操作符，用于查询和操作JSON数据。

假设我们有一个`documents`表：
```sql
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    doc JSONB
);

INSERT INTO documents (doc) VALUES
('{"title": "PostgreSQL Rocks", "author": "DB Pro", "tags": ["database", "sql", "postgres"], "meta": {"pages": 250}}');
```

### 路径和文本提取操作符

- **`->`**: 按键获取JSON对象字段，或按索引获取JSON数组元素。**返回 `jsonb` 类型**。
- **`->>`**: 与`->`类似，但**返回 `text` 类型**。这是最常用的提取操作符。
- **`#>`**: 按路径获取嵌套的JSON对象。返回 `jsonb`。
- **`#>>`**: 与`#>`类似，但返回 `text`。

**示例**:
```sql
-- 获取标题 (text)
SELECT doc ->> 'title' FROM documents;
-- > PostgreSQL Rocks

-- 获取第一个标签 (text)
SELECT doc -> 'tags' ->> 0 FROM documents;
-- > database

-- 获取嵌套的页数 (text)
SELECT doc #>> '{meta,pages}' FROM documents;
-- > 250
```

### 存在与包含操作符

这些操作符通常用于`WHERE`子句，并且可以被GIN索引极大地加速。

- **`?`**: `jsonb ? text` - 检查字符串是否存在于JSON对象的顶层键中。
- **`?|`**: `jsonb ?| text[]` - 检查数组中的任何一个字符串是否存在于顶层键中。
- **`?&`**: `jsonb ?& text[]` - 检查数组中的所有字符串是否都存在于顶层键中。
- **`@>`**: `jsonb @> jsonb` - **包含操作符**。检查左边的`jsonb`值是否包含右边的`jsonb`值。这是最有用的`jsonb`操作符之一。
- **`<@`**: `jsonb <@ jsonb` - **被包含操作符**。检查左边的`jsonb`值是否被右边的`jsonb`值所包含。

**示例**:
```sql
-- 查找所有包含 'author' 键的文档
SELECT * FROM documents WHERE doc ? 'author';

-- 查找所有标签包含 "postgres" 的文档
SELECT * FROM documents WHERE doc -> 'tags' @> '["postgres"]';

-- 查找所有作者是 "DB Pro" 并且有 "sql" 标签的文档 (深度包含)
SELECT * FROM documents WHERE doc @> '{"author": "DB Pro", "tags": ["sql"]}';
```
`@>`操作符的强大之处在于它可以递归地检查嵌套结构。

## `jsonb` 索引

为了高效地查询`jsonb`数据，必须使用索引。

### GIN 索引

通用倒排索引 (GIN) 是`jsonb`最常用也是最强大的索引类型。

- **默认GIN索引 (`jsonb_ops`)**:
  ```sql
  CREATE INDEX idx_gin_documents_doc ON documents USING GIN (doc);
  ```
  这个索引支持`?`, `?|`, `?&`, `@>`等操作符。它会索引`jsonb`文档中的每一个键和值，因此索引体积可能较大，但提供了极大的查询灵活性。

- **路径操作符GIN索引 (`jsonb_path_ops`)**:
  ```sql
  CREATE INDEX idx_gin_path_documents_doc ON documents USING GIN (doc jsonb_path_ops);
  ```
  这个索引只支持`@>`操作符。它的索引体积比默认GIN索引小得多，更新也更快。如果您的查询模式主要是检查特定路径下的值是否存在（即只用`@>`），那么`jsonb_path_ops`是更好的选择。

### B-Tree 索引

如果您的查询总是过滤`jsonb`文档中某个特定字段的值，并且涉及范围查询或排序，那么可以在该字段上创建一个B-Tree索引。

```sql
-- 假设我们经常需要按页数排序或进行范围查询
CREATE INDEX idx_btree_documents_meta_pages ON documents ((doc #>> '{meta,pages}'));

-- 这个查询现在可以使用B-Tree索引
SELECT * FROM documents WHERE (doc #>> '{meta,pages}')::int > 200;
```
注意表达式需要用双括号括起来。

## 更新 `jsonb`

`jsonb_set`函数用于非破坏性地更新`jsonb`文档的某个部分。

```sql
UPDATE documents
SET doc = jsonb_set(
    doc,                        -- 原始文档
    '{meta,pages}',             -- 目标路径
    '300'::jsonb,               -- 新的值
    true                        -- 如果路径不存在，则创建它 (可选)
)
WHERE id = 1;
```

`||`操作符可以用于合并两个`jsonb`对象：
```sql
UPDATE documents
SET doc = doc || '{"status": "published"}'::jsonb
WHERE id = 1;
```

PostgreSQL的`jsonb`功能使其成为构建需要灵活数据模型的现代应用程序的强大后端，既享受了SQL的严谨，又获得了NoSQL的便利。 