# 13. 全文搜索

当简单的 `LIKE` 或 `ILIKE` 查询无法满足复杂的文本搜索需求时（例如，需要处理词形变化、停用词、相关性排名等），PostgreSQL 提供了强大的内置全文搜索 (Full Text Search, FTS) 功能。

## 全文搜索的核心概念

FTS 的工作流程通常包括以下几个步骤：

1.  **解析 (Parsing)**: 将原始文本文档分解成一系列的"词元 (Token)"。
2.  **词典处理 (Dictionary Processing)**: 将每个词元转换为标准化的"词位 (Lexeme)"。这个过程可能包括：
    - 转换为小写。
    - 去除"停用词 (Stop Words)"（如 "a", "the", "in" 等不具信息量的词）。
    - 将词语还原为其词根或原型（词干提取，Stemming），例如将 "running", "ran" 都转换为 "run"。
3.  **存储与索引**: 将处理后的词位存储在专门的数据结构中，以便快速搜索。

## `tsvector` 和 `tsquery`

PostgreSQL 使用两种特殊的数据类型来实现全文搜索：

- **`tsvector` (Text Search Vector)**:
  这是一种用于存储优化后文档的数据类型。它是一个**排序好**的、**不重复**的词位列表。`to_tsvector` 函数用于将原始文本转换为 `tsvector`。

  ```sql
  SELECT to_tsvector('english', 'A fat cat sat on a mat and ate a fat rat.');
  ```
  **结果**:
  ```
  'ate':9 'cat':3 'fat':2,11 'mat':7 'rat':12 'sat':4
  ```
  注意：停用词 "a", "on", "and" 被移除，词位按字母排序，并标出了它们在原始文本中的位置。

- **`tsquery` (Text Search Query)**:
  这是一种用于表示搜索查询的数据类型。`to_tsquery` 函数将用户的搜索词转换为 `tsquery`。

  ```sql
  SELECT to_tsquery('english', 'cats & rats');
  ```
  **结果**:
  ```
  'cat' & 'rat'
  ```
  `tsquery` 可以包含逻辑操作符： `&` (AND), `|` (OR), `!` (NOT), 和 `<->` (FOLLOWED BY)。

## 进行搜索

`@@` 操作符用于匹配一个 `tsquery` 和一个 `tsvector`。

```sql
-- 演示
SELECT to_tsvector('english', 'The quick brown fox jumps over the lazy dog') @@ to_tsquery('english', 'fox & dog');
-- > true

SELECT to_tsvector('english', 'The quick brown fox jumps over the lazy dog') @@ to_tsquery('english', 'fox & cat');
-- > false
```

### 在表上实现全文搜索

1.  **添加 `tsvector` 列**:
    最佳实践是为要搜索的文本内容专门创建一个 `tsvector` 列。

    ```sql
    ALTER TABLE documents ADD COLUMN tsv tsvector;
    ```

2.  **使用触发器自动更新 `tsvector` 列**:
    为了保持 `tsv` 列与源文本列（例如 `doc ->> 'title'` 和 `doc ->> 'content'`）的同步，最可靠的方法是使用触发器。

    ```sql
    -- 更新 tsv 列
    UPDATE documents
    SET tsv = to_tsvector('english', doc ->> 'title' || ' ' || (doc ->> 'author'));

    -- 创建一个函数来自动更新
    CREATE OR REPLACE FUNCTION documents_tsv_trigger() RETURNS trigger AS $$
    begin
      new.tsv :=
        to_tsvector('pg_catalog.english', coalesce(new.doc ->> 'title', '') || ' ' || coalesce(new.doc ->> 'author', ''));
      return new;
    end
    $$ LANGUAGE plpgsql;

    -- 创建一个触发器，在插入或更新时调用该函数
    CREATE TRIGGER tsvectorupdate BEFORE INSERT OR UPDATE
    ON documents FOR EACH ROW EXECUTE PROCEDURE documents_tsv_trigger();
    ```
    现在，每当 `documents` 表中的记录被插入或更新时，`tsv` 列都会自动更新。

3.  **创建 GIN 索引**:
    为了极大地加速全文搜索，必须在 `tsvector` 列上创建一个 GIN 索引。

    ```sql
    CREATE INDEX idx_gin_documents_tsv ON documents USING GIN (tsv);
    ```

4.  **执行查询**:
    现在，可以高效地执行全文搜索查询了。

    ```sql
    SELECT id, doc ->> 'title'
    FROM documents
    WHERE tsv @@ to_tsquery('english', 'PostgreSQL & Rocks');
    ```

## 结果排名与高亮

### 排名 (`ts_rank`, `ts_rank_cd`)

通常，您不仅想找到匹配的文档，还想知道哪些文档与查询的**相关性最高**。`ts_rank` 和 `ts_rank_cd` 函数用于此目的。

```sql
SELECT
    id,
    doc ->> 'title' as title,
    ts_rank_cd(tsv, to_tsquery('english', 'PostgreSQL & Rocks')) as rank
FROM
    documents
WHERE
    tsv @@ to_tsquery('english', 'PostgreSQL & Rocks')
ORDER BY
    rank DESC;
```
`ts_rank_cd` 通常比 `ts_rank` 提供更好的排名结果。

### 高亮 (`ts_headline`)

`ts_headline` 函数用于高亮显示文档中与查询匹配的词语，非常适合在搜索结果页面上展示摘要。

```sql
SELECT
    ts_headline(
        'english',
        doc ->> 'title' || ' by ' || (doc ->> 'author'), -- 要高亮的原始文本
        to_tsquery('english', 'PostgreSQL & Rocks'),
        'StartSel=*, StopSel=*, HighlightAll=true' -- 高亮选项
    ) as headline
FROM
    documents
WHERE
    tsv @@ to_tsquery('english', 'PostgreSQL & Rocks');
```
**结果示例**:
```
"<b>PostgreSQL</b> <b>Rocks</b> by DB Pro"
```

PostgreSQL的全文搜索功能非常成熟和强大，通过结合 `tsvector`, `tsquery`, GIN索引以及排名和高亮函数，可以构建出功能完备且性能卓越的搜索引擎。 