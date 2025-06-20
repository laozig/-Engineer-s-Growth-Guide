# 5. PostgreSQL 数据类型

PostgreSQL 拥有一个非常丰富的数据类型系统，这是它的核心优势之一。选择正确的数据类型不仅可以优化存储，还能提高查询性能，并确保数据的完整性。

## 数值类型

| 类型 | 存储大小 | 范围 | 描述 |
| --- | --- | --- | --- |
| `smallint` | 2 字节 | -32768 到 +32767 | 小范围整数。 |
| `integer` | 4 字节 | -2147483648 到 +2147483647 | 常用的整数类型。 |
| `bigint` | 8 字节 | -9223372036854775808 到 +9223372036854775807 | 大范围整数。 |
| `decimal` | 可变 | 用户指定的精度 | 用于需要精确计算的场景，如货币。 |
| `numeric` | 可变 | 用户指定的精度 | 与 `decimal` 完全相同。 |
| `real` | 4 字节 | 6 位十进制精度 | 单精度浮点数。 |
| `double precision` | 8 字节 | 15 位十进制精度 | 双精度浮点数。 |
| `smallserial` | 2 字节 | 1 到 32767 | 自增的小整数。 |
| `serial` | 4 字节 | 1 到 2147483647 | 自增的整数。 |
| `bigserial` | 8 字节 | 1 到 9223372036854775807 | 自增的大整数。 |

**注意**: `serial` 类型不是真正的类型，而是一个语法糖，它会自动创建一个 `integer` 列并从一个序列中获取默认值。

## 字符类型

| 类型 | 描述 |
| --- | --- |
| `varchar(n)` | 变长字符串，有长度限制。 |
| `char(n)` | 定长字符串，不足部分用空格填充。 |
| `text` | 变长字符串，无长度限制。 |

**最佳实践**: 如果不确定长度，或者长度可能很长，优先使用 `text`。`varchar(n)` 的长度限制在现代PostgreSQL中性能优势已不明显，主要用于数据校验。

## 日期/时间类型

| 类型 | 存储大小 | 描述 |
| --- | --- | --- |
| `timestamp [ (p) ] [ without time zone ]` | 8 字节 | 日期和时间。 |
| `timestamp [ (p) ] with time zone` | 8 字节 | 带时区的日期和时间，存储时会转换为UTC。 |
| `date` | 4 字节 | 只存储日期。 |
| `time [ (p) ] [ without time zone ]` | 8 字节 | 只存储时间。 |
| `interval [ fields ] [ (p) ]` | 16 字节 | 时间间隔。 |

**最佳实践**: 强烈推荐使用 `timestamp with time zone` (`timestamptz`) 来存储所有时间相关的业务数据，以避免时区混淆问题。

## 布尔类型

| 类型 | 存储大小 | 描述 |
| --- | --- | --- |
| `boolean` | 1 字节 | 存储 `true` 或 `false`，也接受 `'t'`, `'f'`, `'yes'`, `'no'`, `'1'`, `'0'` 等输入。 |

## JSON 类型

PostgreSQL 提供了两种强大的JSON类型，使其能高效地处理半结构化数据。

| 类型 | 描述 |
| --- | --- |
| `json` | 存储原始JSON文本，每次查询时都需要重新解析。 |
| `jsonb` | 存储为分解后的二进制格式，插入时稍慢，但处理速度更快，并支持索引。 |

**最佳实践**: 除非有特殊理由需要保留原始JSON的空格、重复键等，否则**总是使用 `jsonb`**。`jsonb` 提供了更强大的操作符和更好的性能。

```sql
CREATE TABLE products (
    id serial PRIMARY KEY,
    name text,
    attributes jsonb
);

INSERT INTO products (name, attributes) VALUES
('Laptop', '{"brand": "Apple", "specs": {"ram": 16, "storage": 512}}');

-- 使用 ->> 操作符以文本形式访问JSON字段
SELECT name, attributes ->> 'brand' as brand FROM products;

-- 使用 @> 操作符检查是否包含某个JSON
SELECT * FROM products WHERE attributes @> '{"brand": "Apple"}';
```

## 数组类型

PostgreSQL 允许任何数据类型的列被定义为多维数组。

```sql
CREATE TABLE monthly_sales (
    month text,
    sales_by_day integer[]
);

INSERT INTO monthly_sales (month, sales_by_day) VALUES
('January', '{10, 20, 15, 25}');

-- 访问数组元素 (PostgreSQL数组索引从1开始)
SELECT sales_by_day[2] FROM monthly_sales WHERE month = 'January'; -- 返回 20
```

## 其他特殊类型

- **`uuid`**: 存储通用唯一标识符。
- **`xml`**: 存储XML数据。
- **`inet`**: 存储IPv4或IPv6地址。
- **`point`, `line`, `polygon`**: 几何类型。
- **`tsvector`, `tsquery`**: 全文搜索类型。

选择合适的数据类型是数据库设计的第一步。了解它们的特性将帮助您构建更健壮、更高效的应用程序。 