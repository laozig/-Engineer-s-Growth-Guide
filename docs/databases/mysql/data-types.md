# 5. 数据类型 (Data Types)

在 MySQL 中，为表的每一列选择正确的数据类型是数据库设计中的一个关键步骤。恰当的数据类型可以优化存储空间、提高查询效率并确保数据的完整性。MySQL 提供了丰富的数据类型，可以分为三大类：数值类型、字符串类型以及日期和时间类型。

## 数值类型 (Numeric Types)

用于存储各种数字，如整数、小数和布尔值。

### 整数类型 (Integer Types)

| 类型 | 存储空间 (Bytes) | 最小值 (Signed) | 最大值 (Signed) | 最小值 (Unsigned) | 最大值 (Unsigned) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `TINYINT` | 1 | -128 | 127 | 0 | 255 |
| `SMALLINT` | 2 | -32,768 | 32,767 | 0 | 65,535 |
| `MEDIUMINT`| 3 | -8,388,608 | 8,388,607 | 0 | 16,777,215 |
| `INT` | 4 | -2,147,483,648 | 2,147,483,647 | 0 | 4,294,967,295 |
| `BIGINT` | 8 | -9,223,372,036,854,775,808 | 9,223,372,036,854,775,807 | 0 | 18,446,744,073,709,551,615 |

- **`SIGNED` vs `UNSIGNED`**: 默认是 `SIGNED`（有符号），可以存储负数。`UNSIGNED`（无符号）只能存储非负数，但其正数范围扩大了一倍。主键 `id` 通常设置为 `INT UNSIGNED` 或 `BIGINT UNSIGNED`。
- **`ZEROFILL`**: (不推荐使用) 如果一个整数列被指定为 `ZEROFILL`，MySQL 会自动将其设置为 `UNSIGNED`，并在显示时用前导零填充到指定的宽度。

```sql
CREATE TABLE products (
    product_id INT UNSIGNED PRIMARY KEY,
    stock_count SMALLINT SIGNED,
    views BIGINT UNSIGNED
);
```

### 小数类型 (Fixed-Point and Floating-Point Types)

#### `DECIMAL` (定点数)

`DECIMAL(M, D)` 用于存储精确的小数值，非常适合财务和货币计算。
- `M`: 总位数（精度），最大为 65。
- `D`: 小数点后的位数（标度），最大为 30。
- 存储空间由 `M` 决定。

```sql
-- 可以存储从 -999.99 到 999.99 的值
price DECIMAL(5, 2)
```

#### `FLOAT` 和 `DOUBLE` (浮点数)

`FLOAT` 和 `DOUBLE` 用于存储近似的小数值。它们使用标准的浮点运算，速度比 `DECIMAL` 快，但可能会有精度损失。
- `FLOAT`: 单精度浮点数，占用 4 字节。
- `DOUBLE`: 双精度浮点数，占用 8 字节，精度更高。

```sql
CREATE TABLE sensors (
    reading_time TIMESTAMP,
    temperature FLOAT,
    pressure DOUBLE
);
```
> **选择建议**: 如果要求精确计算（如金额），必须使用 `DECIMAL`。如果只是存储科学测量等近似值，并且对性能要求很高，可以考虑 `FLOAT` 或 `DOUBLE`。

### 位值类型 (Bit Value Type)

- **`BIT(M)`**: 存储位值，`M` 表示位串的长度，范围从 1 到 64。

```sql
-- 存储一个8位的二进制值
config_flags BIT(8)
```

### 布尔类型 (Boolean Type)

MySQL 没有真正的布尔类型。`BOOL` 或 `BOOLEAN` 是 `TINYINT(1)` 的别名。
- `0` 代表 `FALSE`。
- 非 `0` 值代表 `TRUE`。

```sql
is_active BOOLEAN NOT NULL DEFAULT TRUE; -- 实际上是 TINYINT(1)
```

## 字符串类型 (String Types)

用于存储文本数据，如名称、描述、文章等。

### `CHAR` 和 `VARCHAR`

| 特性 | `CHAR(M)` | `VARCHAR(M)` |
| :--- | :--- | :--- |
| **长度** | 固定长度 | 可变长度 |
| **M** | 0-255 | 0-65,535 (实际受行大小限制) |
| **存储** | 始终占用 M 个字符的长度 | 占用实际内容长度 + 1/2 字节的长度前缀 |
| **性能** | 处理速度稍快，尤其是在更新时 | 更节省空间 |
| **适用场景** | 定长数据，如 MD5 哈希、邮政编码、性别 ('M'/'F') | 长度不固定的数据，如用户名、文章标题 |

```sql
CREATE TABLE articles (
    status CHAR(8), -- 'published', 'draft'
    title VARCHAR(200)
);
```

### `TEXT` 类型

用于存储长文本数据。

| 类型 | 最大长度 (字符数) |
| :--- | :--- |
| `TINYTEXT` | 255 (2^8 - 1) |
| `TEXT` | 65,535 (2^16 - 1) |
| `MEDIUMTEXT` | 16,777,215 (2^24 - 1) |
| `LONGTEXT` | 4,294,967,295 (2^32 - 1) |

- **与 `VARCHAR` 的区别**:
    - `VARCHAR` 有长度限制（受限于行大小），而 `TEXT` 类型可以存储更大的数据。
    - `VARCHAR` 可以有 `DEFAULT` 值，而 `TEXT` 不行。
    - `VARCHAR` 通常存储在行内，查询效率稍高。`TEXT` 数据较大时可能会存储在行外。
    - 对 `TEXT` 列进行索引需要指定前缀长度。

### `BINARY` 和 `VARBINARY`

与 `CHAR` 和 `VARCHAR` 类似，但它们存储的是二进制字节串，而不是字符字符串。它们没有字符集的概念，排序和比较是基于字节的数值。

### `BLOB` 类型

`BLOB` (Binary Large Object) 用于存储大型二进制数据，如图片、音频或视频文件。

| 类型 | 最大长度 (Bytes) |
| :--- | :--- |
| `TINYBLOB` | 255 |
| `BLOB` | 65,535 |
| `MEDIUMBLOB`| 16,777,215 |
| `LONGBLOB` | 4,294,967,295 |

> **注意**: 通常不建议在数据库中存储大型文件（如图片）。更好的做法是，将文件存储在文件系统或对象存储（如 AWS S3）中，然后在数据库中只存储文件的路径或 URL。

### `ENUM` 和 `SET`

- **`ENUM('val1', 'val2', ...)`**: 枚举类型。列的值只能是预定义列表中的一个。存储上非常高效，内部使用整数表示。
- **`SET('val1', 'val2', ...)`**: 集合类型。列的值可以是预定义列表中的零个、一个或多个值的组合。

```sql
CREATE TABLE clothing (
    size ENUM('S', 'M', 'L', 'XL'),
    features SET('waterproof', 'windproof', 'breathable')
);
```
> **使用建议**: `ENUM` 和 `SET` 虽然节省空间，但会降低灵活性。如果未来可能需要增删选项，修改 `ALTER TABLE` 会很麻烦。在很多情况下，使用一个关联的查找表（Lookup Table）是更规范、更灵活的设计。

## 日期和时间类型 (Date and Time Types)

| 类型 | 格式 | 范围 |
| :--- | :--- | :--- |
| `DATE` | 'YYYY-MM-DD' | '1000-01-01' to '9999-12-31' |
| `TIME` | 'HH:MM:SS' | '-838:59:59' to '838:59:59' |
| `DATETIME`| 'YYYY-MM-DD HH:MM:SS'| '1000-01-01 00:00:00' to '9999-12-31 23:59:59'|
| `TIMESTAMP`| 'YYYY-MM-DD HH:MM:SS'| '1970-01-01 00:00:01' UTC to '2038-01-19 03:14:07' UTC |
| `YEAR` | YYYY | 1901 to 2155 |

- **`DATETIME` vs `TIMESTAMP`**:
    - **存储空间**: `DATETIME` 在 MySQL 5.6.4 之后占用 5 字节 + 小数秒精度，之前是 8 字节。`TIMESTAMP` 占用 4 字节 + 小数秒精度。
    - **时区**: `DATETIME` 存储的是字面上的日期和时间，与时区无关。`TIMESTAMP` 存储时会将其从当前连接的时区转换为 UTC（世界标准时间），检索时再从 UTC 转换回当前连接的时区。
    - **范围**: `DATETIME` 的范围远大于 `TIMESTAMP`。
- **选择建议**:
    - 如果你需要记录一个与时区无关的、固定的时间点（如生日），使用 `DATETIME`。
    - 如果你需要记录一个事件发生的时间点，并且希望它能在不同时区的用户看来都是正确的相对时间，使用 `TIMESTAMP`。`created_at`, `updated_at` 字段是 `TIMESTAMP` 的典型用例。
    - `DEFAULT CURRENT_TIMESTAMP` 和 `ON UPDATE CURRENT_TIMESTAMP` 对 `DATETIME` 和 `TIMESTAMP` 都适用。

选择正确的数据类型是构建高效、可维护数据库的基础。务必花时间思考每一列最适合的类型。 