# 6. 数据定义语言 (DDL)

数据定义语言 (Data Definition Language, DDL) 用于定义和管理数据库中的所有对象。这包括创建、修改和删除表、索引、视图等。

## 创建表 (CREATE TABLE)

`CREATE TABLE` 是最核心的DDL命令，用于定义一个新表的结构，包括列名、数据类型和约束。

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
```

### 常用约束 (Constraints)

约束用于强制执行数据的完整性规则：

- `PRIMARY KEY`: 主键。唯一标识表中的每一行，不允许为NULL。一个表只能有一个主键。`SERIAL` 类型会自动创建主键约束。
- `NOT NULL`: 非空约束。确保列不能有NULL值。
- `UNIQUE`: 唯一约束。确保列中的所有值都是唯一的。
- `FOREIGN KEY`: 外键。将一个表中的列与另一个表的主键关联起来，用于强制引用完整性。
- `CHECK`: 检查约束。确保列中的值满足特定条件。
- `DEFAULT`: 默认值。如果插入时未指定该列的值，则使用此默认值。

### 外键示例

```sql
CREATE TABLE user_profiles (
    user_id INT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    bio TEXT,
    -- 定义外键, 关联到 users 表的 id 列
    CONSTRAINT fk_user
        FOREIGN KEY(user_id) 
        REFERENCES users(id)
        ON DELETE CASCADE -- 当 users 表中的记录被删除时，这里的对应记录也一并删除
);
```

## 修改表 (ALTER TABLE)

`ALTER TABLE` 用于修改现有表的结构。

### 添加列

```sql
ALTER TABLE users ADD COLUMN last_login TIMESTAMPTZ;
```

### 删除列

```sql
ALTER TABLE users DROP COLUMN last_login;
```

### 修改列的数据类型

**注意**: 只有当列中的现有数据可以被安全地转换为新类型时，此操作才能成功。

```sql
ALTER TABLE user_profiles ALTER COLUMN first_name TYPE VARCHAR(100);
```

### 添加和删除约束

```sql
-- 添加一个 CHECK 约束
ALTER TABLE users ADD CONSTRAINT username_length_check CHECK (length(username) > 3);

-- 删除一个约束
ALTER TABLE users DROP CONSTRAINT username_length_check;
```

## 删除表 (DROP TABLE)

`DROP TABLE` 用于永久删除一个表及其所有数据。

**警告**: 此操作不可逆，请谨慎使用。

```sql
DROP TABLE user_profiles;
```

### `IF EXISTS`

如果您不确定表是否存在，使用 `IF EXISTS` 可以避免在表不存在时出现错误。

```sql
DROP TABLE IF EXISTS non_existent_table;
```

### `CASCADE`

如果一个表被其他表通过外键引用，直接删除会失败。使用 `CASCADE` 可以级联删除所有依赖于该表的对象。

```sql
DROP TABLE users CASCADE;
-- 这将同时删除 users 表和依赖它的 user_profiles 表
```

## 截断表 (TRUNCATE TABLE)

`TRUNCATE TABLE` 用于快速删除一个表中的所有行，但保留表结构本身。

```sql
TRUNCATE TABLE employees;
```

### `TRUNCATE` vs `DELETE`

| 特性 | `TRUNCATE` | `DELETE` |
| --- | --- | --- |
| **速度** | 非常快，因为它不逐行扫描。 | 较慢，因为它逐行删除并记录日志。 |
| **触发器** | 不会触发 `ON DELETE` 触发器。 | 会触发 `ON DELETE` 触发器。 |
| **事务日志** | 产生的日志非常少。 | 为每一行删除都记录日志。 |
| **`WHERE`子句** | 不支持。 | 支持，可以删除特定行。 |
| **返回值** | 不返回被删除的行数。 | 返回被删除的行数。 |
| **序列重置** | 如果表包含 `SERIAL` 列，会重置序列计数器。 | 不会重置序列。 |

**适用场景**: 当您需要清空一个大表并且不关心单行删除的逻辑时，`TRUNCATE` 是最佳选择。

掌握DDL是进行数据库设计和维护的基础。下一章，我们将学习如何操作数据，即 [数据操作语言 (DML)](dml.md)。 