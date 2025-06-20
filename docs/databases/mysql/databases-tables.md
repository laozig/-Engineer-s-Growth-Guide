# 4. 数据库与数据表 (Databases & Tables)

在关系型数据库中，数据被组织在数据库 (Database) 和数据表 (Table) 中。本章将介绍如何使用 SQL 命令来管理和操作它们。

## 数据库 (Database)

数据库是一个用于存储相关数据表的容器。在开始存储数据之前，您需要先创建一个数据库。

### 查看所有数据库

要查看 MySQL 服务器上存在的所有数据库，使用 `SHOW DATABASES;` 命令。

```sql
SHOW DATABASES;
```

执行后，您会看到一个列表，其中包含 `information_schema`、`mysql`、`performance_schema` 和 `sys` 等系统数据库，以及您自己创建的数据库。

### 创建数据库

使用 `CREATE DATABASE` 语句来创建一个新的数据库。

```sql
-- 基本语法
CREATE DATABASE database_name;

-- 示例：创建一个名为 my_project 的数据库
CREATE DATABASE my_project;
```

为了避免因数据库已存在而导致的错误，通常会加上 `IF NOT EXISTS` 子句。同时，指定字符集和排序规则是一个好习惯，以确保数据正确存储和排序。

```sql
-- 推荐的创建方式
CREATE DATABASE IF NOT EXISTS my_project
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;
```

- **`CHARACTER SET utf8mb4`**: 指定默认字符集为 `utf8mb4`，它可以存储包括 Emoji 在内的所有 Unicode 字符。
- **`COLLATE utf8mb4_unicode_ci`**: 指定排序规则，`_unicode_ci` 表示大小写不敏感 (case-insensitive) 的 Unicode 排序。

### 选择数据库

在对表进行操作之前，您必须先选择要使用的数据库。使用 `USE` 命令。

```sql
USE my_project;
```

成功执行后，之后的所有 SQL 操作都将在 `my_project` 数据库的上下文中执行。

### 删除数据库

使用 `DROP DATABASE` 命令可以永久删除一个数据库及其中的所有表和数据。这是一个非常危险的操作，请务必谨慎！

```sql
-- 基本语法
DROP DATABASE database_name;

-- 示例：删除 my_project 数据库
DROP DATABASE my_project;

-- 加上 IF EXISTS 子句避免因数据库不存在而报错
DROP DATABASE IF EXISTS my_project;
```

> ⚠️ **警告**: `DROP DATABASE` 会删除所有数据且无法恢复。在生产环境中，执行此操作前必须进行备份。

---

## 数据表 (Table)

数据表是数据库中存储数据的基本单位，由行 (Row) 和列 (Column) 组成。每一列代表一个字段，每一行代表一条记录。

### 创建数据表

使用 `CREATE TABLE` 语句来创建新表。您需要定义表的列名、数据类型以及各种约束。

```sql
-- 必须先用 USE 命令选择一个数据库
USE my_project;

-- 创建一个名为 'users' 的表示例
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
```

我们来分解这个例子：
- `id INT AUTO_INCREMENT PRIMARY KEY`:
    - `INT`: 数据类型为整数。
    - `AUTO_INCREMENT`: 当插入新行时，该列的值会自动加 1。常用于主键。
    - `PRIMARY KEY`: 将此列设置为主键。主键必须包含唯一值，且不能为 NULL，用于唯一标识表中的每一行。
- `username VARCHAR(50) NOT NULL UNIQUE`:
    - `VARCHAR(50)`: 可变长度的字符串，最多 50 个字符。
    - `NOT NULL`: 此列的值不能为空。
    - `UNIQUE`: 此列的值必须是唯一的，不能有重复。
- `created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP`:
    - `TIMESTAMP`: 时间戳数据类型。
    - `DEFAULT CURRENT_TIMESTAMP`: 如果在插入新行时未指定此列的值，它将默认为当前的系统时间。
- `ENGINE=InnoDB`: 明确指定使用 InnoDB 存储引擎，这是推荐的做法。

### 查看表结构

使用 `DESCRIBE` 或 `DESC` 命令可以查看表的列定义。

```sql
DESCRIBE users;
-- 或者
DESC users;
```

### 查看创建表的 SQL 语句

如果你想查看用于创建某个表的完整 SQL 语句，可以使用 `SHOW CREATE TABLE`。

```sql
SHOW CREATE TABLE users;
```
这个命令非常有用，因为它会显示表的完整定义，包括字符集、排序规则和所有约束。

### 修改表结构

使用 `ALTER TABLE` 语句可以在表创建后修改其结构。

**添加列 (ADD COLUMN)**
```sql
ALTER TABLE users
ADD COLUMN last_login_ip VARCHAR(45) NULL AFTER password_hash;
```

**修改列定义 (MODIFY COLUMN)**
```sql
-- 将 username 的最大长度从 50 修改为 100
ALTER TABLE users
MODIFY COLUMN username VARCHAR(100) NOT NULL UNIQUE;
```

**重命名列 (RENAME COLUMN)** (在某些 MySQL/MariaDB 版本中语法不同)
```sql
-- 将 password_hash 重命名为 password
ALTER TABLE users
CHANGE COLUMN password_hash password VARCHAR(255) NOT NULL;
```
注意 `CHANGE COLUMN` 需要同时指定旧列名和新列名，以及完整的列定义。

**删除列 (DROP COLUMN)**
```sql
ALTER TABLE users
DROP COLUMN last_login_ip;
```

**添加约束 (ADD CONSTRAINT)**
```sql
-- 添加一个检查约束 (MySQL 8.0.16+ 支持)
ALTER TABLE users
ADD CONSTRAINT check_username_length CHECK (CHAR_LENGTH(username) > 3);
```

### 重命名表

使用 `RENAME TABLE` 或 `ALTER TABLE ... RENAME TO` 来重命名表。

```sql
RENAME TABLE users TO app_users;
-- 或者
ALTER TABLE app_users RENAME TO users;
```

### 删除表

使用 `DROP TABLE` 命令可以永久删除一个表。

```sql
DROP TABLE IF EXISTS users;
```

### 清空表 (Truncate Table)

如果你只想删除表中的所有数据，但保留表结构本身，可以使用 `TRUNCATE TABLE`。

```sql
TRUNCATE TABLE users;
```

**`TRUNCATE` vs `DELETE`**
- `TRUNCATE TABLE` 速度非常快，因为它直接重置表，而不是逐行删除。
- 它是一个 DDL (数据定义语言) 命令，通常不能回滚，且不会触发 `DELETE` 触发器。
- 如果表有 `AUTO_INCREMENT` 列，`TRUNCATE` 会将其计数器重置为初始值。
- `DELETE FROM table_name;` 是 DML (数据操作语言) 命令，会逐行删除，可以回滚，会触发触发器，并且不会重置 `AUTO_INCREMENT` 计数器。 