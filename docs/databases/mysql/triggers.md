# 15. 触发器 (Triggers)

触发器是一种特殊的存储过程，它与特定的表相关联，并在该表发生特定事件（`INSERT`、`UPDATE` 或 `DELETE`）时自动执行。触发器常用于实现复杂的业务规则、数据审计、或保持数据一致性。

## 触发器的组成部分

一个触发器包含以下关键信息：

1.  **触发器名称 (Trigger Name)**: 数据库内的唯一名称。
2.  **关联表 (Associated Table)**: 触发器所绑定的表。
3.  **触发事件 (Trigger Event)**: `INSERT`、`UPDATE` 或 `DELETE`。
4.  **触发时机 (Trigger Timing)**: `BEFORE` 或 `AFTER`。
    - `BEFORE`: 在事件（如插入或更新行）实际发生**之前**执行触发器逻辑。
    - `AFTER`: 在事件已经成功发生**之后**执行。
5.  **触发器主体 (Trigger Body)**: 包含了在触发器被激活时要执行的 SQL 语句。

## 创建触发器

```sql
DELIMITER $$

CREATE TRIGGER trigger_name
{BEFORE | AFTER} {INSERT | UPDATE | DELETE}
ON table_name FOR EACH ROW
BEGIN
    -- 触发器逻辑
END$$

DELIMITER ;
```
- **`FOR EACH ROW`**: 这是一个必要的子句，表示触发器会对受事件影响的**每一行**都执行一次。行级触发器是 MySQL 支持的唯一类型。
- **`OLD` 和 `NEW` 关键字**: 在触发器主体内部，你可以使用特殊的关键字 `OLD` 和 `NEW` 来访问受影响的行数据。
    - `INSERT` 触发器: 只能访问 `NEW`，代表将要被插入的新行。
    - `UPDATE` 触发器: 可以访问 `OLD`（更新前的行数据）和 `NEW`（将要更新为的新数据）。
    - `DELETE` 触发器: 只能访问 `OLD`，代表被删除的行。

---

## 触发器示例

### 示例 1: 数据审计 (Audit Log)

创建一个 `AFTER INSERT` 触发器，每当 `employees` 表中添加一个新员工时，就在 `audit_log` 表中记录一条日志。

首先，创建审计日志表：
```sql
CREATE TABLE audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    log_message VARCHAR(255),
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

然后，创建触发器：
```sql
DELIMITER $$

CREATE TRIGGER employees_after_insert
AFTER INSERT ON employees
FOR EACH ROW
BEGIN
    -- 'NEW' 关键字引用了刚刚被插入的新行
    INSERT INTO audit_log (log_message)
    VALUES (CONCAT('New employee added: ', NEW.first_name, ' ', NEW.last_name, ' (ID: ', NEW.id, ')'));
END$$

DELIMITER ;
```

现在，当你插入一个新员工时：
```sql
INSERT INTO employees (first_name, last_name, email, hire_date, salary)
VALUES ('Frank', 'Miller', 'frank.m@example.com', '2023-08-01', 55000.00);
```
上述 `INSERT` 操作会自动激活 `employees_after_insert` 触发器，导致一条新的日志被插入到 `audit_log` 表中。

### 示例 2: 数据验证与修改 (`BEFORE` 触发器)

创建一个 `BEFORE INSERT` 触发器，在插入新员工数据前，自动将他们的邮箱地址转换为小写。`BEFORE` 触发器允许你**修改**将要被插入或更新的数据。

```sql
DELIMITER $$

CREATE TRIGGER employees_before_insert
BEFORE INSERT ON employees
FOR EACH ROW
BEGIN
    -- 直接修改 NEW 伪列中的值
    SET NEW.email = LOWER(NEW.email);
END$$

DELIMITER ;
```
现在，即使你尝试插入一个带有大写字母的邮箱，它也会被自动转换为小写后再存入数据库：
```sql
INSERT INTO employees (first_name, last_name, email, ...)
VALUES ('Grace', 'Hopper', 'Grace.Hopper@EXAMPLE.COM', ...);

-- 最终存储在表中的 email 将是 'grace.hopper@example.com'
```

### 示例 3: 防止删除 (`BEFORE DELETE` 触发器)

创建一个 `BEFORE DELETE` 触发器来阻止删除特定的记录，例如，不允许删除 'Human Resources' 部门的负责人。

```sql
DELIMITER $$

CREATE TRIGGER employees_before_delete
BEFORE DELETE ON employees
FOR EACH ROW
BEGIN
    -- 'OLD' 关键字引用了将要被删除的行
    IF OLD.id = (SELECT head_id FROM departments WHERE name = 'Human Resources') THEN
        -- 使用 SIGNAL SQLSTATE 抛出一个自定义错误，从而中止 DELETE 操作
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Cannot delete the head of Human Resources.';
    END IF;
END$$

DELIMITER ;
```
`SIGNAL SQLSTATE '45000'` 是一种标准的在存储过程中引发通用错误的方式，它会导致当前语句（在这里是 `DELETE`）失败。

## 管理触发器

- **查看触发器**:
  ```sql
  SHOW TRIGGERS;

  -- 筛选特定数据库的触发器
  SHOW TRIGGERS FROM my_project;

  -- 查看特定触发器的创建语句
  SHOW CREATE TRIGGER employees_after_insert;
  ```

- **删除触发器**:
  ```sql
  DROP TRIGGER IF EXISTS trigger_name;
  ```

## 触发器的优缺点和注意事项

**优点**:
- **自动化**: 自动执行复杂的业务规则和审计。
- **数据一致性**: 强制执行数据完整性规则，比应用层面的检查更可靠。

**缺点**:
- **隐蔽性**: 触发器的执行是"隐形"的，它们在后台运行，这可能使得调试和理解数据如何被修改变得困难。
- **性能开销**: 每个 `INSERT/UPDATE/DELETE` 都可能增加额外的处理开销。设计不佳的触发器会严重影响数据库性能。
- **复杂性**: 复杂的触发器链（一个触发器激活另一个）会使系统逻辑变得非常难以维护。

**使用建议**:
- 优先使用数据库的内置约束（如 `NOT NULL`, `UNIQUE`, `FOREIGN KEY`）。
- 保持触发器逻辑简单，主要用于审计、数据验证或简单的自动化任务。
- 避免在触发器中执行非常复杂或耗时的操作。
- 充分记录所有创建的触发器及其功能，以方便未来维护。 