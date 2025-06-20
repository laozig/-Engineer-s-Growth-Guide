# 12. 事务处理 (Transactions)

事务（Transaction）是数据库管理系统（DBMS）执行过程中的一个逻辑单位，它由一个有限的数据库操作序列构成。事务处理是确保数据完整性和一致性的关键机制，尤其是在多用户并发访问的环境中。

InnoDB 存储引擎是 MySQL 中支持事务的标准引擎。

## ACID 属性

一个设计良好的事务性数据库系统，必须满足 ACID 四个特性：

1.  **原子性 (Atomicity)**
    - 事务是一个不可分割的工作单位。事务中的所有操作，要么**全部成功**，要么**全部失败**（回滚到事务开始前的状态）。
    - 比如，在一个银行转账事务中，从一个账户扣款和向另一个账户存款这两个操作必须同时成功或同时失败。不能只发生一个。

2.  **一致性 (Consistency)**
    - 事务必须使数据库从一个一致性状态转变到另一个一致性状态。
    - 事务开始前和结束后，数据库的完整性约束（如主键、外键、唯一性约束）没有被破坏。
    - 例如，在转账事务后，两个账户的总金额应该保持不变，这维持了业务规则的一致性。

3.  **隔离性 (Isolation)**
    - 并发执行的多个事务之间应该相互隔离，一个事务的执行不应被其他事务干扰。
    - 就像每个事务都在一个独立的、私有的数据库副本上操作一样。
    - 数据库通过锁机制和多版本并发控制（MVCC）来实现隔离。为了平衡性能和隔离程度，SQL 标准定义了四种隔离级别。

4.  **持久性 (Durability)**
    - 一旦事务被提交，它对数据库中数据的改变就应该是**永久性**的。
    - 即使系统发生崩溃（如断电或服务器宕机），已提交的事务结果也不应丢失。这通常通过将事务日志写入非易失性存储（如硬盘）来实现。

## 事务控制语句

MySQL 使用以下语句来控制事务：

- **`START TRANSACTION`** 或 **`BEGIN`**: 显式地开始一个新事务。
- **`COMMIT`**: 提交事务。将事务中所有已执行的操作永久保存到数据库中。
- **`ROLLBACK`**: 回滚事务。撤销事务中所有已执行的操作，使数据库恢复到事务开始前的状态。
- **`SAVEPOINT identifier`**: 在事务内部创建一个保存点。
- **`ROLLBACK TO SAVEPOINT identifier`**: 回滚到指定的保存点，而不是整个事务。
- **`RELEASE SAVEPOINT identifier`**: 删除一个保存点。

**自动提交 (Autocommit)**:
- 默认情况下，MySQL 运行在 `autocommit` 模式下。这意味着每条 SQL 语句都被视为一个独立的事务，并被立即执行和提交。
- 要执行多语句事务，你必须先禁用自动提交或使用 `START TRANSACTION`。
  - `SET autocommit = 0;`  -- 禁用当前会话的自动提交
  - `SET autocommit = 1;`  -- 启用自动提交

## 事务处理示例

假设我们要执行一个银行转账操作：从账户 A（ID=1）转 500 元到账户 B（ID=2）。

```sql
-- accounts 表结构
CREATE TABLE accounts (
    id INT PRIMARY KEY,
    owner_name VARCHAR(100),
    balance DECIMAL(10, 2)
);
INSERT INTO accounts VALUES (1, 'Alice', 2000.00), (2, 'Bob', 5000.00);
```

**成功的事务**:
```sql
-- 开始事务
START TRANSACTION;

-- 1. 检查 Alice 的余额是否足够
-- (在实际应用中，这部分逻辑通常在应用层完成)
-- SELECT balance FROM accounts WHERE id = 1;

-- 2. 从 Alice 账户扣款
UPDATE accounts SET balance = balance - 500 WHERE id = 1;

-- 3. 向 Bob 账户存款
UPDATE accounts SET balance = balance + 500 WHERE id = 2;

-- 4. 提交事务，使更改永久生效
COMMIT;
```
如果在 `COMMIT` 之前发生任何错误或连接中断，数据库会自动回滚，两个账户的余额都不会改变。

**失败并回滚的事务**:
```sql
START TRANSACTION;

UPDATE accounts SET balance = balance - 500 WHERE id = 1;

-- 假设此时发生了一个错误，比如数据库服务器崩溃，或者我们手动回滚
-- ... 错误发生 ...

-- 手动回滚
ROLLBACK;
```
执行 `ROLLBACK` 后，Alice 的账户将恢复到 `2000.00`。

## 事务隔离级别 (Isolation Levels)

隔离性是 ACID 中最复杂的特性。为了在性能和一致性之间取得平衡，SQL 标准定义了四种隔离级别。级别越高，数据一致性越好，但并发性能可能越低。

| 隔离级别 | 脏读 (Dirty Read) | 不可重复读 (Non-Repeatable Read) | 幻读 (Phantom Read) |
| :--- | :--- | :--- | :--- |
| **读未提交 (Read Uncommitted)** | 可能 | 可能 | 可能 |
| **读已提交 (Read Committed)** | 不允许 | 可能 | 可能 |
| **可重复读 (Repeatable Read)** | 不允许 | 不允许 | 可能 |
| **可串行化 (Serializable)** | 不允许 | 不允许 | 不允许 |

- **脏读**: 一个事务读取到了另一个未提交事务修改的数据。
- **不可重复读**: 在同一个事务中，两次读取同一行数据，但得到了不同的结果，因为在这两次读取之间，有另一个事务提交了对该行的修改。
- **幻读**: 在同一个事务中，两次执行相同的查询，但第二次查询返回了更多的行，因为在这两次查询之间，有另一个事务插入了新的、符合查询条件的行（"幻影"行）。

**MySQL (InnoDB) 的默认隔离级别是 `可重复读 (Repeatable Read)`**。值得注意的是，InnoDB 通过多版本并发控制 (MVCC) 和 `next-key` 锁，在默认的 `可重复读` 级别下，很大程度上**避免了幻读**的发生。

**查看和设置隔离级别**:
```sql
-- 查看全局隔离级别
SELECT @@global.transaction_isolation;

-- 查看当前会话的隔离级别
SELECT @@session.transaction_isolation;

-- 设置当前会话的隔离级别为"读已提交"
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;
```

理解并正确使用事务是开发可靠、健壮的数据库应用的基础。 