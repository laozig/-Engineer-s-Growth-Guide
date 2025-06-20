# MySQL 主从复制

MySQL 主从复制是一种允许数据从一个 MySQL 数据库服务器（主服务器）复制到一个或多个 MySQL 数据库服务器（从服务器）的技术。这是实现数据备份、高可用性和扩展系统读取能力的重要手段，在大型应用和企业级数据库解决方案中被广泛使用。

## 目录

- [主从复制概述](#主从复制概述)
- [复制的工作原理](#复制的工作原理)
- [主从复制的配置步骤](#主从复制的配置步骤)
- [复制拓扑结构](#复制拓扑结构)
- [复制模式](#复制模式)
- [复制过滤](#复制过滤)
- [监控与问题排查](#监控与问题排查)
- [最佳实践](#最佳实践)

## 主从复制概述

### 主从复制的主要用途

1. **数据备份**：创建数据的实时副本，作为灾难恢复的一部分
2. **读写分离**：将读请求分发到从服务器，写请求发送到主服务器
3. **数据分析**：可以在从服务器上运行报表查询，避免影响主服务器性能
4. **地理分布**：将数据副本放置在接近用户的地理位置，减少访问延迟

### 主从复制的优势

- 提高系统可用性
- 实现负载均衡
- 确保数据安全
- 支持横向扩展

## 复制的工作原理

MySQL 主从复制基于以下三个关键组件：

1. **二进制日志（Binary Log）**：主服务器记录所有更改数据库的语句或实际数据变化
2. **中继日志（Relay Log）**：从服务器将主服务器的二进制日志复制到本地的中继日志
3. **SQL 线程**：从服务器读取中继日志并重放其中的事件

复制过程分为三个阶段：

1. **主服务器将更改写入二进制日志**
2. **从服务器将主服务器的二进制日志复制到中继日志**
3. **从服务器执行中继日志中的事件**

## 主从复制的配置步骤

### 1. 配置主服务器

编辑 `my.cnf` 配置文件：

```ini
[mysqld]
server-id = 1
log_bin = mysql-bin
binlog_format = ROW  # 或 STATEMENT 或 MIXED
```

创建复制用户：

```sql
CREATE USER 'repl'@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%';
FLUSH PRIVILEGES;
```

获取主服务器状态：

```sql
SHOW MASTER STATUS;
```

记下 File 和 Position 的值，后续配置从服务器时需要用到。

### 2. 准备从服务器数据

可以使用以下方法之一：

- 使用备份工具（如 mysqldump）创建主服务器的备份并恢复到从服务器
- 使用物理备份工具（如 Percona XtraBackup）
- 克隆已存在的服务器

对于 mysqldump 方法：

```bash
# 在主服务器上
mysqldump --all-databases --master-data=2 > dbdump.sql

# 将备份文件传输到从服务器并恢复
mysql < dbdump.sql
```

### 3. 配置从服务器

编辑从服务器的 `my.cnf` 文件：

```ini
[mysqld]
server-id = 2  # 确保每个从服务器的ID唯一
relay_log = /var/lib/mysql/mysql-relay-bin
log_slave_updates = 1  # 如果从服务器也作为其他服务器的主服务器
read_only = 1  # 避免意外写入
```

配置从服务器指向主服务器：

```sql
CHANGE MASTER TO
  MASTER_HOST='主服务器IP',
  MASTER_USER='repl',
  MASTER_PASSWORD='password',
  MASTER_LOG_FILE='mysql-bin.000001',  # 来自SHOW MASTER STATUS的输出
  MASTER_LOG_POS=154;                  # 来自SHOW MASTER STATUS的输出

START SLAVE;
```

### 4. 验证复制状态

在从服务器上检查复制状态：

```sql
SHOW SLAVE STATUS\G
```

确保以下字段显示正常：
- `Slave_IO_Running: Yes`
- `Slave_SQL_Running: Yes`
- `Seconds_Behind_Master` 值不断减小，最终为0

## 复制拓扑结构

MySQL 支持多种复制拓扑结构：

1. **一主多从**：最常见的结构，一个主服务器与多个从服务器
2. **主主复制**：两个服务器互为主从，实现双向复制
3. **级联复制**：从服务器作为其他从服务器的主服务器
4. **环形复制**：多个服务器形成环状复制结构
5. **主 - 中继主 - 从**：引入中间层以减轻主服务器负担

## 复制模式

MySQL 支持三种复制模式：

### 1. 基于语句的复制 (Statement-based Replication, SBR)

复制在主服务器上执行的SQL语句：

```ini
binlog_format = STATEMENT
```

优点：
- 日志文件小
- 不需要记录每行的变化

缺点：
- 某些函数（如 UUID(), NOW()）在不同服务器上结果不同
- 行锁等信息无法复制

### 2. 基于行的复制 (Row-based Replication, RBR)

复制行的实际变化：

```ini
binlog_format = ROW
```

优点：
- 更安全，所有变化都被精确复制
- 支持所有SQL语句类型

缺点：
- 二进制日志可能会很大
- 特别是在大表上执行 UPDATE 或 DELETE

### 3. 混合模式 (Mixed Replication)

结合上述两种模式的优点：

```ini
binlog_format = MIXED
```

- 默认使用基于语句的复制
- 当检测到语句可能导致数据不一致时，自动切换到基于行的复制

## 复制过滤

可以配置复制过滤规则，只复制特定数据库或表：

### 主服务器过滤

在主服务器的 `my.cnf` 文件中：

```ini
binlog-do-db=database1
binlog-ignore-db=database2
```

### 从服务器过滤

在从服务器的 `my.cnf` 文件中：

```ini
replicate-do-db=database1
replicate-ignore-db=database2
replicate-do-table=database.table1
replicate-wild-ignore-table=database.test%
```

## 监控与问题排查

### 常见问题

1. **复制延迟**：`Seconds_Behind_Master` 值很大
   - 解决方法：增加从服务器配置，优化查询，使用并行复制

2. **复制错误**：`Slave_SQL_Running: No`
   - 解决方法：检查错误日志，修复不一致，跳过问题事件

### 监控复制

1. **使用 MySQL 命令**：
   ```sql
   SHOW SLAVE STATUS\G
   ```

2. **使用监控工具**：
   - MySQL Enterprise Monitor
   - Percona Monitoring and Management
   - Prometheus 与 Grafana

3. **关键指标**：
   - 复制延迟（秒数）
   - I/O 和 SQL 线程状态
   - 二进制日志和中继日志的大小

## 最佳实践

1. **使用唯一的 server-id**：确保每个服务器有唯一的ID

2. **启用 GTID 复制**（适用于MySQL 5.6+）：
   ```ini
   gtid_mode = ON
   enforce_gtid_consistency = ON
   ```

3. **启用半同步复制**：确保至少有一个从服务器接收事务
   ```sql
   INSTALL PLUGIN rpl_semi_sync_master SONAME 'semisync_master.so';
   SET GLOBAL rpl_semi_sync_master_enabled = 1;
   ```

4. **定期备份从服务器**：不要仅依赖复制作为备份策略

5. **监控复制延迟**：设置警报系统以便及时发现复制问题

6. **为复制账户使用安全密码**：定期更改复制账户密码

7. **考虑使用 SSL 加密复制流量**：保护敏感数据在网络中传输

## 总结

主从复制是 MySQL 中的关键功能，为数据库提供了高可用性、可扩展性和灾难恢复能力。通过合理配置和维护复制拓扑，可以显著提高系统性能和数据安全性。随着应用规模的增长，合理的复制策略将变得越来越重要。
