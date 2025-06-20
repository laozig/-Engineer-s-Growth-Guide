# 17. 备份与恢复 (Backup & Restore)

数据备份是数据库管理中最关键的任务之一。有效的备份和恢复策略可以保护你的数据免受硬件故障、软件错误、人为误操作甚至恶意攻击带来的损失。

MySQL 提供了多种备份方法，主要分为逻辑备份和物理备份两大类。

## 逻辑备份 (Logical Backup)

逻辑备份将数据库中的数据转换成 SQL 语句（如 `CREATE TABLE`, `INSERT INTO`）或特定格式的文本文件（如 CSV）。

- **优点**:
    - 非常灵活，与存储引擎无关。
    - 备份文件是可读的文本，易于理解和编辑。
    - 可以在不同 MySQL 版本、不同操作系统甚至不同数据库系统之间迁移。
    - 可以只备份特定的数据库或表。
- **缺点**:
    - 备份和恢复速度通常比物理备份慢，尤其对于大型数据库。
    - 在恢复期间，数据库需要执行 SQL 语句来重建表和插入数据，这会消耗大量 CPU 和 I/O 资源。

### `mysqldump`

`mysqldump` 是 MySQL 自带的最常用的逻辑备份工具。它是一个命令行工具，可以将数据库导出为一个 `.sql` 文件。

**备份单个数据库**:
```bash
mysqldump -u [username] -p [database_name] > backup_file.sql
```
- `-u`: 用户名
- `-p`: 提示输入密码
- `>`: 将标准输出重定向到文件

**示例**:
```bash
mysqldump -u root -p my_project > my_project_backup.sql
```

**备份所有数据库**:
```bash
mysqldump -u root -p --all-databases > all_databases_backup.sql
```

**备份特定表**:
```bash
mysqldump -u root -p my_project employees departments > tables_backup.sql
```

**常用选项**:
- `--single-transaction`: 对于支持事务的存储引擎（如 InnoDB），这个选项可以在不锁定表的情况下创建一致性快照。它通过在 `mysqldump` 开始时启动一个事务来实现。这是 InnoDB 表的首选备份方式。
- `--routines`: 包含存储过程和函数。
- `--triggers`: 包含触发器。
- `--events`: 包含事件调度器。
- `--master-data=2`: 在备份文件中记录二进制日志（binlog）的文件名和位置。这对于设置主从复制或进行时间点恢复（Point-in-Time Recovery）至关重要。

**一个完整的备份命令示例**:
```bash
mysqldump -u root -p --single-transaction --routines --triggers --events --master-data=2 --all-databases > full_backup.sql
```

### 恢复逻辑备份

从 `mysqldump` 创建的 `.sql` 文件恢复数据，本质上就是执行这个 SQL 文件。

```bash
mysql -u [username] -p [database_name] < backup_file.sql
```
**示例**:
```bash
-- 1. 创建一个空的数据库 (如果需要)
mysql -u root -p -e "CREATE DATABASE my_project;"

-- 2. 将备份导入到新创建的数据库中
mysql -u root -p my_project < my_project_backup.sql
```

## 物理备份 (Physical Backup)

物理备份是直接复制数据库的原始数据文件（如 `.ibd`, `.frm` 文件、日志文件等）。

- **优点**:
    - 备份和恢复速度非常快，因为它只是文件系统的复制。
    - 对数据库服务器的资源消耗较小。
- **缺点**:
    - 不如逻辑备份灵活。通常要求恢复到相同或非常相似的 MySQL 版本、操作系统和硬件配置中。
    - 备份文件通常不可读，并且与存储引擎高度相关。

### 冷备份 (Cold Backup)

在关闭 MySQL 服务器后，直接复制整个数据目录 (`datadir`)。这是最简单但最不实用的物理备份方式，因为它要求服务中断。

### 热备份 (Hot Backup)

在服务器运行时进行备份，对线上服务影响最小。

- **XtraBackup**: 由 Percona 公司开发的开源热备份工具，是事实上的 MySQL 物理备份标准。它支持 InnoDB 和 XtraDB 存储引擎的在线备份，并且是免费的。
- **MySQL Enterprise Backup**: Oracle 提供的商业备份工具，包含在 MySQL 企业版中。

**使用 Percona XtraBackup (基本流程)**:
1.  **安装 XtraBackup**
2.  **执行备份**:
    ```bash
    xtrabackup --backup --target-dir=/path/to/backup --user=[username] --password=[password]
    ```
3.  **准备 (Prepare) 备份**: 这是恢复前的关键一步，它使数据文件达到一致状态。
    ```bash
    xtrabackup --prepare --target-dir=/path/to/backup
    ```
4.  **恢复备份**:
    ```bash
    # 确保 MySQL 服务已停止且数据目录为空
    xtrabackup --copy-back --target-dir=/path/to/backup
    # 或者使用 --move-back
    
    # 恢复文件所有权并启动 MySQL 服务
    chown -R mysql:mysql /var/lib/mysql
    systemctl start mysql
    ```

## 时间点恢复 (Point-in-Time Recovery, PITR)

PITR 允许你将数据库恢复到任意一个精确的时间点（例如，在发生误删除操作之前的一秒）。这通常通过结合**最近的全量备份**和**之后的所有二进制日志 (binlog)** 来实现。

**前提**: 必须已启用二进制日志 (`log_bin` 配置选项)。

**恢复流程**:
1.  **恢复全量备份**: 使用 `mysqldump` 或 `XtraBackup` 将数据库恢复到备份时的状态。
2.  **找到恢复的终点**: 确定误操作发生的时间点或二进制日志中的位置（position）。你可以使用 `mysqlbinlog` 工具来查看 binlog 内容。
    ```bash
    mysqlbinlog --start-datetime="YYYY-MM-DD HH:MM:SS" --stop-datetime="YYYY-MM-DD HH:MM:SS" binlog.000001
    ```
3.  **应用二进制日志**: 使用 `mysqlbinlog` 提取需要恢复的 SQL 语句，并通过管道传送给 `mysql` 客户端执行。
    ```bash
    mysqlbinlog --stop-position=12345 binlog.000001 | mysql -u root -p
    ```
    这条命令会执行从 binlog 开始到位置 `12345` 之间的所有事件。

制定一个适合你业务需求的备份策略至关重要。通常，一个好的策略是：
- **定期全量备份**（例如，每天一次物理备份）。
- **启用二进制日志**。
- **将备份和 binlog 文件存储在远程、安全的位置**。
- **定期进行恢复演练**，确保你的备份是有效的，并且你熟悉恢复流程。 