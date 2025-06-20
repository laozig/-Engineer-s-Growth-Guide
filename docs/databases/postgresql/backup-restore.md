# 17. 备份与恢复

数据是任何应用程序的核心资产，制定一个可靠的备份和恢复策略是数据库管理中最关键的任务之一。PostgreSQL 提供了多种健壮的工具和方法来保护您的数据免受硬件故障、人为错误或灾难的影响。

本章将重点介绍两种主要的备份方法：逻辑备份（使用`pg_dump`）和物理备份（文件系统级别备份）。

## 逻辑备份 (`pg_dump` 和 `pg_dumpall`)

逻辑备份是指将数据库中的数据（包括表结构、数据、视图、函数等）提取并转储为一个或多个SQL脚本文件或归档文件。

### `pg_dump`

`pg_dump` 是用于备份**单个数据库**的标准工具。

**常用选项**:
- `-U, --username`: 连接的用户名。
- `-W, --password`: 提示输入密码。
- `-h, --host`: 数据库服务器地址。
- `-p, --port`: 数据库服务器端口。
- `-F, --format`: 输出格式 (`p`=纯文本SQL, `c`=自定义归档, `d`=目录归档, `t`=tar归档)。
- `-f, --file`: 输出文件名。

**示例1：纯文本SQL备份**
这是最简单的备份格式，生成一个大的`.sql`文件，可以用`psql`直接恢复。

```bash
pg_dump -U postgres -W -Fp my_database > my_database_backup.sql
```

**恢复方法**:
```bash
# 确保数据库存在且为空
psql -U postgres -W -d my_database -f my_database_backup.sql
```

**示例2：自定义归档格式 (`-Fc`)**
这是**推荐的备份格式**。它会生成一个压缩的二进制文件，并且在恢复时提供了极大的灵活性（可以选择性地恢复特定的表、数据或索引）。

```bash
pg_dump -U postgres -W -Fc my_database > my_database_backup.dump
```

**恢复方法**:
使用`pg_restore`工具进行恢复。

```bash
# 在恢复前，需要手动创建一个空的数据库
createdb -U postgres -W my_database_restored

# 使用pg_restore进行恢复
pg_restore -U postgres -W -d my_database_restored my_database_backup.dump
```
使用`-j`选项（例如`-j 8`）可以让`pg_restore`并行恢复，极大地加快了大型数据库的恢复速度。

### `pg_dumpall`

`pg_dumpall` 用于备份一个PostgreSQL实例中的**所有数据库**，以及全局对象（如角色和表空间）。它只输出纯文本SQL格式。

```bash
pg_dumpall -U postgres -W > all_dbs_backup.sql
```

**恢复方法**:
```bash
psql -U postgres -W -f all_dbs_backup.sql
```

## 物理备份

物理备份是指直接复制构成数据库的数据文件。这种方法通常比逻辑备份快得多，但它也更复杂，并且通常要求数据库暂时关闭或使用更高级的技术。

### 冷备份 (Offline Backup)

最简单的物理备份方法：
1.  **停止** PostgreSQL 服务。
2.  使用文件系统工具（如`cp`, `tar`, `rsync`）复制整个数据目录（Data Directory）。
3.  **启动** PostgreSQL 服务。

**恢复方法**:
1.  停止服务。
2.  用备份的文件替换掉数据目录。
3.  启动服务。

这种方法简单直接，但缺点是需要停机，不适用于需要7x24小时运行的系统。

### 时间点恢复 (Point-in-Time Recovery - PITR)

PITR 是PostgreSQL中最先进和最强大的备份恢复技术，它结合了物理基础备份和持续归档的预写式日志（WAL）。

**PITR 的工作原理**:
1.  **进行基础备份**: 在数据库运行时，使用`pg_basebackup`等工具创建一个数据目录的完整物理快照。
2.  **持续归档WAL日志**: 配置PostgreSQL，使其将所有已写满的WAL日志段文件（包含了基础备份之后的所有数据变更记录）持续地复制到一个安全的、独立的存储位置。
3.  **恢复**: 当需要恢复时：
    a. 从基础备份中恢复数据文件。
    b. 从归档位置复制所需的所有WAL日志文件。
    c. 启动PostgreSQL，它会自动"重放 (replay)"这些WAL日志，将数据库恢复到WAL日志序列中的**任意一个时间点**。

**PITR的优势**:
- **最大限度减少数据丢失**: 可以将数据库恢复到故障发生前的最后一刻。
- **灵活性**: 可以恢复到任意指定的时间点。
- **支持热备份**: 基础备份和WAL归档都在数据库运行时进行，无需停机。
- **支持流复制备库**: PITR是搭建流复制（Streaming Replication）高可用性备库的基础。

配置和管理PITR比`pg_dump`复杂得多，它需要仔细配置`postgresql.conf`中的归档参数（`archive_mode`, `archive_command`）和一个可靠的归档过程。

## 备份策略的选择

| 场景 | 推荐方法 | 理由 |
| --- | --- | --- |
| 中小型数据库，可接受分钟级停机恢复 | `pg_dump` (自定义格式) | 简单、可靠、灵活。易于在不同版本或架构的PostgreSQL间迁移。 |
| 需要备份整个实例（包括角色） | `pg_dumpall` | 一次性备份所有内容。 |
| 大型数据库 (VLDBs)，恢复时间目标(RTO)要求高 | PITR | 恢复速度快（只需重放少量WAL），备份对生产影响小。 |
| 关键业务，恢复点目标(RPO)要求接近于零 | PITR + 流复制备库 | 提供高可用性和灾难恢复能力。 |

制定一个与业务需求相匹配的备份策略，并**定期测试您的恢复过程**，是确保数据安全的关键。一个未经测试的备份等于没有备份。 