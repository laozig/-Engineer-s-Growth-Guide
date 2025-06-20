# Redis 持久化

Redis 提供了两种主要的持久化机制，用于在服务器重启后恢复数据。这两种机制分别是 RDB（Redis Database）和 AOF（Append Only File）。它们各有优缺点，可以单独使用，也可以结合使用。

## 目录
- [RDB (Redis Database)](#rdb-redis-database)
  - [工作原理](#工作原理)
  - [优点](#优点)
  - [缺点](#缺点)
  - [相关配置](#相关配置)
- [AOF (Append Only File)](#aof-append-only-file)
  - [工作原理](#工作原理-1)
  - [优点](#优点-1)
  - [缺点](#缺点-1)
  - [AOF 重写](#aof-重写)
  - [相关配置](#相关配置-1)
- [RDB 与 AOF 的选择](#rdb-与-aof-的选择)
- [RDB 与 AOF 的交互](#rdb-与-aof-的交互)
- [最佳实践](#最佳实践)

---

## RDB (Redis Database)

RDB 持久化通过在指定的时间间隔内生成数据集的时间点快照（point-in-time snapshot）来工作。

### 工作原理

当满足预设的触发条件（如 `save 900 1`，表示900秒内至少有1个键被修改）时，Redis 会自动执行 `BGSAVE` 命令。`BGSAVE` 会 `fork` 一个子进程，子进程负责将内存中的数据写入一个临时的 RDB 文件。当子进程完成写入后，它会用这个临时文件替换掉旧的 RDB 文件。整个过程主进程继续处理客户端请求，不受影响。

手动执行的命令：
- `SAVE`: 阻塞 Redis 服务器，直到 RDB 文件创建完毕。在生产环境中应避免使用。
- `BGSAVE`: `fork` 一个子进程在后台创建 RDB 文件，服务器可以继续处理请求。

### 优点

1.  **性能**：由于 `BGSAVE` 创建子进程来执行持久化，主进程的性能基本不受影响。
2.  **文件紧凑**：RDB 文件是一个经过压缩的二进制文件，体积小，非常适合备份、归档和灾难恢复。
3.  **恢复速度快**：与 AOF 相比，加载 RDB 文件进行数据恢复的速度更快，因为它直接将数据解析到内存中，无需逐条执行命令。

### 缺点

1.  **数据丢失风险**：RDB 是按时间间隔进行快照的。如果在两次快照之间 Redis 发生故障，那么这期间的所有数据修改都将丢失。
2.  **`fork()` 开销**：当数据集较大时，`fork()` 子进程可能会消耗较多的时间和内存，甚至导致服务器在 `fork()` 期间短暂地停止服务。

### 相关配置 (`redis.conf`)

```conf
# 格式：save <seconds> <changes>
# 表示在 <seconds> 秒内，如果至少有 <changes> 个键被修改，则自动触发 BGSAVE
save 900 1
save 300 10
save 60 10000

# 当 BGSAVE 出错时，是否停止写入操作
stop-writes-on-bgsave-error yes

# 是否对 RDB 文件使用 LZF 压缩
rdbcompression yes

# 是否在写入 RDB 文件后进行 CRC64 校验
rdbchecksum yes

# RDB 文件的名称
dbfilename dump.rdb

# RDB 文件的存放目录
dir ./
```

---

## AOF (Append Only File)

AOF 持久化记录服务器接收到的每一个写操作命令，并在服务器启动时通过重新执行这些命令来恢复数据集。

### 工作原理

当 AOF 功能开启后，所有写命令都会被追加到 AOF 文件的末尾。当 Redis 重启时，它会读取 AOF 文件并重新执行所有记录的写命令，从而将数据恢复到内存中。

### 优点

1.  **数据持久性更高**：AOF 提供了多种同步策略（`always`, `everysec`, `no`），其中 `everysec`（每秒同步）是默认策略，即使发生故障，最多也只会丢失1秒的数据。
2.  **日志文件可读**：AOF 文件是一个纯文本文件，包含了所有写命令，易于理解和解析。在紧急情况下，可以手动编辑 AOF 文件来修复错误。

### 缺点

1.  **文件体积更大**：对于相同的数據集，AOF 文件通常比 RDB 文件大。
2.  **恢复速度较慢**：数据恢复需要重新执行所有写命令，当 AOF 文件很大时，恢复速度会比 RDB 慢。
3.  **性能开销**：根据 `fsync` 策略的不同，AOF 可能会对性能产生影响，尤其是 `always` 策略，会显著降低 Redis 的 QPS。

### AOF 重写

随着写操作的增加，AOF 文件会越来越大。Redis 提供了 AOF 重写（rewrite）功能来解决这个问题。AOF 重写会创建一个新的、更紧凑的 AOF 文件，其中只包含恢复当前数据集所需的最少命令集。

例如，对一个计数器执行100次 `INCR`，在旧的 AOF 文件中有100条记录，但重写后的新文件中可能只有一条 `SET` 命令。

AOF 重写也是通过 `fork` 子进程在后台完成的，不会阻塞主进程。

### 相关配置 (`redis.conf`)

```conf
# 是否开启 AOF
appendonly yes

# AOF 文件名
appendfilename "appendonly.aof"

# AOF 同步策略
# appendfsync always  # 每个写命令都同步，最安全但最慢
appendfsync everysec # 每秒同步一次，默认值，兼顾性能和安全
# appendfsync no      # 由操作系统决定何时同步，最快但最不安全

# 在 AOF 重写期间，是否禁止对主进程进行 fsync
no-appendfsync-on-rewrite no

# 触发 AOF 重写的条件
auto-aof-rewrite-percentage 100 # 当前 AOF 文件大小比上次重写后的大小增长了100%
auto-aof-rewrite-min-size 64mb  # 触发重写的最小 AOF 文件大小
```

---

## RDB 与 AOF 的选择

| 场景 | 推荐 | 原因 |
| :--- | :--- | :--- |
| **数据备份、灾难恢复** | RDB | RDB 文件紧凑，易于传输，恢复速度快。 |
| **追求最高数据安全性** | AOF | AOF 提供了更好的数据持久性，最多丢失1秒的数据。 |
| **性能优先** | RDB | RDB 的 `BGSAVE` 对主进程性能影响较小。 |
| **一般情况** | **两者都开启** | 结合 RDB 和 AOF 的优点，提供更健壮的持久化方案。 |

**官方建议：同时开启 RDB 和 AOF。** 这样既可以利用 RDB 进行快速恢复和备份，又可以利用 AOF 保证数据的高持久性。

## RDB 与 AOF 的交互

当 RDB 和 AOF 都开启时，Redis 在启动时会**优先使用 AOF 文件**来恢复数据，因为 AOF 文件通常包含更完整的数据。

从 Redis 4.0 开始，AOF 重写引入了混合持久化的概念 (`aof-use-rdb-preamble yes`)。当开启此功能时，AOF 重写会生成一个以 RDB 格式开头，后跟增量 AOF 命令的文件。这样做的好处是，在加载时可以先快速加载 RDB 部分，然后再加载增量的 AOF 部分，从而显著提高了恢复速度。

## 最佳实践

1.  **同时使用 RDB 和 AOF**：为了获得最佳的数据安全性和恢复性能，建议同时启用这两种持久化方式。
2.  **定期备份 RDB 文件**：将 RDB 文件定期备份到安全的、异地的数据中心，以防硬件故障。
3.  **合理配置 `save` 和 `appendfsync`**：根据业务对数据安全性的要求和性能的敏感度，选择合适的策略。对于大多数应用，`save 900 1` 和 `appendfsync everysec` 是一个不错的起点。
4.  **监控 `fork()` 开销**：监控 Redis 的 `latest_fork_usec` 指标，了解 `BGSAVE` 和 `BGREWRITEAOF` 的耗时。如果耗时过长，考虑优化实例内存或使用物理机。
5.  **设置合理的 `auto-aof-rewrite-min-size`**：避免因 AOF 文件太小而频繁触发重写。
6.  **确保磁盘空间充足**：AOF 重写需要额外的磁盘空间。确保可用空间至少是当前 AOF 文件大小的两倍。 