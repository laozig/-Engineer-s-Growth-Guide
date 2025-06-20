# Redis 基本命令

Redis 提供了丰富的命令集，用于操作其数据结构和控制服务器。本文将介绍最基本的 Redis 命令，为后续学习特定数据类型的操作打下基础。

## 连接到 Redis

### 使用 redis-cli

`redis-cli` 是 Redis 自带的命令行界面工具，是与 Redis 服务器交互的最简单方式：

```bash
# 连接到本地默认端口 (6379) 的 Redis 服务器
redis-cli

# 连接到指定主机和端口的 Redis 服务器
redis-cli -h 192.168.1.100 -p 6380

# 带密码连接
redis-cli -a your_password

# 指定主机、端口和密码
redis-cli -h 192.168.1.100 -p 6380 -a your_password
```

连接后，可以使用 `PING` 命令检查连接是否正常：

```
127.0.0.1:6379> PING
PONG
```

### 使用 AUTH 命令进行认证

如果 Redis 服务器设置了密码，但你在连接时未提供密码，可以使用 `AUTH` 命令进行认证：

```
127.0.0.1:6379> AUTH your_password
OK
```

### 选择数据库

Redis 有 16 个逻辑数据库（默认），编号从 0 到 15。默认使用 0 号数据库，可以用 `SELECT` 命令切换：

```
127.0.0.1:6379> SELECT 1
OK
127.0.0.1:6379[1]>
```

## 键操作命令

### 基本键管理

```
# 检查键是否存在
EXISTS key

# 删除一个或多个键
DEL key1 [key2 ...]

# 异步删除（不阻塞）
UNLINK key1 [key2 ...]

# 设置过期时间（秒）
EXPIRE key seconds

# 设置过期时间（毫秒）
PEXPIRE key milliseconds

# 设置过期时间点（UNIX时间戳，秒）
EXPIREAT key timestamp

# 设置过期时间点（UNIX时间戳，毫秒）
PEXPIREAT key milliseconds-timestamp

# 查看剩余生存时间（秒，-1表示永不过期，-2表示键不存在）
TTL key

# 查看剩余生存时间（毫秒）
PTTL key

# 移除过期时间设置
PERSIST key

# 获取键的类型
TYPE key

# 随机返回一个键
RANDOMKEY

# 重命名键（目标键若已存在会被覆盖）
RENAME key newkey

# 仅当目标键不存在时重命名
RENAMENX key newkey

# 从当前数据库中移动键到指定数据库
MOVE key db
```

### 键模式匹配

```
# 查找符合模式的键
KEYS pattern

# 示例：
KEYS user:*       # 所有以 user: 开头的键
KEYS *2023*       # 包含 2023 的键
KEYS user:?00     # user: 后跟任意一个字符再跟 00 的键
```

> ⚠️ **警告**：`KEYS` 命令在生产环境中应谨慎使用，因为它会遍历所有键，可能阻塞服务器。

更安全的替代方案是 `SCAN` 命令：

```
# 增量迭代键
SCAN cursor [MATCH pattern] [COUNT count] [TYPE type]
```

### 批量操作

```
# 批量检查键是否存在
MKEYS key1 [key2 ...]

# 批量获取值
MGET key1 [key2 ...]

# 批量设置值
MSET key1 value1 [key2 value2 ...]

# 当且仅当所有键都不存在时批量设置值
MSETNX key1 value1 [key2 value2 ...]
```

## 服务器命令

### 服务器信息与状态

```
# 获取服务器信息
INFO [section]

# 可用的 section 包括：
# server, clients, memory, persistence, stats, replication, cpu, commandstats, cluster, keyspace

# 示例：获取内存相关信息
INFO memory

# 获取服务器统计信息
STATS

# 获取数据库中键的数量
DBSIZE

# 获取服务器时间
TIME
```

### 服务器控制

```
# 清空当前数据库
FLUSHDB

# 清空所有数据库
FLUSHALL

# 关闭服务器
SHUTDOWN [NOSAVE|SAVE]

# 将数据同步保存到磁盘
SAVE

# 异步保存数据到磁盘
BGSAVE

# 最后一次保存的状态
LASTSAVE

# 执行 Lua 脚本
EVAL script numkeys key [key ...] arg [arg ...]
```

### 慢查询分析

```
# 获取慢日志配置
CONFIG GET slowlog-*

# 设置慢日志阈值（微秒）
CONFIG SET slowlog-log-slower-than 10000

# 设置慢日志最大长度
CONFIG SET slowlog-max-len 128

# 获取慢日志
SLOWLOG GET [count]

# 重置慢日志
SLOWLOG RESET
```

### 客户端管理

```
# 列出所有连接的客户端
CLIENT LIST

# 获取当前连接的客户端ID
CLIENT ID

# 获取客户端连接名称
CLIENT GETNAME

# 设置客户端连接名称
CLIENT SETNAME connection-name

# 关闭指定客户端连接
CLIENT KILL ip:port

# 暂停所有客户端指定时间（毫秒）
CLIENT PAUSE milliseconds
```

### 配置管理

```
# 获取配置
CONFIG GET parameter

# 示例：获取所有配置
CONFIG GET *

# 设置配置
CONFIG SET parameter value

# 重写配置文件
CONFIG REWRITE
```

## 事务基础

Redis 事务允许你一次执行多个命令，保证了命令的顺序执行：

```
# 开始事务
MULTI

# 事务内命令不会立即执行，而是加入队列
SET key1 value1
SET key2 value2
INCR counter

# 执行事务中的所有命令
EXEC

# 取消事务
DISCARD
```

## 发布订阅基础

Redis 的发布/订阅功能允许实现消息通信：

```
# 订阅一个或多个频道
SUBSCRIBE channel1 [channel2 ...]

# 发布消息到频道
PUBLISH channel message

# 退订所有频道
UNSUBSCRIBE

# 退订指定频道
UNSUBSCRIBE channel1 [channel2 ...]

# 按模式订阅频道
PSUBSCRIBE pattern1 [pattern2 ...]

# 按模式退订频道
PUNSUBSCRIBE pattern1 [pattern2 ...]
```

## 监控与调试

```
# 实时监控 Redis 接收到的命令
MONITOR

# 内存使用分析
MEMORY USAGE key

# 调试对象
DEBUG OBJECT key
```

## 实用技巧

### 使用帮助命令

Redis 提供了内置的帮助系统：

```
# 获取命令分类帮助
HELP @<category>

# 可用的分类：
# @generic, @string, @list, @set, @sorted_set, @hash,
# @pubsub, @transactions, @connection, @server, @scripting, @hyperloglog

# 获取特定命令的帮助
HELP <command>

# 示例：
HELP SET
HELP @string
```

### 命令执行时间

```
# 测量命令执行时间
time <command> [arguments]

# 示例：
time get mykey
```

## 注意事项

1. Redis 命令不区分大小写，但传统上使用大写表示 Redis 命令，小写表示参数
2. 在生产环境中慎用 `KEYS`、`FLUSHALL`、`FLUSHDB` 等高耗时或破坏性命令
3. 合理使用键的过期时间，避免无限制地增长数据库
4. 使用 `MONITOR` 命令时需谨慎，它会大幅降低 Redis 的性能

## 练习示例

### 基本键操作

```
# 设置一些测试键
SET user:1 "Alice"
SET user:2 "Bob"
SET user:3 "Charlie"

# 查找键
KEYS user:*

# 检查键是否存在
EXISTS user:1
EXISTS user:4

# 重命名键
RENAME user:1 user:alice

# 设置过期时间
EXPIRE user:2 60
TTL user:2

# 删除键
DEL user:3

# 移动键到其他数据库
SELECT 0
SET item:1 "Apple"
MOVE item:1 1
EXISTS item:1
SELECT 1
EXISTS item:1
```

### 简单事务示例

```
MULTI
SET score:1 10
SET score:2 20
INCR score:1
EXEC

GET score:1   # 应返回 "11"
```

通过这些基本命令，你可以开始使用 Redis，并为学习更高级的数据类型操作打下基础。在后续章节中，我们将深入探讨各种数据类型的专用命令。 