# Redis 字符串操作

字符串是 Redis 中最基本的数据类型，也是其他复杂数据结构的基础。Redis 字符串可以存储各种类型的值，包括文本、整数、浮点数、二进制数据等，最大容量为 512MB。

## 基本操作

### 设置和获取值

```
# 设置键值对
SET key value [EX seconds] [PX milliseconds] [NX|XX]
# 参数说明:
# EX seconds - 设置过期时间（秒）
# PX milliseconds - 设置过期时间（毫秒）
# NX - 仅当键不存在时设置 
# XX - 仅当键已存在时设置

# 示例:
SET user:name "Alice"
SET login:count 10
SET session:123 "active" EX 3600  # 1小时后过期
SET temp:key "value" PX 100000    # 100秒后过期
SET new:key "value" NX            # 仅当 new:key 不存在时设置
SET existing:key "new value" XX   # 仅当 existing:key 已存在时更新

# 获取值
GET key

# 示例:
GET user:name     # 返回 "Alice"
GET nonexistent   # 返回 nil 表示不存在
```

### 设置并返回旧值

```
# 设置新值并返回旧值
GETSET key value

# 示例:
SET counter 5
GETSET counter 10  # 返回 "5"，同时将 counter 设置为 10
```

### 设置过期时间

```
# 设置值同时设置过期时间（秒）
SETEX key seconds value

# 设置值同时设置过期时间（毫秒）
PSETEX key milliseconds value

# 示例:
SETEX session:token 3600 "user-session-12345"  # 1小时过期
PSETEX temp:otp 60000 "123456"                 # 60秒过期
```

### 条件设置

```
# 仅当键不存在时设置（常用于实现分布式锁）
SETNX key value

# 示例:
SETNX lock:resource1 "process-id-1234"  # 获取锁
```

### 批量操作

```
# 批量设置多个键值对
MSET key1 value1 key2 value2 ...

# 仅当所有键都不存在时批量设置
MSETNX key1 value1 key2 value2 ...

# 批量获取多个键的值
MGET key1 key2 ...

# 示例:
MSET user:1:name "Alice" user:1:email "alice@example.com" user:1:age "28"
MGET user:1:name user:1:email user:1:age  # 返回 ["Alice", "alice@example.com", "28"]
```

## 数值操作

Redis 的字符串类型可以看作整数和浮点数，支持原子递增/递减操作。

### 整数操作

```
# 将值加1（仅用于整数）
INCR key

# 将值减1（仅用于整数）
DECR key

# 将值增加指定的整数
INCRBY key increment

# 将值减少指定的整数
DECRBY key decrement

# 示例:
SET hits 0
INCR hits            # 返回 1
INCRBY hits 10       # 返回 11
DECR hits            # 返回 10
DECRBY hits 5        # 返回 5
```

### 浮点数操作

```
# 将值增加指定的浮点数
INCRBYFLOAT key increment

# 示例:
SET pi 3.14
INCRBYFLOAT pi 0.01     # 返回 3.15
INCRBYFLOAT pi -0.10    # 返回 3.05
```

## 字符串操作

### 获取和设置子串

```
# 获取子串
GETRANGE key start end

# 覆盖字符串的一部分，若key不存在则创建空字符串后再覆盖
SETRANGE key offset value

# 示例:
SET greeting "Hello world!"
GETRANGE greeting 0 4      # 返回 "Hello"
GETRANGE greeting -6 -1    # 返回 "world!" (负索引从字符串末尾开始计数)
SETRANGE greeting 6 "Redis" # 将返回 "Hello Redis!"
```

### 字符串长度

```
# 获取字符串长度
STRLEN key

# 示例:
STRLEN greeting  # 返回 12 (对于 "Hello world!")
```

### 位操作

Redis 支持基于字符串的位操作，适用于处理二进制数据和位图。

```
# 获取指定位置的位值(0或1)
GETBIT key offset

# 设置指定位置的位值
SETBIT key offset value

# 统计位值为1的位数
BITCOUNT key [start end]

# 对多个键执行按位操作并存储结果
BITOP operation destkey key1 [key2 ...]
# 操作类型: AND, OR, XOR, NOT

# 查找第一个设置或未设置的位
BITPOS key bit [start [end]]

# 示例:
SETBIT user:visits:2023-07-01 23 1  # 表示用户ID为23的用户在2023-07-01访问了网站
GETBIT user:visits:2023-07-01 23    # 返回 1
BITCOUNT user:visits:2023-07-01     # 返回设置为1的位数，表示访问用户数
```

### 追加内容

```
# 追加内容到字符串末尾
APPEND key value

# 示例:
SET message "Hello"
APPEND message " Redis!"  # 返回 12，表示新字符串长度
GET message               # 返回 "Hello Redis!"
```

## 高级应用

### 分布式锁

使用 `SETNX` 或带 NX 选项的 `SET` 命令可以实现简单的分布式锁：

```
# 获取锁
SET lock:resource "process-id" NX EX 10

# 释放锁 (使用 Lua 脚本确保原子性)
EVAL "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end" 1 lock:resource "process-id"
```

### 计数器

使用整数操作实现各种计数器：

```
# 页面访问计数器
INCR page:views:homepage

# 用户行为计数
HINCRBY user:123 login_count 1

# 限速器(每分钟)
INCR rate:limit:user:123
EXPIRE rate:limit:user:123 60
```

### 缓存

使用带过期时间的字符串缓存数据：

```
# 缓存用户资料，30分钟过期
SET cache:user:123 "{\"name\":\"Alice\",\"role\":\"admin\"}" EX 1800

# 检查并获取缓存
GET cache:user:123
```

### 会话存储

存储会话信息并设置过期时间：

```
# 保存会话
SET session:token:abc123 "{\"user_id\":123,\"logged_in\":true}" EX 3600

# 刷新会话有效期
EXPIRE session:token:abc123 3600
```

### 排行榜快照

保存排行榜的特定时间点快照：

```
# 保存每日排行榜快照
SET leaderboard:daily:2023-07-01 "{\"top\":[{\"user\":\"Alice\",\"score\":2100}]}"
```

### 消息存储

临时存储消息：

```
# 存储通知消息
SET notification:user:123 "You have a new message" EX 86400
```

## 性能注意事项

1. **大字符串处理**：
   - Redis 字符串最大可存储 512MB，但不建议存储大文件
   - 大字符串操作会阻塞服务器

2. **高频修改字符串**：
   - 字符串是不可变的，每次修改实际上都会创建新字符串
   - 大量高频修改可能导致内存碎片

3. **适用场景**：
   - 小到中等大小的文本或二进制数据
   - 自增/自减操作的计数器
   - 带过期时间的缓存内容

## 命令时间复杂度

| 命令 | 时间复杂度 |
|------|-----------|
| SET, GET, GETSET | O(1) |
| STRLEN | O(1) |
| APPEND | O(1) |
| SETRANGE, GETRANGE | O(N), N 为操作的子串长度 |
| INCR, DECR, INCRBY, DECRBY, INCRBYFLOAT | O(1) |
| MSET, MGET | O(N), N 为操作的键数量 |
| MSETNX | O(N) |
| SETBIT, GETBIT | O(1) |
| BITCOUNT | O(N), N 为字符串长度 |
| BITOP | O(N), N 为最长字符串的长度 |

## 实际应用示例

### 示例1: 用户访问计数器

```
# 增加用户访问计数
INCR user:visits:123

# 增加特定页面的访问量
HINCRBY page:stats homepage visits 1

# 获取总访问量
GET user:visits:123
```

### 示例2: 限流器

```
# 记录用户操作
INCR rate:user:123:actions
# 设置60秒过期
EXPIRE rate:user:123:actions 60

# 检查是否超过限制
GET rate:user:123:actions  # 如果大于阈值，则拒绝请求
```

### 示例3: 一次性令牌

```
# 创建一次性令牌
SET token:reset:user:123 "valid" EX 3600

# 使用令牌（使用后删除）
GETDEL token:reset:user:123  # 返回 "valid" 并删除键 (Redis 6.2+)

# 旧版本使用
GET token:reset:user:123
DEL token:reset:user:123
```

### 示例4: 使用位图追踪用户活跃度

```
# 记录用户每天的登录状态（假设用户ID为123）
SETBIT users:active:2023-07-01 123 1
SETBIT users:active:2023-07-02 123 1
SETBIT users:active:2023-07-03 0    # 未登录

# 获取用户在7月份的活跃天数
BITCOUNT users:active:2023-07-01 + users:active:2023-07-02 + ...

# 统计特定日期的活跃用户数
BITCOUNT users:active:2023-07-01
```

### 示例5: 实现简单的缓存

```
# 检查缓存是否存在
EXISTS cache:user:profile:123

# 获取缓存
GET cache:user:profile:123

# 设置缓存，10分钟过期
SET cache:user:profile:123 "{\"name\":\"Alice\",\"bio\":\"Redis expert\"}" EX 600
```

## 总结

Redis 字符串操作提供了灵活而强大的功能，可以用于多种场景：

- 简单键值存储
- 计数器和限流器
- 缓存和会话管理
- 位操作和二进制数据处理

合理利用字符串操作及其相关特性，可以为应用程序提供高效、可扩展的数据处理能力。记得根据实际需求选择合适的命令和数据结构，并合理设置过期时间，以优化性能和内存使用。 