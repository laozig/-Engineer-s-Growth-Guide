# Redis Lua 脚本

Redis 从 2.6.0 版本开始引入了对 Lua 脚本的支持，这为开发者提供了一种在 Redis 服务器端执行复杂逻辑的强大方式。通过 Lua 脚本，您可以将多个操作封装成一个原子性的单元，从而减少网络延迟、提升性能，并实现事务或 Pipeline 无法完成的复杂操作。

## 为什么使用 Lua 脚本

使用 Lua 脚本主要有以下几个核心优势：

1.  **原子性操作**：Redis 会将整个脚本作为一个不可分割的单元来执行。在脚本执行期间，不会有其他命令或脚本被执行，这确保了复杂操作的原子性，避免了竞态条件。
2.  **减少网络开销**：可以将多个命令的逻辑组合在一个脚本中，通过一次网络请求发送给 Redis，而不是发送多个命令，从而显著减少了客户端与服务器之间的网络往返次数（RTT）。
3.  **可复用性**：可以将复杂的业务逻辑封装在脚本中，并将其缓存在 Redis 中。之后可以通过一个简短的 SHA1 校验和来调用，提高了代码的复用性，也使得调用更加简洁。
4.  **性能提升**：由于脚本在服务器端执行，避免了多次网络通信的开销，对于需要"读取-计算-写入"的场景，性能通常远优于在客户端执行这些步骤。

## 基本命令

### EVAL - 执行 Lua 脚本

`EVAL` 命令是执行 Lua 脚本的主要方式。

**语法：**
```
EVAL script numkeys key [key ...] arg [arg ...]
```

-   `script`：要执行的 Lua 脚本字符串。
-   `numkeys`：指定后续 `key` 参数的数量。这使得 Redis 能够正确地将脚本参数区分为键（`KEYS`）和普通参数（`ARGV`），这对于 Redis Cluster 至关重要。
-   `key [key ...]`：脚本中通过 `KEYS` 全局表（Lua table）访问的键名参数。
-   `arg [arg ...]`：脚本中通过 `ARGV` 全局表访问的普通参数。

**示例：**
```lua
-- 一个简单的 Lua 脚本，设置一个键并返回成功
> EVAL "return redis.call('SET', KEYS[1], ARGV[1])" 1 mykey "Hello, Redis!"
"OK"
```
在这个例子中：
-   `script` 是 `"return redis.call('SET', KEYS[1], ARGV[1])"`。
-   `numkeys` 是 `1`，表示有一个键 `mykey`。
-   在 Lua 脚本中，可以通过 `KEYS[1]` 访问到 `mykey`。
-   可以通过 `ARGV[1]` 访问到 `"Hello, Redis!"`。

### SCRIPT LOAD - 加载脚本到缓存

将脚本加载到 Redis 的脚本缓存中，但不立即执行。Redis 会返回该脚本的 SHA1 校验和，后续可以使用 `EVALSHA` 命令通过这个校验和来执行脚本。

**语法：**
```
SCRIPT LOAD script
```

**示例：**
```
> SCRIPT LOAD "return redis.call('GET', KEYS[1])"
"6e1bf7a8e527a2b6d510f272a255aac43dd7ce19"
```

### EVALSHA - 通过 SHA1 校验和执行脚本

执行由 `SCRIPT LOAD` 缓存的脚本。这是推荐的生产实践，可以节省网络带宽。

**语法：**
```
EVALSHA sha1 numkeys key [key ...] arg [arg ...]
```
-   `sha1`：通过 `SCRIPT LOAD` 命令得到的脚本 SHA1 校验和。

**示例：**
```
> EVALSHA 6e1bf7a8e527a2b6d510f272a255aac43dd7ce19 1 mykey
"Hello, Redis!"
```
**客户端最佳实践**：客户端通常会先尝试 `EVALSHA`。如果 Redis 返回 `NOSCRIPT` 错误（表示脚本不在缓存中），客户端再使用 `EVAL` 执行完整脚本，这样 Redis 会自动缓存它。

### SCRIPT EXISTS - 检查脚本是否存在缓存中

检查一个或多个 SHA1 校验和对应的脚本是否存在于脚本缓存中。
返回一个由 `1` (存在) 或 `0` (不存在) 组成的列表。

### SCRIPT FLUSH - 清空脚本缓存

从脚本缓存中移除所有脚本。在生产环境中应谨慎使用。

### SCRIPT KILL - 终止正在执行的脚本

终止一个长时间运行的脚本。该命令主要用于终止只读脚本。对于已经执行了写操作的脚本，`SCRIPT KILL` 无法终止它，以防止数据状态不一致。

## 在 Lua 脚本中调用 Redis 命令

在 Lua 脚本中，必须使用 `redis.call()` 或 `redis.pcall()` 函数来执行 Redis 命令。

-   `redis.call(command, key, ...)`：执行一个 Redis 命令。如果命令执行出错（例如，语法错误或对错误类型的键执行操作），`redis.call()` 会中断整个脚本的执行并向客户端返回一个错误。
-   `redis.pcall(command, key, ...)`：以保护模式（Protected Call）执行 Redis 命令。如果命令执行出错，`redis.pcall()` 会捕获错误并将其作为 Lua 表返回（包含一个 `err` 字段），脚本会继续执行。

**示例：**
```lua
-- 使用 redis.call()，如果 mykey 不是 list 类型，脚本会中断
-- EVAL "return redis.call('LPOP', KEYS[1])" 1 mykey
local result = redis.call('LPOP', KEYS[1])
return result

-- 使用 redis.pcall()，即使 mykey 不是 list 类型，脚本也会继续
-- EVAL "local result = redis.pcall('LPOP', KEYS[1]); if result.err then return 'Caught error: '..result.err else return result end" 1 mykey
local result = redis.pcall('LPOP', KEYS[1])
if result.err then
    -- 如果有错误，可以处理它，例如返回一个自定义消息
    return "Caught error: " .. result.err
end
return result
```

## Lua 与 Redis 数据类型转换

当 Lua 脚本与 Redis 交互时，数据类型会自动进行转换：

| Redis 类型         | Lua 类型                  |
| :----------------- | :------------------------ |
| Integer            | `number`                  |
| Bulk string        | `string`                  |
| Multi-bulk reply   | `table` (Lua 数组风格)    |
| Status reply       | `table` (带有 `ok` 字段)  |
| Error reply        | `table` (带有 `err` 字段) |
| Nil and Nil array  | `false` (布尔值)          |

从 Lua 返回到 Redis 的数据类型转换：

| Lua 类型                               | Redis 类型       |
| :------------------------------------- | :--------------- |
| `string` or `number`                   | Bulk string      |
| `boolean` (`true`)                     | Integer `1`      |
| `boolean` (`false`)                    | Nil reply        |
| `table` (with `ok` or `err` keys)      | Status or Error  |
| `table` (array-like, no nils)          | Multi-bulk reply |


## 实际应用场景

### 场景1：原子性的 CAS (Check-And-Set) 操作

实现一个原子性的"比较并交换"操作，只有当键的当前值与预期值相同时才设置新值。

```lua
-- 脚本
local current_value = redis.call('GET', KEYS[1])
if current_value == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2])
    return 1
else
    return 0
end
```
**调用：**
```
> EVAL "local v=redis.call('GET',KEYS[1]); if v==ARGV[1] then redis.call('SET',KEYS[1],ARGV[2]); return 1 else return 0 end" 1 mykey "old_value" "new_value"
```

### 场景2：安全的分布式锁释放

一个常见的错误是客户端在释放锁时，可能会错误地释放掉其他客户端持有的锁。安全的做法是，只有锁的持有者（通过一个唯一的随机值来标识）才能释放锁。

```lua
-- 脚本
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
else
    return 0
end
```
**调用：**
```
> EVAL "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end" 1 lock_key "unique_random_value_of_the_lock_holder"
```

### 场景3：限流器 (滑动窗口)

实现一个滑动窗口限流器，在指定时间窗口内，限制某个操作的次数。

```lua
-- 脚本
-- KEYS[1]: a unique key for the action, e.g., ratelimit:user:123
-- ARGV[1]: window size in seconds, e.g., 60
-- ARGV[2]: max requests in the window, e.g., 10

local key = KEYS[1]
local window = tonumber(ARGV[1])
local max_count = tonumber(ARGV[2])

-- `redis.call('TIME')` returns {seconds, microseconds}
local current_time = redis.call('TIME')[1]

-- Use a sorted set. Score and member are both timestamps.
-- 1. Remove timestamps outside the window
redis.call('ZREMRANGEBYSCORE', key, '-inf', current_time - window)

-- 2. Get the current number of requests in the window
local count = redis.call('ZCARD', key)

-- 3. If count is less than max, add the new request
if count < max_count then
    redis.call('ZADD', key, current_time, current_time)
    -- Set an expiration on the key to auto-clean it when idle
    redis.call('EXPIRE', key, window)
    return 1
else
    return 0
end
```
**调用：**
```
-- 限制 user:123 在 60 秒内最多只能访问 10 次
> EVAL <script_body> 1 ratelimit:user:123 60 10
```

## 脚本编写最佳实践

1.  **KEYS 和 ARGV 的正确使用**：始终通过 `KEYS` 数组传递键名，通过 `ARGV` 传递参数。这不仅是好习惯，也对未来 Redis 集群的兼容性至关重要，因为 Redis 集群需要预先知道脚本会操作哪些键。
2.  **保持脚本简洁高效**：避免在脚本中实现过于复杂的业务逻辑。脚本应专注于数据操作，而业务流程应由客户端控制。一个长时间运行的脚本会阻塞整个 Redis 服务器。
3.  **无状态脚本**：脚本应该是无状态的，其行为应仅取决于传入的 `KEYS` 和 `ARGV`。不要依赖全局变量或任何外部状态。
4.  **处理大对象需谨慎**：如果脚本操作的键包含大量数据（如一个有数百万成员的 ZSet），即使是简单的操作也可能很慢。
5.  **错误处理**：根据业务需求，合理使用 `redis.call()` 和 `redis.pcall()`。对于需要严格事务性保证的操作，`redis.call()` 更合适；对于允许部分失败的场景，`redis.pcall()` 更灵活。

## 调试 Lua 脚本

从 Redis 3.2 开始，Redis 提供了内置的 Lua 调试器 `redis-cli --ldb`。

**启动调试会话：**
```bash
redis-cli --ldb --eval /path/to/your/script.lua key1 key2 , arg1 arg2
```
调试器支持设置断点、单步执行（`s`）、打印变量值（`p`）、查看调用栈等功能，是开发复杂脚本的有力工具。

## 总结

Redis Lua 脚本是一个极其强大的功能，它将计算逻辑移到数据旁边，通过原子性执行、减少网络延迟和代码复用，极大地扩展了 Redis 的能力。无论是实现复杂的原子操作、分布式锁，还是高性能的限流器，Lua 脚本都是 Redis 高级应用中一个不可或缺的工具。 