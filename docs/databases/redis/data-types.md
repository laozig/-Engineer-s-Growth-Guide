# Redis 数据类型

Redis 以其丰富的数据类型和相关操作而闻名，这是它区别于简单键值存储系统的核心特性。本文将介绍 Redis 支持的所有数据类型、它们的主要特点和使用场景。

## 目录

- [核心数据类型](#核心数据类型)
  - [字符串 (String)](#字符串-string)
  - [列表 (List)](#列表-list)
  - [集合 (Set)](#集合-set)
  - [有序集合 (Sorted Set)](#有序集合-sorted-set)
  - [哈希表 (Hash)](#哈希表-hash)
- [特殊数据类型](#特殊数据类型)
  - [位图 (Bitmap)](#位图-bitmap)
  - [超日志 (HyperLogLog)](#超日志-hyperloglog)
  - [地理空间 (Geospatial)](#地理空间-geospatial)
  - [流 (Stream)](#流-stream)
- [数据类型的选择](#数据类型的选择)

## 核心数据类型

Redis 提供了五种核心数据类型，它们是 Redis 最基础和常用的数据结构。

### 字符串 (String)

字符串是 Redis 中最基本的数据类型，可以存储文本、序列化对象或二进制数据。

**特点**：
- 二进制安全，最大可存储 512MB 数据
- 可以存储各种类型的数据：文本、整数、浮点数、二进制等
- 支持原子递增/递减操作

**常用命令**：
```
SET key value       # 设置键值
GET key             # 获取键值
INCR key            # 将整数值加1
DECR key            # 将整数值减1
INCRBY key amount   # 将整数值增加指定数量
DECRBY key amount   # 将整数值减少指定数量
APPEND key value    # 在字符串末尾追加内容
STRLEN key          # 返回字符串长度
GETRANGE key s e    # 获取子字符串
```

**应用场景**：
- 缓存页面和 API 响应
- 计数器（如访问量、点赞数）
- 分布式锁
- 会话存储

**内部实现**：
根据内容不同，字符串可能使用以下编码：
- int：对于整数值
- embstr：小于等于44字节的字符串
- raw：大于44字节的字符串

### 列表 (List)

列表是简单的字符串列表，按照插入顺序排序，支持两端操作。

**特点**：
- 有序序列，基于链表实现
- 支持两端的高效插入和删除操作
- 支持范围操作和阻塞操作

**常用命令**：
```
LPUSH key value     # 在左侧添加元素
RPUSH key value     # 在右侧添加元素
LPOP key            # 从左侧弹出元素
RPOP key            # 从右侧弹出元素
LLEN key            # 获取列表长度
LRANGE key s e      # 获取指定范围的元素
BLPOP key timeout   # 阻塞式左侧弹出
BRPOP key timeout   # 阻塞式右侧弹出
```

**应用场景**：
- 消息队列
- 最新动态列表
- 任务调度系统
- 社交媒体时间线

**内部实现**：
- quicklist：组合使用压缩列表和双向链表的混合结构

### 集合 (Set)

集合是无序的字符串集合，不允许有重复元素。

**特点**：
- 无序性，不允许重复
- 支持并集、交集、差集等集合操作
- 高效的成员检测

**常用命令**：
```
SADD key member     # 添加成员
SREM key member     # 删除成员
SMEMBERS key        # 获取所有成员
SISMEMBER key mem   # 检查成员是否存在
SCARD key           # 获取集合大小
SINTER key1 key2    # 集合交集
SUNION key1 key2    # 集合并集
SDIFF key1 key2     # 集合差集
SRANDMEMBER key n   # 随机获取n个成员
```

**应用场景**：
- 用户标签
- 社交关系（好友、关注者）
- 黑名单/白名单
- 随机抽样

**内部实现**：
- intset：当所有元素都是整数且数量小于一定值时
- hashtable：其他情况

### 有序集合 (Sorted Set)

有序集合类似于集合，但每个成员关联一个分数，用于排序。

**特点**：
- 每个元素关联一个浮点数分数
- 元素按分数排序
- 支持范围查询和排名操作

**常用命令**：
```
ZADD key score mem      # 添加成员和分数
ZREM key member         # 删除成员
ZSCORE key member       # 获取成员分数
ZRANK key member        # 获取成员排名
ZRANGE key s e          # 按排名获取范围内成员
ZRANGEBYSCORE k min max # 按分数获取范围内成员
ZINCRBY key inc member  # 增加成员分数
```

**应用场景**：
- 排行榜和计分板
- 优先级队列
- 带权重的任务调度
- 时间轴索引

**内部实现**：
- ziplist：元素数量少且成员长度小时
- skiplist+hashtable：其他情况

### 哈希表 (Hash)

哈希表存储字段-值对的映射，类似小型数据库表。

**特点**：
- 存储对象字段和值的映射
- 高效的字段读写
- 支持增量更新

**常用命令**：
```
HSET key field value    # 设置字段值
HGET key field          # 获取字段值
HMSET key f1 v1 f2 v2   # 批量设置多个字段
HMGET key field1 field2 # 批量获取多个字段
HGETALL key             # 获取所有字段和值
HDEL key field          # 删除字段
HEXISTS key field       # 检查字段是否存在
HINCRBY key field inc   # 增加字段值
```

**应用场景**：
- 用户信息缓存
- 购物车系统
- 实时计数和统计
- 数据库行缓存

**内部实现**：
- ziplist：字段数量少且字段和值长度小时
- hashtable：其他情况

## 特殊数据类型

除了核心数据类型，Redis 还提供了几种特殊的数据类型，用于特定场景。

### 位图 (Bitmap)

位图允许对字符串值进行位操作，适用于状态标记和计数。

**特点**：
- 节省空间，每个位只占用1 bit
- 支持按位置设置和获取
- 提供位计数操作

**常用命令**：
```
SETBIT key offset value # 设置位值
GETBIT key offset       # 获取位值
BITCOUNT key [s] [e]    # 计算位为1的数量
BITOP op destkey keys   # 位操作(AND/OR/XOR/NOT)
```

**应用场景**：
- 用户活跃状态跟踪
- 判断是否签到
- 布隆过滤器的实现
- 实时统计数据

### 超日志 (HyperLogLog)

HyperLogLog 用于估计集合中不重复元素的数量（基数统计）。

**特点**：
- 极低的内存占用（每个 HyperLogLog 仅需 12KB）
- 提供近似的基数统计
- 有约 0.81% 的标准误差

**常用命令**：
```
PFADD key element       # 添加元素
PFCOUNT key             # 获取基数估计
PFMERGE destkey keys    # 合并多个HyperLogLog
```

**应用场景**：
- 网站独立访客计数
- 大数据集去重
- 流量统计

### 地理空间 (Geospatial)

地理空间类型存储经纬度坐标，支持各种地理相关查询。

**特点**：
- 存储地理坐标（经度、纬度）
- 支持范围查询和距离计算
- 可根据距离排序

**常用命令**：
```
GEOADD key lon lat mem      # 添加地理位置
GEOPOS key member           # 获取位置坐标
GEODIST key m1 m2 [unit]    # 计算两点距离
GEORADIUS key lon lat rad   # 查找指定半径内的点
```

**应用场景**：
- 附近的人/餐厅/商店
- 位置共享应用
- 打车服务
- 地理围栏

### 流 (Stream)

流是 Redis 5.0 引入的新数据类型，专为消息队列场景设计。

**特点**：
- 持久性的消息队列
- 支持消费组模式
- 提供阻塞读取和自动确认

**常用命令**：
```
XADD key ID field value     # 添加消息
XREAD COUNT c STREAMS key ID # 读取消息
XGROUP CREATE k g start     # 创建消费组
XREADGROUP GROUP g c COUNT n STREAMS k ID # 消费组读取
XACK key group ID           # 确认消息处理
```

**应用场景**：
- 消息中间件
- 时序数据处理
- 事件溯源
- 日志管理

## 数据类型的选择

为特定用例选择合适的数据类型时，应考虑以下因素：

1. **数据访问模式**：读多或写多？随机访问还是顺序访问？
2. **数据组织**：自然组织方式是什么？
3. **性能需求**：需要什么操作最高效？
4. **内存占用**：数据大小和数量
5. **复杂性**：操作的复杂度

以下是一些常见使用场景的推荐数据类型：

| 使用场景 | 推荐数据类型 | 原因 |
|---------|------------|------|
| 缓存数据 | String | 简单高效，通用性强 |
| 计数器 | String | 原子递增/递减操作 |
| 消息队列（简单） | List | LPUSH + RPOP模式 |
| 消息队列（高级） | Stream | 持久性、消费组、确认机制 |
| 排行榜 | Sorted Set | 自动排序和范围查询 |
| 用户会话 | Hash | 单个键下多字段，便于部分更新 |
| 用户关系 | Set | 集合操作适合关系计算 |
| 地理位置查询 | Geospatial | 原生地理空间功能 |
| 唯一访客统计 | HyperLogLog | 大数据集去重、内存高效 |
| 实时分析 | Bitmap | 位操作适合状态标记和计数 |

## 小结

Redis 丰富的数据类型是其强大功能的基础。通过了解每种数据类型的特点、内部实现和适用场景，可以更高效地利用 Redis 解决各种问题。选择正确的数据类型不仅可以简化应用程序逻辑，还能显著提高性能并减少内存使用。

在接下来的章节中，我们将深入探讨各种数据类型的具体操作命令和高级使用模式，帮助您充分发挥 Redis 的潜力。 