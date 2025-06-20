# Redis 哈希表操作

Redis 哈希表（Hash）是键值对的集合，是字符串字段和字符串值之间的映射，非常适合用来表示对象。每个 Hash 可以存储 2^32 - 1 个键值对（约 40 亿）。

## 基本概念

- **哈希表结构**：由字段(field)和值(value)组成的映射表，类似于 JSON 对象或编程语言中的字典/Map
- **特点**：同一个哈希表下可以有多个字段，每个字段对应一个值
- **内存效率**：相比于将对象每个属性单独存为 String 类型，哈希表的内存占用更低
- **适用场景**：存储对象数据，如用户信息、产品详情、配置项等

## 基本操作

### 设置字段值

```
# 设置单个字段的值
HSET key field value

# 设置多个字段的值
HSET key field1 value1 [field2 value2 ...]

# 返回值：设置的新字段数量（不包括更新的字段）

# 示例：
HSET user:1000 name "张三" age 28 email "zhangsan@example.com" city "北京"  # 返回 4（设置了4个新字段）
HSET user:1000 age 29 title "工程师"  # 返回 1（更新了1个字段，新增了1个字段）
```

### 仅当字段不存在时设置

```
# 仅当字段不存在时设置其值
HSETNX key field value

# 返回值：1表示设置成功，0表示字段已存在，未执行操作

# 示例：
HSETNX user:1000 name "李四"  # 返回 0（name字段已存在，未更改）
HSETNX user:1000 phone "13800138000"  # 返回 1（字段不存在，设置成功）
```

### 获取字段值

```
# 获取单个字段的值
HGET key field

# 返回值：字段的值，如果字段或键不存在则返回nil

# 示例：
HGET user:1000 name  # 返回 "张三"
HGET user:1000 address  # 返回 nil（字段不存在）
```

### 检查字段是否存在

```
# 判断字段是否存在
HEXISTS key field

# 返回值：1表示字段存在，0表示字段不存在

# 示例：
HEXISTS user:1000 name  # 返回 1
HEXISTS user:1000 address  # 返回 0
```

### 删除字段

```
# 删除一个或多个字段
HDEL key field [field ...]

# 返回值：成功删除的字段数量

# 示例：
HDEL user:1000 title phone  # 返回 2（假设两个字段都存在）
HDEL user:1000 address  # 返回 0（字段不存在）
```

### 获取字段数量

```
# 获取哈希表中字段的数量
HLEN key

# 返回值：字段数量

# 示例：
HLEN user:1000  # 返回哈希表中的字段数量
```

## 批量操作

### 批量获取字段值

```
# 获取多个字段的值
HMGET key field [field ...]

# 返回值：一个数组，包含所有请求字段的值，对应不存在的字段返回nil

# 示例：
HMGET user:1000 name age email address  # 返回 ["张三", "29", "zhangsan@example.com", nil]
```

### 获取所有字段和值

```
# 获取哈希表中的所有字段和值
HGETALL key

# 返回值：字段和值的列表，交替出现

# 示例：
HGETALL user:1000  # 返回 ["name", "张三", "age", "29", "email", "zhangsan@example.com", "city", "北京"]
```

### 获取所有字段名

```
# 获取哈希表中的所有字段名
HKEYS key

# 返回值：字段名列表

# 示例：
HKEYS user:1000  # 返回 ["name", "age", "email", "city"]
```

### 获取所有值

```
# 获取哈希表中的所有值
HVALS key

# 返回值：值列表

# 示例：
HVALS user:1000  # 返回 ["张三", "29", "zhangsan@example.com", "北京"]
```

## 数值操作

### 增加数字值

```
# 将字段的整数值增加指定的增量
HINCRBY key field increment

# 将字段的浮点数值增加指定的增量
HINCRBYFLOAT key field increment

# 返回值：增加后的值

# 示例：
HINCRBY user:1000 age 1  # 返回 30（假设age原来是29）
HINCRBY user:1000 visits 1  # 返回 1（如果字段不存在，默认为0再增加）
HINCRBYFLOAT user:1000 salary 1250.50  # 返回新的浮点数值
```

## 扫描命令

### 渐进式迭代字段

```
# 迭代哈希表中的键值对
HSCAN key cursor [MATCH pattern] [COUNT count]

# 返回值：下一个游标和匹配的键值对列表

# 示例：
HSCAN user:1000 0 MATCH a* COUNT 10  # 返回以a开头的字段和对应的值
```

## 高级应用

### 用户信息存储

Redis 哈希表是存储用户信息的理想方式：

```
# 创建/更新用户信息
HSET user:1001 name "李四" gender "male" age "35" email "lisi@example.com" city "上海" vip "true"

# 获取特定信息
HGET user:1001 email  # 获取邮箱

# 检查用户是否是VIP
HGET user:1001 vip

# 用户年龄递增
HINCRBY user:1001 age 1

# 批量获取基本信息
HMGET user:1001 name email city

# 获取完整用户资料
HGETALL user:1001
```

### 购物车实现

哈希表可用于实现简单的购物车功能：

```
# 添加商品到购物车
HSET cart:user:1001 product:101 1  # 添加1个商品101
HSET cart:user:1001 product:102 3  # 添加3个商品102

# 增加商品数量
HINCRBY cart:user:1001 product:101 2  # 商品101再加2个

# 删除购物车商品
HDEL cart:user:1001 product:101

# 获取购物车内所有商品
HGETALL cart:user:1001
```

### 网页点击统计

使用哈希表统计不同页面的点击数：

```
# 增加页面点击数
HINCRBY pageviews "home" 1
HINCRBY pageviews "login" 1
HINCRBY pageviews "products" 1

# 获取特定页面的访问量
HGET pageviews "home"

# 查看所有页面访问情况
HGETALL pageviews
```

### 配置信息管理

集中存储应用配置参数：

```
# 设置应用配置
HSET config:app max_connections 500 cache_time 300 debug true

# 更新单个配置项
HSET config:app debug false

# 获取特定配置
HGET config:app cache_time

# 获取所有配置
HGETALL config:app
```

### 缓存对象数据

缓存从数据库查询的对象：

```
# 缓存产品信息
HSET product:10001 name "智能手机" price "3999" stock "200" category "electronics"

# 使用相同的键进行更新
HSET product:10001 stock "198" price "3899"

# 读取产品信息
HGETALL product:10001
```

## 性能考虑

1. **大小控制**：
   - Redis 哈希表适合存储中小型对象
   - 单个哈希表建议不超过100个字段，过大的哈希可能影响性能

2. **内存优化**：
   - 对于小于512MB的哈希表，Redis使用特殊编码（ziplist）节省内存
   - 可以通过调整配置参数 hash-max-ziplist-entries 和 hash-max-ziplist-value 控制ziplist的使用

3. **选择合适的命令**：
   - 使用 HMGET 代替多次 HGET 以减少网络开销
   - 避免频繁使用 HGETALL 获取所有数据，特别是对于大型哈希表
   - 对于大型哈希表的完整扫描，使用 HSCAN 替代 HGETALL

## 命令时间复杂度

| 命令 | 时间复杂度 |
|------|-----------|
| HSET, HSETNX, HGET, HDEL, HEXISTS | O(1) |
| HINCRBY, HINCRBYFLOAT | O(1) |
| HMGET | O(N), N 是请求的字段数量 |
| HKEYS, HVALS, HGETALL | O(N), N 是哈希表的大小 |
| HLEN | O(1) |
| HSCAN | O(1), 每次调用的平摊复杂度 |

## 实际应用示例

### 示例1：用户会话管理

使用哈希表保存用户会话信息：

```
# 用户登录后，创建会话
HSET session:token:abc123 user_id "1001" login_time "1625140800" ip "192.168.1.10" device "mobile"

# 会话更新
HSET session:token:abc123 last_access "1625142600"

# 检查会话是否有效（通过检查会话是否存在）
EXISTS session:token:abc123

# 获取会话信息
HGETALL session:token:abc123

# 获取特定会话属性
HMGET session:token:abc123 user_id last_access

# 删除会话（用户登出）
DEL session:token:abc123
```

### 示例2：计数器聚合

使用哈希表整合多个相关计数器：

```
# 记录网站不同事件的计数
HINCRBY events:daily:2023-07-10 pageview 1
HINCRBY events:daily:2023-07-10 click 1
HINCRBY events:daily:2023-07-10 signup 1

# 批量获取当天各种事件的计数
HGETALL events:daily:2023-07-10

# 比较两个不同日期的特定事件
HMGET events:daily:2023-07-10 pageview click signup
HMGET events:daily:2023-07-09 pageview click signup
```

### 示例3：优化的关系数据存储

使用哈希表替代多个字符串键来存储相关数据：

```
# 不推荐的方式（使用多个键）
SET user:1001:name "王五"
SET user:1001:email "wangwu@example.com"
SET user:1001:age "42"

# 推荐的方式（使用哈希表）
HSET user:1001 name "王五" email "wangwu@example.com" age "42"

# 读取数据对比
GET user:1001:email  # vs
HGET user:1001 email
```

### 示例4：产品库存管理

使用哈希表管理产品库存和属性：

```
# 添加产品
HSET product:20001 name "笔记本电脑" category "electronics" price "6999" stock "50" sku "LP-2001"

# 更新库存（减少）
HINCRBY product:20001 stock -1

# 更新价格
HSET product:20001 price "6799"

# 检查库存是否充足
HGET product:20001 stock

# 获取产品完整信息
HGETALL product:20001
```

### 示例5：临时数据缓存

哈希表作为关系数据库查询结果的缓存：

```
# 缓存查询结果
HSET cache:query:results:user-orders:1001 total "5" pending "1" delivered "4" amount "1250.50"

# 设置缓存过期时间
EXPIRE cache:query:results:user-orders:1001 300  # 5分钟过期

# 使用缓存
HGETALL cache:query:results:user-orders:1001
```

## 总结

Redis 哈希表提供了一种高效的方式来存储键值对集合，特别适合于以下场景：

- **对象数据存储**：用户信息、产品详情等对象数据
- **计数器集合**：相关计数器的分组管理
- **配置管理**：应用配置的集中存储和管理
- **会话存储**：用户登录会话信息的维护
- **临时数据缓存**：缓存从其他系统查询的结构化数据

哈希表相比于使用多个独立键来存储对象属性的优势在于：
- **减少内存占用**：单个带有多个字段的哈希表比多个单独的键占用更少的内存
- **原子操作**：哈希操作是原子的，无需使用事务或Lua脚本
- **数据隔离**：相关数据集中在一个命名空间下，便于管理和读取
- **减少网络开销**：批量操作（如HMGET, HGETALL）减少了网络往返次数

在实际应用中，合理利用哈希表结构可以显著提升应用性能并简化代码逻辑。 