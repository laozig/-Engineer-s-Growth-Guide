# Redis 集合操作

Redis 集合（Set）是无序的字符串集合，具有成员唯一性的特点。Redis 集合支持添加、删除和测试元素存在性的操作，平均时间复杂度为 O(1)。此外，Redis 还提供了强大的集合间运算，如交集、并集和差集。

## 基本概念

- Redis 集合是**无序**的，不能通过索引或位置访问元素
- 集合中的**元素唯一**，不允许重复
- 底层实现基于哈希表，提供近乎**常量时间**的添加、删除和查找操作
- 一个集合最多可包含 2^32 - 1 个元素（超过 40 亿）

## 添加和删除元素

### 添加元素

```
# 向集合添加一个或多个元素
SADD key member [member ...]

# 返回值：添加到集合的元素数量（不包括已存在的元素）

# 示例：
SADD users:online "user:1" "user:2" "user:3"   # 返回 3
SADD users:online "user:1" "user:4"            # 返回 1（只有 user:4 被添加）
```

### 删除元素

```
# 从集合中移除一个或多个元素
SREM key member [member ...]

# 返回值：从集合中移除的元素数量

# 示例：
SREM users:online "user:2" "user:3"   # 返回 2
SREM users:online "nonexistent"       # 返回 0（元素不存在）
```

### 随机删除元素

```
# 随机移除并返回一个或多个元素
SPOP key [count]

# 返回值：被移除的元素（如指定 count，则返回一个数组）

# 示例：
SADD fruits "apple" "banana" "cherry" "date" "fig"
SPOP fruits     # 随机返回并移除一个元素，例如 "cherry"
SPOP fruits 2   # 随机返回并移除两个元素，例如 ["banana", "fig"]
```

### 随机获取元素（不删除）

```
# 随机返回一个或多个元素，但不从集合中移除
SRANDMEMBER key [count]

# 返回值：
# 不指定 count：随机返回一个元素
# count > 0：返回 count 个不重复的元素（如果 count 大于集合大小则返回整个集合）
# count < 0：返回 |count| 个元素，允许重复

# 示例：
SADD numbers 1 2 3 4 5
SRANDMEMBER numbers    # 随机返回一个数字，例如 4
SRANDMEMBER numbers 3  # 随机返回 3 个不同的数字，例如 [1, 3, 5]
SRANDMEMBER numbers -3 # 随机返回 3 个可能重复的数字，例如 [1, 1, 4]
```

## 查询和计数操作

### 获取集合所有元素

```
# 返回集合中的所有元素
SMEMBERS key

# 返回值：集合中的所有元素（无序）

# 示例：
SMEMBERS users:online   # 返回如 ["user:1", "user:4"]
```

> ⚠️ 注意：对于大型集合，SMEMBERS 可能阻塞服务器。对于大集合，考虑使用 SSCAN 渐进式迭代。

### 获取集合大小

```
# 获取集合中元素的数量
SCARD key

# 返回值：集合中元素的数量

# 示例：
SCARD users:online   # 返回 2
```

### 检查元素是否存在

```
# 判断元素是否是集合的成员
SISMEMBER key member

# 返回值：1 表示是成员，0 表示不是成员

# 示例：
SISMEMBER users:online "user:1"   # 返回 1（表示存在）
SISMEMBER users:online "user:5"   # 返回 0（表示不存在）
```

### 批量检查多个元素是否存在

```
# 判断多个元素是否是集合的成员（Redis 6.2+ 支持）
SMISMEMBER key member [member ...]

# 返回值：一个数组，每个元素对应 1 或 0

# 示例：
SMISMEMBER users:online "user:1" "user:2" "user:4"  # 返回 [1, 0, 1]
```

### 渐进式迭代集合

```
# 增量迭代集合中的元素
SSCAN key cursor [MATCH pattern] [COUNT count]

# 返回值：下次迭代的 cursor 和一批元素

# 示例：
SSCAN users:online 0 MATCH user:* COUNT 10
```

## 集合运算

Redis 集合支持强大的集合间运算，所有操作均在服务器端原子性执行。

### 交集运算

```
# 返回多个集合的交集
SINTER key [key ...]

# 将交集结果存储到目标集合
SINTERSTORE destination key [key ...]

# 返回值：
# SINTER: 交集中的元素
# SINTERSTORE: 结果集中的元素数量

# 示例：
SADD set1 "a" "b" "c" "d"
SADD set2 "c" "d" "e" "f"
SINTER set1 set2               # 返回 ["c", "d"]
SINTERSTORE result set1 set2   # 返回 2（结果集大小）
```

### 并集运算

```
# 返回多个集合的并集
SUNION key [key ...]

# 将并集结果存储到目标集合
SUNIONSTORE destination key [key ...]

# 返回值：
# SUNION: 并集中的元素
# SUNIONSTORE: 结果集中的元素数量

# 示例：
SUNION set1 set2               # 返回 ["a", "b", "c", "d", "e", "f"]
SUNIONSTORE result set1 set2   # 返回 6（结果集大小）
```

### 差集运算

```
# 返回第一个集合与其他集合的差集
SDIFF key [key ...]

# 将差集结果存储到目标集合
SDIFFSTORE destination key [key ...]

# 返回值：
# SDIFF: 差集中的元素
# SDIFFSTORE: 结果集中的元素数量

# 示例：
SDIFF set1 set2               # 返回 ["a", "b"]（在 set1 中但不在 set2 中的元素）
SDIFFSTORE result set1 set2   # 返回 2（结果集大小）
```

### 移动元素

```
# 将元素从一个集合移动到另一个集合
SMOVE source destination member

# 返回值：1 表示成功移动，0 表示元素不在源集合中

# 示例：
SADD active:users "user:1" "user:2"
SADD inactive:users "user:3"
SMOVE active:users inactive:users "user:2"  # 返回 1，user:2 从 active 移动到 inactive
```

## 高级应用

### 标签系统

使用集合存储标签关系，实现双向查询：

```
# 为文章添加标签
SADD article:1:tags "redis" "database" "nosql"
SADD tag:redis:articles "1"

# 查找文章的所有标签
SMEMBERS article:1:tags

# 查找带有特定标签的所有文章
SMEMBERS tag:redis:articles

# 查找同时有多个标签的文章
SINTER tag:redis:articles tag:nosql:articles
```

### 用户关系管理

跟踪用户的关注者和关注列表：

```
# 用户1关注用户2
SADD user:1:following "user:2" 
SADD user:2:followers "user:1"

# 取消关注
SREM user:1:following "user:2"
SREM user:2:followers "user:1"

# 查看共同关注的用户
SINTER user:1:following user:3:following

# 查找可能认识的人（我关注的人也关注了谁）
SUNION user:2:following user:3:following ... | SDIFF - user:1:following
```

### 唯一约束

利用集合的唯一性实现唯一约束：

```
# 检查邮箱是否已注册
SISMEMBER registered:emails "user@example.com"

# 注册邮箱
SADD registered:emails "user@example.com"

# 验证用户名是否可用
SISMEMBER taken:usernames "johndoe"
```

### 随机抽样

从集合中随机选择元素：

```
# 抽取一个随机中奖用户
SADD raffle:participants "user:1" "user:2" "user:3" ... "user:1000"
SRANDMEMBER raffle:participants    # 随机查看一个参与者（不移除）
SPOP raffle:participants           # 随机选择获奖者并将其移除
```

### 投票系统

使用集合记录投票：

```
# 用户对文章投票
SADD article:1:upvotes "user:1" "user:2" "user:3"

# 检查用户是否已投票
SISMEMBER article:1:upvotes "user:4"

# 获取投票数量
SCARD article:1:upvotes

# 查看哪些用户同时为两篇文章投了票
SINTER article:1:upvotes article:2:upvotes
```

## 性能考虑

1. **集合大小**：
   - Redis 集合高效地处理大量元素
   - 但对大型集合使用 SMEMBERS 可能会导致性能问题，应改用 SSCAN

2. **集合运算**：
   - 集合运算（SINTER, SUNION, SDIFF）的时间复杂度与元素数量成正比
   - 对于大型集合，运算可能耗时较长，考虑使用 STORE 变体预先计算结果

3. **内存效率**：
   - 集合的实现使用哈希表，在存储大量整数值时内存开销较大
   - 如果存储整数范围有限，考虑使用位图（bitmap）或 HyperLogLog

## 命令时间复杂度

| 命令 | 时间复杂度 |
|------|-----------|
| SADD, SREM, SISMEMBER | O(1) - 每添加/移除/检查一个元素 |
| SCARD | O(1) - 集合大小在内部跟踪 |
| SMEMBERS, SRANDMEMBER | O(N) - N 是集合大小 |
| SPOP | O(1) - 随机移除一个元素 |
| SINTER, SUNION, SDIFF | O(N) - N 是所有集合元素数量的总和 |
| SINTERSTORE, SUNIONSTORE, SDIFFSTORE | O(N) - 与对应的非 STORE 命令相同 |
| SMOVE | O(1) - 检查和更新操作都是常量时间 |
| SSCAN | O(1) - 每次调用的摊销复杂度 |

## 实际应用示例

### 示例1：用户权限管理

```
# 创建角色并分配权限
SADD role:admin "create" "read" "update" "delete"
SADD role:editor "read" "update"
SADD role:viewer "read"

# 为用户分配角色
SADD user:1:roles "admin"
SADD user:2:roles "editor" "viewer"

# 检查用户是否具有特定权限（通过角色组合来计算）
SADD temp:perms:1 
SMEMBERS user:1:roles  # 获取用户角色
# 对每个角色，将其权限并入临时集合
SUNIONSTORE temp:perms:1 temp:perms:1 role:admin
# 检查权限
SISMEMBER temp:perms:1 "create"  # 返回 1

# 查找具有特定角色的所有用户
SADD role:admin:users "user:1"
```

### 示例2：内容推荐

```
# 记录用户兴趣
SADD user:1:interests "music" "technology" "science"
SADD user:2:interests "technology" "sports" "travel"

# 找出共同兴趣以提供社交推荐
SINTER user:1:interests user:2:interests  # 返回 ["technology"]

# 推荐具有相似兴趣的内容
SADD interest:technology:articles "article:1" "article:2" "article:3"
SADD interest:music:articles "article:4" "article:5"
```

### 示例3：在线状态跟踪

```
# 标记用户在线
SADD online:users "user:1" "user:2" "user:3"

# 检查用户是否在线
SISMEMBER online:users "user:2"  # 返回 1

# 用户下线
SREM online:users "user:3"

# 获取在线用户数
SCARD online:users  # 返回 2

# 找出哪些好友在线
SINTER online:users user:1:friends
```

### 示例4：IP 黑名单/白名单

```
# 添加 IP 到黑名单
SADD blacklist:ip "192.168.1.1" "10.0.0.1"

# 检查 IP 是否被屏蔽
SISMEMBER blacklist:ip "192.168.1.1"  # 返回 1

# 将 IP 从黑名单移到白名单
SMOVE blacklist:ip whitelist:ip "192.168.1.1"
```

### 示例5：商品类别管理

```
# 为商品分配类别
SADD product:1:categories "electronics" "gadgets" "smartphones"
SADD category:electronics:products "product:1" "product:2" "product:3"

# 查找特定类别的所有商品
SMEMBERS category:electronics:products

# 查找属于多个类别的商品
SINTER category:electronics:products category:smartphones:products
```

## 总结

Redis 集合提供了高效的无序集合操作能力，特别擅长于：

- **唯一性**：当需要确保元素不重复时，如邮箱、用户名等唯一标识符
- **标签系统**：实现多对多关系，如文章标签、产品分类
- **关系管理**：例如社交网络中的关注关系
- **集合数学运算**：交集、并集、差集，用于计算关系、推荐和筛选

集合的主要优势在于高效的元素添加、删除、检查和集合运算。如果需要有序的集合或为元素关联分数，应该考虑使用有序集合（Sorted Set）。 