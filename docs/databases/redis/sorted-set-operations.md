# Redis 有序集合操作

有序集合（Sorted Set）是 Redis 中的一种强大的数据结构，它结合了集合（不允许重复成员）的特性和排序（每个成员关联一个分数）的能力。有序集合的成员按照分数值从小到大排序，非常适合于实现排行榜、优先级队列等功能。

## 基本概念

- **有序集合**：由唯一的成员和与每个成员关联的分数组成
- **排序**：成员根据分数（score）自动排序
- **唯一性**：每个成员在有序集合中只能出现一次
- **分数**：可以是整数或双精度浮点数
- **复杂度**：大多数操作的时间复杂度为 O(log(N))

## 添加和更新元素

### 添加元素

```
# 添加一个或多个成员到有序集合，或更新已存在成员的分数
ZADD key [NX|XX] [GT|LT] [CH] [INCR] score member [score member ...]

# 参数说明：
# NX: 仅添加新元素，不更新已存在的元素
# XX: 仅更新已存在的元素，不添加新元素
# GT: 仅当新分数大于当前分数时更新（Redis 6.2+）
# LT: 仅当新分数小于当前分数时更新（Redis 6.2+）
# CH: 返回变更的元素数量，而不是新添加的元素数量
# INCR: 以增量方式添加，类似 ZINCRBY

# 返回值：添加到集合的新成员数量（不包括更新分数的已存在成员）

# 示例：
ZADD leaderboard 100 "user:1"                # 添加一个成员
ZADD leaderboard 200 "user:2" 300 "user:3"   # 添加多个成员
ZADD leaderboard XX 400 "user:1"             # 仅当user:1存在时更新分数
ZADD leaderboard NX 500 "user:4"             # 仅当user:4不存在时添加
ZADD leaderboard GT 150 "user:1"             # 仅当新分数150大于当前分数时更新
ZADD leaderboard LT 50 "user:2"              # 仅当新分数50小于当前分数时更新
ZADD leaderboard CH 600 "user:5"             # 返回变更的元素数量
```

### 增加分数

```
# 将有序集合中指定成员的分数增加指定增量
ZINCRBY key increment member

# 返回值：成员的新分数

# 示例：
ZADD points 50 "user:1"
ZINCRBY points 20 "user:1"   # 返回 70.0，user:1的分数现在是70
ZINCRBY points -30 "user:1"  # 返回 40.0，user:1的分数现在是40
```

## 删除元素

### 删除指定成员

```
# 从有序集合中移除一个或多个成员
ZREM key member [member ...]

# 返回值：被成功移除的成员数量

# 示例：
ZREM leaderboard "user:1" "user:2"  # 删除user:1和user:2
```

### 按排名范围删除

```
# 移除有序集合中指定排名范围内的所有成员
ZREMRANGEBYRANK key start stop

# 返回值：被移除的成员数量

# 示例：
ZREMRANGEBYRANK leaderboard 0 1  # 删除排名最低的两个成员（索引0和1）
```

### 按分数范围删除

```
# 移除有序集合中指定分数范围内的所有成员
ZREMRANGEBYSCORE key min max

# 返回值：被移除的成员数量

# 示例：
ZREMRANGEBYSCORE scores 0 100  # 删除分数在0到100之间的所有成员
```

### 按字典序范围删除

```
# 移除有序集合中指定字典序范围内的所有成员
ZREMRANGEBYLEX key min max

# 返回值：被移除的成员数量

# 注：此命令仅在所有成员分数相同时有用

# 示例：
ZREMRANGEBYLEX names [A [C  # 删除名称以A开头到C开头（不含）的所有成员
```

## 查询元素

### 获取成员分数

```
# 获取有序集合中一个或多个成员的分数
ZSCORE key member
ZMSCORE key member [member ...]  # Redis 6.2+

# 返回值：
# ZSCORE: 成员的分数，或 nil 表示成员不存在
# ZMSCORE: 一个数组，包含所有请求成员的分数，不存在的成员返回 nil

# 示例：
ZSCORE leaderboard "user:1"                    # 返回 100
ZMSCORE leaderboard "user:1" "user:2" "user:9"  # 返回 [100, 200, nil]
```

### 获取排名

```
# 获取有序集合中成员的排名（从低到高，0为最低）
ZRANK key member

# 获取有序集合中成员的排名（从高到低，0为最高）
ZREVRANK key member

# 返回值：成员的排名，或 nil 表示成员不存在

# 示例：
ZRANK leaderboard "user:3"     # 返回 2（第三名，从0开始计数）
ZREVRANK leaderboard "user:3"  # 返回 0（第一名，从高到低排序）
```

## 范围查询

### 按排名范围获取

```
# 获取有序集合中指定排名范围内的成员（从低到高）
ZRANGE key start stop [WITHSCORES]

# 获取有序集合中指定排名范围内的成员（从高到低）
ZREVRANGE key start stop [WITHSCORES]

# 参数说明：
# start, stop: 包含的排名范围，0为第一个元素，-1为最后一个元素
# WITHSCORES: 同时返回成员的分数

# 返回值：指定范围内的成员列表，可选是否带分数

# 示例：
ZRANGE leaderboard 0 2              # 返回排名前三的成员
ZRANGE leaderboard 0 -1             # 返回所有成员，按分数从低到高
ZRANGE leaderboard 0 2 WITHSCORES   # 返回排名前三的成员及其分数
ZREVRANGE leaderboard 0 2           # 返回分数最高的三个成员
```

### 按分数范围获取

```
# 获取有序集合中指定分数范围内的成员（从低到高）
ZRANGEBYSCORE key min max [WITHSCORES] [LIMIT offset count]

# 获取有序集合中指定分数范围内的成员（从高到低）
ZREVRANGEBYSCORE key max min [WITHSCORES] [LIMIT offset count]

# 参数说明：
# min, max: 分数范围，可以是 -inf 和 +inf
# WITHSCORES: 同时返回成员的分数
# LIMIT offset count: 分页参数

# 返回值：指定分数范围内的成员列表，可选是否带分数

# 示例：
ZRANGEBYSCORE scores 50 100             # 返回分数在50到100之间的所有成员
ZRANGEBYSCORE scores -inf +inf          # 返回所有成员
ZRANGEBYSCORE scores (50 (100           # 返回分数在50到100之间的所有成员，不包括50和100
ZRANGEBYSCORE scores 50 100 WITHSCORES  # 返回分数在50到100之间的所有成员及其分数
ZRANGEBYSCORE scores 0 100 LIMIT 0 10   # 返回分数在0到100之间的前10个成员
ZREVRANGEBYSCORE scores 100 0           # 返回分数在0到100之间的所有成员，按分数从高到低
```

### 按字典序范围获取

```
# 获取有序集合中指定字典序范围内的成员
ZRANGEBYLEX key min max [LIMIT offset count]

# 获取有序集合中指定字典序范围内的成员（逆序）
ZREVRANGEBYLEX key max min [LIMIT offset count]

# 参数说明：
# min, max: 字典序范围
#   - [ 表示包含边界
#   - ( 表示不包含边界
#   - - 表示负无穷
#   - + 表示正无穷

# 返回值：指定字典序范围内的成员列表

# 注：此命令仅在所有成员分数相同时才有意义

# 示例：
ZADD names 0 "a" 0 "b" 0 "c" 0 "d" 0 "e" 0 "f"  # 所有成员分数相同
ZRANGEBYLEX names [b [e         # 返回 ["b", "c", "d", "e"]
ZRANGEBYLEX names [b (e         # 返回 ["b", "c", "d"]
ZRANGEBYLEX names - +           # 返回所有成员
ZRANGEBYLEX names - + LIMIT 1 2  # 返回从第二个成员开始的两个成员
```

## 计数操作

### 获取元素数量

```
# 获取有序集合中的成员数量
ZCARD key

# 返回值：有序集合的成员数量

# 示例：
ZCARD leaderboard  # 返回 leaderboard 中的成员数量
```

### 获取指定分数范围内的元素数量

```
# 获取有序集合中指定分数范围内的成员数量
ZCOUNT key min max

# 返回值：分数范围内的成员数量

# 示例：
ZCOUNT scores 50 100   # 返回分数在50到100之间的成员数量
ZCOUNT scores (50 100  # 返回分数大于50且小于等于100的成员数量
```

### 获取指定字典序范围内的元素数量

```
# 获取有序集合中指定字典序范围内的成员数量
ZLEXCOUNT key min max

# 返回值：字典序范围内的成员数量

# 示例：
ZLEXCOUNT names [a [c  # 返回字典序在a和c之间（包括a和c）的成员数量
```

## 集合操作

### 集合间运算

```
# 计算多个有序集合的交集，并将结果存储在新的有序集合中
ZINTERSTORE destination numkeys key [key ...] [WEIGHTS weight [weight ...]] [AGGREGATE SUM|MIN|MAX]

# 计算多个有序集合的并集，并将结果存储在新的有序集合中
ZUNIONSTORE destination numkeys key [key ...] [WEIGHTS weight [weight ...]] [AGGREGATE SUM|MIN|MAX]

# 参数说明：
# destination: 结果存储的键
# numkeys: 输入的有序集合数量
# key [key ...]: 输入的有序集合
# WEIGHTS weight [weight ...]: 每个输入有序集合的权重
# AGGREGATE SUM|MIN|MAX: 指定结果集中成员分数的计算方式

# 返回值：结果集中的成员数量

# 示例：
ZADD math:scores 90 "user:1" 80 "user:2" 85 "user:3"
ZADD physics:scores 95 "user:1" 75 "user:2" 82 "user:3"

# 计算总分（求和）
ZUNIONSTORE total:scores 2 math:scores physics:scores

# 带权重计算加权平均分（数学占60%，物理占40%）
ZUNIONSTORE weighted:scores 2 math:scores physics:scores WEIGHTS 0.6 0.4 AGGREGATE SUM

# 找出两科都高于80分的学生
ZINTERSTORE high:scorers 2 math:scores physics:scores AGGREGATE MIN
ZRANGEBYSCORE high:scorers 80 +inf
```

### Redis 6.2+ 新增命令

Redis 6.2 版本新增了集合间运算并直接返回结果的命令：

```
# 计算多个有序集合的交集，并直接返回结果
ZINTER numkeys key [key ...] [WEIGHTS weight [weight ...]] [AGGREGATE SUM|MIN|MAX] [WITHSCORES]

# 计算多个有序集合的并集，并直接返回结果
ZUNION numkeys key [key ...] [WEIGHTS weight [weight ...]] [AGGREGATE SUM|MIN|MAX] [WITHSCORES]

# 示例：
ZINTER 2 math:scores physics:scores WITHSCORES  # 直接返回交集结果及分数
ZUNION 2 math:scores physics:scores AGGREGATE MIN WITHSCORES  # 直接返回并集结果，使用最小分数
```

### 差集操作 (Redis 6.2+)

```
# 计算第一个有序集合与其他有序集合的差集
ZDIFF numkeys key [key ...] [WITHSCORES]

# 计算差集并存储到目标键
ZDIFFSTORE destination numkeys key [key ...]

# 示例：
ZDIFF 2 math:scores physics:scores WITHSCORES  # 返回在数学中有成绩但物理中没有成绩的学生
ZDIFFSTORE math:only 2 math:scores physics:scores  # 存储只有数学成绩的学生
```

## 高级应用

### 排行榜

```
# 创建游戏分数排行榜
ZADD game:scores 1000 "player:1" 2000 "player:2" 1500 "player:3"

# 玩家获得新分数
ZINCRBY game:scores 200 "player:1"  # player:1 现在有 1200 分

# 获取前10名玩家
ZREVRANGE game:scores 0 9 WITHSCORES

# 获取玩家排名
ZREVRANK game:scores "player:1"  # 返回 player:1 的排名（从0开始）

# 获取周围玩家名次
# 假设 player:1 的排名是 5
ZREVRANGE game:scores 3 7 WITHSCORES  # 获取排名 4-8 的玩家（围绕 player:1）
```

### 优先级队列

```
# 添加带优先级的任务
ZADD tasks 10 "task:low-priority" 5 "task:high-priority" 7 "task:medium-priority"

# 获取下一个要执行的任务（优先级最高的，分数最低）
ZRANGE tasks 0 0

# 执行后删除任务
ZREM tasks "task:high-priority"

# 增加任务优先级（减小分数值）
ZINCRBY tasks -2 "task:low-priority"  # 优先级提高
```

### 时间序列数据

```
# 记录每小时的访问量，使用时间戳作为分数
ZADD visits 1625097600 "2021-07-01:00" 25  # 7月1日0点有25次访问
ZADD visits 1625101200 "2021-07-01:01" 32  # 7月1日1点有32次访问

# 获取特定时间范围的数据
ZRANGEBYSCORE visits 1625097600 1625184000 WITHSCORES  # 获取7月1日的所有访问数据
```

### 地理空间索引

Redis 提供了专门的地理空间命令（基于有序集合实现）：

```
# 添加地理位置
GEOADD locations 121.4737 31.2304 "Shanghai" 116.4074 39.9042 "Beijing" 114.0579 22.5431 "Shenzhen"

# 计算两地距离
GEODIST locations "Shanghai" "Beijing" km  # 返回两地距离，单位公里

# 查找半径内的位置
GEORADIUS locations 121.4737 31.2304 300 km  # 返回上海300公里范围内的城市

# 获取地理位置的坐标
GEOPOS locations "Shanghai" "Beijing"  # 返回城市的经纬度
```

### 时间窗口限流

```
# 将用户操作记录到有序集合，分数是时间戳
ZADD ratelimit:user:123 1625097600 "action:1" 1625097605 "action:2" 1625097610 "action:3"

# 清理旧记录并检查是否超过限制
# 当前时间戳是 1625097620
# 删除60秒前的记录
ZREMRANGEBYSCORE ratelimit:user:123 0 1625097560

# 计算最近60秒的操作数
ZCOUNT ratelimit:user:123 1625097560 1625097620

# 如果操作数小于限制，添加新操作
ZADD ratelimit:user:123 1625097620 "action:4"
```

## 性能考虑

1. **数据量**：
   - 有序集合在处理大量元素时效率仍然很高（O(log N)）
   - 但大型集合的完整遍历（如 ZRANGE key 0 -1）可能会消耗大量资源

2. **内存使用**：
   - 有序集合相比普通集合需要更多内存，因为要存储分数
   - 对于大型有序集合，内存使用是一个重要考虑因素

3. **分数精度**：
   - Redis 使用双精度浮点数存储分数，注意浮点数精度问题
   - 如需完全精确的排序，可以使用整数分数

4. **集合操作**：
   - ZINTERSTORE 和 ZUNIONSTORE 操作在处理大型集合时可能会很耗时
   - 这些操作的时间复杂度取决于所有集合中的总元素数量

## 命令时间复杂度

| 命令 | 时间复杂度 |
|------|-----------|
| ZADD, ZINCRBY | O(log(N)) - 其中 N 是有序集合的基数 |
| ZREM | O(M*log(N)) - 其中 M 是被移除成员的数量，N 是有序集合的基数 |
| ZSCORE, ZRANK, ZREVRANK | O(log(N)) |
| ZCARD | O(1) |
| ZCOUNT | O(log(N)) |
| ZRANGE, ZREVRANGE | O(log(N)+M) - 其中 M 是返回的元素数量 |
| ZRANGEBYSCORE, ZREVRANGEBYSCORE | O(log(N)+M) - 其中 M 是返回的元素数量 |
| ZREMRANGEBYRANK, ZREMRANGEBYSCORE | O(log(N)+M) - 其中 M 是被移除的元素数量 |
| ZINTERSTORE, ZUNIONSTORE | O(N*K+M*log(M)) - 其中 N 是最小输入集合的基数，K 是输入集合的数量，M 是结果集中的元素数量 |

## 实际应用示例

### 示例1：实时游戏排行榜

```
# 玩家得分更新
ZADD game:leaderboard 1200 "player:1"  # 新玩家或更新分数
ZINCRBY game:leaderboard 50 "player:2"  # 增加现有玩家分数

# 查看排名前10的玩家
ZREVRANGE game:leaderboard 0 9 WITHSCORES

# 查看特定玩家排名
ZREVRANK game:leaderboard "player:1"

# 获取特定玩家前后5名的玩家
# 先获取玩家排名
SET player_rank ZREVRANK game:leaderboard "player:1"
# 然后获取前后排名
ZREVRANGE game:leaderboard player_rank-5 player_rank+5 WITHSCORES
```

### 示例2：电子商务商品排序

```
# 根据不同因素为产品评分
ZADD products:views 15000 "product:1" 12000 "product:2" 8000 "product:3"
ZADD products:sales 200 "product:1" 350 "product:2" 100 "product:3"
ZADD products:rating 4.5 "product:1" 4.8 "product:2" 3.9 "product:3"

# 计算综合排序分数（视图*0.3 + 销售*0.5 + 评分*200*0.2）
ZUNIONSTORE products:ranking 3 products:views products:sales products:rating WEIGHTS 0.3 0.5 40

# 显示排名靠前的产品
ZREVRANGE products:ranking 0 9 WITHSCORES
```

### 示例3：时间窗口限流

```
# 将用户操作记录到有序集合，分数是时间戳
ZADD ratelimit:user:123 1625097600 "action:1" 1625097605 "action:2" 1625097610 "action:3"

# 清理旧记录并检查是否超过限制
# 当前时间戳是 1625097620
# 删除60秒前的记录
ZREMRANGEBYSCORE ratelimit:user:123 0 1625097560

# 计算最近60秒的操作数
ZCOUNT ratelimit:user:123 1625097560 1625097620

# 如果操作数小于限制，添加新操作
ZADD ratelimit:user:123 1625097620 "action:4"
```

## 总结

Redis 有序集合提供了强大而灵活的功能，特别适合以下场景：

- **排行榜和排名**：利用分数和排名实现实时排行榜
- **优先级队列**：使用分数表示优先级，实现优先级排序
- **范围查询**：高效地进行分数范围和排名范围的查询
- **权重计算**：结合 ZUNIONSTORE 实现复杂的多因素加权排序
- **时间序列数据**：使用时间戳作为分数存储和查询时间序列数据

与普通集合相比，有序集合的主要优势在于保持了元素的排序，同时提供了高效的范围查询操作。但这也带来了更多的内存使用和复杂性，所以在选择数据结构时需要权衡这些因素。 