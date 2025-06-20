# Redis 列表操作

Redis 列表是简单的字符串列表，按照插入顺序排序。你可以添加元素到列表的头部（左边）或者尾部（右边），一个列表最多可以包含 2^32 - 1 个元素（超过 40 亿）。

## 基本概念

- Redis 列表是**双向链表**实现的，支持两端快速插入和删除操作
- 因为是链表结构，**按索引访问元素**的速度相对较慢（时间复杂度为 O(N)）
- 列表非常适合实现**消息队列**、**最新动态**和需要**先进先出**数据结构的场景

## 添加元素

### 左端（头部）操作

```
# 将一个或多个值插入到列表头部
LPUSH key value [value ...]

# 仅当列表存在时，将值插入到头部
LPUSHX key value [value ...]

# 示例：
LPUSH notifications "Message 1"   # 返回 1，列表现在是 ["Message 1"]
LPUSH notifications "Message 2"   # 返回 2，列表现在是 ["Message 2", "Message 1"]
LPUSH notifications "Message 3" "Message 4"  # 返回 4，列表现在是 ["Message 4", "Message 3", "Message 2", "Message 1"]

# 对不存在的列表使用 LPUSHX 不会创建列表
LPUSHX nonexistent "value"   # 返回 0，什么都不做
```

### 右端（尾部）操作

```
# 将一个或多个值插入到列表尾部
RPUSH key value [value ...]

# 仅当列表存在时，将值插入到尾部
RPUSHX key value [value ...]

# 示例：
RPUSH queue "Job 1"   # 返回 1，列表现在是 ["Job 1"]
RPUSH queue "Job 2"   # 返回 2，列表现在是 ["Job 1", "Job 2"]
RPUSH queue "Job 3" "Job 4"  # 返回 4，列表现在是 ["Job 1", "Job 2", "Job 3", "Job 4"]
```

### 在指定位置插入元素

```
# 将值插入到列表中指定元素的前面或后面
LINSERT key BEFORE|AFTER pivot value

# 示例：
RPUSH fruits "apple" "orange" "banana"   # 创建水果列表
LINSERT fruits BEFORE "orange" "pear"    # 返回 4，列表现在是 ["apple", "pear", "orange", "banana"]
LINSERT fruits AFTER "banana" "grape"    # 返回 5，列表现在是 ["apple", "pear", "orange", "banana", "grape"]
```

## 获取元素

### 获取列表范围

```
# 获取列表指定范围内的元素
LRANGE key start stop

# 参数说明：
# - start 和 stop 是索引，从0开始，可以使用负数表示从末尾开始计数
# - 闭区间，包含 start 和 stop 指定的元素
# - 超出范围不会报错，会自动调整到有效范围

# 示例：
LRANGE queue 0 -1    # 获取列表中所有元素，返回 ["Job 1", "Job 2", "Job 3", "Job 4"]
LRANGE queue 1 2     # 获取第2和第3个元素，返回 ["Job 2", "Job 3"]
LRANGE queue -2 -1   # 获取最后两个元素，返回 ["Job 3", "Job 4"]
```

### 获取指定索引的元素

```
# 获取列表中指定索引位置的元素
LINDEX key index

# 示例：
LINDEX queue 0      # 返回 "Job 1"
LINDEX queue -1     # 返回 "Job 4"
LINDEX queue 99     # 超出范围返回 nil
```

### 获取列表长度

```
# 获取列表的长度
LLEN key

# 示例：
LLEN queue   # 返回 4
```

## 删除元素

### 弹出元素

```
# 移除并返回列表头部的第一个元素
LPOP key [count]

# 移除并返回列表尾部的最后一个元素
RPOP key [count]

# 示例：
LPOP queue           # 返回 "Job 1"，列表变为 ["Job 2", "Job 3", "Job 4"]
RPOP queue           # 返回 "Job 4"，列表变为 ["Job 2", "Job 3"]

# Redis 6.2+ 支持弹出多个元素
LPOP queue 2         # 返回 ["Job 2", "Job 3"]，列表变为空
```

### 按值移除元素

```
# 从列表中移除指定数量的等于给定值的元素
LREM key count value

# 参数说明：
# count > 0: 从头开始，移除最多 count 个等于 value 的元素
# count < 0: 从尾开始，移除最多 |count| 个等于 value 的元素
# count = 0: 移除所有等于 value 的元素

# 示例：
RPUSH tasks "task1" "task2" "task1" "task3" "task1"
LREM tasks 2 "task1"     # 返回 2，列表变为 ["task2", "task3", "task1"]
LREM tasks 0 "task1"     # 返回 1，列表变为 ["task2", "task3"]
```

### 修剪列表

```
# 修剪列表，只保留指定区间内的元素
LTRIM key start stop

# 示例：
RPUSH messages "msg1" "msg2" "msg3" "msg4" "msg5"
LTRIM messages 0 2       # 只保留前3个元素，列表变为 ["msg1", "msg2", "msg3"]
```

### 按索引设置元素值

```
# 设置列表中指定索引的元素值
LSET key index value

# 示例：
RPUSH items "item1" "item2" "item3"
LSET items 1 "updated-item2"   # 将第二个元素设置为 "updated-item2"
```

## 阻塞操作

阻塞操作在列表为空时会阻塞连接，直到有新元素可用或超时。这些操作非常适合实现消息队列。

### 阻塞弹出

```
# 阻塞式弹出列表头部元素
BLPOP key [key ...] timeout

# 阻塞式弹出列表尾部元素
BRPOP key [key ...] timeout

# 参数说明：
# - timeout: 超时时间（秒），0表示永不超时
# - 可以指定多个列表，按顺序检查直到找到非空列表

# 示例：
BLPOP queue 5     # 如果 queue 列表为空，最多等待5秒
                  # 如果超时，返回 nil
                  # 如果在超时前有数据，返回 ["queue", "元素值"]
```

### 弹出并推入

```
# 原子性地将列表source中的最后一个元素弹出并添加到列表destination的头部
RPOPLPUSH source destination

# 阻塞版本的 RPOPLPUSH
BRPOPLPUSH source destination timeout

# 示例：移动任务从待处理队列到处理中队列
RPOPLPUSH pending processing    # 返回被移动的元素
```

注意：Redis 6.2+ 推荐使用新命令 LMOVE 和 BLMOVE 替代 RPOPLPUSH 和 BRPOPLPUSH：

```
# 原子性地将元素从source的一端移动到destination的另一端
LMOVE source source-direction destination destination-direction

# 阻塞版本
BLMOVE source source-direction destination destination-direction timeout

# direction 可以是 LEFT 或 RIGHT

# 示例：等价于 RPOPLPUSH
LMOVE pending RIGHT processing LEFT
```

## 高级应用

### 简单消息队列

使用列表实现先进先出的消息队列：

```
# 生产者：添加消息到队列尾部
RPUSH jobs:queue "job payload"

# 消费者：从队列头部获取消息
BLPOP jobs:queue 0
```

### 可靠的消息队列

使用 RPOPLPUSH (或 LMOVE) 实现可靠的工作队列：

```
# 生产者：添加任务
RPUSH jobs:pending "job1"

# 消费者：获取任务并移至处理队列
RPOPLPUSH jobs:pending jobs:processing

# 处理完成后：
LREM jobs:processing 1 "job1"  # 从处理队列中删除
# 或
RPUSH jobs:completed "job1"    # 移动到完成队列
```

### 循环列表

使用 RPOPLPUSH 在同一列表上操作可以创建循环列表：

```
# 轮流处理列表中的每个元素
RPOPLPUSH mylist mylist  # 将尾部元素移到头部
```

### 最新动态列表

跟踪最新项目，仅保留有限数量：

```
# 添加新项目到头部
LPUSH latest:news "Breaking news: ..."

# 保持列表在可控长度
LTRIM latest:news 0 99  # 只保留最新的100条
```

### 优先级队列

使用多个列表实现不同优先级的队列：

```
# 将任务添加到不同优先级的队列
LPUSH jobs:high "high-priority-job"
LPUSH jobs:medium "medium-priority-job"
LPUSH jobs:low "low-priority-job"

# 优先处理高优先级队列中的任务
BRPOP jobs:high jobs:medium jobs:low 0
```

## 性能考虑

以下是使用 Redis 列表时的一些性能注意事项：

1. **列表长度**：
   - Redis 列表是链表实现的，理论上支持非常长的列表
   - 但列表过长可能导致内存压力和遍历性能问题

2. **按索引访问**：
   - 按索引访问元素（LINDEX）为 O(N) 操作，对长列表效率较低
   - 尽量使用头尾操作（LPUSH/RPUSH/LPOP/RPOP）保持 O(1) 性能

3. **范围操作**：
   - LRANGE 时间复杂度为 O(S+N)，其中 S 是起始偏移量，N 是请求的元素数
   - 获取列表中部的大范围元素可能较慢

4. **内存效率**：
   - Redis 3.2 之前使用的是双向链表实现
   - Redis 3.2+ 使用的是压缩列表（ziplist）和双向链表的组合，提高内存效率

## 命令时间复杂度

| 命令 | 时间复杂度 |
|------|-----------|
| LPUSH, RPUSH, LPOP, RPOP | O(1) - 常量时间，不受列表长度影响 |
| LRANGE, LINDEX | O(N) - 与访问的元素数量或索引位置成正比 |
| LTRIM | O(N) - N 是被移除元素的数量 |
| LINSERT | O(N) - N 是 pivot 之前/之后的元素数量 |
| LLEN | O(1) - 列表长度在内部跟踪，常量时间 |
| LSET | O(N) - 与到达指定索引所需的时间成正比 |
| LREM | O(N) - N 是列表长度 |

## 实际应用示例

### 示例1：社交媒体时间线

```
# 发布新状态
LPUSH user:1000:timeline "Status update at 2023-07-10 10:30"

# 获取最新10条状态
LRANGE user:1000:timeline 0 9

# 限制时间线长度，避免无限增长
LTRIM user:1000:timeline 0 999  # 只保留最新的1000条
```

### 示例2：分布式任务队列

```
# 添加新任务到队列
RPUSH tasks:queue "{\"id\":123,\"type\":\"email\",\"recipient\":\"user@example.com\"}"

# 工作进程获取任务
BLPOP tasks:queue 0

# 带备份的任务获取（更可靠）
BRPOPLPUSH tasks:queue tasks:processing 0

# 任务完成后从处理队列中删除
LREM tasks:processing 1 "{\"id\":123,\"type\":\"email\",\"recipient\":\"user@example.com\"}"
```

### 示例3：实时日志收集

```
# 添加日志条目
LPUSH logs:app1 "2023-07-10 10:35:22 [ERROR] Connection failed"

# 获取最近日志
LRANGE logs:app1 0 49  # 获取最新的50条日志

# 定期归档并清理
LTRIM logs:app1 0 999  # 只保留最新的1000条
```

### 示例4：聊天室消息历史

```
# 发送新消息到聊天室
RPUSH chatroom:123:messages "{\"user\":\"Alice\",\"text\":\"Hello everyone!\",\"time\":1688980800}"

# 获取聊天历史
LRANGE chatroom:123:messages 0 -1

# 获取最近的20条消息
LRANGE chatroom:123:messages 0 19

# 限制历史记录长度
LTRIM chatroom:123:messages 0 99  # 保留最新的100条
```

### 示例5：轮询系统

```
# 初始化轮询列表
RPUSH servers "server1" "server2" "server3" "server4"

# 获取下一个服务器并将其放到列表末尾
RPOPLPUSH servers servers  # 返回当前服务器，并将其添加到列表末尾
```

## 总结

Redis 列表提供了丰富的操作来处理有序数据集合，特别适合以下场景：

- **消息队列和任务队列**：利用 LPUSH + RPOP 或 RPUSH + LPOP 实现 FIFO（先进先出）队列
- **最新动态**：使用 LPUSH + LTRIM 组合保持有限数量的最新项
- **实时日志**：使用列表收集日志条目，定期截断以避免无限增长
- **聊天历史**：存储有限数量的最近聊天消息

列表的优势在于其对头尾操作的高效性能和灵活性，但如果需要频繁的随机访问或按索引修改元素，可能需要考虑其他数据结构如有序集合（Sorted Sets）。 