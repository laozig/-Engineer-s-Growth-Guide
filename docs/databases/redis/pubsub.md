# Redis 发布订阅

Redis 发布订阅（Pub/Sub）是一种消息通信模式，它允许发送者（发布者）发送消息，而不知道有哪些接收者（订阅者）存在，同时允许接收者订阅感兴趣的消息频道，而不必知道有哪些发布者。这种松散耦合的消息传递机制非常适合构建实时通信系统。

## 基本概念

- **发布者（Publisher）**：发送消息的客户端
- **订阅者（Subscriber）**：接收消息的客户端
- **频道（Channel）**：消息传递的通道，发布者将消息发送到频道，订阅者从频道接收消息
- **模式（Pattern）**：使用通配符订阅多个匹配的频道
- **消息（Message）**：在频道中传递的数据

## 发布订阅命令

### 发布消息

```
# 将消息发布到指定的频道
PUBLISH channel message

# 返回值：接收到消息的订阅者数量

# 示例：
PUBLISH news:tech "New smartphone released today!"  # 向 news:tech 频道发布消息
PUBLISH alerts:system "Server CPU usage exceeded 90%"  # 向 alerts:system 频道发布消息
```

### 订阅频道

```
# 订阅一个或多个频道的消息
SUBSCRIBE channel [channel ...]

# 返回值：无直接返回值，但会收到三种类型的消息：
# 1. 订阅确认消息
# 2. 取消订阅确认消息
# 3. 发布的消息

# 示例：
SUBSCRIBE news:tech news:sports  # 订阅两个频道
```

执行 `SUBSCRIBE` 命令后，客户端将进入订阅模式，不能执行其他命令（除了其他订阅相关命令如 `PSUBSCRIBE`、`UNSUBSCRIBE` 等），直到取消所有订阅。

### 模式订阅

```
# 订阅与给定模式匹配的所有频道
PSUBSCRIBE pattern [pattern ...]

# 返回值：与 SUBSCRIBE 命令类似

# 示例：
PSUBSCRIBE news:*  # 订阅所有以 news: 开头的频道
PSUBSCRIBE *.tech  # 订阅所有以 .tech 结尾的频道
```

模式订阅使用 glob 风格的通配符：
- `?` 匹配任意一个字符
- `*` 匹配任意个（包括零个）字符
- `[...]` 匹配方括号中的任意一个字符
- `[^...]` 或 `[!...]` 匹配不在方括号中的任意一个字符

### 取消订阅

```
# 取消订阅一个或多个频道
UNSUBSCRIBE [channel [channel ...]]

# 取消模式订阅
PUNSUBSCRIBE [pattern [pattern ...]]

# 返回值：取消订阅确认消息

# 示例：
UNSUBSCRIBE news:tech  # 取消订阅特定频道
UNSUBSCRIBE  # 取消所有频道订阅
PUNSUBSCRIBE news:*  # 取消特定模式订阅
```

如果不带参数执行 `UNSUBSCRIBE` 或 `PUNSUBSCRIBE`，将取消所有相应类型的订阅。

### 查看订阅信息

```
# 查看活跃频道（至少有一个订阅者的频道）
PUBSUB CHANNELS [pattern]

# 查看指定频道的订阅者数量
PUBSUB NUMSUB [channel [channel ...]]

# 查看模式订阅数量
PUBSUB NUMPAT

# 示例：
PUBSUB CHANNELS  # 列出所有活跃频道
PUBSUB CHANNELS news:*  # 列出以 news: 开头的活跃频道
PUBSUB NUMSUB news:tech news:sports  # 获取特定频道的订阅者数量
PUBSUB NUMPAT  # 获取模式订阅数量
```

## 工作原理

Redis 发布订阅的工作流程如下：

1. **订阅者建立订阅关系**：
   - 订阅者使用 `SUBSCRIBE` 命令订阅一个或多个频道
   - 或使用 `PSUBSCRIBE` 命令订阅符合特定模式的频道

2. **发布者发布消息**：
   - 发布者使用 `PUBLISH` 命令将消息发送到指定频道

3. **Redis 转发消息**：
   - Redis 服务器将消息转发给所有订阅相应频道或匹配模式的客户端

4. **订阅者接收消息**：
   - 订阅者客户端接收到消息，格式为：
     - 消息类型（message/pmessage）
     - 频道名称
     - 消息内容
     - 对于模式订阅，还会包括匹配的模式

## 特性和限制

### 特性

1. **低延迟**：Redis Pub/Sub 提供近实时的消息传递
2. **简单易用**：API 简洁，易于集成
3. **多模式订阅**：支持灵活的通配符模式订阅
4. **与其他 Redis 功能集成**：可以与其他 Redis 数据结构结合使用

### 限制

1. **消息可靠性**：
   - 消息不会持久化，断开连接的订阅者无法获取历史消息
   - 没有确认机制，不保证消息一定被接收

2. **消息排序**：
   - 虽然同一个客户端发布的消息通常按顺序接收，但不保证跨客户端的消息顺序

3. **扩展性考虑**：
   - 对于大规模应用，可能需要考虑分布式 Redis 实例的 Pub/Sub 同步问题

## 应用模式

### 实时通知系统

```
# 发送通知
PUBLISH user:1000:notifications "You have a new friend request from user 2000"

# 客户端订阅个人通知频道
SUBSCRIBE user:1000:notifications
```

### 聊天系统

```
# 用户发送聊天消息到特定房间
PUBLISH chat:room:123 "User1001: Hello everyone!"

# 用户加入聊天室
SUBSCRIBE chat:room:123

# 系统消息
PUBLISH chat:room:123 "SYSTEM: User1002 has joined the room"
```

### 配置更新广播

```
# 广播配置更改
PUBLISH config:updates "cache_timeout=600"

# 应用服务器订阅配置更新
SUBSCRIBE config:updates
```

### 事件驱动架构

```
# 发布用户注册事件
PUBLISH events:user:registered "{\"user_id\":1001,\"email\":\"user@example.com\",\"time\":1625097600}"

# 各个服务订阅感兴趣的事件
SUBSCRIBE events:user:registered
PSUBSCRIBE events:user:*
```

## 高级应用实例

### 示例1：实时通知系统

实现向特定用户或所有用户推送通知：

```python
# 发布者：发送通知
import redis
import json

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

# 向特定用户发送通知
def send_user_notification(user_id, message, importance="normal"):
    notification = json.dumps({
        "message": message,
        "importance": importance,
        "timestamp": time.time()
    })
    r.publish(f"user:{user_id}:notifications", notification)
    
# 向所有用户发送系统通知
def send_global_notification(message):
    r.publish("global:notifications", message)

# 调用示例
send_user_notification(1001, "您的订单已发货", "high")
send_global_notification("系统将在今晚10点进行维护")
```

```python
# 订阅者：接收通知
import redis
import json

r = redis.Redis(host='localhost', port=6379, decode_responses=True)
pubsub = r.pubsub()

# 订阅个人通知和全局通知
user_id = 1001
pubsub.subscribe(f"user:{user_id}:notifications", "global:notifications")

# 消息处理循环
for message in pubsub.listen():
    if message['type'] == 'message':
        channel = message['channel']
        data = message['data']
        
        try:
            # 尝试解析JSON格式的通知
            notification = json.loads(data)
            print(f"收到通知：{notification['message']}")
            if 'importance' in notification and notification['importance'] == 'high':
                print("这是一条重要通知！")
        except:
            # 处理纯文本通知
            print(f"系统通知：{data}")
```

### 示例2：分布式任务分发

使用 Pub/Sub 实现简单的任务分发系统：

```python
# 任务分发者
import redis
import json
import uuid

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

def dispatch_task(task_type, task_data):
    task_id = str(uuid.uuid4())
    task = {
        "id": task_id,
        "type": task_type,
        "data": task_data,
        "created_at": time.time()
    }
    
    # 发布任务到对应类型的频道
    r.publish(f"tasks:{task_type}", json.dumps(task))
    return task_id

# 分发不同类型的任务
dispatch_task("email", {"recipient": "user@example.com", "subject": "Welcome"})
dispatch_task("image_processing", {"image_url": "https://example.com/img.jpg"})
```

```python
# 任务处理者
import redis
import json
import time

r = redis.Redis(host='localhost', port=6379, decode_responses=True)
pubsub = r.pubsub()

# 工作器处理特定类型的任务
task_type = "email"
pubsub.subscribe(f"tasks:{task_type}")

def process_email_task(task_data):
    recipient = task_data.get("recipient")
    subject = task_data.get("subject")
    print(f"Sending email to {recipient} with subject: {subject}")
    # 实际的邮件发送逻辑...
    time.sleep(1)  # 模拟处理时间
    return True

print(f"Started worker for {task_type} tasks...")
for message in pubsub.listen():
    if message['type'] == 'message':
        try:
            task = json.loads(message['data'])
            print(f"Processing task: {task['id']}")
            process_email_task(task['data'])
            print(f"Task {task['id']} completed")
        except Exception as e:
            print(f"Error processing task: {e}")
```

### 示例3：实时协作编辑

使用 Pub/Sub 实现多用户协作编辑的变更广播：

```javascript
// 客户端：发送编辑更新
function sendDocumentUpdate(docId, userId, changes) {
    const update = JSON.stringify({
        userId: userId,
        changes: changes,  // 例如 {position: 120, insert: "text", delete: 0}
        timestamp: Date.now()
    });
    
    // 使用Redis客户端发布更新
    redisClient.publish(`doc:${docId}:updates`, update);
}

// 当用户输入时调用
documentEditor.on('change', (changes) => {
    sendDocumentUpdate('doc123', 'user456', changes);
});
```

```javascript
// 在同一文档的其他客户端：接收更新
function subscribeToDocumentUpdates(docId, userId) {
    const pubsub = redisClient.duplicate();
    
    // 订阅文档更新
    pubsub.subscribe(`doc:${docId}:updates`);
    
    pubsub.on('message', (channel, message) => {
        const update = JSON.parse(message);
        
        // 忽略自己发出的更新
        if (update.userId === userId) return;
        
        // 将其他用户的更改应用到本地文档
        applyChangesToDocument(update.changes);
        
        // 显示谁做了更改
        showUserActivity(update.userId);
    });
    
    return pubsub;
}

// 连接到文档时调用
const subscription = subscribeToDocumentUpdates('doc123', 'user456');

// 离开文档时取消订阅
function leaveDocument() {
    subscription.unsubscribe();
    subscription.quit();
}
```

## 与Stream比较

Redis 5.0 引入了 Stream 数据类型，它提供了一种持久化的消息队列机制，与 Pub/Sub 有以下区别：

| 特性 | Pub/Sub | Stream |
|------|---------|--------|
| 消息持久性 | 不持久化，离线客户端无法收到消息 | 消息持久存储，可以获取历史消息 |
| 消费者组 | 不支持 | 支持消费者组，允许多个消费者协同处理消息 |
| 消息确认 | 不支持 | 支持消息确认，确保消息处理 |
| 消息重试 | 不支持 | 支持未确认消息的重新投递 |
| 用途 | 简单的实时消息广播 | 可靠的消息队列系统 |

**选择建议**：
- 当需要简单的实时消息传递且不关心历史消息时，使用 Pub/Sub
- 当需要可靠的消息队列、消息持久化或消费者组功能时，使用 Stream

## 可靠性增强

由于Pub/Sub本身不提供消息持久性，可以采用以下策略增强可靠性：

1. **结合 Redis Stream**：
   ```
   # 发布消息同时存储到 Stream
   MULTI
   PUBLISH channel:name "message"
   XADD channel:history * message "message"
   EXEC
   
   # 消费者首次连接时可以查询历史消息
   XRANGE channel:history - +
   ```

2. **设置消息过期时间**：
   ```
   # 设置一个临时键保存最后的消息
   SETEX channel:last_message 3600 "message"  # 保留1小时
   ```

3. **实现消息确认机制**：
   ```
   # 发送包含消息ID的消息
   PUBLISH channel "{\"id\":\"msg123\",\"data\":\"message content\"}"
   
   # 订阅者收到后发布确认消息
   PUBLISH channel:ack "{\"id\":\"msg123\",\"status\":\"received\"}"
   ```

## 最佳实践

1. **频道命名规范**：
   - 使用冒号分隔的命名空间，如 `app:feature:entity:action`
   - 示例：`chat:room:123:messages`, `user:1001:notifications`

2. **消息格式**：
   - 使用结构化格式如 JSON，便于处理和扩展
   - 包含元数据如时间戳、消息ID等

3. **连接管理**：
   - 对于订阅者，专用一个 Redis 连接用于订阅，避免阻塞其他操作
   - 实现断线重连机制

4. **异常处理**：
   - 处理连接断开、解析错误等异常
   - 对于关键消息，考虑实现确认机制

5. **监控**：
   - 监控活跃频道和订阅者数量
   - 关注消息吞吐量和处理延迟

## 总结

Redis Pub/Sub 提供了一种简单高效的实时消息通信机制，特别适用于：

- **实时通知系统**：向用户推送即时消息
- **聊天应用**：广播聊天消息给房间内的所有用户
- **实时数据更新**：推送数据变更，如股票价格、游戏状态
- **系统监控**：分发系统告警和状态更新
- **配置广播**：向多个应用实例广播配置更改

虽然Redis Pub/Sub在消息持久性和可靠性方面有一定限制，但凭借其简单性和低延迟特性，在许多实时通信场景中仍然是一个很好的选择。对于需要更高可靠性的消息传递场景，可以考虑结合 Redis Stream 或专用消息队列系统。 