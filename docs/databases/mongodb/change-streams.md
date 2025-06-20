# MongoDB Change Streams

MongoDB Change Streams 是一个强大的功能，允许应用程序实时订阅单个集合、数据库或整个部署中的数据更改。它提供了一个与 oplog 类似但更灵活、更易于使用的 API，用于构建响应式、事件驱动的系统。

## Change Streams 的核心概念

Change Streams 提供了一个可恢复、有序的事件流，这些事件表示数据在创建、更新或删除时发生的变化。

- **实时数据捕获**：实时获取数据更改，无需轮询数据库。
- **可恢复性**：如果应用程序断开连接，Change Streams 可以从上次中断的地方自动恢复，确保不会丢失事件。
- **过滤能力**：可以配置 Change Streams 只监听特定类型的操作（如 `insert`, `update`, `delete`）或符合特定条件的文档。
- **有序性**：事件流保证了操作的顺序性。

## 使用场景

Change Streams 在多种场景下都非常有用：

- **实时通知**：当特定数据发生变化时，向用户发送推送通知。
- **数据同步**：在微服务架构中，保持不同服务之间的数据同步。
- **ETL（提取、转换、加载）**：将 MongoDB 中的数据更改实时流式传输到数据仓库或分析系统。
- **实时分析**：对实时数据流进行分析，例如监控用户活动或检测异常。
- **协作应用**：在多人协作工具中，实时更新所有用户的视图。

## 如何使用 Change Streams

要使用 Change Streams，您需要连接到一个 MongoDB 复制集或分片集群。

以下是在 Node.js (使用官方 `mongodb` 驱动) 中使用 Change Streams 的基本示例：

```javascript
const { MongoClient } = require('mongodb');

async function watchChanges() {
  const uri = 'mongodb://localhost:27017/?replicaSet=rs0';
  const client = new MongoClient(uri);

  try {
    await client.connect();
    const database = client.db('testdb');
    const collection = database.collection('inventory');

    // 定义要监听的管道
    const pipeline = [
      { $match: { 'fullDocument.username': 'alice' } }
    ];

    // 在集合上打开一个 Change Stream
    const changeStream = collection.watch(pipeline);

    console.log('Watching for changes...');

    // 监听 'change' 事件
    for await (const change of changeStream) {
      console.log('Received a change event: \n', JSON.stringify(change, null, 2));
    }

  } finally {
    await client.close();
  }
}

watchChanges().catch(console.error);
```

### Change Event 文档结构

Change Stream 返回的事件文档包含有关更改的详细信息。一个典型的事件结构如下：

```json
{
  "_id": { "_data": "..." },
  "operationType": "update",
  "clusterTime": { "$timestamp": { "t": ..., "i": ... } },
  "ns": { "db": "testdb", "coll": "inventory" },
  "documentKey": { "_id": ... },
  "updateDescription": {
    "updatedFields": { "status": "urgent" },
    "removedFields": []
  },
  "fullDocument": {
    "_id": ...,
    "username": "alice",
    "status": "urgent"
  }
}
```

- `operationType`：操作类型，如 `insert`、`update`、`delete`、`replace`。
- `ns`：命名空间，指定了数据库和集合。
- `documentKey`：唯一标识被修改的文档。
- `updateDescription`：对于 `update` 操作，描述了哪些字段被更改。
- `fullDocument`：包含更改后的完整文档（默认情况下，对于 `update` 操作，需要额外配置才能获取）。

## 配置选项

在使用 `.watch()` 方法时，您可以传递一些选项来定制 Change Streams 的行为：

- `fullDocument`：
  - `'default'` (默认): 对于 `insert` 和 `replace` 操作，包含 `fullDocument`。对于 `update` 操作，不包含。
  - `'updateLookup'`: 对于 `update` 操作，查找并返回文档的最新版本。
  - `'required'`: 要求 `fullDocument` 存在。
  - `'whenAvailable'`: 仅在可用时返回。

- `resumeAfter`：指定一个恢复令牌 (`_id`)，从该令牌之后开始恢复事件流。

- `startAtOperationTime`：从一个特定的时间戳开始监听。

## 注意事项与最佳实践

- **复制集要求**：Change Streams 只能在复制集或分片集群上使用。单机实例不支持。
- **读关注 (Read Concern)**：Change Streams 使用 `majority` 读关注。
- **Oplog 大小**：确保您的 oplog 足够大，以避免在应用程序离线时因 oplog 翻滚而丢失事件。
- **错误处理**：在生产环境中，实现健壮的错误处理和重连逻辑至关重要。
- **权限**：用户需要 `changeStream` 和 `find` 权限才能在集合上使用 Change Streams。

通过利用 Change Streams，您可以构建出高度动态和响应迅速的应用程序，从而提升用户体验和系统效率。
