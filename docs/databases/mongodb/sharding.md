# MongoDB 分片 (Sharding)

当数据量增长到单个服务器的存储容量或处理能力无法满足需求时，就需要进行**水平扩展（Horizontal Scaling）**。在 MongoDB 中，实现水平扩展的核心技术就是**分片（Sharding）**。分片是将一个大的集合水平拆分，并将数据分布到多个服务器（或复制集）上的过程。

## 目录
- [为什么要分片？](#为什么要分片)
- [分片集群的架构](#分片集群的架构)
  - [Shards (分片)](#shards-分片)
  - [Config Servers (配置服务器)](#config-servers-配置服务器)
  - [Mongos (查询路由)](#mongos-查询路由)
- [分片的核心概念](#分片的核心概念)
  - [分片键 (Shard Key)](#分片键-shard-key)
  - [数据块 (Chunks)](#数据块-chunks)
  - [均衡器 (Balancer)](#均衡器-balancer)
- [如何选择一个好的分片键？](#如何选择一个好的分片键)
  - [分片键的基数 (Cardinality)](#分片键的基数-cardinality)
  - [分片键的写分布 (Write Distribution)](#分片键的写分布-write-distribution)
  - [分片键的读分布 (Read Distribution)](#分片键的读分布-read-distribution)
- [分片策略](#分片策略)
  - [范围分片 (Ranged Sharding)](#范围分片-ranged-sharding)
  - [哈希分片 (Hashed Sharding)](#哈希分片-hashed-sharding)
- [分片的优缺点](#分片的优缺点)

---

## 为什么要分片？

当应用面临以下挑战时，应考虑使用分片：

1.  **存储容量瓶颈**：单个服务器的磁盘空间不足以存储整个数据集。
2.  **吞吐量瓶颈**：单个服务器的 CPU 或 RAM 无法处理应用的读写请求负载（即使使用了复制集进行读扩展）。
3.  **地理分布需求**：希望将数据存放在离用户更近的地理位置，以减少网络延迟（通过区域分片 Zones）。

分片通过将数据分布到多个分片上，使得整个集群的存储容量和处理能力可以随着分片的增加而线性增长。

## 分片集群的架构

一个 MongoDB 分片集群主要由三个组件构成：

### Shards (分片)

-   每个分片是存储整个数据集的一个子集（subset）的 `mongod` 实例。
-   **在生产环境中，每一个分片都应该是一个复制集（Replica Set）**，以保证分片级别的高可用性。如果一个分片的主节点宕机，其复制集内部会选举出新的主节点，保证该分片上的数据服务不中断。

### Config Servers (配置服务器)

-   配置服务器是一组特殊的 `mongod` 实例，它们存储了整个集群的**元数据（Metadata）**。
-   这些元数据包括：
    -   分片键是什么。
    -   每个数据块（Chunk）分布在哪个分片上。
    -   集群的认证和授权信息。
-   配置服务器本身也必须以**复制集**的形式部署（从 MongoDB 3.4 开始强制要求），以保证元数据的高可用性。

### Mongos (查询路由)

-   `mongos` 是一个轻量级的、无状态的路由服务。**应用程序不直接连接到任何分片，而是连接到 `mongos`**。
-   `mongos` 从配置服务器缓存元数据，它知道所有数据在各个分片上的分布情况。
-   当一个查询到达 `mongos` 时，它会解析查询，根据分片键将查询**路由**到一个或多个相关的分片上，然后合并从分片返回的结果，最后将最终结果返回给客户端。
-   可以运行多个 `mongos` 实例来分担路由压力并实现路由层的高可用。

**数据流**：`Application <-> Mongos <-> Shards & Config Servers`

## 分片的核心概念

### 分片键 (Shard Key)

-   分片键是你在一个集合中选定的、**已建立索引**的一个或多个字段。MongoDB 使用这个键的值来计算和决定一个文档应该存储在哪个分片上。
-   **一旦一个集合被分片，其分片键就不可更改**。
-   分片键的选择是分片策略中最重要的一环，直接决定了分片集群的性能和可扩展性。

### 数据块 (Chunks)

-   MongoDB 不会逐个文档地移动数据。它会将集合划分为连续的、基于分片键范围的数据块（Chunks）。每个 Chunk 是一个包含一定范围内分片键值的文档集合。
-   默认情况下，一个 Chunk 的大小为 64MB（可配置）。

### 均衡器 (Balancer)

-   均衡器是一个在后台运行的进程，它负责监控各个分片上的 Chunk 数量。
-   当某个分片上的 Chunk 数量明显多于其他分片时，均衡器会自动启动，将一些 Chunk 从最繁忙的分片**迁移**到最空闲的分片，以确保数据在整个集群中分布均匀。
-   数据迁移过程对应用是透明的。

## 如何选择一个好的分片键？

一个理想的分片键应具备以下三个特性：

### 1. 分片键的基数 (Cardinality)

-   **含义**：分片键所能拥有的**不同值的数量**。
-   **要求**：基数应该非常高。低基数的分片键（如 `gender: ["male", "female"]`）会导致所有数据只能被划分到极少数的几个 Chunk 中，无法有效地分布到多个分片上，形成"巨型数据块"（Jumbo Chunks）。

### 2. 分片键的写分布 (Write Distribution)

-   **含义**：写操作是否能够均匀地分布到所有分片上。
-   **要求**：应避免"热点"分片。如果分片键是单调递增的（如时间戳、自增 ID），那么所有新的写入操作都会集中在最后一个分片上，导致该分片成为性能瓶颈，而其他分片处于空闲状态。

### 3. 分片键的读分布 (Read Distribution)

-   **含义**：读操作能否被高效地路由。
-   **要求**：最理想的情况是，大部分查询都包含分片键，这样 `mongos` 就可以将查询**精确地路由到单个分片**（称为 Targeted Query），避免了向所有分片广播查询（Scatter-Gather Query）所带来的性能开销。

## 分片策略

### 范围分片 (Ranged Sharding)

-   根据分片键的**值范围**来划分数据。分片键值相邻的文档很可能被存放在同一个 Chunk 和同一个分片上。
-   **优点**：对于基于范围的查询（如 `find({timestamp: {$gt: T1, $lt: T2}})`）非常高效，因为 `mongos` 可以直接将查询路由到包含该范围的分片。
-   **缺点**：如果分片键是单调递增的（如时间戳），容易产生写操作的热点问题。

### 哈希分片 (Hashed Sharding)

-   MongoDB 会先计算分片键值的**哈希值**，然后根据这个哈希值的范围来划分数据。
-   **优点**：即使分片键是单调递增的，它们的哈希值也是随机分布的，因此可以确保写操作**均匀地分布**到所有分片上，避免了热点问题。
-   **缺点**：牺牲了范围查询的性能。由于分片键值相邻的文档被哈希到了不同的分片，一个范围查询很可能需要广播到所有分片。

**复合分片键**：也可以使用多个字段作为分片键，例如 `{ customer_id: 1, order_id: 1 }`，以满足更复杂的分布和查询需求。

## 分片的优缺点

**优点**：
-   提供近乎无限的水平扩展能力。
-   通过将负载分散到多个节点，提高读写吞吐量。
-   通过 Zones 实现数据的地理分布。

**缺点**：
-   **架构复杂性**：部署和维护一个分片集群比单个复制集要复杂得多。
-   **分片键选择**：错误的分片键选择是不可逆的，可能导致性能问题。
-   **查询限制**：某些操作在分片环境下有限制或表现不同（例如，`update` 默认只能针对单个文档）。
-   **备份和恢复更复杂**。

**结论**：分片是一个强大的功能，但不应轻易使用。只有当数据量和负载确实超出了单个复制集的能力范围时，才应考虑引入分片。在决定分片之前，应充分优化应用、查询和索引。 