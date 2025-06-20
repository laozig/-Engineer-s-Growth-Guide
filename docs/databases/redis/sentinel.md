# Redis Sentinel (哨兵)

Redis Sentinel 是 Redis 官方推荐的高可用性（High Availability）解决方案。它是一个分布式系统，用于监控多个 Redis 主从实例，并在主节点下线时，能够自动地将一个从节点提升为新的主节点，从而实现故障转移（Failover）。

## 目录
- [Sentinel 的作用](#sentinel-的作用)
- [核心概念](#核心概念)
  - [主观下线 (SDOWN)](#主观下线-sdown)
  - [客观下线 (ODOWN)](#客观下线-odown)
  - [领导者选举 (Leader Election)](#领导者选举-leader-election)
  - [故障转移 (Failover)](#故障转移-failover)
- [工作原理](#工作原理)
- [如何配置和部署](#如何配置和部署)
  - [配置文件 (`sentinel.conf`)](#配置文件-sentinelconf)
  - [启动 Sentinel](#启动-sentinel)
  - [客户端连接](#客户端连接)
- [故障转移的详细步骤](#故障转移的详细步骤)
- [常见问题与运维要点](#常见问题与运维要点)
- [总结](#总结)

---

## Sentinel 的作用

Sentinel 系统的核心功能可以概括为以下四点：

1.  **监控 (Monitoring)**：Sentinel 会持续地检查主节点和从节点是否正常工作。
2.  **通知 (Notification)**：当被监控的 Redis 实例出现问题时，Sentinel 可以通过 API 通知系统管理员或其他应用程序。
3.  **自动故障转移 (Automatic Failover)**：当主节点无法正常工作时，Sentinel 会启动故障转移流程，从从节点中选举一个作为新的主节点。
4.  **配置提供者 (Configuration Provider)**：客户端可以连接到 Sentinel 来获取当前 Redis 主节点的地址。当故障转移发生后，Sentinel 会报告新的主节点地址。

## 核心概念

### 主观下线 (SDOWN - Subjectively Down)

单个 Sentinel 实例，如果超过配置的 `down-after-milliseconds` 时间未能收到某个 Redis 实例（主或从）的有效 PING 回复，就会在自己的视角里，将该实例标记为**主观下线**。这个判断是单个 Sentinel 自己做出的，可能存在误判（例如，仅仅是该 Sentinel 与目标实例之间的网络不通）。

### 客观下线 (ODOWN - Objectively Down)

当一个 Sentinel 将主节点标记为"主观下线"后，它会向其他 Sentinel 实例发送 `SENTINEL is-master-down-by-addr` 命令，询问它们是否也认为该主节点已下线。当足够数量（达到 `quorum` 配置）的 Sentinel 都认为主节点主观下线时，该主节点就会被标记为**客观下线**。这个标记是集群共识的结果，更加可靠。

只有主节点才会被标记为客观下线，从节点或其他 Sentinel 实例的下线都只是主观下线。

### 领导者选举 (Leader Election)

一旦主节点被确认为客观下线，所有 Sentinel 实例会进行一次领导者选举。选举遵循 Raft 算法，在一个任期（epoch）内，得票超过半数（并且票数达到 `quorum` 数量）的 Sentinel 将成为领导者，由它来负责执行接下来的故障转移操作。

### 故障转移 (Failover)

由选举出的领导者 Sentinel 来执行整个故障转移流程，主要包括：
1.  从健康的从节点中，按照一定规则（优先级、复制偏移量、运行ID）挑选一个最优的从节点。
2.  向选出的从节点发送 `REPLICAOF NO ONE` 命令，使其成为新的主节点。
3.  向其余的从节点发送 `REPLICAOF` 命令，让它们去复制新的主节点。
4.  更新内部记录，将旧的主节点标记为新主节点的从节点，等待其恢复后加入新的主从架构。

## 工作原理

1.  **三个定时任务**：
    -   每10秒，每个 Sentinel 向主从节点发送 `INFO` 命令，以发现新的从节点和确认主从关系。
    -   每2秒，每个 Sentinel 通过主节点的 `channel`（`__sentinel__:hello`）交换信息，以发现其他 Sentinel 实例并建立连接。
    -   每1秒，每个 Sentinel 向所有实例（包括主从节点和其他 Sentinel）发送 `PING` 命令，进行心跳检测，这是实现主观下线的基础。
2.  **故障检测与转移**：
    -   当 `PING` 超时，实例被标记为 **SDOWN**。
    -   如果下线的是主节点，Sentinel 之间通过投票，将其标记为 **ODOWN**。
    -   Sentinel 集群进行**领导者选举**。
    -   领导者 Sentinel 执行**故障转移**。

## 如何配置和部署

假设有一个主节点 `127.0.0.1:6379` 和两个从节点，我们需要部署一个由3个 Sentinel 实例组成的监控集群。

### 配置文件 (`sentinel.conf`)

为每个 Sentinel 创建一个配置文件，例如 `sentinel-26379.conf`：
```conf
# 监控的主节点，别名为 mymaster，quorum 为 2
# 表示至少需要 2 个 Sentinel 同意，才能将主节点标记为客观下线
sentinel monitor mymaster 127.0.0.1 6379 2

# 主节点被标记为主观下线所需的毫秒数
sentinel down-after-milliseconds mymaster 30000

# 故障转移的超时时间
sentinel failover-timeout mymaster 180000

# 在同一时间，只允许一个从节点对新的主节点进行同步
# parallel-syncs <master-name> <num-replicas>
sentinel parallel-syncs mymaster 1
```
**注意**：`sentinel monitor` 是最重要的配置，Sentinel 会自动发现该主节点下的所有从节点和其他 Sentinel 实例。为了高可用，Sentinel 实例的数量应为奇数（如3, 5, 7），并且 `quorum` 的值建议设为 `(N/2) + 1`，其中 N 是 Sentinel 的总数。

### 启动 Sentinel

可以通过以下两种方式启动 Sentinel：
```bash
# 方式一：直接使用 sentinel 程序
redis-sentinel /path/to/sentinel.conf

# 方式二：使用 redis-server 并开启 sentinel 模式
redis-server /path/to/sentinel.conf --sentinel
```
为另外两个 Sentinel 实例创建不同的配置文件（修改端口号），并依次启动。

### 客户端连接
客户端不应该直接硬编码主节点的 IP 地址，而应该连接到 Sentinel。客户端首先向 Sentinel 查询指定 `master-name` 的当前主节点地址，然后才连接到该地址进行操作。当故障转移发生后，客户端再次向 Sentinel 查询，就能获取到新的主节点地址。

## 故障转移的详细步骤

1.  **选出新主节点**：领导者 Sentinel 会从所有健康的从节点中，按以下顺序进行筛选：
    a. 排除掉线或长时间未响应的从节点。
    b. 排除掉与主节点断开时间过长的从节点。
    c. 按从节点优先级 (`replica-priority`) 从低到高排序，优先级越低（数字越小）越优先。
    d. 如果优先级相同，比较复制偏移量 (`replication offset`)，偏移量越大（数据越新）越优先。
    e. 如果偏移量也相同，比较运行 ID (`runid`)，选择 ID 较小的。
2.  **执行切换**：向选出的从节点发送 `REPLICAOF NO ONE`。
3.  **更新从节点**：向其他从节点发送 `REPLICAOF <new-master-ip> <new-master-port>`。

## 常见问题与运维要点
- **部署**：Sentinel 实例应该部署在与 Redis 实例不同的物理机或虚拟机上，以保证其自身的可用性。
- **Quorum 的重要性**：`quorum` 的数量只用于判断客观下线，而领导者选举需要超过半数（`N/2 + 1`）的 Sentinel 参与才能成功。
- **时间同步**：确保所有 Redis 实例和 Sentinel 实例所在的服务器时间是同步的，否则可能影响故障判断。
- **客户端支持**：需要使用支持 Sentinel 模式的 Redis 客户端库，才能实现自动的主节点地址查询和切换。

## 总结
Redis Sentinel 为 Redis 提供了强大的高可用能力，它通过去中心化的协作方式，实现了对主从系统的健康监控和自动故障转移。虽然 Redis Cluster 在数据分片方面更胜一筹，但对于不需要数据分片、只追求高可用的场景，Sentinel 依然是一个非常成熟、可靠且易于部署的解决方案。 