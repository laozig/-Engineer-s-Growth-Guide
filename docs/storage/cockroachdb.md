# 19. CockroachDB

CockroachDB 是一个开源的、可扩展的、容错的分布式SQL数据库。它的名字"Cockroach"（蟑螂）形象地体现了其核心设计目标：**生存能力 (Survivability)**。CockroachDB旨在构建一个能够容忍磁盘、机器、机架甚至数据中心级别故障而不会中断服务、不会丢失数据的数据库。

与TiDB一样，CockroachDB也深受Google Spanner的启发，但它在架构上做出了不同的选择，提供了一个更一体化、更易于部署的解决方案。

## CockroachDB 架构: 对称与一体化

与TiDB的计算存储分离架构不同，CockroachDB采用的是**对称的、一体化的（Shared-Nothing）架构**。

![CockroachDB Architecture](https://www.cockroachlabs.com/docs/stable/media/architecture-overview.png)
*(图片来源: Cockroach Labs Docs)*

- **所有节点都是对等的**: 集群中的每个节点都是一个对称的**网关 (Gateway)**。这意味着客户端可以连接到**任何一个节点**来执行SQL查询。
- **一体化节点**: 每个CockroachDB节点都包含了SQL处理、分布式事务协调和数据存储的所有功能。它内部集成了：
  - **SQL层**: 负责解析、优化和执行SQL查询。
  - **分布式KV层**: 负责处理分布式事务和数据路由。
  - **存储层**: 负责将数据实际存储在本地磁盘上（使用RocksDB作为存储引擎）。

这种架构使得CockroachDB的部署和运维相对简单，因为只有一个服务需要部署和管理。

## 数据流与分层

当一个SQL查询进入一个CockroachDB节点时，它会经过以下几层：

1.  **SQL层**:
    - 接收PostgreSQL线协议的连接。
    - 将SQL查询文本转换为抽象语法树（AST），并最终生成一个优化的逻辑执行计划。

2.  **分布式KV层 (DistSender & TxnCoordinator)**:
    - **DistSender**: 负责将逻辑计划中的KV操作路由到正确的节点。它通过查询元数据（Meta Ranges）来找到存储目标Key的节点。
    - **TxnCoordinator**: 负责管理分布式事务的状态，执行两阶段提交协议，处理写入冲突和事务重试。

3.  **多副本一致性层 (Replication Layer)**:
    - 数据在这一层被组织成**范围 (Ranges)**，每个Range默认大小为512MB。这与TiKV的Region概念非常相似。
    - 每个Range都有多个副本，它们组成一个Raft Group，通过**Raft共识算法**来保证数据的一致性和高可用性。
    - 所有对该Range的读写请求都必须由其Raft Leader来处理。

4.  **存储层 (Storage Layer)**:
    - 使用**RocksDB**作为其底层的物理存储引擎，将数据持久化到本地磁盘。

## 地理分区 (Geo-Partitioning)

CockroachDB一个非常强大的特性是其**地理分区**能力，它允许你将数据固定（Pin）到特定的地理位置（如国家、城市、数据中心），以满足**数据主权**和**低延迟**的需求。

- **工作原理**:
  1.  你可以为集群中的每个节点设置其地理位置信息（例如 `locality=region=us-east-1`）。
  2.  你可以为表或表的某些行定义分区规则，指定哪些数据应该存储在哪个地理位置。
  - **分区 (Partitioning)**: `ALTER TABLE ... PARTITION BY ...`
  - **副本放置约束 (Replication Zone Constraints)**: `CONFIGURE ZONE ... SET CONSTRAINTS = '[+region=us-east-1]'`
- **优势**:
  - **数据主权**: 确保德国用户的数据只存储在德国境内的服务器上，满足GDPR等法规要求。
  - **低延迟读写**: 将数据放置在离用户最近的地方，可以显著降低访问延迟。例如，美国用户访问的数据副本位于美国，欧洲用户访问的数据副本位于欧洲。
  - CockroachDB的查询优化器能够感知数据的地理位置，并尽可能地将查询路由到持有本地数据的节点，或从最近的副本读取数据。

## CockroachDB vs. TiDB

| 特性 | CockroachDB | TiDB |
| --- | --- | --- |
| **核心架构** | 对称、一体化。每个节点都是全功能节点。| 计算与存储分离。由TiDB, TiKV, PD三个组件构成。|
| **部署与运维** | 相对简单，只有一个服务。 | 相对复杂，需要部署和协调多个组件。 |
| **协议兼容性** | **PostgreSQL** 线协议。 | **MySQL** 线协议。 |
| **地理分区** | **核心特性**。提供强大灵活的策略来控制数据地理位置。 | 相对较弱。可以通过标签来影响PD的调度，但不如CockroachDB的控制粒度精细。|
| **HTAP能力** | 不支持。专注于OLTP。 | **支持**。通过TiFlash节点提供HTAP能力。 |
| **生态系统** | 更加聚焦于数据库本身。 | 生态更庞大，包含数据迁移(DM)、数据同步(TiCDC)等多种工具。 |
| **最佳场景** | 需要**地理分布**、**数据主权**、**极致弹性**和**PostgreSQL兼容性**的OLTP应用。| 需要**MySQL兼容性**、**HTAP**能力、超大规模(PB级)数据存储的场景。|

## 总结

CockroachDB是一个专注于**弹性和生存能力**的分布式SQL数据库。它通过一体化的对称架构，提供了简单优雅的部署和扩展体验。其最突出的特性在于强大的地理分区能力，使其成为构建全球分布、需要满足数据主权合规性应用的理想选择。

如果你正在寻找一个与PostgreSQL兼容、能够轻松实现多活和地理分布的数据库，CockroachDB是一个极具竞争力的选项。而如果你的需求更偏向于MySQL兼容性和HTAP，TiDB可能是更好的选择。 