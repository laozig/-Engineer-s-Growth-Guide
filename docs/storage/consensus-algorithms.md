# 4. 共识算法 (Paxos, Raft)

在分布式系统中，多个节点需要就某个值或状态达成一致的决定，这个过程就称为**共识 (Consensus)**。共识是构建可靠的、容错的分布式系统的核心基石。

例如：
- 在一个数据库集群中，所有节点必须对哪个节点是主节点（Leader）达成共识。
- 在一个分布式事务中，所有参与的节点必须对该事务是提交（Commit）还是中止（Abort）达成共识。
- 在一个状态机复制（State Machine Replication）系统中，所有副本必须对要执行的操作序列达成共识，以保证它们的状态保持一致。

共识算法的目标是，在一个可能存在节点故障和网络延迟的环境中，确保一组节点最终能够选择**同一个值**。

## Paxos 算法

Paxos由莱斯利·兰伯特（Leslie Lamport）在1990年提出，是共识算法的鼻祖，也是第一个被严格证明在异步系统（只假设消息最终会到达，但延迟无上限）中可以保证安全的共识算法。

Paxos的理论非常优雅但理解起来极其困难，它通过一个"两阶段提交"的协议来达成共识。

**Paxos中的角色**:
- **Proposer (提议者)**: 提出一个值，希望被选中。
- **Acceptor (接受者)**: 对Proposer提出的值进行投票。
- **Learner (学习者)**: 学习最终被选中的值。
在实际实现中，一个节点可以同时扮演多个角色。

**协议流程（简化版）**:
1.  **Phase 1: Prepare (准备阶段)**
    - Proposer选择一个全局唯一的、递增的提案编号`N`，向所有Acceptor发送`Prepare(N)`请求。
    - Acceptor收到`Prepare(N)`后，如果`N`大于它之前响应过的所有提案编号，它会承诺不再接受任何编号小于`N`的提案，并回复它之前已经接受（accept）过的最高编号的提案值（如果有的话）。

2.  **Phase 2: Accept (接受阶段)**
    - 如果Proposer收到了来自**多数派 (Majority)** Acceptor的响应，它会选择其中编号最高的提案值作为自己的提案值（如果响应中没有值，则可以使用自己的初始值）。然后，它向这些Acceptor发送`Accept(N, value)`请求。
    - Acceptor收到`Accept(N, value)`请求后，只要`N`不小于它已承诺的编号，它就会接受这个值。

3.  **学习阶段**:
    - 一旦一个值被多数派的Acceptor接受，这个值就被选定了。Learner可以通过各种方式得知这个被选定的值。

Paxos的正确性证明非常复杂，但它奠定了所有后续共识算法的理论基础。许多系统（如Google Chubby, Spanner）都使用了Paxos或其变种。

## Raft 算法

由于Paxos的难以理解和实现，斯坦福大学的Diego Ongaro和John Ousterhout在2014年设计了Raft算法，其核心目标就是**可理解性 (Understandability)**。Raft在提供与Paxos同等安全保证的前提下，结构更清晰，更容易被工程实现。Raft已成为现代分布式系统中最流行的共识算法。

Raft将共识问题分解为三个相对独立的子问题：
1.  **领导者选举 (Leader Election)**
2.  **日志复制 (Log Replication)**
3.  **安全性 (Safety)**

### Raft中的角色

Raft中的节点只有三种状态：
- **Leader (领导者)**: 负责处理所有客户端请求，管理日志复制。在任何时刻，一个集群中最多只有一个Leader。
- **Follower (跟随者)**: 被动的角色，接收并持久化来自Leader的日志，并在选举中投票。
- **Candidate (候选人)**: 在选举期间，一个Follower可以转变为Candidate来竞选Leader。

### 核心流程

1.  **领导者选举**:
    - 系统启动时，所有节点都是Follower。
    - 每个Follower都有一个选举计时器。如果在计时器超时前没有收到来自Leader的心跳，它就会转变为Candidate，发起新一轮选举。
    - Candidate会向所有其他节点发送投票请求。
    - 其他节点收到请求后，如果尚未投票，就会投票给该Candidate。
    - 一旦一个Candidate获得了**多数派**的选票，它就成为新的Leader。
    - Leader会周期性地向所有Follower发送心跳，以维持其领导地位。

2.  **日志复制**:
    - 当Leader收到客户端请求（例如，一个写操作）时，它会将这个操作作为一个日志条目（Log Entry）追加到自己的日志中。
    - 然后，Leader会将这个新的日志条目并行地发送给所有的Follower。
    - Follower收到后，会将其写入自己的日志，并向Leader发送确认。
    - 一旦Leader收到了来自**多数派**Follower的确认，它就认为这个日志条目是**已提交 (Committed)**的。
    - Leader会执行这个操作，并将结果返回给客户端。同时，它也会通知所有Follower该日志条目已提交，Follower也会执行该操作。

![Raft Log Replication](https://raft.github.io/raft.svg)
*(图片来源: The Raft Consensus Algorithm website)*

### 安全性保证

Raft通过一系列规则来保证共识的安全性，例如：
- 一个任期（Term）内最多只有一个Leader。
- 只有日志最完整的节点才能当选为Leader。
- Leader提交的日志条目必须是持久化的，不会被覆盖。

## Paxos vs. Raft

| 特性 | Paxos | Raft |
| --- | --- | --- |
| **核心思想** | 所有节点对等，通过两阶段协议达成共识。 | 强Leader模型，所有决策由Leader做出并分发。 |
| **可理解性** | 极难理解和实现。 | 设计目标就是为了可理解性，结构清晰。 |
| **领导者** | 没有明确的、持久的Leader概念。 | 有明确的Leader，通过选举产生。 |
| **应用** | Google Spanner, Chubby, Zookeeper (ZAB协议受Paxos启发) | etcd, Consul, TiKV, CockroachDB |

在当今的分布式系统领域，Raft及其变种已成为事实上的标准共识算法。理解Raft的工作原理，特别是领导者选举和日志复制的过程，对于理解现代分布式存储和协调服务的内部机制至关重要。 