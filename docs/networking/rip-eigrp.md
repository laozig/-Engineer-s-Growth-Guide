# 11. RIP 和 EIGRP

在距离矢量路由协议的家族中，RIP 是最古老、最简单的协议之一，而 EIGRP 则是思科开发的一个高级、功能强大的混合型协议。了解它们的特点和差异对于选择合适的路由协议至关重要。

---

### 11.1 RIP (Routing Information Protocol)

RIP 是一个非常经典的距离矢量协议，主要用于小型、简单的网络。它使用"跳数"（Hop Count）作为唯一的度量标准（Metric）。每经过一台路由器，跳数加 1。

**RIP 的主要特点**:
-   **度量标准**: 仅使用跳数。最大有效跳数为 15，任何跳数达到 16 的路由都被认为是不可达的。这极大地限制了 RIP 的网络规模。
-   **路由更新**: 每隔 30 秒，RIP 路由器会将其完整的路由表广播给所有邻居。
-   **收敛速度**: 非常慢。除了 30 秒的更新周期，它还有多个计时器，导致网络拓扑变化后需要数分钟才能完全收敛。
-   **版本**:
    -   **RIPv1**: 有类路由协议（Classful）。不发送子网掩码信息，不支持 VLSM（可变长子网掩码）。使用广播（255.255.255.255）发送更新。
    -   **RIPv2**: 无类路由协议（Classless）。在路由更新中包含了子网掩码信息，支持 VLSM。使用多播（224.0.0.9）发送更新，减少了对非路由设备的干扰。
-   **现代应用**: 由于其种种限制，RIP 在现代生产网络中**已基本不再使用**，主要用于教学和非常小的、对性能要求不高的网络环境。

**RIPv2 配置示例**:
```bash
Router(config)# router rip
Router(config-router)# version 2
Router(config-router)# network 10.0.0.0
Router(config-router)# network 192.168.1.0
Router(config-router)# no auto-summary
```
-   `version 2`: 启用 RIPv2。
-   `network <network-address>`: 在连接到指定主类网络的所有接口上启用 RIP，并向邻居通告这个网络。
-   `no auto-summary`: 关闭自动汇总功能。在 RIPv2 中，这是一个必须的步骤以支持不连续子网。

---

### 11.2 EIGRP (Enhanced Interior Gateway Routing Protocol)

EIGRP 是思科开发的专有协议（现已部分开放），它是一个"高级距离矢量协议"或"混合型协议"。它结合了距离矢量协议的简易性和链路状态协议的快速收敛等优点。

**EIGRP 的主要特点**:
-   **快速收敛**:
    -   EIGRP 的核心是 **DUAL (Diffusing Update Algorithm)** 算法。
    -   它会为每个目标网络预先计算出一条**后继路由 (Successor)**，即最佳路径。
    -   同时，它还会计算出一条**可行后继路由 (Feasible Successor)**，即满足特定条件（可行性条件）的无环路备份路径。
    -   当主路径（后继路由）失效时，EIGRP 可以**立即**使用预先计算好的可行后继路由，无需重新计算，从而实现几乎瞬时的收敛。

-   **复杂的复合度量值 (Composite Metric)**:
    -   与 RIP 只看跳数不同，EIGRP 默认使用**带宽 (Bandwidth)** 和**延迟 (Delay)** 来计算度量值，能够更精确地反映路径的优劣。还可以包含链路的可靠性（Reliability）和负载（Load）。

-   **增量更新**:
    -   EIGRP 不会像 RIP 那样定期发送整个路由表。它只在网络拓扑发生变化时才发送**增量更新 (Partial Updates)**，且只发送给受影响的路由器。这大大减少了网络开销。

-   **邻居关系**:
    -   EIGRP 通过发送 Hello 包来发现和维护邻居关系。

-   **协议无关模块 (Protocol-Dependent Modules)**:
    -   EIGRP 不仅仅能路由 IPX 和 AppleTalk，还支持 IPv4 和 IPv6。

**EIGRP 配置示例**:
```bash
# AS 号码在同一个自治系统内的所有 EIGRP 路由器上必须相同
Router(config)# router eigrp 100

# 宣告直连网络，可以使用反向掩码（wildcard mask）进行精确控制
Router(config-router)# network 10.1.1.0 0.0.0.255
Router(config-router)# network 192.168.1.0 0.0.0.3

# (可选) 关闭自动汇总
Router(config-router)# no auto-summary
```

---

### 11.3 RIP vs EIGRP 对比总结

| 特性 | RIPv2 | EIGRP |
| :--- | :--- | :--- |
| **协议类型** | 标准的距离矢量 | 高级距离矢量 (混合型) |
| **标准** | 开放标准 (IETF) | 思科专有 (部分开放) |
| **度量标准** | 跳数 (Hop Count) | 带宽, 延迟, 可靠性, 负载 |
| **最大跳数** | 15 | 255 (默认为 100) |
| **收敛速度** | 慢 (数分钟) | 非常快 (秒级或亚秒级) |
| **环路避免** | 水平分割, 毒性逆转 | DUAL 算法, 可行性条件 |
| **更新方式** | 定期广播整个路由表 | 触发式增量更新 |
| **网络规模** | 小型网络 | 大型企业网络 |
| **管理距离(AD)**| 120 | 90 (内部) |

**结论**: EIGRP 在几乎所有方面都远超 RIP。在思科设备环境中，如果需要一个易于配置且性能卓越的 IGP，EIGRP 是一个绝佳的选择。 