# 12. OSPF (Open Shortest Path First)

OSPF 是目前应用最广泛、最重要的内部网关协议（IGP）之一。它是一个开放标准的、基于链路状态算法的路由协议。与 EIGRP 不同，OSPF 可以在几乎所有厂商的网络设备上运行，这使其在多厂商混合的网络环境中备受青睐。

---

### 12.1 OSPF 的核心特点

-   **开放标准**: 由 IETF 定义在 RFC 2328 中，具有极好的互操作性。
-   **链路状态算法**:
    -   每台 OSPF 路由器都使用 **SPF (Shortest Path First) 或 Dijkstra 算法**来计算到达所有已知网络的无环路路径。
    -   路由器之间交换的是**链路状态通告 (LSA)**，而不是路由表。所有路由器最终会构建一个相同的**链路状态数据库 (LSDB)**，即整个网络的拓扑地图。
-   **快速收敛**: 当网络拓扑发生变化时，路由器会立即泛洪（flooding）更新的 LSA，使得整个网络能够快速地重新计算路径并收敛。
-   **无类路由协议**: OSPF 在设计上就是无类的，它在更新中携带子网掩码信息，完全支持 VLSM 和不连续子网。
-   **高效的更新**: 使用触发式、增量的更新。只有在网络变化时才发送更新，且只发送变化的部分。
-   **度量标准 (Metric)**: 使用**成本 (Cost)** 作为度量标准。成本是根据链路的**带宽**自动计算的，`Cost = 参考带宽 / 接口带宽`。管理员可以手动修改参考带宽或接口成本来影响路径选择。
-   **支持区域 (Areas)**: OSPF 允许将一个大型的自治系统（AS）划分成多个**区域**。这极大地提高了 OSPF 的可扩展性。

---

### 12.2 OSPF 的邻居和邻接关系

OSPF 路由器通过交换 **Hello** 包来发现邻居并建立关系。要成为邻居，两台路由器接口上的以下参数必须匹配：
-   **Area ID**: 必须在同一个区域。
-   **Hello/Dead 时间间隔**: Hello 包发送的频率和宣告邻居死亡的等待时间必须一致。
-   **认证**: 如果启用了认证，密码和类型必须一致。
-   **子网掩码**: 必须在同一个子网中。

并非所有邻居都会发展成完全的**邻接 (Adjacency)** 关系。在以太网等多路访问网络中，为了减少 LSA 的交换数量，会选举一个 **指定路由器 (DR)** 和一个 **备份指定路由器 (BDR)**。网络中的所有其他路由器只与 DR 和 BDR 建立完全的邻接关系，并只将自己的 LSA 发送给 DR。然后由 DR 负责将这些 LSA 泛洪给网络中的所有其他路由器。

---

### 12.3 OSPF 区域 (Areas)

区域是 OSPF 最重要的特性之一。通过将 AS 划分为多个区域，可以实现：
-   **减小 LSDB 的大小**: 每台路由器只需要维护其所在区域的详细拓扑信息，而不是整个 AS 的。
-   **减少 SPF 算法的计算负担**: SPF 算法只在区域内部运行。
-   **限制 LSA 的泛洪范围**: 大多数 LSA 只会在其产生的区域内部泛洪，不会穿越到其他区域。

所有 OSPF 网络都必须有一个 **骨干区域 (Backbone Area)**，即 **Area 0**。所有其他非骨干区域都必须**直接连接**到 Area 0。区域之间的路由信息交换由 **区域边界路由器 (Area Border Router, ABR)** 负责。

---

### 12.4 单区域 OSPF 配置

在只有一个区域的网络中（通常就是 Area 0），OSPF 的配置非常简单。

**配置示例**:
```bash
Router(config)# router ospf 1
# "1" 是进程号 (Process ID)，它只在本地路由器上有意义，不必在所有路由器上都相同。

# 使用 network 命令宣告参与 OSPF 的接口和区域
# 写法一：使用主类网络
Router(config-router)# network 10.0.0.0 0.255.255.255 area 0

# 写法二：使用精确的反向掩码（推荐）
# 宣告 192.168.1.0/24 网络
Router(config-router)# network 192.168.1.0 0.0.0.255 area 0
# 宣告 10.1.1.1/32 接口（例如 loopback 接口）
Router(config-router)# network 10.1.1.1 0.0.0.0 area 0

# (可选) 手动设置 Router ID
Router(config-router)# router-id 1.1.1.1

# (可选) 修改 Cost
Router(config-router)# interface Serial0/0
Router(config-if)# ip ospf cost 1562
```
-   **Router ID**: 是一个 32 位的点分十进制数，用于在 OSPF 网络中唯一标识一台路由器。如果没手动配置，OSPF 会自动选择一个 Loopback 接口的最高 IP 地址或物理接口的最高 IP 地址作为 Router ID。最佳实践是**手动配置**。
-   **network 命令**: 这个命令的作用不是通告网络，而是告诉 OSPF 在哪些接口上**启用**协议。只有启用了 OSPF 的接口所在的网络才会被通告出去。

---

### 12.5 验证 OSPF

```bash
# 查看 OSPF 邻居关系
show ip ospf neighbor

# 查看 OSPF 协议的总体信息
show ip ospf

# 查看某个接口的 OSPF 相关信息
show ip ospf interface brief
show ip ospf interface <interface-name>

# 查看 OSPF 路由
show ip route ospf
```
`show ip ospf neighbor` 是最重要的排错命令之一。如果邻居关系没有达到 `FULL` 状态，你需要检查两边的接口配置是否满足邻居建立的条件。 