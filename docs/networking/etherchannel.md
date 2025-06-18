# 7. 链路聚合 (EtherChannel)

随着网络流量的增加，交换机之间的单一链路很可能成为瓶颈。虽然可以升级到更高速率的链路（例如从 1Gbps 升级到 10Gbps），但这通常成本高昂。链路聚合（Cisco 称之为 EtherChannel）技术提供了一种经济高效的解决方案，它通过将多条物理链路捆绑成一条逻辑链路，来增加带宽并提供冗余。

---

### 7.1 EtherChannel 的优势

1.  **增加带宽**:
    -   这是最直接的好处。将四条 1Gbps 的物理链路捆绑在一起，就可以创建一条逻辑上拥有 4Gbps 带宽的链路。数据流会在这四条物理链路上进行负载均衡。

2.  **提供冗余和高可用性**:
    -   捆绑在一起的链路互为备份。如果其中一条物理链路发生故障，流量会自动地在剩余的链路上重新分配，整个过程对上层协议和用户是透明的，不会导致网络中断。这比 STP 在链路故障后需要 30-50 秒来重新收敛要快得多。

3.  **简化管理**:
    -   多条物理链路被视为一条逻辑链路（称为端口通道，Port-channel）。管理员只需要对这个逻辑接口进行配置（如配置为 Trunk、添加 VLAN 等），所有配置会自动应用到捆绑的所有物理接口上。

4.  **不违反 STP 规则**:
    -   由于 STP 将整个 EtherChannel 视为**一条**逻辑链路，因此不会将其中任何一条物理链路置于阻塞状态。所有物理链路都可以同时用于转发流量。

---

### 7.2 EtherChannel 的配置要求

要成功创建 EtherChannel，所有被捆绑的物理接口必须具有相同的配置。关键要求包括：

-   **相同的速率和双工模式**: 例如，所有接口都必须是 1Gbps 全双工。
-   **相同的 VLAN 配置**: 如果是接入端口，必须属于同一个 VLAN。如果是中继端口（Trunk），必须具有相同的 Native VLAN 和允许的 VLAN 列表。
-   **相同的 STP 配置**: 包括端口成本、优先级等。

---

### 7.3 EtherChannel 的协商协议

我们可以手动将接口配置为 EtherChannel 的一部分（`on` 模式），但更好的做法是使用协商协议。协商协议可以在链路的两端动态地、自动地协商和建立 EtherChannel，从而减少配置错误。

有两个主要的协商协议：

1.  **PAgP (Port Aggregation Protocol)**:
    -   **思科私有协议**。
    -   **模式**:
        -   `auto`: 被动模式。接口会等待对方发起协商。如果两端都设置为 `auto`，则 EtherChannel 不会建立。
        -   `desirable`: 主动模式。接口会主动向对方发起协商。
    -   **有效组合**: `desirable` - `desirable` 或 `desirable` - `auto`。

2.  **LACP (Link Aggregation Control Protocol)**:
    -   **业界标准 (IEEE 802.3ad)**。可以实现与非思科设备的互操作。
    -   **模式**:
        -   `passive`: 被动模式。类似于 PAgP 的 `auto`。如果两端都设置为 `passive`，则 EtherChannel 不会建立。
        -   `active`: 主动模式。类似于 PAgP 的 `desirable`。
    -   **有效组合**: `active` - `active` 或 `active` - `passive`。

**最佳实践**: 推荐使用 LACP，因为它是一个开放标准，具有更好的兼容性。

---

### 7.4 配置 LACP EtherChannel

以下是在两台交换机（SW1 和 SW2）之间配置一个二层 LACP EtherChannel 的示例。假设我们捆绑接口 `FastEthernet 0/1` 和 `FastEthernet 0/2`。

**在 SW1 上配置**:
```bash
SW1# configure terminal

# (可选但推荐) 先将要捆绑的接口恢复到默认设置
SW1(config)# interface range FastEthernet 0/1 - 2
SW1(config-if-range)# shutdown
SW1(config-if-range)# default interface FastEthernet 0/1
SW1(config-if-range)# default interface FastEthernet 0/2

# 创建端口通道逻辑接口
SW1(config)# interface port-channel 1

# (可选) 对逻辑接口进行配置，例如配置为 Trunk
SW1(config-if)# switchport mode trunk
SW1(config-if)# exit

# 将物理接口加入通道组
SW1(config)# interface range FastEthernet 0/1 - 2
SW1(config-if-range)# channel-group 1 mode active
# "active" 表示使用 LACP 主动模式。 "1" 是通道组号，必须与 port-channel 接口号一致。

# 重新启用接口
SW1(config-if-range)# no shutdown
```

**在 SW2 上配置**:
在 SW2 上执行完全相同的配置步骤。可以将对端的模式也设置为 `active` 或设置为 `passive`。

**验证 EtherChannel**:
```bash
# 查看 EtherChannel 的简要状态
show etherchannel summary

# 查看某个特定端口通道的详细信息
show etherchannel 1 port-channel

# 查看接口状态
show interfaces port-channel 1
```
`show etherchannel summary` 命令的输出中，状态标志 `(P)` 表示该通道正在使用中（in-use），`I` 表示它是一个独立的逻辑链路，`S` 表示它是一个二层 EtherChannel。这些都是我们期望看到的状态。

---

### 7.5 EtherChannel 的负载均衡

EtherChannel 并不会将一个大数据流（如一个大的文件传输）切分成小块分发到不同的链路上。它是在**数据流 (flow) 的层面上**进行负载均衡的。

交换机通过一个哈希算法来决定某个特定的数据流应该走哪条物理链路。哈希算法的输入可以是以下一项或多项的组合：
-   源 MAC 地址
-   目的 MAC 地址
-   源 IP 地址
-   目的 IP 地址
-   源 TCP/UDP 端口号
-   目的 TCP/UDP 端口号

默认的负载均衡方法通常是基于源 MAC 地址。为了实现更均匀的流量分配，最佳实践是配置一个包含 IP 地址和端口号的更复杂的负载均衡方法，例如 `src-dst-ip` 或 `src-dst-port`。
```bash
Switch(config)# port-channel load-balance src-dst-ip
``` 