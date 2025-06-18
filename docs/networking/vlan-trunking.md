# 5. VLAN 与 Trunking

在传统的扁平化二层网络中，所有设备都在同一个广播域。这意味着任何一台设备发送广播帧（如 ARP 请求），网络中的所有其他设备都会收到。当网络规模变大时，这会产生大量不必要的流量，降低网络性能。VLAN（虚拟局域网）技术正是为了解决这个问题而生的。

---

### 5.1 什么是 VLAN (Virtual LAN)？

VLAN 是一种在物理交换机上创建逻辑上独立的网络的技术。它可以将一个物理交换机划分成多个虚拟的交换机，每个 VLAN 就是一个独立的广播域。

**核心优势**:
1.  **隔离广播域**: 这是 VLAN 最主要的功能。广播帧会被限制在它们所属的 VLAN 内部，不会被转发到其他 VLAN。这大大减少了网络流量，提升了性能。
2.  **增强网络安全**: 不同 VLAN 之间的设备在二层上是隔离的，默认情况下无法直接通信。它们之间的通信必须通过三层设备（如路由器或三层交换机）进行，这为在三层设备上部署访问控制策略提供了机会。
3.  **提高灵活性**: VLAN 的划分不受物理位置的限制。无论用户身处何处，只要将其端口分配到相应的 VLAN，他们就属于该逻辑网络。例如，可以将不同楼层的财务部员工划分到同一个"财务VLAN"中。

---

### 5.2 配置 VLAN

在思科交换机上，VLAN 的配置非常直接。

```bash
# 进入全局配置模式
Switch> enable
Switch# configure terminal

# 创建 VLAN 10 并命名为 Sales
Switch(config)# vlan 10
Switch(config-vlan)# name Sales

# 创建 VLAN 20 并命名为 Marketing
Switch(config)# vlan 20
Switch(config-vlan)# name Marketing

# 退出配置模式
Switch(config-vlan)# end

# 查看 VLAN 信息
Switch# show vlan brief
```
`show vlan brief` 命令会显示交换机上所有的 VLAN 以及哪些端口被分配给了这些 VLAN。默认情况下，所有端口都在 VLAN 1 中。

---

### 5.3 分配端口到 VLAN (Access Ports)

一个被分配到特定 VLAN 的端口称为**接入端口 (Access Port)**。接入端口只能属于一个 VLAN，并且通常用于连接终端设备（如计算机、打印机）。

```bash
# 进入接口配置模式
Switch# configure terminal
Switch(config)# interface FastEthernet 0/1

# 将该端口设置为接入模式
Switch(config-if)# switchport mode access

# 将该端口分配给 VLAN 10 (Sales)
Switch(config-if)# switchport access vlan 10

# 配置另一个端口到 VLAN 20
Switch(config)# interface FastEthernet 0/2
Switch(config-if)# switchport mode access
Switch(config-if)# switchport access vlan 20
```
现在，连接到 `Fa0/1` 的设备就在 Sales VLAN 中，而连接到 `Fa0/2` 的设备就在 Marketing VLAN 中。它们之间无法在二层直接通信。

---

### 5.4 Trunking (中继)

当我们需要在多个交换机之间扩展 VLAN 时，就需要用到 **Trunking**。如果两个交换机上都有 VLAN 10 和 VLAN 20 的用户，我们总不能为每个 VLAN 都拉一根物理线缆连接交换机吧？

**Trunk 端口**就是解决这个问题的。Trunk 端口是一种特殊的端口，它能够同时承载**多个 VLAN** 的流量。

**工作原理**:
当一个数据帧要通过 Trunk 链路从一个交换机传到另一个交换机时，发送方的交换机会给这个帧打上一个"标签（Tag）"，指明它属于哪个 VLAN。接收方的交换机看到这个标签后，就知道应该将这个帧转发到哪个 VLAN 的端口。

**802.1Q 协议**:
这是业界标准的 Trunking 协议。它通过在以太网帧的源 MAC 地址和类型字段之间插入一个 4 字节的 **802.1Q 标签**来实现。这个标签中包含了 VLAN ID (VID) 信息。

**配置 Trunk**:
```bash
# 在连接两个交换机的端口上进行配置
Switch(config)# interface FastEthernet 0/24

# 将端口封装类型设置为 802.1Q
Switch(config-if)# switchport trunk encapsulation dot1q

# 将端口模式设置为 trunk
Switch(config-if)# switchport mode trunk
```
现在，`Fa0/24` 端口就成为了一个 Trunk 端口，所有 VLAN 的流量都可以通过它在交换机之间传递。

**Native VLAN**:
在 802.1Q Trunk 链路上，有一个特殊的 VLAN 叫做 **Native VLAN**。通过 Native VLAN 的流量是**不带标签**的。默认情况下，Native VLAN 是 VLAN 1。为了安全，最佳实践是更改 Native VLAN 并确保 Trunk 链路两端的 Native VLAN 必须一致。

---

### 5.5 VLAN 间路由 (Inter-VLAN Routing)

由于不同 VLAN 是隔离的，要让它们之间能够通信，就必须经过一个三层设备。这个过程称为 **VLAN 间路由**。常见实现方式有：
1.  **传统 VLAN 间路由**: 为每个 VLAN 在路由器上使用一个物理接口。成本高，扩展性差，已不常用。
2.  **单臂路由 (Router-on-a-Stick)**: 在路由器上创建一个物理接口，并为每个 VLAN 在其上配置一个逻辑的**子接口**。这是最经典的学习模型。
3.  **三层交换机 (Multilayer Switch)**: 在三层交换机上为每个 VLAN 创建一个**交换虚拟接口 (SVI)**。这是现代网络中最常用、性能最高的方式。 