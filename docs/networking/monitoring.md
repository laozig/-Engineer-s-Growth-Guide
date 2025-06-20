# 19. 网络监控与管理 (SNMP & NetFlow)

一个网络搭建完成后，持续的监控和管理是确保其稳定、高效和安全运行的关键。网络管理员需要工具来了解网络的健康状况、流量模式和潜在问题。在众多工具中，SNMP 和 NetFlow 是两种最基础、最重要的技术。

---

### 19.1 SNMP (Simple Network Management Protocol)

SNMP 是一种标准的互联网协议，用于收集和组织关于受管设备（如路由器、交换机、服务器）的信息，并修改这些信息以改变设备行为。

**SNMP 的核心组件**:
1.  **管理站 (NMS - Network Management Station)**:
    -   运行监控软件的计算机，通常是一个强大的服务器。
    -   NMS 向网络中的设备发送请求，收集数据，并提供一个用户界面来展示网络状态。流行的 NMS 软件包括 PRTG, SolarWinds, Zabbix 等。
2.  **被管设备 (Managed Device)**:
    -   网络中任何包含 SNMP 代理（Agent）并可以通过 SNMP 访问的设备。
3.  **SNMP 代理 (Agent)**:
    -   运行在被管设备上的软件模块。
    -   它负责收集设备的本地信息，并响应来自 NMS 的查询。
4.  **MIB (Management Information Base)**:
    -   MIB 是一个**分层的、树状结构的数据库**，它定义了被管设备上所有可以通过 SNMP 进行查询或设置的变量。
    -   每个变量被称为一个**对象标识符 (Object Identifier, OID)**。例如，有一个特定的 OID 用于表示接口的输入流量，另一个 OID 用于表示 CPU 的使用率。

**SNMP 的操作**:
-   `Get`: NMS 从代理处获取一个或多个 OID 的值。这是**最常用**的操作，用于轮询设备状态。
-   `Set`: NMS 向代理设置一个 OID 的值，用于修改设备配置（如禁用一个端口）。此操作需谨慎使用。
-   `Trap`: **与前两者方向相反**。当代理检测到某个重要事件发生时（如接口关闭、设备重启），它会**主动**向 NMS 发送一个 `Trap` 消息进行告警。这比 NMS 持续轮询更高效。

**SNMP 版本**:
-   **v1**: 最早的版本，非常简单，但安全性差（使用纯文本的 community string 进行认证）。
-   **v2c**: v1 的增强版，改进了性能，但仍然使用 community string，安全性不足。**目前在许多内部网络中仍被广泛使用**。
-   **v3**: **最安全的版本**。提供了强大的安全特性，包括加密、消息完整性验证和严格的用户认证。在对安全性要求高的环境中应首选 v3。

---

### 19.2 NetFlow

如果说 SNMP 提供了关于**"什么"**（What）的信息（如 CPU 使用率、接口带宽），那么 NetFlow 则提供了关于**"谁"和"如何"**（Who & How）的信息。NetFlow 是一种由思科开发的技术，用于收集和分析网络中流经路由器或交换机的 IP 流量。

**什么是"流" (Flow)?**
一个流是一组具有相同特征的单向数据包序列。一个流通常由以下七个关键字段定义：
1.  源 IP 地址
2.  目的 IP 地址
3.  源端口号
4.  目的端口号
5.  三层协议类型 (如 TCP, UDP)
6.  服务类型 (ToS) 字节
7.  输入逻辑接口

当路由器看到一个与现有流不匹配的数据包时，它会创建一个新的流记录。当它认为流结束后（例如，看到 TCP FIN/RST 标志，或长时间没有新数据包），它会将这个流的统计信息（如总字节数、总包数、持续时间）从缓存中导出。

**NetFlow 的组件**:
1.  **导出器 (Exporter)**: 开启了 NetFlow 功能的路由器或交换机。它负责监控流量、创建流记录并将其导出。
2.  **收集器 (Collector)**: 接收并存储来自导出器的 NetFlow 数据的服务器。
3.  **分析器 (Analyzer)**: 分析收集到的数据，并生成可读的报告和图表，向管理员展示流量模式。

**NetFlow 的应用**:
-   **网络分析**: 了解谁在使用最多的带宽，什么应用（如视频、P2P）占用了网络资源。
-   **容量规划**: 根据历史流量数据，预测未来的带宽需求。
-   **安全检测**: 通过分析异常的流量模式（如端口扫描、DDoS 攻击的特征），来识别潜在的安全威胁。
-   **计费**: 根据用户或部门的流量使用情况进行计费。

---

### 19.3 在思科路由器上配置

**基本 SNMPv2c (只读) 配置**:
```bash
# "RO_COMMUNITY" 是只读的 community string，相当于密码
# "ACL_FOR_NMS" 是一个访问控制列表，只允许指定的 NMS 服务器 IP 来查询
Router(config)# snmp-server community RO_COMMUNITY ro ACL_FOR_NMS
# 启用发送 Trap 消息到 NMS
Router(config)# snmp-server host 10.1.1.100 RO_COMMUNITY
# "10.1.1.100" 是 NMS 服务器的地址
```

**基本 NetFlow 配置**:
```bash
# 配置 NetFlow 导出版本和目标收集器
Router(config)# ip flow-export version 9
Router(config)# ip flow-export destination 10.1.1.200 9996
# "10.1.1.200" 是收集器地址，"9996" 是收集器监听的 UDP 端口

# 在需要监控流量的接口上启用 NetFlow
Router(config)# interface GigabitEthernet0/1
# 同时监控进入和离开接口的流量
Router(config-if)# ip flow ingress
Router(config-if)# ip flow egress
```

**验证命令**:
```bash
# 查看 SNMP 配置
show snmp
# 验证 NetFlow 接口配置
show ip flow interface
# 查看 NetFlow 缓存中的活动流
show ip cache flow
# 查看 NetFlow 导出统计
show ip flow export
``` 