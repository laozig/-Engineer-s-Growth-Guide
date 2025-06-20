# 17. 访问控制列表 (ACLs)

访问控制列表（Access Control List, ACL）是一系列有序的规则（称为访问控制条目, ACE），用于在路由器或防火墙接口上过滤流量。ACL 是网络安全的基本构建块，它定义了哪些流量被允许通过，哪些流量被拒绝。

---

### 17.1 ACL 的工作原理

-   ACL 是一系列 `permit` (允许) 或 `deny` (拒绝) 的语句。
-   当数据包到达应用了 ACL 的接口时，设备会从上到下逐条检查 ACL 的规则。
-   一旦数据包匹配了某条规则，设备会立即执行该规则的动作（`permit` 或 `deny`），并且**不再检查后续的任何规则**。
-   如果在检查完所有规则后，数据包没有匹配任何一条，它将被一条**隐藏的、隐式的 `deny any`** 规则所拒绝。这意味着，一个 ACL 必须至少有一条 `permit` 语句，否则它会拒绝所有流量。

**ACL 的应用方向**:
-   **入站 (Inbound)**: 在数据包**进入**接口时进行检查，在它被路由到出站接口之前。
-   **出站 (Outbound)**: 在数据包被路由之后，**离开**接口之前进行检查。

---

### 17.2 ACL 的类型

ACL 主要分为两种类型：标准 ACL 和扩展 ACL。

1.  **标准 ACL (Standard ACL)**:
    -   **规则号**: 1-99 和 1300-1999。
    -   **匹配条件**: 只检查数据包的**源 IP 地址**。
    -   **特点**: 功能简单，处理速度快，但不够精确。因为它不能区分流量的类型（如 Web 流量 vs FTP 流量）。
    -   **放置原则**: 由于它无法指定目的地址，为了避免误伤，标准 ACL 应该**尽可能地靠近目的**。

2.  **扩展 ACL (Extended ACL)**:
    -   **规则号**: 100-199 和 2000-2699。
    -   **匹配条件**: 能够检查多种条件，非常灵活和精确。包括：
        -   **源 IP 地址**
        -   **目的 IP 地址**
        -   **协议类型** (TCP, UDP, ICMP 等)
        -   **源端口号** (对于 TCP/UDP)
        -   **目的端口号** (对于 TCP/UDP)
    -   **放置原则**: 由于其精确性，扩展 ACL 应该**尽可能地靠近源**，以便尽早地过滤掉不需要的流量，节省网络带宽。

---

### 17.3 配置标准 ACL

**场景**: 禁止 `192.168.10.0/24` 这个网络访问任何地方，但允许所有其他网络。

```bash
Router(config)# access-list 10 deny 192.168.10.0 0.0.0.255
# 规则 1：拒绝源地址为 192.168.10.0/24 的流量

Router(config)# access-list 10 permit any
# 规则 2：允许任何其他流量。"any" 关键字是 0.0.0.0 255.255.255.255 的简写。

# 将 ACL 应用到接口
Router(config)# interface GigabitEthernet0/1
# 假设 192.168.10.0/24 网络连接在这个接口上，我们在其入站方向应用 ACL
Router(config-if)# ip access-group 10 in
```
**注意**: 反向掩码（Wildcard Mask）中的 `0` 表示精确匹配，`1` 表示不关心。`0.0.0.255` 表示匹配前 24 位，忽略后 8 位。

---

### 17.4 配置扩展 ACL

**场景**: 只允许 `192.168.10.0/24` 网络中的主机访问 `192.168.30.10` 这台服务器的 Web 服务 (HTTP 端口 80)，拒绝其他任何访问。

```bash
# 使用命名式 ACL，更易读
Router(config)# ip access-list extended WEB_ACCESS_POLICY

# 允许源为 192.168.10.0/24，目的为 主机 192.168.30.10 的 TCP 80 端口流量
Router(config-ext-nacl)# permit tcp 192.168.10.0 0.0.0.255 host 192.168.30.10 eq 80
# "host" 关键字是 0.0.0.0 反向掩码的简写
# "eq" 表示 "equals" (等于)

# (可选) 明确拒绝所有其他 TCP 流量，便于日志记录
Router(config-ext-nacl)# deny tcp any any

# (可选) 允许 ICMP (ping) 流量，方便排错
Router(config-ext-nacl)# permit icmp any any

# 记住，最后有一条隐式的 "deny ip any any"

# 将 ACL 应用到接口
Router(config)# interface GigabitEthernet0/0
# 假设 192.168.10.0/24 网络需要通过 G0/0 才能访问服务器，我们在其入站方向应用 ACL
Router(config-if)# ip access-group WEB_ACCESS_POLICY in
```

---

### 17.5 验证 ACL

```bash
# 显示所有 ACL 的配置
show access-lists

# 显示 ACL 10 的配置
show access-lists 10

# 查看 ACL 在接口上的应用情况
show ip interface GigabitEthernet0/0
# 在输出中寻找 "Inbound access list is..." 或 "Outbound access list is..."

# 查看 ACL 规则的匹配次数
# 这是非常有用的排错命令，可以看到每条规则被命中了多少次
show access-lists
```

ACL 是网络安全和流量工程中一个极其强大和灵活的工具。正确地设计和部署 ACL 是每一个网络工程师必备的技能。 