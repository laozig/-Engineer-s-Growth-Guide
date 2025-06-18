# 8. 交换机安全

交换机作为局域网（LAN）的核心，是网络接入的第一道关卡，因此其安全性至关重要。交换机安全涉及一系列用于保护二层网络免受攻击的功能和技术。其中，端口安全（Port Security）是最基本也是最重要的一项。

---

### 8.1 端口安全 (Port Security)

端口安全功能可以限制一个交换机端口上允许接入的设备的 MAC 地址数量，并可以指定具体的 MAC 地址。这可以有效地防止未经授权的设备接入网络。

**核心功能**:
1.  **限制 MAC 地址数量**: 你可以定义一个端口最多可以学习多少个 MAC 地址。默认通常是 1。
2.  **定义允许的 MAC 地址**:
    -   **动态学习 (Dynamic)**: 这是默认方式。端口会像往常一样学习 MAC 地址，直到达到数量限制。这些地址在交换机重启后会丢失。
    -   **静态配置 (Static)**: 管理员手动为端口配置一个或多个允许的 MAC 地址。这些地址会保存在运行配置中。
    -   **粘性学习 (Sticky)**: 这是最实用的一种方式。端口会自动学习 MAC 地址（就像动态学习一样），但它会将学到的地址**转换成静态条目并保存到运行配置中**。这样，即使交换机重启，配置也不会丢失。

**违规处理模式 (Violation Modes)**:
当一个未授权的 MAC 地址（超过数量限制或与允许列表不符）试图通过端口发送流量时，端口安全会触发违规。有三种处理模式：

1.  **Protect (保护)**:
    -   来自未授权 MAC 地址的数据包会被**丢弃**。
    -   交换机**不会**发送任何告警（如 Syslog 或 SNMP Trap），违规计数器**不会**增加。这是最"安静"的模式。

2.  **Restrict (限制)**:
    -   与 Protect 模式一样，来自未授权 MAC 地址的数据包会被**丢弃**。
    -   交换机**会**发送告警，并且端口的**违规计数器会增加**。这比 Protect 提供了更好的可见性。

3.  **Shutdown (关闭)**:
    -   这是**默认**的违规模式，也是最安全的模式。
    -   一旦发生违规，端口会立即进入 `err-disabled` (错误禁用) 状态，完全关闭。
    -   交换机会发送告警，违规计数器会增加。
    -   要恢复处于 `err-disabled` 状态的端口，管理员必须手动登录交换机，先 `shutdown` 再 `no shutdown` 该端口。

---

### 8.2 配置端口安全 (使用 Sticky 模式)

```bash
Switch# configure terminal
Switch(config)# interface FastEthernet 0/1

# 1. 将端口设置为接入模式
Switch(config-if)# switchport mode access

# 2. 启用端口安全功能
Switch(config-if)# switchport port-security

# 3. (可选) 设置允许的最大 MAC 地址数量
Switch(config-if)# switchport port-security maximum 2

# 4. (可选) 设置违规处理模式
Switch(config-if)# switchport port-security violation restrict

# 5. 启用粘性学习
Switch(config-if)# switchport port-security mac-address sticky
```
配置完成后，当第一台和第二台设备（假设 `maximum` 设为 2）接入 `Fa0/1` 并发送流量时，它们的 MAC 地址会被自动学习并写入到 `running-config` 中。之后如果第三台设备接入，就会触发 `restrict` 违规。

**验证端口安全**:
```bash
# 查看所有接口的端口安全状态
show port-security

# 查看特定接口的端口安全详细信息
show port-security interface FastEthernet 0/1
```

---

### 8.3 其他二层安全威胁与缓解措施

除了端口安全，还有其他一些常见的二层攻击需要防范。

1.  **DHCP 欺骗 (DHCP Spoofing)**:
    -   **攻击**: 攻击者在网络中搭建一个假的 DHCP 服务器，向客户端分发错误的 IP 地址、网关和 DNS 服务器信息，从而实现中间人攻击。
    -   **缓解**: **DHCP Snooping**。该功能将交换机端口分为**信任 (Trusted)** 和**非信任 (Untrusted)**。只有来自信任端口（通常是连接合法 DHCP 服务器的端口）的 DHCP Offer/Ack 报文才被允许通过。所有其他端口都被视为非信任，不能发送 DHCP 服务器报文。

2.  **ARP 欺骗 (ARP Spoofing/Poisoning)**:
    -   **攻击**: 攻击者发送伪造的 ARP 响应，将自己的 MAC 地址与网关的 IP 地址进行绑定。这会导致流向网关的数据包全部被重定向到攻击者的机器。
    -   **缓解**: **动态 ARP 检测 (Dynamic ARP Inspection, DAI)**。DAI 依赖于 DHCP Snooping 建立的 IP-MAC 绑定表。它会拦截所有 ARP 报文，并验证其 IP-MAC 映射关系是否与绑定表一致。对于不一致的 ARP 报文，DAI 会将其丢弃。

3.  **STP 操纵攻击 (STP Manipulation)**:
    -   **攻击**: -攻击者将其计算机伪装成一个 BID (Bridge ID) 为 0 的交换机，从而"劫持"根桥的角色，重塑网络流量的走向，实现中间人攻击。
    -   **缓解**: **BPDU Guard**。在所有配置为 `portfast` 的接入端口上启用 BPDU Guard。一旦这些端口收到任何 BPDU 报文（这在正常的接入端口上是不应该发生的），BPDU Guard 会立即将该端口置于 `err-disabled` 状态。

通过综合运用端口安全、DHCP Snooping、DAI 和 BPDU Guard 等技术，可以构建一个健壮的、能够抵御常见二层攻击的安全局域网环境。 