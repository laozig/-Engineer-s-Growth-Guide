# 14. DHCP (Dynamic Host Configuration Protocol)

在任何网络中，为每一台计算机、打印机或智能手机手动配置 IP 地址、子网掩码、默认网关和 DNS 服务器是一项极其繁琐且容易出错的任务。动态主机配置协议（DHCP）就是为了自动化这个过程而设计的，它允许网络设备在启动时自动获取所需的网络配置信息。

---

### 14.1 DHCP 的工作原理：DORA 过程

DHCP 的核心是客户端和服务器之间的四步交互过程，缩写为 **DORA**:

1.  **Discover (发现)**:
    -   当一个 DHCP 客户端启动并接入网络时，它对自己的 IP 配置一无所知。
    -   它会发送一个 **DHCP Discover** 报文。这是一个**广播**报文，源 IP 地址是 `0.0.0.0`，目的 IP 地址是 `255.255.255.255`。
    -   报文的大意是："嘿，网络里有 DHCP 服务器吗？我需要一个 IP 地址！"

2.  **Offer (提供)**:
    -   网络中所有收到 Discover 报文的 DHCP 服务器都会做出响应。
    -   每个服务器会从自己的地址池中选择一个可用的 IP 地址，并连同其他配置信息（如子网掩码、租期、网关地址）一起，打包成一个 **DHCP Offer** 报文。
    -   这个报文通常是**单播**发送回客户端（因为 Discover 报文中包含了客户端的 MAC 地址）。

3.  **Request (请求)**:
    -   客户端可能会收到来自多个 DHCP 服务器的 Offer。通常，它会选择**第一个**收到的 Offer。
    -   然后，客户端会再次发送一个**广播**的 **DHCP Request** 报文。
    -   这个报文明确地告诉所有 DHCP 服务器："好的，我决定接受来自服务器 A（例如）提供的 IP 地址 X。"
    -   使用广播是为了通知所有其他提供了 Offer 的服务器："谢谢你们，但我已经选了别人，你们可以收回之前提供的地址了。"

4.  **Acknowledge (确认)**:
    -   被客户端选中的那个 DHCP 服务器会发送一个最后的 **DHCP Acknowledge (ACK)** 报文。
    -   这个报文确认了租约，并包含了所有最终的网络配置参数。
    -   当客户端收到 ACK 报文后，它就可以使用分配到的 IP 地址和其他信息进行网络通信了。

---

### 14.2 在思科路由器上配置 DHCP 服务器

思科路由器可以方便地配置成一个 DHCP 服务器，为小型或分支机构网络提供服务。

**配置步骤**:
```bash
Router# configure terminal

# 1. (可选但推荐) 排除不想被分配的地址
# 通常，网关、服务器等重要设备的地址应该是静态配置的。
# 我们需要将这些地址从 DHCP 地址池中排除，以防被分配给普通客户端。
Router(config)# ip dhcp excluded-address 192.168.1.1
Router(config)# ip dhcp excluded-address 192.168.1.250 192.168.1.254

# 2. 创建 DHCP 地址池
# "LAN_POOL_1" 是地址池的名称，可以自定义。
Router(config)# ip dhcp pool LAN_POOL_1

# 3. 配置地址池的网络范围
# 定义了该地址池可以分配的 IP 地址所在的网络和子网掩码。
Router(config-dhcp)# network 192.168.1.0 255.255.255.0

# 4. 配置默认网关
# 这是分配给客户端的默认网关地址。
Router(config-dhcp)# default-router 192.168.1.1

# 5. 配置 DNS 服务器
# 可以配置一个或多个 DNS 服务器。
Router(config-dhcp)# dns-server 8.8.8.8 1.1.1.1

# 6. (可选) 配置域名
Router(config-dhcp)# domain-name mycompany.local

# 7. (可选) 配置租期
# 默认租期是 1 天。可以按天、时、分来设置。
# 设置租期为 8 天
Router(config-dhcp)# lease 8
```

---

### 14.3 DHCP 中继 (DHCP Relay)

DHCP 的 Discover 和 Request 报文都是广播报文，而路由器默认是**不转发广播**的。这意味着，如果 DHCP 客户端和 DHCP 服务器不在同一个子网（VLAN）中，客户端将永远无法联系到服务器。

**DHCP 中继代理 (Relay Agent)** 就是解决这个问题的。我们可以在客户端所在子网的路由器接口上配置一个 `ip helper-address` 命令。

**工作原理**:
1.  路由器接口收到客户端的 DHCP 广播。
2.  `ip helper-address` 命令使路由器捕获这个广播，并将其转换成一个**单播**报文。
3.  路由器将这个单播报文发送到命令中指定的 DHCP 服务器的 IP 地址。
4.  DHCP 服务器收到这个单播报文后，正常处理并回复单播给路由器，路由器再将其转发给客户端。

**配置示例**:
假设客户端在 `192.168.2.0/24` 网络，路由器接口是 `GigabitEthernet0/1`，而 DHCP 服务器的地址是 `10.10.10.5`。
```bash
Router(config)# interface GigabitEthernet0/1
Router(config-if)# ip address 192.168.2.1 255.255.255.0
# "ip helper-address" 命令指向真正的 DHCP 服务器地址
Router(config-if)# ip helper-address 10.10.10.5
```
这样，即使 DHCP 服务器远在天边，该子网的客户端也能顺利地获取 IP 地址。

---

### 14.4 验证 DHCP

```bash
# 查看 DHCP 服务器的地址绑定情况（哪些 IP 分配给了哪个 MAC 地址）
show ip dhcp binding

# 查看 DHCP 服务器的统计信息
show ip dhcp server statistics

# 在客户端上（例如 Windows PC）
# 查看获取到的 IP 配置
ipconfig /all
# 释放 IP 地址
ipconfig /release
# 重新获取 IP 地址
ipconfig /renew
``` 