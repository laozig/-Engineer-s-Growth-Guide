# 18. VPN 技术 (Virtual Private Network)

虚拟专用网络（VPN）是一种通过公共网络（通常是互联网）来创建安全、加密的连接的技术。它就像在公共道路上修建了一条私人的、加密的隧道，只有授权用户才能进入和查看其中的数据。VPN 主要用于保护数据隐私、实现远程访问和连接地理上分散的办公室。

---

### 18.1 VPN 的核心概念

-   **隧道（Tunneling）**: 这是 VPN 的核心技术。它将整个数据包（包括其原始的、私有的源和目的 IP 地址）封装在一个新的 IP 数据包中。这个新的数据包使用公共的、可在互联网上路由的 IP 地址作为其源和目的地址。这个过程被称为**隧道化**。
-   **加密（Encryption）**: 仅有隧道是不够的，因为数据在公共网络上传输时仍然可能被窃听。VPN 使用加密算法（如 AES）将原始数据包转换成无法读取的密文。只有拥有正确密钥的 VPN 对端才能解密并读取数据。
-   **身份验证（Authentication）**：在建立 VPN 连接之前，双方必须验证彼此的身份，以确保只有授权的用户或设备才能连接。这通常通过预共享密钥（Pre-Shared Keys, PSK）或数字证书来完成。
-   **数据完整性（Integrity）**：VPN 使用哈希算法（如 SHA）来确保数据在传输过程中没有被篡改。

---

### 18.2 VPN 的主要类型

1.  **远程访问 VPN (Remote-Access VPN)**
    -   **用途**: 允许单个用户（如远程办公的员工、出差的销售人员）从任何地方安全地连接到公司的内部网络。
    -   **工作方式**: 用户在他们的设备（笔记本电脑、手机）上运行 VPN 客户端软件。该软件会与公司网络边界的 VPN 网关（通常是防火墙或路由器）建立一个加密的隧道。
    -   一旦连接，用户的设备就好像直接连接在公司局域网中一样，可以访问内部文件服务器、数据库等资源。
    -   常见的协议包括 **SSL/TLS (常被称为 SSL VPN)** 和 **IPsec**。

2.  **站点到站点 VPN (Site-to-Site VPN)**
    -   **用途**: 用于连接两个或多个地理位置不同的办公室局域网（LAN），使它们能够安全地共享资源。例如，将北京总部和上海分公司的网络连接起来。
    -   **工作方式**: 在每个站点的网络边界都部署一个 VPN 网关（路由器或防火墙）。这两个网关之间建立一个永久的、加密的隧道。
    -   对于网络中的用户来说，这个过程是完全透明的。当北京办公室的员工访问上海办公室的服务器时，流量会自动通过 VPN 隧道进行加密和传输。
    -   **最常用的协议是 IPsec**。

---

### 18.3 IPsec：VPN 的标准协议

IPsec (Internet Protocol Security) 是一个协议套件，而不是单一的协议。它在 IP 层工作，可以保护所有上层协议（TCP, UDP, ICMP 等）的流量。

**IPsec 的主要组件**:
-   **AH (Authentication Header)**: 提供连接无关的数据完整性、数据源身份验证和反重放保护。**它不提供加密**。
-   **ESP (Encapsulating Security Payload)**: 提供加密、数据完整性、数据源身份验证和反重放保护。因为提供了加密，ESP 是目前使用最广泛的组件。
-   **IKE (Internet Key Exchange)**: 用于动态、安全地协商安全关联（Security Associations, SA）和交换密钥。IKE 自动化了密钥管理过程，是 IPsec VPN 能够大规模部署的关键。IKEv1 和 IKEv2 是其两个主要版本，IKEv2 更加高效和稳定。

**IPsec 的两种模式**:
-   **传输模式 (Transport Mode)**:
    -   只加密和/或认证 IP 数据包的**有效载荷 (payload)**。
    -   原始的 IP 头部保持不变。
    -   通常用于端到端（如客户端到服务器）的通信。
-   **隧道模式 (Tunnel Mode)**:
    -   加密和/或认证**整个原始 IP 数据包**（包括头部和载荷）。
    -   然后将这个加密后的包封装在一个**新的 IP 数据包**中。
    -   这是**站点到站点 VPN** 的标准模式。

---

### 18.4 思科 IOS 上的简单站点到站点 IPsec VPN 配置

这是一个非常简化的概念性示例，用于展示配置的主要步骤。实际配置会更复杂。

**假设**:
-   RouterA (北京) 和 RouterB (上海) 之间建立 VPN。
-   北京内网: `192.168.1.0/24`
-   上海内网: `192.168.2.0/24`
-   RouterA 公网 IP: `203.0.113.1`
-   RouterB 公网 IP: `198.51.100.1`
-   预共享密钥: `cisco123`

```bash
# === 在 RouterA 上配置 ===

# --- IKE Phase 1 (建立管理连接) ---
crypto isakmp policy 10
 encr aes
 authentication pre-share
 group 2
!
crypto isakmp key cisco123 address 198.51.100.1  # 对端公网 IP 和密钥

# --- IKE Phase 2 (建立数据连接) ---
crypto ipsec transform-set MY_TRANSFORM_SET esp-aes esp-sha-hmac
!
# --- 定义需要加密的 "有趣" 流量 ---
access-list 101 permit ip 192.168.1.0 0.0.0.255 192.168.2.0 0.0.0.255
!
# --- 将所有部分组合到 Crypto Map 中 ---
crypto map MY_CRYPTO_MAP 10 ipsec-isakmp
 set peer 198.51.100.1
 set transform-set MY_TRANSFORM_SET
 match address 101
!
# --- 将 Crypto Map 应用到公网接口 ---
interface GigabitEthernet0/0
 ip address 203.0.113.1 255.255.255.252
 crypto map MY_CRYPTO_MAP
!
```
RouterB 上的配置与 RouterA 镜像对称（例如，`set peer` 和 `access-list` 中的地址要反过来）。当 RouterA 的 `192.168.1.5` ping RouterB 的 `192.168.2.5` 时，"有趣" 的流量会触发 VPN 隧道的建立。

**验证命令**:
```bash
# 查看 Phase 1 的安全关联
show crypto isakmp sa
# 查看 Phase 2 的安全关联和流量加密/解密统计
show crypto ipsec sa
``` 