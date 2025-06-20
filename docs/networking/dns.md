# 15. DNS (Domain Name System)

人类善于记忆像 `www.google.com` 这样的域名，而计算机则通过像 `172.217.160.100` 这样的 IP 地址进行通信。域名系统（DNS）就是互联网的"电话簿"，它的主要职责是将人类可读的域名解析（或翻译）成机器可读的 IP 地址。没有 DNS，现代互联网将无法正常运作。

---

### 15.1 DNS 的工作原理

DNS 是一个全球性的、分布式的、分层的数据库。当你在浏览器中输入一个域名时，你的计算机会执行一系列查询来找到对应的 IP 地址。

**查询过程（简化版）**:

1.  **检查本地缓存**:
    -   你的计算机会首先检查自己的 DNS 缓存，看看最近是否已经查询过这个域名。浏览器也有自己的缓存。

2.  **查询本地 DNS 服务器**:
    -   如果本地缓存中没有，计算机会向其网络配置中指定的本地 DNS 服务器（通常由你的 ISP 或公司提供）发送一个**递归查询 (Recursive Query)**。
    -   递归查询的意思是："请帮我找到 `www.google.com` 的 IP 地址，并把最终结果给我。我不想知道中间过程。"

3.  **本地 DNS 服务器的迭代查询**:
    -   本地 DNS 服务器收到请求后，它会代表你开始一个**迭代查询 (Iterative Query)** 的过程。
    -   **a. 查询根服务器 (Root Servers)**: 本地 DNS 服务器首先询问全球 13 组根服务器之一："谁知道 `.com` 的信息？" 根服务器不会直接知道 `www.google.com` 的地址，但它会回复说："我不知道，但你可以去问 `.com` 的顶级域（TLD）服务器，它们的地址是 X.X.X.X。"
    -   **b. 查询 TLD 服务器 (Top-Level Domain Servers)**: 本地 DNS 服务器接着去问 `.com` TLD 服务器："谁知道 `google.com` 的信息？" TLD 服务器同样不会知道最终答案，但它会回复说："我不知道，但 `google.com` 的权威名称服务器（Authoritative Name Server）的地址是 Y.Y.Y.Y。"
    -   **c. 查询权威名称服务器 (Authoritative Name Servers)**: 最后，本地 DNS 服务器去问 `google.com` 的权威名称服务器："`www.google.com` 的 IP 地址是什么？" 权威名称服务器是负责管理 `google.com` 域中所有记录的服务器，它拥有最终的答案。它会回复说："`www.google.com` 的 IP 地址是 `172.217.160.100`。"

4.  **返回结果并缓存**:
    -   本地 DNS 服务器将获取到的 IP 地址返回给你的计算机。
    -   同时，它会将这个查询结果缓存起来，以便下次有其他用户查询同一个域名时，可以直接返回答案，无需重复整个过程。缓存的有效期由记录的 TTL (Time-To-Live) 值决定。

---

### 15.2 常见的 DNS 记录类型

DNS 数据库中存储了多种类型的资源记录（Resource Records, RR）。

-   **A 记录 (Address Record)**:
    -   最常见的记录类型。
    -   用于将一个域名映射到一个 **IPv4** 地址。
    -   示例: `www.example.com.  IN  A  93.184.216.34`

-   **AAAA 记录 (Quad-A Record)**:
    -   用于将一个域名映射到一个 **IPv6** 地址。
    -   示例: `www.example.com.  IN  AAAA  2606:2800:220:1:248:1893:25c8:1946`

-   **CNAME 记录 (Canonical Name Record)**:
    -   用于创建一个域名的**别名**。
    -   它将一个域名指向另一个域名，而不是 IP 地址。
    -   示例: `ftp.example.com.  IN  CNAME  www.example.com.` (访问 ftp.example.com 实际上会访问 www.example.com)

-   **MX 记录 (Mail Exchange Record)**:
    -   指定负责接收该域电子邮件的邮件服务器。
    -   记录中包含一个优先级值（数值越小，优先级越高）和邮件服务器的域名。
    -   示例: `example.com.  IN  MX  10  mail.example.com.`

-   **NS 记录 (Name Server Record)**:
    -   指定负责管理该域的权威名称服务器。

-   **PTR 记录 (Pointer Record)**:
    -   用于**反向 DNS 查询**，即将一个 IP 地址映射回一个域名。主要用于邮件服务器验证等场景。

---

### 15.3 在思科路由器上配置 DNS 客户端

我们可以配置路由器本身使用 DNS 服务，这样我们就可以在路由器上使用域名而不是 IP 地址来进行 `ping` 或 `traceroute` 等操作。

```bash
Router(config)# ip name-server 8.8.8.8 1.1.1.1
# 指定一个或多个 DNS 服务器

Router(config)# ip domain-lookup
# 启用 DNS 查询功能 (默认是开启的)

Router(config)# ip domain-name mycompany.local
# (可选) 指定一个默认域名。这样，当你 ping 一个主机名（如 "server1"）时，路由器会自动将其补全为 "server1.mycompany.local" 进行查询。
```

**验证**:
```bash
# 测试 DNS 解析
ping www.cisco.com

# 查看路由器的 DNS 统计或缓存
show hosts
```

虽然路由器可以作为 DNS 客户端，但它们通常不被用作功能齐全的 DNS 服务器。在生产环境中，DNS 服务通常由专用的 Windows Server、Linux（使用 BIND 等软件）或云服务提供商来承担。 