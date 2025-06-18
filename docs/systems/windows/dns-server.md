# 10. DNS 服务器配置

域名系统 (DNS) 是互联网和 Active Directory 的核心服务之一，它负责将友好的域名解析为 IP 地址。在安装 Active Directory 时，DNS 服务器角色通常会自动安装，因为它对 AD 的正常运行至关重要。本章将探讨如何管理和配置 Windows Server 上的 DNS 服务。

---

### 10.1 DNS 核心概念

-   **区域 (Zone)**:
    -   DNS 服务器上存储特定域名（如 `ad.yourcompany.local`）的资源记录的数据库。
    -   **正向查找区域 (Forward Lookup Zone)**: 将域名解析为 IP 地址（例如 `server1.ad.yourcompany.local` -> `192.168.1.10`）。
    -   **反向查找区域 (Reverse Lookup Zone)**: 将 IP 地址解析为域名（例如 `192.168.1.10` -> `server1.ad.yourcompany.local`）。主要用于某些验证和日志记录。

-   **资源记录 (Resource Records, RR)**:
    -   区域数据库中的条目，用于提供有关域名的信息。
    -   **A 记录**: 将一个主机名映射到一个 IPv4 地址。
    -   **AAAA 记录 (Quad-A)**: 将一个主机名映射到一个 IPv6 地址。
    -   **CNAME (别名) 记录**: 将一个域名（别名）指向另一个域名（规范名称）。
    -   **MX (邮件交换) 记录**: 指定负责处理该域电子邮件的邮件服务器。
    -   **PTR (指针) 记录**: 用于反向查找，将 IP 地址映射回主机名。
    -   **SRV (服务) 记录**: 定义域中特定服务（如 AD 域控制器、VoIP）的位置。**对 Active Directory 至关重要**。

-   **转发器 (Forwarder)**:
    -   当本地 DNS 服务器无法解析某个域名时（因为它不属于本地服务器管理的任何区域），它会将查询请求**转发**给另一台 DNS 服务器（如你的 ISP 的 DNS 或公共 DNS，像 `8.8.8.8`）。
    -   这是实现内网域名和公网域名都能解析的关键。

---

### 10.2 使用 GUI 工具：DNS 管理器

**访问方式**:
-   在服务器管理器中，点击 `工具 (Tools)` -> `DNS`。
-   按 `Win + R`，输入 `dnsmgmt.msc` 并回车。

#### 管理正向查找区域

当你安装 AD DS 时，一个与你的域同名的正向查找区域会自动创建。

-   **查看记录**: 展开 `正向查找区域` -> `你的域名`，你可以看到所有自动注册的记录，特别是域控制器的 A 记录和 `_tcp`、`_udp` 等文件夹下的 SRV 服务记录。

-   **手动创建记录**:
    1.  右键点击你的域名区域，选择 `新建主机(A 或 AAAA)...` 或 `新建别名(CNAME)...` 等。
    2.  **创建 A 记录**:
        -   **名称**: 只需输入主机名部分（如 `fileserver`），域名会自动追加。
        -   **IP 地址**: 输入对应的 IP 地址。
        -   **创建相关的指针(PTR)记录**: 如果你已经配置了反向查找区域，勾选此项可以自动创建 PTR 记录。

#### 配置转发器

1.  在 DNS 管理器中，右键点击你的服务器名称，选择 `属性 (Properties)`。
2.  切换到 `转发器 (Forwarders)` 选项卡。
3.  点击 `编辑 (Edit)`，然后输入一个或多个公共 DNS 服务器的 IP 地址（如 Google 的 `8.8.8.8` 或 Cloudflare 的 `1.1.1.1`）。

---

### 10.3 区域类型

在区域的属性中，你可以看到其类型。

-   **主要区域 (Primary Zone)**:
    -   区域数据的主要读/写副本。
-   **次要区域 (Secondary Zone)**:
    -   主要区域的只读副本，用于负载均衡和容错。
-   **存根区域 (Stub Zone)**:
    -   只包含用于识别该区域的权威 DNS 服务器的记录，用于改善名称解析。

-   **与 Active Directory 集成 (Active Directory-Integrated)**:
    -   **这是 AD 环境中的标准和最佳实践**。
    -   当勾选此项后，DNS 区域数据不再作为普通的文本文件存储，而是存储在 **Active Directory 数据库**中。
    -   **优势**:
        1.  **安全动态更新**: 只有加入了域的计算机才能安全地自动注册和更新自己的 DNS 记录。
        2.  **多主复制**: 每个 DC 都持有区域的可写副本，通过 AD 的高效复制机制进行同步，大大增强了容错性。

---

### 10.4 使用 PowerShell 管理 DNS

-   **查看区域和记录**:
    ```powershell
    # 获取服务器上的所有区域
    Get-DnsServerZone

    # 获取特定区域中的所有记录
    Get-DnsServerResourceRecord -ZoneName "ad.yourcompany.local"
    ```

-   **创建记录**:
    ```powershell
    # 在指定区域为 fileserver 创建一个 A 记录
    Add-DnsServerResourceRecordA -ZoneName "ad.yourcompany.local" -Name "fileserver" -IPv4Address "192.168.1.50"

    # 创建一个 CNAME 记录
    Add-DnsServerResourceRecordCName -ZoneName "ad.yourcompany.local" -Name "www" -HostNameAlias "webserver01.ad.yourcompany.local"
    ```

-   **管理转发器**:
    ```powershell
    # 查看转发器
    Get-DnsServerForwarder

    # 设置转发器 (会覆盖现有设置)
    Set-DnsServerForwarder -IPAddress "8.8.8.8", "1.1.1.1"

    # 添加一个转发器
    Add-DnsServerForwarder -IPAddress "8.8.4.4"
    ```

---

### 10.5 故障排查

-   `nslookup`:
    -   `nslookup fileserver01`: 使用默认 DNS 服务器解析。
    -   `nslookup fileserver01 192.168.1.10`: 指定使用 `192.168.1.10` 这个 DNS 服务器进行解析。
-   `ipconfig /flushdns`: 清除本地客户端的 DNS 解析缓存。当 DNS 记录变更后，客户端可能因为缓存而无法立即获取最新记录，此命令可以解决该问题。
-   **DNS 事件日志**: 在事件查看器中，`应用程序和服务日志 -> DNS Server` 提供了详细的日志信息。 