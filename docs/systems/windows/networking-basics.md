# 8. 网络基础配置

正确的网络配置是任何计算机加入网络、与外界通信的基础。本章将介绍如何在 Windows 中配置核心的网络参数，如 IP 地址、子网掩码、默认网关和 DNS 服务器。

---

### 8.1 理解核心网络参数

-   **IP 地址 (IP Address)**:
    -   网络中设备的唯一标识符，如同门牌号码。分为 IPv4 和 IPv6 两种。
    -   **IPv4**: 32位地址，通常写作 `192.168.1.100` 的形式。
    -   **IPv6**: 128位地址，更复杂，用于应对 IPv4 地址耗尽的问题。

-   **子网掩码 (Subnet Mask)**:
    -   用于区分 IP 地址中的**网络部分**和**主机部分**。
    -   例如，对于 IP `192.168.1.100` 和子网掩码 `255.255.255.0`，`192.168.1` 是网络地址，`100` 是主机地址。
    -   同一网络中的所有设备必须有相同的网络地址。

-   **默认网关 (Default Gateway)**:
    -   当计算机需要与**不同网络**中的设备通信时，它会把数据包发送到默认网关。
    -   通常是你的路由器或网络出口的 IP 地址，例如 `192.168.1.1`。没有它，计算机就无法访问互联网。

-   **DNS 服务器 (Domain Name System Server)**:
    -   负责将人类可读的域名（如 `www.google.com`）解析成机器可读的 IP 地址（如 `172.217.160.68`）。
    -   没有 DNS，你就只能通过 IP 地址访问网站。

---

### 8.2 DHCP vs. 静态 IP

-   **DHCP (动态主机配置协议)**:
    -   网络中的 DHCP 服务器（通常是路由器）会自动为接入的设备**分配** IP 地址、子网掩码、默认网关和 DNS 服务器。
    -   这是**工作站**和移动设备的首选方式，即插即用，无需手动配置。

-   **静态 IP (Static IP)**:
    -   手动为设备指定一个**固定不变**的 IP 地址。
    -   这是**服务器**的标准实践。因为服务器提供的服务需要一个稳定、可预测的地址，以便客户端能够随时找到它。想象一下，如果网站服务器的 IP 地址每天都在变，DNS 将如何工作？

---

### 8.3 使用 GUI 配置网络

#### Windows 工作站 (设置)

1.  打开 `设置 -> 网络和 Internet`。
2.  选择你正在使用的网络连接（如 `以太网` 或 `WLAN`）。
3.  找到 `IP 分配`，点击 `编辑`。
4.  在弹出的窗口中，你可以选择：
    -   `自动(DHCP)`
    -   `手动`
5.  选择 `手动` 后，你可以为 IPv4 和 IPv6 分别输入 IP 地址、子网掩码、网关和首选/备用 DNS。

#### Windows 服务器 (服务器管理器) & 传统控制面板

这个方法在工作站和服务器版本中都适用。

1.  **访问网络连接**:
    -   **服务器**: 在 `服务器管理器 -> 本地服务器` 中，点击以太网适配器的链接。
    -   **通用**: 按 `Win + R`，输入 `ncpa.cpl` 并回车。
2.  **打开属性**:
    -   右键点击你要配置的网络适配器，选择 `属性 (Properties)`。
3.  **配置 IPv4**:
    -   在列表中找到并双击 `Internet 协议版本 4 (TCP/IPv4)`。
    -   你可以选择"自动获得 IP 地址"或"使用下面的 IP 地址"来手动配置。

---

### 8.4 使用命令行配置网络

#### PowerShell

PowerShell 提供了管理网络配置的全套 cmdlet，是自动化和脚本编写的首选。

-   **查看网络适配器**:
    ```powershell
    # 获取所有网络接口的基本信息
    Get-NetAdapter

    # 获取 IP 配置详细信息
    Get-NetIPConfiguration
    ```

-   **设置静态 IP 地址和 DNS**:
    ```powershell
    # 1. 首先获取要配置的接口的索引号(ifIndex)
    Get-NetAdapter

    # 2. 设置 IP 地址、网关和子网掩码
    # 注意: 子网掩码用前缀长度表示 (255.255.255.0 = 24)
    New-NetIPAddress -InterfaceIndex 12 -IPAddress "192.168.1.100" -PrefixLength 24 -DefaultGateway "192.168.1.1"

    # 3. 设置 DNS 服务器
    Set-DnsClientServerAddress -InterfaceIndex 12 -ServerAddresses ("8.8.8.8", "8.8.4.4")
    ```

-   **切换回 DHCP**:
    ```powershell
    # 移除静态 IP
    Remove-NetIPAddress -InterfaceIndex 12 -Confirm:$false

    # 移除手动设置的网关 (通过重置路由)
    Set-NetIPInterface -InterfaceIndex 12 -Dhcp Enabled

    # 恢复 DHCP 分配的 DNS
    Set-DnsClientServerAddress -InterfaceIndex 12 -ResetServerAddresses
    ```

#### Netsh (传统工具)

`netsh` 是一个传统的网络配置命令行工具，功能依然强大。

-   **设置静态 IP**:
    ```cmd
    netsh interface ip set address name="Ethernet0" static 192.168.1.100 255.255.255.0 192.168.1.1
    ```

-   **设置 DNS**:
    ```cmd
    netsh interface ip set dns name="Ethernet0" static 8.8.8.8
    netsh interface ip add dns name="Ethernet0" 8.8.4.4 index=2
    ```

-   **切换回 DHCP**:
    ```cmd
    netsh interface ip set address name="Ethernet0" dhcp
    netsh interface ip set dns name="Ethernet0" dhcp
    ```

---

### 8.5 故障排查工具

-   `ping <ip_or_domain>`: 测试到目标的网络连通性。
-   `tracert <ip_or_domain>`: (Trace Route) 显示数据包到达目标所经过的路由路径。
-   `nslookup <domain>`: 查询域名的 DNS 解析记录。
-   `ipconfig /all`: 显示所有网络适配器的完整配置信息。
-   `Get-NetAdapter | Format-List -Property *`: (PowerShell) 显示网络适配器的所有属性。 