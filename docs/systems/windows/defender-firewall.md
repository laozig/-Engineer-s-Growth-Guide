# 13. Windows Defender 与防火墙

在当今的网络环境中，安全性至关重要。Windows 内置了两个强大的安全工具来保护系统免受恶意软件和网络攻击：**Windows Defender 防病毒** 和 **Windows Defender 防火墙**。

---

### 13.1 Windows Defender 防病毒

Windows Defender 是内置于 Windows 的反恶意软件解决方案，提供实时保护，抵御病毒、勒索软件、间谍软件和其他恶意威胁。

#### 核心功能

-   **实时保护 (Real-time Protection)**: 持续在后台运行，扫描你打开、下载或运行的文件。
-   **病毒和威胁防护**: 定期扫描系统，并允许你手动启动不同类型的扫描。
    -   **快速扫描**: 检查系统中恶意软件最可能隐藏的区域。
    -   **完全扫描**: 扫描系统上的所有文件和正在运行的程序。
    -   **自定义扫描**: 只扫描你选择的文件和文件夹。
    -   **脱机扫描**: 重启系统并在 Windows 加载前运行扫描，用于清除一些难以移除的 rootkit 等恶意软件。
-   **云提供的保护 (Cloud-delivered Protection)**: 将新的威胁信息近乎实时地从微软云安全中心同步下来，提供更快的响应速度。
-   **勒索软件防护**: 通过"受控文件夹访问"功能，防止未经授权的应用修改受保护文件夹（如"文档"、"图片"）中的文件。

#### 使用 GUI 工具：Windows 安全中心

**访问方式**:
-   在系统托盘中找到盾牌图标。
-   在"设置"中搜索 `Windows 安全中心`。

在 **病毒和威胁防护** 部分，你可以：
-   查看当前的威胁状态和保护历史记录。
-   运行不同类型的扫描。
-   管理 `病毒和威胁防护设置`，例如开关实时保护、云保护等。
-   配置 `受控文件夹访问`。

#### 在服务器上使用 Defender

-   在 **Windows Server 2016 及更高版本**中，Defender 是默认安装并启用的。
-   在带"桌面体验"的服务器上，你可以使用 Windows 安全中心 GUI。
-   在 **Server Core** 上，你只能通过 **PowerShell** 来管理 Defender。

#### 使用 PowerShell 管理 Defender

```powershell
# 查看 Defender 状态
Get-MpComputerStatus

# 启动一次快速扫描
Start-MpScan -ScanType QuickScan

# 查看当前的威胁
Get-MpThreatDetection

# 更新病毒定义库
Update-MpSignature
```

---

### 13.2 Windows Defender 防火墙

防火墙是一个网络过滤器，它根据一组规则来**允许**或**阻止**进出你计算机的网络流量。这是防止网络攻击（如蠕虫、端口扫描）的第一道防线。

#### 防火墙配置文件 (Profiles)

Windows 防火墙有三个网络配置文件，系统会根据你连接的网络类型自动切换：

-   **域配置文件 (Domain Profile)**: 当计算机连接到其所属的 Active Directory 域时自动应用。这是最受信任的环境，规则通常最宽松。
-   **专用配置文件 (Private Profile)**: 当你连接到你信任的家庭或工作网络（非域环境）时使用。
-   **公用配置文件 (Public Profile)**: 当你连接到不受信任的公共网络（如咖啡店、机场的 Wi-Fi）时使用。这是限制最严格的配置文件，默认会阻止大部分入站连接。

#### 使用 GUI 工具：高级安全 Windows Defender 防火墙

这是一个功能强大的 MMC 管理单元，用于创建精细的防火墙规则。

**访问方式**:
-   在开始菜单搜索 `wf.msc`。
-   `控制面板` -> `Windows Defender 防火墙` -> `高级设置`。

**核心组件**:
-   **入站规则 (Inbound Rules)**: 控制**进入**计算机的网络流量。**这是最重要的部分**，因为默认情况下，防火墙会阻止大部分未经请求的入站连接。
-   **出站规则 (Outbound Rules)**: 控制**从**计算机发出的网络流量。默认情况下，防火墙允许所有出站连接。

**创建一条新的入站规则 (示例：允许 Web 服务器的 HTTP 流量)**
1.  在 `入站规则` 上右键，选择 `新建规则...`。
2.  **规则类型**:
    -   `程序`: 允许或阻止某个特定的程序（.exe 文件）。
    -   `端口`: **最常用**。允许或阻止特定的 TCP 或 UDP 端口。
    -   `预定义`: 为系统内置的某些服务（如文件和打印共享）创建规则。
    -   `自定义`: 创建包含多种条件的复杂规则。
3.  **协议和端口**:
    -   选择 `端口`。
    -   选择 `TCP`。
    -   选择 `特定本地端口`，并输入 `80`。
4.  **操作**:
    -   选择 `允许连接 (Allow the connection)`。
5.  **配置文件**:
    -   选择该规则在哪些配置文件（域、专用、公用）下生效。
6.  **名称**: 为规则起一个描述性的名称，如 `Allow Web Server (HTTP In)`。

#### 使用 PowerShell 管理防火墙

```powershell
# 查看所有防火墙规则
Get-NetFirewallRule

# 创建一条新的防火墙规则 (与上面 GUI 示例等效)
New-NetFirewallRule -DisplayName "Allow Web Server (HTTP In)" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow

# 禁用/启用规则
Disable-NetFirewallRule -DisplayName "Allow Web Server (HTTP In)"
Enable-NetFirewallRule -DisplayName "Allow Web Server (HTTP In)"

# 按配置文件查看防火墙状态
Get-NetFirewallProfile -Name Domain, Private, Public
```

**最佳实践**: 始终保持防火墙处于启用状态，并遵循**最小权限原则**：只打开你确实需要的服务的入站端口。 