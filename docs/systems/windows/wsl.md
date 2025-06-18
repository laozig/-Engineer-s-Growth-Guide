# 19. Windows Subsystem for Linux (WSL)

Windows Subsystem for Linux (WSL) 是一个强大的功能，它允许开发人员、系统管理员和高级用户直接在 Windows 上运行原生的 Linux 二进制文件 (ELF64格式)。这打破了 Windows 和 Linux 生态系统之间的壁垒，提供了一个无缝集成两种环境的工作方式。

---

### 19.1 WSL 的两个版本：WSL 1 vs WSL 2

了解两个版本之间的差异至关重要：

| 特性 | WSL 1 | WSL 2 |
| :--- | :--- | :--- |
| **架构** | 翻译层，将 Linux 系统调用实时翻译为 Windows 系统调用 | 真正的 Linux 内核，运行在一个轻量级的虚拟机 (VM) 中 |
| **文件系统性能** | 在 Windows 文件系统 (`/mnt/c`) 中访问文件速度快 | 在 Linux 原生文件系统 (`ext4`) 中访问文件速度极快，但在跨操作系统访问文件时 (`/mnt/c`) 较慢 |
| **系统调用兼容性** | 良好，但并非 100% 兼容 | **完全兼容**，可以运行 Docker、systemd (需配置) 等 |
| **网络** | 与 Windows 共享网络堆栈和 IP 地址 | 拥有自己独立的、虚拟化的网络接口和 IP 地址 |
| **内核** | 不包含 Linux 内核 | 包含一个由微软编译和维护的真正的 Linux 内核 |

**结论**: 对于绝大多数用例，尤其是需要 Docker 或完全系统调用兼容性的场景，**WSL 2 是首选**。

---

### 19.2 安装 WSL

在现代的 Windows 10 和 Windows 11 中，安装 WSL 非常简单。

1.  **以管理员身份打开 PowerShell 或命令提示符**。
2.  运行以下命令来安装 WSL 和默认的 Ubuntu 发行版：
    ```powershell
    wsl --install
    ```
3.  这个命令会自动完成以下所有步骤：
    -   启用所需的 Windows 功能（虚拟机平台和适用于 Linux 的 Windows 子系统）。
    -   下载并安装最新的 Linux 内核。
    -   将 WSL 2 设置为默认版本。
    -   下载并安装 Ubuntu 发行版。
4.  安装完成后，**重启你的计算机**。

重启后，你的 Linux 发行版会自动启动，并要求你创建一个用户账户和密码。这个账户是 Linux 环境专用的，与你的 Windows 用户名无关。

---

### 19.3 管理 Linux 发行版

-   **查看已安装的发行版**:
    ```bash
    wsl --list --verbose  # 或者 wsl -l -v
    ```
    此命令会显示所有已安装的发行版、它们的运行状态以及所使用的 WSL 版本。

-   **安装其他发行版**:
    你可以从 Microsoft Store 中搜索并安装其他发行版，如 Debian, Kali Linux, Fedora 等。或者使用命令行：
    ```bash
    wsl --install -d <DistroName>
    ```
    使用 `wsl --list --online` 查看可用发行版列表。

-   **设置默认发行版**:
    ```bash
    wsl --set-default <DistroName>
    ```

-   **切换发行版的 WSL 版本**:
    ```bash
    wsl --set-version <DistroName> 2  # 切换到 WSL 2
    wsl --set-version <DistroName> 1  # 切换到 WSL 1
    ```

-   **终止和重启 WSL**:
    ```bash
    wsl --shutdown  # 强制关闭所有正在运行的发行版和 WSL 2 虚拟机
    wsl --terminate <DistroName> # 关闭指定的发行版
    ```

---

### 19.4 Windows 与 Linux 之间的互操作性

这是 WSL 最强大的功能之一。

-   **从 Windows 访问 Linux 文件**:
    -   打开文件资源管理器。
    -   在地址栏输入 `\\wsl$`。
    -   你会看到所有已安装发行版的文件夹，可以像操作普通文件夹一样操作它们。
    -   **最佳实践**: 当处理 Linux 项目时，**始终将文件存储在 Linux 文件系统内** (例如 `~/project`) 以获得最佳性能。

-   **从 Linux 访问 Windows 文件**:
    -   你的 Windows 驱动器会自动挂载到 `/mnt/` 目录下。
    -   例如，你的 `C:\` 盘可以在 Linux 的 `/mnt/c/` 路径下访问。

-   **在系统之间运行命令**:
    -   **从 PowerShell/CMD 运行 Linux 命令**:
        ```powershell
        wsl grep "my-text" /mnt/c/Users/YourUser/Documents/file.txt
        ```
    -   **从 Linux 终端运行 Windows 工具**:
        ```bash
        # 启动记事本编辑 .bashrc 文件
        notepad.exe ~/.bashrc
        
        # 使用 ipconfig 查看 Windows 网络配置
        ipconfig.exe | grep "IPv4"
        ```

WSL 极大地扩展了 Windows 的能力，使其成为一个对 Web 开发、数据科学和 IT 管理都极其友好的平台。 