# 7. 服务与进程管理

理解和管理在后台运行的**服务 (Services)** 和在前台或后台执行的**进程 (Processes)** 是 Windows 系统管理的基本功。这对于故障排查、性能优化和安全监控至关重要。

---

### 7.1 进程管理 (Process Management)

进程是程序代码在内存中执行的实例。每个你打开的应用程序（如浏览器、Word）或系统后台运行的任务，都以一个或多个进程的形式存在。

#### GUI 工具：任务管理器 (Task Manager)

任务管理器是查看和管理进程最常用的图形工具。

**访问方式**:
-   `Ctrl + Shift + Esc` (最快)
-   `Ctrl + Alt + Del` 然后选择"任务管理器"
-   右键点击任务栏，选择"任务管理器"

**核心标签页**:
-   **进程 (Processes)**:
    -   以用户友好的方式显示正在运行的应用程序和后台进程。
    -   可以清晰地看到 CPU、内存、磁盘、网络的实时使用情况。
    -   **结束任务**: 右键点击一个进程，选择 `结束任务 (End task)`，可以强制关闭无响应的程序。
-   **性能 (Performance)**:
    -   以图形化方式展示系统总体资源使用情况，包括 CPU、内存、磁盘、以太网和 GPU。
    -   是快速诊断系统性能瓶颈的入口。
-   **详细信息 (Details)**:
    -   提供一个传统的、更详细的进程列表，包含进程 ID (PID)、状态、用户名和内存使用量等。
    -   在这里可以进行更高级的操作，如**设置优先级 (Set priority)** 或**设置相关性 (Set affinity)** (将进程绑定到特定的 CPU核心)。

#### GUI 工具：资源监视器 (Resource Monitor)

资源监视器是任务管理器的"超级版"，提供更深入的资源使用情况分析。

**访问方式**:
-   在任务管理器的"性能"选项卡中，点击底部的"打开资源监视器"。
-   按 `Win + R`，输入 `resmon` 并回车。

**优势**:
-   可以详细地看到是**哪个进程**在读写**哪个文件** (`磁盘` 选项卡)。
-   可以清晰地看到是**哪个进程**在与**哪个网络地址**通信 (`网络` 选项卡)。
-   是进行深度故障排查的利器。

---

### 7.2 服务管理 (Service Management)

服务是在后台运行的特殊类型的应用程序，它们通常在系统启动时自动开始运行，并且不需要用户交互。例如，Windows 更新、打印服务、网络连接都是由服务来处理的。

#### GUI 工具：服务管理器

服务管理器 (`services.msc`) 是管理系统服务的标准工具。

**访问方式**:
-   按 `Win + R`，输入 `services.msc` 并回车。
-   通过 `计算机管理 -> 服务和应用程序 -> 服务`。

**核心信息列**:
-   **名称 (Name)**: 服务的简称，如 `wuauserv` (Windows Update)。
-   **描述 (Description)**: 解释该服务的功能。
-   **状态 (Status)**: 显示服务是否正在"正在运行 (Running)"。
-   **启动类型 (Startup Type)**: **这是最重要的配置项**。

**启动类型**:
-   **自动 (Automatic)**:
    -   服务将在操作系统启动时自动开始运行。
    -   适用于系统运行所必需的关键服务。
-   **自动 (延迟启动) (Automatic (Delayed Start))**:
    -   服务将在系统启动后、所有"自动"服务启动完毕后的一小段时间再启动。
    -   **目的**: 加快系统启动速度和用户登录速度，适用于一些不那么紧急的后台服务。
-   **手动 (Manual)**:
    -   服务默认不启动，但可以由用户、应用程序或其他服务（依赖项）按需启动。
-   **禁用 (Disabled)**:
    -   服务被完全禁用，无法启动。

**管理操作**:
-   **启动/停止/重启**: 在服务上右键，可以对其进行"启动 (Start)"、"停止 (Stop)"、"暂停 (Pause)"、"恢复 (Resume)"和"重新启动 (Restart)"。
-   **属性 (Properties)**:
    -   **常规**: 修改启动类型。
    -   **登录**: 配置服务以哪个用户账户身份运行（默认为 `Local System` 等系统账户）。
    -   **恢复**: 配置服务在失败时应采取的操作（如自动重启）。
    -   **依赖关系**: 查看该服务依赖哪些其他服务，以及哪些服务依赖于它。这在排查服务启动失败问题时非常有用。

---

### 7.3 命令行工具

#### 进程管理

-   **tasklist**: 列出正在运行的进程。
    ```powershell
    # 查看所有进程
    tasklist

    # 查找名为 "chrome.exe" 的所有进程
    tasklist | findstr /i "chrome.exe"
    ```
-   **taskkill**: 结束一个或多个进程。
    ```powershell
    # 按进程 ID (PID) 结束进程
    taskkill /pid 1234 /f

    # 按镜像名 (Image Name) 结束所有同名进程
    taskkill /im chrome.exe /f
    ```
    `/f` 参数表示强制结束。

#### 服务管理

-   **PowerShell**: PowerShell 提供了最现代和最强大的服务管理方式。
    ```powershell
    # 获取所有服务
    Get-Service

    # 获取特定服务 (可以使用通配符)
    Get-Service -Name "wuauserv"
    Get-Service -DisplayName "*Windows Update*"

    # 启动/停止/重启服务
    Start-Service -Name "spooler" # 打印服务
    Stop-Service -Name "spooler"
    Restart-Service -Name "spooler"

    # 更改服务的启动类型
    Set-Service -Name "spooler" -StartupType Automatic
    ```

-   **sc.exe**: 传统的服务控制命令，功能强大但语法较旧。
    ```powershell
    # 查询服务状态
    sc query spooler

    # 更改启动类型为手动
    sc config spooler start= demand # 注意: demand 代表手动
    
    # 停止服务
    sc stop spooler
    ```

**结论**: 对于现代 Windows 系统管理，应**优先使用 PowerShell** 的 `*-Service` 和 `*-Process` cmdlet，它们提供了更一致、更易用的体验。 