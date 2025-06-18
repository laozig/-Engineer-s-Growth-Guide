# 18. PowerShell 脚本入门

手动管理单个服务器是可行的，但要管理数十、数百甚至数千个系统，自动化是唯一的出路。PowerShell 是 Windows 环境下最核心的自动化引擎和命令行管理工具。它不仅仅是一个 Shell，更是一个基于 .NET 的强大脚本语言。

---

### 18.1 为什么选择 PowerShell?

-   **对象管道 (Object Pipeline)**: 与 Linux Shells 传递纯文本不同，PowerShell 在命令之间传递的是结构化的 **.NET 对象**。这意味着你可以轻松地访问对象的属性和方法，而无需用 `grep`, `awk` 等工具去解析复杂的文本字符串。
-   **一致的命名规范**: PowerShell 的命令 (Cmdlets) 遵循 `动词-名词` 的格式，例如 `Get-Service`, `Stop-Process`, `New-Item`。这种规范使得命令非常容易发现和学习。
-   **强大的远程管理**: 使用 PowerShell Remoting (基于 WinRM)，你可以轻松地在一台计算机上对成百上千台远程服务器执行命令。
-   **访问广泛**: PowerShell 可以管理 Windows 操作系统的方方面面，包括注册表、WMI、文件系统、服务、进程等，并且可以与 Active Directory, Exchange, SQL Server 等几乎所有微软服务器产品进行深度集成。

---

### 18.2 PowerShell 核心概念

1.  **Cmdlets (命令)**:
    -   遵循 `Verb-Noun` 格式的本地命令。
    -   使用 `Get-Command` 来查找命令，例如 `Get-Command *-Service` 会找到所有与服务相关的命令。
    -   使用 `Get-Help` 来获取命令的帮助文档，例如 `Get-Help Get-Service -Full`。

2.  **变量 (Variables)**:
    -   以 `$` 符号开头，例如 `$name = "World"`。
    -   `echo "Hello, $name"` 会输出 "Hello, World"。

3.  **管道 (Pipeline `|`)**:
    -   将一个 Cmdlet 的输出（对象）作为另一个 Cmdlet 的输入。
    -   **示例**: 获取所有正在运行的服务，并按名称排序。
        ```powershell
        Get-Service | Where-Object { $_.Status -eq 'Running' } | Sort-Object DisplayName
        ```
    -   `$_` 是一个特殊变量，代表管道中当前的对象。

4.  **常用操作符**:
    -   比较操作符: `-eq` (等于), `-ne` (不等于), `-gt` (大于), `-lt` (小于), `-ge` (大于等于), `-le` (小于等于)。
    -   逻辑操作符: `-and`, `-or`, `-not`。
    -   匹配操作符: `-like` (使用通配符 `*`), `-match` (使用正则表达式)。

---

### 18.3 编写你的第一个脚本

PowerShell 脚本是以 `.ps1` 为扩展名的纯文本文件。

**示例脚本: `Get-StoppedServices.ps1`**

```powershell
# 这是一个简单的脚本，用于查找所有已停止的服务，并尝试启动它们。

# 1. 获取所有状态为 "Stopped" 的服务
$stoppedServices = Get-Service | Where-Object { $_.Status -eq 'Stopped' }

# 2. 检查是否找到了已停止的服务
if ($stoppedServices) {
    Write-Host "找到了以下已停止的服务:"
    # 将服务列表输出到控制台
    $stoppedServices | Format-Table Name, DisplayName

    # 3. 遍历每个服务并尝试启动
    foreach ($service in $stoppedServices) {
        Write-Host "正在尝试启动 $($service.Name)..."
        try {
            Start-Service -Name $service.Name -ErrorAction Stop
            Write-Host "$($service.Name) 已成功启动。" -ForegroundColor Green
        }
        catch {
            Write-Warning "启动 $($service.Name) 失败: $($_.Exception.Message)"
        }
    }
}
else {
    Write-Host "系统中没有已停止的服务。" -ForegroundColor Yellow
}

Write-Host "脚本执行完毕。"
```

---

### 18.4 执行策略 (Execution Policy)

为了防止恶意脚本的执行，PowerShell 有一个安全功能叫做"执行策略"。默认情况下，它通常是 `Restricted`（禁止任何脚本运行）。

1.  **查看当前策略**:
    ```powershell
    Get-ExecutionPolicy
    ```

2.  **常见的执行策略**:
    -   `Restricted`: 不允许运行任何脚本。
    -   `AllSigned`: 只允许运行由受信任的发布者签名的脚本。
    -   `RemoteSigned`: **推荐用于服务器**。允许运行本地创建的脚本，但从网络下载的脚本必须经过签名。
    -   `Unrestricted`: 允许所有脚本运行，有安全风险。

3.  **更改执行策略**:
    你必须以**管理员身份**运行 PowerShell 才能更改策略。
    ```powershell
    Set-ExecutionPolicy RemoteSigned
    ```

**如何运行脚本**:
-   打开 PowerShell 控制台。
-   导航到脚本所在的目录。
-   输入 `.\YourScriptName.ps1` 并按回车。

---

### 18.5 远程管理

PowerShell Remoting 允许你在远程计算机上执行命令，就像在本地操作一样。

1.  **在目标服务器上启用 WinRM**:
    以管理员身份在目标服务器上运行以下命令：
    ```powershell
    Enable-PSRemoting -Force
    ```

2.  **在你的管理机上执行远程命令**:
    -   **一对一 (Interactive Session)**: 进入一个远程会话。
        ```powershell
        Enter-PSSession -ComputerName RemoteServerName
        # 之后你输入的所有命令都在远程服务器上执行
        # 输入 exit 退出会话
        ```
    -   **一对多 (Invoke-Command)**: 在一台或多台计算机上执行命令。
        ```powershell
        $computers = "Server01", "Server02", "WebApp01"
        Invoke-Command -ComputerName $computers -ScriptBlock {
            # 这个代码块中的所有内容都会在每个远程服务器上执行
            Get-Service -Name "Spooler"
        }
        ```

掌握 PowerShell 是从"手动管理员"转变为"自动化工程师"的关键一步。它是现代 Windows 管理不可或缺的技能。 