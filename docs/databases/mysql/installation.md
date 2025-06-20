# 2. 安装与配置 (Installation & Configuration)

MySQL 可以在多个主流操作系统上安装，包括 Windows、macOS 和各种 Linux 发行版。本章将介绍在这些平台上安装 MySQL Community Server 的通用步骤，并进行基础配置。

> ⚠️ **注意**: 软件版本和安装步骤可能会随时间变化。建议始终参考 MySQL 官方文档获取最新信息。

## 在 Windows 上安装

在 Windows 上安装 MySQL 最简便的方法是使用 MySQL Installer。

1.  **下载 MySQL Installer**:
    - 访问 [MySQL Community Downloads 页面](https://dev.mysql.com/downloads/installer/)。
    - 下载 "Windows (x86, 32-bit), MSI Installer"。它包含了所有 MySQL 产品，可以选择在线安装或离线安装。推荐下载离线版本（ حجم较大）。

2.  **运行安装程序**:
    - 双击下载的 `.msi` 文件启动安装向导。
    - **选择安装类型**:
        - **Developer Default**: 安装开发所需的所有产品，包括 MySQL Server、Shell、Router、Workbench 等。推荐初学者选择此项。
        - **Server only**: 只安装 MySQL 服务器。
        - **Client only**: 只安装客户端工具。
        - **Full**: 安装所有可用产品。
        - **Custom**: 自定义要安装的产品、版本和平台。
    - **检查依赖**: 安装程序会自动检查所需的依赖（如 Visual C++ Redistributable）。如果缺少，它会尝试自动安装。
    - **安装**: 确认要安装的产品列表，然后点击 "Execute" 开始安装。

3.  **配置 MySQL Server**:
    - 安装完成后，向导会自动进入配置阶段。
    - **High Availability**: 选择 "Standalone MySQL Server / Classic MySQL Replication"。
    - **Type and Networking**:
        - **Config Type**: 选择 "Development Computer"，这会使用较少的内存。 "Server Computer" 或 "Dedicated Computer" 用于生产环境。
        - **Connectivity**: 保持默认 TCP/IP 端口 `3306`。确保防火墙允许此端口的流量。
    - **Authentication Method**:
        - 推荐选择 "Use Strong Password Encryption for Authentication (RECOMMENDED)"，这是更安全的 `caching_sha2_password` 验证方式。
        - 如果需要兼容旧版客户端，可以选择 "Use Legacy Authentication Method"。
    - **Accounts and Roles**:
        - **设置 `root` 密码**: `root` 是 MySQL 的超级管理员用户。务必设置一个强密码并牢记。
        - **添加用户 (可选)**: 可以创建一个普通用户，并分配角色（如 `DB Admin`, `DB Designer`）。
    - **Windows Service**:
        - 将 MySQL 配置为 Windows 服务，使其能够开机自启。可以自定义服务名称。
    - **Apply Configuration**: 点击 "Execute" 应用所有配置。

4.  **验证安装**:
    - 打开 **MySQL Command Line Client** 或 **MySQL Shell**。
    - 输入您在安装过程中设置的 `root` 密码。
    - 如果成功登录并看到 `mysql>` 提示符，说明安装成功。
    - 运行 `SHOW DATABASES;` 命令查看默认的数据库。

## 在 macOS 上安装

在 macOS 上，推荐使用 Homebrew 包管理器进行安装。

1.  **安装 Homebrew** (如果尚未安装):
    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

2.  **安装 MySQL**:
    ```bash
    brew install mysql
    ```
    Homebrew 会自动处理依赖并安装最新稳定版的 MySQL。

3.  **启动 MySQL 服务**:
    ```bash
    brew services start mysql
    ```
    这会将 MySQL 设置为开机自启的服务。

4.  **安全配置**:
    - 运行 MySQL 提供的安全配置脚本：
      ```bash
      mysql_secure_installation
      ```
    - 这个脚本会引导您完成以下设置：
        - **Validate Password Component**: 是否启用密码强度验证插件。
        - **设置 `root` 密码**: 为 `root` 用户设置新密码。
        - **移除匿名用户**: 增强安全性。
        - **禁止 `root` 远程登录**: 限制 `root` 只能从本地登录。
        - **移除 `test` 数据库**: 清理测试数据。
        - **重新加载权限表**: 使所有更改生效。

5.  **登录 MySQL**:
    ```bash
    mysql -u root -p
    ```
    输入您刚刚设置的 `root` 密码即可登录。

## 在 Linux (Ubuntu/Debian) 上安装

以 Ubuntu 20.04/22.04 为例。

1.  **更新软件包列表**:
    ```bash
    sudo apt update
    sudo apt upgrade
    ```

2.  **安装 MySQL Server**:
    ```bash
    sudo apt install mysql-server
    ```
    APT 包管理器会自动处理安装过程。

3.  **安全配置**:
    - 与 macOS 类似，运行安全配置脚本：
      ```bash
      sudo mysql_secure_installation
      ```
    - 按照提示完成 `root` 密码设置和其他安全选项的配置。

4.  **验证服务状态**:
    ```bash
    sudo systemctl status mysql
    ```
    如果服务正在运行，您会看到 "active (running)" 的状态信息。

5.  **登录 MySQL**:
    - 在 Ubuntu/Debian 中，`root` 用户默认使用 `auth_socket` 插件进行认证，这意味着您需要使用 `sudo` 来登录。
      ```bash
      sudo mysql
      ```
    - 如果想使用密码登录，需要进入 MySQL，修改 `root` 用户的认证方式：
      ```sql
      ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'YourNewPassword';
      FLUSH PRIVILEGES;
      EXIT;
      ```
      之后就可以使用 `mysql -u root -p` 登录了。

## 连接到 MySQL

安装完成后，您可以使用多种工具连接到 MySQL 服务器：

- **命令行接口 (CLI)**:
  - **MySQL Shell**: 功能更强大的新一代命令行工具，支持 SQL、JavaScript 和 Python 模式。
  - **MySQL Command Line Client**: 传统的客户端。
- **图形用户界面 (GUI)**:
  - **MySQL Workbench**: 官方提供的集数据库设计、建模、管理于一体的强大工具。
  - **phpMyAdmin**: 基于 Web 的流行 MySQL 管理工具。
  - **DBeaver**: 开源的通用数据库管理工具，支持多种数据库。
  - **Navicat**: 功能强大的商业数据库管理工具。 