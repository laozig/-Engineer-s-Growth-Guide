# MongoDB 安装与环境配置

本指南将详细介绍如何在主流操作系统（Windows, macOS, Linux）上安装 MongoDB Community Server，以及如何配置必要的工具，如 MongoDB Shell (`mongosh`) 和 MongoDB Compass (GUI)。

## 目录
- [选择合适的 MongoDB 版本](#选择合适的-mongodb-版本)
- [在 Windows 上安装](#在-windows-上安装)
- [在 macOS 上安装](#在-macos-上安装)
- [在 Linux 上安装 (以 Ubuntu 为例)](#在-linux-上安装-以-ubuntu-为例)
- [通过 Docker 安装](#通过-docker-安装)
- [安装 MongoDB Shell (`mongosh`)](#安装-mongodb-shell-mongosh)
- [安装 MongoDB Compass (GUI 工具)](#安装-mongodb-compass-gui-工具)
- [验证安装与基本配置](#验证安装与基本配置)

---

## 选择合适的 MongoDB 版本

-   **MongoDB Community Server**: 免费的社区版，功能齐全，是本指南的安装重点。
-   **MongoDB Enterprise Server**: 企业版，在社区版基础上提供了额外的安全、管理和运维功能，需要商业订阅。
-   **MongoDB Atlas**: 全托管的云服务，无需自己安装和管理数据库，是快速上手和生产部署的推荐方式。

## 在 Windows 上安装

1.  **下载安装程序**：
    -   访问 [MongoDB 官方下载中心](https://www.mongodb.com/try/download/community)。
    -   选择合适的版本（Version）、平台（Platform: Windows x64）和包（Package: msi）。
    -   点击 "Download"。

2.  **运行 MSI 安装向导**：
    -   双击下载的 `.msi` 文件。
    -   选择 **"Complete" (完整)** 安装，这会安装所有组件并将其设置为 Windows 服务。
    -   在 "Service Configuration" 步骤中，建议勾选 **"Install MongoD as a Service"** 并选择 **"Run service as Network Service user"**（默认选项）。
    -   记下或自定义数据目录（Data Directory）和日志目录（Log Directory）。
    -   **重要**：安装程序会自动安装 **MongoDB Compass** (官方 GUI 工具)，建议勾选。

3.  **配置环境变量 (可选但推荐)**：
    -   将 MongoDB Server 的 `bin` 目录（例如 `C:\Program Files\MongoDB\Server\6.0\bin`）添加到系统的 `PATH` 环境变量中。这样你就可以在任何命令行窗口中直接运行 `mongod` 和 `mongosh` 命令。

## 在 macOS 上安装

推荐使用 [Homebrew](https://brew.sh/) 包管理器进行安装，这是最简单的方式。

1.  **更新 Homebrew**：
    ```sh
    brew update
    ```
2.  **添加 MongoDB 的 Homebrew Tap**：
    ```sh
    brew tap mongodb/brew
    ```
3.  **安装 MongoDB Community Edition**：
    ```sh
    brew install mongodb-community
    ```
4.  **运行 MongoDB 服务**：
    -   **作为后台服务运行**（推荐）：
        ```sh
        brew services start mongodb-community
        ```
    -   **手动在前台运行**（用于调试）：
        ```sh
        mongod --config /usr/local/etc/mongod.conf
        ```
    -   要停止后台服务，使用 `brew services stop mongodb-community`。

## 在 Linux 上安装 (以 Ubuntu 为例)

不推荐直接使用 `apt install mongodb`，因为官方仓库的版本通常很旧。应遵循 MongoDB 官方的指导来添加其软件源。

1.  **导入 MongoDB 公共 GPG 密钥**：
    ```sh
    sudo apt-get install gnupg
    curl -fsSL https://pgp.mongodb.com/server-6.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
    ```
    *注意：请根据需要安装的 MongoDB 版本替换 `6.0`。*

2.  **为 MongoDB 创建列表文件**：
    ```sh
    echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
    ```

3.  **更新本地包数据库**：
    ```sh
    sudo apt-get update
    ```

4.  **安装 MongoDB 包**：
    这将安装最新的稳定版 MongoDB 及其相关工具。
    ```sh
    sudo apt-get install -y mongodb-org
    ```

5.  **启动和管理 MongoDB 服务 (`systemd`)**：
    -   **启动服务**：
        ```sh
        sudo systemctl start mongod
        ```
    -   **验证服务状态**：
        ```sh
        sudo systemctl status mongod
        ```
    -   **设置开机自启**：
        ```sh
        sudo systemctl enable mongod
        ```
    -   **停止/重启服务**：
        `sudo systemctl stop mongod` / `sudo systemctl restart mongod`

## 通过 Docker 安装

对于开发和测试环境，使用 Docker 是一个非常方便的选择。

1.  **拉取 MongoDB 镜像**：
    ```sh
    docker pull mongo
    ```
2.  **运行 MongoDB 容器**：
    ```sh
    docker run --name my-mongo-container -p 27017:27017 -d mongo
    ```
    -   `--name`: 为容器指定一个名字。
    -   `-p 27017:27017`: 将主机的 27017 端口映射到容器的 27017 端口。
    -   `-d`: 在后台运行容器。

## 安装 MongoDB Shell (`mongosh`)

`mongosh` 是下一代的 MongoDB 命令行客户端。在较新版本的 MongoDB Server 安装包中通常会自带。如果未安装，可以单独安装。

-   **通过 Homebrew (macOS)**: `brew install mongosh`
-   **通过 `apt` (Ubuntu)**: 通常已随 `mongodb-org` 包安装。
-   **单独下载**：访问 [MongoDB Shell 下载页面](https://www.mongodb.com/try/download/shell) 下载对应系统的二进制包并配置环境变量。

## 安装 MongoDB Compass (GUI 工具)

Compass 提供了一个图形化界面来操作 MongoDB。

-   **在 Windows/macOS 安装时**：通常可以选择附带安装 Compass。
-   **单独下载**：访问 [MongoDB Compass 下载页面](https://www.mongodb.com/try/download/compass) 下载并安装。

## 验证安装与基本配置

1.  **启动 `mongosh`**：
    打开一个新的终端或命令提示符，输入：
    ```sh
    mongosh
    ```
    如果成功连接到本地运行的 MongoDB 实例，您会看到一个欢迎信息和提示符 `>`。

2.  **执行基本命令**：
    在 `mongosh` 中，尝试执行以下命令：
    ```javascript
    // 查看当前数据库
    > db

    // 查看所有数据库
    > show dbs

    // 切换到一个新数据库（如果不存在则会在第一次插入数据时创建）
    > use myNewDB

    // 插入一条数据
    > db.myCollection.insertOne({ name: "MongoDB", type: "Database", status: "Awesome" })

    // 查询数据
    > db.myCollection.find()
    ```
    如果以上命令都能正常执行，恭喜您，MongoDB 环境已成功搭建！ 