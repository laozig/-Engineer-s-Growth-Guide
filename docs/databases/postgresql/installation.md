# 2. PostgreSQL 安装与配置

在本章节中，我们将介绍如何在常见的操作系统（Windows, macOS, Linux）上安装和配置PostgreSQL。我们还将介绍如何使用Docker进行快速部署。

## 在 Windows 上安装

Windows 用户最简单的方式是使用 EDB (EnterpriseDB) 提供的图形化安装包。

1.  **下载安装包**:
    访问 [PostgreSQL 官方下载页面](https://www.postgresql.org/download/windows/)，然后点击 EDB 的下载链接。根据您的系统选择合适的版本（例如，PostgreSQL 14）。

2.  **运行安装程序**:
    - 下载完成后，双击运行安装程序。
    - **Installation Directory**: 选择安装路径，例如 `C:\PostgreSQL\14`。
    - **Select Components**: 保持默认选项即可，包括 PostgreSQL Server, pgAdmin 4, Stack Builder, 和 Command Line Tools。
    - **Data Directory**: 选择数据存储路径，例如 `C:\PostgreSQL\14\data`。
    - **Password**: 设置数据库超级用户 `postgres` 的密码。**请务必记住这个密码**。
    - **Port**: 保持默认端口 `5432`。
    - **Advanced Options**: 选择默认的 "Default locale"。
    - 点击 "Next" 完成安装。

3.  **验证安装**:
    - 打开 `psql`（SQL Shell）或 pgAdmin 4。
    - 当提示输入密码时，输入您之前设置的密码。
    - 成功连接后，您会看到 `postgres=#` 提示符。
    - 输入 `SELECT version();` 可以查看当前数据库版本。

## 在 macOS 上安装

macOS 用户推荐使用 [Homebrew](https://brew.sh/) 包管理器进行安装。

```bash
# 更新 Homebrew
brew update

# 安装 PostgreSQL
brew install postgresql

# 启动 PostgreSQL 服务
brew services start postgresql
```

安装完成后，`postgres` 用户和数据库已经创建，默认无需密码即可本地连接。

## 在 Linux 上安装 (以 Ubuntu/Debian 为例)

大多数Linux发行版的官方仓库都包含了PostgreSQL。

```bash
# 更新软件包列表
sudo apt update

# 安装 PostgreSQL 和相关工具
sudo apt install postgresql postgresql-contrib

# PostgreSQL 服务会自动启动
```

安装后，系统会创建一个名为 `postgres` 的Linux用户。您需要切换到此用户来访问数据库。

```bash
# 切换到 postgres 用户
sudo -i -u postgres

# 连接到数据库
psql
```

## 使用 Docker 快速部署

如果您希望快速启动一个隔离的开发环境，Docker是最佳选择。

1.  **拉取镜像**:
    ```bash
    docker pull postgres:latest
    ```

2.  **启动容器**:
    ```bash
    docker run --name my-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 5432:5432 -d postgres
    ```
    - `--name my-postgres`: 为容器命名。
    - `-e POSTGRES_PASSWORD=mysecretpassword`: 设置 `postgres` 用户的密码。
    - `-p 5432:5432`: 将本机的5432端口映射到容器的5432端口。
    - `-d`: 后台运行。

3.  **连接到容器**:
    您可以使用任何本地的SQL客户端（如DBeaver, DataGrip, 或 psql）连接到 `localhost:5432`，用户名为 `postgres`，密码为您设置的 `mysecretpassword`。

    或者，直接在容器内使用 `psql`:
    ```bash
    docker exec -it my-postgres psql -U postgres
    ```

## 初始配置 `postgresql.conf`

`postgresql.conf` 是PostgreSQL的主配置文件，通常位于数据目录下。对于初学者，默认配置已经足够好。随着您对PostgreSQL的深入，您可能需要调整一些参数，例如：

- `listen_addresses`: 监听的IP地址，默认为 `localhost`。如果要允许远程连接，可以设置为 `*`。
- `max_connections`: 最大并发连接数。
- `shared_buffers`: 分配给数据块缓存的内存。
- `work_mem`: 单个查询操作（如排序、哈希）可以使用的内存。

修改配置后，需要重启PostgreSQL服务才能生效。

接下来，我们将深入了解 [PostgreSQL的体系结构](architecture.md)。 