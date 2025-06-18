# 8. Docker Compose 入门

到目前为止，我们已经学会了如何运行单个容器。但现实世界中的应用很少是孤立的，它们通常由多个相互依赖的服务组成，例如一个 Web 应用前端、一个后端 API、一个数据库和一个缓存服务。

手动管理这些容器是一件非常痛苦的事情：
-   你需要手动创建网络，以确保容器可以相互通信。
-   你需要记住并按正确的顺序启动和停止每个容器。
-   `docker run` 命令会变得异常冗长和复杂，难以维护。

为了解决这个问题，Docker 官方推出了 **Docker Compose**。

## Docker Compose 是什么？

Docker Compose 是一个用于**定义和运行多容器 Docker 应用程序**的工具。通过 Compose，你可以使用一个 **YAML 文件**来配置应用程序的所有服务，然后使用一个简单的命令，就可以从这个配置中创建并启动所有服务。

Compose 的使用是一个三步过程：
1.  在一个 `Dockerfile` 中定义你的应用环境，使其可以在任何地方重现。
2.  在一个 `docker-compose.yml` 文件中定义构成你的应用的服务，以便它们可以在一个隔离的环境中一起运行。
3.  运行 `docker-compose up` 命令来启动并运行你的整个应用。

## 核心概念

-   **服务 (Services)**:
    一个服务就是应用中的一个容器。它通常基于一个镜像来构建，并包含一些额外的配置，如端口映射、网络连接、卷挂载等。例如，`web`、`db`、`api` 都可以是服务。

-   **网络 (Networks)**:
    Compose 会为你的应用创建一个**默认的自定义桥接网络**。应用中的每个服务都会连接到这个网络。这使得服务之间可以通过其**服务名**作为主机名直接进行通信，极大地简化了服务发现。

-   **卷 (Volumes)**:
    你可以在 `docker-compose.yml` 的顶层定义命名卷，然后在多个服务之间共享和重用这些卷，方便集中管理持久化数据。

## `docker-compose.yml` 文件结构

`docker-compose.yml` 是 Compose 的核心。它使用 YAML 语法来描述一个多容器应用。

**一个简单的 `docker-compose.yml` 示例**:
```yaml
# 指定 Compose 文件格式的版本 (在现代 Compose 中已非必需，但仍是良好实践)
version: '3.8'

# 定义所有的服务
services:
  # 第一个服务，名为 "web"
  web:
    # 基于哪个镜像来构建
    image: nginx:latest
    # 端口映射
    ports:
      - "8080:80"

  # 第二个服务，名为 "database"
  database:
    image: redis:alpine
```
在这个例子中：
-   我们定义了两个服务：`web` 和 `database`。
-   Compose 会自动创建一个网络，并将这两个服务都连接进去。
-   在 `web` 容器内部，可以通过主机名 `database` 来访问 `redis` 服务。

## 常用命令

所有 `docker-compose` 命令都需要在包含 `docker-compose.yml` 文件的目录中运行。

-   **`docker-compose up`**:
    这是最核心的命令。它会按照 `docker-compose.yml` 的定义，自动执行以下操作：
    1.  查找或构建服务的镜像。
    2.  创建并启动所有服务的容器。
    3.  创建网络并将容器连接上去。
    4.  附加到所有容器的日志输出。

    -   **`docker-compose up -d`**: 在**后台** (detached mode) 启动并运行所有服务。这是生产或日常开发中最常用的方式。
    -   **`docker-compose up --build`**: 在启动前强制重新构建镜像。

-   **`docker-compose down`**:
    这是一个"清理"命令。它会停止并**移除**由 `up` 命令创建的所有容器和网络。
    -   **`docker-compose down -v`**: 在清理的同时，**移除**在 `volumes` 部分定义的命名卷。这对于彻底重置应用状态非常有用。

-   **`docker-compose ps`**:
    列出当前 Compose 应用中所有容器的状态。

-   **`docker-compose logs`**:
    查看所有服务的日志。
    -   **`docker-compose logs -f <service_name>`**: 实时跟踪指定服务的日志。

-   **`docker-compose exec <service_name> <command>`**:
    在指定服务的**一个正在运行的**容器内执行一个命令。
    ```bash
    # 进入 web 服务的容器的 shell
    docker-compose exec web /bin/sh
    ```

-   **`docker-compose pull`**:
    拉取 `docker-compose.yml` 中定义的所有服务的最新镜像。

-   **`docker-compose build`**:
    只构建（或重新构建）服务的镜像，但不启动它们。

Docker Compose 将复杂的多容器管理流程简化为几个易于记忆的命令和一个声明式的配置文件，是本地开发和测试环境中的必备神器。在下一章，我们将看一个更复杂的例子，来编排一个真实的应用。 