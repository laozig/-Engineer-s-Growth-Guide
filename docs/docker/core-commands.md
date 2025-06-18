# 3. 核心命令

掌握 Docker 的核心命令是高效使用它的关键。本章将分类介绍管理镜像、容器生命周期、与容器交互以及系统清理的最常用命令。

## 镜像管理 (Image Management)

镜像是构建容器的基础。以下命令用于管理这些镜像。

-   **`docker images`**: 列出本地存储的所有镜像。
    ```bash
    docker images
    # REPOSITORY    TAG       IMAGE ID       CREATED         SIZE
    # hello-world   latest    d2c94e258dcb   5 months ago    13.3kB
    # nginx         latest    6efc10a3a788   5 months ago    187MB
    # ubuntu        22.04     2b74de74fb80   5 months ago    77.8MB
    ```

-   **`docker pull <image_name>[:tag]`**: 从 Docker Hub 或其他配置的仓库中拉取一个镜像。
    ```bash
    # 拉取最新版的 Redis
    docker pull redis

    # 拉取特定版本的 Redis
    docker pull redis:6.2
    ```
    如果不指定标签 (tag)，默认会拉取 `latest` 标签。

-   **`docker rmi <image_id_or_name:tag>`**: 删除一个或多个本地镜像。
    ```bash
    docker rmi redis:6.2
    ```
    **注意**: 如果有容器正在使用该镜像，你必须先删除容器才能删除镜像。可以使用 `-f` 标志强制删除。

-   **`docker tag <source_image> <target_image>`**: 为镜像创建一个新的标签。这通常用于在推送前重命名镜像以符合仓库的命名规范。
    ```bash
    # 将本地的 nginx 镜像标记为你的 Docker Hub 用户名下的 my-nginx
    docker tag nginx your-username/my-nginx:1.0
    ```

-   **`docker push <image_name:tag>`**: 将一个本地镜像推送到远程仓库。你需要先登录到该仓库 (`docker login`)。
    ```bash
    # 推送刚才标记的镜像
    docker push your-username/my-nginx:1.0
    ```

## 容器生命周期管理 (Container Lifecycle)

这些命令用于创建、启动、停止和删除容器。

-   **`docker run <image>`**: 这是最核心的命令，从一个镜像创建并启动一个新容器。它有很多非常有用的参数：
    -   `-d` (detach): 在后台运行容器，并打印出容器ID。
    -   `-p <host_port>:<container_port>`: 将宿主机的端口映射到容器的端口。
    -   `--name <container_name>`: 为容器指定一个易于记忆的名称。
    -   `-it` (interactive + tty): 创建一个交互式的终端会话，允许你进入容器的 shell。
    -   `--rm`: 容器退出时自动将其删除。
    -   `-v <host_path>:<container_path>`: 将宿主机的目录或文件挂载到容器中（卷和挂载将在后续章节详细介绍）。
    -   `-e <KEY=VALUE>`: 设置环境变量。

    **示例**:
    ```bash
    # 在后台运行一个名为 "my-web-server" 的 nginx 容器，
    # 并将宿主机的 8080 端口映射到容器的 80 端口。
    docker run -d -p 8080:80 --name my-web-server nginx
    ```

-   **`docker ps`**: 列出当前**正在运行**的容器。
    -   `docker ps -a`: 列出**所有**的容器，包括已停止的。

-   **`docker stop <container_id_or_name>`**: 优雅地停止一个或多个正在运行的容器（会先发送一个 SIGTERM 信号）。

-   **`docker start <container_id_or_name>`**: 启动一个或多个已停止的容器。

-   **`docker restart <container_id_or_name>`**: 重启一个容器。

-   **`docker rm <container_id_or_name>`**: 删除一个或多个**已停止**的容器。
    -   `docker rm -f <container>`: 强制删除一个正在运行的容器。

## 容器交互与监控 (Interaction & Monitoring)

-   **`docker logs <container>`**: 查看一个容器的日志（标准输出和标准错误）。
    -   `docker logs -f <container>`: 实时跟踪日志输出 (follow)。
    -   `docker logs --tail 100 <container>`: 只看最后100行日志。

-   **`docker exec -it <container> <command>`**: 在一个**正在运行**的容器内部执行一个命令。这是与容器交互的主要方式。
    **示例**:
    ```bash
    # 进入名为 "my-web-server" 的容器的 bash shell
    docker exec -it my-web-server /bin/bash

    # 在容器内执行一个 ls 命令，而无需进入 shell
    docker exec my-web-server ls /usr/share/nginx/html
    ```

-   **`docker inspect <container_or_image>`**: 显示一个 Docker 对象（容器、镜像、卷等）的底层详细信息，通常以 JSON 格式输出。这对于调试网络或存储问题非常有用。

## 系统清理 (System Cleanup)

随着时间推移，你的系统可能会积累大量无用的容器、镜像和卷。

-   **`docker system prune`**: 这是一个非常有用的命令，用于一键清理：
    -   所有已停止的容器
    -   所有悬空的镜像 (dangling images，即没有标签且不被任何容器使用的镜像)
    -   所有未被任何容器使用的网络
    -   所有构建缓存

    运行此命令前请仔细阅读提示。

-   **清理所有未使用的镜像**:
    如果想更彻底地清理，可以添加 `-a` 标志来删除所有当前未被任何容器使用的镜像（不仅仅是悬空镜像）。
    ```bash
    docker system prune -a
    ```

掌握这些核心命令，你就可以开始在日常工作中高效地使用 Docker 了。在后续章节中，我们将学习如何通过 Dockerfile 来自动构建我们自己的镜像。 