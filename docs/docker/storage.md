# 7. 数据持久化 (卷与挂载)

容器被设计为无状态和临时的。当你停止并删除一个容器时，它在可写层中创建的所有数据都会随之消失。这对于运行无状态的应用来说没有问题，但对于数据库、用户上传的文件或任何需要持久保存的数据来说，这是一个致命的问题。

Docker 提供了几种强大的机制来将数据持久化，让数据独立于容器的生命周期存在。

## Docker 数据持久化方案

主要有三种方式来为容器提供持久化存储：

1.  **卷 (Volumes)**
2.  **绑定挂载 (Bind Mounts)**
3.  **tmpfs 挂载 (tmpfs Mounts)**

让我们来详细了解它们。

### 1. 卷 (Volumes) - 推荐的方式

卷是存储容器数据的**首选机制**。
-   **工作原理**: 卷是由 Docker 创建和管理的、存储在宿主机文件系统特定部分（Linux 上通常是 `/var/lib/docker/volumes/`）的数据区域。你不需要关心它在宿主机上的具体位置，Docker 会为你处理好一切。
-   **优点**:
    -   **与容器生命周期解耦**: 删除容器不会删除其关联的卷。
    -   **更安全、更易于管理**: 卷由 Docker CLI 管理，避免了与宿主机文件系统的紧密耦合。
    -   **易于备份和迁移**: 可以轻松地备份、恢复或迁移卷。
    -   **性能更好**: 在许多情况下，卷在 Docker 引擎中的实现能提供比绑定挂载更好的性能。
    -   **跨平台兼容**: 卷的行为在所有平台上都是一致的。
    -   **支持卷驱动 (Volume Drivers)**: 允许你将数据存储在远程主机或云存储上。

-   **如何使用**:
    -   **匿名卷 (Anonymous Volume)**:
        ```bash
        # Docker 会自动创建一个卷并挂载到容器的 /app/data 目录
        docker run -d -v /app/data my-image
        ```
        这种方式不推荐，因为难以引用和管理这个卷。
    -   **命名卷 (Named Volume)**: 这是最佳实践。
        ```bash
        # -v <volume_name>:<container_path>
        docker run -d --name my-container -v my-app-data:/app/data my-image
        ```
        如果名为 `my-app-data` 的卷不存在，Docker 会自动创建它。

-   **卷管理命令**:
    -   `docker volume create <name>`: 创建一个卷。
    -   `docker volume ls`: 列出所有卷。
    -   `docker volume inspect <name>`: 查看卷的详细信息。
    -   `docker volume rm <name>`: 删除一个或多个卷。
    -   `docker volume prune`: 删除所有未被任何容器使用的卷。

### 2. 绑定挂载 (Bind Mounts)

绑定挂载将宿主机上的一个**任意**文件或目录直接挂载到容器中。这个文件或目录由其在宿主机上的**绝对路径**来引用。

-   **工作原理**: 容器中的指定路径实际上就是宿主机上的那个路径。对容器内该路径的任何修改，都会**实时反映**在宿主机上，反之亦然。
-   **主要用途**:
    -   **开发环境**: 这是绑定挂载最经典的用途。你可以将本地的源代码目录挂载到容器中。当你在本地 IDE 中修改代码时，容器内的应用可以立即感知到变化（例如通过热重载），无需重新构建镜像。
-   **缺点**:
    -   **与宿主机紧密耦合**: 应用的可移植性变差，因为它依赖于宿主机上特定的目录结构。
    -   **权限问题**: 容器内的进程（可能以 `root` 运行）可以修改宿主机上的文件，包括关键的系统文件，这可能带来安全风险。文件所有权和权限 (UID/GID) 的问题也常常令人头疼。

-   **如何使用**:
    ```bash
    # -v /path/on/host:/path/in/container
    docker run -d --name my-dev-container -v /home/user/my-app/src:/app/src my-dev-image
    ```

### 3. tmpfs 挂载

`tmpfs` 挂载是一种**非持久化**的存储方式，它将数据直接存储在宿主机的**内存**中。当容器停止时，`tmpfs` 挂载中的数据会**立即被删除**。

-   **用途**:
    -   当你不想让数据持久化到容器的可写层或宿主机磁盘上时。
    -   适用于存储临时的状态文件或不需要持久化的敏感数据。
-   **如何使用**:
    ```bash
    docker run -d --name my-tmp-container --mount type=tmpfs,destination=/app/cache my-image
    ```

## `--mount` vs. `-v` (或 `--volume`)

你可能注意到了，有两种方式可以指定卷和绑定挂载：`-v` 和 `--mount`。
-   **`-v`**: 语法更简洁，历史更悠久。
-   **`--mount`**: 语法更长，但更明确、更易读。它使用键值对的方式来指定选项，例如 `type=volume,source=my-data,destination=/app/data`。

**对比**:
| | `-v` | `--mount` |
|---|---|---|
| **卷** | `-v my-vol:/app` | `--mount type=volume,source=my-vol,target=/app` |
| **绑定挂载**| `-v /path:/app` | `--mount type=bind,source=/path,target=/app`|

虽然两者功能几乎相同，但 **`--mount` 是 Docker 官方现在推荐的方式**，因为它更具可读性和明确性。

## 如何选择？

-   **绝大多数场景**: 使用**卷 (Volumes)**。特别是当你需要存储应用数据（如数据库文件、用户上传内容）时。
-   **开发和共享配置**: 使用**绑定挂载 (Bind Mounts)**。非常适合将源代码注入容器以实现实时开发，或将宿主机上的配置文件共享给容器。
-   **临时敏感数据**: 使用 **tmpfs 挂载**。

正确地管理数据是成功运行有状态容器化应用的关键。 