# 6. Docker 网络

当运行单个容器时，网络问题似乎很简单。但要构建由多个容器组成的复杂应用时，理解 Docker 的网络模型就变得至关重要。Docker 提供了一套强大而灵活的网络系统，允许容器之间以及容器与外部世界进行通信。

## 容器网络基础

Docker 的网络功能是基于 **Linux 网络命名空间 (Network Namespace)** 实现的。每个 Docker 容器都有自己独立的网络栈，包括：
-   自己的 `lo` (loopback) 回环网卡。
-   自己的 `eth0` 虚拟网卡。
-   自己的 IP 地址。
-   自己的路由表和 `iptables` 规则。

这种隔离意味着，默认情况下，一个容器无法感知到宿主机或其他容器的网络接口。Docker 的任务就是通过其网络驱动，在这些隔离的命名空间之间以及与宿主机之间建立通信的桥梁。

## 网络驱动 (Network Drivers)

Docker 提供了多种网络驱动，以适应不同的使用场景。

### 1. `bridge` (桥接网络) - 默认模式

这是最常用也是 Docker 默认的网络模式。
-   **工作原理**: 当 Docker 启动时，它会在宿主机上创建一个名为 `docker0` 的虚拟网络**网桥 (bridge)**。每当你不指定网络模式创建一个新容器时，Docker 会为该容器创建一个虚拟网卡对 (veth pair)，一端连接到容器的网络命名空间（在容器内显示为 `eth0`），另一端连接到宿主机的 `docker0` 网桥上。
-   **IP 地址**: Docker 会从一个私有 IP 地址段（如 `172.17.0.0/16`）中为连接到 `docker0` 网桥的每个容器分配一个 IP 地址。
-   **容器间通信**:
    -   连接到**同一个**默认 `bridge` 网络的容器，可以通过它们的 **IP 地址**相互通信。
    -   **注意**: 在默认的 `bridge` 网络中，不支持通过容器名进行 DNS 解析。
-   **外部访问**: 外部世界无法直接访问 `bridge` 网络中的容器。要让外部能够访问容器内的服务，你必须使用 `-p` 或 `--publish` 标志进行**端口映射**。
    ```bash
    docker run -d -p 8080:80 nginx
    ```
    这条命令会将宿主机的所有网络接口上的 `8080` 端口的流量，通过 `iptables` 规则转发到容器的 `80` 端口。

### 2. `host` (主机网络)

-   **工作原理**: 在此模式下，容器**不会**获得自己独立的网络命名空间。相反，它与宿主机**共享**同一个网络栈。
-   **优点**:
    -   **性能最高**: 因为它直接使用宿主机的网络，无需经过 NAT 或端口映射，网络性能几乎与原生应用无异。
-   **缺点**:
    -   **安全性低**: 容器不再有网络隔离。容器内运行的服务可以直接访问宿主机的所有网络接口。
    -   **端口冲突**: 容器内监听的端口会直接占用宿主机的端口，你无法在同一台宿主机上运行多个监听相同端口的容器。
-   **使用方式**:
    ```bash
    docker run --network host nginx
    ```

### 3. `none` (无网络)

-   **工作原理**: 容器拥有自己的网络命名空间，但 Docker 不会为其进行任何网络配置。容器内只有一个 `lo` 回环接口，没有 `eth0`。
-   **使用场景**: 适用于那些完全不需要网络连接，只需要执行计算任务或文件操作的容器。
-   **使用方式**:
    ```bash
    docker run --network none ubuntu
    ```

### 4. `overlay` (覆盖网络)

-   **工作原理**: 覆盖网络是一种用于连接**多个 Docker 主机**上容器的网络驱动。它可以在不同的宿主机之间创建一个分布式的虚拟网络，使得不同主机上的容器就像在同一个局域网中一样，可以直接通信。
-   **使用场景**: 这是 Docker Swarm（Docker 的原生集群工具）和 Kubernetes 等容器编排平台实现多机通信的核心技术。我们将在介绍这些工具时再深入探讨它。

## 网络管理命令

Docker 提供了一组 `docker network` 命令来管理网络。

-   **`docker network ls`**: 列出所有可用的网络。
    ```bash
    # docker network ls
    # NETWORK ID     NAME      DRIVER    SCOPE
    # a1b2c3d4e5f6   bridge    bridge    local
    # f6e5d4c3b2a1   host      host      local
    # b2c3d4e5f6a1   none      none      local
    ```

-   **`docker network create <network_name>`**: 创建一个自定义网络。默认情况下，创建的是 `bridge` 类型的网络。
    ```bash
    docker network create my-app-net
    ```

-   **`docker network inspect <network_name>`**: 查看一个网络的详细配置，包括其子网、网关以及连接到该网络的容器列表。

-   **`docker network connect <network> <container>`**: 将一个**正在运行**的容器连接到一个网络。一个容器可以同时连接到多个网络。

-   **`docker network disconnect <network> <container>`**: 将一个容器与一个网络断开。

## 最佳实践：使用自定义桥接网络

虽然 Docker 默认提供了一个 `bridge` 网络，但在实际应用开发中，**最佳实践是为你自己的应用创建一个或多个自定义的桥接网络**。

**为什么？**
1.  **更好的隔离性**: 默认的 `bridge` 网络是一个大杂烩，所有未指定网络的容器都会连到上面。将你的应用（例如，一个 web 前端和一个数据库后端）放在一个专门的网络中，可以实现与机器上其他无关容器的网络隔离。
2.  **内置的自动 DNS 解析**: 这是最重要的优点！在自定义桥接网络中，容器可以通过它们的**容器名**直接相互通信。Docker 会自动为你管理 DNS。

**示例**:
```bash
# 1. 创建一个自定义网络
docker network create my-app-net

# 2. 启动数据库容器，并将其连接到新网络
docker run -d --name db --network my-app-net postgres:14-alpine

# 3. 启动应用容器，并将其连接到新网络
# 假设应用通过一个名为 DATABASE_HOST 的环境变量来连接数据库
docker run -d --name api --network my-app-net \
       -e DATABASE_HOST=db \
       my-api-image
```
在这个例子中，`api` 容器可以直接通过主机名 `db` 来访问 `postgres` 数据库容器，而无需关心其 IP 地址。这使得应用的配置变得非常简单和健壮。 