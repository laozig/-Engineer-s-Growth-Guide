# 4. Pods：原子部署单元

欢迎来到 Kubernetes 的核心。在你深入了解所有高级功能之前，必须先透彻理解 **Pod**。

## 什么是 Pod？

在 Kubernetes 中，**Pod 是最小、最基本的可部署对象**。一个 Pod 代表了集群上一个正在运行的**进程组**。

你可能会想："等等，我以为容器是最小的单位？" 这是最常见的误解。在 Kubernetes 的世界里，你**不直接管理容器**，而是管理封装了容器的 Pod。

一个 Pod 可以包含：
-   一个或多个容器（例如 Docker 容器）。
-   共享的存储资源 (Volumes)。
-   共享的网络资源（唯一的集群 IP 地址）。
-   关于如何运行每个容器的配置信息（例如容器镜像版本、要使用的端口等）。

可以把 Pod 想象成一个独立的"逻辑主机"或"轻量级虚拟机"。它为内部的容器们提供了一个隔离的、共享的运行环境。

## 为何需要 Pod？

为什么不直接操作容器呢？因为容器本身是为运行**单个进程**而设计的。当多个进程需要紧密协作、共享资源时，就需要一个更高层次的抽象来"打包"它们。

Pod 正是这个抽象。同一个 Pod 内的所有容器共享：
-   **网络命名空间**: 它们共享同一个 IP 地址和端口空间。这意味着容器 `A` 可以通过 `localhost` 访问容器 `B` 开放的端口。
-   **IPC 命名空间**: 它们可以通过标准的进程间通信（如 SystemV IPC 或 POSIX 消息队列）进行通信。
-   **存储卷 (Volumes)**: 它们可以访问和操作同一组挂载的存储卷，实现数据共享。

这种设计使得那些需要紧密耦合的辅助进程（如日志收集器、数据代理、监控代理等）可以和主应用进程"生活"在一起，就像它们运行在同一台物理机上一样。

## Pod 的 YAML 定义

和 Kubernetes 中所有的对象一样，Pod 是通过一个 YAML 文件来声明式地定义的。让我们来看一个最简单的例子：

`nginx-pod.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: nginx-pod-example
  labels:
    app: web
spec:
  containers:
  - name: nginx-container
    image: nginx:1.25
    ports:
    - containerPort: 80
```

让我们分解一下这个文件：
-   `apiVersion`: 定义了创建此对象所需的 Kubernetes API 版本。对于 Pod，它是 `v1`。
-   `kind`: 定义了我们要创建的资源类型，这里是 `Pod`。
-   `metadata`: 包含了帮助识别该对象的元数据，如 `name` (唯一名称) 和 `labels` (键值对标签，用于组织和选择对象)。
-   `spec`: 这部分是重点，定义了 Pod 的**期望状态**。
    -   `containers`: 一个列表，定义了此 Pod 中要运行的所有容器。
        -   `name`: 容器的名称。
        -   `image`: 要使用的容器镜像。
        -   `ports`: 容器需要暴露的端口。`containerPort` 是容器内部监听的端口。

要创建这个 Pod，你可以使用 `kubectl apply`:
```bash
kubectl apply -f nginx-pod.yaml
```

## 单容器 Pod vs 多容器 Pod

### 单容器 Pod
这是最常见的使用模式。一个 Pod 中只运行一个容器。这种情况下，可以把 Pod 看作是容器的一个"包装器"，Kubernetes 通过管理 Pod 来间接管理容器。上面的 `nginx-pod-example` 就是一个单容器 Pod。

### 多容器 Pod (Sidecar 模式)
当一个应用需要一个或多个辅助工具来增强其功能时，就会使用多容器 Pod。这些辅助容器被称为 **Sidecar (边车)**。

**常见用例**:
-   **日志收集**: Sidecar 容器负责从主应用容器共享的卷中读取日志，并将其发送到集中的日志系统。
-   **服务网格代理**: 像 Istio 或 Linkerd 这样的服务网格会注入一个 Sidecar 代理容器，来处理所有的出入流量，以实现流量管理、监控和安全。
-   **数据同步**: Sidecar 容器可以定期从外部源（如 Git 仓库）拉取数据，并将其放入共享卷中供主应用使用。

**示例：带有日志收集 Sidecar 的 Pod**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-sidecar
spec:
  containers:
  - name: main-app-container
    image: busybox
    command: ["/bin/sh", "-c", "while true; do echo 'Main app running...' >> /var/log/app.log; sleep 5; done"]
    volumeMounts:
    - name: log-volume
      mountPath: /var/log
  - name: log-collector-sidecar
    image: busybox
    command: ["/bin/sh", "-c", "tail -f /var/log/app.log"]
    volumeMounts:
    - name: log-volume
      mountPath: /var/log
  volumes:
  - name: log-volume
    emptyDir: {}
```
在这个例子中：
1.  `main-app-container` 是我们的主应用，它不断地向 `/var/log/app.log` 文件写入日志。
2.  `log-collector-sidecar` 是边车，它负责读取同一个文件。
3.  它们通过一个名为 `log-volume` 的 `emptyDir` 卷来共享这个日志文件。`emptyDir` 是一个临时卷，其生命周期与 Pod 相同。

## Pod 的生命周期与不变性

**Pod 是短暂的 (Ephemeral)**。它们被设计为一次性的、可任意替换的单元。当一个 Pod 被创建后，它会经历以下几个阶段：
-   **Pending**: Pod 已被接受，但其容器尚未创建。通常是在下载镜像或等待调度。
-   **Running**: Pod 已被绑定到一个节点，并且所有容器都已创建。至少有一个容器正在运行，或者正处于启动或重启状态。
-   **Succeeded**: Pod 中的所有容器都已成功终止，并且不会再重启。
-   **Failed**: Pod 中的所有容器都已终止，并且至少有一个容器是因失败而终止的。
-   **Unknown**: 由于某种原因，无法获取 Pod 的状态，通常是与节点通信失败。

最重要的一点是：**Pod 的核心规范（如容器镜像、环境变量）是不可变的**。你不能在 Pod 运行后去修改它的定义。如果你需要更新应用，你必须**销毁旧的 Pod 并创建一个新的 Pod**。

这种"不可变基础设施"的思想是 Kubernetes 可靠性和可预测性的基石。然而，手动管理 Pod 的创建和销毁是非常繁琐的。在下一章，我们将学习 `Deployment`，这是一个更高级别的对象，它会自动为我们处理 Pod 的生命周期管理。 