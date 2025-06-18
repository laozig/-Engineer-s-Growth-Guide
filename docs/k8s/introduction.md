# 1. Kubernetes 简介

在 Docker 学习路径的结尾，我们探讨了为何需要一个比 Docker Compose 更强大的工具来管理生产环境中的容器。现在，我们正式进入这个工具的学习——Kubernetes。

## Kubernetes 是什么？

Kubernetes（常简称为 K8s）是一个开源的、用于**自动化部署、扩展和管理容器化应用程序**的系统。它最初由 Google 设计，现在由云原生计算基金会（CNCF）维护。

如果说 Docker 提供了标准化的"集装箱"，那么 Kubernetes 就是那个自动化的"港口"和"全球航运系统"。它负责处理大规模集装箱的调度、装卸、监控和维护工作。

Kubernetes 的核心思想是**声明式配置 (Declarative Configuration)**。
-   **命令式 (Imperative)**: 你告诉系统**如何**做。例如，"启动一个容器，然后启动第二个，将它们连接到网络A..."。这是 `docker run` 的方式。
-   **声明式 (Declarative)**: 你告诉系统你**想要什么**。例如，"我想要我的应用有 3 个副本，对外暴露 80 端口，并能访问数据库"。你将这个"期望状态"写入一个 YAML 文件，然后由 Kubernetes 自己想办法达成并维持这个状态。如果一个副本崩溃了，Kubernetes 会自动创建一个新的来替代它，以确保始终有 3 个副本在运行。

这种声明式的范式是 Kubernetes 强大自愈和自动化能力的基础。

## Kubernetes 核心架构

一个 Kubernetes 集群由两类主要节点组成：**控制平面 (Control Plane)** 和 **工作节点 (Worker Nodes)**。

![K8s Architecture](https://i.imgur.com/your-k8s-arch-image.png) <!-- 你需要替换成真实的图片链接 -->

### 控制平面 (Control Plane)

控制平面是集群的"大脑"，它做出所有关于集群的全局决策（例如，调度），以及检测和响应集群事件。控制平面的组件可以运行在任何机器上，但在生产环境中，它们通常运行在专用的主节点 (Master Nodes) 上以实现高可用。

**控制平面的核心组件**:
-   **`kube-apiserver` (API 服务器)**:
    -   控制平面的**唯一入口**。所有组件之间的通信，以及用户（通过 `kubectl`）与集群的交互，都必须通过 API 服务器。
    -   它负责验证和处理 REST 请求，并更新后端的 `etcd` 存储。
-   **`etcd`**:
    -   一个高可用的、一致的**键值存储**。
    -   它是 Kubernetes 的唯一"事实来源 (Source of Truth)"，存储了整个集群的所有配置数据和状态。
-   **`kube-scheduler` (调度器)**:
    -   监视新创建的、但尚未分配到节点的 Pods。
    -   根据资源需求、硬件限制、亲和性策略等一系列规则，为每个 Pod 选择一个最佳的 Worker Node 来运行。
-   **`kube-controller-manager` (控制器管理器)**:
    -   运行着所有核心的**控制器 (Controllers)**。
    -   每个控制器都是一个独立的循环，它通过 API 服务器跟踪集群的状态，并努力将当前状态转变为期望状态。例如，`Deployment` 控制器确保应用的副本数正确，`Node` 控制器负责监控节点状态。

### 工作节点 (Worker Nodes)

工作节点是集群中真正运行你的应用程序（即 Pods）的地方。每个集群至少有一个工作节点。

**工作节点的核心组件**:
-   **`kubelet`**:
    -   在每个 Worker Node 上运行的代理。它的主要工作是确保分配给该节点的 Pods 都在运行且健康。
    -   它从 API 服务器接收 Pod 的规格（PodSpec），并指示容器运行时（如 Docker）来启动或停止容器。
-   **`kube-proxy` (网络代理)**:
    -   在每个 Worker Node 上运行的网络代理。
    -   它负责实现 Kubernetes 的 `Service` 概念，通过维护节点上的网络规则（例如使用 `iptables`）来实现 Pod 之间的网络通信和负载均衡。
-   **`Container Runtime` (容器运行时)**:
    -   负责实际运行容器的软件。
    -   最著名的是 **Docker**，但 Kubernetes 也支持其他符合 CRI (Container Runtime Interface) 标准的运行时，如 **containerd** 和 **CRI-O**。

## 核心对象概览

你通过向 Kubernetes API 服务器提交 YAML 文件来创建和管理 **K8s 对象 (Objects)**，这些对象代表了你的期望状态。我们将在后续章节中深入学习它们：
-   **Pod**: 最小和最简单的部署单元。一个 Pod 代表了集群中一个正在运行的进程。
-   **Deployment**: 管理 Pod 的副本，并提供声明式的更新和回滚策略。
-   **Service**: 为一组 Pod 提供一个稳定的网络端点（IP 地址和 DNS 名称）。
-   **Namespace**: 在同一个物理集群中创建多个虚拟集群，用于隔离资源。

理解这个架构是掌握 Kubernetes 的第一步。它解释了 Kubernetes 是如何通过一组协作的组件，将你的声明式配置转化为一个正在运行的、自我修复的应用系统。 