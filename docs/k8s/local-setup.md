# 2. 搭建本地 K8s 环境

在与真正的 Kubernetes 集群交互之前，我们需要一个安全、隔离且易于重置的实验环境。幸运的是，社区提供了多种优秀的工具，可以让你在自己的个人电脑上轻松运行一个单节点的 Kubernetes 集群。

本章将介绍三种主流的本地集群搭建方案：**Minikube**、**Kind** 和 **Docker Desktop**。

## 如何选择？

| 工具 | 主要特点 | 优点 | 缺点 | 推荐场景 |
| :--- | :--- | :--- | :--- | :--- |
| **Minikube** | 在虚拟机(VM)或容器中运行单节点 K8s | 功能全面，社区成熟，支持多种驱动 | 资源占用相对较高 | 需要模拟完整 K8s 环境，或需要特定插件(Addon)的用户。 |
| **Kind** (Kubernetes in Docker) | 使用 Docker 容器作为 K8s "节点" | 启动快，资源占用低，易于创建多节点集群进行测试 | 依赖 Docker，网络配置相对简单 | CI/CD 环境，需要快速创建/销毁集群的开发者。 |
| **Docker Desktop** | 内置于 Docker for Win/Mac | 安装最简单，与 Docker 工具链无缝集成 | 配置选项少，灵活性差，可能占用较多系统资源 | 已经在使用 Docker Desktop 的 Windows/Mac 用户，追求便捷性。 |

对于初学者，**Docker Desktop** 是最快上手的方式。如果你想更深入地了解 K8s 的组件或需要一个更灵活的环境，**Minikube** 是一个非常可靠的选择。

---

## 方案一：Minikube

Minikube 是一个跨平台的工具，它可以在你的笔记本电脑上的虚拟机（如 VirtualBox, Hyper-V）或容器（如 Docker）内启动一个单节点 Kubernetes 集群。

### 1. 安装

首先，你需要安装 `kubectl`，这是 Kubernetes 的命令行工具。然后，根据你的操作系统安装 Minikube。

- **官方 `kubectl` 安装指南**: [Install and Set Up kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
- **官方 `minikube` 安装指南**: [Get Started with Minikube](https://minikube.sigs.k8s.io/docs/start/)

### 2. 启动集群

安装完成后，一个简单的命令就可以启动你的本地集群。Minikube 会自动选择一个驱动（driver），但你也可以用 `--driver` 标志指定一个。使用 Docker 驱动通常性能更好。

```bash
# 启动集群 (推荐使用 docker 驱动)
minikube start --driver=docker

# 如果遇到国内镜像拉取问题，可以指定镜像仓库
minikube start --driver=docker --image-mirror-country=cn
```

### 3. 与集群交互

Minikube 会自动配置 `kubectl`，使其指向新创建的集群。

```bash
# 检查节点状态，确认集群已就绪
kubectl get nodes
# NAME       STATUS   ROLES           AGE   VERSION
# minikube   Ready    control-plane   1m    v1.28.3

# 获取集群的 IP 地址
minikube ip
```

### 4. 其他常用命令

```bash
# 停止集群 (保留所有状态)
minikube stop

# 暂停 Kubernetes (不停止虚拟机/容器)
minikube pause

# 恢复暂停的集群
minikube unpause

# 删除集群 (会删除所有数据)
minikube delete

# 打开 Kubernetes Dashboard (Web UI)
minikube dashboard
```

---

## 方案二：Kind

Kind 使用 Docker 容器来模拟 Kubernetes 节点，因此它的启动速度非常快，资源占用也小。

### 1. 安装

Kind 只有一个二进制文件，安装非常简单。

- **官方 `kind` 安装指南**: [Kind Quick Start](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)

### 2. 创建集群

```bash
# 创建一个名为 "my-k8s-cluster" 的集群
kind create cluster --name my-k8s-cluster

# Kind 也会自动将 kubectl 的上下文切换到新集群
kubectl cluster-info --context kind-my-k8s-cluster
```

### 3. 删除集群

```bash
kind delete cluster --name my-k8s-cluster
```

Kind 的主要优势在于能够轻松创建**多节点集群**，这对于测试复杂的调度和网络策略非常有用。你只需创建一个配置文件即可，详情请查阅官方文档。

---

## 方案三：Docker Desktop Kubernetes

对于已经安装了 Docker Desktop (Windows 或 macOS) 的用户来说，这是最直接的方法。

### 1. 启用 Kubernetes

1.  打开 Docker Desktop 的设置 (Settings)。
2.  导航到 **Kubernetes** 标签页。
3.  勾选 **"Enable Kubernetes"**。
4.  点击 **"Apply & Restart"**。

Docker Desktop 会在后台下载所需的镜像并启动一个单节点集群。这个过程可能需要一些时间。

### 2. 切换上下文

启用后，Docker Desktop 会自动添加一个新的 `kubectl` 上下文 `docker-desktop`。

```bash
# 查看所有可用的上下文
kubectl config get-contexts

# 切换到 Docker Desktop 的上下文
kubectl config use-context docker-desktop
```

## 验证安装

无论你选择哪种方法，最后都可以通过以下命令来验证你的本地 Kubernetes 集群是否已成功安装并正在运行。

```bash
# 获取集群中的节点信息
kubectl get nodes
```

如果你看到一个状态为 `Ready` 的节点，那么恭喜你，你已经拥有了一个可以用于学习和实验的 Kubernetes 环境！ 