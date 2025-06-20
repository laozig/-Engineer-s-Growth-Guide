# 2. 搭建本地实验环境

在深入学习 Kubernetes 之前，拥有一个可以动手实践的本地环境至关重要。本章将介绍几种主流的本地 Kubernetes 环境搭建方案，并提供详细的安装和使用指南。

## 2.1 为什么需要本地环境？

- **学习与实验**：在不影响生产环境的情况下，自由地测试和验证 Kubernetes 的各种功能。
- **本地开发**：在与生产环境一致的容器编排环境中开发和调试应用。
- **离线工作**：无需云服务商的集群，随时随地进行学习和开发。
- **成本效益**：完全免费，避免使用云资源的开销。

## 2.2 主流方案对比

| 工具 | 优点 | 缺点 | 适用场景 |
| :--- | :--- | :--- | :--- |
| **Minikube** | 功能全面，社区成熟，支持多种驱动 | 资源占用相对较高 | 功能验证、模拟完整集群 |
| **Kind (Kubernetes in Docker)** | 启动快，资源占用低，原生支持多节点 | 功能相对基础 | CI/CD、快速测试、多节点实验 |
| **Docker Desktop** | 安装简单，与Docker无缝集成 | 占用资源较多，Windows/Mac特定 | Docker用户、快速上手 |

对于初学者，**Minikube** 或 **Docker Desktop** 是最容易上手的选择。如果你需要进行多节点集群的模拟实验，**Kind** 是一个绝佳的选择。

---

## 2.3 方案一：使用 Minikube

Minikube 是一个轻量级的 Kubernetes 实现，可以在本地的虚拟机或容器中创建一个单节点的 Kubernetes 集群。

### 2.3.1 安装 Minikube

**Windows (使用 Chocolatey):**
```powershell
choco install minikube
```

**macOS (使用 Homebrew):**
```bash
brew install minikube
```

**Linux (二进制安装):**
```bash
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube
```

### 2.3.2 安装驱动

Minikube 需要一个驱动来创建虚拟机或容器。推荐使用 **Docker** 作为驱动。请确保你已经安装了 Docker。

### 2.3.3 启动集群

```bash
# 启动 Minikube 集群，使用 docker 驱动
minikube start --driver=docker

# 检查集群状态
minikube status
```

输出应类似：
```
minikube
type: Control Plane
host: Running
kubelet: Running
apiserver: Running
kubeconfig: Configured
```

### 2.3.4 与集群交互

Minikube 会自动配置 `kubectl`。你可以直接使用 `kubectl` 命令：

```bash
# 获取集群信息
kubectl cluster-info

# 获取节点列表
kubectl get nodes
```

### 2.3.5 常用命令

- `minikube stop`: 停止集群
- `minikube delete`: 删除集群
- `minikube dashboard`: 打开 Kubernetes Dashboard
- `minikube ssh`: SSH 到 Minikube 虚拟机

---

## 2.4 方案二：使用 Kind

Kind (Kubernetes in Docker) 使用 Docker 容器作为"节点"，可以快速创建和销毁多节点的 Kubernetes 集群。

### 2.4.1 安装 Kind

**Windows (使用 Chocolatey):**
```powershell
choco install kind
```

**macOS / Linux (使用 Homebrew 或二进制):**
```bash
# macOS
brew install kind

# Linux
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.11.1/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind
```

### 2.4.2 创建集群

```bash
# 创建一个名为 "my-cluster" 的默认集群
kind create cluster --name my-cluster

# 检查集群列表
kind get clusters
```

### 2.4.3 创建多节点集群

创建一个 `kind-config.yaml` 文件：
```yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
```

然后使用此配置创建集群：
```bash
kind create cluster --config kind-config.yaml
```

使用 `kubectl get nodes` 你将看到一个控制平面和两个工作节点。

### 2.4.4 删除集群

```bash
kind delete cluster --name my-cluster
```

---

## 2.5 方案三：使用 Docker Desktop

如果你已经安装了最新版的 Docker Desktop (for Windows or Mac)，它内置了 Kubernetes 支持。

### 2.5.1 启用 Kubernetes

1. 打开 Docker Desktop 的设置 (Settings)。
2. 导航到 **Kubernetes** 标签页。
3. 勾选 **Enable Kubernetes**。
4. 点击 **Apply & Restart**。

Docker Desktop 会在后台下载所需的镜像并启动一个单节点的 Kubernetes 集群。

### 2.5.2 切换上下文

Docker Desktop 会自动将 `kubectl` 的上下文切换到 `docker-desktop`。你可以通过以下命令确认：

```bash
kubectl config current-context
# 输出应为: docker-desktop
```

现在你可以直接使用 `kubectl` 与这个本地集群交互了。

## 2.6 总结

本章我们介绍了三种主流的本地 Kubernetes 环境搭建方案：Minikube、Kind 和 Docker Desktop。我们学习了如何安装和使用它们来创建、管理和销毁本地集群。

现在你已经拥有一个可以实践的 Kubernetes 环境了。在下一章，我们将学习 `kubectl` 的核心命令，它是你与 Kubernetes 集群交互的主要工具。 