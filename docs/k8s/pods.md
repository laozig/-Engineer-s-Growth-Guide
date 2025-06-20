# 4. Pods：原子部署单元

欢迎来到 Kubernetes 核心工作负载的第一章。本章我们将深入探讨 Kubernetes 中最基本、最重要的部署单元——**Pod**。

## 4.1 什么是 Pod？

在 Kubernetes 的世界里，**Pod 是最小的可部署、可管理的计算单元**。它不是直接运行单个容器，而是对容器的一层封装。

一个 Pod 可以包含：
- **一个或多个容器** (例如，一个主应用容器和一个辅助日志收集容器)。
- **共享的存储资源** (Volumes)。
- **共享的网络命名空间** (即唯一的 IP 地址)。

**核心理念**：Pod 内的所有容器共享同一个网络环境（IP地址、端口空间）和存储卷。它们可以通过 `localhost` 互相通信，就像运行在同一台物理机上的进程一样。

<div align="center">
  <img src="https://i.imgur.com/vI5g2xU.png" alt="Pod with multiple containers" width="600">
</div>

## 4.2 Pod 的生命周期

Pod 被设计为**临时的、一次性的**。它们被创建、分配一个唯一的 ID (UID)，然后被调度到某个节点上运行，直到它们终止（因完成任务或出错）或被删除。

- **Pod 不会自我修复**。如果一个 Pod 所在的节点发生故障，或者 Pod 本身崩溃，它不会在新的节点上被重新创建。这是更高级别的控制器（如 Deployment）的职责。
- 当一个 Pod 被删除时，其内部的容器、共享资源会随之一同被销毁。

Pod 的生命周期有几个主要阶段（Phase）:
- **Pending**: Pod 已被接受，但其容器尚未全部创建。通常在拉取镜像或等待网络资源时处于此状态。
- **Running**: Pod 已绑定到节点，所有容器都已创建。至少有一个容器正在运行，或者正在启动/重启。
- **Succeeded**: Pod 中的所有容器都已成功终止，并且不会再重启。通常用于 Job 或一次性任务。
- **Failed**: Pod 中的所有容器都已终止，但至少有一个容器是因失败而终止的。
- **Unknown**: 由于某种原因，无法获取 Pod 的状态，通常是与节点通信失败。

## 4.3 如何定义一个 Pod (YAML)

在 Kubernetes 中，我们通常使用 YAML 文件来声明式地定义资源。下面是一个简单的 Nginx Pod 的定义示例：

**`nginx-pod.yaml`**:
```yaml
# API 版本，对于 Pod 来说通常是 v1
apiVersion: v1
# 资源类型
kind: Pod
# 元数据，包含名称、标签等
metadata:
  name: nginx-pod-example
  labels:
    app: nginx
# 规格，定义 Pod 的期望状态
spec:
  containers:
    # 容器列表
    - name: nginx-container
      image: nginx:1.14.2
      ports:
        - containerPort: 80
```

**关键字段解释**：
- `apiVersion`: 指定了创建此对象所使用的 Kubernetes API 的版本。
- `kind`: 指定了要创建的资源类型，这里是 `Pod`。
- `metadata`: 包含了对象的元数据，如 `name`（唯一标识）和 `labels`（用于选择和组织对象的键值对）。
- `spec`: 定义了 Pod 的期望状态，最核心的部分是 `containers` 列表。
  - `containers`: 一个或多个容器的定义。
    - `name`: 容器的名称。
    - `image`: 用于创建容器的 Docker 镜像。
    - `ports`: 容器需要暴露的端口。

## 4.4 Pod 的管理操作 (`kubectl`)

**创建 Pod**:
```bash
kubectl apply -f nginx-pod.yaml
```

**查看 Pod**:
```bash
# 查看所有 Pod
kubectl get pods

# 查看名为 nginx-pod-example 的 Pod 的详细信息
kubectl describe pod nginx-pod-example
```

**删除 Pod**:
```bash
kubectl delete pod nginx-pod-example
```

## 4.5 何时使用多容器 Pod？

虽然一个 Pod 最常见的情况是只运行一个容器，但在某些特定场景下，将多个容器紧密耦合在一个 Pod 中会非常有用。这通常被称为 **Sidecar 模式**。

常见用例：
- **日志收集**: 一个主应用容器，旁边有一个 "sidecar" 容器负责收集和转发日志。
- **数据代理/代理服务**: 一个 sidecar 容器负责处理网络请求，为主应用容器提供服务或安全过滤。
- **配置刷新**: 一个 sidecar 容器监控配置源，当配置变化时自动更新并通知主应用。

这些 sidecar 容器与主应用容器共享生命周期和网络，形成了强大的功能单元。

## 4.6 总结

本章我们学习了 Pod 作为 Kubernetes 的原子单元的核心地位。我们了解了它的构成、生命周期、如何用 YAML 定义它，以及何时使用多容器模式。

请记住，我们通常不直接创建和管理单个 Pod。在下一章，我们将学习 **Deployments**，这是一个更高级别的资源，它能自动化管理 Pod 的副本、更新和回滚，是无状态应用部署的首选方式。