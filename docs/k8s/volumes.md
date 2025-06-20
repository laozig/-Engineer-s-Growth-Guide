# 10. Volumes：容器存储

容器的文件系统是**临时的**。当容器崩溃或被删除时，其中写入的所有数据都会丢失。对于需要持久化数据或在容器间共享文件的应用来说，这显然是不可接受的。

为了解决这个问题，Kubernetes 引入了 **Volume** 的概念。

## 10.1 什么是 Volume？

在 Kubernetes 中，**Volume** 是一种独立于容器生命周期的存储抽象。它允许数据在容器重启甚至被删除后依然存在，并可以在同一个 Pod 的多个容器之间共享。

**核心概念**：
- **生命周期**：Volume 的生命周期与 **Pod** 绑定。只要 Pod 存在，Volume 就会存在。如果 Pod 被删除，Volume 也会被销毁（除非它是一种持久化类型的 Volume）。
- **数据共享**：Pod 中的所有容器都可以共享同一个 Volume，只需将它挂载到各自的文件系统中。

Volume 的本质是将一个外部存储目录（无论是宿主机上的目录、云存储还是其他类型的存储）"链接"到 Pod 内部的一个或多个挂载点。

<div align="center">
  <img src="https://i.imgur.com/kS9eLpQ.png" alt="Volume shared between containers in a Pod" width="600">
</div>

## 10.2 Volume 的类型

Kubernetes 支持多种类型的 Volume，以适应不同的存储需求和后端存储系统。下面介绍几种最常见的类型。

### 1. `emptyDir`

- **描述**：一个临时的、与 Pod 生命周期完全一致的空目录。
- **生命周期**：当 Pod 被创建时，`emptyDir` 也被创建；当 Pod 被删除时，`emptyDir` 中的数据会**永久丢失**。
- **用途**:
    - 在同一 Pod 的多个容器之间共享文件。
    - 作为临时空间，例如用于缓存或存放中间计算结果。

**示例**：
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-pod
spec:
  containers:
  - image: nginx
    name: nginx-container
    volumeMounts:
    - mountPath: /cache
      name: cache-volume
  - image: busybox
    name: busybox-container
    command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
    volumeMounts:
    - mountPath: /data
      name: cache-volume
  volumes:
  - name: cache-volume
    emptyDir: {}
```
在这个例子中，Nginx 容器和 BusyBox 容器共享同一个名为 `cache-volume` 的 `emptyDir` 卷，它们分别挂载在 `/cache` 和 `/data` 目录下。

### 2. `hostPath`

- **描述**：将宿主机节点上的一个文件或目录挂载到 Pod 中。
- **生命周期**：数据直接存在于节点上，如果 Pod 被删除并重新调度到**另一个节点**，数据会丢失。
- **用途**：
    - 需要访问节点上系统级文件或设备的应用（如监控代理）。
    - 在单节点集群中进行本地开发和测试。
- **警告**：`hostPath` 是一种强大的工具，但也存在安全风险。它会暴露底层节点的细节，并且可能导致应用与特定节点强耦合。在多节点生产环境中应谨慎使用。

**示例**：
```yaml
volumes:
- name: node-logs
  hostPath:
    # 宿主机上的目录路径
    path: /var/log
    # 类型，确保路径是目录
    type: Directory
```

### 3. `configMap` 和 `secret`

- **描述**：我们已经学习过，可以将 ConfigMap 和 Secret 作为只读卷挂载到 Pod 中。
- **用途**：将配置信息和敏感数据作为文件注入到应用中，而不是使用环境变量。

### 4. `persistentVolumeClaim` (PVC)

- **描述**：这是处理**持久化存储**的标准和推荐方式。它允许 Pod "申请" 使用一块持久化存储，而无需关心底层的存储技术（如 AWS EBS, GCP Persistent Disk, NFS 等）。
- **生命周期**：数据的生命周期与 Pod **完全解耦**。即使 Pod 被删除，数据依然保留在后端的持久化存储上。
- **用途**：数据库、有状态应用、需要长期保存数据的文件系统等。

`persistentVolumeClaim` 是一个非常重要的概念，它涉及 `PersistentVolume` (PV) 和 `StorageClass` 等其他对象。我们将在下一章专门深入探讨它。

## 10.3 如何在 Pod 中定义和使用 Volume

在 Pod 的 YAML 中，使用 Volume 分为两步：
1.  **定义 Volume (`spec.volumes`)**: 在 Pod 的 `spec` 下，使用 `volumes` 列表来定义一个或多个 Volume，并为它们命名。这里需要指定 Volume 的类型（如 `emptyDir`, `hostPath`）。
2.  **挂载 Volume (`spec.containers.volumeMounts`)**: 在需要使用该 Volume 的每个容器的定义下，使用 `volumeMounts` 列表来将已定义的 Volume 挂载到容器内的特定路径 (`mountPath`)。

回顾上面的 `emptyDir` 示例，你可以清晰地看到这两步的实践。

## 10.4 总结

Volume 是 Kubernetes 中实现数据共享和持久化的核心机制。它通过将存储与容器解耦，解决了容器文件系统临时性的问题。我们介绍了几种常见的 Volume 类型，特别是临时的 `emptyDir` 和节点绑定的 `hostPath`。

然而，对于真正的生产级有状态应用，我们需要更强大、更灵活的持久化存储方案。这就是 `PersistentVolumeClaim` 的用武之地，也是我们下一章的主题。
