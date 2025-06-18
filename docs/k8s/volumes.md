# 10. Volumes：容器存储

我们知道，容器的文件系统是**短暂的 (ephemeral)**。当一个容器崩溃、被删除或被重启时，其内部所做的任何文件修改都会丢失。此外，在一个多容器的 Pod 中，每个容器都有自己隔离的文件系统，它们之间无法直接共享文件。

这两个问题——**数据持久化**和**文件共享**——由 Kubernetes 的 `Volume` 机制来解决。

## 什么是 Volume？

在 Kubernetes 中，`Volume` 可以被理解为一个**可被 Pod 中所有容器访问的目录**。

它的核心特性是：
1.  **独立于容器的生命周期**: `Volume` 的生命周期与 **Pod** 绑定，而不是 Pod 内的某个特定容器。即使容器重启，`Volume` 中的数据依然存在。
2.  **Pod 内共享**: 一个 `Volume` 可以被同一个 Pod 内的多个容器同时挂载，从而实现文件共享。

当 Pod 被销毁时，`Volume` 才会根据其类型的不同而被清理或保留。

## Volume 的使用

在 Pod 的 `spec` 中定义 `Volume` 分为两步：
1.  `spec.volumes`: 在 Pod 级别定义一个或多个 `Volume`，并指定其类型（例如 `emptyDir`, `hostPath` 等）。
2.  `spec.containers.volumeMounts`: 在每个需要访问该 `Volume` 的容器中，指定要挂载哪个 `Volume` (`name` 字段必须与 `spec.volumes` 中定义的 `name` 匹配) 和挂载到容器内的哪个路径 (`mountPath`)。

## 常用的 Volume 类型

Kubernetes 支持多种多样的 `Volume` 类型，从简单的临时目录到复杂的云存储系统。本章我们先介绍几种最基础的类型。

### 1. `emptyDir`

-   **作用**: 创建一个临时的、初始为空的目录。
-   **生命周期**: 与 Pod 完全相同。当 Pod 被创建时，`emptyDir` 卷被创建；当 Pod 因任何原因被删除时，`emptyDir` 卷中的数据将**永久丢失**。
-   **适用场景**:
    -   在同一个 Pod 的多个容器之间共享文件（例如，Sidecar 模式）。
    -   作为临时的工作空间或缓存目录，用于存放中间计算结果。
-   **YAML 示例 (Sidecar 文件共享)**:
    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: pod-with-emptydir
    spec:
      containers:
      - name: writer-container
        image: busybox
        command: ["/bin/sh", "-c", "echo 'Shared content' > /shared-data/data.txt && sleep 3600"]
        volumeMounts:
        - name: shared-volume
          mountPath: /shared-data
      - name: reader-container
        image: busybox
        command: ["/bin/sh", "-c", "cat /shared-data/data.txt && sleep 3600"]
        volumeMounts:
        - name: shared-volume
          mountPath: /shared-data
      volumes:
      - name: shared-volume
        emptyDir: {}
    ```

### 2. `hostPath`

-   **作用**: 将宿主节点（Node）文件系统上的一个文件或目录直接挂载到 Pod 中。
-   **生命周期**: `hostPath` 卷中的数据不会随 Pod 的删除而丢失。但它与宿主节点的生命周期绑定。
-   **适用场景 (需要谨慎使用)**:
    -   访问节点的 Docker 守护进程 (`/var/lib/docker`)。
    -   运行需要访问节点系统文件或日志的监控代理。
-   **严重警告**: `hostPath` 是一个**强大但危险**的工具！
    -   **安全风险**: 容器可以访问甚至修改宿主节点的文件系统，可能导致权限提升和安全漏洞。
    -   **节点绑定**: 使用 `hostPath` 的 Pod 会与特定的宿主节点强耦合。如果 Pod 被调度到另一个没有该文件/目录的节点上，它就会失败。
    -   **你应该在绝大多数情况下避免使用它**，除非你正在开发需要与节点直接交互的系统级软件。
-   **YAML 示例**:
    ```yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: pod-with-hostpath
    spec:
      containers:
      - name: my-container
        image: busybox
        command: ["/bin/sh", "-c", "ls -l /node-logs && sleep 3600"]
        volumeMounts:
        - name: host-log-volume
          mountPath: /node-logs
      volumes:
      - name: host-log-volume
        hostPath:
          path: /var/log # 宿主节点上的路径
          type: Directory # 指定路径类型
    ```

### 3. `configMap` 和 `secret`

我们在前两章已经接触过这两种特殊的 `Volume` 类型。它们的作用不是通用存储，而是将特定的配置或敏感数据作为文件注入到 Pod 中。这进一步说明了 `Volume` 是一种通用的挂载机制。

```yaml
# ...
  volumes:
  - name: config-volume
    configMap:
      name: my-configmap
  - name: secret-volume
    secret:
      secretName: my-secret
```

## 展望：真正的持久化存储

我们目前学习的 `Volume` 类型（特别是 `emptyDir` 和 `hostPath`）仍然有局限性：
-   `emptyDir` 的数据随 Pod 一同消失。
-   `hostPath` 的数据与特定节点绑定，不适合分布式应用。

对于需要**真正的数据持久化**的应用（如数据库、消息队列），我们需要一种存储方案，其生命周期**完全独立于 Pod 和节点**。即使 Pod 被删除或被调度到其他节点，数据依然安全存在，并能被新的 Pod 重新挂载。

这就是下一章我们要学习的 `PersistentVolume` (PV) 和 `PersistentVolumeClaim` (PVC) 的用武之地。它们提供了一个强大的抽象，将存储的"供应"与"消费"解耦，并能与各种网络存储（如 NFS、Ceph）和云存储（如 AWS EBS、GCP Persistent Disk）无缝集成。 