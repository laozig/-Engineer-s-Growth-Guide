# 7. Namespaces：集群资源隔离

随着你的 Kubernetes 集群规模扩大，或者当多个团队、多个项目需要共享同一个集群时，问题随之而来：
-   如何防止不同团队之间的资源命名冲突？（例如，两个团队都想创建一个名为 `database-svc` 的 Service）
-   如何对不同项目的资源进行分组和隔离？
-   如何为不同项目分配和限制资源使用量？

Kubernetes 使用 **Namespaces** 来解决这些问题。

## 什么是 Namespace？

你可以把 Namespace 想象成在同一个物理集群之上划分出的一个个**虚拟集群**。它为 Kubernetes 中的**对象名称提供了一个作用域**。

-   在同一个 Namespace 内，所有资源（如 Pod, Deployment, Service）的名称必须是唯一的。
-   在不同的 Namespace 之间，资源的名称可以重复。

例如，`team-a` 命名空间可以有一个名为 `my-app` 的 Deployment，同时 `team-b` 命名空间也可以有一个同名的 `my-app` Deployment，它们是完全独立、互不干扰的。

**Namespace 的主要用途**:
-   **范围化名称**: 避免命名冲突。
-   **授权与策略**: 为不同的用户或团队设置不同的权限和策略（与 RBAC 结合使用）。
-   **资源隔离与配额**: 限制特定 Namespace 可以使用的计算资源总量（如 CPU 和内存）。

## 默认的 Namespaces

一个新创建的 Kubernetes 集群会自带几个初始的 Namespace：

-   **`default`**:
    -   如果你在创建资源时**没有指定**任何 Namespace，那么这个资源就会被创建在 `default` 命名空间中。
    -   对于初学者和小项目，这很方便，但对于生产环境，最佳实践是为你的应用创建专用的 Namespace。
-   **`kube-system`**:
    -   所有由 Kubernetes 系统创建和使用的对象都存放在这里。
    -   这里包含了集群的"大脑"和"神经中枢"，例如 `kube-apiserver`, `kube-scheduler`, `kube-proxy` 等控制平面组件的 Pod。
    -   **永远不要**在这里手动创建或修改资源，除非你非常清楚自己在做什么。
-   **`kube-public`**:
    -   这是一个特殊的 Namespace，所有用户（包括未认证的用户）都默认拥有对其的只读权限。
    -   通常用于存放一些希望对整个集群公开可见的信息，例如集群的版本信息。
-   **`kube-node-lease`**:
    -   每个节点都有一个关联的 Lease（租约）对象在这个命名空间中。
    -   这些租约用于节点心跳检测，帮助集群判断节点是否健康。

## Namespace 的使用

### 1. 查看和创建

```bash
# 查看集群中所有的 Namespaces
kubectl get namespaces
# 简写: kubectl get ns

# 创建一个新的 Namespace
kubectl create namespace my-app-ns

# 或者通过 YAML 文件创建
# my-namespace.yaml
# ---
# apiVersion: v1
# kind: Namespace
# metadata:
#   name: my-app-ns
# ---
# kubectl apply -f my-namespace.yaml
```

### 2. 在特定 Namespace 中操作资源

-   **使用 `-n` 或 `--namespace` 标志**:
    ```bash
    # 在 "my-app-ns" 命名空间中应用配置文件
    kubectl apply -f my-deployment.yaml -n my-app-ns

    # 查看 "my-app-ns" 中的所有 Pods
    kubectl get pods -n my-app-ns
    ```
-   **在 YAML 中指定**:
    在资源的 `metadata` 部分添加 `namespace` 字段。
    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nginx-deployment
      namespace: my-app-ns # 指定 Namespace
    spec:
      # ...
    ```

### 3. 设置默认 Namespace

频繁地使用 `-n` 标志会很繁琐。你可以设置当前上下文的默认 Namespace。
```bash
# 将当前上下文的默认 Namespace 设置为 "my-app-ns"
kubectl config set-context --current --namespace=my-app-ns

# 此后，所有 kubectl 命令将默认在此 Namespace 中执行
kubectl get pods # 这等同于 kubectl get pods -n my-app-ns
```

## Namespace 的作用域

需要注意的是，**并非所有 Kubernetes 对象都属于 Namespace**。

-   **命名空间作用域 (Namespaced)**: 大多数面向用户的资源都属于某个 Namespace。
    -   **工作负载**: `Pod`, `Deployment`, `ReplicaSet`, `StatefulSet`, `Job` 等。
    -   **服务与网络**: `Service`, `Ingress`, `Endpoint` 等。
    -   **配置与存储**: `ConfigMap`, `Secret`, `PersistentVolumeClaim` 等。
-   **集群作用域 (Cluster-scoped)**: 这些资源是全局的，不属于任何特定的 Namespace。
    -   `Node`: 节点是整个集群的物理资源。
    -   `Namespace`: Namespace 本身是集群级别的资源。
    -   `PersistentVolume`: 持久化卷是集群级别的存储资源。
    -   `StorageClass`: 定义存储类型的资源。
    -   `ClusterRole`, `ClusterRoleBinding`: 集群级别的权限控制。

你可以用以下命令来查看一个资源类型是否是命名空间作用域的：
```bash
kubectl api-resources --namespaced=true  # 查看所有命名空间作用域的资源
kubectl api-resources --namespaced=false # 查看所有集群作用域的资源
```

## 跨 Namespace 通信

默认情况下，所有 Pod 都可以与任何其他 Namespace 中的 Pod 和 Service 通信（除非设置了 `NetworkPolicy`）。

要访问另一个 Namespace 中的 Service，你需要使用其**完全限定域名 (FQDN)**：
`<service-name>.<namespace-name>.svc.cluster.local`

例如，一个在 `frontend` 命名空间中的 Pod 要访问 `backend` 命名空间中名为 `api-svc` 的 Service，它应该使用 `api-svc.backend.svc.cluster.local` 这个地址。在大多数 DNS 配置下，`api-svc.backend` 也足够了。

## Namespace 与资源配额 (ResourceQuota)

Namespace 的一个强大功能是与 `ResourceQuota` 结合使用。管理员可以创建一个 `ResourceQuota` 对象，来限制一个 Namespace 中可以：
-   创建的资源**数量**（例如，最多 10 个 Pod，20 个 Service）。
-   消耗的**计算资源总量**（例如，总共不超过 10 CPU核心，20Gi 内存）。

这对于在多租户环境中控制资源消耗、防止"吵闹的邻居"问题至关重要。

通过合理使用 Namespace，你可以将一个庞大的物理集群，划分成多个逻辑上隔离、易于管理、安全可控的子单元。 