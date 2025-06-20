# 7. Namespaces：集群资源隔离

随着你在 Kubernetes 中部署的应用越来越多，如何组织和管理这些资源就成了一个挑战。Kubernetes 提供了 **Namespace** 这一核心功能，用于实现多租户和资源隔离。

## 7.1 什么是 Namespace？

你可以将 Namespace 想象成在同一个物理集群之上构建的多个**虚拟集群**。它为资源名称提供了一个作用域，从而允许你在不同 Namespace 中创建同名的资源而不会发生冲突。

**主要用途**：
- **资源隔离**：将一个物理集群划分为多个逻辑单元，供不同的团队、项目或环境（如开发、测试、生产）使用。
- **访问控制**：结合 RBAC（基于角色的访问控制），可以限制用户只能访问其被授权的 Namespace 中的资源。
- **资源配额**：可以为每个 Namespace 设置资源配额（ResourceQuota），限制其可以使用的计算资源总量（如 CPU、内存）或对象数量。
- **避免命名冲突**：不同团队可以独立地命名自己的应用，无需担心与其他团队的命名冲突。

## 7.2 默认的 Namespaces

一个全新的 Kubernetes 集群会自带几个默认的 Namespace：

- **`default`**: 如果你在创建资源时没有指定 Namespace，那么这些资源会自动被创建在这个 Namespace 中。它是你日常操作的默认工作空间。
- **`kube-system`**: 用于存放 Kubernetes 系统自身组件的资源，如 API Server、Scheduler、kube-proxy 等。**不要**轻易修改或删除这个 Namespace 下的任何资源。
- **`kube-public`**: 一个特殊的 Namespace，所有用户（包括未经身份验证的）都可以读取其中的资源。通常用于存放一些需要对整个集群可见的公共信息，如集群版本等。
- **`kube-node-lease`**: 用于存放与节点心跳相关的 Lease 对象，以提升大规模集群的性能。

## 7.3 如何管理 Namespace

### 创建 Namespace

**命令式创建**:
```bash
kubectl create namespace development
```

**声明式创建 (YAML)**:
`development-ns.yaml`:
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: development
```
然后执行 `kubectl apply -f development-ns.yaml`。

### 查看 Namespace

```bash
# 列出所有 Namespace
kubectl get namespaces

# 查看特定 Namespace 的详细信息
kubectl describe namespace development
```

### 在特定 Namespace 中操作

要在特定的 Namespace 中创建或查询资源，你需要使用 `-n` 或 `--namespace` 标志。

```bash
# 在 'development' Namespace 中创建一个 nginx Pod
kubectl apply -f nginx-pod.yaml -n development

# 查看 'development' Namespace 中的所有 Pod
kubectl get pods -n development

# 查看所有 Namespace 中的所有 Pod
kubectl get pods --all-namespaces
```

### 切换默认 Namespace

频繁使用 `-n` 标志会很繁琐。你可以更改 `kubectl` 的当前上下文，使其默认在指定的 Namespace 中操作。

```bash
# 将当前上下文的默认 Namespace 切换到 'development'
kubectl config set-context --current --namespace=development

# 现在，所有命令都将默认在 'development' 中执行
kubectl get pods
```

**别忘了切换回来！** 当你完成在 `development` 中的操作后，记得切换回 `default` 或其他你需要的 Namespace。
```bash
kubectl config set-context --current --namespace=default
```

### 删除 Namespace

```bash
kubectl delete namespace development
```
**警告**：删除一个 Namespace 将会**级联删除**该 Namespace 中的**所有资源**（Pod, Service, Deployment 等）。这是一个破坏性极大的操作，请务务必谨慎！

## 7.4 Namespace 与 DNS

当你在一个 Namespace 中创建一个 Service（例如，`my-service` 在 `development` 中），Kubernetes 会自动为其创建一个 DNS A 记录。

完整的 DNS 名称格式为：`<service-name>.<namespace-name>.svc.cluster.local`。

- 在同一个 Namespace (`development`) 内的 Pod，可以直接通过服务名 (`my-service`) 访问。
- 在不同 Namespace（例如 `production`）的 Pod，必须使用完整的 FQDN (`my-service.development`) 来访问。

这种机制确保了服务在 Namespace 内部的简洁访问，同时又提供了跨 Namespace 通信的明确路径。

## 7.5 总结

Namespace 是 Kubernetes 实现多租户和逻辑隔离的基石。通过将资源划分到不同的 Namespace，我们可以有效地组织应用、控制访问权限和分配资源配额。熟练使用 Namespace 是管理复杂 Kubernetes 集群的必备技能。

至此，我们完成了对 Kubernetes 核心工作负载的学习。在接下来的部分，我们将探讨如何通过 ConfigMap 和 Secret 来管理应用的配置和敏感数据。