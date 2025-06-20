# 5. Deployments：声明式应用管理

在上一章，我们学习了 Pod。但直接管理 Pod 是非常繁琐且不可靠的。在真实世界中，我们需要一个更高级别的控制器来管理 Pod 的生命周期。这就是 **Deployment** 的用武之地。

## 5.1 什么是 Deployment？

**Deployment** 是 Kubernetes 中用于管理**无状态应用**的核心资源对象。它提供了一种声明式的方式来定义应用的最终状态，并负责在后台创建、更新和维护指定数量的 Pod 副本。

Deployment 的主要职责：
- **定义期望的 Pod 模板**：你告诉 Deployment 你想运行什么样的 Pod（镜像、端口、配置等）。
- **管理副本数量 (`replicas`)**：确保集群中始终运行着指定数量的 Pod 实例。如果一个 Pod 挂了，Deployment 会自动创建一个新的来替代它。
- **提供滚动更新策略**：安全地将应用从一个版本更新到另一个版本，无需停机。
- **支持回滚**：如果新版本出现问题，可以一键回滚到之前的稳定版本。

简单来说，你只需要告诉 Deployment "我想要3个运行着 `nginx:1.14.2` 的 Pod"，Deployment 就会为你搞定一切。

## 5.2 Deployment, ReplicaSet 和 Pod 的关系

当你创建一个 Deployment 时，它并不会直接管理 Pod。相反，它会创建一个名为 **ReplicaSet** 的中间资源。

- **Deployment**: 负责管理 ReplicaSet，处理版本更新和回滚策略。
- **ReplicaSet**: 负责确保指定数量的 Pod 副本正在运行。
- **Pod**: 由 ReplicaSet 创建和管理的实际工作单元。

关系如下：
`Deployment` -> 管理 -> `ReplicaSet` -> 管理 -> `Pod`, `Pod`, `Pod`...

这种分层设计使得版本更新变得非常清晰。当执行滚动更新时，Deployment 会创建一个新的 ReplicaSet（对应新版本），并逐渐增加新 ReplicaSet 的 Pod 数量，同时减少旧 ReplicaSet 的 Pod 数量，直到更新完成。

<div align="center">
  <img src="https://i.imgur.com/gTG9z7R.png" alt="Deployment, ReplicaSet, and Pod relationship" width="700">
</div>

## 5.3 如何定义一个 Deployment (YAML)

下面是一个典型的 Deployment YAML 文件，它将部署3个 Nginx Pod。

**`nginx-deployment.yaml`**:
```yaml
# API 版本，对于 Deployment 来说是 apps/v1
apiVersion: apps/v1
# 资源类型
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  # 期望的 Pod 副本数量
  replicas: 3
  # 选择器，用于找到该 Deployment 管理的 Pod
  selector:
    matchLabels:
      app: nginx
  # Pod 模板，用于创建新的 Pod
  template:
    metadata:
      # Pod 的标签，必须与上面的 selector 匹配
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
```

**关键字段解释**：
- `apiVersion`: 对于 Deployment，我们使用 `apps/v1`。
- `spec.replicas`: 定义了期望的 Pod 数量，这里是3个。
- `spec.selector`: Deployment 通过这个**标签选择器**来识别它应该管理哪些 Pod。
- `spec.template`: 这是 Pod 的定义模板，与我们上一章学习的 Pod 定义几乎一样。
  - `template.metadata.labels`: Pod 模板中的标签**必须**与 `spec.selector.matchLabels` 中的标签匹配，这样 Deployment 才能正确地找到并管理它创建的 Pod。

## 5.4 Deployment 的管理操作 (`kubectl`)

**创建 Deployment**:
```bash
kubectl apply -f nginx-deployment.yaml
```

**查看 Deployment 状态**:
```bash
# 列出所有 Deployment
kubectl get deployments

# 查看 nginx-deployment 的详细信息
kubectl describe deployment nginx-deployment
```

**扩缩容**:
```bash
# 将副本数扩展到 5 个
kubectl scale deployment nginx-deployment --replicas=5
```

**更新镜像 (滚动更新)**:
```bash
# 将 nginx 容器的镜像更新到 1.16.1
kubectl set image deployment/nginx-deployment nginx=nginx:1.16.1

# 监控滚动更新的状态
kubectl rollout status deployment/nginx-deployment
```

**回滚更新**:
```bash
# 查看更新历史
kubectl rollout history deployment/nginx-deployment

# 回滚到上一个版本
kubectl rollout undo deployment/nginx-deployment
```

**删除 Deployment**:
```bash
kubectl delete deployment nginx-deployment
```
删除 Deployment 会级联删除它所管理的 ReplicaSet 和 Pod。

## 5.5 总结

Deployment 是 Kubernetes 中管理无状态应用最常用、最重要的工具。它通过管理 ReplicaSet 来保证 Pod 的高可用性，并提供了强大的滚动更新和回滚机制，极大地简化了应用发布的复杂性。

在接下来的章节中，我们将学习如何通过 **Service** 将我们的 Deployment 暴露给外部访问。
