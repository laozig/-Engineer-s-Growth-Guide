# 5. Deployments：声明式应用管理

在上一章我们了解到，Pod 是短暂的，并且其核心配置是不可变的。如果一个 Pod 所在的节点宕机，Pod 就会消失。如果需要更新应用，必须销毁旧 Pod 并创建新 Pod。手动执行这些操作是不可靠且极其繁琐的。

这就是为什么我们需要 `Deployment`。在实际生产中，你几乎永远不会直接创建独立的 Pod。相反，你会通过 `Deployment` 这样的控制器来管理它们。

## 什么是 Deployment？

`Deployment` 是一个 Kubernetes API 对象，它为你提供了一种**声明式**的方式来管理 Pod 和 ReplicaSet。

你只需要在一个 `Deployment` 对象中描述你应用的**期望状态**，例如：
-   "我希望运行 3 个 `nginx:1.25` 的副本。"
-   "我希望将应用从版本 `1.0` 更新到 `2.0`，并且在更新过程中服务不能中断。"

`Deployment` 控制器会持续工作，确保集群的**实际状态**与你的**期望状态**保持一致。

**Deployment 的核心职责**:
1.  **管理 Pod 副本**: 确保在任何时候都有指定数量的 Pod 副本在运行。如果一个 Pod 挂了，它会自动创建一个新的来替代。
2.  **管理应用发布**: 控制应用更新的过程，支持**滚动更新 (Rolling Update)** 等策略，实现零停机发布。
3.  **支持回滚**: 如果新版本的应用出现问题，可以轻松地回滚到之前的某个稳定版本。

## Deployment 的 YAML 定义

让我们把上一章的 Nginx Pod 转换为一个 Deployment。

`nginx-deployment.yaml`:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx-app
  template:
    metadata:
      labels:
        app: nginx-app
    spec:
      containers:
      - name: nginx
        image: nginx:1.25
        ports:
        - containerPort: 80
```

让我们分解这个 YAML 文件：
-   `apiVersion`: 对于 Deployment，我们使用 `apps/v1` API 组。
-   `kind`: `Deployment`。
-   `spec`: Deployment 的期望状态。
    -   `replicas`: **期望的 Pod 副本数量**。这里是 3。
    -   `selector`: **选择器**。Deployment 需要知道要管理哪些 Pod。`matchLabels` 字段定义了一组标签（`app: nginx-app`），任何拥有这个标签的 Pod 都被视为是这个 Deployment 的一部分。
    -   `template`: **Pod 模板**。这部分是 Deployment 创建新 Pod 时使用的蓝图。
        -   `metadata.labels`: **模板中的标签必须与 `selector.matchLabels` 匹配**，否则 Deployment 会创建失败。
        -   `spec`: 这部分就是我们熟悉的 Pod `spec`，定义了要在 Pod 中运行的容器。

## Deployment, ReplicaSet 和 Pod 的关系

`Deployment` 自身并不直接管理 Pod。它通过一个中间层 `ReplicaSet` 来完成这个工作。它们的关系是：
-   一个 `Deployment` 负责管理一个或多个 `ReplicaSet`。
-   一个 `ReplicaSet` 负责根据其模板管理一组 Pod 副本，确保数量正确。

当你创建一个 `Deployment` 时，它会自动创建一个 `ReplicaSet`。这个 `ReplicaSet` 再去创建指定数量的 Pod。

当你**更新** `Deployment`（例如，修改容器镜像版本）时，神奇的事情发生了：
1.  `Deployment` 会创建一个**新的 `ReplicaSet`**，这个新的 `ReplicaSet` 使用新的 Pod 模板。
2.  `Deployment` 开始按照指定的更新策略（默认为滚动更新），逐渐增加新 `ReplicaSet` 的 Pod 数量。
3.  同时，它会逐渐减少旧 `ReplicaSet` 的 Pod 数量。
4.  当所有新 Pod 都已就绪，并且所有旧 Pod 都已销毁后，更新完成。旧的 `ReplicaSet` 仍然被保留，以便未来可能的回滚操作。

![Deployment-ReplicaSet-Pod-Relation](https://i.imgur.com/your-dep-rs-pod-image.png) <!-- 你需要替换成真实的图片链接 -->

## 核心功能：滚动更新 (Rolling Update)

滚动更新是 `Deployment` 的默认发布策略，它能实现**零停机时间**的应用升级。

你可以通过 `spec.strategy` 字段来微调更新过程。
```yaml
spec:
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 25%
      maxSurge: 25%
```
-   `maxUnavailable`: 在更新过程中，允许的**不可用 Pod 的最大比例或数量**。例如，如果 `replicas` 为 4，`maxUnavailable` 为 25%，那么 Kubernetes 会确保在任何时候都至少有 3 (4 - 4*0.25) 个 Pod 可用。
-   `maxSurge`: 在更新过程中，允许的**超出期望副本数的最大 Pod 比例或数量**。例如，如果 `replicas` 为 4，`maxSurge` 为 25%，那么 Kubernetes 在更新时最多可以创建 1 (4*0.25) 个新 Pod，使得总 Pod 数一度达到 5。

这两个参数共同决定了更新的速度和资源消耗。

## 回滚操作

如果新版本的部署出了问题，你可以快速回滚。

```bash
# 更新 Deployment 的镜像到一个不存在的版本，模拟一次失败的发布
kubectl set image deployment/nginx-deployment nginx=nginx:1.99.9

# 查看发布状态，会发现它卡住了
kubectl rollout status deployment/nginx-deployment

# 查看发布历史
kubectl rollout history deployment/nginx-deployment
# REVISION  CHANGE-CAUSE
# 1         <none>
# 2         <none>

# 回滚到上一个版本 (即 revision 1)
kubectl rollout undo deployment/nginx-deployment

# 再次检查状态，应用已恢复
kubectl rollout status deployment/nginx-deployment
```
`Deployment` 是管理无状态应用（如 Web 服务器、API 后端）的首选方式。它将 Pod 的管理自动化，让我们能够专注于应用本身，而不是底层的运维细节。 