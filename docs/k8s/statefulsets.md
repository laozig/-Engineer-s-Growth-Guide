# 14. StatefulSets：管理有状态应用

到目前为止，我们学习的 `Deployment` 非常适合管理**无状态应用**（stateless applications），如 Web 前端、API 服务等。这些应用的特点是，每一个 Pod 副本都是完全相同的、可互换的。我们可以随意地创建、销毁和替换它们，而不会影响应用的整体功能。

但对于**有状态应用**（stateful applications）——如数据库 (MySQL, Zookeeper, etcd)、消息队列或任何需要持久化自身状态的应用——`Deployment` 的模型就不够用了。有状态应用通常需要：
1.  **稳定的、唯一的网络标识符**: 每个副本需要一个固定的、可预测的名称，以便其他副本可以找到它。
2.  **稳定的、持久的存储**: 每个副本都需要自己独立的存储空间，并且在重启后能重新连接到同一个存储。
3.  **有序的部署、伸缩和更新**: 副本的创建、删除和更新必须遵循严格的顺序。例如，在数据库集群中，主节点必须先启动，然后备用节点才能加入。

为了满足这些复杂的需求，Kubernetes 提供了 `StatefulSet`。

## StatefulSet 的核心保证

`StatefulSet` 为其管理的每个 Pod 提供以下几个关键保证：

-   **稳定的、唯一的网络标识符**:
    -   `StatefulSet` 中的每个 Pod 都会得到一个包含序号的、固定的主机名。格式为 `<statefulset-name>-<ordinal-index>`。例如，一个名为 `web` 的 `StatefulSet` 会创建名为 `web-0`, `web-1`, `web-2` 的 Pods。
    -   这个名称在 Pod 的整个生命周期中保持不变，即使它被调度到不同的节点。

-   **稳定的、持久的存储**:
    -   `StatefulSet` 可以使用 `volumeClaimTemplates` 为每个 Pod 自动创建一个对应的 `PersistentVolumeClaim` (PVC)。
    -   这个 PVC 的名称也是固定的 (`<volume-name>-<statefulset-name>-<ordinal-index>`)。
    -   这意味着 `web-0` 将永远绑定到 `data-volume-web-0` 这个 PVC，`web-1` 永远绑定到 `data-volume-web-1`，以此类推。当 Pod 重启或重新调度时，它会重新挂载回属于它自己的那块持久化存储。

-   **有序的部署和伸缩**:
    -   **部署 (Scaling Up)**: 当你创建一个有 N 个副本的 `StatefulSet` 时，Pods 会严格按照 `0, 1, 2, ..., N-1` 的顺序逐个创建。只有当 `web-0` 达到 Running 和 Ready 状态后，`web-1` 才会被创建。
    -   **缩容 (Scaling Down)**: 当你缩减副本数时，Pods 会严格按照 `N-1, N-2, ..., 0` 的逆序逐个删除。只有当 `web-2` 完全终止后，`web-1` 才会被删除。

-   **有序的滚动更新**:
    -   当你更新 `StatefulSet` 的 Pod 模板（例如，修改容器镜像）时，更新也是按照**逆序**进行的。Pod 会被逐个删除并以新版本重建，顺序为 `N-1, N-2, ..., 0`。这确保了集群的整体可用性，特别是在主从架构中。

## Headless Service

`StatefulSet` 的稳定网络标识符依赖于一个特殊的 `Service`——**Headless Service (无头服务)**。

一个 Headless Service 是一个 `clusterIP` 被明确设置为 `None` 的普通 `Service`。与普通 `Service` 不同，它**没有自己的 ClusterIP**，也不会做负载均衡。

当 DNS 查询一个 Headless Service 时，它不会返回 `Service` 的 IP，而是会直接返回其**后端所有 Pods 的 IP 地址列表**。

更重要的是，对于 `StatefulSet`，它还会为每个 Pod 创建一个固定的 DNS A 记录，格式为：
`pod-name.service-name.namespace.svc.cluster.local`

例如，`web-0.my-headless-svc.my-ns.svc.cluster.local` 会永远解析到 `web-0` 这个 Pod 的 IP 地址。这使得 Pod 之间可以通过一个可预测的 DNS 名称相互发现。

## StatefulSet 的 YAML 定义

一个典型的 `StatefulSet` YAML 包含三个部分：`StatefulSet` 本身，用于存储的 `volumeClaimTemplates`，以及用于网络发现的 `Headless Service`。

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-headless-svc # 1. Headless Service
  labels:
    app: nginx
spec:
  ports:
  - port: 80
    name: web
  clusterIP: None # 关键：设置为 None
  selector:
    app: nginx

---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: nginx
  serviceName: "nginx-headless-svc" # 2. 必须指向上面定义的 Headless Service
  replicas: 3
  template: # Pod 模板，与 Deployment 类似
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: registry.k8s.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www-storage
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates: # 3. PVC 模板
  - metadata:
      name: www-storage
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "standard-ssd" # 假设已有名为 standard-ssd 的 StorageClass
      resources:
        requests:
          storage: 1Gi
```
**剖析**:
1.  **Headless Service**: `clusterIP: None` 使其成为 Headless Service。它的 `selector` (`app: nginx`) 必须与 `StatefulSet` 的 `selector` 匹配。
2.  **`serviceName`**: 在 `StatefulSet` 的 `spec` 中，`serviceName` 字段必须指向这个 Headless Service 的名称。这是将两者关联起来的关键。
3.  **`volumeClaimTemplates`**: 这是 `StatefulSet` 的核心。
    -   它是一个 PVC 的模板列表。
    -   对于 `replicas: 3`，`StatefulSet` 会创建 3 个 PVC：`www-storage-web-0`, `www-storage-web-1`, `www-storage-web-2`。
    -   每个 PVC 都会根据模板的 `spec` 请求一个 1Gi 的、由 `standard-ssd` `StorageClass` 提供的持久化卷。

`StatefulSet` 是一个非常强大的工具，但它也比 `Deployment` 更复杂。只有当你的应用确实需要 `StatefulSet` 提供的稳定标识符和有序性保证时，才应该使用它。对于绝大多数无状态应用，`Deployment` 仍然是最佳选择。 