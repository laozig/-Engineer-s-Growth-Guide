# 14. StatefulSets：管理有状态应用

到目前为止，我们学习的 `Deployment` 非常适合管理无状态应用。对于无状态应用来说，所有的 Pod 副本都是完全相同的、可互换的。但对于数据库、消息队列等**有状态应用**，我们需要更强的保障。

有状态应用的核心需求：
- **稳定的、唯一的网络标识**：Pod 重启后主机名和 DNS 记录保持不变。
- **稳定的、持久的存储**：Pod 重启后能重新挂载到之前使用的同一块存储卷。
- **有序的、优雅的部署和伸缩**：Pod 必须按照固定的顺序（0, 1, 2...）来创建和销毁。
- **有序的、自动化的滚动更新**：更新时也必须遵循固定的逆序（n-1, n-2, ...0）进行。

为了满足这些苛刻的要求，Kubernetes 提供了 `StatefulSet`。

## 14.1 StatefulSet vs. Deployment

| 特性 | Deployment | StatefulSet |
| :--- | :--- | :--- |
| **Pod 身份** | 随机、可互换 | 稳定、唯一 (`<name>-0`, `<name>-1`) |
| **存储** | 共享同一个 PVC (如果需要) | 每个 Pod 拥有自己独立的 PVC |
| **网络** | 共享一个 Service IP | 每个 Pod 拥有独立的 DNS 记录 |
| **部署/伸缩** | 并行、无序 | 有序 (0 -> N-1) |
| **更新/删除** | 并行、无序 | 有序 (N-1 -> 0) |

## 14.2 StatefulSet 的核心组件

StatefulSet 的神奇之处在于它巧妙地结合了其他几个 Kubernetes 对象来实现其功能。

### 1. Headless Service
- 与普通 Service 不同，Headless Service 不提供负载均衡和单一的 ClusterIP。通过将 `spec.clusterIP` 设置为 `None` 来创建。
- 它的唯一作用是为 StatefulSet 管理的**每个 Pod** 创建一个独立的、稳定的 DNS A 记录。
- DNS 记录的格式为：`pod-name.headless-service-name.namespace.svc.cluster.local`。
- 例如，名为 `my-db-0` 的 Pod 可以通过 `my-db-0.mysql.default.svc.cluster.local` 这个固定的地址被访问。这为有状态应用提供了点对点的稳定网络标识。

### 2. volumeClaimTemplates
- 这是 StatefulSet `spec` 中的一个关键字段，它是一个 PVC 的模板。
- 当 StatefulSet 创建一个新的 Pod（如 `my-db-0`）时，它会使用这个模板**为该 Pod 动态地创建一个专属的 PVC**（如 `data-my-db-0`）。
- 当这个 Pod 挂掉并被重新调度时，它会**重新挂载到这个完全相同的 PVC**，从而保证了数据的持久性和稳定性。

## 14.3 如何定义一个 StatefulSet (YAML)

下面是一个部署 Zookeeper 集群的 StatefulSet 示例。

`zookeeper-statefulset.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: zk-headless
spec:
  # 1. 定义 Headless Service
  clusterIP: None
  selector:
    app: zookeeper
  ports:
  - port: 2181
    name: client
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: zk
spec:
  serviceName: "zk-headless" # 必须与 Headless Service 的名称匹配
  replicas: 3
  selector:
    matchLabels:
      app: zookeeper
  template: # Pod 模板
    metadata:
      labels:
        app: zookeeper
    spec:
      containers:
      - name: zookeeper
        image: k8s.gcr.io/zookeeper:3.4.10
        ports:
        - containerPort: 2181
          name: client
        volumeMounts:
        - name: data
          mountPath: /var/lib/zookeeper
  # 2. 定义 PVC 模板
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "my-storage-class" # 需要一个支持动态配置的 StorageClass
      resources:
        requests:
          storage: 1Gi
```

**分析**：
1.  我们首先创建了一个名为 `zk-headless` 的 Headless Service。
2.  然后创建了一个名为 `zk` 的 StatefulSet，并通过 `serviceName` 字段与 Headless Service 关联。
3.  `replicas: 3` 会创建三个 Pod：`zk-0`, `zk-1`, `zk-2`。
4.  `volumeClaimTemplates` 会为每个 Pod 创建一个独立的 PVC：`data-zk-0`, `data-zk-1`, `data-zk-2`。
5.  每个 Pod 都会有自己唯一的 DNS 记录，如 `zk-0.zk-headless.default.svc.cluster.local`。

## 14.4 有序操作

- **部署**：StatefulSet 会先创建 `zk-0`，等待它完全启动并进入 `Ready` 状态后，再开始创建 `zk-1`，以此类推。
- **缩容**：如果要将副本从 3 缩减到 2 (`kubectl scale statefulset zk --replicas=2`)，StatefulSet 会先优雅地终止 `zk-2`，完成后再考虑其他操作。它会保留 `zk-2` 对应的 PVC，以便将来扩容时可以重用。
- **滚动更新**：当你更新 Pod 模板（例如，更换镜像）时，StatefulSet 会以**逆序**（`zk-2`, `zk-1`, `zk-0`）逐个更新 Pod。它会先删除并重建 `zk-2`，等待其 `Ready` 后，再继续更新 `zk-1`。这种方式可以最大限度地保证集群的可用性（例如，对于有主从关系的数据库，先更新从节点）。

## 14.5 总结

StatefulSet 是 Kubernetes 中用于管理有状态应用（如数据库、分布式文件系统、消息队列等）的终极武器。它通过提供稳定的网络标识、独立的持久化存储以及严格的有序性保证，解决了有状态应用在容器化环境中面临的核心挑战。

虽然 StatefulSet 的概念比 Deployment 更复杂，但它是运行生产级有状态服务的关键。在下一章，我们将学习另一种特殊的工作负载类型：`DaemonSet`。