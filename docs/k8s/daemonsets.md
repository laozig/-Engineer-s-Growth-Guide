# 15. DaemonSets：在每个节点运行 Pod

在 Kubernetes 中，我们通常不关心 Pod 具体运行在哪个节点上，这是由调度器决定的。但某些特定的场景下，我们恰恰需要**在集群的每一个（或指定的某一些）节点上都运行且只运行一个 Pod 副本**。

这些典型的"节点级"应用包括：
-   **日志收集器**: 如 Fluentd, Logstash, Filebeat，它们需要从每个节点收集容器日志。
-   **节点监控代理**: 如 Prometheus Node Exporter, Datadog Agent，它们需要采集每个节点的性能指标（CPU, 内存, 网络）。
-   **网络和存储插件**: 很多 CNI 插件（如 Calico, Flannel）和存储插件都需要在每个节点上运行一个代理进程来管理网络路由或存储卷。

对于这种"一个节点一个副本"的需求，`Deployment` 或 `StatefulSet` 都不适用。为此，Kubernetes 提供了 `DaemonSet`。

## 什么是 DaemonSet？

`DaemonSet` 是一种工作负载资源，它确保**所有（或一部分）符合条件的节点上都运行一个指定的 Pod 副本**。

`DaemonSet` 控制器的工作逻辑很简单：
-   它会持续监控集群中的节点列表。
-   当一个**新的节点加入**集群并且符合 `DaemonSet` 的调度要求时，`DaemonSet` 会自动在该节点上创建一个 Pod。
-   当一个**节点从集群中被移除**时，`DaemonSet` 会自动清理掉该节点上的对应 Pod。
-   当一个 `DaemonSet` 被删除时，它创建的所有 Pod 也会被一并删除。

你可以把它看作是 Kubernetes 里的"守护进程"管理器。

## DaemonSet 的 YAML 定义

`DaemonSet` 的 YAML 结构与 `Deployment` 非常相似，主要的区别在于它**没有 `replicas` 字段**。因为它的副本数是由符合条件的节点数量动态决定的。

`fluentd-daemonset.yaml`:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd-log-collector
  namespace: kube-system # 系统级插件通常放在 kube-system 命名空间
  labels:
    k8s-app: fluentd-logging
spec:
  selector:
    matchLabels:
      name: fluentd-es
  template:
    metadata:
      labels:
        name: fluentd-es
    spec:
      tolerations: # 1. 容忍节点的 "污点"
      - key: node-role.kubernetes.io/control-plane
        operator: Exists
        effect: NoSchedule
      containers:
      - name: fluentd
        image: fluent/fluentd-kubernetes-daemonset:v1
        resources:
          limits:
            memory: 200Mi
          requests:
            cpu: 100m
            memory: 200Mi
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
      volumes:
      - name: varlog
        hostPath: # DaemonSet 经常与 hostPath 配合使用
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
```

### 在特定节点上运行 DaemonSet

默认情况下，`DaemonSet` 会在集群的**所有**节点上创建 Pod。但你可以通过标准的节点亲和性/选择性机制来限制它运行的范围。

-   **`spec.template.spec.nodeSelector`**:
    只在拥有特定标签的节点上运行。
    ```yaml
    # ...
    spec:
      template:
        spec:
          nodeSelector:
            disktype: ssd # 只在带有 "disktype=ssd" 标签的节点上运行
          # ...
    ```
-   **`spec.template.spec.affinity`**:
    使用更复杂的节点亲和性规则。
-   **`spec.template.spec.tolerations`**:
    如上面的例子所示，`DaemonSet` 通常需要添加对主节点"污点 (Taints)"的"容忍 (Tolerations)"，以确保它们也能在主节点上运行。

## DaemonSet 的更新策略

`DaemonSet` 支持两种更新策略，通过 `spec.updateStrategy.type` 字段指定：

1.  **`RollingUpdate` (默认)**:
    -   这是推荐的策略，与 `Deployment` 的滚动更新类似。
    -   当你更新 `DaemonSet` 的模板时，它会逐个节点地删除旧的 Pod 并创建新的 Pod。
    -   你可以通过 `spec.updateStrategy.rollingUpdate.maxUnavailable` (默认为 1) 来控制在更新过程中同时可以有多少个 Pod 不可用。

2.  **`OnDelete`**:
    -   使用此策略时，更新 `DaemonSet` 模板不会自动触发任何变更。
    -   只有当你**手动删除**一个旧的 `DaemonSet` Pod 后，控制器才会用新的模板创建一个新的 Pod 来替代它。
    -   这种策略为你提供了手动控制更新过程的能力，适用于需要精细操作的场景。

## DaemonSet vs. Deployment

| 特性 | DaemonSet | Deployment |
| :--- | :--- | :--- |
| **核心目标** | **节点覆盖率**：确保每个节点上都有一个副本 | **总副本数**：确保集群中有指定数量的副本 |
| **副本数** | 由符合条件的节点数决定 | 由 `replicas` 字段明确指定 |
| **调度** | 忽略节点的不可调度状态 (`unschedulable`) | 尊重节点的不可调度状态 |
| **适用场景** | 节点级的代理、监控、日志收集 | 无状态的应用服务（Web, API）|

`DaemonSet` 是构建健壮的、可观测的 Kubernetes 集群不可或缺的一部分。通过它，我们可以轻松地将基础服务部署到集群的每一个角落。 