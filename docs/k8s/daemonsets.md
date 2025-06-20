# 15. DaemonSets：在每个节点运行 Pod

在某些场景下，我们希望确保集群中的**每个（或某些）节点**上都运行且只运行一个特定的 Pod 副本。例如：
- **日志收集**: 在每个节点上运行一个如 Fluentd 或 Logstash 的日志收集代理。
- **节点监控**: 在每个节点上运行一个如 Prometheus Node Exporter 或 Datadog Agent 的监控代理。
- **网络插件**: 某些 CNI 网络插件（如 Calico, Cilium）需要在每个节点上运行一个代理 Pod。
- **节点存储**: 如 GlusterFS 或 Ceph 等存储守护进程需要在每个节点上运行。

对于这类需求，使用 `Deployment` 是不合适的，因为它无法保证 Pod 在节点间的均匀分布。Kubernetes 为此提供了专门的控制器：**DaemonSet**。

## 15.1 什么是 DaemonSet？

**DaemonSet** 是一个 Kubernetes 工作负载对象，它能确保所有（或一部分）符合条件的节点上都运行一个指定的 Pod 副本。

**核心特性**：
- **节点覆盖**：当有新的节点加入集群时，DaemonSet 会自动在该节点上创建一个新的 Pod。当节点被移除时，对应的 Pod 会被垃圾回收。
- **节点选择**：可以通过 `nodeSelector` 或 `affinity` 来指定 DaemonSet 只在特定的节点子集上运行 Pod（例如，只在带有 SSD 硬盘的节点上运行存储守护进程）。
- **一一对应**：DaemonSet 保证每个符合条件的节点上**最多只有一个**它所管理的 Pod。

可以把 DaemonSet 理解为节点的"守护进程"管理器。

## 15.2 DaemonSet vs. Deployment

| 特性 | Deployment | DaemonSet |
| :--- | :--- | :--- |
| **副本控制** | `replicas` 字段控制 Pod 总数 | 无 `replicas` 字段，副本数由符合条件的节点数决定 |
| **调度目标** | 将 Pod 调度到**任何可用**的节点 | 将 Pod 调度到**每个符合条件**的节点 |
| **主要用途** | 部署无状态或有状态应用 | 部署节点级别的代理或守护进程 |

## 15.3 如何定义一个 DaemonSet (YAML)

DaemonSet 的 YAML 定义与 Deployment 非常相似，主要区别在于**没有 `replicas` 字段**。

下面是一个部署 Fluentd 日志收集代理的 DaemonSet 示例。

`fluentd-daemonset.yaml`:
```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: fluentd-logging
  labels:
    app: fluentd
spec:
  # 1. 选择器，用于关联 Pod
  selector:
    matchLabels:
      name: fluentd-es
  # 2. Pod 模板
  template:
    metadata:
      labels:
        name: fluentd-es
    spec:
      # 容忍所有污点，确保能在 master 节点上也运行
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      containers:
      - name: fluentd-es
        image: fluent/fluentd-kubernetes-daemonset:v1.4.2-debian-elasticsearch-1.1
        # 挂载宿主机的 /var/log 目录来收集日志
        volumeMounts:
        - name: varlog
          mountPath: /var/log
        # 挂载宿主机的容器日志目录
        - name: varlibdockercontainers
          mountPath: /var/lib/docker/containers
          readOnly: true
      # 终止 Pod 前的宽限期
      terminationGracePeriodSeconds: 30
      volumes:
      - name: varlog
        hostPath:
          path: /var/log
      - name: varlibdockercontainers
        hostPath:
          path: /var/lib/docker/containers
```

**分析**：
- 这个 DaemonSet 会在集群的**每一个节点**（包括 Master 节点，因为我们添加了相应的 `tolerations`）上都部署一个 Fluentd Pod。
- 每个 Pod 都会使用 `hostPath` 卷来挂载该节点上的 `/var/log` 和 `/var/lib/docker/containers` 目录，从而能访问到该节点上所有容器的日志文件。

## 15.4 更新 DaemonSet

DaemonSet 支持与 Deployment 类似的滚动更新策略。

**`spec.updateStrategy`**:
- **`RollingUpdate`** (默认): 当你更新 Pod 模板时，DaemonSet 会逐个节点地删除旧的 Pod 并创建新的 Pod。你可以通过 `maxUnavailable` (默认为1) 来控制同一时间最多有多少个 Pod 可以处于不可用状态。
- **`OnDelete`**: 更新 Pod 模板后，只有当你手动删除旧的 Pod 时，DaemonSet 才会创建新的 Pod。这种方式提供了更手动的控制。

**示例**：
```yaml
spec:
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      # 在更新期间，最多允许一个 Pod 不可用
      maxUnavailable: 1
```

## 15.5 总结

DaemonSet 是 Kubernetes 中用于部署节点级代理和守护进程的关键工具。它通过确保在每个符合条件的节点上都运行一个 Pod 实例，简化了集群范围内的日志收集、监控和网络管理等任务的部署。

与 Deployment 和 StatefulSet 一样，DaemonSet 也是 Kubernetes 提供的核心工作负载之一。在下一章，我们将学习最后一种工作负载类型：**Job** 和 **CronJob**，用于处理批处理和定时任务。