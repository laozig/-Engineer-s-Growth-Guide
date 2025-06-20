# 17. 可观测性：日志与监控

运行一个复杂的分布式系统，如果无法了解其内部状态，就像在黑暗中开车。**可观测性（Observability）** 是确保系统健康、稳定和高效运行的关键。在 Kubernetes 中，可观测性主要包括三个方面：**日志（Logging）**、**指标（Metrics）** 和 **追踪（Tracing）**。

本章我们重点关注最核心的两个：日志和指标。

## 17.1 日志 (Logging)

在 Kubernetes 中，日志的最佳实践是让应用将日志信息**输出到标准输出（`stdout`）和标准错误（`stderr`）**。容器运行时（如 Docker）会捕获这些输出，并将其存储在节点的特定位置（通常是 `/var/log/containers` 目录下）。

### `kubectl logs`
这是查看日志最直接的方式。
```bash
# 查看 Pod 的日志
kubectl logs <pod-name>

# 实时跟踪日志 ("tail -f")
kubectl logs -f <pod-name>

# 查看多容器 Pod 中特定容器的日志
kubectl logs <pod-name> -c <container-name>
```
`kubectl logs` 非常适合临时性的调试，但它有局限性：
- Pod 被删除后，日志就丢失了。
- 需要手动检查每个 Pod 的日志，无法进行聚合查询和分析。

### 集群级日志解决方案
为了解决上述问题，我们需要一个集群级的日志系统。其通用架构如下：
1.  在每个节点上运行一个**日志代理（Agent）**，通常使用 `DaemonSet` 来部署。
2.  这个代理负责收集该节点上所有容器的日志文件。
3.  代理对日志进行处理、丰富（例如，加上 Pod 名称、Namespace 等元数据）。
4.  最后，将处理后的日志发送到一个集中的**日志后端存储和分析系统**。

<div align="center">
  <img src="https://i.imgur.com/8QGZqYk.png" alt="Cluster-level logging architecture" width="700">
</div>

**常用工具组合**：
- **Fluentd + Elasticsearch + Kibana (EFK Stack)**:
    - **Fluentd**: 强大的日志收集代理。
    - **Elasticsearch**: 高性能的搜索和分析引擎，用于存储和索引日志。
    - **Kibana**: 一个 Web UI，用于查询、可视化和分析存储在 Elasticsearch 中的日志。
- **Fluent Bit**: 一个比 Fluentd 更轻量级的日志代理，性能更高，资源消耗更少。
- **Loki**: 由 Grafana Labs 开发的日志系统，设计理念是只索引元数据而不是完整的日志内容，从而实现极高的存储效率。

## 17.2 监控 (Monitoring)

监控的核心是**收集、存储和分析时间序列指标（Metrics）**。指标是关于系统在某个时间点状态的数字度量，例如：
- 节点 CPU 使用率
- Pod 内存消耗
- API 请求延迟
- 数据库查询速率

### Kubernetes 中的指标
Kubernetes 自身暴露了大量的指标：
- **核心指标（Core Metrics）**: 由 `metrics-server` 提供，主要包括节点和 Pod 的 CPU、内存使用情况。`kubectl top nodes/pods` 命令的数据就来自这里。
- **完整指标**: 由 `kube-state-metrics` 和 `kubelet` 等组件以 Prometheus 格式暴露，包含了 Kubernetes 对象的详细状态，如 Deployment 的副本数、Pod 的状态、PVC 的容量等。

### Prometheus：事实上的标准
**Prometheus** 是 CNCF 旗下的一个开源监控和告警项目，已成为 Kubernetes 监控领域的事实标准。

**核心架构**：
1.  **Prometheus Server**: 负责从各个目标（Targets）**拉取（Pull）**指标数据，并将其存储在内置的时间序列数据库中。
2.  **Exporters**: Prometheus 通过各种 "Exporter" 来获取指标。例如，`node-exporter` 负责暴露节点的硬件和系统指标，`kube-state-metrics` 负责暴露 Kubernetes 对象的状态指标。
3.  **Alertmanager**: 处理由 Prometheus Server 发送的告警（Alerts），负责去重、分组，并通过 Email、Slack、PagerDuty 等方式发送通知。
4.  **Grafana**: 最常用的数据可视化工具。它可以连接到 Prometheus 作为数据源，创建丰富、美观的仪表盘（Dashboard）来展示监控数据。

<div align="center">
  <img src="https://i.imgur.com/N7bK8vJ.png" alt="Prometheus monitoring architecture" width="700">
</div>

**部署**：在 Kubernetes 中部署和管理 Prometheus 生态系统最简单的方式是使用 **Prometheus Operator** 或 **Helm Chart**。这些工具极大地简化了配置和管理，使得你可以轻松地搭建起一套生产级的监控系统。

## 17.3 总结

可观测性是维护生产级 Kubernetes 集群的基石。我们了解了两种核心的日志架构：`kubectl logs` 用于快速调试，以及基于代理的集群级日志系统（如 EFK）用于长期存储和分析。在监控方面，我们学习了以 Prometheus 为核心的生态系统，它通过拉取模型收集指标，并结合 Grafana 进行可视化，构成了 Kubernetes 监控的黄金标准。

在下一章，我们将学习如何使用 **Helm**，Kubernetes 的包管理器，来简化复杂应用的部署和管理。 