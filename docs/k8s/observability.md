# 17. 可观测性：日志与监控

部署应用只是第一步。在生产环境中，当问题发生时，我们必须能够快速地理解系统内部发生了什么。**可观测性 (Observability)** 就是我们从系统外部推断其内部状态的能力。在云原生领域，它通常由三大支柱构成：
-   **日志 (Logging)**: "发生了什么？" - 记录了离散的、带有时间戳的事件。
-   **指标 (Metrics)**: "表现如何？" - 一系列随时间变化的、可聚合的数值（如 CPU 使用率、请求延迟）。
-   **追踪 (Tracing)**: "请求经历了什么？" - 记录了单次请求在分布式系统中的完整调用链。

本章将重点讨论 Kubernetes 中的日志和监控方案。

## 日志 (Logging)

在 Kubernetes 中，最佳实践是让应用将日志写入其**标准输出 (stdout)** 和**标准错误 (stderr)** 流。

### 基础：`kubectl logs`
我们可以用 `kubectl logs` 命令来查看一个正在运行的 Pod 的日志：
```bash
# 查看 Pod 日志
kubectl logs <pod-name>

# 实时跟踪日志 (类似 tail -f)
kubectl logs -f <pod-name>

# 如果 Pod 有多个容器，需要指定容器名
kubectl logs <pod-name> -c <container-name>
```
这种方式简单直接，非常适合临时调试。但它有致命的缺点：
-   当 Pod 被删除或重启时，日志就丢失了。
-   当节点发生故障时，该节点上的所有日志都无法访问。
-   要排查一个涉及多个 Pod 的问题，需要手动查看每个 Pod 的日志，效率极低。

因此，我们需要一个**中心化的日志解决方案**。

### 中心化日志架构

最流行和标准的架构是在每个节点上运行一个**日志收集代理 (Logging Agent)**。

![Logging-Architecture](https://i.imgur.com/your-logging-arch-image.png) <!-- 你需要替换成真实的图片链接 -->

这个架构的工作流程如下：
1.  **应用写日志**: 你的应用容器将日志写入 `stdout` 和 `stderr`。
2.  **容器引擎重定向**: 容器运行时（如 containerd）会将这些流重定向到节点上的特定日志文件中（通常在 `/var/log/containers` 目录下）。
3.  **日志代理收集**: 你在集群中部署一个 `DaemonSet`，确保每个节点上都运行一个日志代理 Pod（如 [Fluentd](https://www.fluentd.org/) 或 [Filebeat](https://www.elastic.co/beats/filebeat)）。
4.  **代理挂载目录**: 这个代理 Pod 使用 `hostPath` 卷挂载了宿主节点的 `/var/log/containers` 和 `/var/log/pods` 目录。
5.  **发送到后端**: 代理负责读取这些日志文件，可能会进行一些解析和丰富（例如，附加上下文信息如 Pod 名称、Namespace、标签等），然后将它们发送到一个统一的日志存储和分析后端。

**流行的日志后端**:
-   **Elasticsearch**: 功能强大的搜索引擎，通常与 Kibana (可视化) 和 Logstash/Fluentd/Filebeat (收集) 组成 ELK/EFK 技术栈。
-   **Loki**: 由 Grafana Labs 开发，设计理念是只索引元数据（如标签），而不是完整的日志内容，这使得它存储成本更低，更易于运维。通常与 Grafana (可视化) 和 Promtail (收集) 配合使用。

## 监控 (Monitoring)

监控关注的是系统的量化指标。在 Kubernetes 中，需要监控的指标可以分为几个层次。

### 核心指标类型
-   **集群级指标**: 整个集群的健康状况，如节点总数、可用节点数。
-   **节点级指标**: 每个节点的资源使用情况，如 CPU、内存、磁盘和网络 I/O。
-   **Kubernetes 对象指标**:
    -   `Deployment`/`StatefulSet`: 期望的副本数 vs. 实际可用的副本数。
    -   `Pod`: Pod 的生命周期阶段（Pending, Running, Failed）。
    -   `PersistentVolumeClaim`: 存储卷的容量使用情况。
-   **应用级指标**: 应用内部暴露的自定义指标，如 API 请求延迟、队列深度、活跃用户数等（这通常需要应用代码进行埋点）。

### Kubernetes 监控架构

#### Metrics Server
-   **是什么**: `metrics-server` 是一个轻量级的、集群范围的资源使用指标聚合器。
-   **作用**: 它从每个节点的 `kubelet` 上收集基本的资源使用数据（CPU 和内存），并通过 Kubernetes API 将其暴露出来。
-   **核心用途**:
    -   为 `kubectl top node` 和 `kubectl top pod` 命令提供数据。
    -   为 **Horizontal Pod Autoscaler (HPA)** 提供决策依据，以实现应用的自动伸缩。
-   它只存储最新的指标，不保留历史数据，因此不适用于深入的性能分析。

#### Prometheus + Grafana
这是当今云原生监控领域**事实上的标准**。

![Monitoring-Architecture](https://i.imgur.com/your-monitoring-arch-image.png) <!-- 你需要替换成真实的图片链接 -->

-   **Prometheus**:
    -   一个开源的监控和告警系统。
    -   它采用**拉取 (Pull)** 模型：Prometheus Server 会定期地从配置好的监控目标 (称为 target) 的 HTTP 端点上抓取指标数据。
    -   它通过与 Kubernetes API 集成，能够实现强大的**服务发现 (Service Discovery)**。例如，它可以自动发现所有带有特定注解 (`annotations`) 的 `Service` 或 `Pod`，并将其作为监控目标。
-   **Exporters**:
    -   由于很多应用本身不直接暴露 Prometheus 格式的指标，社区开发了大量的 **Exporter**。
    -   Exporter 是一个 Sidecar 或独立的进程，它负责从目标应用（如数据库、消息队列）或系统（如 Linux 内核）收集指标，然后将其转换为 Prometheus 能理解的格式，并提供一个 HTTP 端点供 Prometheus 抓取。
    -   两个至关重要的 Exporter：
        -   **`node-exporter`**: 通常以 `DaemonSet` 的形式部署，用于收集每个节点的系统级指标。
        -   **`kube-state-metrics`**: 监听 Kubernetes API，并将集群中各种对象（如 Deployment, Pod, Service）的状态转换为指标。
-   **Grafana**:
    -   一个开源的可视化和分析平台。
    -   它与 Prometheus 无缝集成，可以让你创建丰富的、可交互的仪表盘（Dashboard）来展示 Prometheus 收集到的指标数据，并根据这些数据设置告警规则。

通过建立一套中心化的日志和监控系统，你可以获得对 Kubernetes 集群和其上运行应用的深刻洞察力，从而实现快速故障排查、性能优化和主动告警。 