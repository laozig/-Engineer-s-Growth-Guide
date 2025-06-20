# 13. NetworkPolicies：网络隔离策略

默认情况下，Kubernetes 集群中的网络是**完全开放**的。这意味着任何 Pod 都可以与任何其他 Pod 通信，无论它们在哪个 Namespace。这种"扁平网络"模型简化了服务发现，但也带来了安全隐患。

为了实现更精细的访问控制，类似于传统网络中的防火墙规则，Kubernetes 引入了 **NetworkPolicy** 对象。

## 13.1 什么是 NetworkPolicy？

**NetworkPolicy** 是一个 API 对象，它定义了 Pod 之间（以及 Pod 与外部网络之间）如何被允许进行通信。你可以把它看作是 Kubernetes 中作用于 Pod 的**三层/四层（IP/端口）防火墙规则**。

**核心原则**：
- **默认拒绝（Default Deny）**：一旦你为一个 Pod 应用了任何一个 NetworkPolicy，它就会立即进入"默认拒绝"模式。这意味着所有不被策略明确允许的流量（入站和出站）都将被**拒绝**。
- **标签选择器驱动**：NetworkPolicy 使用标签来选择它要作用于哪些 Pod，以及定义允许哪些源/目的 Pod 进行通信。
- **与 CNI 插件相关**：NetworkPolicy 的实现依赖于你所使用的**网络插件（CNI）**。如果你的 CNI 插件（如 Flannel）不支持 NetworkPolicy，那么创建这个对象将不会产生任何效果。常用的支持者包括 Calico, Cilium, Weave Net 等。

## 13.2 NetworkPolicy 的组成部分

一个 NetworkPolicy 主要由三部分组成：
1.  **`podSelector`**: 选择该策略要应用到哪些 Pod。如果留空，它将作用于 Namespace 下的所有 Pod。
2.  **`policyTypes`**: 定义策略的类型。可以是 `Ingress`（入站规则）、`Egress`（出站规则），或两者都有。
3.  **`ingress` 和 `egress`**: 分别定义具体的入站和出站规则列表。

<div align="center">
  <img src="https://i.imgur.com/gO1oI5e.png" alt="NetworkPolicy components" width="700">
</div>

## 13.3 常用策略示例

### 示例 1：默认拒绝所有入站流量

这是最基础也是最安全的起点。创建一个策略，选中所有 `app=api` 的 Pod，但不定义任何 `ingress` 规则。

`deny-all-ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-deny-all-ingress
spec:
  # 应用到所有带有 app=api 标签的 Pod
  podSelector:
    matchLabels:
      app: api
  # 策略类型为入站
  policyTypes:
  - Ingress
  # ingress 规则列表为空，表示拒绝所有入站流量
  ingress: []
```

### 示例 2：只允许特定 Pod 访问

现在，我们希望只允许带有 `app=frontend` 标签的 Pod 访问我们的 `app=api` Pod 的 80 端口。

`allow-frontend-to-api.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-api
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
  - Ingress
  ingress:
  - from:
    # 允许来自以下源的流量
    # 1. 带有 app=frontend 标签的 Pod
    - podSelector:
        matchLabels:
          app: frontend
    # 2. 来自特定 Namespace 的所有 Pod
    - namespaceSelector:
        matchLabels:
          name: monitoring
    ports:
    # 流量必须访问 80 端口
    - protocol: TCP
      port: 80
```
- **`from`** 列表定义了允许的**入站源**。
- **`ports`** 列表定义了允许访问的**端口**。
- 如果同时定义了 `from` 和 `ports`，则流量必须同时满足两个条件才被允许。

### 示例 3：只允许出站到特定目标

我们也可以限制 Pod 的出站流量。例如，我们只允许 `app=database-connector` 的 Pod 访问外部的数据库（通过 IP 地址）和内部的 DNS 服务。

`allow-egress-to-db.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: db-connector-allow-egress
spec:
  podSelector:
    matchLabels:
      app: database-connector
  policyTypes:
  - Egress
  egress:
  # 允许出站到以下目标
  # 1. 外部数据库的 IP 地址段
  - to:
    - ipBlock:
        cidr: 192.168.100.0/24
    ports:
    - protocol: TCP
      port: 5432
  # 2. 集群内部的 DNS 服务（kube-system Namespace）
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```
- **`to`** 列表定义了允许的**出站目的地**。
- **`ipBlock`** 可以用来指定允许访问的 CIDR 网段，非常适合用于控制对集群外部服务的访问。

## 13.4 策略组合

你可以为一个 Pod 应用多个 NetworkPolicy。Kubernetes 会将所有适用于该 Pod 的策略**合并**计算。只要**至少有一个**策略允许某个流量，那么该流量就是被允许的。

例如，你可以创建一个"允许所有 Pod 访问 DNS"的全局出站策略，然后再为每个应用创建特定的出站规则。

## 13.5 总结

NetworkPolicy 是 Kubernetes 中实现网络微隔离（Micro-segmentation）的关键工具。通过实施"默认拒绝"并精细地定义允许的流量规则，你可以极大地增强集群的安全性，防止攻击者在集群内部横向移动。

这是我们网络部分的最后一章。在下一部分，我们将学习更高级的工作负载类型，如 `StatefulSet` 和 `DaemonSet`。