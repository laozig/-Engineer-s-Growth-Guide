# 13. NetworkPolicies：网络隔离策略

默认情况下，Kubernetes 的集群网络是**完全开放**的。这意味着，任何 Pod 都可以与任何其他 Pod 通信，无论它们是否在同一个 Namespace。这种"扁平网络"模型虽然简单，但在多租户环境或处理敏感数据的应用中，会带来严重的安全风险。

为了实现更精细的访问控制，就像在传统网络中使用防火墙一样，Kubernetes 提供了 `NetworkPolicy`。

## 什么是 NetworkPolicy？

`NetworkPolicy` 是一个 Kubernetes API 对象，它允许你通过规则来控制 Pod 组之间的流量以及 Pod 与外部端点之间的流量。

你可以使用 `NetworkPolicy` 来定义类似这样的规则：
-   "只允许 `frontend` 命名空间中的 Pods 访问 `backend` 命名空间中带有 `app=api` 标签的 Pods 的 8080 端口。"
-   "`database` 命名空间中的 Pods 不允许访问集群外部的任何地址。"
-   "`default` 命名空间中的所有 Pods 之间不能相互通信。"

### 重要前提：需要网络插件支持

与 `Ingress` 和 `Ingress Controller` 的关系类似，`NetworkPolicy` 资源本身只是一套规则。要让这些规则生效，你的集群必须使用一个**支持 `NetworkPolicy` 的网络插件 (CNI)**。

一些流行的支持 `NetworkPolicy` 的网络插件包括：
-   Calico
-   Cilium
-   Weave Net
-   Antrea

如果你使用的是云服务商提供的 Kubernetes 服务（如 GKE, EKS, AKS），它们通常会默认配置或提供支持 `NetworkPolicy` 的选项。如果你的策略不生效，首先要检查的就是网络插件是否正确配置。

## NetworkPolicy 的核心逻辑

`NetworkPolicy` 的工作方式基于"默认拒绝"的白名单模型，理解其核心逻辑至关重要：

1.  **默认全通**: 在默认情况下，所有 Pod 都是**非隔离的 (non-isolated)**，它们可以接收和发送任何来源和去向的流量。
2.  **一旦被选中即隔离**: 当一个或多个 `NetworkPolicy` 通过 `podSelector` **选中**了某个 Pod，该 Pod 就变成了**隔离的 (isolated)**。
3.  **隔离后默认全拒**: 对于一个隔离的 Pod，**所有流量（入站和出站）都会被默认拒绝**。
4.  **白名单放行**: 只有被选中该 Pod 的 `NetworkPolicy` 规则**明确允许 (allow)** 的流量，才会被放行。

**简而言之：不被任何策略选中的 Pod，网络是通的。一旦被任何策略选中，网络就全不通，需要策略来明确"开洞"。**

## NetworkPolicy 的 YAML 定义

一个 `NetworkPolicy` 主要由四部分组成：

`policy-example.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-allow-policy
  namespace: backend
spec:
  podSelector: # 1. 选择要应用此策略的 Pods
    matchLabels:
      app: api
  policyTypes: # 2. 策略类型 (入站/出站)
  - Ingress
  - Egress
  ingress: # 3. 入站规则 (允许谁进来)
  - from:
    - namespaceSelector: # a. 允许来自 'frontend' 命名空间的流量
        matchLabels:
          name: frontend
    - podSelector: # b. 允许来自 'backend' 命名空间中带有 'role=monitoring' 标签的 Pod 的流量
        matchLabels:
          role: monitoring
    ports: # c. 且必须是访问 TCP 8080 端口
    - protocol: TCP
      port: 8080
  egress: # 4. 出站规则 (允许出去访问谁)
  - to:
    - ipBlock: # a. 允许访问公网 (除了两个私有网段)
        cidr: 0.0.0.0/0
        except:
        - 10.0.0.0/8
        - 192.168.0.0/16
    ports: # b. 且只能访问 TCP 443 端口 (HTTPS)
    - protocol: TCP
      port: 443
```
1.  `podSelector`: 定义了这条策略应用到哪些 Pod 上。如果留空，则应用到该 Namespace 下的所有 Pod。
2.  `policyTypes`: 指定策略是应用于 `Ingress` (入站) 流量、`Egress` (出站) 流量，还是两者都有。
3.  `ingress`: 定义入站规则列表。每个规则定义了一组允许的**来源 (from)** 和**端口 (ports)**。
4.  `egress`: 定义出站规则列表。每个规则定义了一组允许的**去向 (to)** 和**端口 (ports)**。

### `from` 和 `to` 的选择器

-   `podSelector`: 选择同一个 Namespace 内的特定 Pods。
-   `namespaceSelector`: 选择特定 Namespace 内的所有 Pods。
-   `ipBlock`: 基于 CIDR 选择特定的 IP 地址范围。

如果 `from` 或 `to` 规则为空，表示允许所有来源或所有去向。

## 常用策略示例

### 示例 1: 默认拒绝 Namespace 内所有入站流量

这是实现 Namespace 级别网络隔离的基石。
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: my-app-ns
spec:
  podSelector: {} # 选择该 Namespace 下的所有 Pods
  policyTypes:
  - Ingress
  # ingress: [] # ingress 列表为空，表示不允许任何入站流量
```

### 示例 2: 只允许同一 Namespace 内的 Pod 互相通信

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: my-app-ns
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {} # 允许来自该 Namespace 内所有 Pod 的流量
```

`NetworkPolicy` 是 Kubernetes 中实现"零信任网络"安全模型的关键工具。通过精细地定义 Pod 间的通信规则，你可以极大地增强应用的安全性，防止攻击者在集群内部横向移动。 