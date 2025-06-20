# 6. Services：服务发现与负载均衡

我们已经学会了使用 Deployment 来部署和管理 Pod，但这引出了一个新的问题：Pod 是短暂的，它们的 IP 地址会随着重建而改变。那么，一个应用（或外部用户）如何才能稳定地访问到我们部署的 Pod 呢？

答案就是 **Service**。

## 6.1 什么是 Service？

**Service** 是 Kubernetes 中的一个核心对象，它为一组功能相同的 Pod 提供一个**稳定、统一的访问入口**。

主要功能：
- **服务发现**：Service 提供了一个稳定的 DNS 名称和 IP 地址（称为 ClusterIP）。集群内的其他 Pod 可以通过这个 DNS 名称来访问服务，而无需关心后端 Pod 的具体 IP。
- **负载均衡**：当一个 Service 代理多个 Pod 副本时，它会自动将接收到的流量分发到后端的某个健康 Pod 上。

你可以将 Service 想象成一个内部的负载均衡器或一个微服务的"名片"。它将**服务的前端（一个稳定的地址）**与**服务的后端（一组动态的 Pod）**解耦。

<div align="center">
  <img src="https://i.imgur.com/uaj9fR3.png" alt="Service providing a stable endpoint for Pods" width="700">
</div>

## 6.2 Service 如何与 Pod 关联？

Service 通过**标签选择器 (Label Selector)** 来动态地发现它应该代理哪些 Pod。

工作流程：
1. 你在 Deployment 的 Pod 模板中为 Pod 打上特定的标签（例如 `app: my-api`）。
2. 你创建一个 Service，并定义其 `selector` 字段，使其匹配这些标签（`selector: { app: my-api }`）。
3. Kubernetes 会持续监控所有带有 `app: my-api` 标签的 Pod，并自动将它们的 IP 地址和端口更新到一个名为 **Endpoint** 的内部列表中。
4. 当有请求发送到该 Service 的地址时，`kube-proxy` 组件会从 Endpoint 列表中选择一个健康的 Pod，并将流量转发过去。

这种基于标签的动态关联机制是 Kubernetes 服务发现的核心，它使得 Pod 的扩缩容、更新和故障对服务的消费者完全透明。

## 6.3 如何定义一个 Service (YAML)

假设我们有一个之前创建的 `nginx-deployment`，它管理的 Pod 带有 `app: nginx` 标签。下面是为它创建一个 Service 的 YAML 定义：

**`nginx-service.yaml`**:
```yaml
# API 版本
apiVersion: v1
# 资源类型
kind: Service
metadata:
  name: nginx-service
spec:
  # Service 的类型，决定了它如何被访问
  type: ClusterIP
  # 标签选择器，用于关联后端 Pod
  selector:
    app: nginx
  #端口定义
  ports:
    - protocol: TCP
      # Service 自身暴露的端口
      port: 80
      # 流量要转发到的后端 Pod 的容器端口
      targetPort: 80
```

**关键字段解释**:
- `spec.type`: Service 的类型，这是最重要的字段之一。
- `spec.selector`: 必须与你想要暴露的 Pod 的标签完全匹配。
- `spec.ports`: 定义了端口映射。
  - `port`: Service 在其 ClusterIP 上监听的端口。
  - `targetPort`: Service 将流量转发到的目标 Pod 的端口。

## 6.4 Service 的类型 (`type`)

Kubernetes 提供了几种不同类型的 Service，以适应不同的访问需求。

### 1. `ClusterIP` (默认)
- **作用**：在集群内部暴露服务。
- **访问方式**：只能从集群内部通过 Service 的 ClusterIP 或 DNS 名称 (`<service-name>.<namespace>.svc.cluster.local`) 访问。
- **用途**：最常见的类型，用于集群内部服务之间的通信（例如，Web 前端访问后端 API）。

### 2. `NodePort`
- **作用**：在每个节点的 IP 地址上的一个静态端口暴露服务。
- **访问方式**：可以从集群外部通过 `<NodeIP>:<NodePort>` 访问。
- **工作原理**：Kubernetes 会在所有节点上保留一个端口（默认为 30000-32767 范围），并将发往该端口的流量转发到 Service 的 ClusterIP。
- **用途**：用于开发和测试阶段，快速地将服务暴露给外部，或用于不支持 `LoadBalancer` 的环境。

### 3. `LoadBalancer`
- **作用**：使用云服务商提供的外部负载均衡器来暴露服务。
- **访问方式**：通过云服务商提供的负载均衡器的公网 IP 地址访问。
- **工作原理**：当创建此类型的 Service 时，Kubernetes 会自动向底层云平台（如 AWS, GCP, Azure）请求一个负载均衡器，并将其配置为将流量指向所有节点的 NodePort。
- **用途**：在生产环境中，将服务安全、可靠地暴露给公网用户的标准方式。

### 4. `ExternalName`
- **作用**：将 Service 映射到集群外部的一个 DNS 名称，而不是通过标签选择器关联 Pod。
- **工作原理**：当集群内的 Pod 访问这个 Service 时，会直接返回配置的外部 DNS 地址的 CNAME 记录。
- **用途**：用于在集群内部创建一个指向外部服务的别名，让集群内的应用像访问内部服务一样访问外部依赖。

## 6.5 总结

Service 是 Kubernetes 网络模型中的基石。它通过提供稳定的 IP 地址和 DNS 名称，并结合标签选择器实现了强大的服务发现和负载均衡机制。通过使用不同类型的 Service，我们可以灵活地控制服务的访问方式，无论是集群内部通信还是对外暴露应用。

在下一章，我们将学习 **Namespaces**，了解如何使用它来在同一个物理集群中创建多个虚拟的、隔离的逻辑集群。 