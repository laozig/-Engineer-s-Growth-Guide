# 12. Ingress：集群流量入口

我们已经学习了如何使用 `Service` (如 `NodePort` 或 `LoadBalancer`) 来暴露应用。但这些方式存在一些问题：
- `NodePort`：占用每个节点的端口，且端口范围有限，不适合大规模使用。
- `LoadBalancer`：每暴露一个服务就需要一个云服务商的负载均衡器，成本高昂。

对于需要暴露多个 HTTP/HTTPS 服务的场景，Kubernetes 提供了更强大、更灵活的解决方案：**Ingress**。

## 12.1 什么是 Ingress？

**Ingress** 是对集群中 Service 的**七层（HTTP/HTTPS）负载均衡**和**流量路由**规则的集合。它本身不是一个 Service，而是一个 API 对象，用于定义外部流量如何到达集群内部的 Service。

你可以将 Ingress 想象成集群的"交通警察"或"API 网关"。它能检查传入的 HTTP 请求，并根据**主机名（Host）**和**路径（Path）**来决定将流量转发到哪个 Service。

**核心功能**：
- **基于主机名的路由**：将 `foo.example.com` 的流量导向 `foo-service`，将 `bar.example.com` 的流量导向 `bar-service`。
- **基于路径的路由**：将 `example.com/api` 的流量导向 `api-service`，将 `example.com/ui` 的流量导向 `ui-service`。
- **SSL/TLS 终止**：集中管理 TLS 证书，为你的服务提供 HTTPS 加密，而无需在每个 Service 中单独配置。
- **将多个 Service 聚合到单个 IP 地址**：所有流量都通过 Ingress 的入口 IP 进入，有效节省了 `LoadBalancer` 的使用和成本。

## 12.2 Ingress Controller：真正的工作者

值得注意的是，创建 Ingress 对象本身**并不会生效**。你必须在集群中运行一个 **Ingress Controller**。

- **Ingress Controller** 是一个实际的 Pod 或一组 Pod，它负责监听 Ingress 资源的变化，并根据其中定义的规则来配置底层的负载均衡器（通常是一个反向代理，如 Nginx, HAProxy, 或 Traefik）。

**工作流程**：
1.  外部流量到达 Ingress Controller 的入口点（通常是一个 `LoadBalancer` 类型的 Service）。
2.  Ingress Controller 查看请求的 HTTP Host 和 Path。
3.  它在已创建的 Ingress 资源中查找匹配的路由规则。
4.  根据规则，它将流量转发到后端对应的 Service，再由 Service 转发到最终的 Pod。

常见的 Ingress Controller 实现包括：
- **Kubernetes NGINX Ingress Controller**: 由 Kubernetes 社区维护，使用 Nginx 作为反向代理。
- **Traefik**: 一个现代的、云原生的反向代理和负载均衡器。
- **Contour**: 由 Heptio (现为 VMware) 开源的 Ingress Controller。
- 各大云厂商也提供其自家的 Ingress Controller 实现。

<div align="center">
  <img src="https://i.imgur.com/gK9wJ1b.png" alt="Ingress workflow" width="700">
</div>

## 12.3 如何定义一个 Ingress (YAML)

下面是一个 Ingress 资源的示例，它定义了基于主机名和路径的路由规则。

`my-ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: my-app-ingress
  annotations:
    # Ingress Controller 特定的注解，用于额外配置
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  # Ingress 类，指定由哪个 Ingress Controller 处理
  ingressClassName: nginx-example
  # 定义 TLS 配置
  tls:
  - hosts:
    - my-app.example.com
    # 引用包含证书和私钥的 Secret
    secretName: my-tls-secret
  # 定义路由规则
  rules:
  - host: my-app.example.com
    http:
      paths:
      # 将 /analytics 路径的流量转发到 analytics-service 的 80 端口
      - path: /analytics
        pathType: Prefix
        backend:
          service:
            name: analytics-service
            port:
              number: 80
      # 将 /shopping 路径的流量转发到 shopping-service 的 8080 端口
      - path: /shopping
        pathType: Prefix
        backend:
          service:
            name: shopping-service
            port:
              number: 8080
```

**关键字段解释**:
- `metadata.annotations`: 用于提供 Ingress Controller 特定的配置，每个 Controller 的注解都不同。
- `spec.ingressClassName`: 在有多个 Ingress Controller 的集群中，明确指定由哪一个来处理此 Ingress 资源。
- `spec.tls`: 定义 TLS 配置。`hosts` 列表中的域名将使用 `secretName` 引用的 Secret 中的证书进行加密。
- `spec.rules`: 路由规则的核心。
  - `host`: 匹配的请求主机名。
  - `http.paths`: 该主机下的路径规则列表。
    - `path`: 匹配的 URL 路径。
    - `pathType`: 路径匹配类型，`Prefix` (前缀匹配) 或 `Exact` (精确匹配)。
    - `backend.service`: 定义了流量要转发到的目标 Service 和端口。

## 12.4 默认后端 (Default Backend)

你还可以定义一个默认后端。如果没有任何规则匹配传入的请求，流量将被发送到这个默认的 Service。这对于处理 404 页面或提供一个默认的"欢迎"页面非常有用。

```yaml
spec:
  defaultBackend:
    service:
      name: default-404-service
      port:
        number: 80
```

## 12.5 总结

Ingress 是 Kubernetes 中管理 HTTP/HTTPS 流量路由的强大工具。通过结合 Ingress Controller，它提供了一种集中、高效且经济的方式来将集群内部的多个服务暴露给外部世界。理解如何配置基于主机和路径的路由，以及如何使用 TLS 终止，是构建生产级 Web 应用的关键技能。

在下一章，我们将探讨 Kubernetes 网络安全的另一个重要方面：**NetworkPolicy**，学习如何在 Pod 之间创建防火墙规则。