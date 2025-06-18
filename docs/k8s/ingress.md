# 12. Ingress：集群流量入口

我们已经知道如何使用 `Service` 的 `NodePort` 或 `LoadBalancer` 类型来将应用暴露给外部世界。但这两种方式有明显的缺点：

-   `NodePort`: 每个服务都需要在所有节点上占用一个端口，管理混乱且不适合大规模应用。
-   `LoadBalancer`: **每暴露一个服务就需要一个云服务商提供的负载均衡器**。这非常昂贵，而且每个负载均衡器都需要一个公网 IP，这在 IPv4 地址日益枯竭的今天是一种巨大的浪费。

想象一下，如果你有几十个微服务需要对外暴露，难道要创建几十个 `LoadBalancer` 吗？显然不现实。

为了解决这个问题，Kubernetes 引入了 `Ingress`。

## 什么是 Ingress？

`Ingress` 是一个 Kubernetes API 对象，它为集群内的 `Service` 集合提供了一个**统一的、智能的七层 (HTTP/S) 路由入口**。

你可以把 `Ingress` 想象成一个集群的"流量总管"或"API 网关"。它允许你用一套统一的规则来定义：
-   如何将外部请求**基于主机名 (Host)** 路由到不同的服务。
-   如何将外部请求**基于路径 (Path)** 路由到不同的服务。
-   如何管理和终止 **TLS (HTTPS)** 连接。

通过 `Ingress`，你可以使用**一个公网 IP 和一个负载均衡器**，来为集群内**所有**的服务提供外部访问。

![Ingress-Architecture](https://i.imgur.com/your-ingress-arch-image.png) <!-- 你需要替换成真实的图片链接 -->

## Ingress vs. Ingress Controller

理解 `Ingress` 的关键在于区分两个概念：

1.  **`Ingress` 对象**: 这是一个 Kubernetes 资源，你在 YAML 文件中定义的是它。它本身**不做任何事情**，它只是一套**路由规则**的集合。
2.  **`Ingress Controller` (Ingress 控制器)**: 这是一个**真正工作的程序**，它通常是一个运行在集群中的反向代理服务器（如 NGINX, Traefik, HAProxy）。`Ingress Controller` 持续地监听 (watch) 集群中 `Ingress` 对象的变化，并根据这些规则来动态地配置自己，将外部流量正确地转发到后端服务。

**这个关系至关重要**：在你的集群中，**必须先部署一个 `Ingress Controller`**，然后创建的 `Ingress` 规则才会生效。常见的 Ingress Controller 包括 [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/), [Traefik](https://traefik.io/traefik/), [Contour](https://projectcontour.io/) 等。

## Ingress 的 YAML 定义

`Ingress` 的强大之处在于其灵活的路由规则。

### 1. 基于路径的路由 (Path-based Routing)

你可以根据请求的 URL 路径将流量分发到不同的服务。

`single-host-ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: simple-fanout-example
spec:
  rules:
  - host: my-app.example.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: api-service # /api 的请求转发到这里
            port:
              number: 8080
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service # 其他所有请求转发到这里
            port:
              number: 80
```
-   `host`: 指定该规则适用的主机名。
-   `paths`: 一个路径规则列表。
-   `path`: URL 路径。
-   `pathType`: 路径匹配类型，`Prefix` 表示前缀匹配，`Exact` 表示精确匹配。
-   `backend`: 定义了流量应该被转发到的后端 `Service`。

### 2. 基于名称的虚拟主机 (Name-based Virtual Hosting)

你可以根据请求的主机名将流量分发到不同的服务，就像配置 NGINX 的 `server_name` 一样。

`multi-host-ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: name-virtual-host-ingress
spec:
  rules:
  - host: foo.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: foo-service # foo.example.com 的请求转发到 foo-service
            port:
              number: 80
  - host: bar.example.com
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: bar-service # bar.example.com 的请求转发到 bar-service
            port:
              number: 80
```

### 3. TLS (HTTPS) 终止

`Ingress` 可以为你处理 HTTPS 流量的解密，这个过程称为 TLS 终止。你的应用本身只需要处理普通的 HTTP 流量即可。

`tls-ingress.yaml`:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tls-example-ingress
spec:
  tls:
  - hosts:
    - https-app.example.com
    secretName: my-tls-secret # 引用包含 TLS 证书和私钥的 Secret
  rules:
  - host: https-app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-secure-app-service
            port:
              number: 80
```
-   `tls`: 定义了 TLS 配置。
-   `hosts`: 该证书适用的主机名列表。
-   `secretName`: 引用一个类型为 `kubernetes.io/tls` 的 `Secret`。这个 `Secret` 必须包含 `tls.crt` (证书) 和 `tls.key` (私钥) 两个键。

## 总结：Ingress 工作流程

1.  用户在浏览器中输入 `https://foo.example.com/api`。
2.  DNS 将 `foo.example.com` 解析到你的 **Ingress Controller** 的公网 IP 地址。
3.  流量到达 `Ingress Controller`（它通常是一个 `LoadBalancer` 类型的服务）。
4.  `Ingress Controller` 检查请求：主机头是 `foo.example.com`，路径是 `/api`。
5.  `Ingress Controller` 在其内存中的配置里查找匹配的 `Ingress` 规则。
6.  它找到了一个规则，指示应将此请求转发到 `api-service` 的 8080 端口。
7.  `Ingress Controller` 将请求转发给 `api-service`。
8.  `api-service` 再将请求负载均衡到其后端的某个 `Pod`。

`Ingress` 是 Kubernetes 中管理应用入口流量的强大工具，它通过统一的路由规则和对 TLS 的原生支持，极大地简化了在生产环境中发布和管理大规模微服务的复杂性。 