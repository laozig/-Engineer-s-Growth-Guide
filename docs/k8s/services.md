# 6. Services：服务发现与负载均衡

我们已经学习了如何使用 `Deployment` 来创建和维护一组运行我们应用程序的 Pod 副本。但是，这带来了一个关键问题：Pods 是短暂的，它们会被创建和销毁，每次重建后其 IP 地址都会改变。

那么：
1.  集群内的其他 Pods（例如，一个前端应用如何找到后端 API？）如何可靠地访问它们？
2.  外部用户（例如，通过浏览器）又该如何访问我们的应用？

答案就是 `Service`。

## 什么是 Service？

`Service` 是一个 Kubernetes 对象，它为一组功能相同的 Pods 提供了一个**稳定的、统一的访问入口**。

可以把 `Service` 想象成一个内部的负载均衡器或者一个虚拟的中间人。它有一个**不会改变的 IP 地址 (称为 ClusterIP) 和一个 DNS 名称**。当请求发送到这个 `Service` 的地址时，`Service` 会自动将流量转发到其后端某个健康的 Pod 上。

**Service 的核心职责**:
-   **服务发现**: 为一组 Pod 提供一个稳定的 DNS 名称和 IP 地址。
-   **负载均衡**: 将接收到的流量分发到后端的多个 Pod 副本上。

## Service 如何与 Pods 关联？

`Service` 通过**标签和选择器 (Labels and Selectors)** 来找到它应该代理的 Pods。这个机制与 `Deployment` 的 `selector` 完全相同。

1.  你在 `Deployment` 中为你的 Pod 模板打上标签（例如 `app: my-backend`）。
2.  你在 `Service` 的定义中创建一个选择器，指向同一个标签 (`selector: {app: my-backend}`)。
3.  `Service` 会自动持续地扫描集群，找到所有匹配该标签的 Pods，并将它们作为自己的后端端点 (Endpoints)。

![Service-Selector-Pods](https://i.imgur.com/your-svc-selector-image.png) <!-- 你需要替换成真实的图片链接 -->

## Service 的 YAML 定义

让我们为之前创建的 `nginx-deployment` 创建一个 `Service`。

`nginx-service.yaml`:
```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  selector:
    app: nginx-app
  ports:
  - name: http
    protocol: TCP
    port: 80
    targetPort: 80
```

分解这个 YAML：
-   `kind`: `Service`。
-   `spec`:
    -   `selector`: **这是关键**。它告诉 `Service` 去寻找所有带有 `app: nginx-app` 标签的 Pod。
    -   `ports`: 定义了端口映射规则。
        -   `port`: `Service` 自身暴露的端口。其他 Pod 将通过这个端口访问 `Service`。
        -   `targetPort`: 流量将被转发到的**目标 Pod 上的容器端口**。
        -   `protocol`: 端口协议，默认为 `TCP`。

## Service 的类型

Kubernetes 提供了不同类型的 `Service`，以应对不同的暴露需求。你通过 `spec.type` 字段来指定。

### 1. `ClusterIP` (默认类型)

-   **作用**: 在集群**内部**暴露服务。
-   **工作方式**: 为 `Service` 分配一个只能从集群内部访问的虚拟 IP 地址。
-   **适用场景**: 集群内部组件之间的通信（例如，前端 Pod 访问后端 Pod）。
-   如果省略 `type` 字段，默认就是 `ClusterIP`。我们上面的 `nginx-service` 就是一个 `ClusterIP` 类型的 `Service`。

### 2. `NodePort`

-   **作用**: 在集群**外部**通过节点的 IP 和静态端口暴露服务。
-   **工作方式**: 在 `ClusterIP` 的基础上，`NodePort` 会在**每一个集群节点**上都开放一个相同的、指定的静态端口（默认范围 30000-32767）。任何发送到 `[NodeIP]:[NodePort]` 的流量都会被转发到 `Service` 的 `ClusterIP`，再由 `ClusterIP` 转发到后端的 Pod。
-   **适用场景**: 开发和测试环境，或者当你不使用云服务商的负载均衡器时，快速地将服务暴露给外部。
-   **YAML 示例**:
    ```yaml
    spec:
      type: NodePort
      selector:
        app: nginx-app
      ports:
      - port: 80
        targetPort: 80
        nodePort: 30080 # 可选，如果不指定，会自动分配一个
    ```

### 3. `LoadBalancer`

-   **作用**: 使用云服务商提供的**外部负载均衡器**来暴露服务。
-   **工作方式**: 这是 `NodePort` 的扩展。当你创建一个 `LoadBalancer` 类型的 `Service` 时，Kubernetes 会向其所在的云平台（如 AWS, GCP, Azure）发起一个 API 调用，请求创建一个外部负载均衡器。这个负载均衡器会有自己的公网 IP，并将流量导向所有节点的 `NodePort`。
-   **适用场景**: 在公有云上将应用发布到互联网的**标准方式**。
-   **YAML 示例**:
    ```yaml
    spec:
      type: LoadBalancer
      selector:
        app: nginx-app
      ports:
      - port: 80
        targetPort: 80
    ```
    创建后，你可以通过 `kubectl get service nginx-service` 查看到 `EXTERNAL-IP` 字段会从 `<pending>` 变为一个公网 IP 地址。

### 4. `ExternalName`

-   **作用**: 将 `Service` 映射到一个外部的 DNS 名称，而不是选择器。
-   **工作方式**: 当集群内的 Pod 查询这个 `Service` 的 DNS 名称时，Kubernetes 的 DNS 服务会返回一个 `CNAME` 记录，指向你指定的外部地址。
-   **适用场景**: 在集群内部用一个固定的名称来访问一个外部服务（如外部的数据库），方便未来迁移。

## 服务发现机制

`Service` 创建后，Kubernetes 提供了两种主要的方式让其他 Pod 发现它：

1.  **环境变量 (不推荐)**: 当一个 Pod 启动时，`kubelet` 会为**当时已经存在**的每个 `Service` 创建一组环境变量。这种方式有顺序依赖，所以不推荐。
2.  **DNS (推荐)**: 这是首选且最常用的方式。每个 `Service` 都会在集群内部的 DNS 服务中获得一个条目。一个 Pod 可以通过一个固定的 DNS 名称来访问另一个 `Service`。
    -   格式为: `<service-name>.<namespace-name>.svc.cluster.local`
    -   在同一个 `namespace` 内，可以直接使用 `<service-name>` 进行访问。

`Service` 是 Kubernetes 网络模型的核心，它解耦了 Pod 的短暂性与应用访问的稳定性，是构建健壮、可扩展微服务架构的基石。 