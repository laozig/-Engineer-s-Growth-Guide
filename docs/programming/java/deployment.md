# 部署与容器化: Docker, Kubernetes (K8s)

开发完成后，下一步是将应用程序部署到生产环境，使其能够为最终用户提供服务。传统的部署方式（如将 WAR/JAR 包手动复制到服务器上）存在环境不一致、扩展性差和管理困难等问题。

现代云原生应用的部署标准是 **容器化 (Containerization)**，而 **Docker** 和 **Kubernetes** 是这个领域无可争议的王者。

---

## 1. Docker：将应用打包成容器

**Docker** 是一个开源平台，用于开发、发布和运行应用程序。它允许你将应用程序及其所有依赖（库、运行时、系统工具等）打包到一个称为 **容器 (Container)** 的标准化单元中。

-   **镜像 (Image)**: 一个轻量级的、独立的、可执行的软件包，包含了运行应用程序所需的一切。镜像是只读的模板。
-   **容器 (Container)**: 镜像的运行时实例。你可以启动、停止、移动或删除容器。容器与主机系统和其他容器隔离。

**为什么使用 Docker？**
-   **环境一致性**: "在我机器上能跑"的问题成为历史。容器确保了开发、测试和生产环境的完全一致。
-   **快速部署**: 容器可以在几秒钟内启动。
-   **资源隔离**: 容器使用 Linux 内核的 cgroups 和 namespaces 技术，提供了进程级别的隔离，比虚拟机更轻量、更高效。
-   **可移植性**: 容器可以在任何支持 Docker 的机器上运行，无论是物理机、虚拟机还是云服务器。

### 1.1. 为 Spring Boot 应用创建 Dockerfile

`Dockerfile` 是一个文本文件，包含了一系列用于构建 Docker 镜像的指令。

```dockerfile
# 阶段1：使用 Maven 构建应用
# 使用一个包含 JDK 和 Maven 的基础镜像
FROM maven:3.8.4-openjdk-11 AS build
WORKDIR /app
# 复制 pom.xml 并下载依赖，利用 Docker 的层缓存机制
COPY pom.xml .
RUN mvn dependency:go-offline
# 复制源代码并打包
COPY src ./src
RUN mvn package -DskipTests

# 阶段2：构建最终的运行镜像
# 使用一个非常小的仅包含 JRE 的基础镜像
FROM openjdk:11-jre-slim
WORKDIR /app
# 从构建阶段复制打包好的 JAR 文件
COPY --from=build /app/target/*.jar app.jar
# 暴露应用端口
EXPOSE 8080
# 容器启动时执行的命令
ENTRYPOINT ["java", "-jar", "app.jar"]
```
这个示例使用了 **多阶段构建 (Multi-stage build)**，这是一个最佳实践。它能确保最终的生产镜像非常小，只包含运行应用所需的 JRE 和 JAR 文件，而不包含构建时需要的 JDK、Maven 等工具，从而减小了镜像体积和安全风险。

### 1.2. 构建和运行 Docker 镜像

```bash
# 构建镜像
# -t my-app:latest  给镜像打上标签 (tag)
docker build -t my-app:latest .

# 运行容器
# -p 8080:8080 将主机的 8080 端口映射到容器的 8080 端口
# -d           在后台运行容器
docker run -p 8080:8080 -d my-app:latest
```

---

## 2. Kubernetes (K8s)：容器编排与管理

当你的应用由多个微服务组成时，手动管理成百上千个容器的部署、扩展、网络和健康状况是不现实的。这时就需要一个 **容器编排 (Container Orchestration)** 系统。

**Kubernetes** (常简写为 K8s) 是一个开源的容器编排平台，最初由 Google 设计。它自动化了容器化应用的部署、扩展和管理。

### 2.1. 核心概念

-   **Cluster (集群)**: 一个 Kubernetes 集群由多个 **Node (节点)** 组成。Node 是运行容器的工作机器（可以是物理机或虚拟机）。
    -   **Control Plane (控制平面)**: 集群的大脑，负责管理整个集群的状态。
    -   **Worker Nodes (工作节点)**: 负责运行实际的应用容器。
-   **Pod**: Kubernetes 中 **最小的部署单元**。一个 Pod 封装了一个或多个紧密相关的容器、存储资源和唯一的网络 IP。通常，一个 Pod 只运行一个容器。
-   **Deployment**: 用于 **声明式地** 管理 Pod。你告诉 Deployment 你希望运行哪个镜像的多少个副本 (Replica)，Deployment 会确保这个状态得以维持。如果一个 Pod 崩溃了，Deployment 会自动创建一个新的来替代它。
-   **Service**: 为一组功能相同的 Pod 提供一个 **稳定的网络端点** (一个固定的 IP 地址和 DNS 名称)。由于 Pod 是短暂的，它们的 IP 地址会变化，Service 解决了服务发现和负载均衡的问题。
-   **Ingress**: 管理从集群 **外部** 到集群内部 Service 的 HTTP/HTTPS 访问。它可以提供负载均衡、SSL 终止和基于名称的虚拟主机。
-   **ConfigMap / Secret**: 用于将配置和敏感数据（如密码、API 密钥）从应用镜像中分离出来，并注入到容器中。

### 2.2. 为 Spring Boot 应用创建 Kubernetes 部署文件

Kubernetes 的配置通常使用 YAML 文件来定义。

```yaml
# deployment.yaml

# 1. Deployment: 定义如何运行你的应用 Pod
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app-deployment
spec:
  replicas: 3 # 期望运行 3 个 Pod 副本
  selector:
    matchLabels:
      app: my-app
  template: # Pod 的模板
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app-container
        image: my-app:latest # 使用之前构建的 Docker 镜像
        ports:
        - containerPort: 8080

---
# 2. Service: 为上面的 3 个 Pod 提供一个统一的访问入口
apiVersion: v1
kind: Service
metadata:
  name: my-app-service
spec:
  selector:
    app: my-app # 选择所有带有 app=my-app 标签的 Pod
  ports:
    - protocol: TCP
      port: 80 # Service 暴露的端口
      targetPort: 8080 # 流量转发到 Pod 的端口
  type: LoadBalancer # (在云环境中) 会创建一个外部负载均衡器来暴露服务
```

### 2.3. 部署到 Kubernetes

```bash
# 应用 YAML 文件来创建/更新资源
kubectl apply -f deployment.yaml

# 查看 Pod 状态
kubectl get pods

# 查看 Service 状态，获取外部 IP 地址
kubectl get service my-app-service

# 更新部署 (例如，更新镜像版本)
# 1. 修改 deployment.yaml 中的 image: my-app:v2
# 2. 重新应用配置
kubectl apply -f deployment.yaml
# Kubernetes 会自动进行滚动更新 (Rolling Update)，保证服务不中断

# 扩展应用
kubectl scale deployment my-app-deployment --replicas=5
```

Docker 和 Kubernetes 的结合为现代 Java 应用的开发、部署和运维提供了一套强大而标准化的流程，是云原生时代开发者必备的技能。
