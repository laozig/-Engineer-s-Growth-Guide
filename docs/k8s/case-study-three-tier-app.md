# 案例研究：部署一个三层 Web 应用

本案例研究将引导您完成在 Kubernetes 上部署一个经典的三层架构（Three-Tier）Web 应用程序的完整过程。这个应用包含：

1.  **前端 (Frontend)**：一个基于 Nginx 的 React 应用，负责用户界面。
2.  **后端 (Backend)**：一个 Node.js API 服务器，负责处理业务逻辑。
3.  **数据库 (Database)**：一个 MongoDB 数据库，负责数据存储。

我们将为每一层创建 Kubernetes `Deployment` 和 `Service`，并使用 `ConfigMap` 和 `Secret` 来管理配置。

## 先决条件

- 一个正在运行的 Kubernetes 集群（如 Minikube, kind, Docker Desktop）。
- `kubectl` 已配置并连接到您的集群。

## 架构图

```
+----------------+      +------------------+      +----------------+
|   用户 (User)  | ---> | Ingress/LB Service | ---> | 前端 (Frontend)  |
+----------------+      +------------------+      +----------------+
                                                         |
                                                         v
                                                  +----------------+
                                                  | 后端 (Backend)   |
                                                  +----------------+
                                                         |
                                                         v
                                                  +----------------+
                                                  | 数据库 (Database)|
                                                  +----------------+
```

## 第一步：创建命名空间

为了保持资源隔离，我们首先创建一个新的命名空间。

```bash
kubectl create namespace three-tier-app
```

## 第二步：部署数据库层 (Database Tier)

我们将从部署 MongoDB 数据库开始。

### 1. 创建 Secret

数据库密码不应该硬编码在 YAML 文件中。我们使用 `Secret` 来存储它。

`mongodb-secret.yaml`
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mongodb-secret
  namespace: three-tier-app
type: Opaque
data:
  # 密码 "admin123" 经过 Base64 编码
  mongo-root-password: YWRtaW4xMjM=
```

应用它：`kubectl apply -f mongodb-secret.yaml`

### 2. 创建 Deployment 和 Service

`mongodb-deployment.yaml`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mongodb-deployment
  namespace: three-tier-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mongodb
  template:
    metadata:
      labels:
        app: mongodb
    spec:
      containers:
      - name: mongodb
        image: mongo:5.0
        ports:
        - containerPort: 27017
        env:
        - name: MONGO_INITDB_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mongodb-secret
              key: mongo-root-password
---
apiVersion: v1
kind: Service
metadata:
  name: mongodb-service
  namespace: three-tier-app
spec:
  selector:
    app: mongodb
  ports:
  - protocol: TCP
    port: 27017
    targetPort: 27017
```

- **Deployment**: 部署一个包含 MongoDB 5.0 镜像的 Pod。它通过 `env` 从我们创建的 `Secret` 中获取 root 密码。
- **Service**: 创建一个名为 `mongodb-service` 的 `ClusterIP` 服务。这使得集群内的其他 Pod 可以通过 DNS 名称 `mongodb-service.three-tier-app.svc.cluster.local` 或简写 `mongodb-service` 来访问数据库。

应用它：`kubectl apply -f mongodb-deployment.yaml`

## 第三步：部署后端层 (Backend Tier)

现在部署 Node.js API 服务器。

### 1. 创建 ConfigMap

我们将数据库连接字符串存储在 `ConfigMap` 中。

`backend-configmap.yaml`
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: backend-configmap
  namespace: three-tier-app
data:
  database_url: "mongodb://root:admin123@mongodb-service:27017"
```

应用它：`kubectl apply -f backend-configmap.yaml`

### 2. 创建 Deployment 和 Service

`backend-deployment.yaml`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend-deployment
  namespace: three-tier-app
spec:
  replicas: 2 # 部署两个实例以实现高可用
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: backend
        # 这是一个示例镜像，你需要替换成你自己的后端应用镜像
        image: your-repo/three-tier-backend:1.0 
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            configMapKeyRef:
              name: backend-configmap
              key: database_url
---
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: three-tier-app
spec:
  selector:
    app: backend
  ports:
  - protocol: TCP
    port: 8080
    targetPort: 8080
```

- **Deployment**: 部署后端应用。它从 `ConfigMap` 中读取数据库 URL。
- **Service**: 创建一个 `ClusterIP` 服务，供前端访问。

应用它：`kubectl apply -f backend-deployment.yaml`

## 第四步：部署前端层 (Frontend Tier)

最后，我们部署 React 前端。

### 1. 创建 Deployment 和 Service

`frontend-deployment.yaml`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend-deployment
  namespace: three-tier-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: frontend
        # 这是一个示例镜像，你需要替换成你自己的前端应用镜像
        image: your-repo/three-tier-frontend:1.0
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: frontend-service
  namespace: three-tier-app
spec:
  selector:
    app: frontend
  ports:
  - protocol: TCP
    port: 80
    targetPort: 80
  # 将类型改为 NodePort 或 LoadBalancer 以便从外部访问
  type: NodePort 
```

- **Deployment**: 部署前端应用。
- **Service**: 创建一个 `NodePort` 类型的服务。这会使前端应用在集群的每个节点上暴露一个端口，从而允许外部访问。在生产环境中，您可能会使用 `LoadBalancer` 类型的服务或 `Ingress`。

应用它：`kubectl apply -f frontend-deployment.yaml`

## 第五步：验证部署

1.  **检查 Pod 状态**：
    `kubectl get pods -n three-tier-app`
    确保所有 Pod 都处于 `Running` 状态。

2.  **检查 Service**：
    `kubectl get services -n three-tier-app`
    找到 `frontend-service` 的 `NodePort`。

3.  **访问应用**：
    通过 `<NodeIP>:<NodePort>` 在浏览器中访问您的应用。如果您使用的是 Minikube，可以运行 `minikube service frontend-service -n three-tier-app` 来直接在浏览器中打开它。

这个案例研究展示了如何使用 Kubernetes 的核心组件来部署一个功能完整的应用程序，同时遵循了配置和密钥管理的最佳实践。 