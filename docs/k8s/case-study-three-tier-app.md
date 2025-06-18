# 案例研究：部署一个三层 Web 应用

本案例研究将引导你完成在 Kubernetes 集群上部署一个典型的三层 Web 应用程序的全过程。这个应用包含三个核心组件：

1.  **前端 (Frontend)**：一个基于 Nginx 的 Web 服务器，负责提供静态 Web 内容。
2.  **后端 (Backend)**：一个提供 RESTful API 的应用服务。
3.  **数据库 (Database)**：一个用于持久化存储数据的数据库。

通过这个案例，你将综合运用之前章节学到的多个 Kubernetes 核心概念。

---

### 1. 应用架构概览

我们的三层应用架构如下：

-   **用户流量** -> **Ingress** -> **前端 Service** -> **前端 Pods (Nginx)**
-   **前端 Pods** -> **后端 Service** -> **后端 Pods (API Server)**
-   **后端 Pods** -> **数据库 Service** -> **数据库 Pod (e.g., PostgreSQL)**

我们将使用以下 Kubernetes 资源来构建这个应用：

-   **Deployments**: 用于无状态的前端和后端服务。
-   **StatefulSet**: 用于有状态的数据库服务。
-   **Services**: 为每个层级提供稳定的网络端点。
-   **PersistentVolume (PV)** & **PersistentVolumeClaim (PVC)**: 为数据库提供持久化存储。
-   **ConfigMap**: 存储后端的非敏感配置，如数据库主机名。
-   **Secret**: 存储敏感数据，如数据库密码。
-   **Ingress**: 将外部 HTTP/HTTPS 流量路由到前端服务。
-   **NetworkPolicy**: 限制不同层级之间的网络通信，增强安全性。

---

### 2. 准备工作：命名空间

首先，我们为这个项目创建一个专用的命名空间，以便于管理和隔离资源。

```yaml
# 00-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: three-tier-app
```

应用此清单：`kubectl apply -f 00-namespace.yaml`

---

### 3. 第三层：数据库 (Database)

我们将使用 PostgreSQL 作为数据库。由于数据库是"有状态"的，我们使用 `StatefulSet` 来部署它，并为其配置持久化存储。

#### 3.1. 存储 (PV & PVC)

在生产环境中，通常使用 `StorageClass` 进行动态卷供应。为了简化，这里我们手动创建一个 `PersistentVolume`。

```yaml
# 01-database-pv.yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: db-pv
spec:
  capacity:
    storage: 1Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce # 只能被单个节点挂载
  hostPath: # 仅用于本地实验环境
    path: "/mnt/data/postgres"
```

> **注意**: `hostPath` 仅适用于单节点集群（如 Minikube），它将数据存储在宿主机节点的文件系统上。在多节点集群中，应使用网络存储解决方案（如 NFS, Ceph, or Cloud Provider's storage）。

接下来，创建 `PersistentVolumeClaim` 来请求存储。

```yaml
# 02-database-pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: db-pvc
  namespace: three-tier-app
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

#### 3.2. 敏感数据 (Secret)

为数据库创建一个 `Secret` 来存储用户名和密码。

```yaml
# 03-database-secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secret
  namespace: three-tier-app
type: Opaque
stringData: # 使用 stringData 更方便，Kubernetes 会自动进行 Base64 编码
  POSTGRES_USER: "admin"
  POSTGRES_PASSWORD: "mysecretpassword"
```

#### 3.3. StatefulSet 和 Service

现在，我们来定义数据库的 `StatefulSet` 和 `Service`。`StatefulSet` 确保了 Pod 拥有稳定的网络标识符和持久化存储。`Service` 为后端应用提供一个稳定的数据库连接地址。

```yaml
# 04-database-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: database
  namespace: three-tier-app
spec:
  serviceName: "db-service"
  replicas: 1
  selector:
    matchLabels:
      app: database
  template:
    metadata:
      labels:
        app: database
    spec:
      containers:
      - name: postgres
        image: postgres:13
        ports:
        - containerPort: 5432
        envFrom:
        - secretRef:
            name: db-secret
        volumeMounts:
        - name: db-data
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates: # StatefulSet 的一个关键特性
  - metadata:
      name: db-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 1Gi
```

```yaml
# 05-database-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: db-service # 后端将使用这个 DNS 名称来连接数据库
  namespace: three-tier-app
spec:
  ports:
  - port: 5432
    targetPort: 5432
  selector:
    app: database
  clusterIP: None # 创建一个 Headless Service，直接解析到 Pod IP
```

---

### 4. 第二层：后端 (Backend)

后端是一个 API 服务，它连接到数据库并处理业务逻辑。

#### 4.1. 配置 (ConfigMap)

使用 `ConfigMap` 存储数据库的主机名。

```yaml
# 06-backend-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: backend-config
  namespace: three-tier-app
data:
  DB_HOST: "db-service.three-tier-app.svc.cluster.local" # 数据库 Service 的 FQDN
```

#### 4.2. Deployment 和 Service

使用 `Deployment` 部署后端应用，并创建一个 `ClusterIP` 类型的 `Service`，使其能被前端访问。

```yaml
# 07-backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: backend
  namespace: three-tier-app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: backend
  template:
    metadata:
      labels:
        app: backend
    spec:
      containers:
      - name: backend-api
        image: your-backend-api-image:latest # 替换成你自己的后端镜像
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: backend-config
        - secretRef:
            name: db-secret
        env: # 添加额外的环境变量
        - name: DB_NAME
          value: "mydatabase" # 假设的数据库名
```

```yaml
# 08-backend-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: backend-service
  namespace: three-tier-app
spec:
  type: ClusterIP # 仅在集群内部可访问
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: backend
```

---

### 5. 第一层：前端 (Frontend)

前端是一个 Nginx 服务器，它处理外部用户的请求，并将 API 请求代理到后端服务。

#### 5.1. Deployment 和 Service

```yaml
# 09-frontend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: three-tier-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
      - name: nginx
        image: nginx:latest # 可以基于此镜像构建并包含你的静态文件和 nginx 配置
        ports:
        - containerPort: 80
```

> **提示**: 在实际项目中，你需要创建一个自定义的 Nginx 镜像，其中包含一个配置文件 (`nginx.conf`)，用于将 `/api` 等路径的请求反向代理到 `http://backend-service`。

```yaml
# 10-frontend-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: frontend-service
  namespace: three-tier-app
spec:
  type: ClusterIP # 我们将通过 Ingress 暴露它
  ports:
  - port: 80
    targetPort: 80
  selector:
    app: frontend
```

---

### 6. 暴露应用 (Ingress)

现在，我们使用 `Ingress` 将前端服务暴露给外部世界。

```yaml
# 11-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: app-ingress
  namespace: three-tier-app
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
spec:
  rules:
  - host: my-app.example.com # 替换成你的域名
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: frontend-service
            port:
              number: 80
```

> **前提**: 你的集群中必须已经安装并运行了 Ingress Controller（如 NGINX Ingress Controller）。

---

### 7. 安全加固 (NetworkPolicy)

最后，我们定义 `NetworkPolicy` 来限制 Pod 之间的通信，遵循最小权限原则。

#### 7.1. 默认拒绝所有流量

首先，在命名空间内设置一个策略，默认拒绝所有 Ingress (入站) 流量。

```yaml
# 12-netpol-default-deny.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: three-tier-app
spec:
  podSelector: {} # 选择命名空间中的所有 Pod
  policyTypes:
  - Ingress
```

#### 7.2. 定义允许的流量

现在，我们精确地定义允许的流量：

1.  **允许外部流量通过 Ingress Controller 进入前端**
2.  **允许前端访问后端**
3.  **允许后端访问数据库**

```yaml
# 13-netpol-allow-traffic.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-traffic
  namespace: three-tier-app
spec:
  # 目标：前端 Pods
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Ingress
  ingress:
    # 来源：允许来自 Ingress Controller 的流量
    - from:
      - namespaceSelector: # 通常 Ingress Controller 在自己的命名空间
          matchLabels:
            name: ingress-nginx
      - podSelector:
          matchLabels:
            app.kubernetes.io/name: ingress-nginx
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: three-tier-app
spec:
  # 目标：后端 Pods
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
    # 来源：只允许来自前端 Pods 的流量
    - from:
      - podSelector:
          matchLabels:
            app: frontend
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-backend-to-db
  namespace: three-tier-app
spec:
  # 目标：数据库 Pods
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
    # 来源：只允许来自后端 Pods 的流量
    - from:
      - podSelector:
          matchLabels:
            app: backend
```

---

### 8. 部署与验证

将以上所有 YAML 文件保存后，按顺序在 `three-tier-app` 命名空间中创建资源：

1.  `kubectl apply -f 00-namespace.yaml`
2.  `kubectl apply -f . -n three-tier-app` (在包含所有其他 yaml 文件的目录中运行)

使用以下命令检查部署状态：

-   `kubectl get all -n three-tier-app`
-   `kubectl get pvc -n three-tier-app`
-   `kubectl get ingress -n three-tier-app`

当所有 Pods 都处于 `Running` 状态，并且 Ingress 获取到外部 IP 地址后，你就可以通过配置的域名 (`my-app.example.com`) 访问你的三层应用了。

这个案例研究展示了如何将在 Kubernetes 中学习到的各种资源组合起来，以构建一个健壮、可扩展且安全的应用程序。 