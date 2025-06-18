# 18. Helm：Kubernetes 包管理器

随着我们应用规模的增长，部署一个应用可能需要管理一大堆 Kubernetes YAML 文件：一个 `Deployment`，一个 `Service`，一个 `Ingress`，再加上几个 `ConfigMap` 和 `Secret`。

手动管理这些文件会遇到很多问题：
-   **重复性**: 为开发、测试、生产等不同环境维护多套几乎相同的 YAML 文件，只是其中几个值（如镜像标签、副本数、域名）不同。
-   **复杂性**: 更新应用时，需要手动追踪和应用所有相关的 YAML 文件，很容易出错。
-   **难以分发和共享**: 如何将这一整套复杂的应用打包，并让其他人能够一键安装？

为了解决这些问题，社区创造了 **Helm**。

## 什么是 Helm？

Helm 被称为 **"Kubernetes 的包管理器"**。

你可以把它类比成 Linux 系统中的 `apt` 或 `yum`，或者 Node.js 中的 `npm`。`apt` 用来管理 `.deb` 包，`npm` 用来管理 `node_modules`，而 Helm 则用来管理 **Kubernetes 应用**。

Helm 允许你将运行一个应用所需的所有 Kubernetes 资源打包、配置、分发和版本化。

## Helm 的核心概念

要理解 Helm，需要先了解三个核心概念：

1.  **`Chart` (图表)**:
    -   这是 Helm 的打包格式。一个 `Chart` 就是一个**目录**，它包含了运行一个应用（例如 WordPress, Redis, 或你自己的应用）所需的所有 Kubernetes 资源定义的**模板**、**默认配置**和**元数据**。

2.  **`Release` (发布)**:
    -   一个 `Release` 是一个 `Chart` 在 Kubernetes 集群中的一次**部署实例**。
    -   你可以将同一个 `Chart` 在同一个集群中安装多次，每次安装都会创建一个新的 `Release`。例如，你可以用 WordPress `Chart` 安装两个独立的博客网站，它们就是两个不同的 `Release`。

3.  **`Repository` (仓库)**:
    -   `Repository` 是用来存放和分发 `Chart` 的地方。它就是一个简单的 HTTP 服务器，上面存放着打包好的 `Chart` 文件。
    -   你可以添加公共的 `Repository`（如 Bitnami, Artifact Hub），也可以创建自己的私有仓库。

## Chart 的目录结构

一个典型的 `Chart` 目录看起来是这样的：
```
my-app-chart/
├── Chart.yaml          # 必需。包含 Chart 的元数据（名称，版本等）。
├── values.yaml         # 必需。为模板提供默认的配置值。
├── templates/          # 必需。存放所有 K8s 资源定义的模板文件。
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── ingress.yaml
│   └── _helpers.tpl    # 可选。存放可重用的模板片段。
└── charts/             # 可选。存放此 Chart 依赖的其他 Charts (子图表)。
```

-   **`Chart.yaml`**:
    ```yaml
    apiVersion: v2
    name: my-app-chart
    description: A Helm chart for my awesome application
    type: application
    version: 0.1.0 # 这是 Chart 的版本
    appVersion: "1.0.0" # 这是你的应用的版本
    ```
-   **`values.yaml`**: 这是实现 `Chart` 可配置性的关键。它定义了所有可以在模板中使用的变量的**默认值**。
    ```yaml
    replicaCount: 1
    image:
      repository: nginx
      pullPolicy: IfNotPresent
      tag: "" # 默认使用 Chart 的 appVersion
    service:
      type: ClusterIP
      port: 80
    ingress:
      enabled: false
      className: ""
      hosts:
        - host: chart-example.local
          paths:
            - path: /
              pathType: ImplementationSpecific
    ```
-   **`templates/`**: 这个目录下的所有 YAML 文件都会被 Helm 的模板引擎处理。
    在模板文件中，你可以使用 **Go 模板语言**来引用 `values.yaml` 中定义的值。

    例如，`templates/deployment.yaml` 可能是这样的：
    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: {{ .Release.Name }}-deployment
    spec:
      replicas: {{ .Values.replicaCount }} # 引用 values.yaml 中的 replicaCount
      template:
        spec:
          containers:
            - name: my-app
              image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}" # 引用镜像仓库和标签
              ports:
                - containerPort: {{ .Values.service.port }}
    ```

## Helm 的工作流程

1.  **打包和模板化**: Helm 将 `templates/` 目录中的模板文件和 `values.yaml` 中的值结合起来，生成最终的、可部署的 Kubernetes YAML 清单。
2.  **可配置安装**: 在安装时，你可以覆盖 `values.yaml` 中的默认值，从而为不同环境定制部署。
    ```bash
    # 使用默认值安装
    helm install my-release ./my-app-chart

    # 在安装时覆盖值
    helm install my-prod-release ./my-app-chart --set replicaCount=3 --set image.tag="1.2.0"

    # 使用一个自定义的 values 文件来覆盖
    # prod-values.yaml:
    # replicaCount: 5
    # ingress:
    #   enabled: true
    helm install my-prod-release-2 ./my-app-chart -f prod-values.yaml
    ```
3.  **生命周期管理**: Helm 会跟踪由它创建的所有资源，并将它们组合成一个 `Release`。这使得升级、回滚和卸载变得非常简单。

## 常用 Helm 命令

```bash
# 添加一个 Chart 仓库
helm repo add bitnami https://charts.bitnami.com/bitnami

# 更新仓库信息
helm repo update

# 搜索一个 Chart
helm search repo wordpress

# 安装一个 Chart (创建一个 Release)
helm install my-wordpress bitnami/wordpress

# 列出所有已部署的 Releases
helm list

# 升级一个 Release
helm upgrade my-wordpress bitnami/wordpress --set service.type=LoadBalancer

# 查看一个 Release 的历史版本
helm history my-wordpress

# 回滚到一个历史版本
helm rollback my-wordpress 1

# 卸载一个 Release (会删除由它创建的所有 K8s 资源)
helm uninstall my-wordpress
```

通过将 Kubernetes 应用"Chart化"，Helm 极大地提高了部署的标准化、可配置性和可重用性，是 Kubernetes 生态系统中不可或beta的部分。 