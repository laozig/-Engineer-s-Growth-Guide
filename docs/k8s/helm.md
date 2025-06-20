# Helm：Kubernetes 包管理器

Helm 是 Kubernetes 的一个开源包管理器，它能帮助您轻松地定义、安装、升级和管理最复杂的 Kubernetes 应用程序。Helm 将应用程序打包成一种称为 **Chart** 的格式，其中包含了部署应用所需的所有资源定义、配置和依赖项。

## 为什么需要 Helm？

直接使用 `kubectl` 和 YAML 文件来管理 Kubernetes 应用时，您可能会遇到以下挑战：

- **重复的 YAML**：为不同的环境（如开发、测试、生产）管理多套几乎相同的 YAML 文件。
- **配置管理复杂**：难以跟踪和管理应用程序的配置变更。
- **发布和回滚困难**：手动执行发布、升级和回滚操作既繁琐又容易出错。
- **缺乏依赖管理**：如果您的应用依赖于其他服务（如数据库或消息队列），您需要手动管理这些依赖的部署。

Helm 通过以下核心概念解决了这些问题。

## 核心概念

### 1. Chart

**Chart** 是 Helm 的打包格式。它是一个包含了描述一组相关 Kubernetes 资源文件的目录。一个 Chart 可能很简单，只用于部署一个服务（如 Memcached），也可能很复杂，用于部署一个完整的多层 Web 应用（如包含 Web 服务器、数据库、缓存等）。

一个典型的 Chart 目录结构如下：

```
my-chart/
├── Chart.yaml        # 包含 Chart 的元数据，如名称、版本、描述
├── values.yaml       # Chart 的默认配置值
├── templates/        # 存放 Kubernetes 资源模板文件的目录
│   ├── deployment.yaml
│   ├── service.yaml
│   └── ...
└── charts/           # 存放此 Chart 所依赖的其他 Chart 的目录 (子 Chart)
```

### 2. Release

当一个 **Chart** 被安装到 Kubernetes 集群中时，它就创建了一个 **Release**。Release 是 Chart 在集群中的一个运行实例。每次对 Chart 进行升级或回滚时，都会创建一个新的 Release 版本。

### 3. Repository

**Repository** (仓库) 是用于存储和分享 Chart 的地方。您可以将自己打包的 Chart 上传到仓库，也可以从仓库中搜索和下载他人分享的 Chart。

## Helm 基本操作

假设您已经安装了 Helm CLI 并配置了对 Kubernetes 集群的访问。

### 1. 安装一个 Chart

您可以从公共仓库（如 Artifact Hub）安装一个 Chart。例如，安装 `stable/mysql` Chart：

```bash
# 1. 添加仓库
helm repo add bitnami https://charts.bitnami.com/bitnami

# 2. 搜索 Chart
helm search repo mysql

# 3. 安装 Chart
# 这会在集群中创建一个名为 "my-mysql" 的 Release
helm install my-mysql bitnami/mysql --version 8.8.22
```

### 2. 自定义安装

通常您需要根据环境自定义 Chart 的配置。可以通过 `--set` 参数或自定义 `values.yaml` 文件来实现。

**使用 `--set`**：

```bash
helm install my-mysql bitnami/mysql --set auth.rootPassword=secretpassword
```

**使用自定义 `values.yaml` 文件**：

创建一个 `my-values.yaml` 文件：

```yaml
# my-values.yaml
auth:
  rootPassword: "anothersecret"
```

然后安装：

```bash
helm install my-mysql bitnami/mysql -f my-values.yaml
```

### 3. 查看已安装的 Release

```bash
helm list
# 或者简写
helm ls
```

### 4. 升级一个 Release

当您需要更改已部署应用的配置或更新到新版本的 Chart 时，使用 `helm upgrade`。

```bash
helm upgrade my-mysql bitnami/mysql --set persistence.enabled=true
```

### 5. 回滚一个 Release

如果升级后出现问题，可以轻松回滚到之前的版本。

```bash
# 1. 查看 Release 的历史版本
helm history my-mysql

# 2. 回滚到上一个版本 (版本号为 1)
helm rollback my-mysql 1
```

### 6. 卸载一个 Release

```bash
helm uninstall my-mysql
```

## 创建自己的 Chart

您也可以轻松地为自己的应用程序创建 Chart。

```bash
# 创建一个名为 "my-app" 的 Chart 骨架
helm create my-app
```

这会生成一个包含标准目录和示例文件的 `my-app` 目录。您可以在 `templates/` 目录中修改或添加 Kubernetes 资源定义，并在 `values.yaml` 中定义可配置的参数。

模板文件使用 Go 模板语言，允许您通过 `{{ .Values.someValue }}` 的方式引用 `values.yaml` 中的值，从而实现配置的参数化。

Helm 极大地简化了 Kubernetes 上的应用生命周期管理，是 DevOps 工具链中不可或缺的一环。 