# 8. ConfigMaps：管理应用配置

在构建应用时，我们经常需要将配置与代码分离，以便在不同环境中（开发、测试、生产）使用不同的配置。硬编码配置信息到容器镜像中是一种反模式，因为它使得镜像变得僵化且难以管理。

Kubernetes 提供了 **ConfigMap** 对象，专门用于存储**非敏感的**配置数据。

## 8.1 什么是 ConfigMap？

**ConfigMap** 是一个用于存储键值对配置数据的 API 对象。它可以被 Pod 用来注入配置信息，从而实现配置与应用代码的解耦。

**核心思想**：将配置文件、命令行参数、环境变量等配置数据从容器镜像中分离出来，作为独立的 Kubernetes 对象进行管理。

**适用场景**：
- 存储应用的数据库地址、API 端点等。
- 存放完整的配置文件，如 `nginx.conf` 或 `application.properties`。
- 为 Pod 设置环境变量。

**重要提示**：ConfigMap 不适合存储敏感数据（如密码、API 密钥、证书）。对于这类信息，应该使用我们下一章将要学习的 **Secret**。ConfigMap 中的数据是**纯文本**存储的，没有加密。

## 8.2 创建 ConfigMap

有多种方式可以创建 ConfigMap。

### 方式一：从字面值创建

这种方式适合存储简单的键值对。

```bash
kubectl create configmap app-config \
  --from-literal=APP_COLOR=blue \
  --from-literal=APP_LOG_LEVEL=info
```

### 方式二：从文件创建

你可以将一个或多个文件作为键值对注入 ConfigMap。键是文件名，值是文件内容。

假设你有一个 `game.properties` 文件：
```properties
# game.properties
enemies=aliens
lives=3
```
和一个 `ui.properties` 文件：
```properties
# ui.properties
color.good=purple
color.bad=yellow
```

创建 ConfigMap:
```bash
kubectl create configmap game-config \
  --from-file=game.properties \
  --from-file=ui.properties
```

### 方式三：从 YAML 文件定义

这是最灵活、最推荐的声明式方法。

`app-configmap.yaml`:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config-yaml
data:
  # 类似 --from-literal
  APP_COLOR: "green"
  APP_LOG_LEVEL: "debug"

  # 类似 --from-file，键是自定义的，值是文件内容
  nginx.conf: |
    server {
      listen       80;
      server_name  localhost;

      location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
      }
    }
```
然后应用它：`kubectl apply -f app-configmap.yaml`

## 8.3 在 Pod 中使用 ConfigMap

将 ConfigMap 中的数据注入到 Pod 中主要有三种方式：

### 1. 作为环境变量注入

这是最常见的方式。你可以将 ConfigMap 中的特定键或所有键值对注入为 Pod 的环境变量。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: my-app-container
      image: busybox
      command: [ "/bin/sh", "-c", "env" ]
      env:
        # 注入单个键作为环境变量
        - name: LOG_LEVEL
          valueFrom:
            configMapKeyRef:
              name: app-config # ConfigMap 的名称
              key: APP_LOG_LEVEL # ConfigMap 中的键
      envFrom:
        # 将 ConfigMap 中所有的键值对都注入为环境变量
        - configMapRef:
            name: app-config
```

### 2. 作为命令行参数注入

这种方式比较少见，但有时也很有用。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: my-app-container
      image: busybox
      command: [ "echo" ]
      # 将 ConfigMap 的值作为命令的参数
      args:
        - "$(APP_COLOR_ARG)"
      env:
        - name: APP_COLOR_ARG
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: APP_COLOR
```

### 3. 作为文件挂载到卷中

这是最强大的方式，特别适合注入完整的配置文件。你可以将 ConfigMap 中的每个键值对作为一个文件挂载到 Pod 的指定目录中。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-nginx-pod
spec:
  containers:
    - name: nginx
      image: nginx
      volumeMounts:
        - name: nginx-conf-volume
          mountPath: /etc/nginx/conf.d # 将文件挂载到 nginx 的配置目录
  volumes:
    - name: nginx-conf-volume
      configMap:
        # ConfigMap 的名称
        name: app-config-yaml
        items:
          # 指定要挂载的键，并重命名文件
          - key: nginx.conf
            path: default.conf
```
在这个例子中，`app-config-yaml` ConfigMap 中的 `nginx.conf` 键对应的内容，会被创建为一个名为 `default.conf` 的文件，并存在于 Pod 的 `/etc/nginx/conf.d/` 目录下。

## 8.4 更新 ConfigMap

当你更新一个 ConfigMap 时，需要注意：
- 通过**环境变量**注入的配置**不会**自动更新。你需要重启 Pod 才能让新的配置生效。
- 通过**卷挂载**注入的配置**会**自动更新（通常在一分钟内）。Pod 内的应用需要有能力检测文件变化并重新加载配置。

这种差异是由于环境变量是在 Pod 启动时一次性注入的，而卷挂载是动态链接的。

## 8.5 总结

ConfigMap 是 Kubernetes 中管理非敏感配置数据的标准方式。它通过将配置与代码解耦，极大地提高了应用的灵活性和可移植性。我们学习了如何创建 ConfigMap，以及如何通过环境变量或卷挂载的方式将其注入到 Pod 中。

在下一章，我们将学习如何使用 **Secret** 来安全地管理密码、API 密钥等敏感信息。