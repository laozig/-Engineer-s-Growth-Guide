# 8. ConfigMaps：管理应用配置

在构建容器化应用时，一个核心的最佳实践是：**将配置与应用代码分离**。硬编码配置（如数据库地址、API URL、功能开关等）到容器镜像中会带来许多问题：
-   **灵活性差**: 同一个镜像无法不经修改就用于开发、测试和生产环境。
-   **维护困难**: 每次配置变更都需要重新构建和推送镜像。
-   **透明度低**: 无法直观地了解一个正在运行的应用使用了哪些配置。

为了解决这个问题，Kubernetes 提供了 `ConfigMap`。

## 什么是 ConfigMap？

`ConfigMap` 是一个 Kubernetes API 对象，用于存储**非敏感**的配置数据。它允许你将配置信息从 Pod 的定义中解耦出来，实现配置的集中管理和动态注入。

数据在 `ConfigMap` 中以**键值对 (key-value pairs)** 的形式存储。值可以是简短的字符串，也可以是完整的配置文件内容。

> **重要提示**: `ConfigMap` 不提供加密或保密性。对于存储敏感数据（如密码、API 密钥、证书），你应该使用 `Secret` 对象，我们将在下一章讨论。

## 创建 ConfigMap

你可以通过 `kubectl` 命令式地创建，也可以通过 YAML 文件声明式地创建。

### 1. 从字面值 (Literal) 创建

```bash
kubectl create configmap app-config \
  --from-literal=APP_COLOR=blue \
  --from-literal=APP_GREETING="Hello World"
```
这个命令创建了一个名为 `app-config` 的 ConfigMap，包含两个键：`APP_COLOR` 和 `APP_GREETING`。

### 2. 从文件 (File) 创建

假设你有一个配置文件 `app.properties`:
```properties
# app.properties
APP_ENV=production
ENABLE_FEATURE_X=true
```
你可以用这个文件创建一个 ConfigMap：
```bash
# --from-file 会使用文件名作为 key，文件内容作为 value
kubectl create configmap app-config-from-file --from-file=app.properties

# 你也可以指定一个 key
kubectl create configmap app-config-from-file-key --from-file=custom-key=app.properties
```

### 3. 从 YAML 文件创建 (声明式)

这是在 GitOps 流程中最推荐的方式。

`my-configmap.yaml`:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config-yaml
data:
  # 键值对形式
  APP_COLOR: "green"
  APP_GREETING: "Namaste"
  # 也可以嵌入多行文件内容
  my-config-file.conf: |
    server {
        listen      80;
        server_name example.com;
    }
```
然后使用 `kubectl apply -f my-configmap.yaml` 创建。

## 在 Pod 中使用 ConfigMap

创建了 `ConfigMap` 之后，有三种主要的方式将数据注入到你的 Pod 中。

### 方式一：作为环境变量注入

你可以将 `ConfigMap` 中的一个或多个键值对作为环境变量注入到容器中。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-env
spec:
  containers:
  - name: my-container
    image: busybox
    command: [ "/bin/sh", "-c", "env" ]
    env:
      # 将 app-config-yaml 中 APP_COLOR 的值注入到环境变量 MY_APP_COLOR
      - name: MY_APP_COLOR
        valueFrom:
          configMapKeyRef:
            name: app-config-yaml # ConfigMap 的名称
            key: APP_COLOR     # 要引用的 key
    envFrom:
      # 将 app-config-yaml 中所有的键值对都注入为环境变量
      - configMapRef:
          name: app-config-yaml
```

### 方式二：作为命令行参数注入

这是方式一的变种。你首先将 `ConfigMap` 数据注入为环境变量，然后在容器的启动命令 (`command` 或 `args`) 中引用这些环境变量。

```yaml
# ...
spec:
  containers:
  - name: my-container
    image: my-app
    command: [ "app-binary", "--color=$(MY_APP_COLOR)" ] # 引用环境变量
    env:
      - name: MY_APP_COLOR
        valueFrom:
          configMapKeyRef:
            name: app-config-yaml
            key: APP_COLOR
```

### 方式三：作为文件挂载到卷中 (最常用)

这是最强大和灵活的方式。你可以将整个 `ConfigMap` 或其中的特定键挂载为一个卷，容器中的应用就可以像读取本地文件一样读取配置。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-volume
spec:
  containers:
  - name: my-container
    image: busybox
    command: [ "/bin/sh", "-c", "ls -l /etc/config && sleep 3600" ]
    volumeMounts:
    - name: config-volume
      mountPath: /etc/config # 挂载到容器的路径
  volumes:
  - name: config-volume
    configMap:
      # ConfigMap 的名称
      name: app-config-yaml
      # 可选：指定哪些 key 应该被创建为文件
      items:
      - key: APP_GREETING
        path: greeting.txt # 文件名为 greeting.txt
      - key: my-config-file.conf
        path: my.conf      # 文件名为 my.conf
```
-   当 Pod 启动后，你可以在容器的 `/etc/config` 目录下看到 `greeting.txt` 和 `my.conf` 两个文件。
-   **热更新**: 通过这种方式挂载的配置，当 `ConfigMap` 本身被更新后，卷中的文件内容**通常会**在短时间内自动更新，应用无需重启。但这需要应用本身能够检测配置文件的变更并重新加载。

通过 `ConfigMap`，你可以将环境相关的配置与你的应用逻辑完全分离，使得你的应用镜像更加通用和可移植。 