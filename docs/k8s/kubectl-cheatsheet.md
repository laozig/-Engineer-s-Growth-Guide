# 3. kubectl 核心命令速查

`kubectl` 是 Kubernetes 的瑞士军刀，是你与集群API服务器交互的主要命令行工具。熟练掌握它将极大地提高你的工作效率。本章提供了一个常用命令的速查表，供日常参考。

## 基本语法

`kubectl` 的命令遵循一个通用格式：
`kubectl [command] [TYPE] [NAME] [flags]`

-   **command**: 要执行的操作，如 `get`, `describe`, `delete`。
-   **TYPE**: 资源类型，如 `pod`, `node`, `service`。资源类型不区分大小写，可以使用单数、复数或简写形式（如 `po` 代表 `pod`）。
-   **NAME**: 资源的名称。如果省略，则显示该类型的所有资源。
-   **flags**: 可选的标志，如 `-n` 指定命名空间，`-o wide` 提供更多输出信息。

> **小技巧**: 使用 `kubectl explain [TYPE]` 可以查看该资源类型的 YAML 字段文档。例如: `kubectl explain pod.spec.containers`。

---

## 1. 上下文与配置 (Context & Config)

当你在多个环境（如开发、测试、生产）中工作时，需要管理不同的集群配置。`kubectl` 通过"上下文 (context)"来实现这一点。

```bash
# 查看所有定义的上下文
kubectl config get-contexts

# 显示当前使用的上下文
kubectl config current-context

# 切换到另一个上下文
kubectl config use-context <context-name>

# 查看当前配置的摘要信息
kubectl config view
```

---

## 2. 查看资源 (Viewing Resources)

这是最常用的命令分组，用于检查集群的状态。

```bash
# 获取所有 Pods
kubectl get pods

# 获取所有 Pods，并显示更详细的信息 (如 IP, 所在节点)
kubectl get pods -o wide

# 获取名为 "my-pod" 的 Pod 的 YAML 定义
kubectl get pod my-pod -o yaml

# 获取所有命名空间 (Namespace)
kubectl get namespaces
# 简写: kubectl get ns

# 获取特定命名空间下的所有 Pods
kubectl get pods -n <namespace-name>

# 获取所有资源 (适用于所有类型)
kubectl get all # 注意: "all" 并不真的包含所有资源类型，但涵盖了最核心的

# 显示名为 "my-pod" 的 Pod 的详细信息 (包括事件和状态)
kubectl describe pod my-pod

# 显示节点 "worker-node-1" 的详细信息
kubectl describe node worker-node-1
```

---

## 3. 创建、应用与删除资源 (Creating, Applying & Deleting)

```bash
# -- 声明式管理 (推荐) --
# 从 my-app.yaml 文件创建或更新资源
kubectl apply -f my-app.yaml

# -- 命令式管理 --
# 根据 my-pod.yaml 文件创建资源
kubectl create -f my-pod.yaml

# 创建一个名为 "my-deployment" 的 Deployment，使用 nginx 镜像
kubectl create deployment my-deployment --image=nginx

# 删除名为 "my-pod" 的 Pod
kubectl delete pod my-pod

# 根据 my-app.yaml 文件中定义的名称和类型删除资源
kubectl delete -f my-app.yaml
```

**`apply` vs `create`**:
-   `apply` 是声明式的：它会根据你提供的 YAML 文件更新资源，只修改有差异的部分。如果资源不存在，它会创建它。这是 GitOps 和自动化流程中的首选。
-   `create` 是命令式的：它只用于创建新资源。如果资源已存在，它会报错。

---

## 4. 更新与部署管理 (Updating & Rollouts)

```bash
# 直接在终端中编辑名为 "my-deployment" 的 Deployment
kubectl edit deployment my-deployment

# 将 "my-deployment" 的副本数扩展到 5
kubectl scale deployment my-deployment --replicas=5

# -- 管理应用发布 (Rollout) --
# 查看 "my-deployment" 的发布状态
kubectl rollout status deployment/my-deployment

# 查看 "my-deployment" 的发布历史
kubectl rollout history deployment/my-deployment

# 回滚到上一个版本
kubectl rollout undo deployment/my-deployment

# 回滚到指定的修订版本 (revision)
kubectl rollout undo deployment/my-deployment --to-revision=2
```

---

## 5. 调试与交互 (Debugging & Interacting)

```bash
# 查看 "my-pod" 的日志
kubectl logs my-pod

# 实时跟踪 "my-pod" 的日志 (类似 tail -f)
kubectl logs -f my-pod

# 如果 Pod 中有多个容器，需要指定容器名
kubectl logs my-pod -c <container-name>

# 在 "my-pod" 中执行 "ls -l" 命令
kubectl exec my-pod -- ls -l

# 在 "my-pod" 中启动一个交互式的 shell
kubectl exec -it my-pod -- /bin/sh
# -i: stdin, -t: tty

# 将本地的 app.log 文件复制到 "my-pod" 的 /tmp 目录
kubectl cp app.log my-pod:/tmp/app.log

# 将 "my-pod" 的 8080 端口转发到本地的 9090 端口
kubectl port-forward pod/my-pod 9090:8080
```
这只是 `kubectl` 功能的冰山一角，但掌握了这些核心命令，你就能处理绝大多数日常的 Kubernetes 管理任务。 