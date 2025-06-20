# 3. kubectl 核心命令速查

`kubectl` 是与 Kubernetes 集群进行交互的命令行工具。熟练掌握 `kubectl` 是高效管理 Kubernetes 的关键。本章提供一个核心命令的速查表，方便你快速查找和使用。

## 3.1 `kubectl` 命令结构

`kubectl` 的命令遵循统一的结构：

```
kubectl [command] [TYPE] [NAME] [flags]
```

- **command**: 要执行的操作，如 `create`, `get`, `delete`, `describe`。
- **TYPE**: 资源类型，如 `pod`, `service`, `deployment`。
- **NAME**: 资源名称（可选）。如果省略，则操作于所有该类型的资源。
- **flags**: 可选标志，如 `-n` 指定命名空间，`-o` 指定输出格式。

---

## 3.2 上下文与配置 (Context & Configuration)

- **查看当前上下文**: `kubectl config current-context`
- **查看所有上下文**: `kubectl config get-contexts`
- **切换上下文**: `kubectl config use-context <context-name>`
- **查看集群信息**: `kubectl cluster-info`

---

## 3.3 资源查看与检索 (Get & Describe)

- **列出所有 Pod**: `kubectl get pods`
- **列出特定命名空间中的所有 Pod**: `kubectl get pods -n <namespace>`
- **列出所有 Pod 并显示更多信息 (如 IP、节点)**: `kubectl get pods -o wide`
- **列出所有 Service**: `kubectl get services`
- **列出所有 Deployment**: `kubectl get deployments`
- **获取特定 Pod 的详细信息 (YAML格式)**: `kubectl get pod <pod-name> -o yaml`
- **查看特定 Pod 的详细描述 (事件、状态等)**: `kubectl describe pod <pod-name>`
- **查看所有节点的资源使用情况**: `kubectl top nodes`
- **查看所有 Pod 的资源使用情况**: `kubectl top pods`

---

## 3.4 资源创建与应用 (Create & Apply)

- **从 YAML 文件创建资源**: `kubectl apply -f <filename.yaml>`
- **从多个 YAML 文件创建资源**: `kubectl apply -f <dir>`
- **直接创建一个 Deployment**: `kubectl create deployment <name> --image=<image>`
- **直接暴露一个 Deployment 为 Service**: `kubectl expose deployment <name> --port=<port> --type=LoadBalancer`
- **直接运行一个 Pod**: `kubectl run <name> --image=<image> --restart=Never`

**`apply` vs `create`**:
- `apply` 是声明式的，可以重复执行，用于创建和更新资源。**推荐使用**。
- `create` 是命令式的，只能用于创建新资源，如果资源已存在会报错。

---

## 3.5 资源更新与修改 (Update & Edit)

- **编辑一个正在运行的资源**: `kubectl edit <type>/<name>` (会打开默认编辑器修改 YAML)
- **更新镜像版本 (Deployment)**: `kubectl set image deployment/<name> <container-name>=<new-image-version>`
- **滚动更新与回滚 (Deployment)**:
  - `kubectl rollout status deployment/<name>`: 查看更新状态
  - `kubectl rollout history deployment/<name>`: 查看更新历史
  - `kubectl rollout undo deployment/<name>`: 回滚到上一个版本
  - `kubectl rollout undo deployment/<name> --to-revision=<n>`: 回滚到指定版本

---

## 3.6 资源删除 (Delete)

- **从 YAML 文件删除资源**: `kubectl delete -f <filename.yaml>`
- **删除特定 Pod**: `kubectl delete pod <pod-name>`
- **删除所有同标签的 Pod**: `kubectl delete pods -l <label-key>=<label-value>`
- **强制删除 Pod (忽略优雅终止)**: `kubectl delete pod <pod-name> --grace-period=0 --force`

---

## 3.7 调试与排查 (Debug & Troubleshoot)

- **查看 Pod 日志**: `kubectl logs <pod-name>`
- **实时跟踪 Pod 日志**: `kubectl logs -f <pod-name>`
- **查看 Pod 中特定容器的日志**: `kubectl logs <pod-name> -c <container-name>`
- **在 Pod 中执行命令**: `kubectl exec -it <pod-name> -- <command>` (例如 `bash`, `sh`)
- **将本地端口转发到 Pod 端口**: `kubectl port-forward <pod-name> <local-port>:<pod-port>`
- **将本地端口转发到 Service 端口**: `kubectl port-forward svc/<service-name> <local-port>:<service-port>`
- **查看资源上的标签**: `kubectl get pods --show-labels`
- **添加/更新标签**: `kubectl label pods <pod-name> <key>=<value> --overwrite`
- **移除标签**: `kubectl label pods <pod-name> <key>-`

## 3.8 常用技巧

- **别名**: 在你的 `.bashrc` 或 `.zshrc` 中添加 `alias k=kubectl`，可以极大提高效率。
- **自动补全**:
  - `source <(kubectl completion bash)` (for Bash)
  - `source <(kubectl completion zsh)` (for Zsh)
- **指定输出格式**: `-o json`, `-o yaml`, `-o wide`, `-o custom-columns`

本速查表涵盖了日常使用中最频繁的命令。随着我们学习的深入，还会接触到更多高级命令。建议将此页作为书签，随时查阅。