# 9. Secrets：管理敏感数据

在上一章我们学习了用 ConfigMap 管理非敏感配置，但对于密码、Token、API 密钥、TLS 证书等敏感信息，我们需要一个更安全的解决方案。这就是 **Secret**。

## 9.1 什么是 Secret？

**Secret** 是 Kubernetes 中专门用于存储和管理小块敏感数据的对象。它的设计意图与 ConfigMap 非常相似，但提供了额外的安全保障。

**核心区别**：
1.  **编码存储**：Secret 中的数据默认使用 Base64 编码进行存储。**注意：这只是编码，不是加密！** 它能防止无意间暴露数据，但任何能访问 etcd 的人都可以轻松解码。
2.  **内存存储**：当作为卷挂载到 Pod 时，Secret 会被存储在内存文件系统 (`tmpfs`) 中，而不是写入节点的磁盘，以减少数据持久化带来的风险。
3.  **访问控制**：默认情况下，只有创建了 Secret 的 Pod，或者在 Pod 定义中明确引用的 Secret，才能被该 Pod 访问。
4.  **自动拉取**：Kubernetes 可以自动为 ServiceAccount 创建和附加 Secret，用于与 API Server 的安全通信。

**一句话总结**：把 Secret 当作是为敏感数据设计的特殊版 ConfigMap。

## 9.2 创建 Secret

与 ConfigMap 类似，创建 Secret 也有多种方式。

### 方式一：从字面值创建 (`generic`)

这是最直接的方式，用于存储普通的键值对，如用户名和密码。

```bash
# 注意，数据在创建时会自动进行 Base64 编码
kubectl create secret generic db-credentials \
  --from-literal=username='myuser' \
  --from-literal=password='S!p3rS3cr3t'
```

### 方式二：从文件创建 (`generic`)

你可以将包含敏感信息的文件内容作为 Secret 数据。

```bash
# 创建一个包含 API 密钥的文件
echo -n 'a-very-long-and-secret-api-key' > ./api-key.txt

# 从文件创建 Secret
kubectl create secret generic api-key-secret \
  --from-file=./api-key.txt
```

### 方式三：专门用于 TLS 证书 (`tls`)

Kubernetes 提供了专门的 `tls` 类型来处理 TLS/SSL 证书。你需要提供一个证书文件 (`.crt`) 和一个私钥文件 (`.key`)。

```bash
kubectl create secret tls my-tls-secret \
  --cert=/path/to/tls.crt \
  --key=/path/to/tls.key
```
这会自动创建名为 `tls.crt` 和 `tls.key` 的数据项。

### 方式四：从 YAML 文件定义

同样，声明式是管理 Secret 的最佳实践。**在提交到版本控制系统之前，务必对 YAML 中的敏感数据进行 Base64 编码**。

你可以使用 `echo -n 'myuser' | base64` 命令来生成编码后的字符串。

`db-secret.yaml`:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-secret-yaml
type: Opaque # Opaque 是通用 Secret 的默认类型
data:
  # Base64 编码后的 'myuser'
  username: bXl1c2Vy
  # Base64 编码后的 'S!p3rS3cr3t'
  password: UyFwM3JTM2NyM3Q=
```
然后应用它：`kubectl apply -f db-secret.yaml`

## 9.3 在 Pod 中使用 Secret

将 Secret 注入 Pod 的方式与 ConfigMap 完全相同：

### 1. 作为环境变量注入

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: my-app-container
      image: my-app
      env:
        - name: DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-secret-yaml # Secret 的名称
              key: username # Secret 中的键
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-secret-yaml
              key: password
```

### 2. 作为文件挂载到卷中

这是更安全的方式，因为它避免将敏感信息暴露为环境变量。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: my-app-container
      image: my-app
      volumeMounts:
        - name: db-creds-volume
          mountPath: "/etc/creds"
          readOnly: true # 推荐将 Secret 卷设置为只读
  volumes:
    - name: db-creds-volume
      secret:
        secretName: db-secret-yaml
```
在这个例子中，Pod 的 `/etc/creds` 目录下会出现两个文件：`username` 和 `password`，其内容分别是解码后的 Secret 值。

## 9.4 安全最佳实践

- **最小权限原则**：使用 RBAC 限制谁可以读取和创建 Secret。
- **优先使用卷挂载**：避免将 Secret 作为环境变量注入，因为环境变量可能会在日志或调试信息中意外泄露。
- **启用静态加密**：配置 Kubernetes 在 etcd 中对 Secret 进行加密存储（Encryption at Rest）。这是生产环境的必要安全措施。
- **定期轮换 Secret**：定期更换密码、证书和密钥，以减少泄露风险。
- **不要将 Secret 定义文件提交到 Git**：如果必须提交，请使用如 Bitnami Sealed Secrets 或 HashiCorp Vault 等工具进行加密管理。

## 9.5 总结

Secret 是 Kubernetes 管理敏感数据的标准机制。虽然它本身不提供强加密，但它与 Kubernetes 的生态系统（如 RBAC、卷挂载）相结合，提供了一套管理敏感信息的完整工作流。正确地使用 Secret 是保障集群安全的关键一环。

接下来，我们将进入存储的下一个主题：**Volumes**，了解容器如何持久化数据。