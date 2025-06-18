# 9. Secrets：管理敏感数据

上一章我们学习了如何使用 `ConfigMap` 来管理应用的非敏感配置。但如果我们需要处理密码、API 密钥、TLS 证书或数据库凭证等敏感信息呢？将它们以明文形式存储在 `ConfigMap` 或更糟糕的——硬编码在镜像里，是严重的安全隐患。

为了解决这个问题，Kubernetes 提供了 `Secret` 对象。

## 什么是 Secret？

`Secret` 是一个专门用于存储和管理少量敏感数据的 Kubernetes 对象。它的设计初衷、API 和使用方式都与 `ConfigMap` 非常相似，但有几个关键区别，使其更适合处理机密信息。

### Secret vs. ConfigMap

| 特性 | ConfigMap | Secret |
| :--- | :--- | :--- |
| **用途** | 存储非敏感的纯文本配置数据 | 存储敏感数据，如密码、Token、密钥 |
| **数据编码** | 明文存储 | 默认以 Base64 编码存储 |
| **访问控制** | 默认权限较宽松 | 默认权限更严格，系统会更谨慎地处理 |
| **挂载方式** | 可作为环境变量或卷文件 | 可作为环境变量或卷文件 (推荐卷) |
| **安全性**| 不提供任何加密保证 | 提供基础的隔离和访问控制，可集成更强的加密方案 |

**一个非常重要的警告**: Kubernetes `Secret` 默认只是将数据进行 **Base64 编码**后存储在 `etcd` 中。**Base64 是编码，不是加密**，任何人都可以轻松地解码它。`Secret` 的主要安全优势在于：
1.  **访问控制**: 通过 RBAC，你可以精确控制哪些用户或服务账户可以读取特定的 `Secret`。
2.  **与 Pod 解耦**: 敏感数据不存储在 Pod 定义或镜像中。
3.  **减少意外泄露**: `kubectl get` 和 `describe` 命令默认不显示 `Secret` 的内容。
4.  **内存挂载**: 作为卷挂载时，`Secret` 通常被存储在内存文件系统 (`tmpfs`) 中，而不是写入磁盘。

要实现真正的静态加密（Encryption at Rest），需要管理员配置对 `etcd` 的加密。

## Secret 的类型

`Secret` 对象有一个 `type` 字段，用于区分不同用途的敏感数据。一些常见的类型包括：

-   `Opaque`: 默认类型。用于存储任意的键值对数据，比如数据库密码或 API key。
-   `kubernetes.io/service-account-token`: 用于存储服务账户的身份凭证，由 Kubernetes 自动管理。
-   `kubernetes.io/dockerconfigjson`: 用于存储访问私有 Docker 镜像仓库的认证信息。
-   `kubernetes.io/tls`: 用于存储 TLS 证书和私钥，通常供 Ingress 控制器使用。

## 创建 Secret

> **安全最佳实践**: 永远不要将包含敏感信息的 `Secret` YAML 文件提交到你的 Git 仓库中。

### 1. 从字面值创建 (仅限临时测试)
```bash
kubectl create secret generic db-credentials \
  --from-literal=username=admin \
  --from-literal=password='S3cr3tP@ssw0rd'
```

### 2. 从文件创建 (推荐)

这是更安全的方式，因为敏感数据只存在于你的本地文件中，这些文件可以被 `.gitignore` 排除。

假设你有 `username.txt` 和 `password.txt` 两个文件：
```bash
# username.txt
# admin

# password.txt
# S3cr3tP@ssw0rd
```

```bash
kubectl create secret generic db-credentials-from-file \
  --from-file=./username.txt \
  --from-file=./password.txt
```
这会创建一个 `Secret`，其 `key` 为文件名 (`username.txt` 和 `password.txt`)，`value` 为文件内容。

## 在 Pod 中使用 Secret

在 Pod 中使用 `Secret` 的方式与 `ConfigMap` 几乎完全相同。

### 方式一：作为环境变量注入 (不推荐)

虽然可行，但**不推荐**这种方式，因为环境变量可能会被意外地记录到日志中，或者通过 `kubectl describe pod` 等命令泄露。

```yaml
# ...
    env:
      - name: DB_USERNAME
        valueFrom:
          secretKeyRef:
            name: db-credentials # Secret 的名称
            key: username     # 要引用的 key
```

### 方式二：作为卷文件挂载 (推荐)

这是**最推荐、最安全**的方式。`Secret` 的内容会被作为文件挂载到容器中，并且通常是挂载在内存文件系统 `tmpfs` 上。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod-with-secret-volume
spec:
  containers:
  - name: my-container
    image: busybox
    command: [ "/bin/sh", "-c", "ls -l /etc/secrets && sleep 3600" ]
    volumeMounts:
    - name: secret-volume
      mountPath: "/etc/secrets"
      readOnly: true # 推荐将 Secret 挂载为只读
  volumes:
  - name: secret-volume
    secret:
      secretName: db-credentials-from-file
      # items: ... (和 ConfigMap 一样，可以选择性地挂载特定的 key)
```
当 Pod 启动后，`/etc/secrets` 目录下会包含 `username.txt` 和 `password.txt` 两个文件。你的应用程序就可以像读取普通文件一样读取这些凭证。

## 安全最佳实践总结

-   **优先使用卷挂载**: 避免将 Secret 作为环境变量注入。
-   **最小权限原则**: 使用 RBAC (Role-Based Access Control) 确保只有必须访问该 `Secret` 的 Pod 或用户才有权限读取它。
-   **启用静态加密**: 在生产环境中，配置 `etcd` 的静态加密，确保即使有人物理访问了 `etcd` 的存储，也无法读取其中的 `Secret` 数据。
-   **使用外部 Secret 管理器**: 对于高度敏感的环境，考虑使用像 HashiCorp Vault 或云服务商的 KMS (Key Management Service) 这样的外部工具，并通过相应的集成方案（如 Secrets Store CSI Driver）来将外部管理的机密信息同步到 Kubernetes 的 `Secret` 中。

通过正确使用 `Secret`，你可以安全地管理应用的敏感凭证，同时保持配置的灵活性和可移植性。 