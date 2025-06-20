# 11. PersistentVolumes & PersistentVolumeClaims：持久化存储

在上一章中，我们了解了 Volume，但像 `hostPath` 这样的持久化方案与特定节点紧密耦合，缺乏灵活性。为了解决这个问题，Kubernetes 提供了一套更强大、更抽象的持久化存储机制，其核心是两个 API 对象：**PersistentVolume (PV)** 和 **PersistentVolumeClaim (PVC)**。

## 11.1 核心概念：PV 与 PVC

这套机制的设计思想是**将存储的"提供"与"使用"相分离**，类似于生产者和消费者的关系。

### PersistentVolume (PV)
- **角色**：存储的**提供者**（由集群管理员配置）。
- **是什么**：PV 是集群中的一块网络存储，例如一块 AWS EBS 卷、一个 NFS 共享目录或一个 GCE Persistent Disk。它是一个**集群级别的资源**，就像节点一样，不属于任何 Namespace。
- **目的**：管理员预先（静态）或通过 `StorageClass` 动态地配置好一批可用的存储资源（PVs），等待被使用。

### PersistentVolumeClaim (PVC)
- **角色**：存储的**使用者**（由应用开发者/用户创建）。
- **是什么**：PVC 是用户对存储资源的一次"申请"。它定义了需要多大的存储空间、需要什么样的访问模式（例如，读写一次还是读写多次）等。PVC 是一个**命名空间级别的资源**。
- **目的**：用户在自己的 Namespace 中创建 PVC 来申请存储。Kubernetes 会在已有的 PV 中寻找一个满足 PVC 要求的 PV，并将它们**绑定（Bind）**在一起。

**工作流程**：
1. **管理员**创建一批 PV。
2. **用户**在自己的 Namespace 中创建一个 PVC，声明存储需求。
3. **Kubernetes 控制平面**找到一个与 PVC 匹配的 PV，并将它们绑定。
4. **用户**在 Pod 的 `volumes` 定义中引用该 PVC，就像使用普通 Volume 一样。

这个过程将应用开发者从复杂的底层存储细节中解放出来。开发者只需关心"我需要多大的、什么类型的存储"，而无需关心这些存储是来自 AWS、GCP 还是本地的 NFS 服务器。

<div align="center">
  <img src="https://i.imgur.com/kP8yD0c.png" alt="PV, PVC, and Pod relationship" width="700">
</div>

## 11.2 访问模式 (Access Modes)

在定义 PV 和 PVC 时，你需要指定访问模式，它决定了存储卷可以被如何挂载和访问。

- **`ReadWriteOnce` (RWO)**: 卷可以被**单个节点**以读写方式挂载。这是最常见的模式，适用于大多数块存储（如 AWS EBS, GCP PD）。
- **`ReadOnlyMany` (ROX)**: 卷可以被**多个节点**以只读方式挂载。
- **`ReadWriteMany` (RWX)**: 卷可以被**多个节点**以读写方式挂载。这通常只被文件存储（如 NFS）或复杂的块存储（如 GlusterFS, Ceph）支持。

## 11.3 静态与动态配置 (Static vs. Dynamic Provisioning)

### 静态配置
这是我们上面描述的流程：管理员**手动创建**一系列 PV，然后 PVC 来绑定它们。这种方式适用于存储资源已知且固定的情况。

**示例**：
1.  **管理员创建 PV**:
    `pv.yaml`
    ```yaml
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: my-manual-pv
    spec:
      capacity:
        storage: 5Gi # 存储大小
      accessModes:
        - ReadWriteOnce
      hostPath: # 这里以 hostPath 为例，实际通常是网络存储
        path: "/mnt/data"
    ```
2.  **用户创建 PVC**:
    `pvc.yaml`
    ```yaml

    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: my-app-pvc
    spec:
      accessModes:
        - ReadWriteOnce
      resources:
        requests:
          storage: 3Gi # 申请大小
    ```
    Kubernetes 会发现 `my-manual-pv` (5Gi) 满足 `my-app-pvc` (3Gi) 的需求，并绑定它们。

### 动态配置与 StorageClass
手动管理 PV 非常繁琐。在云环境中，我们希望存储能够按需自动创建。这就是 **StorageClass** 的作用。

- **StorageClass**: 是一个 API 对象，它定义了存储的"类别"或"模板"。它描述了存储的提供商（`provisioner`，如 `kubernetes.io/aws-ebs`）、参数（如磁盘类型 `gp2`）等。

**工作流程**:
1. **管理员**创建一个或多个 StorageClass。
2. **用户**创建一个 PVC，并在其中**指定一个 `storageClassName`**。
3. Kubernetes 不会去查找已有的 PV，而是会**触发**该 StorageClass 定义的 `provisioner`，**动态地创建一个新的 PV**，并自动与该 PVC 绑定。

**示例**:
`storageclass.yaml`
```yaml
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: fast-storage
provisioner: kubernetes.io/aws-ebs # 使用 AWS EBS
parameters:
  type: gp2 # 磁盘类型
  fsType: ext4
```
`pvc-dynamic.yaml`
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-dynamic-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: fast-storage # 指定 StorageClass
  resources:
    requests:
      storage: 10Gi
```
当 `my-dynamic-pvc` 被创建时，Kubernetes 会自动在 AWS 中创建一个 10Gi 的 gp2 类型的 EBS 卷，并将其封装成 PV 与之绑定。

## 11.4 在 Pod 中使用 PVC

一旦 PVC 处于 `Bound` 状态，就可以像其他 Volume 类型一样在 Pod 中引用它。

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app-pod
spec:
  containers:
    - name: my-app
      image: nginx
      volumeMounts:
      - mountPath: "/var/www/html"
        name: my-storage
  volumes:
    - name: my-storage
      persistentVolumeClaim:
        # 引用 PVC 的名称
        claimName: my-app-pvc
```

## 11.5 总结

PV/PVC 模型是 Kubernetes 持久化存储的基石。它通过将存储的实现细节与应用的使用需求解耦，提供了极大的灵活性和可移植性。`StorageClass` 的引入进一步实现了存储的自动化（动态配置），使得管理有状态应用变得前所未有的简单。

掌握 PV, PVC, 和 StorageClass 是部署和管理数据库等有状态应用的关键。在后续章节中，我们将看到 `StatefulSet` 如何利用这套机制来管理有状态应用。
