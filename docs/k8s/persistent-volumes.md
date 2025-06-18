# 11. PersistentVolumes & PersistentVolumeClaims：持久化存储

上一章我们介绍了 `Volume`，但 `emptyDir` 和 `hostPath` 无法满足有状态应用（如数据库）对真正持久化存储的需求。我们需要一种存储，它的生命周期完全独立于 Pod，并且可以被动态地分配和管理。

为了解决这个问题，Kubernetes 引入了两个强大的 API 对象：`PersistentVolume` (PV) 和 `PersistentVolumeClaim` (PVC)。

## 核心思想：存储的供应与消费解耦

PV 和 PVC 的设计借鉴了计算资源中 Node 和 Pod 的关系，其核心思想是将**存储的"供应方" (Provisioning)** 与**存储的"消费方" (Consuming)** 分离。

-   **集群管理员 (供应方)**: 负责提供具体的存储资源。他们了解底层的存储系统是什么（例如，是 NFS、Ceph，还是云厂商的块存储）。他们创建 `PersistentVolume` (PV) 来将这些存储资源纳入 Kubernetes 集群的管理。
-   **应用开发者 (消费方)**: 负责部署应用。他们不关心底层存储的具体实现，只关心应用需要多大的存储空间、需要什么样的访问模式（例如，读写或只读）。他们通过创建 `PersistentVolumeClaim` (PVC) 来"申请"存储资源。

Kubernetes 则充当了中间人，负责将用户的"申请" (PVC) 与管理员提供的"资源" (PV) 进行匹配和绑定。

![PV-PVC-Diagram](https://i.imgur.com/your-pv-pvc-image.png) <!-- 你需要替换成真实的图片链接 -->

---

## PersistentVolume (PV)

`PersistentVolume` (PV) 是集群中的一块**已经由管理员配置好的网络存储**。它和 `Node` 一样，是集群级别的资源。PV 封装了底层存储的实现细节，无论是物理的 SAN 存储，还是云端的块存储。

一个 PV 的 YAML 定义示例 (`pv-definition.yaml`):
```yaml
apiVersion: v1
kind: PersistentVolume
metadata:
  name: my-nfs-pv
spec:
  capacity:
    storage: 5Gi # 1. 容量
  accessModes:
    - ReadWriteOnce # 2. 访问模式
  persistentVolumeReclaimPolicy: Retain # 3. 回收策略
  nfs: # 4. 具体的存储类型和配置
    path: /mnt/nfs_share
    server: 192.168.1.100
```
**关键字段**:
1.  `capacity.storage`: 定义了这块存储的容量。
2.  `accessModes`: 定义了卷的访问模式。
    -   `ReadWriteOnce` (RWO): 该卷可以被**单个节点**以读写模式挂载。
    -   `ReadOnlyMany` (ROX): 该卷可以被**多个节点**以只读模式挂载。
    -   `ReadWriteMany` (RWX): 该卷可以被**多个节点**以读写模式挂载。
3.  `persistentVolumeReclaimPolicy`: 当 PVC 被删除后，如何处理这个 PV。
    -   `Retain` (保留): PV 和其上的数据被保留。管理员需要手动清理。**生产环境推荐**。
    -   `Delete` (删除): PV 和其底层存储上的数据都会被删除。
    -   `Recycle` (回收): (已废弃) 会清空卷中的数据，使其可以被新的 PVC 使用。
4.  **存储类型**: 定义了具体的后端存储，例如 `nfs`, `awsElasticBlockStore`, `gcePersistentDisk`, `azureDisk` 等。

---

## PersistentVolumeClaim (PVC)

`PersistentVolumeClaim` (PVC) 是**用户（或开发者）对存储资源发出的一个"请求"**。它和 `Pod` 一样，是命名空间级别的资源。

一个 PVC 的 YAML 定义示例 (`pvc-definition.yaml`):
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-app-pvc
  namespace: my-app-ns
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 2Gi
```
**关键字段**:
-   `accessModes`: 请求的访问模式。它必须是 PV 所支持的访问模式的子集。
-   `resources.requests.storage`: 请求的存储容量。

当这个 PVC 被创建时，Kubernetes 的控制平面会寻找一个能够满足其请求（`accessModes` 和 `storage` 容量）的、尚未被绑定的 PV。如果找到，就将它们**绑定 (Bound)** 在一起。此后，这个 PV 就专属于这个 PVC，不能再被其他 PVC 绑定。

---

## 在 Pod 中使用 PVC

一旦 PVC 处于 `Bound` 状态，Pod 就可以像使用其他类型的 `Volume` 一样来使用它。

`pod-with-pvc.yaml`:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-database-pod
  namespace: my-app-ns
spec:
  containers:
    - name: database-container
      image: postgres
      ports:
        - containerPort: 5432
      volumeMounts:
        - mountPath: /var/lib/postgresql/data
          name: db-storage
  volumes:
    - name: db-storage
      persistentVolumeClaim:
        claimName: my-app-pvc # 引用同一个命名空间下的 PVC
```
现在，`postgres` 容器的数据目录就被挂载到了由 PV 提供的持久化存储上。即使这个 Pod 被删除或重启，只要 PV/PVC 还存在，数据就不会丢失。新的 Pod 可以通过引用同一个 PVC 来挂载回这块存储。

---

## StorageClass 与动态供应

手动创建和管理 PV 是一项繁琐的工作，这被称为**静态供应 (Static Provisioning)**。在云环境中，我们更希望存储能够按需自动创建。这就是 `StorageClass` 的作用。

`StorageClass` 提供了一种**动态供应 (Dynamic Provisioning)** PV 的机制。

-   **定义**: 一个 `StorageClass` 对象定义了存储的"类别"，例如 `fast-ssd` 或 `slow-hdd`，并指定了用于创建 PV 的**驱动 (Provisioner)**。
-   **工作方式**:
    1.  管理员预先创建好 `StorageClass` 对象。
    2.  用户在创建 PVC 时，通过 `storageClassName` 字段指定一个 `StorageClass`。
    3.  当 Kubernetes 看到这个 PVC 时，它不会去寻找现成的 PV，而是会调用 `StorageClass` 指定的驱动。
    4.  该驱动会在后端存储系统（如 AWS EBS）中创建一个新的存储卷，然后自动地为这个卷创建一个对应的 PV 对象，并将其与用户的 PVC 绑定。

**示例**:
```yaml
# storage-class.yaml (由管理员创建)
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: standard-ssd
provisioner: kubernetes.io/aws-ebs # AWS EBS 存储驱动
parameters:
  type: gp2
reclaimPolicy: Retain

---
# pvc-with-sc.yaml (由用户创建)
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: my-dynamic-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard-ssd # 请求使用这个 StorageClass
  resources:
    requests:
      storage: 10Gi
```

动态供应是 Kubernetes 在云环境中管理有状态应用的标准和推荐方式。它极大地简化了存储管理，使开发者能够像申请 CPU 和内存一样，按需申请持久化存储。 