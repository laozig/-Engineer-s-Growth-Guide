# Azure 文件存储

Azure 文件存储是 Microsoft 提供的完全托管的文件共享服务，支持行业标准的 SMB 和 NFS 协议。本文档提供了 Azure 文件存储的全面概述、核心概念和使用指南。

## 目录

- [概述](#概述)
- [核心概念](#核心概念)
- [存储账户类型](#存储账户类型)
- [文件共享类型](#文件共享类型)
- [访问方法](#访问方法)
- [安全性](#安全性)
- [性能与扩展性](#性能与扩展性)
- [备份与恢复](#备份与恢复)
- [使用方法](#使用方法)
- [监控与诊断](#监控与诊断)
- [成本优化](#成本优化)
- [最佳实践](#最佳实践)
- [常见场景](#常见场景)
- [常见问题](#常见问题)
- [其他资源](#其他资源)

## 概述

Azure 文件存储提供完全托管的云文件共享，可通过行业标准的 SMB 协议（所有 Windows、macOS 和 Linux 版本均支持）或 NFS 协议（适用于 Linux 和 macOS 客户端）访问。Azure 文件共享可以同时在云端和本地环境中挂载。文件存储特别适合：

- **替代或补充本地文件服务器**：将文件服务器或 NAS 设备迁移到云端，同时保持兼容性
- **"随处可用"的文件**：在多个虚拟机或服务之间共享文件数据
- **共享应用程序设置**：在开发和测试环境中存储配置文件
- **容器持久存储**：为容器提供持久化存储
- **混合云场景**：通过 Azure 文件同步在本地和云端之间同步文件

**主要优势：**

- **完全托管**：无需管理硬件或操作系统
- **共享访问**：多个计算实例可同时访问
- **兼容性**：使用行业标准的 SMB 和 NFS 协议
- **弹性扩展**：根据需求调整容量
- **混合能力**：通过 Azure 文件同步实现本地和云端集成
- **安全性**：提供多层次的安全控制和加密

## 核心概念

### 存储账户

Azure 文件存储是通过 Azure 存储账户提供的。存储账户为所有 Azure 存储服务（包括文件存储）提供唯一的命名空间。

### 文件共享

文件共享是 Azure 中的 SMB 或 NFS 文件共享。所有目录和文件必须在文件共享中创建。一个账户可以包含无限数量的共享，一个共享可以存储无限数量的文件，直到达到存储账户的容量限制。

### 目录和文件

Azure 文件存储提供了一个熟悉的文件系统接口：

```mermaid
flowchart TD
    A[存储账户] --> B[文件共享1]
    A --> C[文件共享2]
    B --> D[目录1]
    B --> E[文件1]
    B --> F[文件2]
    D --> G[文件3]
    D --> H[文件4]
    C --> I[目录2]
    I --> J[文件5]
```

## 存储账户类型

Azure 文件存储支持以下类型的存储账户：

| 存储账户类型 | 支持的文件共享类型 | 推荐使用场景 |
|------------|---------------|-----------|
| 通用 v2 (GPv2) | 标准文件共享 | 大多数场景，支持所有存储服务 |
| FileStorage | 高级文件共享 | 企业级应用程序，高性能工作负载 |

## 文件共享类型

Azure 文件存储提供四种不同类型的文件共享：

### 标准文件共享

- **协议支持**：SMB 2.1、3.0、3.1.1
- **性能层级**：标准性能
- **冗余选项**：LRS、ZRS、GRS、RA-GRS
- **容量**：最高 100 TiB
- **适用场景**：一般用途文件共享，开发/测试环境

### 高级文件共享

- **协议支持**：SMB 2.1、3.0、3.1.1
- **性能层级**：高级性能（SSD 支持）
- **冗余选项**：LRS、ZRS
- **容量**：最高 100 TiB
- **适用场景**：高性能企业应用程序，如数据库、ERP 系统

### NFS 文件共享

- **协议支持**：NFSv4.1
- **性能层级**：高级性能（仅限高级存储）
- **冗余选项**：LRS、ZRS
- **容量**：最高 100 TiB
- **适用场景**：Linux 应用程序，HPC 工作负载，容器存储

### Azure NetApp Files

- **协议支持**：NFSv3、NFSv4.1、SMB 3.x
- **性能层级**：超高性能
- **冗余选项**：本地冗余
- **容量**：最高 500 TiB
- **适用场景**：企业级应用程序，SAP HANA，Oracle，极高性能要求

## 访问方法

### SMB 访问

可以通过多种方式访问 SMB 文件共享：

1. **直接挂载**：在 Windows、Linux 或 macOS 上直接挂载
2. **Azure 文件同步**：在本地服务器上缓存 Azure 文件共享
3. **REST API**：通过 REST API 访问文件共享
4. **Azure 存储客户端库**：使用各种编程语言的客户端库

### NFS 访问

NFS 文件共享只能从以下位置访问：

1. **VNet 内的虚拟机**：在虚拟网络内部署的虚拟机
2. **对等互连的网络**：与包含 NFS 共享的 VNet 对等互连的网络
3. **本地网络**：通过 VPN 或 ExpressRoute 连接的本地网络

## 安全性

Azure 文件存储提供多层安全功能：

### 数据加密

- **静态加密**：所有数据自动使用 Azure 存储服务加密 (SSE) 进行加密
- **传输中加密**：通过 SMB 3.0+ 加密或 HTTPS 进行安全传输
- **客户管理的密钥**：可选择使用自己的加密密钥

### 身份验证和访问控制

- **共享密钥授权**：使用存储账户密钥
- **Azure Active Directory 身份验证**：针对 SMB 的基于身份的访问控制
- **共享访问签名 (SAS)**：提供有限的访问权限
- **基于角色的访问控制 (RBAC)**：精细的权限管理

### 网络安全

- **私有终结点**：通过 Azure 私有链接进行私有访问
- **服务终结点**：限制访问特定虚拟网络
- **防火墙规则**：基于 IP 地址限制访问

## 性能与扩展性

Azure 文件存储的性能特点：

### 标准文件共享

- **IOPS**：最高 10,000 IOPS
- **吞吐量**：最高 300 MiB/秒
- **延迟**：个位数毫秒级别

### 高级文件共享

- **IOPS**：每 GiB 提供 100 IOPS，最高 100,000 IOPS
- **吞吐量**：每 GiB 提供 10 MiB/秒，最高 5,000 MiB/秒
- **延迟**：低于 1 毫秒

### 扩展限制

- **文件共享大小**：最高 100 TiB
- **文件大小**：最高 4 TiB
- **目录深度**：无限制（受路径长度限制）
- **每个目录的项目数**：无限制（受总容量限制）

## 备份与恢复

Azure 文件存储提供多种数据保护选项：

### Azure 备份

Azure 备份为 Azure 文件共享提供原生备份解决方案：

- 基于时间点的快照
- 集中管理和监控
- 自动备份调度
- 精细恢复能力

### 共享快照

文件共享快照提供文件共享的只读版本：

- 保留文件共享的精确时间点副本
- 只存储增量更改，节省存储空间
- 用户可以自行恢复单个文件

### 软删除

软删除功能可以保护文件共享免受意外删除：

- 可以恢复已删除的文件共享
- 可配置的保留期（1-365 天）
- 无需备份即可恢复

## 使用方法

### 创建文件共享

#### 使用 Azure 门户

1. 登录 Azure 门户
2. 导航到存储账户（或创建新账户）
3. 选择"文件共享"
4. 点击"+ 文件共享"
5. 输入名称和配额（最大大小）
6. 选择所需的层级（标准/高级）
7. 点击"创建"

#### 使用 Azure CLI

```bash
# 创建标准文件共享
az storage share create \
    --name myshare \
    --account-name mystorageaccount \
    --quota 1024

# 创建 NFS 文件共享（需要高级存储账户）
az storage share-nfs create \
    --name mynfsshare \
    --account-name mystorageaccount \
    --enabled-protocols NFS \
    --root-squash NoRootSquash
```

#### 使用 PowerShell

```powershell
# 创建标准文件共享
New-AzRmStorageShare `
    -ResourceGroupName "myResourceGroup" `
    -StorageAccountName "mystorageaccount" `
    -Name "myshare" `
    -QuotaGiB 1024
```

### 挂载文件共享

#### Windows

```powershell
# 使用存储账户密钥挂载
$connectTestResult = Test-NetConnection -ComputerName mystorageaccount.file.core.windows.net -Port 445
if ($connectTestResult.TcpTestSucceeded) {
    # 保存凭据
    cmd.exe /C "cmdkey /add:`"mystorageaccount.file.core.windows.net`" /user:`"localhost\mystorageaccount`" /pass:`"StorageAccountKey`""
    # 挂载
    New-PSDrive -Name Z -PSProvider FileSystem -Root "\\mystorageaccount.file.core.windows.net\myshare" -Persist
} else {
    Write-Error -Message "无法通过端口 445 连接，请检查网络设置"
}
```

#### Linux (SMB)

```bash
# 安装 CIFS 工具
sudo apt-get update
sudo apt-get install cifs-utils

# 创建挂载点
sudo mkdir /mnt/myshare

# 挂载文件共享
sudo mount -t cifs //mystorageaccount.file.core.windows.net/myshare /mnt/myshare -o username=mystorageaccount,password=StorageAccountKey,serverino
```

#### Linux (NFS)

```bash
# 安装 NFS 客户端
sudo apt-get update
sudo apt-get install nfs-common

# 创建挂载点
sudo mkdir /mnt/mynfsshare

# 挂载 NFS 文件共享
sudo mount -t nfs mystorageaccount.file.core.windows.net:/mystorageaccount/mynfsshare /mnt/mynfsshare -o vers=4,minorversion=1,sec=sys
```

### 文件操作

一旦挂载，可以像使用本地文件系统一样操作文件：

- 创建、读取、更新和删除文件
- 创建和管理目录
- 设置文件和目录权限
- 使用标准文件系统命令和工具

### 使用 Azure 文件同步

Azure 文件同步允许将本地文件服务器与 Azure 文件共享同步：

1. 在 Azure 门户中创建存储同步服务
2. 创建同步组
3. 在本地服务器上安装 Azure 文件同步代理
4. 注册服务器
5. 添加服务器终结点（本地路径）
6. 添加云终结点（Azure 文件共享）

## 监控与诊断

### Azure Monitor

使用 Azure Monitor 监控文件存储的性能和运行状况：

- **指标**：IOPS、延迟、吞吐量、可用性等
- **日志**：详细的操作日志、存储分析日志

### 存储分析

启用存储分析以记录详细的请求信息：

```powershell
# 启用存储分析日志
Set-AzStorageServiceLoggingProperty -ServiceType File `
    -LoggingOperations read,write,delete `
    -RetentionDays 10 `
    -Context $ctx
```

## 成本优化

优化 Azure 文件存储成本的策略：

1. **选择合适的层级**：根据性能需求选择标准或高级文件共享
2. **设置适当的配额**：限制文件共享大小以控制成本
3. **利用分层存储**：使用 Azure 文件同步的云分层功能
4. **优化备份策略**：调整备份频率和保留期
5. **监控使用情况**：定期检查使用情况并清理不需要的数据

## 最佳实践

### 性能最佳实践

- 对于高性能需求，使用高级文件共享
- 将文件共享与访问它的计算资源放在同一区域
- 使用 SMB 多通道提高吞吐量
- 对于频繁访问的文件，考虑使用 Azure 文件同步进行本地缓存
- 避免在单个目录中存储大量文件（建议每个目录不超过 100,000 个文件）

### 安全最佳实践

- 尽可能使用 Azure AD 身份验证而非共享密钥
- 实施网络安全控制（私有终结点、服务终结点）
- 启用传输中加密
- 定期轮换访问密钥
- 使用最小权限原则分配 RBAC 角色

### 可靠性最佳实践

- 为关键数据使用 ZRS 或 GRS 冗余选项
- 实施定期备份策略
- 启用软删除功能
- 测试恢复过程
- 监控文件共享健康状况和性能

## 常见场景

### 替换本地文件服务器

Azure 文件存储可以完全或部分替代本地文件服务器：

1. 创建 Azure 文件共享
2. 使用 Azure 文件同步进行数据迁移和持续同步
3. 配置云分层以优化本地存储使用
4. 设置备份策略

### 应用程序文件共享

为多个虚拟机或服务提供共享存储：

1. 创建文件共享
2. 在每个虚拟机上挂载文件共享
3. 配置应用程序使用共享路径
4. 实施适当的并发控制

### 容器持久存储

为容器提供持久化存储解决方案：

1. 创建文件共享
2. 在 Kubernetes 中配置持久卷
3. 使用 Azure Kubernetes Service (AKS) 的内置支持

```yaml
# Kubernetes PV 示例
apiVersion: v1
kind: PersistentVolume
metadata:
  name: azurefile
spec:
  capacity:
    storage: 5Gi
  accessModes:
    - ReadWriteMany
  storageClassName: azurefile
  azureFile:
    secretName: azure-secret
    shareName: myshare
    readOnly: false
```

### 混合云存储

使用 Azure 文件同步实现混合云存储架构：

1. 在本地服务器上安装 Azure 文件同步代理
2. 创建同步组和终结点
3. 配置云分层策略
4. 使用 Azure 备份保护数据

## 常见问题

### 如何提高文件共享性能？

1. 使用高级文件共享
2. 启用大文件共享功能（对于需要高容量的标准共享）
3. 使用 SMB 3.0+ 客户端启用 SMB 多通道
4. 将文件共享与访问它的计算资源放在同一区域
5. 避免在单个目录中存储过多文件

### 如何实现本地和云端文件同步？

使用 Azure 文件同步：

1. 创建存储同步服务
2. 设置同步组
3. 在本地服务器上安装同步代理
4. 注册服务器并配置终结点
5. 配置云分层策略（可选）

### 如何在 Azure 文件共享上设置权限？

对于 SMB 文件共享：

1. **使用 NTFS 权限**：在挂载的文件共享上设置标准 NTFS 权限
2. **使用 Azure RBAC**：在 Azure 门户中分配适当的 RBAC 角色
3. **使用 Azure AD 身份验证**：启用基于身份的访问控制

对于 NFS 文件共享：

1. **使用 UNIX 权限**：设置标准的 UNIX 风格权限（用户、组、其他）

## 其他资源

- [Azure 文件存储官方文档](https://docs.microsoft.com/zh-cn/azure/storage/files/)
- [Azure 文件同步文档](https://docs.microsoft.com/zh-cn/azure/storage/file-sync/)
- [Azure 存储定价](https://azure.microsoft.com/zh-cn/pricing/details/storage/files/)
- [SMB 多通道性能](https://docs.microsoft.com/zh-cn/azure/storage/files/storage-files-smb-multichannel-performance)
- [Azure 文件存储常见问题](https://docs.microsoft.com/zh-cn/azure/storage/files/storage-files-faq) 