# Amazon EFS (Elastic File System)

Amazon Elastic File System (EFS) 是一种简单、可扩展、完全托管的弹性 NFS 文件系统，可与 AWS 云服务和本地资源配合使用。

## 目录

- [概述](#概述)
- [核心概念](#核心概念)
- [性能与吞吐量模式](#性能与吞吐量模式)
- [存储类别与生命周期管理](#存储类别与生命周期管理)
- [创建和管理文件系统](#创建和管理文件系统)
- [挂载 EFS 文件系统](#挂载-efs-文件系统)
- [数据保护与备份](#数据保护与备份)
- [安全与访问控制](#安全与访问控制)
- [性能优化](#性能优化)
- [监控与日志](#监控与日志)
- [成本优化](#成本优化)
- [EFS 与其他存储服务对比](#efs-与其他存储服务对比)
- [常见使用场景](#常见使用场景)
- [实际应用案例](#实际应用案例)

## 概述

Amazon EFS 设计为可根据文件添加和删除自动扩展和缩减，无需预置和管理容量。它提供共享文件访问，并支持数千个并发连接。其主要特点包括：

- **完全托管**：无需管理文件服务器或存储
- **弹性扩展**：存储容量和性能随需求自动扩展
- **共享访问**：支持数千个并发 NFSv4.1 客户端
- **高可用性和持久性**：数据冗余存储在多个可用区（AZ）中
- **与 AWS 服务集成**：无缝集成 EC2、ECS、EKS、Lambda 等服务
- **按需付费**：只需为使用的存储付费

## 核心概念

### 文件系统 (File System)

EFS 中的主要资源，提供一个可挂载的文件系统。

### 挂载目标 (Mount Target)

在 VPC 的一个可用区中创建的 NFSv4.1 端点。每个挂载目标都有一个唯一的 IP 地址，用于将 EFS 文件系统挂载到客户端。

### 访问点 (Access Point)

为访问 EFS 文件系统的应用程序提供专用的入口点。访问点可以强制执行特定的用户和组，并限制对特定目录的访问。

## 性能与吞吐量模式

### 性能模式

1. **通用性能模式 (General Purpose)**
   - 默认模式，适用于大多数文件系统工作负载
   - 针对延迟敏感型应用进行了优化
   - 适合：Web 服务器、内容管理系统、主目录

2. **最大 I/O 模式 (Max I/O)**
   - 针对大规模、高吞吐量工作负载进行优化
   - 可扩展到更高的吞吐量和 IOPS
   - 适合：大数据分析、媒体处理、科学计算

### 吞吐量模式

1. **突发吞吐量模式 (Bursting)**
   - 默认模式，吞吐量随文件系统大小增长而扩展
   - 提供基准吞吐量，并允许突发到更高水平

2. **预置吞吐量模式 (Provisioned)**
   - 为文件系统指定固定的吞吐量
   - 适合吞吐量需求高于突发模式所能提供的应用程序

3. **弹性吞吐量模式 (Elastic)**
   - 自动扩展吞吐量以满足应用程序需求
   - 按需付费，仅为实际使用的吞吐量付费

## 存储类别与生命周期管理

### EFS 存储类别

1. **EFS 标准 (Standard)**
   - 用于存储频繁访问的文件
   - 在多个可用区冗余存储

2. **EFS 不频繁访问 (Infrequent Access - IA)**
   - 成本优化，用于不经常访问的文件
   - 访问文件时会产生数据访问费用

3. **EFS 单可用区 (One Zone)**
   - 将数据存储在单个可用区中，成本更低
   - 适合不需要多可用区冗余的工作负载

4. **EFS 单可用区-不频繁访问 (One Zone-IA)**
   - 单可用区中成本最低的存储类别

### 生命周期管理

EFS 生命周期管理自动将文件从标准存储类别移动到不频繁访问存储类别，以节省成本。

```bash
# 创建启用了生命周期管理的文件系统
aws efs create-file-system \
  --creation-token my-efs \
  --performance-mode generalPurpose \
  --tags Key=Name,Value=MyFileSystem \
  --lifecycle-policies "TransitionToIA=AFTER_30_DAYS"
```

## 创建和管理文件系统

### 创建文件系统

#### 使用 AWS 控制台

1. 登录 AWS 管理控制台，进入 EFS 服务
2. 点击"创建文件系统"
3. 配置 VPC、可用区和安全组
4. 选择性能和吞吐量模式
5. 创建文件系统

#### 使用 AWS CLI

```bash
# 创建基本 EFS 文件系统
aws efs create-file-system \
  --creation-token my-efs-token \
  --performance-mode generalPurpose \
  --tags Key=Name,Value=MyFileSystem

# 创建挂载目标
aws efs create-mount-target \
  --file-system-id fs-12345678 \
  --subnet-id subnet-12345678 \
  --security-groups sg-12345678
```

### 创建访问点

```bash
# 创建 EFS 访问点
aws efs create-access-point \
  --client-token my-ap-token \
  --file-system-id fs-12345678 \
  --posix-user '{"Uid": 1001, "Gid": 1001}' \
  --root-directory '{"Path": "/app-data", "CreationInfo": {"OwnerUid": 1001, "OwnerGid": 1001, "Permissions": "755"}}'
```

## 挂载 EFS 文件系统

### 先决条件

安装 EFS 挂载帮助程序：

```bash
# Amazon Linux
sudo yum install -y amazon-efs-utils

# Ubuntu
sudo apt-get -y update
sudo apt-get -y install amazon-efs-utils
```

### 挂载到 EC2 实例

```bash
# 创建挂载点
mkdir ~/efs-mount-point

# 使用 EFS 挂载帮助程序挂载
sudo mount -t efs -o tls fs-12345678:/ ~/efs-mount-point

# 使用访问点挂载
sudo mount -t efs -o tls,accesspoint=fsap-12345678 fs-12345678:/ ~/efs-mount-point

# 配置 /etc/fstab 实现自动挂载
echo "fs-12345678:/ /home/ec2-user/efs-mount-point efs _netdev,tls 0 0" | sudo tee -a /etc/fstab
```

### 与容器集成

EFS 可以为 ECS 和 EKS 提供持久存储。

**ECS 任务定义示例**

```json
{
  "containerDefinitions": [
    {
      "name": "my-container",
      "image": "nginx",
      "mountPoints": [
        {
          "sourceVolume": "efs-volume",
          "containerPath": "/usr/share/nginx/html"
        }
      ]
    }
  ],
  "volumes": [
    {
      "name": "efs-volume",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-12345678",
        "rootDirectory": "/web-content",
        "transitEncryption": "ENABLED"
      }
    }
  ]
}
```

### 与 Lambda 集成

可以将 EFS 文件系统挂载到 Lambda 函数，以访问共享数据。

## 数据保护与备份

### AWS Backup

使用 AWS Backup 集中管理 EFS 文件系统的备份：

```bash
# 创建备份计划
aws backup create-backup-plan --backup-plan file://backup-plan.json

# backup-plan.json 示例
{
  "BackupPlanName": "EFS-Daily-Backup",
  "Rules": [
    {
      "RuleName": "Daily",
      "TargetBackupVaultName": "Default",
      "ScheduleExpression": "cron(0 5 ? * * *)",
      "StartWindowMinutes": 480,
      "CompletionWindowMinutes": 10080,
      "Lifecycle": {
        "DeleteAfterDays": 30
      }
    }
  ]
}

# 将 EFS 资源分配给备份计划
aws backup create-backup-selection \
  --backup-plan-id <plan-id> \
  --backup-selection '{"SelectionName": "EFS-Selection", "IamRoleArn": "arn:aws:iam::123456789012:role/service-role/AWSBackupDefaultServiceRole", "Resources": ["arn:aws:elasticfilesystem:region:123456789012:file-system/fs-12345678"]}'
```

### EFS 复制

自动将 EFS 文件系统复制到另一个区域：

```bash
# 创建复制配置
aws efs create-replication-configuration \
  --source-file-system-id fs-12345678 \
  --destinations '[{"Region": "us-west-2"}]'
```

## 安全与访问控制

### 网络安全

- **安全组**：控制对挂载目标的网络访问
- **网络 ACL**：控制子网级别的流量

```bash
# 允许从安全组访问 NFS 端口
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345678 \
  --protocol tcp \
  --port 2049 \
  --source-group sg-abcdefgh
```

### IAM 策略

使用 IAM 策略控制对 EFS API 操作的访问。

### 文件系统策略

基于资源的策略，用于控制对文件系统的访问：

```json
{
  "Version": "2012-10-17",
  "Id": "efs-policy-example",
  "Statement": [
    {
      "Sid": "Allow-read-only-access-to-specific-role",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/ReadOnlyRole"
      },
      "Action": [
        "elasticfilesystem:ClientMount",
        "elasticfilesystem:ClientRead"
      ],
      "Resource": "arn:aws:elasticfilesystem:region:123456789012:file-system/fs-12345678"
    }
  ]
}
```

### 传输中加密

使用 TLS 加密 EFS 和客户端之间的连接。

### 静态加密

EFS 文件系统中的数据使用 AWS KMS 自动加密。

## 性能优化

### 性能最佳实践

1. **并行处理**：
   - 尽可能并行读写文件
   - 使用多线程应用程序

2. **元数据密集型工作负载**：
   - 减少元数据操作（如 `ls`, `stat`）
   - 将小文件打包成大文件

3. **选择正确的模式**：
   - 大多数工作负载使用通用性能模式
   - 对于大规模分析，使用最大 I/O 模式
   - 对于吞吐量需求高的应用，使用预置或弹性吞吐量模式

4. **监控性能**：
   - 使用 CloudWatch 监控吞吐量、IOPS 和延迟

## 监控与日志

### CloudWatch 指标

EFS 提供以下 CloudWatch 指标：

- **BurstCreditBalance**：突发吞吐量模式的积分余额
- **ClientConnections**：客户端连接数
- **DataReadIOBytes/DataWriteIOBytes**：读/写吞- **PercentIOLimit**：达到 IOPS 限制的百分比
- **PermittedThroughput**：允许的总吞吐量
- **TotalIOBytes**：总 I/O 字节数

```bash
# 获取文件系统指标
aws cloudwatch get-metric-statistics \
  --namespace AWS/EFS \
  --metric-name ClientConnections \
  --dimensions Name=FileSystemId,Value=fs-12345678 \
  --start-time 2023-06-15T00:00:00Z \
  --end-time 2023-06-16T00:00:00Z \
  --period 3600 \
  --statistics Average
```

### AWS CloudTrail

记录对 EFS API 的调用，用于审计和合规性。

## 成本优化

1. **使用生命周期管理**：自动将不经常访问的文件移动到 IA 存储类别
2. **选择合适的存储类别**：对非关键工作负载使用 EFS 单可用区
3. **优化吞吐量模式**：
   - 对于可预测的吞吐量需求，使用预置吞吐量模式
   - 对于突发性工作负载，使用弹性吞吐量模式
4. **清理未使用资源**：删除不再需要的文件系统和挂载目标

## EFS 与其他存储服务对比

### EFS vs. EBS

| 特性 | EFS | EBS |
|------|-----|-----|
| 访问模型 | 文件存储 (NFS) | 块存储 |
| 访问范围 | 多实例并发访问 | 单实例访问（或 Multi-Attach） |
| 可用区 | 多可用区 | 单可用区 |
| 扩展性 | 自动扩展 | 手动扩展 |
| 使用场景 | 共享文件系统、Web 服务器、内容管理 | 数据库、启动卷、单个应用数据 |

### EFS vs. S3

| 特性 | EFS | S3 |
|------|-----|----|
| 访问模型 | 文件系统 (NFS) | 对象存储 (HTTP) |
| 数据结构 | 层次结构目录 | 扁平键值对 |
| 性能 | 低延迟、高 IOPS | 高吞吐量 |
| 一致性 | 强一致性 | 强一致性 |
| 使用场景 | 共享文件系统、传统应用 | 数据湖、备份、静态网站托管 |

## 常见使用场景

### Web 服务和内容管理

多个 Web 服务器共享网站内容、图像和插件。

### 共享主目录

为开发人员和数据科学家提供共享的主目录。

### 大数据分析

为 Hadoop 和 Spark 等分析框架提供共享数据存储。

### 媒体处理

多个 EC2 实例并行处理视频和音频文件。

### 容器持久存储

为 ECS 和 EKS 中的有状态容器应用提供共享持久存储。

## 实际应用案例

### 案例 1：可扩展的内容管理系统 (CMS)

一家新闻机构使用 EFS 部署 WordPress 网站：

1. **架构**：
   - 多个 EC2 实例运行 WordPress
   - EFS 文件系统存储共享的 `wp-content` 目录
   - Amazon Aurora 数据库存储网站数据
   - Application Load Balancer 分发流量

2. **优势**：
   - 轻松扩展 Web 服务器
   - 所有服务器共享一致的内容
   - 使用 AWS Backup 简化备份

### 案例 2：容器化微服务

一家金融科技公司使用 EFS 为 EKS 中的微服务提供持久存储：

1. **架构**：
   - 多个微服务作为 Pod 运行在 EKS 集群中
   - EFS 访问点为每个微服务提供隔离的存储目录
   - EFS CSI 驱动程序动态预置持久卷

2. **优势**：
   - 为有状态服务提供共享持久存储
   - 简化了数据共享和管理
   - 与 Kubernetes 生态系统无缝集成

### 案例 3：Lambda 数据处理

一家数据分析公司使用 Lambda 和 EFS 处理数据：

1. **架构**：
   - 数据文件上传到 S3
   - S3 事件触发 Lambda 函数
   - Lambda 函数挂载 EFS 文件系统以访问大型参考数据集
   - 处理结果写回 S3

2. **优势**：
   - Lambda 可以访问大型文件和共享库
   - 避免了每次调用下载大型数据集的开销
   - 无服务器架构，成本效益高 