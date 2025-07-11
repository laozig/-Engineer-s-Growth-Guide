# Amazon S3 Glacier

Amazon S3 Glacier 和 S3 Glacier Deep Archive 是安全、持久且成本极低的云存储服务，适用于数据归档和长期备份。

## 目录

- [概述](#概述)
- [核心概念](#核心概念)
- [检索选项与速度](#检索选项与速度)
- [S3 Glacier 与 S3 存储类的关系](#s3-glacier-与-s3-存储类的关系)
- [数据模型与操作](#数据模型与操作)
- [文件库锁定 (Vault Lock)](#文件库锁定-vault-lock)
- [数据保护与安全](#数据保护与安全)
- [数据检索流程](#数据检索流程)
- [监控与日志](#监控与日志)
- [成本模型](#成本模型)
- [最佳实践](#最佳实践)
- [常见使用场景](#常见使用场景)
- [实际应用案例](#实际应用案例)

## 概述

Amazon S3 Glacier 专为长期数据归档而设计，提供了两种服务：

1.  **S3 Glacier**: 适用于不常访问且可接受数分钟到数小时检索时间的归档数据。
2.  **S3 Glacier Deep Archive**: AWS 中成本最低的存储选项，适用于需要保留数年但很少访问的数据，检索时间通常在 12 小时内。

主要特点：

- **极低成本**: 是云中成本最低的存储解决方案之一。
- **高持久性**: 设计持久性为 99.999999999% (11个9)。
- **安全性**: 支持静态和传输中加密，并提供强大的访问控制。
- **合规性支持**: 通过 Vault Lock 功能支持 WORM (一次写入，多次读取) 等合规性要求。
- **与 S3 集成**: 通过 S3 生命周期策略无缝集成，自动化数据归档。

## 核心概念

### 文件库 (Vault)

文件库是 Glacier 中存储存档的容器。每个 AWS 账户可以在每个区域创建多达 1000 个文件库。

### 存档 (Archive)

存档是 Glacier 中存储的任何数据对象，如照片、视频或文档。它是 Glacier 中的基本存储单元，最大可达 40TB。

### 任务 (Job)

Glacier 中的操作是异步的。您需要启动一个任务来执行操作，例如检索存档或获取文件库清单。任务完成后，您可以下载其输出。

## 检索选项与速度

Glacier 提供多种数据检索选项，以平衡成本和访问时间：

### S3 Glacier 检索选项

| 检索选项 | 典型检索时间 | 成本 | 适用场景 |
| :--- | :--- | :--- | :--- |
| **加急型 (Expedited)** | 1-5 分钟 | 最高 | 紧急访问归档数据 |
| **标准型 (Standard)** | 3-5 小时 | 中等 | 标准数据恢复需求 |
| **批量型 (Bulk)** | 5-12 小时 | 最低 | 大规模、非紧急的数据检索 |

### S3 Glacier Deep Archive 检索选项

| 检索选项 | 典型检索时间 | 成本 | 适用场景 |
| :--- | :--- | :--- | :--- |
| **标准型 (Standard)** | 12 小时内 | 中等 | 默认的 Deep Archive 恢复 |
| **批量型 (Bulk)** | 48 小时内 | 最低 | 最大规模、成本最低的数据恢复 |

## S3 Glacier 与 S3 存储类的关系

虽然 S3 Glacier 是一个独立的服务，但更常见和推荐的使用方式是将其作为 S3 的存储类，通过 S3 生命周期策略进行管理。

- **S3 Glacier Instant Retrieval**: 用于需要毫秒级访问的归档数据。
- **S3 Glacier Flexible Retrieval**: 对应 S3 Glacier 服务，提供分钟到小时的灵活检索。
- **S3 Glacier Deep Archive**: 对应 S3 Glacier Deep Archive 服务，提供最低成本的长期存储。

**推荐**: 除非有特定需求直接使用 Glacier API，否则应通过 S3 生命周期策略将对象转换到 Glacier 存储类。

## 数据模型与操作

### 创建文件库

```bash
# 创建一个名为 my-vault 的文件库
aws glacier create-vault --account-id - --vault-name my-vault
```

### 上传存档

#### 使用 S3 生命周期策略 (推荐)

这是将数据归档到 Glacier 最常见的方法。

```json
// S3 生命周期策略示例
{
  "Rules": [
    {
      "ID": "ArchiveToGlacierAfter90Days",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "documents/"
      },
      "Transitions": [
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        }
      ]
    },
    {
      "ID": "ArchiveToDeepArchiveAfter1Year",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "logs/"
      },
      "Transitions": [
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ]
    }
  ]
}
```

#### 直接上传到 Glacier (使用 CLI)

```bash
# 将文件 my-archive.zip 上传到 my-vault
aws glacier upload-archive --account-id - --vault-name my-vault --body my-archive.zip
```

## 文件库锁定 (Vault Lock)

Vault Lock 允许您部署和强制执行合规性控制。一旦锁定，策略将无法更改。

### 创建 Vault Lock 策略

```bash
# 1. 创建锁定策略文件 (lock-policy.json)
#    此策略示例禁止删除存档
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DisallowDelete",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "glacier:DeleteArchive",
      "Resource": "arn:aws:glacier:region:account-id:vaults/my-vault"
    }
  ]
}

# 2. 启动锁定过程
aws glacier initiate-vault-lock --account-id - --vault-name my-vault --policy file://lock-policy.json

# 3. (在24小时内) 完成锁定过程
aws glacier complete-vault-lock --account-id - --vault-name my-vault --lock-id <lock-id-from-previous-step>
```

## 数据保护与安全

### 加密

- **传输中加密**: 默认使用 HTTPS/TLS 加密。
- **静态加密**: 默认使用 AES-256 加密。

### 访问控制

- **IAM 策略**: 控制用户和角色对 Glacier API 操作的权限。
- **文件库策略**: 基于资源的策略，用于跨账户共享或限制对特定文件库的访问。

```json
// 文件库策略示例: 允许特定 IAM 用户检索存档
{
    "Version":"2012-10-17",
    "Statement":[
       {
          "Sid": "Allow-retrieval-for-user",
          "Effect": "Allow",
          "Principal": {
             "AWS": "arn:aws:iam::123456789012:user/data-analyst"
          },
          "Action": [
             "glacier:InitiateJob",
             "glacier:GetJobOutput"
          ],
          "Resource": "arn:aws:glacier:region:123456789012:vaults/my-vault"
       }
    ]
}
```

## 数据检索流程

数据检索是一个异步的两步过程：

1.  **启动检索任务**:
    您需要启动一个 `archive-retrieval` 任务，并指定检索速度。

2.  **下载数据**:
    任务完成后，您可以下载任务的输出。下载链接通常在 24 小时内有效。

### 检索示例 (使用 CLI)

```bash
# 1. 启动标准检索任务
aws glacier initiate-job \
  --account-id - \
  --vault-name my-vault \
  --job-parameters '{"Type": "archive-retrieval", "ArchiveId": "YOUR_ARCHIVE_ID", "Tier": "Standard"}'

# 任务启动后会返回一个 JobId

# 2. 检查任务状态
aws glacier describe-job \
  --account-id - \
  --vault-name my-vault \
  --job-id "YOUR_JOB_ID"

# 3. 任务完成后 (Succeeded: true)，下载数据
aws glacier get-job-output \
  --account-id - \
  --vault-name my-vault \
  --job-id "YOUR_JOB_ID" \
  output.zip
```

## 监控与日志

- **AWS CloudTrail**: 记录所有对 Glacier API 的调用，用于审计和安全分析。
- **Amazon CloudWatch**: 通过与 SNS 集成，可以监控 Glacier 任务的完成状态并发送通知。
- **文件库清单**: 您可以启动一个 `inventory-retrieval` 任务来获取文件库中所有存档的列表。

```bash
# 启动文件库清单任务
aws glacier initiate-job \
  --account-id - \
  --vault-name my-vault \
  --job-parameters '{"Type": "inventory-retrieval"}'
```

## 成本模型

Glacier 的定价模型包括以下几个部分：

- **存储费用**: 按每月每 GB 收费，是主要成本。Deep Archive 成本更低。
- **上传费用**: 通过 S3 生命周期策略上传免费，直接上传有少量费用。
- **检索费用**:
  - 按检索的数据量 (GB) 收费。
  - 按检索请求次数收费。
  - 费用因检索速度（加急型、标准型、批量型）而异。
- **提前删除费用**: 在最短存储期（Glacier 为 90 天，Deep Archive 为 180 天）之前删除存档会产生费用。

## 最佳实践

1.  **使用 S3 生命周期策略**: 这是将数据移入和移出 Glacier 的最简单、最推荐的方法。
2.  **聚合小文件**: 将大量小文件打包成一个大文件（如 .zip 或 .tar）再上传，以降低管理和检索成本。
3.  **规划数据检索**: 提前规划您的数据恢复需求，以选择成本最低的检索选项。避免不必要的加急检索。
4.  **使用文件库清单**: 定期生成文件库清单，以跟踪您的归档数据。
5.  **为合规性使用 Vault Lock**: 如果您有监管或合规性要求，请使用 Vault Lock 来强制执行数据保留策略。
6.  **标记资源**: 为文件库添加标签，以便进行成本分配和管理。

## 常见使用场景

- **媒体资产归档**: 存储原始视频素材、高分辨率图像和其他大型媒体文件。
- **医疗记录归档**: 长期保存病历、医学影像以满足法规要求。
- **金融服务数据保留**: 归档交易记录、财务报表等以备审计。
- **科学数据保存**: 存储大型研究数据集、基因组数据等。
- **磁带替换**: 用云端归档替换传统的物理磁带备份基础设施。
- **数字内容保留**: 长期保存数字图书馆、博物馆藏品等文化遗产。

## 实际应用案例

### 案例：广播公司的媒体归档

一家大型广播公司需要归档数 PB 的历史视频素材，以降低存储成本并替换其老化的磁带库。

1.  **架构设计**:
    - **S3 Standard**: 用于存储近期和频繁访问的节目。
    - **S3 生命周期策略**:
        - 30 天后，将不常访问的素材自动转换到 `S3 Standard-IA`。
        - 90 天后，将素材转换到 `S3 Glacier Flexible Retrieval` 进行归档。
        - 超过 7 年的合规性归档转移到 `S3 Glacier Deep Archive`。
    - **元数据管理**: 使用 Amazon DynamoDB 存储每个存档的元数据（如节目名称、日期、内容描述），以便快速搜索。

2.  **工作流程**:
    - 新的视频素材上传到 S3 Standard。
    - 生命周期策略自动处理归档流程。
    - 当需要旧素材时，制作人员通过内部应用程序搜索元数据，找到存档 ID。
    - 应用程序启动一个 `Standard` 检索任务。
    - 任务完成后，通知制作人员，他们可以下载并使用该素材。

3.  **优势**:
    - 大幅降低了长期存储成本。
    - 提高了数据持久性和可用性。
    - 简化了数据检索流程，无需物理磁带操作。
    - 通过 Vault Lock 满足了部分内容的长期保留合规性要求。 