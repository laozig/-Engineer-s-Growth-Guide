# AWS入门基础

Amazon Web Services (AWS) 是全球领先的云计算平台，提供了丰富的按需服务，包括计算能力、数据库存储、内容分发和其他功能，帮助企业降低IT成本，提高灵活性和可扩展性。本文档将帮助您了解AWS的基本概念和核心服务。

## 云计算概述

### 什么是云计算？

云计算是通过互联网按需提供计算资源（如服务器、存储、数据库、网络、软件等）的交付模式，通常采用按使用量付费的方式。

### 云计算的主要优势

1. **成本效益**：将资本支出转为运营支出，按实际使用量付费
2. **可扩展性**：根据业务需求轻松扩展或缩减资源
3. **灵活性**：快速部署和调整资源以响应业务变化
4. **安全性**：利用云提供商的专业安全实践和规模经济
5. **高可用性**：通过多区域部署实现业务连续性和灾难恢复
6. **全球覆盖**：在全球范围内快速部署应用程序

### 云计算的服务模式

- **基础设施即服务 (IaaS)**：提供虚拟化的计算资源（如EC2、S3）
- **平台即服务 (PaaS)**：提供应用程序开发平台（如Elastic Beanstalk、Lambda）
- **软件即服务 (SaaS)**：提供完整的应用程序（如WorkMail、Chime）

## AWS简介

### AWS的发展历程

- 2002年：Amazon开始内部重构，为未来的AWS奠定基础
- 2006年：AWS正式推出，提供S3和EC2等核心服务
- 2010年代：AWS迅速扩展服务组合，成为云计算市场的领导者
- 至今：AWS提供超过200项服务，覆盖全球多个区域

### AWS的基本架构

AWS基础设施按层次结构组织，从大到小依次为：

1. **区域（Regions）**：地理位置分散的数据中心集群
2. **可用区（Availability Zones）**：每个区域内的独立数据中心
3. **本地区域（Local Zones）**：扩展的基础设施部署，靠近大型人口中心
4. **边缘站点（Edge Locations）**：用于内容缓存的全球分布式站点

### AWS全球区域覆盖

AWS在全球多个地理区域设立了数据中心，帮助用户满足低延迟和数据驻留要求：

- **美洲**：美国东部、美国西部、加拿大、南美洲
- **亚太地区**：中国、日本、韩国、新加坡、印度等
- **欧洲**：爱尔兰、伦敦、法兰克福、巴黎等
- **中东和非洲**：巴林、阿联酋、南非等

## AWS核心服务概览

### 计算服务

- **EC2 (Elastic Compute Cloud)**：可扩展的虚拟服务器
- **Lambda**：无服务器函数计算
- **ECS/EKS**：容器编排服务
- **Lightsail**：简化的虚拟私有服务器

### 存储服务

- **S3 (Simple Storage Service)**：对象存储
- **EBS (Elastic Block Store)**：块存储
- **EFS (Elastic File System)**：文件存储
- **S3 Glacier**：长期归档存储

### 数据库服务

- **RDS (Relational Database Service)**：托管关系数据库
- **DynamoDB**：NoSQL数据库
- **ElastiCache**：内存缓存
- **Redshift**：数据仓库

### 网络服务

- **VPC (Virtual Private Cloud)**：隔离的网络环境
- **Route 53**：DNS和域名服务
- **CloudFront**：内容分发网络
- **ELB (Elastic Load Balancing)**：负载均衡

### 安全服务

- **IAM (Identity and Access Management)**：用户权限管理
- **WAF (Web Application Firewall)**：Web应用防火墙
- **Shield**：DDoS保护
- **GuardDuty**：威胁检测

### 管理工具

- **CloudWatch**：监控和观测
- **CloudFormation**：基础设施即代码
- **CloudTrail**：API活动跟踪
- **Systems Manager**：操作管理

## AWS账户设置

### 创建AWS账户

1. 访问 [AWS官网](https://aws.amazon.com/cn/)
2. 点击"创建AWS账户"按钮
3. 填写个人信息和付款方式
4. 完成电话验证
5. 选择支持计划（通常初学者选择免费的基本支持）

### AWS免费套餐

AWS提供12个月的免费套餐，包括：

- 每月750小时的EC2 t2.micro或t3.micro实例
- 每月5GB的S3标准存储
- 每月750小时的RDS数据库使用
- 每月1百万次的Lambda函数调用
- 其他多种服务的有限量免费使用

> **注意**：即使在免费套餐期间，也请密切监控您的使用情况，以避免意外收费。

### 设置账单警报

为避免意外费用，建议设置账单警报：

1. 登录AWS管理控制台
2. 导航至"账单和成本管理"控制面板
3. 创建预算并设置阈值告警
4. 配置通知以在接近阈值时发送电子邮件

## AWS管理方式

AWS提供多种管理和访问服务的方式：

### AWS管理控制台

基于Web的图形界面，适合初学者和日常管理任务。

### AWS命令行界面 (CLI)

用于自动化和脚本操作的命令行工具，安装方法：

```bash
# 在Linux/macOS上安装
pip install awscli

# 在Windows上安装
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi

# 配置凭证
aws configure
```

### AWS SDK

针对各种编程语言的软件开发工具包，如Python、Java、JavaScript等。

```python
# Python示例：使用Boto3创建S3存储桶
import boto3

s3 = boto3.resource('s3')
bucket = s3.create_bucket(
    Bucket='my-bucket-name',
    CreateBucketConfiguration={'LocationConstraint': 'ap-northeast-1'}
)
```

### 基础设施即代码

使用代码定义和部署基础设施：

- **CloudFormation**：AWS原生解决方案
- **Terraform**：跨云提供商解决方案
- **AWS CDK**：使用熟悉的编程语言

## 下一步

现在您已经了解了AWS的基础知识，建议继续探索以下内容：

1. [账户管理与安全](account-setup.md) - 学习如何设置IAM用户、组和角色
2. [EC2实例详解](compute/ec2.md) - 深入了解AWS的核心计算服务
3. [S3对象存储](storage/s3.md) - 掌握AWS最常用的存储服务
4. [VPC虚拟私有云](networking/vpc.md) - 学习如何构建安全的网络环境

## 参考资源

- [AWS官方文档](https://docs.aws.amazon.com/zh_cn/)
- [AWS架构中心](https://aws.amazon.com/architecture/)
- [AWS培训与认证](https://aws.amazon.com/training/)
- [AWS解决方案库](https://aws.amazon.com/solutions/) 