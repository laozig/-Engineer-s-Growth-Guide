# Microsoft Azure服务与解决方案

> [!NOTE]
> 本文档正在积极开发中。部分内容已完成，其他部分仍在计划阶段。

## 概述

Microsoft Azure是微软的云计算平台，提供了丰富的服务和解决方案，帮助组织构建、部署和管理应用程序。本文档系列旨在提供Azure平台的全面指南，从基础概念到高级应用。

## 目录

- [Azure基础知识](#azure基础知识)
- [核心服务](#核心服务)
- [解决方案架构](#解决方案架构)
- [DevOps与CI/CD](#devops与cicd)
- [安全与合规](#安全与合规)
- [成本管理](#成本管理)
- [最佳实践](#最佳实践)
- [微服务架构](#微服务架构)

## Azure基础知识

- **[Azure概述](azure/introduction.md)** - Azure平台简介和基本概念
- **[账户与订阅](azure/accounts-subscriptions.md)** - 管理Azure账户和订阅
- **[资源管理](azure/resource-management.md)** - Azure资源管理器(ARM)和资源组
- **[虚拟网络](azure/virtual-networks.md)** - Azure虚拟网络和网络服务
- **[Azure门户](azure/portal.md)** - 使用Azure门户管理资源

## 核心服务

### 计算服务

- **[虚拟机](azure/compute/virtual-machines.md)** - IaaS解决方案
- **[App Service](azure/compute/app-service.md)** - PaaS Web应用托管
- **[Azure Functions](azure/compute/functions.md)** - 无服务器计算
- **[容器服务](azure/compute/containers.md)** - AKS与容器实例
- **[Azure 虚拟桌面](azure/compute/virtual-desktop.md)** - 云端桌面解决方案

### 存储服务

- **[Blob存储](azure/storage/blob.md)** - 对象存储
- **[文件存储](azure/storage/files.md)** - 托管文件共享
- **[表存储](azure/storage/tables.md)** - NoSQL键值存储
- **[队列存储](azure/storage/queues.md)** - 消息队列
- **[磁盘存储](azure/storage/disks.md)** - 虚拟机存储

### 数据库服务

- **[Azure SQL](azure/databases/sql.md)** - 托管SQL Server
- **[Cosmos DB](azure/databases/cosmos-db.md)** - 多模型NoSQL数据库
- **[MySQL/PostgreSQL](azure/databases/mysql-postgresql.md)** - 托管开源数据库
- **[SQL数据仓库](azure/databases/synapse.md)** - 企业级分析

### 网络服务

- **[虚拟网络](azure/networking/vnet.md)** - 私有网络
- **[负载均衡器](azure/networking/load-balancer.md)** - 流量分发
- **[应用网关](azure/networking/application-gateway.md)** - Web流量负载均衡
- **[CDN](azure/networking/cdn.md)** - 内容分发网络
- **[VPN网关](azure/networking/vpn.md)** - 站点到站点连接
- **[ExpressRoute](azure/networking/expressroute.md)** - 专用连接

## 解决方案架构

- **[Web应用架构](azure/solutions/web-apps.md)** - 可扩展Web应用
- **[微服务架构](azure/solutions/microservices.md)** - 使用AKS和Service Fabric
- **[无服务器架构](azure/solutions/serverless.md)** - 使用Functions和Logic Apps
- **[大数据解决方案](azure/solutions/big-data.md)** - 使用HDInsight和Databricks
- **[IoT解决方案](azure/solutions/iot.md)** - 使用IoT Hub和Digital Twins
- **[混合云架构](azure/solutions/hybrid.md)** - 使用Arc和Stack

## DevOps与CI/CD

- **[Azure DevOps](azure/devops/overview.md)** - DevOps服务套件
- **[CI/CD管道](azure/devops/pipelines.md)** - 持续集成与部署
- **[GitHub集成](azure/devops/github.md)** - 与GitHub的集成
- **[基础设施即代码](azure/devops/iac.md)** - 使用ARM模板和Bicep

## 安全与合规

- **[身份管理](azure/security/identity.md)** - Azure AD与身份保护
- **[网络安全](azure/security/network.md)** - NSG、防火墙和DDoS保护
- **[数据加密](azure/security/encryption.md)** - 静态和传输中的加密
- **[密钥管理](azure/security/key-vault.md)** - 使用Key Vault
- **[安全中心](azure/security/security-center.md)** - 统一安全管理
- **[合规性](azure/security/compliance.md)** - 法规与标准合规

## 成本管理

- **[定价模型](azure/cost/pricing.md)** - 了解Azure定价
- **[成本优化](azure/cost/optimization.md)** - 优化Azure支出
- **[预算与警报](azure/cost/budgets.md)** - 设置预算和成本警报
- **[成本分析](azure/cost/analysis.md)** - 分析和预测成本

## 最佳实践

- **[架构设计](azure/best-practices/architecture.md)** - 架构设计原则
- **[性能优化](azure/best-practices/performance.md)** - 提升应用性能
- **[可靠性](azure/best-practices/reliability.md)** - 构建可靠的应用
- **[监控与诊断](azure/best-practices/monitoring.md)** - 使用Azure Monitor
- **[灾难恢复](azure/best-practices/disaster-recovery.md)** - 备份和恢复策略

## 微服务架构

- **[微服务架构设计与实现](microservices/design-implementation.md)** - 微服务设计原则和实现方法
- **[微服务通信模式](microservices/communication-patterns.md)** [计划中] - 同步和异步通信模式
- **[微服务数据管理](microservices/data-management.md)** [计划中] - 数据一致性和查询模式
- **[微服务安全](microservices/security.md)** [计划中] - 认证、授权和API安全
- **[微服务监控与可观测性](microservices/monitoring.md)** [计划中] - 日志、指标和分布式追踪

## 文档状态

| 文档 | 状态 |
|------|------|
| [Azure概述](azure/introduction.md) | ✅ 已完成 |
| [账户与订阅](azure/accounts-subscriptions.md) | ✅ 已完成 |
| [资源管理](azure/resource-management.md) | ✅ 已完成 |
| [虚拟网络](azure/virtual-networks.md) | ✅ 已完成 |
| [Azure门户](azure/portal.md) | ✅ 已完成 |
| [虚拟机](azure/compute/virtual-machines.md) | ✅ 已完成 |
| [App Service](azure/compute/app-service.md) | ✅ 已完成 |
| [Azure Functions](azure/compute/functions.md) | ✅ 已完成 |
| [容器服务](azure/compute/containers.md) | ✅ 已完成 |
| [Azure 虚拟桌面](azure/compute/virtual-desktop.md) | ✅ 已完成 |
| [Blob存储](azure/storage/blob.md) | ✅ 已完成 |
| [文件存储](azure/storage/files.md) | ✅ 已完成 |
| [表存储](azure/storage/tables.md) | ✅ 已完成 |
| [队列存储](azure/storage/queues.md) | ✅ 已完成 |
| [磁盘存储](azure/storage/disks.md) | ✅ 已完成 |
| [Azure SQL](azure/databases/sql.md) | ✅ 已完成 |
| [Cosmos DB](azure/databases/cosmos-db.md) | ✅ 已完成 |
| [MySQL/PostgreSQL](azure/databases/mysql-postgresql.md) | ✅ 已完成 |
| [SQL数据仓库](azure/databases/synapse.md) | ✅ 已完成 |
| [虚拟网络](azure/networking/vnet.md) | ✅ 已完成 |
| [负载均衡器](azure/networking/load-balancer.md) | ✅ 已完成 |
| [应用网关](azure/networking/application-gateway.md) | ✅ 已完成 |
| [CDN](azure/networking/cdn.md) | ✅ 已完成 |
| [VPN网关](azure/networking/vpn.md) | ✅ 已完成 |
| [ExpressRoute](azure/networking/expressroute.md) | ✅ 已完成 |
| [Web应用架构](azure/solutions/web-apps.md) | ✅ 已完成 |
| [微服务架构](azure/solutions/microservices.md) | ✅ 已完成 |
| [无服务器架构](azure/solutions/serverless.md) | ✅ 已完成 |
| [大数据解决方案](azure/solutions/big-data.md) | ✅ 已完成 |
| [IoT解决方案](azure/solutions/iot.md) | ✅ 已完成 |
| [混合云架构](azure/solutions/hybrid.md) | ✅ 已完成 |
| [Azure DevOps](azure/devops/overview.md) | ✅ 已完成 |
| [CI/CD管道](azure/devops/pipelines.md) | ✅ 已完成 |
| [GitHub集成](azure/devops/github.md) | ✅ 已完成 |
| [基础设施即代码](azure/devops/iac.md) | ✅ 已完成 |
| [身份管理](azure/security/identity.md) | ✅ 已完成 |
| [网络安全](azure/security/network.md) | ✅ 已完成 |
| [数据加密](azure/security/encryption.md) | ✅ 已完成 |
| [密钥管理](azure/security/key-vault.md) | ✅ 已完成 |
| [安全中心](azure/security/security-center.md) | ✅ 已完成 |
| [合规性](azure/security/compliance.md) | ✅ 已完成 |
| [定价模型](azure/cost/pricing.md) | ✅ 已完成 |
| [成本优化](azure/cost/optimization.md) | ✅ 已完成 |
| [预算与警报](azure/cost/budgets.md) | ✅ 已完成 |
| [成本分析](azure/cost/analysis.md) | ✅ 已完成 |
| [架构设计](azure/best-practices/architecture.md) | ✅ 已完成 |
| [性能优化](azure/best-practices/performance.md) | ✅ 已完成 |
| [可靠性](azure/best-practices/reliability.md) | ✅ 已完成 |
| [监控与诊断](azure/best-practices/monitoring.md) | ✅ 已完成 |
| [灾难恢复](azure/best-practices/disaster-recovery.md) | ✅ 已完成 |
| [微服务架构设计与实现](microservices/design-implementation.md) | ✅ 已完成 |
| 其他解决方案架构相关文档 | 🔄 计划中 |

## 学习路径

1. 从[Azure基础知识](#azure基础知识)开始，了解平台基本概念
2. 探索[核心服务](#核心服务)，熟悉常用服务的功能和用途
3. 学习[解决方案架构](#解决方案架构)，了解如何构建完整解决方案
4. 深入[DevOps与CI/CD](#devops与cicd)、[安全与合规](#安全与合规)和[成本管理](#成本管理)
5. 应用[最佳实践](#最佳实践)优化您的Azure应用和基础设施

## 资源

- [Azure官方文档](https://docs.microsoft.com/azure/)
- [Azure架构中心](https://docs.microsoft.com/azure/architecture/)
- [Azure学习路径](https://docs.microsoft.com/learn/azure/)
- [Azure GitHub示例](https://github.com/Azure-Samples)

---

> 本文档将持续更新，欢迎提供反馈和建议。 