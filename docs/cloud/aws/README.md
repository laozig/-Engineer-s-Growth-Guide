# AWS云服务指南

本文档提供了关于Amazon Web Services (AWS) 的全面指导，涵盖了核心服务、架构最佳实践、安全考虑、成本优化以及实际应用场景。

## 1. AWS基础

- [AWS入门基础](introduction.md) - 云计算概念与AWS简介
- [账户管理与安全](account-setup.md) - 设置组织、账户、IAM用户与角色
- [AWS全球基础设施](global-infrastructure.md) - 区域、可用区与本地区域
- [AWS价格模式](pricing-model.md) - 按需、预留、Savings Plans与现货实例

## 2. 核心服务

### 计算服务
- [EC2实例详解](compute/ec2.md) - 弹性计算云
- [Lambda无服务器计算](compute/lambda.md) - 事件驱动计算
- [ECS容器服务](compute/ecs.md) - Docker容器编排
- [EKS Kubernetes服务](compute/eks.md) - 托管Kubernetes
- [Fargate无服务器容器](compute/fargate.md) - 无需管理服务器的容器运行环境

### 存储服务
- [S3对象存储](storage/s3.md) - 简单存储服务
- [EBS块存储](storage/ebs.md) - 弹性块存储
- [EFS文件系统](storage/efs.md) - 弹性文件系统
- [S3 Glacier归档存储](storage/glacier.md) - 长期归档解决方案
- [Storage Gateway混合存储](storage/storage-gateway.md) - 混合云存储

### 数据库服务
- [RDS关系型数据库](database/rds.md) - 托管关系数据库服务
- [DynamoDB NoSQL数据库](database/dynamodb.md) - 可扩展性NoSQL数据库
- [ElastiCache内存缓存](database/elasticache.md) - Redis与Memcached
- [Aurora高性能数据库](database/aurora.md) - MySQL和PostgreSQL兼容
- [Redshift数据仓库](database/redshift.md) - 数据仓库与分析

### 网络服务
- [VPC虚拟私有云](networking/vpc.md) - 虚拟网络
- [Route 53 DNS服务](networking/route53.md) - DNS与域名管理
- [CloudFront内容分发](networking/cloudfront.md) - CDN服务
- [ELB负载均衡器](networking/elb.md) - 应用与网络负载均衡
- [Direct Connect专线连接](networking/direct-connect.md) - 本地到AWS的专用网络

### 安全与身份服务
- [IAM身份与访问管理](security/iam.md) - 用户、组与权限
- [AWS WAF Web应用防火墙](security/waf.md) - Web应用安全
- [Shield DDoS防护](security/shield.md) - DDoS缓解
- [GuardDuty威胁检测](security/guardduty.md) - 智能威胁检测
- [Security Hub安全合规中心](security/security-hub.md) - 安全合规管理

### 管理与监控
- [CloudWatch监控](management/cloudwatch.md) - 指标、日志与告警
- [CloudTrail审计](management/cloudtrail.md) - API调用记录与审计
- [CloudFormation基础设施即代码](management/cloudformation.md) - 模板化资源管理
- [Config配置合规性](management/config.md) - 资源配置与合规性跟踪
- [Organizations多账户管理](management/organizations.md) - 企业账户管理

## 3. 解决方案架构

### 应用架构
- [微服务架构](solutions/microservices.md) - 使用AWS构建微服务
- [无服务器应用](solutions/serverless-apps.md) - 使用Lambda和API Gateway
- [容器化应用](solutions/containerized-apps.md) - 使用ECS和EKS
- [事件驱动架构](solutions/event-driven.md) - 使用SQS、SNS和EventBridge
- [混合云架构](solutions/hybrid-cloud.md) - AWS Outposts和Snowball

### 特定场景
- [Web应用托管](solutions/web-hosting.md) - 从简单到复杂的Web应用
- [大数据处理](solutions/big-data.md) - EMR、Athena、Glue集成
- [机器学习与AI](solutions/ml-ai.md) - SageMaker和AI服务
- [DevOps CI/CD](solutions/devops.md) - CodePipeline、CodeBuild与CodeDeploy
- [灾备与高可用](solutions/dr-ha.md) - 多区域部署与故障转移

## 4. 最佳实践

- [Well-Architected框架](best-practices/well-architected.md) - 卓越运营、安全、可靠性、性能效率、成本优化
- [安全最佳实践](best-practices/security.md) - 保护AWS环境
- [成本优化策略](best-practices/cost-optimization.md) - 控制和优化AWS支出
- [性能优化](best-practices/performance.md) - 提高AWS服务性能
- [运维自动化](best-practices/automation.md) - 自动化AWS资源管理

## 5. 实战案例

- [电商平台架构](case-studies/ecommerce.md) - 可扩展电商解决方案
- [内容管理系统](case-studies/cms.md) - 高性能内容平台
- [数据分析平台](case-studies/data-analytics.md) - 企业级数据湖与分析
- [IoT应用后端](case-studies/iot-backend.md) - 物联网设备管理与数据处理
- [移动应用后端](case-studies/mobile-backend.md) - 移动应用的可扩展后端

## 6. 迁移与现代化

- [AWS迁移策略](migration/strategies.md) - 重新托管、平台重构、重建等方法
- [大规模迁移](migration/large-scale.md) - 企业级工作负载迁移计划
- [应用现代化](migration/modernization.md) - 重构遗留应用
- [数据库迁移](migration/database.md) - 使用DMS和SCT进行数据库迁移
- [云原生转型](migration/cloud-native.md) - 向云原生架构转型

## 7. 上手指南

- [AWS CLI使用](guides/aws-cli.md) - 命令行界面
- [AWS SDK应用](guides/aws-sdk.md) - 编程访问AWS资源
- [AWS CDK开发](guides/aws-cdk.md) - 使用代码定义基础设施
- [Terraform管理AWS](guides/terraform.md) - 使用Terraform管理AWS资源
- [IAM权限调试](guides/iam-debugging.md) - 解决权限问题

## 8. 认证准备

- [AWS认证路径](certification/path.md) - AWS认证概览
- [认证解决方案架构师](certification/solutions-architect.md) - Associate与Professional
- [认证开发人员](certification/developer.md) - Associate级别
- [认证SysOps管理员](certification/sysops.md) - Associate级别
- [专业认证](certification/specialty.md) - 安全、数据分析、机器学习等

## 学习路径建议

对于AWS初学者，建议按照以下顺序学习：

1. 阅读[AWS入门基础](introduction.md)了解云计算概念
2. 学习[账户管理与安全](account-setup.md)设置您的AWS环境
3. 探索基础服务：EC2、S3和VPC
4. 了解数据库选项：RDS和DynamoDB
5. 学习监控与管理工具：CloudWatch和CloudFormation
6. 深入研究特定解决方案架构
7. 应用最佳实践优化您的部署

## 参考资源

- [AWS官方文档](https://docs.aws.amazon.com/zh_cn/)
- [AWS Architecture Center](https://aws.amazon.com/architecture/)
- [AWS Well-Architected](https://aws.amazon.com/architecture/well-architected/)
- [AWS博客](https://aws.amazon.com/blogs/china/)
- [AWS GitHub仓库](https://github.com/aws-samples)

## 贡献

欢迎贡献AWS相关文档或完善现有内容。请参阅主项目的[贡献指南](../../../CONTRIBUTING.md)。 