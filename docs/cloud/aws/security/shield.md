# AWS Shield DDoS防护

AWS Shield 是一项托管式分布式拒绝服务 (DDoS) 防护服务，可保护运行在 AWS 上的应用程序免受攻击。本文档详细介绍 Shield 的原理、功能、配置方法、运维与最佳实践。

## 目录

- [服务简介](#服务简介)
- [Shield Standard 与 Shield Advanced](#shield-standard-与-shield-advanced)
- [防护架构](#防护架构)
- [DDoS 攻击类型与防护](#ddos-攻击类型与防护)
- [Shield Advanced 配置](#shield-advanced-配置)
- [与其他 AWS 服务集成](#与其他-aws-服务集成)
- [监控与响应](#监控与响应)
- [Shield Response Team (SRT)](#shield-response-team-srt)
- [成本与保障](#成本与保障)
- [最佳实践](#最佳实践)
- [常见问题排查](#常见问题排查)
- [参考资源](#参考资源)

## 服务简介

AWS Shield 提供针对 DDoS 攻击的持续检测和自动内联缓解，帮助保持应用程序的可用性和响应能力。Shield 分为两个服务级别：

- **Shield Standard**：自动包含在所有 AWS 服务中，无需额外费用
- **Shield Advanced**：提供增强的 DDoS 防护功能，需额外付费

## Shield Standard 与 Shield Advanced

### Shield Standard

- 自动为所有 AWS 客户启用，无需额外配置
- 防护常见的网络层 (L3) 和传输层 (L4) 攻击
- 与 AWS 全球边缘网络集成
- 适用于 Amazon EC2、Elastic Load Balancing、Amazon CloudFront、AWS Global Accelerator 和 Route 53

### Shield Advanced

- 提供增强的 DDoS 检测和缓解功能
- 应用层 (L7) 防护（结合 AWS WAF）
- 24x7 全天候访问 AWS Shield Response Team (SRT)
- 实时 DDoS 攻击可视化
- 成本保障（DDoS 攻击期间的资源扩展费用）
- 专业的安全评估和架构建议

## 防护架构

### 边缘位置防护

- AWS 全球边缘网络（200+ 个 PoP）
- 大容量 DDoS 缓解系统
- 自动流量工程和异常流量丢弃
- 无状态 SYN Flood 缓解技术

### 区域 DDoS 缓解系统

- 保护 EC2 实例和区域性服务
- 自动检测和缓解
- 与 VPC、安全组集成

### 应用层防护

- 结合 AWS WAF 提供应用层防护
- 自定义规则和托管规则
- 速率限制和请求控制

## DDoS 攻击类型与防护

### 网络/传输层攻击

- **SYN Flood**：利用 TCP 三次握手漏洞
- **UDP Reflection**：如 NTP、DNS、SSDP 反射
- **TCP Reflection**：如 SYN-ACK 反射
- **Volumetric 攻击**：大流量耗尽带宽

### 应用层攻击

- **HTTP Flood**：大量 HTTP 请求耗尽应用资源
- **Slowloris**：慢速 HTTP 请求耗尽连接池
- **Cache-busting 攻击**：绕过缓存直接攻击源站
- **WordPress XML-RPC 攻击**：针对 WordPress 的特定攻击

### Shield 防护机制

- 流量模式分析与异常检测
- 自动缓解技术部署
- 流量分类与过滤
- 自适应速率限制
- 全球流量重定向

## Shield Advanced 配置

### 开通与设置

1. 在 AWS Management Console 中导航到 Shield
2. 选择"开通 Shield Advanced"
3. 选择要保护的资源类型
4. 配置保护组（Protection Groups）
5. 设置告警和通知

### 保护资源类型

- CloudFront 分配
- Route 53 托管区域
- 全球加速器
- 应用负载均衡器 (ALB)
- 经典负载均衡器 (CLB)
- 弹性 IP 地址 (EIP)

### 保护组配置

- 按资源类型分组
- 按标签分组
- 自定义分组
- 配置聚合保护（多资源协同防护）

### 与 AWS WAF 集成

- 启用应用层防护
- 配置 Web ACL
- 设置速率限制规则
- 部署托管规则组

## 与其他 AWS 服务集成

### CloudFront 集成

- 全球分布式防护
- 缓存减轻源站压力
- 自定义错误页面

### Route 53 集成

- DNS 查询洪水防护
- 健康检查与故障转移
- 地理位置路由

### AWS WAF 集成

- 应用层防护
- 自定义规则与托管规则
- 流量可视化

### Global Accelerator 集成

- 全球入口点防护
- 多区域部署
- 自动故障转移

### AWS Firewall Manager 集成

- 集中管理 Shield Advanced 保护
- 多账户防护策略
- 合规性监控

## 监控与响应

### CloudWatch 指标与告警

- DDoSDetected
- DDoSAttackBitsPerSecond
- DDoSAttackPacketsPerSecond
- DDoSAttackRequestsPerSecond
- 自定义告警阈值

### 攻击可视化

- 实时攻击监控
- 历史攻击数据
- 攻击向量分析
- 流量模式识别

### 事件通知

- CloudWatch Events/EventBridge 集成
- SNS 通知
- 自动化响应

### 攻击报告

- 详细的攻击摘要
- 攻击向量分析
- 缓解措施效果
- 建议的优化措施

## Shield Response Team (SRT)

- 24x7 专家支持
- 主动参与攻击缓解
- 攻击前准备与演练
- 攻击后分析与优化
- 自定义缓解策略

## 成本与保障

- Shield Advanced 订阅费用
- 数据传输费用减免
- AWS WAF 费用（应用层防护）
- DDoS 成本保障计划
- 服务积分政策

## 最佳实践

### 架构设计

- 使用 CloudFront 作为前端
- 隐藏源站 IP 地址
- 多区域部署
- 过度配置资源（预留容量）
- 无状态应用设计

### 防护配置

- 保护所有公网入口点
- 配置保护组
- 结合 AWS WAF 规则
- 启用高级事件通知
- 定期演练和测试

### 响应流程

- 建立 DDoS 响应计划
- 设置自动化缓解措施
- 配置告警与升级流程
- 与 SRT 建立联系流程
- 定期回顾和更新响应计划

### 成本优化

- 识别关键资源优先保护
- 利用保护组减少资源数量
- 了解成本保障计划适用范围
- 监控和分析防护效果

## 常见问题排查

- 攻击检测延迟
- 误报处理
- 应用性能下降
- SRT 联系流程
- 跨区域保护配置

## 参考资源

- [AWS Shield 官方文档](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html)
- [AWS DDoS 白皮书](https://d1.awsstatic.com/whitepapers/Security/DDoS_White_Paper.pdf)
- [AWS Shield 最佳实践](https://aws.amazon.com/cn/blogs/security/aws-shield-best-practices/)
- [AWS DDoS 响应指南](https://aws.amazon.com/cn/answers/networking/aws-ddos-attack-mitigation/)
- [AWS Shield 定价](https://aws.amazon.com/cn/shield/pricing/) 