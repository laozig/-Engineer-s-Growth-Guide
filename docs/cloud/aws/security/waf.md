# AWS WAF Web应用防火墙

AWS WAF 是一款可扩展的 Web 应用防火墙服务，帮助用户防护常见 Web 攻击（如 SQL 注入、XSS、恶意爬虫等），并与多种 AWS 服务无缝集成。本文档详细介绍 WAF 的原理、功能、配置方法、运维与最佳实践。

## 目录

- [服务简介](#服务简介)
- [核心概念与架构](#核心概念与架构)
- [主要功能](#主要功能)
- [规则与策略](#规则与策略)
- [集成场景](#集成场景)
- [配置流程](#配置流程)
- [日志与监控](#日志与监控)
- [安全与合规](#安全与合规)
- [常见问题排查](#常见问题排查)
- [最佳实践](#最佳实践)
- [参考资源](#参考资源)

## 服务简介

- AWS WAF 保护 Web 应用免受常见攻击（OWASP Top 10）。
- 支持自定义规则和托管规则集。
- 与 CloudFront、ALB、API Gateway、AppSync 等服务集成。
- 按需计费，弹性扩展。

## 核心概念与架构

- **Web ACL（访问控制列表）**：WAF 的核心策略容器，包含一组规则。
- **规则（Rule）**：定义检测和拦截流量的条件。
- **规则组（Rule Group）**：规则的集合，可复用和共享。
- **托管规则（Managed Rule Group）**：AWS 或第三方提供的预置规则集。
- **条件（Statement）**：如 IP 匹配、字符串匹配、正则表达式、地理位置等。
- **操作（Action）**：允许（Allow）、阻止（Block）、计数（Count）。
- **优先级与评估顺序**：规则按优先级依次评估，先匹配先执行。

## 主要功能

- **SQL 注入防护**、**XSS 防护**、**恶意爬虫与自动化工具拦截**
- **IP 黑白名单**、**地理位置限制**、**速率限制（Rate-based Rule）**
- **自定义 Header、Cookie、QueryString 检查**
- **Bot Control**（高级机器人管理）
- **Account Takeover Prevention**（账号接管防护）
- **Captcha 验证**（防止自动化攻击）
- **集成 AWS Shield（DDoS 防护）**

## 规则与策略

- **自定义规则**：基于业务需求灵活配置。
- **托管规则**：快速防护常见威胁，定期自动更新。
- **组合策略**：多层防护，提升安全性。
- **速率限制规则**：防止暴力破解、爬虫等高频攻击。
- **异常流量监控与响应**：结合 Count 动作和 CloudWatch 告警。

## 集成场景

- **CloudFront 集成**：全球边缘防护，适合静态/动态网站。
- **ALB 集成**：保护 Web 应用和 API。
- **API Gateway 集成**：保护 RESTful API。
- **AppSync 集成**：保护 GraphQL API。
- **多账户/多区域统一防护**：通过 AWS Firewall Manager 集中管理。

## 配置流程

1. 创建 Web ACL
2. 添加规则（自定义/托管/规则组）
3. 配置规则优先级与动作
4. 关联资源（CloudFront、ALB、API Gateway、AppSync）
5. 启用日志记录与监控
6. 持续优化规则

## 日志与监控

- **WAF 日志**：支持实时日志（Kinesis Data Firehose）、S3 存储。
- **CloudWatch Metrics**：规则命中数、拦截数、通过数等。
- **CloudWatch Alarms**：异常流量自动告警。
- **AWS Security Hub 集成**：统一安全事件管理。

## 安全与合规

- **最小权限原则**：仅授权必要的 WAF 管理权限。
- **规则变更审计**：结合 CloudTrail 记录操作日志。
- **合规性支持**：PCI DSS、GDPR 等。

## 常见问题排查

- 规则未生效：检查优先级、条件配置、资源关联。
- 误拦截/漏拦截：使用 Count 动作先观测，逐步调整规则。
- 日志无数据：确认日志流配置、权限设置。
- 性能影响：WAF 设计为高性能，极端场景下可联系 AWS Support。
- 规则冲突：合理设置优先级，避免互斥规则。

## 最佳实践

- 结合托管规则与自定义规则，分层防护。
- 先用 Count 动作观测，逐步切换为 Block。
- 定期回顾和优化规则，关注新型威胁。
- 配合 Shield、CloudFront、ALB 实现多层安全。
- 自动化部署与版本管理（IaC、CI/CD）。
- 监控日志，及时响应异常流量。

## 参考资源

- [AWS WAF 官方文档](https://docs.aws.amazon.com/waf/)
- [托管规则文档](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html)
- [WAF 日志与监控](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html)
- [WAF 最佳实践](https://aws.amazon.com/cn/blogs/security/best-practices-for-using-aws-waf/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
