# AWS Direct Connect 专线连接

Direct Connect 提供本地数据中心与 AWS 云之间的专用网络连接，提升带宽、降低延迟并增强安全性。本文档详细介绍 Direct Connect 的原理、架构、配置流程及运维建议。

## 目录

- [服务简介](#服务简介)
- [核心概念与架构](#核心概念与架构)
- [接入方式与场景](#接入方式与场景)
- [配置流程](#配置流程)
- [虚拟接口（VIF）类型](#虚拟接口vif类型)
- [高可用与灾备](#高可用与灾备)
- [安全与合规](#安全与合规)
- [监控与运维](#监控与运维)
- [常见问题排查](#常见问题排查)
- [最佳实践](#最佳实践)
- [参考资源](#参考资源)

## 服务简介

- Direct Connect 通过专线将本地数据中心、办公室或托管环境与 AWS 连接。
- 优势：专线带宽、低延迟、数据安全、稳定性。
- 与 VPN、互联网连接的对比：更高带宽、更低抖动、更高 SLA。

## 核心概念与架构

- **物理连接**：Dedicated Connection（专用物理链路）、Hosted Connection（托管专线）。
- **连接点（Location/PoP）**：AWS 在全球设有 Direct Connect 站点。
- **虚拟接口（VIF）**：
  - 私有 VIF：连接到 VPC
  - 公有 VIF：连接到 AWS 公有服务（如 S3、DynamoDB）
  - Transit VIF：连接到 Direct Connect Gateway，实现多 VPC/多区域互联
- **典型架构**：本地路由器 <-> Direct Connect <-> AWS 边缘 <-> VPC/VGW/DCGW
- **支持速率**：50Mbps ~ 100Gbps，支持链路聚合（LAG）。

## 接入方式与场景

- **专线接入（Dedicated Connection）**：客户直接申请物理专线。
- **托管专线（Hosted Connection/Hosted VIF）**：通过 AWS 合作伙伴提供的托管专线。
- **典型场景**：混合云部署、数据中心迁移、大数据传输、灾备等。

## 配置流程

1. 选择接入点（Location）
2. 申请专线/托管专线
3. 物理链路部署与测试
4. 创建虚拟接口（VIF）
5. 配置本地路由器（BGP 配置、VLAN、IP 地址）
6. 连接到 VPC（通过 VGW 或 Direct Connect Gateway）
7. 验证连通性

## 虚拟接口（VIF）类型

- **私有 VIF**：连接到 VPC，适用于私有子网通信。
- **公有 VIF**：连接到 AWS 公有服务（如 S3、DynamoDB），可访问所有区域的公有服务。
- **Transit VIF**：连接到 Direct Connect Gateway，实现多 VPC/多区域互联。
- 各类型的配置方法与适用场景对比。

## 高可用与灾备

- 多链路冗余设计，建议至少两条物理链路。
- 与 VPN 联动，作为备份链路。
- 跨区域高可用设计。
- 路由优先级与故障切换策略。

## 安全与合规

- 物理链路本身不加密，建议应用层加密（如 IPsec、TLS）。
- 访问控制与隔离：合理配置 VIF、VLAN、路由策略。
- 审计与合规：结合 CloudTrail、CloudWatch 进行操作审计。

## 监控与运维

- CloudWatch 监控 Direct Connect 连接状态、流量、错误等指标。
- 连接状态与告警设置。
- 流量分析与带宽管理。
- 日志采集与分析。

## 常见问题排查

- 物理链路不通：检查光纤、端口、物理层。
- BGP 邻居未建立：检查 BGP 配置、VLAN、IP 地址。
- 路由不可达：检查路由表、ACL、安全组。
- 带宽瓶颈与丢包：分析流量、排查拥塞。
- 访问 AWS 服务异常：检查公有/私有 VIF 配置。

## 最佳实践

- 选型建议：根据业务需求选择专线/托管、速率、接入点。
- 高可用与多链路设计。
- 路由优化与安全加固。
- 成本控制与带宽管理。

## 参考资源

- [AWS Direct Connect 官方文档](https://docs.aws.amazon.com/directconnect/)
- [Direct Connect 入门指南](https://docs.aws.amazon.com/zh_cn/directconnect/latest/UserGuide/Welcome.html)
- [Direct Connect 常见问题](https://aws.amazon.com/cn/directconnect/faqs/)
- [Direct Connect 定价](https://aws.amazon.com/cn/directconnect/pricing/)
