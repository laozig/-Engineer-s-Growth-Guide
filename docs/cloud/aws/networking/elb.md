# AWS ELB 负载均衡器

Elastic Load Balancing (ELB) 自动在多个目标（如 Amazon EC2 实例、容器、IP 地址和 Lambda 函数）之间分配传入的应用程序流量。本文档详细介绍 ELB 的不同类型、功能和最佳实践。

## 目录

- [ELB 简介](#elb-简介)
- [负载均衡器类型](#负载均衡器类型)
- [Application Load Balancer (ALB)](#application-load-balancer-alb)
- [Network Load Balancer (NLB)](#network-load-balancer-nlb)
- [Gateway Load Balancer (GWLB)](#gateway-load-balancer-gwlb)
- [Classic Load Balancer (CLB)](#classic-load-balancer-clb)
- [核心组件](#核心组件)
- [安全功能](#安全功能)
- [监控与日志](#监控与日志)
- [最佳实践与性能优化](#最佳实践与性能优化)
- [常见问题排查](#常见问题排查)

## ELB 简介

- **高可用性**: 自动分配流量到健康的后端目标，实现跨可用区容灾。
- **弹性扩展**: 根据流量变化自动扩展负载均衡能力。
- **安全性**: 提供集成的安全功能，如 SSL/TLS 终止和与 WAF 的集成。
- **灵活性**: 支持不同类型的负载均衡器，以适应不同应用场景。

## 负载均衡器类型

AWS 提供四种类型的负载均衡器：

- **Application Load Balancer (ALB)**: 在应用层（HTTP/HTTPS）运行，提供高级请求路由功能。
- **Network Load Balancer (NLB)**: 在传输层（TCP/UDP/TLS）运行，提供超高性能和低延迟。
- **Gateway Load Balancer (GWLB)**: 在网络层运行，用于部署、扩展和管理第三方虚拟网络设备。
- **Classic Load Balancer (CLB)**: 上一代负载均衡器，仍在 EC2-Classic 网络中支持。建议迁移到新一代负载均衡器。

## Application Load Balancer (ALB)

### 特性
- **第七层路由**: 基于主机名、路径、查询参数、HTTP 标头等进行高级路由。
- **目标类型**: 支持 EC2 实例、IP 地址、Lambda 函数、容器 (ECS, EKS)。
- **安全集成**: 与 AWS WAF、AWS Certificate Manager (ACM) 集成。
- **HTTP/2 和 WebSocket 支持**。
- **重定向和固定响应**: 支持配置 HTTP 重定向和返回固定响应。

### 组件
- **侦听器 (Listener)**: 检查来自客户端的连接请求。
- **规则 (Rule)**: 定义如何将请求路由到目标组。
- **目标组 (Target Group)**: 包含一个或多个已注册的目标。

## Network Load Balancer (NLB)

### 特性
- **第四层路由**: 基于 TCP/UDP 流量进行路由。
- **超高性能**: 每秒可处理数百万个请求，延迟极低。
- **静态 IP**: 为每个可用区的 NLB 提供一个静态 IP 地址。
- **源 IP 地址保留**: 将客户端的源 IP 地址传递给后端目标。
- **TLS 卸载**: 支持在 NLB 上进行 TLS 流量的终止和处理。

### 组件
- **侦听器 (Listener)**: 检查 TCP、UDP 或 TLS 连接。
- **目标组 (Target Group)**: 注册 EC2 实例、IP 地址或 ALB。

## Gateway Load Balancer (GWLB)

### 特性
- **透明网络网关**: 可在网络路径中透明插入虚拟设备。
- **集中化设备管理**: 方便地部署、扩展和管理第三方防火墙、IDS/IPS 等。
- **可扩展性和弹性**: 自动扩展虚拟设备实例。
- **GENEVE 协议支持**: 使用 GENEVE 协议封装流量。

### 组件
- **Gateway Load Balancer**: 提供流量分发。
- **Gateway Load Balancer Endpoint**: 作为路由表中的下一跳，将流量发送到 GWLB。

## Classic Load Balancer (CLB)

- **上一代产品**: 建议迁移到 ALB 或 NLB。
- **支持 EC2-Classic**: 主要用于支持旧的 EC2-Classic 网络。
- **第四层和第七层**: 提供基本的第四层 (TCP/SSL) 和第七层 (HTTP/HTTPS) 负载均衡。

## 核心组件

### 目标组 (Target Groups)
- **目标注册**: 注册 EC2 实例、IP 地址、Lambda 函数等。
- **健康检查**: 监控已注册目标的运行状况，并仅将流量路由到健康目标。
- **属性**: 可配置延迟注销、粘性会话等。

### 健康检查
- **配置**: 可自定义协议、端口、路径、响应超时、检查间隔和阈值。
- **状态**: 目标状态分为 `healthy`, `unhealthy`, `initial` 等。

## 安全功能

- **SSL/TLS 证书**: 与 ACM 集成，轻松部署和管理 SSL 证书。
- **安全组**: 作为虚拟防火墙，控制进出负载均衡器的流量。
- **网络访问控制列表 (NACL)**: 控制子网级别的流量。
- **AWS WAF 集成 (仅 ALB)**: 保护 Web 应用免受常见漏洞攻击。

## 监控与日志

### CloudWatch 指标
- **ALB 指标**: `HealthyHostCount`, `UnHealthyHostCount`, `HTTPCode_Target_2XX_Count`, `TargetConnectionErrorCount` 等。
- **NLB 指标**: `HealthyHostCount`, `UnHealthyHostCount`, `ProcessedBytes`, `ActiveFlowCount` 等。

### 访问日志
- **ALB/NLB 访问日志**: 捕获有关发送到负载均衡器的请求的详细信息，并将其存储在 S3 中。
- **日志分析**: 可使用 Athena、ELK 等工具进行分析。

### CloudTrail 日志
- 记录对 ELB API 的所有调用，用于安全审计和合规性检查。

## 最佳实践与性能优化

- **选择合适的类型**: 根据应用需求选择 ALB、NLB 或 GWLB。
- **跨可用区部署**: 为实现高可用性，将目标部署在多个可用区。
- **启用跨区域负载均衡**: 在目标组级别启用，以均匀分配流量。
- **配置健康检查**: 合理设置健康检查参数以快速响应目标故障。
- **预热 (Warm-up)**: 对于预期有流量突增的场景，联系 AWS Support 进行预热 (主要针对 NLB)。
- **优化后端目标**: 确保后端应用能够处理负载。

## 常见问题排查

- **502 Bad Gateway (ALB)**: 目标组没有健康的目标，或者目标关闭了连接。
- **503 Service Unavailable (ALB)**: 目标组没有注册任何目标，或者目标正在过载。
- **504 Gateway Timeout (ALB)**: 目标未能及时响应请求。
- **健康检查失败**: 检查安全组、NACL、目标应用状态和健康检查配置。
- **客户端连接超时**: 检查路由、安全组和 NLB 目标是否能正确接收流量。

## 参考资源

- [Elastic Load Balancing 官方文档](https://docs.aws.amazon.com/elasticloadbalancing/)
- [Application Load Balancer 用户指南](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/introduction.html)
- [Network Load Balancer 用户指南](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/introduction.html)
- [Gateway Load Balancer 用户指南](https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/introduction.html) 