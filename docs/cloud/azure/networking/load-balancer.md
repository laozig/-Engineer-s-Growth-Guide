# Azure 负载均衡器

> [!NOTE]
> 本文档提供了Azure负载均衡器的详细介绍，包括基本概念、配置方法和最佳实践。

## 概述

Azure 负载均衡器是一项核心的网络服务，用于在多个后端资源之间分配传入的网络流量，提高应用程序的可用性和可靠性。通过负载均衡器，您可以创建高可用性的应用程序架构，确保即使某些后端资源出现故障，服务仍然可以正常运行。

## 负载均衡器类型

Azure提供两种类型的负载均衡器：

### 1. 公共负载均衡器

- **功能**：将来自互联网的流量分发到后端资源
- **用途**：面向互联网的应用程序，如Web应用、API服务等
- **公共IP**：需要至少一个公共IP地址
- **SKU**：提供标准SKU和基本SKU

### 2. 内部负载均衡器

- **功能**：在虚拟网络内部分发流量
- **用途**：多层应用程序的内部层，如数据库层、应用层等
- **可见性**：仅在虚拟网络内部或通过VPN/ExpressRoute连接可见
- **私有IP**：使用私有IP地址

## 负载均衡器SKU比较

| 功能 | 标准SKU | 基本SKU |
|------|---------|---------|
| 后端池大小 | 最多1000个实例 | 最多300个实例 |
| 可用区支持 | 是（区域冗余） | 否 |
| 诊断 | Azure Monitor多维指标 | 基本日志 |
| HA端口 | 支持 | 不支持 |
| 安全性 | 默认安全（关闭) | 默认开放 |
| 出站规则 | 支持 | 不支持 |
| 多前端IP配置 | 支持 | 支持（有限） |
| 虚拟网络服务端点 | 支持 | 不支持 |
| SLA | 99.99% | 不提供 |

## 核心组件

Azure负载均衡器由以下核心组件组成：

### 1. 前端IP配置

- 定义负载均衡器的IP地址（公共或私有）
- 可以配置多个前端IP地址
- 公共负载均衡器使用公共IP，内部负载均衡器使用私有IP

### 2. 后端池

- 接收流量的虚拟机或实例集合
- 可以包含虚拟机、虚拟机规模集、App Service实例等
- 支持跨可用区的资源分布（标准SKU）

### 3. 健康探测

- 定期检查后端资源的健康状态
- 支持HTTP、HTTPS、TCP协议的探测
- 自动从轮询中移除不健康的实例
- 可配置探测间隔、超时和不健康阈值

### 4. 负载均衡规则

- 定义如何将前端流量分发到后端池
- 指定协议（TCP/UDP）、端口映射和会话持久性
- 可配置空闲超时和TCP重置

### 5. 入站NAT规则

- 将特定前端端口转发到特定后端实例
- 常用于SSH/RDP等管理流量
- 支持端口转发和IP浮动

### 6. 出站规则（仅标准SKU）

- 控制从后端实例到公共IP的出站连接
- 配置SNAT（源网络地址转换）端口分配
- 管理出站连接的空闲超时

## 负载均衡算法

Azure负载均衡器使用以下算法分发流量：

### 1. 哈希分发

- 默认算法
- 基于五元组哈希：源IP、源端口、目标IP、目标端口和协议
- 确保同一客户端连接总是路由到同一后端实例（会话亲和性）

### 2. 会话持久性选项

- **无**：可能将来自同一客户端的不同请求发送到不同后端
- **客户端IP**：来自同一客户端IP的请求发送到同一后端
- **客户端IP和协议**：基于客户端IP和协议的组合

## 配置负载均衡器

### 使用Azure门户创建公共负载均衡器

1. 登录Azure门户并创建新的负载均衡器资源
2. 选择订阅、资源组和名称
3. 选择SKU（标准或基本）和类型（公共）
4. 配置公共IP地址
5. 添加后端池并关联虚拟机
6. 创建健康探测（如HTTP:80路径"/"）
7. 配置负载均衡规则（如TCP:80到80）

```json
// Azure ARM模板示例 - 负载均衡器配置
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Network/loadBalancers",
      "apiVersion": "2021-05-01",
      "name": "myLoadBalancer",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "Standard"
      },
      "properties": {
        "frontendIPConfigurations": [
          {
            "name": "myFrontend",
            "properties": {
              "publicIPAddress": {
                "id": "[resourceId('Microsoft.Network/publicIPAddresses', 'myPublicIP')]"
              }
            }
          }
        ],
        "backendAddressPools": [
          {
            "name": "myBackendPool"
          }
        ],
        "probes": [
          {
            "name": "myHealthProbe",
            "properties": {
              "protocol": "Http",
              "port": 80,
              "requestPath": "/",
              "intervalInSeconds": 15,
              "numberOfProbes": 2
            }
          }
        ],
        "loadBalancingRules": [
          {
            "name": "myHTTPRule",
            "properties": {
              "frontendIPConfiguration": {
                "id": "[resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', 'myLoadBalancer', 'myFrontend')]"
              },
              "backendAddressPool": {
                "id": "[resourceId('Microsoft.Network/loadBalancers/backendAddressPools', 'myLoadBalancer', 'myBackendPool')]"
              },
              "probe": {
                "id": "[resourceId('Microsoft.Network/loadBalancers/probes', 'myLoadBalancer', 'myHealthProbe')]"
              },
              "protocol": "Tcp",
              "frontendPort": 80,
              "backendPort": 80,
              "idleTimeoutInMinutes": 15
            }
          }
        ]
      }
    }
  ]
}
```

### 使用Azure CLI创建内部负载均衡器

```bash
# 创建资源组
az group create --name myResourceGroup --location eastus

# 创建虚拟网络和子网
az network vnet create \
  --resource-group myResourceGroup \
  --name myVNet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name mySubnet \
  --subnet-prefix 10.0.0.0/24

# 创建内部负载均衡器
az network lb create \
  --resource-group myResourceGroup \
  --name myInternalLB \
  --sku Standard \
  --vnet-name myVNet \
  --subnet mySubnet \
  --frontend-ip-name myFrontEnd \
  --backend-pool-name myBackEndPool \
  --private-ip-address 10.0.0.10

# 创建健康探测
az network lb probe create \
  --resource-group myResourceGroup \
  --lb-name myInternalLB \
  --name myHealthProbe \
  --protocol tcp \
  --port 80

# 创建负载均衡规则
az network lb rule create \
  --resource-group myResourceGroup \
  --lb-name myInternalLB \
  --name myHTTPRule \
  --protocol tcp \
  --frontend-port 80 \
  --backend-port 80 \
  --frontend-ip-name myFrontEnd \
  --backend-pool-name myBackEndPool \
  --probe-name myHealthProbe
```

## 高级功能

### 1. 跨区域冗余

标准SKU负载均衡器支持跨可用区部署，提供更高的可用性：

- 前端IP可以是区域冗余的
- 后端池可以包含来自多个可用区的资源
- 即使整个可用区出现故障，服务仍然可用

### 2. 出站连接管理

标准SKU负载均衡器提供出站连接的精细控制：

- 出站规则允许配置SNAT端口分配
- 可以指定空闲超时时间
- 支持出站流量的负载均衡

### 3. 多前端配置

负载均衡器支持多个前端IP配置：

- 在同一负载均衡器上托管多个网站/服务
- 为不同服务提供不同的IP地址
- 支持IPv4和IPv6双栈配置

### 4. 直接服务器返回(DSR)

- 允许后端实例直接响应客户端，绕过负载均衡器
- 提高数据传输效率
- 减少负载均衡器的处理负担

## 监控和诊断

### 1. Azure Monitor指标

标准SKU负载均衡器提供以下多维指标：

- 数据路径可用性
- 字节计数
- 数据包计数
- SYN计数
- 健康探测状态
- SNAT连接

### 2. 日志分析

可以配置诊断日志以发送到：

- Azure Monitor日志
- Azure存储账户
- Azure事件中心

### 3. 网络洞察

- 提供负载均衡器性能的可视化视图
- 显示后端实例的健康状态
- 帮助识别配置问题和瓶颈

## 安全最佳实践

### 1. 使用标准SKU

- 默认安全（关闭状态）
- 与网络安全组集成
- 支持更多安全功能

### 2. 网络安全组(NSG)集成

- 在子网或NIC级别应用NSG规则
- 限制只允许必要的流量
- 实施最小权限原则

### 3. 私有链接支持

- 通过私有链接访问Azure PaaS服务
- 保持流量在Azure骨干网络内
- 避免公共互联网暴露

## 性能优化最佳实践

### 1. 后端池配置

- 确保所有后端实例具有相似的配置和容量
- 均匀分布实例到可用区（如使用标准SKU）
- 适当调整后端池大小以处理流量峰值

### 2. 健康探测优化

- 选择适合应用程序的探测协议和路径
- 配置合适的探测间隔和超时
- 实现专用的健康检查端点

### 3. 会话持久性配置

- 根据应用程序需求选择合适的会话持久性选项
- 对无状态应用程序禁用会话持久性
- 考虑应用程序级会话管理

### 4. TCP设置优化

- 调整TCP空闲超时
- 配置TCP重置选项
- 优化SNAT端口使用

## 常见场景与解决方案

### 1. Web应用负载均衡

- 使用公共负载均衡器
- 配置HTTP/HTTPS健康探测
- 考虑与Azure应用程序网关结合使用

### 2. 多层应用程序

- 使用内部负载均衡器连接应用层和数据层
- 公共负载均衡器用于前端Web层
- 配置适当的NSG规则隔离各层

### 3. 高可用性数据库

- 使用内部负载均衡器
- 配置特定于数据库的健康探测
- 实施读写分离模式

### 4. 全球分布式应用

- 结合使用Azure Traffic Manager和区域负载均衡器
- 实现地理冗余
- 优化全球用户访问体验

## 常见问题解答

### 负载均衡器与应用程序网关的区别是什么？

- **负载均衡器**：工作在OSI模型的第4层（传输层），基于IP地址和端口分发流量
- **应用程序网关**：工作在OSI模型的第7层（应用层），可以基于URL路径、主机头等应用层属性路由流量

### 如何处理SSL/TLS终止？

Azure负载均衡器不处理SSL/TLS终止。对于需要SSL终止的场景，可以：
- 在后端服务器上处理SSL/TLS终止
- 使用Azure应用程序网关代替或结合负载均衡器使用
- 部署Azure Front Door服务

### 标准SKU和基本SKU的主要区别是什么？

主要区别包括：
- 标准SKU支持可用区冗余，基本SKU不支持
- 标准SKU提供99.99%的SLA，基本SKU没有SLA
- 标准SKU默认安全（关闭状态），基本SKU默认开放
- 标准SKU支持出站规则和更多高级功能

### 如何解决SNAT端口耗尽问题？

- 使用出站规则增加SNAT端口分配
- 实现连接复用
- 使用保持活动连接减少新连接创建
- 考虑使用NAT网关

## 参考资源

- [Azure负载均衡器官方文档](https://docs.microsoft.com/azure/load-balancer/)
- [负载均衡器SKU比较](https://docs.microsoft.com/azure/load-balancer/skus)
- [负载均衡器设计模式](https://docs.microsoft.com/azure/architecture/guide/technology-choices/load-balancing-overview)
- [Azure负载均衡器最佳实践](https://docs.microsoft.com/azure/load-balancer/load-balancer-standard-availability-zones)

---

> 本文档将持续更新，欢迎提供反馈和建议。 