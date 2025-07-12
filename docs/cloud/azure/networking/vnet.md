# Azure 虚拟网络 (VNet)

> [!NOTE]
> 本文档提供了Azure虚拟网络的全面概述，包括其特性、设计原则、安全性和最佳实践。

## 概述

Azure 虚拟网络 (VNet) 是Azure中网络服务的基础构建块，提供了一个隔离、安全的环境，用于在云中部署Azure资源。虚拟网络使您能够安全地相互通信，与Internet通信，以及与本地网络通信。它本质上是云中您自己的网络，类似于传统数据中心中的网络，但具有Azure基础设施提供的可扩展性、可用性和隔离优势。

## 核心概念

### 虚拟网络基础

1. **地址空间**：
   - 使用CIDR表示法定义（例如10.0.0.0/16）
   - 可以添加、修改和删除地址空间
   - 不能与其他虚拟网络或本地网络重叠（如果计划连接）

2. **子网**：
   - 虚拟网络内的地址范围细分
   - 用于组织和保护资源
   - 可以应用不同的安全策略（NSG）
   - 某些子网名称是保留的（如GatewaySubnet）

3. **区域和订阅**：
   - VNet限定于单个区域/位置
   - 可以跨可用性区域
   - 可以连接到其他区域的VNet
   - 可以跨订阅连接

### 网络通信

1. **内部通信**：
   - 同一VNet中的资源可以通过私有IP地址相互通信
   - 默认允许所有子网之间的流量
   - 可以使用NSG和路由表控制流量

2. **外部通信**：
   - Internet出站：默认允许
   - Internet入站：需要公共IP或负载均衡器
   - 与本地网络：通过VPN或ExpressRoute
   - 与其他VNet：通过对等互连或VPN

3. **名称解析**：
   - Azure提供基本DNS服务
   - 可以使用自定义DNS服务器
   - 支持私有DNS区域

## 设计和规划

### 地址空间规划

规划地址空间是VNet设计中最关键的决策之一：

1. **选择合适的大小**：
   - 考虑当前和未来需求
   - 私有IP地址范围(RFC 1918):
     - 10.0.0.0 - 10.255.255.255 (10.0.0.0/8)
     - 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
     - 192.168.0.0 - 192.168.255.255 (192.168.0.0/16)
   - 避免使用已在本地网络中使用的范围

2. **子网划分策略**：
   - 按照应用层划分（Web/App/DB）
   - 按照安全边界划分
   - 按照管理边界划分
   - 为每个子网预留足够空间

```
示例地址规划:
VNet: 10.0.0.0/16 (65,536个地址)
  |-- 子网1(Web层): 10.0.0.0/24 (256个地址)
  |-- 子网2(应用层): 10.0.1.0/24 (256个地址)
  |-- 子网3(数据层): 10.0.2.0/24 (256个地址)
  |-- GatewaySubnet: 10.0.255.0/27 (32个地址)
  |-- AzureBastionSubnet: 10.0.254.0/27 (32个地址)
```

3. **特殊子网**：
   - **GatewaySubnet**：用于VPN/ExpressRoute网关，至少/27
   - **AzureBastionSubnet**：用于Azure Bastion，必须是/27或更大
   - **Azure Firewall子网**：名称必须是AzureFirewallSubnet，至少/26

### 网络拓扑模型

根据组织需求选择合适的网络拓扑：

1. **平面网络**：
   - 所有资源在一个VNet中
   - 简单易管理
   - 适合小型部署

2. **中枢辐射型(Hub-Spoke)**：
   - 中心VNet连接到多个辐射VNet
   - 中心集中共享服务（安全、连接）
   - 辐射包含独立工作负载
   - 适合大型企业部署

3. **全网格型**：
   - 所有VNet直接互连
   - 最低延迟
   - 管理复杂度高
   - 适合特定性能要求

4. **传输网络**：
   - 专用VNet用于连接其他网络
   - 集中路由和安全控制
   - 适合复杂的多区域部署

## 连接选项

### VNet对等互连

VNet对等互连允许两个虚拟网络无缝连接：

1. **特点**：
   - 低延迟、高带宽的私有连接
   - 无需公共IP
   - 流量保持在Microsoft骨干网络
   - 支持跨区域和跨订阅

2. **类型**：
   - **区域内对等互连**：同一区域内的VNet
   - **全球对等互连**：不同区域的VNet

3. **配置**：
```powershell
# 创建从VNet1到VNet2的对等互连
Add-AzVirtualNetworkPeering `
  -Name "VNet1-to-VNet2" `
  -VirtualNetwork $vnet1 `
  -RemoteVirtualNetworkId $vnet2.Id

# 创建从VNet2到VNet1的对等互连
Add-AzVirtualNetworkPeering `
  -Name "VNet2-to-VNet1" `
  -VirtualNetwork $vnet2 `
  -RemoteVirtualNetworkId $vnet1.Id
```

4. **注意事项**：
   - 对等互连不具有传递性
   - 需要在两个VNet之间分别配置
   - 地址空间不能重叠

### VPN连接

使用VPN网关连接到本地网络或其他云：

1. **站点到站点(S2S)VPN**：
   - 连接本地网络和Azure VNet
   - 使用IPsec/IKE加密
   - 支持多个站点连接

2. **点到站点(P2S)VPN**：
   - 连接单个客户端到Azure VNet
   - 使用SSTP、IKEv2或OpenVPN协议
   - 适合远程工作人员

3. **VNet到VNet VPN**：
   - 通过VPN网关连接VNet
   - 适用于不支持对等互连的场景
   - 支持跨区域和跨订阅

4. **网关SKU选择**：
   - 基本：测试/概念验证
   - VpnGw1-5：生产工作负载，带宽从650Mbps到10Gbps不等
   - ErGw1-3：ExpressRoute网关

### ExpressRoute

提供私有连接到Microsoft云服务：

1. **特点**：
   - 不通过公共Internet
   - 更高的可靠性、速度和安全性
   - 低延迟和一致的延迟
   - 最高可达10Gbps带宽

2. **连接模型**：
   - CloudExchange共置
   - 点对点以太网连接
   - 任意到任意连接

3. **路由域**：
   - 私有对等互连：连接到Azure VNet
   - Microsoft对等互连：连接到Microsoft 365服务
   - 公共对等互连（已弃用）

## 安全性

### 网络安全组(NSG)

NSG包含安全规则，控制进出子网和网络接口的流量：

1. **规则组件**：
   - 优先级
   - 源/目标（IP地址、服务标记、应用安全组）
   - 协议（TCP、UDP、ICMP、Any）
   - 方向（入站/出站）
   - 端口范围
   - 操作（允许/拒绝）

2. **默认规则**：
   - 允许VNet内部通信
   - 允许Azure负载均衡器的入站流量
   - 拒绝所有其他入站流量
   - 允许所有出站流量

3. **最佳实践**：
   - 使用服务标记简化管理
   - 使用应用安全组基于应用功能分组
   - 创建最小权限规则
   - 规划规则优先级，留出间隔

```json
// NSG规则示例
{
  "name": "allow-web",
  "protocol": "Tcp",
  "sourceAddressPrefix": "Internet",
  "sourcePortRange": "*",
  "destinationAddressPrefix": "10.0.0.0/24",
  "destinationPortRange": "80,443",
  "access": "Allow",
  "priority": 100,
  "direction": "Inbound"
}
```

### 应用安全组(ASG)

将VM分组为应用逻辑单元，简化NSG规则管理：

1. **特点**：
   - 按应用角色分组VM（如Web服务器、数据库服务器）
   - 在NSG规则中引用ASG而非IP地址
   - 减少维护复杂性

2. **使用场景**：
   - 多层应用程序
   - 微服务架构
   - 需要频繁变更的环境

```powershell
# 创建ASG
$webAsg = New-AzApplicationSecurityGroup `
  -ResourceGroupName "myResourceGroup" `
  -Name "WebServers" `
  -Location "ChinaEast2"

# 在NSG规则中引用ASG
$nsgRule = New-AzNetworkSecurityRuleConfig `
  -Name "AllowHTTP" `
  -Access Allow `
  -Protocol Tcp `
  -Direction Inbound `
  -Priority 100 `
  -SourceAddressPrefix Internet `
  -SourcePortRange * `
  -DestinationApplicationSecurityGroup $webAsg `
  -DestinationPortRange 80
```

### Azure 防火墙

托管的云防火墙服务，提供高可用性和无限云可扩展性：

1. **功能**：
   - 内置高可用性
   - 无限云可扩展性
   - FQDN筛选
   - 网络流量筛选规则
   - 应用程序规则（URL筛选）
   - 威胁情报

2. **部署模式**：
   - 标准模式：基本防火墙功能
   - 强制隧道模式：所有Internet流量强制通过本地网关

3. **规则集**：
   - NAT规则：将入站流量转换并筛选到内部IP
   - 网络规则：基于源/目标/协议/端口筛选流量
   - 应用程序规则：控制出站HTTP/S访问

### 服务终结点

为Azure服务提供从VNet的直接连接：

1. **优势**：
   - 从VNet直接连接到Azure服务
   - 通过Microsoft骨干网络优化路由
   - 保护Azure资源，限制只能从VNet访问
   - 无需公共IP

2. **支持的服务**：
   - Azure Storage
   - Azure SQL Database
   - Azure Cosmos DB
   - Azure Key Vault
   - Azure Service Bus
   - 等等

3. **配置**：
```powershell
# 为子网启用服务终结点
$subnet = Get-AzVirtualNetworkSubnetConfig `
  -Name "mySubnet" `
  -VirtualNetwork $vnet

Set-AzVirtualNetworkSubnetConfig `
  -Name "mySubnet" `
  -VirtualNetwork $vnet `
  -AddressPrefix $subnet.AddressPrefix `
  -ServiceEndpoint "Microsoft.Storage"

$vnet | Set-AzVirtualNetwork
```

### 私有链接

为Azure PaaS服务或客户/合作伙伴服务提供私有连接：

1. **与服务终结点的区别**：
   - 私有链接提供私有IP连接到特定资源实例
   - 服务终结点仍使用公共IP，但限制访问源

2. **优势**：
   - 私有IP访问Azure服务
   - 防止数据泄露风险
   - 全球连接到服务，无需公共对等互连
   - 跨区域和跨租户连接

3. **支持的服务**：
   - Azure Storage
   - Azure SQL Database
   - Azure Cosmos DB
   - Azure Key Vault
   - Azure Kubernetes Service
   - 等等

## 高级功能

### 用户定义路由(UDR)

自定义VNet内的流量路径：

1. **用途**：
   - 通过网络虚拟设备(NVA)路由流量
   - 强制通过特定路径
   - 覆盖Azure默认路由

2. **路由表组件**：
   - 名称
   - 地址前缀
   - 下一跳类型（虚拟设备、VNet网关、Internet等）
   - 下一跳地址（如适用）

```powershell
# 创建路由表
$routeTable = New-AzRouteTable `
  -ResourceGroupName "myResourceGroup" `
  -Location "ChinaEast2" `
  -Name "myRouteTable"

# 添加路由
Add-AzRouteConfig `
  -Name "ToFirewall" `
  -AddressPrefix "0.0.0.0/0" `
  -NextHopType "VirtualAppliance" `
  -NextHopIpAddress "10.0.100.4" `
  -RouteTable $routeTable

$routeTable | Set-AzRouteTable

# 关联到子网
Set-AzVirtualNetworkSubnetConfig `
  -Name "mySubnet" `
  -VirtualNetwork $vnet `
  -AddressPrefix "10.0.1.0/24" `
  -RouteTable $routeTable

$vnet | Set-AzVirtualNetwork
```

### 网络虚拟设备(NVA)

在Azure中部署网络功能设备：

1. **常见NVA类型**：
   - 防火墙
   - 负载均衡器
   - WAN优化器
   - SD-WAN设备

2. **部署考虑因素**：
   - 高可用性（使用负载均衡器或Azure Route Server）
   - 监控和警报
   - 吞吐量和性能
   - IP转发启用

3. **最佳实践**：
   - 使用可用性集或区域
   - 配置健康探测
   - 考虑主动-主动或主动-被动模式
   - 使用UDR路由流量

### 虚拟WAN

简化大规模分支连接的服务：

1. **特点**：
   - 统一连接管理
   - 自动化站点到站点VPN
   - 按需ExpressRoute连接
   - 与SD-WAN设备集成

2. **组件**：
   - 虚拟WAN中心
   - 中心到中心连接
   - 分支连接（VPN/ExpressRoute）
   - 路由

3. **使用场景**：
   - 大型分支机构网络
   - 全球连接需求
   - 需要简化管理的企业

### DDoS保护

保护应用程序免受分布式拒绝服务攻击：

1. **保护级别**：
   - **基本**：所有Azure资源自动启用
   - **标准**：增强的缓解功能，适用于面向Internet的应用

2. **标准层功能**：
   - 流量监控和机器学习
   - DDoS快速响应支持
   - 成本保护
   - 攻击分析和报告

3. **最佳实践**：
   - 为关键应用启用标准保护
   - 设计应用程序以增强弹性
   - 实施警报和监控

## 监控和诊断

### 网络监视器

Azure网络监视器提供全面的网络监控和诊断：

1. **连接监视器**：
   - 监控端到端连接
   - 检测网络瓶颈
   - 可视化网络拓扑

2. **NSG流日志**：
   - 记录通过NSG的流量
   - 分析安全规则效果
   - 排查连接问题

3. **VPN诊断**：
   - 排查VPN连接问题
   - 分析网关性能
   - 监控连接状态

4. **数据包捕获**：
   - 捕获VM网络流量
   - 深入分析网络问题
   - 导出为标准格式

### 诊断日志

为网络资源启用诊断日志：

1. **可记录资源**：
   - NSG
   - 公共IP
   - 负载均衡器
   - 网络接口
   - VPN网关

2. **存储选项**：
   - Azure存储账户
   - Log Analytics工作区
   - Event Hub

3. **配置**：
```powershell
# 为NSG启用流日志
$nsg = Get-AzNetworkSecurityGroup -Name "myNSG" -ResourceGroupName "myResourceGroup"
$storageAccount = Get-AzStorageAccount -Name "mystorageaccount" -ResourceGroupName "myResourceGroup"

Set-AzNetworkWatcherFlowLog `
  -NetworkWatcher $networkWatcher `
  -TargetResourceId $nsg.Id `
  -StorageAccountId $storageAccount.Id `
  -EnableFlowLog $true `
  -RetentionInDays 90
```

## 最佳实践

### 设计最佳实践

1. **地址空间规划**：
   - 选择足够大的地址空间
   - 考虑未来增长
   - 避免与本地网络重叠
   - 为特殊用途预留子网

2. **子网设计**：
   - 基于功能或安全边界划分子网
   - 不要创建过大或过小的子网
   - 为Azure服务预留专用子网
   - 使用命名约定

3. **网络拓扑**：
   - 对于复杂环境，使用中枢辐射模型
   - 集中共享服务
   - 考虑区域设计和灾难恢复
   - 规划流量流向

### 安全最佳实践

1. **深度防御**：
   - 多层安全控制
   - 结合NSG、防火墙和NVA
   - 实施零信任原则

2. **网络隔离**：
   - 使用NSG限制流量
   - 考虑私有链接而非公共访问
   - 限制Internet暴露
   - 使用服务终结点保护资源

3. **监控和审计**：
   - 启用NSG流日志
   - 配置警报
   - 定期审查安全规则
   - 使用Azure安全中心

### 性能和可靠性

1. **避免瓶颈**：
   - 了解VM网络带宽限制
   - 选择适当的网关SKU
   - 考虑加速网络
   - 使用负载均衡分散流量

2. **高可用性**：
   - 跨可用性区域部署资源
   - 使用区域冗余服务
   - 实施备份连接路径
   - 配置健康探测和自动故障转移

3. **延迟优化**：
   - 将相关资源放在同一区域
   - 使用Azure Front Door或CDN缓存内容
   - 考虑ExpressRoute而非VPN
   - 监控和优化网络路径

## 常见场景与解决方案

### 混合连接

连接本地数据中心和Azure：

1. **小型部署**：
   - 站点到站点VPN
   - 基本或标准VPN网关
   - 适用于低带宽需求

2. **企业级部署**：
   - ExpressRoute专用连接
   - 高性能VPN网关（VpnGw3+）
   - 考虑冗余连接

3. **多站点连接**：
   - 虚拟WAN
   - 多站点VPN
   - 区域连接策略

### 多层应用程序

在VNet中部署典型的多层应用：

1. **子网划分**：
   - Web层子网（面向Internet）
   - 应用层子网（内部）
   - 数据层子网（受限）

2. **安全控制**：
   - NSG限制层间流量
   - 仅允许必要的通信
   - 为管理访问使用堡垒主机

3. **负载均衡**：
   - 外部负载均衡器用于Web层
   - 内部负载均衡器用于应用层
   - 考虑应用网关用于Web流量

### 微服务架构

为容器化微服务设计网络：

1. **AKS集成**：
   - 为AKS集群使用专用子网
   - 配置Kubenet或Azure CNI
   - 规划Pod IP地址空间

2. **服务网格**：
   - 使用Istio或Linkerd管理服务通信
   - 实施零信任网络策略
   - 加密服务间流量

3. **API管理**：
   - 使用内部VNET模式部署API管理
   - 保护后端服务
   - 实现API网关模式

## 故障排除

### 常见连接问题

1. **VM连接问题**：
   - 检查NSG规则
   - 验证有效路由
   - 确认VM网络配置
   - 检查主机防火墙

2. **VPN连接问题**：
   - 验证本地设备配置
   - 检查共享密钥
   - 确认兼容的IPsec/IKE参数
   - 检查路由传播

3. **对等互连问题**：
   - 确认两侧都配置了对等互连
   - 检查地址空间重叠
   - 验证DNS设置
   - 检查网络安全组

### 诊断工具

1. **连接疑难解答**：
   - 网络监视器连接疑难解答
   - VM连接检查
   - 下一跳工具

2. **NSG诊断**：
   - 有效安全规则视图
   - NSG流日志分析
   - 流验证

3. **网络性能**：
   - 网络性能监视器
   - 连接监视器
   - ExpressRoute监视

## 参考资源

- [Azure虚拟网络官方文档](https://docs.microsoft.com/zh-cn/azure/virtual-network/)
- [Azure网络安全最佳实践](https://docs.microsoft.com/zh-cn/azure/security/fundamentals/network-best-practices)
- [虚拟网络规划和设计](https://docs.microsoft.com/zh-cn/azure/virtual-network/virtual-network-vnet-plan-design-arm)
- [Azure网络架构中心](https://docs.microsoft.com/zh-cn/azure/architecture/reference-architectures/hybrid-networking/)
- [Azure网络服务概述](https://docs.microsoft.com/zh-cn/azure/networking/networking-overview)

---

> 本文档将持续更新，欢迎提供反馈和建议。
