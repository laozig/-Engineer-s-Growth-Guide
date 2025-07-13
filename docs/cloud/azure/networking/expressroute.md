# Azure ExpressRoute

> [!NOTE]
> 本文档提供了Azure ExpressRoute的详细介绍，包括基本概念、配置方法和最佳实践。

## 概述

Azure ExpressRoute 是一项连接服务，允许您通过专用连接将本地网络扩展到Microsoft云环境，绕过公共互联网。ExpressRoute提供了比传统VPN连接更高的安全性、可靠性、速度和更低的延迟，是企业级混合云解决方案的理想选择。

通过ExpressRoute，您可以建立与Microsoft云服务的专用连接，包括Azure、Microsoft 365和Dynamics 365。连接可以通过连接服务提供商的共置设施、点到点以太网连接或通过广域网(WAN)建立。这些连接不会通过公共互联网，提供了更高的安全性、可靠性和速度，以及一致的延迟体验。

## ExpressRoute的优势

### 1. 增强的连接性能

- **更高的带宽**：支持高达10 Gbps的带宽（通过ExpressRoute Direct可达100 Gbps）
- **低延迟**：通过专用连接减少网络延迟
- **一致的性能**：避免公共互联网的拥塞和不可预测性

### 2. 增强的安全性

- **私有连接**：数据不经过公共互联网传输
- **专用网络路径**：减少暴露于互联网威胁的风险
- **与企业网络集成**：无缝扩展现有网络安全策略

### 3. 可靠性和SLA

- **高可用性设计**：支持主动-主动连接配置
- **99.95%的可用性SLA**：当配置为主动-主动时
- **弹性连接**：多个物理连接提供冗余

### 4. 广泛的连接选项

- **支持多种连接模型**：通过连接服务提供商、点到点连接或WAN集成
- **全球覆盖**：在全球多个对等互连位置提供服务
- **多种带宽选项**：从50 Mbps到100 Gbps不等

## ExpressRoute连接模型

Azure ExpressRoute支持三种主要的连接模型：

### 1. 云交换共置

![云交换共置模型](https://docs.microsoft.com/azure/expressroute/media/expressroute-introduction/expressroute-connectivity-models-diagram.png)

- **特点**：通过连接服务提供商的共置设施连接
- **优势**：利用现有的云交换基础设施
- **适用场景**：已在云交换提供商处有存在点的企业

### 2. 点到点以太网连接

- **特点**：通过服务提供商的点到点连接直接链接到Microsoft云
- **优势**：专用连接，不与其他客户共享
- **适用场景**：需要专用带宽和高度隔离的企业

### 3. 任意位置连接（IPVPN）

- **特点**：将WAN网络与Microsoft云集成
- **优势**：利用现有的WAN网络扩展到Azure
- **适用场景**：拥有MPLS VPN的大型企业网络

## ExpressRoute线路和定价

### 线路带宽和定价

ExpressRoute线路提供多种带宽选项，价格因地区和带宽而异：

| 带宽 | 月费(标准) | 月费(高级附加组件) |
|------|------------|-------------------|
| 50 Mbps | $$ | $$ + 高级费用 |
| 100 Mbps | $$ | $$ + 高级费用 |
| 200 Mbps | $$ | $$ + 高级费用 |
| 500 Mbps | $$ | $$ + 高级费用 |
| 1 Gbps | $$ | $$ + 高级费用 |
| 2 Gbps | $$ | $$ + 高级费用 |
| 5 Gbps | $$ | $$ + 高级费用 |
| 10 Gbps | $$ | $$ + 高级费用 |

> 注：具体价格因区域而异，请参考[Azure ExpressRoute定价页面](https://azure.microsoft.com/pricing/details/expressroute/)获取最新价格。

### ExpressRoute Direct

对于需要更高带宽的场景，ExpressRoute Direct提供直接连接到Microsoft全球网络的能力：

- 支持10 Gbps或100 Gbps端口对
- 允许在同一对端口上配置多个ExpressRoute线路
- 提供物理层级别的连接

## ExpressRoute功能和概念

### 1. 对等互连

ExpressRoute线路支持三种类型的对等互连：

#### 私有对等互连

- **用途**：连接到Azure虚拟网络
- **特点**：扩展本地网络到Azure
- **IP寻址**：使用私有IP地址空间
- **路由**：通过BGP交换路由

#### Microsoft对等互连

- **用途**：连接到Microsoft 365、Dynamics 365和Azure公共服务
- **特点**：通过公共IP地址访问Microsoft SaaS服务
- **IP寻址**：使用公共IP地址空间
- **路由**：通过BGP交换路由，需要公共AS号

#### Azure公共对等互连（已弃用）

- 此类型对等互连已被Microsoft对等互连取代
- 现有使用此类型的客户可以继续使用

### 2. 路由域和BGP会话

![ExpressRoute路由域](https://docs.microsoft.com/azure/expressroute/media/expressroute-circuit-peerings/expressroute-peerings.png)

- 每种对等互连类型代表一个独立的BGP会话
- BGP会话用于交换路由信息
- 建议使用MD5哈希进行BGP会话认证

### 3. ExpressRoute高级功能

ExpressRoute高级附加组件提供以下额外功能：

- **增加路由限制**：从4,000条路由增加到10,000条（私有对等互连）
- **全球连接**：连接到任何区域中的虚拟网络（跨地缘政治边界）
- **增加VNet链接**：连接更多虚拟网络到ExpressRoute线路

### 4. ExpressRoute Global Reach

- 连接不同地理位置的ExpressRoute线路
- 允许本地网络通过Microsoft网络相互通信
- 绕过传统的互联网或专用WAN连接
- 提供全球性能和冗余

### 5. ExpressRoute FastPath

- 绕过ExpressRoute虚拟网络网关，直接将流量发送到虚拟网络
- 降低网络延迟
- 提高每秒数据包数性能
- 适用于需要最低延迟的场景

## 配置ExpressRoute

### 使用Azure门户配置ExpressRoute

1. **创建ExpressRoute线路**：
   - 登录Azure门户
   - 创建新的ExpressRoute线路资源
   - 选择提供商、对等位置、带宽和计费模型
   - 选择是否启用高级功能

2. **获取服务密钥**：
   - 创建线路后获取服务密钥
   - 将服务密钥提供给连接提供商以完成配置

3. **配置对等互连**：
   - 在ExpressRoute线路中配置私有对等互连和/或Microsoft对等互连
   - 提供ASN、对等IP地址和前缀

4. **将虚拟网络链接到ExpressRoute线路**：
   - 创建虚拟网络网关（ExpressRoute类型）
   - 创建连接资源，将虚拟网络网关与ExpressRoute线路关联

### 使用Azure CLI配置ExpressRoute

```bash
# 创建资源组
az group create --name ExpressRouteResourceGroup --location eastus

# 创建ExpressRoute线路
az network express-route create \
  --name MyExpressRoute \
  --resource-group ExpressRouteResourceGroup \
  --location eastus \
  --bandwidth 200 \
  --peering-location "New York" \
  --provider Equinix \
  --sku-family MeteredData \
  --sku-tier Standard

# 配置私有对等互连
az network express-route peering create \
  --circuit-name MyExpressRoute \
  --resource-group ExpressRouteResourceGroup \
  --peering-type AzurePrivatePeering \
  --peer-asn 65001 \
  --primary-peer-subnet 172.16.0.0/30 \
  --secondary-peer-subnet 172.16.0.4/30 \
  --vlan-id 100

# 创建虚拟网络和网关子网
az network vnet create \
  --name MyVNet \
  --resource-group ExpressRouteResourceGroup \
  --location eastus \
  --address-prefix 10.0.0.0/16 \
  --subnet-name Subnet1 \
  --subnet-prefix 10.0.1.0/24

az network vnet subnet create \
  --name GatewaySubnet \
  --resource-group ExpressRouteResourceGroup \
  --vnet-name MyVNet \
  --address-prefix 10.0.255.0/27

# 创建ExpressRoute网关
az network public-ip create \
  --name MyGatewayIP \
  --resource-group ExpressRouteResourceGroup \
  --allocation-method Dynamic

az network vnet-gateway create \
  --name MyExpressRouteGateway \
  --resource-group ExpressRouteResourceGroup \
  --location eastus \
  --vnet MyVNet \
  --gateway-type ExpressRoute \
  --sku Standard \
  --public-ip-address MyGatewayIP \
  --no-wait

# 连接虚拟网络到ExpressRoute线路
az network vpn-connection create \
  --name MyConnection \
  --resource-group ExpressRouteResourceGroup \
  --vnet-gateway1 MyExpressRouteGateway \
  --express-route-circuit2 MyExpressRoute \
  --routing-weight 0
```

### 使用ARM模板部署ExpressRoute

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "expressRouteCircuitName": {
      "type": "string",
      "defaultValue": "MyExpressRoute"
    },
    "serviceProviderName": {
      "type": "string",
      "defaultValue": "Equinix"
    },
    "peeringLocation": {
      "type": "string",
      "defaultValue": "New York"
    },
    "bandwidthInMbps": {
      "type": "int",
      "defaultValue": 200
    },
    "peerASN": {
      "type": "int",
      "defaultValue": 65001
    },
    "primaryPeerAddressPrefix": {
      "type": "string",
      "defaultValue": "172.16.0.0/30"
    },
    "secondaryPeerAddressPrefix": {
      "type": "string",
      "defaultValue": "172.16.0.4/30"
    },
    "vlanId": {
      "type": "int",
      "defaultValue": 100
    }
  },
  "resources": [
    {
      "type": "Microsoft.Network/expressRouteCircuits",
      "apiVersion": "2021-05-01",
      "name": "[parameters('expressRouteCircuitName')]",
      "location": "[resourceGroup().location]",
      "sku": {
        "name": "Standard_MeteredData",
        "tier": "Standard",
        "family": "MeteredData"
      },
      "properties": {
        "serviceProviderProperties": {
          "serviceProviderName": "[parameters('serviceProviderName')]",
          "peeringLocation": "[parameters('peeringLocation')]",
          "bandwidthInMbps": "[parameters('bandwidthInMbps')]"
        }
      },
      "resources": [
        {
          "type": "peerings",
          "apiVersion": "2021-05-01",
          "name": "AzurePrivatePeering",
          "dependsOn": [
            "[resourceId('Microsoft.Network/expressRouteCircuits', parameters('expressRouteCircuitName'))]"
          ],
          "properties": {
            "peeringType": "AzurePrivatePeering",
            "peerASN": "[parameters('peerASN')]",
            "primaryPeerAddressPrefix": "[parameters('primaryPeerAddressPrefix')]",
            "secondaryPeerAddressPrefix": "[parameters('secondaryPeerAddressPrefix')]",
            "vlanId": "[parameters('vlanId')]"
          }
        }
      ]
    }
  ],
  "outputs": {
    "serviceKey": {
      "type": "string",
      "value": "[reference(parameters('expressRouteCircuitName')).serviceKey]"
    }
  }
}
```

## 高级配置场景

### 1. 配置ExpressRoute Global Reach

连接不同地理位置的ExpressRoute线路：

```bash
# 启用Global Reach
az network express-route peering connection create \
  --name GlobalReachConnection \
  --circuit-name MyExpressRoute1 \
  --resource-group ExpressRouteResourceGroup \
  --peering-name AzurePrivatePeering \
  --peer-circuit MyExpressRoute2 \
  --address-prefix 192.168.100.0/29
```

### 2. 配置ExpressRoute FastPath

绕过ExpressRoute网关，直接将流量发送到虚拟网络：

```bash
# 在创建连接时启用FastPath
az network vpn-connection create \
  --name MyConnection \
  --resource-group ExpressRouteResourceGroup \
  --vnet-gateway1 MyExpressRouteGateway \
  --express-route-circuit2 MyExpressRoute \
  --express-route-gateway-bypass true
```

### 3. 配置ExpressRoute Direct

为高带宽需求配置直接连接：

```bash
# 创建ExpressRoute Direct资源
az network express-route port create \
  --name MyExpressRouteDirect \
  --resource-group ExpressRouteResourceGroup \
  --location eastus \
  --peering-location "New York" \
  --bandwidth 100 \
  --encapsulation QinQ

# 在ExpressRoute Direct上创建线路
az network express-route create \
  --name MyExpressRoute \
  --resource-group ExpressRouteResourceGroup \
  --location eastus \
  --bandwidth 10000 \
  --peering-location "New York" \
  --port MyExpressRouteDirect \
  --sku-family MeteredData \
  --sku-tier Standard
```

### 4. 配置ExpressRoute与VPN共存

实现ExpressRoute和VPN网关的混合连接：

1. **创建ExpressRoute网关和VPN网关**：
   - 在同一虚拟网络中部署两种类型的网关
   - 确保网关子网足够大（/27或更大）

2. **配置路由优先级**：
   - ExpressRoute路由通常优先于VPN路由
   - 使用路由权重调整优先级

## 监控和诊断

### 1. ExpressRoute监控

监控ExpressRoute线路的健康状态和性能：

- **线路状态**：检查线路是否已配置并正常运行
- **对等互连状态**：监控BGP会话状态
- **带宽使用情况**：跟踪入站和出站流量

### 2. 诊断日志

配置诊断日志以深入分析ExpressRoute性能：

```bash
# 启用诊断日志
az monitor diagnostic-settings create \
  --name ExpressRouteDiagnostics \
  --resource $(az network express-route show --name MyExpressRoute --resource-group ExpressRouteResourceGroup --query id -o tsv) \
  --logs '[{"category":"PeeringRouteLog","enabled":true},{"category":"PeeringRoutesEventLog","enabled":true}]' \
  --metrics '[{"category":"AllMetrics","enabled":true}]' \
  --workspace $(az monitor log-analytics workspace show --name LogAnalyticsWorkspace --resource-group LogAnalyticsResourceGroup --query id -o tsv)
```

### 3. Network Performance Monitor

使用Network Performance Monitor监控ExpressRoute连接：

- 端到端性能监控
- 服务健康状态监控
- 历史性能趋势分析

### 4. ExpressRoute网络见解

使用Azure Monitor网络见解获取ExpressRoute连接的可视化视图：

- 拓扑可视化
- 连接问题诊断
- 性能瓶颈识别

## 安全最佳实践

### 1. 网络安全

保护通过ExpressRoute的流量：

- 使用网络安全组(NSG)控制虚拟网络内的流量
- 实施Azure Firewall或NVA进行深度数据包检查
- 使用DDoS保护防御针对公共端点的攻击

### 2. 路由安全

保护BGP路由交换：

- 使用MD5哈希进行BGP会话认证
- 实施路由筛选和前缀限制
- 监控路由更改和异常

### 3. 加密

尽管ExpressRoute提供专用连接，但可以考虑额外的加密：

- 使用IPsec VPN over ExpressRoute进行端到端加密
- 对应用层实施TLS/SSL加密
- 使用Azure加密功能保护静态数据

### 4. 访问控制

管理对ExpressRoute资源的访问：

- 使用Azure RBAC控制ExpressRoute管理访问
- 实施最小权限原则
- 审核ExpressRoute配置更改

## 性能优化

### 1. 带宽规划

选择合适的ExpressRoute带宽：

- 基于当前和预计的流量需求
- 考虑流量模式和高峰使用情况
- 监控带宽使用情况并根据需要调整

### 2. 网络设计

优化网络设计以最大化ExpressRoute性能：

- 使用FastPath减少延迟
- 优化本地网络设备配置
- 实施流量工程以平衡负载

### 3. 路由优化

优化路由以提高性能：

- 使用BGP社区标签控制路由
- 实施前缀筛选和汇总
- 优化路由以减少跳数和延迟

### 4. 高可用性设计

设计高可用性ExpressRoute连接：

- 部署冗余ExpressRoute线路
- 使用不同的对等位置实现地理冗余
- 配置故障转移机制

## 常见场景与解决方案

### 1. 混合云连接

将本地数据中心扩展到Azure：

- 使用ExpressRoute私有对等互连连接到Azure虚拟网络
- 配置路由以允许本地服务器与Azure资源通信
- 实施一致的安全策略

### 2. Microsoft 365集成

通过ExpressRoute访问Microsoft 365服务：

- 使用Microsoft对等互连
- 遵循Microsoft的指导，仅为特定场景使用ExpressRoute
- 配置适当的DNS和路由

### 3. 多区域连接

连接多个区域的Azure资源：

- 使用Global Reach连接不同区域的ExpressRoute线路
- 实施全球负载均衡和故障转移
- 优化跨区域流量路由

### 4. 灾难恢复

构建使用ExpressRoute的灾难恢复解决方案：

- 在主要和次要区域部署ExpressRoute连接
- 配置自动故障转移机制
- 定期测试灾难恢复流程

## ExpressRoute与其他服务的集成

### 1. 与Azure Virtual WAN集成

使用Virtual WAN简化ExpressRoute部署：

- 集中管理多个ExpressRoute连接
- 自动化配置和扩展
- 简化分支连接

### 2. 与Azure Firewall集成

结合使用ExpressRoute和Azure Firewall：

- 在流量进入虚拟网络前进行检查
- 实施统一的安全策略
- 启用高级威胁防护

### 3. 与Azure Private Link集成

通过ExpressRoute安全访问Azure PaaS服务：

- 使用Private Link将PaaS服务暴露到ExpressRoute连接的网络
- 避免数据通过公共互联网传输
- 简化合规性和安全性

### 4. 与SD-WAN解决方案集成

将ExpressRoute作为SD-WAN架构的一部分：

- 将ExpressRoute作为高优先级路径
- 使用SD-WAN智能路由功能
- 实施混合连接模型

## 常见问题解答

### ExpressRoute和VPN网关有什么区别？

- **ExpressRoute**：通过专用连接绕过公共互联网
- **VPN网关**：通过公共互联网使用加密隧道连接
- ExpressRoute提供更高的带宽、更低的延迟和SLA保证
- VPN适合小型部署和成本敏感场景

### 如何选择合适的ExpressRoute带宽？

选择ExpressRoute带宽的考虑因素：
- 当前和预计的流量需求
- 应用程序延迟要求
- 数据传输模式（突发vs持续）
- 成本约束
- 未来增长计划

### ExpressRoute配置需要多长时间？

ExpressRoute配置通常包括以下时间线：
1. Azure端配置：几分钟（通过门户或API）
2. 服务提供商配置：几天到几周（取决于提供商）
3. 物理连接设置：几周（如需新的交叉连接）
4. 端到端测试和验证：几天

### 如何排查ExpressRoute连接问题？

排查ExpressRoute连接问题的步骤：
1. 检查线路和对等互连状态
2. 验证BGP会话和路由交换
3. 测试连接和延迟
4. 检查本地和Azure端的配置
5. 联系服务提供商验证其端的配置
6. 使用Azure支持和监控工具

## 参考资源

- [Azure ExpressRoute官方文档](https://docs.microsoft.com/azure/expressroute/)
- [ExpressRoute连接模型](https://docs.microsoft.com/azure/expressroute/expressroute-connectivity-models)
- [ExpressRoute对等互连](https://docs.microsoft.com/azure/expressroute/expressroute-circuit-peerings)
- [ExpressRoute Global Reach](https://docs.microsoft.com/azure/expressroute/expressroute-global-reach)

---

> 本文档将持续更新，欢迎提供反馈和建议。 