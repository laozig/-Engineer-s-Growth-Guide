# Azure VPN 网关

> [!NOTE]
> 本文档提供了Azure VPN网关的详细介绍，包括基本概念、配置方法和最佳实践。

## 概述

Azure VPN 网关是一种虚拟网络网关，用于在Azure虚拟网络和本地网络之间发送加密流量，实现跨本地和云环境的安全连接。VPN网关作为专用虚拟网络网关部署在Azure虚拟网络中，提供以下连接功能：

- 站点到站点(S2S)VPN：连接本地网络与Azure虚拟网络
- 点到站点(P2S)VPN：允许个人设备安全连接到Azure虚拟网络
- 虚拟网络到虚拟网络(VNet-to-VNet)连接：连接不同区域或订阅中的Azure虚拟网络
- 传输网络：构建跨多个站点的网络拓扑

Azure VPN网关通过IPsec/IKE标准协议提供安全的跨界连接，支持多种身份验证方法和加密选项，满足企业级安全要求。

## VPN网关类型

Azure提供两种主要类型的VPN网关：

### 1. 基于路由的VPN网关

- **特点**：使用"路由"或"策略"来指导流量
- **优势**：支持多个连接，提供更高的灵活性
- **用途**：适用于大多数生产环境和复杂网络拓扑
- **支持功能**：点到站点VPN、VNet到VNet连接、主动-主动配置、自定义BGP路由

### 2. 基于策略的VPN网关

- **特点**：静态指定需要通过IPsec隧道加密的IP地址前缀
- **限制**：仅支持特定场景，功能受限
- **用途**：特定的兼容性要求或传统设备支持
- **不支持功能**：点到站点VPN、VNet到VNet连接、ExpressRoute共存

## VPN网关SKU

Azure VPN网关提供多种SKU，具有不同的性能和功能：

| SKU | 站点到站点/VNet到VNet隧道 | 聚合吞吐量 | BGP支持 | 主动-主动 | 区域冗余 |
|-----|------------------------|----------|--------|----------|---------|
| 基本 | 最多10个 | 100 Mbps | 否 | 否 | 否 |
| VpnGw1/Az | 最多30个 | 650 Mbps | 是 | 是 | 是(Az) |
| VpnGw2/Az | 最多30个 | 1.0 Gbps | 是 | 是 | 是(Az) |
| VpnGw3/Az | 最多30个 | 1.25 Gbps | 是 | 是 | 是(Az) |
| VpnGw4/Az | 最多30个 | 2.5 Gbps | 是 | 是 | 是(Az) |
| VpnGw5/Az | 最多30个 | 5.0 Gbps | 是 | 是 | 是(Az) |

> 注：带有"Az"后缀的SKU支持区域冗余，在可用区中部署，提供更高的可用性。

## VPN网关架构

### 基本组件

Azure VPN网关由以下核心组件组成：

#### 1. 虚拟网络网关

- 部署在虚拟网络的网关子网中
- 包含两个或更多VM实例，自动部署和管理
- 提供VPN功能和路由

#### 2. 本地网络网关

- 代表本地VPN设备
- 定义本地网络的IP地址范围
- 指定VPN设备的公共IP地址

#### 3. 连接

- 将虚拟网络网关和本地网络网关连接起来
- 定义连接类型、共享密钥和其他参数

#### 4. 网关子网

- 专用子网，用于部署VPN网关VM
- 建议使用/27或更大的地址空间(/26、/25)
- 不能包含其他资源或NSG

### 高可用性架构

#### 1. 主动-待机配置

- 默认部署模式
- 一个网关实例处理流量，另一个作为备份
- 故障转移自动进行，通常需要1-2分钟

#### 2. 主动-主动配置

- 两个网关实例同时处理流量
- 提供更高吞吐量和故障转移能力
- 需要BGP支持
- 需要VpnGw1或更高SKU

#### 3. 区域冗余网关

- 在区域内的多个可用区部署
- 提供更高的可用性保护
- 需要VpnGw1Az或更高SKU

### 架构图示

```
                                  Azure
┌───────────────────────────────────────────────────────────────┐
│                                                               │
│  ┌─────────────────┐          ┌───────────────────────────┐   │
│  │                 │          │                           │   │
│  │  Azure 虚拟网络  │◄─────────┤      VPN 网关            │   │
│  │                 │          │  (网关子网中的VM实例)      │   │
│  └─────────────────┘          └───────────────┬───────────┘   │
│                                               │               │
└───────────────────────────────────────────────┼───────────────┘
                                                │
                                                │ IPsec 隧道
                                                │
                                                ▼
┌───────────────────────────────────────────────────────────────┐
│                                                               │
│  ┌─────────────────┐          ┌───────────────────────────┐   │
│  │                 │          │                           │   │
│  │   本地网络      │◄─────────┤      VPN 设备            │   │
│  │                 │          │                           │   │
│  └─────────────────┘          └───────────────────────────┘   │
│                                                               │
└───────────────────────────────────────────────────────────────┘
                                本地
```

## 配置VPN网关

### 使用Azure门户创建站点到站点VPN

1. **创建虚拟网络和网关子网**：
   - 创建虚拟网络或使用现有虚拟网络
   - 添加名为"GatewaySubnet"的子网(建议使用/27或更大)

2. **创建虚拟网络网关**：
   - 选择"创建资源" > "网络" > "虚拟网络网关"
   - 指定名称、区域、网关类型(VPN)、VPN类型(路由)、SKU
   - 选择虚拟网络和公共IP地址

3. **创建本地网络网关**：
   - 指定名称和本地VPN设备的公共IP地址
   - 定义本地网络地址空间

4. **创建VPN连接**：
   - 在虚拟网络网关中，选择"连接" > "添加"
   - 指定连接类型(站点到站点)、本地网络网关
   - 输入共享密钥(PSK)

5. **配置本地VPN设备**：
   - 使用Azure门户下载VPN设备配置脚本
   - 根据设备供应商的说明应用配置

### 使用Azure CLI配置站点到站点VPN

```bash
# 创建资源组
az group create --name VPNResourceGroup --location eastus

# 创建虚拟网络和网关子网
az network vnet create \
  --name VNetName \
  --resource-group VPNResourceGroup \
  --address-prefix 10.0.0.0/16 \
  --subnet-name FrontEnd \
  --subnet-prefix 10.0.1.0/24

# 添加网关子网
az network vnet subnet create \
  --name GatewaySubnet \
  --resource-group VPNResourceGroup \
  --vnet-name VNetName \
  --address-prefix 10.0.255.0/27

# 创建公共IP地址
az network public-ip create \
  --name VPNGatewayIP \
  --resource-group VPNResourceGroup \
  --allocation-method Dynamic

# 创建虚拟网络网关
az network vnet-gateway create \
  --name VNetGateway \
  --resource-group VPNResourceGroup \
  --vnet VNetName \
  --gateway-type Vpn \
  --vpn-type RouteBased \
  --sku VpnGw1 \
  --public-ip-address VPNGatewayIP \
  --no-wait

# 创建本地网络网关
az network local-gateway create \
  --name LocalGateway \
  --resource-group VPNResourceGroup \
  --gateway-ip-address 203.0.113.1 \
  --local-address-prefixes 192.168.0.0/16

# 创建VPN连接
az network vpn-connection create \
  --name VNet1ToSite1 \
  --resource-group VPNResourceGroup \
  --vnet-gateway1 VNetGateway \
  --local-gateway2 LocalGateway \
  --shared-key "YourSharedKey"
```

### 使用ARM模板部署VPN网关

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "vnetName": {
      "type": "string",
      "defaultValue": "VNetName"
    },
    "localGatewayName": {
      "type": "string",
      "defaultValue": "LocalGateway"
    },
    "localGatewayIpAddress": {
      "type": "string",
      "defaultValue": "203.0.113.1"
    },
    "localAddressPrefix": {
      "type": "array",
      "defaultValue": ["192.168.0.0/16"]
    },
    "vpnGatewayName": {
      "type": "string",
      "defaultValue": "VNetGateway"
    },
    "connectionName": {
      "type": "string",
      "defaultValue": "VNet1ToSite1"
    },
    "sharedKey": {
      "type": "securestring"
    }
  },
  "resources": [
    {
      "type": "Microsoft.Network/localNetworkGateways",
      "apiVersion": "2021-05-01",
      "name": "[parameters('localGatewayName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "localNetworkAddressSpace": {
          "addressPrefixes": "[parameters('localAddressPrefix')]"
        },
        "gatewayIpAddress": "[parameters('localGatewayIpAddress')]"
      }
    },
    {
      "type": "Microsoft.Network/virtualNetworkGateways",
      "apiVersion": "2021-05-01",
      "name": "[parameters('vpnGatewayName')]",
      "location": "[resourceGroup().location]",
      "dependsOn": [
        "[resourceId('Microsoft.Network/publicIPAddresses', 'VPNGatewayIP')]"
      ],
      "properties": {
        "ipConfigurations": [
          {
            "name": "default",
            "properties": {
              "privateIPAllocationMethod": "Dynamic",
              "subnet": {
                "id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', parameters('vnetName'), 'GatewaySubnet')]"
              },
              "publicIPAddress": {
                "id": "[resourceId('Microsoft.Network/publicIPAddresses', 'VPNGatewayIP')]"
              }
            }
          }
        ],
        "gatewayType": "Vpn",
        "vpnType": "RouteBased",
        "enableBgp": false,
        "sku": {
          "name": "VpnGw1",
          "tier": "VpnGw1"
        }
      }
    },
    {
      "type": "Microsoft.Network/connections",
      "apiVersion": "2021-05-01",
      "name": "[parameters('connectionName')]",
      "location": "[resourceGroup().location]",
      "dependsOn": [
        "[resourceId('Microsoft.Network/virtualNetworkGateways', parameters('vpnGatewayName'))]",
        "[resourceId('Microsoft.Network/localNetworkGateways', parameters('localGatewayName'))]"
      ],
      "properties": {
        "virtualNetworkGateway1": {
          "id": "[resourceId('Microsoft.Network/virtualNetworkGateways', parameters('vpnGatewayName'))]"
        },
        "localNetworkGateway2": {
          "id": "[resourceId('Microsoft.Network/localNetworkGateways', parameters('localGatewayName'))]"
        },
        "connectionType": "IPsec",
        "connectionProtocol": "IKEv2",
        "routingWeight": 10,
        "sharedKey": "[parameters('sharedKey')]",
        "enableBgp": false
      }
    }
  ]
}
```

## 高级配置场景

### 1. 配置点到站点(P2S)VPN

允许个人设备安全连接到Azure虚拟网络：

1. **创建证书**：
   - 生成根证书和客户端证书
   - 将根证书公钥上传到Azure

2. **配置点到站点连接**：
   - 在虚拟网络网关中启用点到站点配置
   - 指定地址池、隧道类型和身份验证方法

```bash
# 配置点到站点VPN
az network vnet-gateway update \
  --name VNetGateway \
  --resource-group VPNResourceGroup \
  --address-prefixes 172.16.201.0/24 \
  --client-protocol IkeV2 \
  --vpn-client-root-certificates \
    filename=RootCert.cer

# 下载VPN客户端配置
az network vnet-gateway vpn-client generate \
  --name VNetGateway \
  --resource-group VPNResourceGroup \
  --output-folder ./vpnclient
```

### 2. 配置VNet到VNet连接

连接不同区域或订阅中的Azure虚拟网络：

1. **创建两个虚拟网络网关**：
   - 在每个虚拟网络中创建网关

2. **创建连接**：
   - 在两个方向上创建连接（VNet1到VNet2和VNet2到VNet1）

```bash
# 创建从VNet1到VNet2的连接
az network vpn-connection create \
  --name VNet1ToVNet2 \
  --resource-group VPNResourceGroup \
  --vnet-gateway1 VNetGateway1 \
  --vnet-gateway2 VNetGateway2 \
  --shared-key "YourSharedKey"

# 创建从VNet2到VNet1的连接
az network vpn-connection create \
  --name VNet2ToVNet1 \
  --resource-group VPNResourceGroup2 \
  --vnet-gateway1 VNetGateway2 \
  --vnet-gateway2 VNetGateway1 \
  --shared-key "YourSharedKey"
```

### 3. 配置BGP和高可用性

启用BGP以实现动态路由和高可用性：

1. **启用BGP**：
   - 在创建虚拟网络网关时启用BGP
   - 配置ASN(自治系统编号)和BGP对等IP

2. **配置主动-主动模式**：
   - 启用主动-主动模式以提高可用性和性能

```bash
# 创建启用BGP的虚拟网络网关
az network vnet-gateway create \
  --name VNetGateway \
  --resource-group VPNResourceGroup \
  --vnet VNetName \
  --gateway-type Vpn \
  --vpn-type RouteBased \
  --sku VpnGw1 \
  --public-ip-address VPNGatewayIP \
  --asn 65515 \
  --bgp-peering-address 10.0.255.30 \
  --active-active

# 创建启用BGP的本地网络网关
az network local-gateway create \
  --name LocalGateway \
  --resource-group VPNResourceGroup \
  --gateway-ip-address 203.0.113.1 \
  --local-address-prefixes 192.168.0.0/16 \
  --asn 65516 \
  --bgp-peering-address 192.168.1.1

# 创建启用BGP的连接
az network vpn-connection create \
  --name VNet1ToSite1 \
  --resource-group VPNResourceGroup \
  --vnet-gateway1 VNetGateway \
  --local-gateway2 LocalGateway \
  --shared-key "YourSharedKey" \
  --enable-bgp
```

### 4. 配置区域冗余网关

在支持可用区的区域部署区域冗余网关：

```bash
# 创建区域冗余公共IP
az network public-ip create \
  --name VPNGatewayIP \
  --resource-group VPNResourceGroup \
  --allocation-method Static \
  --sku Standard \
  --zone 1 2 3

# 创建区域冗余网关
az network vnet-gateway create \
  --name VNetGateway \
  --resource-group VPNResourceGroup \
  --vnet VNetName \
  --gateway-type Vpn \
  --vpn-type RouteBased \
  --sku VpnGw1Az \
  --public-ip-address VPNGatewayIP
```

## 监控和诊断

### 1. 连接监控

监控VPN连接状态和性能：

- **连接状态**：检查连接是否已建立
- **数据传输**：监控入站和出站流量
- **隧道状态**：对于主动-主动配置，监控两个隧道

### 2. 诊断日志

配置诊断日志以深入分析VPN性能：

```bash
# 启用诊断日志
az monitor diagnostic-settings create \
  --name VPNGatewayDiagnostics \
  --resource $(az network vnet-gateway show --name VNetGateway --resource-group VPNResourceGroup --query id -o tsv) \
  --logs '[{"category":"GatewayDiagnosticLog","enabled":true},{"category":"TunnelDiagnosticLog","enabled":true},{"category":"RouteDiagnosticLog","enabled":true},{"category":"IKEDiagnosticLog","enabled":true}]' \
  --metrics '[{"category":"AllMetrics","enabled":true}]' \
  --workspace $(az monitor log-analytics workspace show --name LogAnalyticsWorkspace --resource-group LogAnalyticsResourceGroup --query id -o tsv)
```

### 3. Azure Monitor集成

使用Azure Monitor创建仪表板和警报：

- 创建自定义仪表板显示VPN指标
- 设置警报通知连接中断或性能下降
- 与Log Analytics集成进行高级分析

### 4. 网络包捕获

对VPN网关进行网络包捕获以排查连接问题：

```bash
# 启动网络包捕获
az network vnet-gateway packet-capture start \
  --name VNetGateway \
  --resource-group VPNResourceGroup \
  --filter "FilterName" \
  --file-path "vpn.cap"

# 停止网络包捕获
az network vnet-gateway packet-capture stop \
  --name VNetGateway \
  --resource-group VPNResourceGroup
```

## 安全最佳实践

### 1. IPsec/IKE策略配置

配置强大的IPsec/IKE策略以增强安全性：

- 使用强加密算法(如AES-256)
- 配置适当的密钥长度和DH组
- 定期轮换共享密钥

```bash
# 配置自定义IPsec/IKE策略
az network vpn-connection ipsec-policy add \
  --connection-name VNet1ToSite1 \
  --resource-group VPNResourceGroup \
  --ike-encryption AES256 \
  --ike-integrity SHA256 \
  --dh-group DHGroup14 \
  --ipsec-encryption AES256 \
  --ipsec-integrity SHA256 \
  --pfs-group PFS2048 \
  --sa-lifetime 27000 \
  --sa-max-size 102400000
```

### 2. 网络安全组配置

使用NSG保护虚拟网络流量：

- 在虚拟网络子网上应用NSG
- 限制只允许必要的流量
- 不要在网关子网上应用NSG

### 3. 点到站点VPN安全

增强点到站点VPN的安全性：

- 使用证书身份验证而非RADIUS
- 实施多因素身份验证
- 定期轮换客户端证书

### 4. 审计和合规

确保VPN配置符合安全标准：

- 定期审核VPN配置
- 记录和监控所有VPN连接
- 实施最小权限原则

## 性能优化

### 1. 选择合适的SKU

根据需求选择适当的网关SKU：

- 考虑所需的吞吐量和隧道数
- 对于高性能需求，选择VpnGw3或更高SKU
- 对于高可用性需求，使用Az系列SKU

### 2. 网络拓扑优化

优化网络拓扑以提高性能：

- 使用主动-主动配置分散流量
- 考虑使用ExpressRoute和VPN的并行连接
- 优化路由以减少延迟

### 3. 吞吐量优化

提高VPN连接的吞吐量：

- 使用BGP启用等价多路径(ECMP)路由
- 配置多个VPN隧道
- 考虑使用TCP最大段大小(MSS)钳制

### 4. 连接耐用性

提高VPN连接的可靠性：

- 配置适当的IKE参数
- 使用DPD(死对等检测)
- 实施自动重连机制

## 常见场景与解决方案

### 1. 混合云连接

将本地数据中心扩展到Azure：

- 使用站点到站点VPN连接本地网络和Azure虚拟网络
- 配置BGP以动态交换路由
- 考虑使用ExpressRoute作为高带宽选项

### 2. 分支机构连接

连接多个分支机构到Azure：

- 使用多站点VPN或虚拟WAN
- 实施中心辐射型拓扑
- 使用BGP简化路由管理

### 3. 远程工作解决方案

为远程工作人员提供安全访问：

- 配置点到站点VPN
- 实施多因素身份验证
- 使用条件访问策略

### 4. 灾难恢复

构建跨区域灾难恢复解决方案：

- 在多个区域部署VPN网关
- 配置VNet对等互连或VNet到VNet连接
- 实施自动故障转移机制

## VPN网关与其他服务的集成

### 1. 与ExpressRoute集成

结合使用ExpressRoute和VPN网关：

- ExpressRoute用于高带宽、低延迟连接
- VPN作为ExpressRoute的备份
- 配置路由以控制流量路径

### 2. 与Azure Virtual WAN集成

使用Virtual WAN简化大规模VPN部署：

- 集中管理多个VPN连接
- 自动化配置和扩展
- 简化分支连接

### 3. 与Azure Firewall集成

结合使用VPN网关和Azure Firewall：

- 在VPN流量进入虚拟网络前进行检查
- 实施统一的安全策略
- 启用高级威胁防护

### 4. 与Azure Monitor和Network Watcher集成

全面监控VPN连接：

- 使用Network Watcher排查连接问题
- 配置Azure Monitor警报
- 使用Log Analytics分析长期趋势

## 常见问题解答

### VPN网关部署需要多长时间？

VPN网关部署通常需要30-45分钟完成。这是因为网关服务需要配置和部署底层虚拟机和网络组件。在计划部署时应考虑这一点。

### 如何排查VPN连接问题？

排查VPN连接问题的步骤：
1. 检查连接状态和诊断日志
2. 验证本地和Azure端的配置匹配
3. 确认共享密钥一致
4. 检查本地防火墙规则
5. 使用Network Watcher的VPN故障排除工具
6. 检查路由表和NSG配置

### VPN网关和ExpressRoute有什么区别？

- **VPN网关**：通过公共互联网使用加密隧道连接
- **ExpressRoute**：通过专用连接绕过公共互联网
- VPN网关适合小到中等带宽需求和成本敏感场景
- ExpressRoute适合高带宽、低延迟和严格合规性要求

### 如何估算VPN网关成本？

VPN网关成本由以下因素决定：
- 选择的网关SKU
- 网关运行时间（按小时计费）
- 数据传输费用（出站数据）
- 点到站点连接数（如适用）
- 区域差异

使用Azure定价计算器估算具体成本。

## 参考资源

- [Azure VPN网关官方文档](https://docs.microsoft.com/azure/vpn-gateway/)
- [VPN网关设计指南](https://docs.microsoft.com/azure/vpn-gateway/design)
- [VPN设备配置示例](https://docs.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpn-devices)
- [VPN故障排除指南](https://docs.microsoft.com/azure/vpn-gateway/vpn-gateway-troubleshoot)

---

> 本文档将持续更新，欢迎提供反馈和建议。 