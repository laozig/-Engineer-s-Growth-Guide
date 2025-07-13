# Azure虚拟网络

本文档详细介绍Azure虚拟网络的概念、组件、配置方法以及最佳实践，帮助您设计和实现高效、安全的云网络架构。

## 目录

- [虚拟网络基础](#虚拟网络基础)
- [子网](#子网)
- [IP地址管理](#ip地址管理)
- [网络安全组](#网络安全组)
- [路由和路由表](#路由和路由表)
- [DNS和名称解析](#dns和名称解析)
- [虚拟网络对等互连](#虚拟网络对等互连)
- [混合连接](#混合连接)
- [负载均衡](#负载均衡)
- [网络监控和诊断](#网络监控和诊断)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)

## 虚拟网络基础

Azure虚拟网络(VNet)是Azure中网络功能的基本构建块，提供了一个隔离的、安全的环境来运行虚拟机和其他Azure资源。

### 虚拟网络特性

- **隔离与分段** - 在Azure云中创建逻辑隔离的网络
- **Internet通信** - 默认情况下，资源可以向外发起通信
- **Azure资源通信** - 虚拟网络中的资源可以安全地相互通信
- **本地连接** - 可以连接到本地网络
- **流量路由** - 默认路由或自定义路由表
- **网络过滤** - 使用网络安全组和应用程序安全组过滤流量

### 虚拟网络规划

创建虚拟网络前需要考虑：

1. **地址空间** - 选择不与本地网络重叠的私有IP地址范围
2. **子网划分** - 根据应用程序和安全需求划分子网
3. **DNS服务器** - 使用Azure提供的DNS或自定义DNS
4. **服务终结点** - 是否需要访问Azure服务
5. **对等互连** - 是否需要连接到其他虚拟网络
6. **本地连接** - 是否需要混合云连接

### 创建虚拟网络

使用Azure门户创建虚拟网络：

1. 导航到"虚拟网络"服务
2. 点击"创建"
3. 选择订阅和资源组
4. 提供名称和区域
5. 配置IP地址空间
6. 配置子网
7. 配置安全和标记
8. 点击"创建"

使用Azure CLI创建虚拟网络：

```azurecli
# 创建资源组
az group create --name myResourceGroup --location eastus

# 创建虚拟网络和子网
az network vnet create \
  --name myVNet \
  --resource-group myResourceGroup \
  --address-prefix 10.0.0.0/16 \
  --subnet-name default \
  --subnet-prefix 10.0.0.0/24
```

## 子网

子网允许您将虚拟网络分割成更小的网段，以组织和保护Azure资源。

### 子网规划

规划子网时考虑以下因素：

- **资源分组** - 按功能或安全要求分组资源
- **子网大小** - 根据预期资源数量确定大小
- **网络安全组** - 每个子网可以关联一个NSG
- **服务终结点** - 为特定子网启用服务终结点
- **委托子网** - 某些Azure服务需要委托的子网

### 创建和管理子网

使用Azure门户添加子网：

1. 导航到虚拟网络
2. 选择"子网"
3. 点击"+ 子网"
4. 提供名称和地址范围
5. 配置服务终结点和委托（如需要）
6. 点击"保存"

使用Azure CLI添加子网：

```azurecli
# 添加子网
az network vnet subnet create \
  --name appSubnet \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --address-prefix 10.0.1.0/24
```

### 特殊子网

某些Azure服务需要专用子网或特殊配置：

- **Azure应用程序网关** - 需要专用子网
- **Azure Kubernetes服务** - 需要足够大的子网
- **Azure VPN网关** - 需要名为"GatewaySubnet"的子网
- **Azure Firewall** - 需要名为"AzureFirewallSubnet"的子网
- **Azure Bastion** - 需要名为"AzureBastionSubnet"的子网

## IP地址管理

Azure虚拟网络支持IPv4和IPv6地址，包括公共和私有IP地址。

### 私有IP地址

私有IP地址用于虚拟网络内的通信：

- 从虚拟网络地址空间分配
- 可以是静态或动态分配
- 在资源的生命周期内保持不变（即使停止）

```azurecli
# 创建具有静态私有IP的网络接口
az network nic create \
  --name myNIC \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --subnet default \
  --private-ip-address 10.0.0.4
```

### 公共IP地址

公共IP地址用于从Internet访问Azure资源：

- 可以是静态或动态分配
- 可以是标准或基本SKU
- 可以是IPv4或IPv6

```azurecli
# 创建静态公共IP地址
az network public-ip create \
  --name myPublicIP \
  --resource-group myResourceGroup \
  --allocation-method Static \
  --sku Standard
```

### IP地址前缀

IP地址前缀允许您分配连续的公共IP地址块：

- 简化多个公共IP的管理
- 支持标准和基本SKU
- 可以分配给负载均衡器或虚拟机

```azurecli
# 创建公共IP前缀
az network public-ip prefix create \
  --name myPublicIPPrefix \
  --resource-group myResourceGroup \
  --length 28 \
  --location eastus
```

## 网络安全组

网络安全组(NSG)包含安全规则，用于允许或拒绝虚拟网络中的网络流量。

### NSG规则组件

每个NSG规则包含以下组件：

- **名称** - 唯一标识符
- **优先级** - 数字（100-4096），数字越小优先级越高
- **源或目标** - 任何或IP地址、CIDR块、服务标记、应用程序安全组
- **协议** - TCP、UDP、ICMP或任何
- **方向** - 入站或出站
- **端口范围** - 单个端口或范围
- **操作** - 允许或拒绝

### 默认规则

每个NSG包含默认规则，无法删除但可以被更高优先级的规则覆盖：

**入站规则**:
- AllowVNetInBound - 允许VNet内流量
- AllowAzureLoadBalancerInBound - 允许Azure负载均衡器健康探测
- DenyAllInBound - 拒绝所有其他入站流量

**出站规则**:
- AllowVNetOutBound - 允许VNet内流量
- AllowInternetOutBound - 允许出站Internet流量
- DenyAllOutBound - 拒绝所有其他出站流量

### 创建和应用NSG

使用Azure CLI创建NSG并添加规则：

```azurecli
# 创建NSG
az network nsg create --name myNSG --resource-group myResourceGroup

# 添加入站规则
az network nsg rule create \
  --name allow-http \
  --nsg-name myNSG \
  --resource-group myResourceGroup \
  --priority 100 \
  --destination-port-ranges 80 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --description "Allow HTTP"

# 将NSG应用到子网
az network vnet subnet update \
  --name default \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --network-security-group myNSG
```

### 应用程序安全组

应用程序安全组(ASG)将虚拟机分组为应用程序，简化NSG规则管理：

```azurecli
# 创建ASG
az network asg create --name webAsg --resource-group myResourceGroup

# 将NIC添加到ASG
az network nic ip-config update \
  --name ipconfig1 \
  --nic-name myNIC \
  --resource-group myResourceGroup \
  --application-security-groups webAsg

# 创建使用ASG的NSG规则
az network nsg rule create \
  --name allow-web \
  --nsg-name myNSG \
  --resource-group myResourceGroup \
  --priority 110 \
  --source-asgs webAsg \
  --destination-port-ranges 80 443 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp
```

## 路由和路由表

Azure自动为虚拟网络创建系统路由，但您可以创建自定义路由表来覆盖默认路由行为。

### 系统路由

Azure为每个子网创建以下默认路由：

- 子网内路由
- 虚拟网络内路由
- Internet路由
- 虚拟网络对等互连路由
- 虚拟网络网关路由

### 用户定义路由

创建自定义路由表以修改默认路由行为：

```azurecli
# 创建路由表
az network route-table create --name myRouteTable --resource-group myResourceGroup

# 添加路由
az network route-table route create \
  --name toFirewall \
  --route-table-name myRouteTable \
  --resource-group myResourceGroup \
  --address-prefix 0.0.0.0/0 \
  --next-hop-type VirtualAppliance \
  --next-hop-ip-address 10.0.2.4

# 将路由表应用到子网
az network vnet subnet update \
  --name default \
  --vnet-name myVNet \
  --resource-group myResourceGroup \
  --route-table myRouteTable
```

### 下一跳类型

用户定义路由支持以下下一跳类型：

- **虚拟网络网关** - 发送到VPN网关
- **虚拟网络** - 路由到虚拟网络内
- **Internet** - 路由到默认Internet网关
- **虚拟设备** - 路由到网络虚拟设备
- **无** - 丢弃流量

## DNS和名称解析

Azure提供内置DNS服务，但也支持自定义DNS服务器。

### Azure提供的DNS

默认情况下，Azure为虚拟网络中的资源提供名称解析：

- 自动注册虚拟机名称
- 仅解析同一虚拟网络中的名称
- 不需要配置

### 自定义DNS服务器

配置自定义DNS服务器以支持跨虚拟网络名称解析或与本地集成：

```azurecli
# 更新虚拟网络以使用自定义DNS
az network vnet update \
  --name myVNet \
  --resource-group myResourceGroup \
  --dns-servers 10.0.0.4 10.0.0.5
```

### Azure DNS私有区域

Azure DNS私有区域提供私有域名解析，无需自定义DNS服务器：

```azurecli
# 创建私有DNS区域
az network private-dns zone create \
  --name contoso.local \
  --resource-group myResourceGroup

# 将区域链接到虚拟网络
az network private-dns link vnet create \
  --name myVNetLink \
  --resource-group myResourceGroup \
  --zone-name contoso.local \
  --virtual-network myVNet \
  --registration-enabled true
```

## 虚拟网络对等互连

虚拟网络对等互连允许两个虚拟网络通过Azure骨干网络直接连接。

### 对等互连类型

- **区域内对等互连** - 连接同一区域的虚拟网络
- **全局对等互连** - 连接不同区域的虚拟网络

### 对等互连功能

- **低延迟、高带宽** - 通过Microsoft骨干网络的私有连接
- **无网关要求** - 直接连接，无需VPN网关
- **无中断连接** - 资源之间的直接通信
- **跨订阅支持** - 连接不同订阅中的网络
- **跨Azure AD租户支持** - 连接不同租户中的网络

### 创建对等互连

```azurecli
# 从VNet1到VNet2的对等互连
az network vnet peering create \
  --name VNet1ToVNet2 \
  --resource-group myResourceGroup \
  --vnet-name VNet1 \
  --remote-vnet VNet2 \
  --allow-vnet-access

# 从VNet2到VNet1的对等互连
az network vnet peering create \
  --name VNet2ToVNet1 \
  --resource-group myResourceGroup \
  --vnet-name VNet2 \
  --remote-vnet VNet1 \
  --allow-vnet-access
```

### 对等互连设置

- **虚拟网络访问** - 允许对等网络间的通信
- **转发的流量** - 允许从对等网络转发的流量
- **网关传输** - 允许使用远程网络的VPN网关
- **远程网关** - 使用远程网络的VPN网关

## 混合连接

Azure提供多种方法将本地网络连接到Azure虚拟网络。

### VPN网关

Azure VPN网关提供站点到站点和点到站点VPN连接：

```azurecli
# 创建VPN网关
az network vnet subnet create \
  --name GatewaySubnet \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --address-prefix 10.0.255.0/27

az network public-ip create \
  --name VPNGatewayIP \
  --resource-group myResourceGroup \
  --allocation-method Dynamic

az network vnet-gateway create \
  --name myVPNGateway \
  --resource-group myResourceGroup \
  --vnet myVNet \
  --gateway-type Vpn \
  --vpn-type RouteBased \
  --sku VpnGw1 \
  --public-ip-address VPNGatewayIP
```

### ExpressRoute

ExpressRoute提供通过专用连接将本地网络扩展到Azure：

- 更高的带宽（最高10 Gbps）
- 更低的延迟
- 更高的可靠性
- 不通过公共Internet

### Azure Virtual WAN

Azure Virtual WAN是一项网络服务，提供优化的自动化分支连接：

- 全球传输网络架构
- 集成的连接服务
- 自动化的分支连接
- 分支连接到VNet

## 负载均衡

Azure提供两种主要的负载均衡服务：Azure负载均衡器和应用程序网关。

### Azure负载均衡器

Azure负载均衡器在第4层(TCP/UDP)工作：

```azurecli
# 创建标准负载均衡器
az network lb create \
  --name myLoadBalancer \
  --resource-group myResourceGroup \
  --sku Standard \
  --public-ip-address myPublicIP \
  --frontend-ip-name myFrontEnd \
  --backend-pool-name myBackEndPool

# 创建健康探测
az network lb probe create \
  --name myHealthProbe \
  --lb-name myLoadBalancer \
  --resource-group myResourceGroup \
  --protocol tcp \
  --port 80

# 创建负载均衡规则
az network lb rule create \
  --name myHTTPRule \
  --lb-name myLoadBalancer \
  --resource-group myResourceGroup \
  --protocol tcp \
  --frontend-port 80 \
  --backend-port 80 \
  --frontend-ip-name myFrontEnd \
  --backend-pool-name myBackEndPool \
  --probe-name myHealthProbe
```

### 应用程序网关

应用程序网关是第7层(HTTP/HTTPS)负载均衡器，提供：

- Web流量路由
- SSL终止
- Cookie基础会话亲和性
- URL路径映射
- Web应用防火墙

```azurecli
# 创建应用程序网关
az network application-gateway create \
  --name myAppGateway \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --subnet appGatewaySubnet \
  --capacity 2 \
  --sku Standard_v2 \
  --http-settings-cookie-based-affinity Enabled \
  --public-ip-address myPublicIP \
  --frontend-port 80
```

## 网络监控和诊断

Azure提供多种工具来监控和诊断网络问题。

### 网络观察程序

Azure网络观察程序提供网络监控和诊断工具：

- **拓扑** - 可视化网络资源和关系
- **连接监视器** - 监控网络连接
- **NSG流日志** - 记录NSG允许和拒绝的流量
- **IP流验证** - 验证流量是否被允许或拒绝
- **下一跳** - 确定数据包的下一个路由目的地
- **有效安全规则** - 查看应用于资源的规则

### 网络性能监视器

网络性能监视器监控网络性能和连接：

- 性能监视
- 服务连接监视
- ExpressRoute监视

### 流量分析

NSG流日志的流量分析提供见解和可视化：

```azurecli
# 启用NSG流日志
az network watcher flow-log create \
  --name myFlowLog \
  --resource-group myResourceGroup \
  --nsg myNSG \
  --storage-account myStorageAccount \
  --enabled true \
  --retention 7
```

## 最佳实践

### 网络设计

1. **地址空间规划** - 选择足够大的地址空间，避免与本地网络重叠
2. **子网分段** - 按功能和安全需求划分子网
3. **命名约定** - 使用一致的命名约定
4. **网络文档** - 维护网络设计和配置文档

### 安全性

1. **默认拒绝** - 采用默认拒绝策略，只允许必要的流量
2. **最小特权** - 限制网络访问权限
3. **网络分段** - 使用子网和NSG分隔网络
4. **保护管理访问** - 使用Azure Bastion或跳转服务器
5. **监控和审计** - 启用NSG流日志和诊断日志

### 性能和可靠性

1. **区域选择** - 选择靠近用户的区域
2. **负载均衡** - 使用适当的负载均衡解决方案
3. **可用性区域** - 跨可用性区域部署资源
4. **带宽规划** - 考虑带宽需求和限制
5. **监控** - 持续监控网络性能

## 常见问题

### 如何在虚拟网络之间移动资源？

虚拟机可以移动到不同的子网或虚拟网络，但需要重新部署。最佳实践是使用ARM模板或脚本记录配置，然后在新位置重新创建资源。

### 虚拟网络对等互连和VPN网关有什么区别？

虚拟网络对等互连用于连接Azure虚拟网络，而VPN网关用于连接到本地网络或其他云提供商。对等互连提供更低的延迟和更高的带宽，但仅限于Azure内部。

### 如何处理重叠的IP地址空间？

如果两个需要连接的网络有重叠的IP地址空间，可以考虑：
- 重新规划其中一个网络的IP地址
- 使用NAT网关进行地址转换
- 使用代理服务器进行通信

### 如何监控虚拟网络的成本？

使用Azure成本管理和计费功能查看网络资源的成本。标记资源可以帮助分析不同项目或部门的网络成本。

### 如何保护Azure虚拟网络？

保护虚拟网络的多层方法：
- 使用NSG控制流量
- 部署Azure Firewall或第三方NVA
- 实施JIT访问
- 使用私有终结点访问PaaS服务
- 启用Azure DDoS保护
- 定期审核安全配置 