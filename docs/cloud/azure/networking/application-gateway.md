# Azure 应用网关

> [!NOTE]
> 本文档提供了Azure应用网关的详细介绍，包括基本概念、配置方法和最佳实践。

## 概述

Azure 应用网关是一种专用的Web流量负载均衡器，在应用层(OSI第7层)运行，能够基于HTTP属性进行路由决策。与传统的负载均衡器(工作在传输层)相比，应用网关提供了更丰富的流量管理功能，特别适合Web应用程序和API服务。

应用网关可以处理SSL终止、基于URL的内容路由、Web应用防火墙保护、Cookie会话亲和性等高级功能，是构建安全、高性能Web应用的理想选择。

## 核心功能

### 1. 应用层路由

- **基于URL路径的路由**：根据URL路径将请求发送到不同的后端池
- **基于主机名的路由**：支持多租户应用程序，根据主机头路由流量
- **基于HTTP头的路由**：可以根据HTTP请求头信息进行路由决策

### 2. SSL/TLS终止

- **SSL卸载**：在应用网关层终止SSL/TLS连接，减轻后端服务器负担
- **端到端SSL**：支持到后端服务器的重新加密
- **证书管理**：集中管理SSL证书，支持自动续订(与Key Vault集成)

### 3. Web应用防火墙(WAF)

- **OWASP核心规则集**：防御常见Web攻击(如SQL注入、XSS等)
- **自定义规则**：创建特定于应用程序的安全规则
- **地理筛选**：基于来源国家/地区筛选请求
- **速率限制**：防止DDoS攻击和暴力破解

### 4. 会话亲和性

- **基于Cookie的会话亲和性**：确保用户会话路由到同一后端服务器
- **轮询负载均衡**：在后端服务器之间均匀分配流量
- **加权轮询**：根据服务器容量分配不同权重

### 5. 自动扩展和高可用性

- **自动扩展**：根据流量模式自动调整实例数量
- **区域冗余**：跨可用区部署以提高可用性
- **健康探测**：监控后端服务健康状态并自动移除不健康的实例

### 6. 其他高级功能

- **URL重写**：修改传递到后端的请求URL
- **HTTP头修改**：添加、移除或修改HTTP请求和响应头
- **自定义错误页**：配置自定义错误响应页面
- **WebSocket支持**：支持WebSocket协议的长连接

## 应用网关SKU

Azure应用网关提供以下SKU:

| 功能 | 标准V2 | WAF V2 |
|------|---------|---------|
| 自动扩展 | 是 | 是 |
| 可用区冗余 | 是 | 是 |
| 静态VIP | 是 | 是 |
| Web应用防火墙 | 否 | 是 |
| 区域性WAF策略 | 否 | 是 |
| 实例数 | 最多125个 | 最多125个 |
| 性能 | 高 | 高 |
| 后端池大小 | 无限制 | 无限制 |
| 每个应用网关的站点数 | 多个 | 多个 |
| 价格模式 | 固定+使用量 | 固定+使用量 |

> 注：还有标准和WAF(v1)SKU，但对于新部署，建议使用v2 SKU，因为它们提供了更好的性能和功能。

## 应用网关架构

### 组件

Azure应用网关由以下核心组件组成：

#### 1. 前端IP配置

- 定义应用网关的IP地址(公共或私有)
- 可以配置多个前端IP地址
- 支持静态IP地址分配

#### 2. 监听器

- 检查传入的连接请求
- 处理特定协议(HTTP/HTTPS)和端口的请求
- 可以配置多个监听器用于不同协议、端口或主机名

#### 3. 路由规则

- 将监听器与后端池关联
- 定义URL路径映射
- 配置HTTP设置(如Cookie亲和性、连接耗尽等)

#### 4. HTTP设置

- 定义与后端通信的参数
- 配置协议(HTTP/HTTPS)、端口、Cookie、超时等
- 设置自定义探测

#### 5. 后端池

- 接收流量的目标服务器组
- 可以包含虚拟机、虚拟机规模集、App Service、API Management等
- 支持IP地址、FQDN或多租户服务

#### 6. 健康探测

- 监控后端资源的健康状态
- 支持HTTP、HTTPS和TCP协议
- 可自定义探测间隔、超时和不健康阈值

### 多层架构示例

```
                                   ┌───────────────────┐
                                   │                   │
                                   │  Azure Front Door │  (全球负载均衡)
                                   │                   │
                                   └─────────┬─────────┘
                                             │
                                             ▼
┌───────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                          应用网关 (区域级)                              │
│                                                                       │
├───────────────┬───────────────────────────────────┬───────────────────┤
│ 监听器1        │ 监听器2                           │ 监听器3            │
│ (example.com) │ (api.example.com)                │ (admin.example.com)│
└───────┬───────┴──────────────┬──────────────────┬┴───────────────────┘
        │                      │                  │
        ▼                      ▼                  ▼
┌───────────────┐    ┌─────────────────┐   ┌────────────────┐
│               │    │                 │   │                │
│  Web前端服务器  │    │   API服务器      │   │  管理服务器     │
│  (VM/VMSS)    │    │  (App Service)  │   │  (VM/VMSS)    │
│               │    │                 │   │                │
└───────────────┘    └─────────────────┘   └────────────────┘
```

## 配置应用网关

### 使用Azure门户创建应用网关

1. 登录Azure门户并创建新的应用网关资源
2. 选择订阅、资源组和名称
3. 选择区域和SKU(标准V2或WAF V2)
4. 配置虚拟网络和子网
5. 添加前端IP配置(公共或私有)
6. 配置监听器(协议、端口、主机名等)
7. 创建后端池并关联目标服务器
8. 配置HTTP设置(协议、端口、Cookie等)
9. 设置路由规则，将监听器与后端池关联
10. 配置健康探测(可选)
11. 配置URL路径映射(可选)
12. 启用WAF(如果使用WAF SKU)

### 使用ARM模板部署

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "applicationGatewayName": {
      "type": "string",
      "defaultValue": "myAppGateway"
    },
    "tier": {
      "type": "string",
      "defaultValue": "Standard_v2",
      "allowedValues": [
        "Standard_v2",
        "WAF_v2"
      ]
    }
  },
  "resources": [
    {
      "type": "Microsoft.Network/applicationGateways",
      "apiVersion": "2021-05-01",
      "name": "[parameters('applicationGatewayName')]",
      "location": "[resourceGroup().location]",
      "properties": {
        "sku": {
          "name": "[parameters('tier')]",
          "tier": "[parameters('tier')]"
        },
        "autoscaleConfiguration": {
          "minCapacity": 2,
          "maxCapacity": 10
        },
        "gatewayIPConfigurations": [
          {
            "name": "appGatewayIpConfig",
            "properties": {
              "subnet": {
                "id": "[resourceId('Microsoft.Network/virtualNetworks/subnets', 'myVNet', 'mySubnet')]"
              }
            }
          }
        ],
        "frontendIPConfigurations": [
          {
            "name": "appGwPublicFrontendIp",
            "properties": {
              "publicIPAddress": {
                "id": "[resourceId('Microsoft.Network/publicIPAddresses', 'myPublicIP')]"
              }
            }
          }
        ],
        "frontendPorts": [
          {
            "name": "port_80",
            "properties": {
              "port": 80
            }
          }
        ],
        "backendAddressPools": [
          {
            "name": "myBackendPool",
            "properties": {
              "backendAddresses": [
                {
                  "fqdn": "app1.example.com"
                },
                {
                  "fqdn": "app2.example.com"
                }
              ]
            }
          }
        ],
        "backendHttpSettingsCollection": [
          {
            "name": "myHTTPSetting",
            "properties": {
              "port": 80,
              "protocol": "Http",
              "cookieBasedAffinity": "Disabled",
              "pickHostNameFromBackendAddress": true,
              "requestTimeout": 30
            }
          }
        ],
        "httpListeners": [
          {
            "name": "myListener",
            "properties": {
              "frontendIPConfiguration": {
                "id": "[resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', parameters('applicationGatewayName'), 'appGwPublicFrontendIp')]"
              },
              "frontendPort": {
                "id": "[resourceId('Microsoft.Network/applicationGateways/frontendPorts', parameters('applicationGatewayName'), 'port_80')]"
              },
              "protocol": "Http"
            }
          }
        ],
        "requestRoutingRules": [
          {
            "name": "myRoutingRule",
            "properties": {
              "ruleType": "Basic",
              "httpListener": {
                "id": "[resourceId('Microsoft.Network/applicationGateways/httpListeners', parameters('applicationGatewayName'), 'myListener')]"
              },
              "backendAddressPool": {
                "id": "[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', parameters('applicationGatewayName'), 'myBackendPool')]"
              },
              "backendHttpSettings": {
                "id": "[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', parameters('applicationGatewayName'), 'myHTTPSetting')]"
              }
            }
          }
        ]
      }
    }
  ]
}
```

### 使用Azure CLI部署

```bash
# 创建资源组
az group create --name myResourceGroup --location eastus

# 创建虚拟网络和子网
az network vnet create \
  --name myVNet \
  --resource-group myResourceGroup \
  --location eastus \
  --address-prefix 10.0.0.0/16 \
  --subnet-name myAGSubnet \
  --subnet-prefix 10.0.1.0/24

# 创建公共IP地址
az network public-ip create \
  --resource-group myResourceGroup \
  --name myAGPublicIPAddress \
  --allocation-method Static \
  --sku Standard

# 创建应用网关
az network application-gateway create \
  --name myAppGateway \
  --location eastus \
  --resource-group myResourceGroup \
  --vnet-name myVNet \
  --subnet myAGSubnet \
  --capacity 2 \
  --sku Standard_v2 \
  --http-settings-cookie-based-affinity Disabled \
  --frontend-port 80 \
  --http-settings-port 80 \
  --http-settings-protocol Http \
  --public-ip-address myAGPublicIPAddress

# 创建后端池
az network application-gateway address-pool create \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --name myBackendPool \
  --servers app1.example.com app2.example.com

# 创建自定义健康探测
az network application-gateway probe create \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --name myCustomProbe \
  --protocol Http \
  --host-name-from-http-settings true \
  --path /health \
  --interval 30 \
  --timeout 30 \
  --threshold 3

# 更新HTTP设置以使用自定义探测
az network application-gateway http-settings update \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --name appGatewayBackendHttpSettings \
  --probe myCustomProbe
```

## 高级配置场景

### 1. 多站点托管

应用网关可以托管多个网站，每个网站使用不同的监听器、后端池和规则：

```bash
# 添加新的监听器
az network application-gateway http-listener create \
  --name site2Listener \
  --frontend-ip appGatewayFrontendIP \
  --frontend-port appGatewayFrontendPort \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --host-name site2.example.com

# 添加新的后端池
az network application-gateway address-pool create \
  --name site2Pool \
  --servers site2vm1.example.com site2vm2.example.com \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway

# 添加新的路由规则
az network application-gateway rule create \
  --name site2Rule \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --address-pool site2Pool \
  --http-listener site2Listener \
  --http-settings appGatewayBackendHttpSettings \
  --rule-type Basic
```

### 2. URL路径映射

配置基于URL路径的路由，将不同路径的请求发送到不同的后端池：

```bash
# 创建额外的后端池
az network application-gateway address-pool create \
  --name imagesPool \
  --servers images1.example.com images2.example.com \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway

az network application-gateway address-pool create \
  --name videosPool \
  --servers videos1.example.com videos2.example.com \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway

# 创建URL路径映射
az network application-gateway url-path-map create \
  --name myPathMap \
  --paths /images/* \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --address-pool imagesPool \
  --default-address-pool myBackendPool \
  --http-settings appGatewayBackendHttpSettings \
  --default-http-settings appGatewayBackendHttpSettings

# 添加路径规则
az network application-gateway url-path-map rule create \
  --name videosRule \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --path-map-name myPathMap \
  --paths /videos/* \
  --address-pool videosPool \
  --http-settings appGatewayBackendHttpSettings
```

### 3. SSL终止和端到端SSL

配置SSL终止和端到端SSL加密：

```bash
# 导入SSL证书
az network application-gateway ssl-cert create \
  --name mySslCert \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --cert-file /path/to/cert.pfx \
  --cert-password P@ssw0rd

# 创建HTTPS监听器
az network application-gateway http-listener create \
  --name httpsListener \
  --frontend-ip appGatewayFrontendIP \
  --frontend-port httpsPort \
  --resource-group myResourceGroup \
  --gateway-name myAppGateway \
  --ssl-cert mySslCert

# 配置后端HTTPS设置(端到端SSL)
az network application-gateway http-settings create \
  --name httpsBackendSettings \
  --port 443 \
  --protocol Https \
  --cookie-based-affinity Disabled \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --host-name-from-backend-pool true \
  --trusted-root-certificate trustedRootCert
```

### 4. WAF配置

启用和配置Web应用防火墙：

```bash
# 更新应用网关SKU为WAF_v2
az network application-gateway update \
  --name myAppGateway \
  --resource-group myResourceGroup \
  --sku WAF_v2 \
  --capacity 2

# 配置WAF
az network application-gateway waf-config set \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --enabled true \
  --firewall-mode Prevention \
  --rule-set-type OWASP \
  --rule-set-version 3.2

# 禁用特定规则
az network application-gateway waf-config set \
  --gateway-name myAppGateway \
  --resource-group myResourceGroup \
  --enabled true \
  --firewall-mode Prevention \
  --rule-set-type OWASP \
  --rule-set-version 3.2 \
  --disabled-rule-groups REQUEST-942-APPLICATION-ATTACK-SQLI \
  --disabled-rules 942130 942200
```

## 监控和诊断

### 1. 应用网关指标

应用网关提供以下关键指标：

- **吞吐量**：每秒处理的字节数
- **响应时间**：从应用网关接收请求到发送响应的时间
- **失败的请求**：返回错误代码的请求数
- **健康状态**：后端实例的健康状态
- **容量单位使用率**：当前使用的容量单位百分比

### 2. 诊断日志

可以配置以下诊断日志：

- **应用网关访问日志**：记录每个请求的详细信息
- **应用网关性能日志**：记录性能相关信息
- **应用网关防火墙日志**：记录WAF检测到的请求
- **应用网关后端健康日志**：记录后端健康状态

### 3. 配置日志存储

日志可以发送到以下位置：

```bash
# 配置诊断设置
az monitor diagnostic-settings create \
  --name myDiagSettings \
  --resource myAppGateway \
  --resource-group myResourceGroup \
  --resource-type Microsoft.Network/applicationGateways \
  --storage-account myStorageAccount \
  --workspace myLogAnalyticsWorkspace \
  --logs '[{"category":"ApplicationGatewayAccessLog","enabled":true},{"category":"ApplicationGatewayPerformanceLog","enabled":true},{"category":"ApplicationGatewayFirewallLog","enabled":true}]' \
  --metrics '[{"category":"AllMetrics","enabled":true}]'
```

## 安全最佳实践

### 1. WAF保护

- 启用WAF并使用防护模式
- 定期更新WAF规则集版本
- 为特定应用程序创建自定义规则
- 监控WAF日志以识别攻击模式

### 2. SSL/TLS配置

- 使用最新的TLS版本(最低TLS 1.2)
- 禁用旧版密码套件
- 实施HSTS(HTTP严格传输安全)
- 定期轮换SSL证书

### 3. 网络安全

- 将应用网关部署在专用子网中
- 使用NSG限制子网流量
- 仅允许必要的入站和出站流量
- 考虑使用专用IP而非公共IP(适用于内部应用)

### 4. 访问控制

- 使用RBAC控制应用网关管理权限
- 实施最小权限原则
- 使用Azure监视器监控配置更改
- 启用Azure活动日志审核

## 性能优化

### 1. 自动扩展配置

- 根据流量模式设置适当的最小和最大实例数
- 监控容量单位使用率以确保足够的资源
- 考虑使用预留实例以降低成本(对于稳定工作负载)

### 2. 后端优化

- 确保后端服务器具有足够资源
- 优化后端应用程序响应时间
- 实施缓存策略减少后端请求
- 使用压缩减少传输数据量

### 3. 会话持久性配置

- 仅在必要时启用Cookie亲和性
- 对无状态应用禁用会话亲和性
- 考虑使用应用程序级会话管理

### 4. 连接设置优化

- 调整请求超时设置
- 配置适当的连接耗尽超时
- 优化健康探测间隔和超时

## 常见场景与解决方案

### 1. 多区域部署

对于需要全球分布的应用程序：

- 在多个区域部署应用网关
- 使用Azure Front Door或Traffic Manager进行全球负载均衡
- 实施地理冗余和故障转移策略

### 2. 微服务架构

对于微服务应用：

- 使用路径基本路由将请求发送到不同的微服务
- 为每个微服务配置独立的后端池
- 考虑结合使用应用网关和API管理

### 3. 电子商务网站

对于电子商务应用：

- 使用WAF保护敏感交易
- 配置路径映射将静态内容路由到CDN
- 为支付处理配置端到端SSL
- 实施会话持久性保持购物车状态

### 4. 企业应用迁移

对于迁移到Azure的企业应用：

- 使用URL重写支持旧版URL结构
- 配置多站点托管合并多个应用
- 实施HTTP到HTTPS重定向
- 使用WAF保护遗留应用程序

## 应用网关与其他服务的集成

### 1. 与Azure Front Door集成

- Front Door提供全球入口点和CDN功能
- 应用网关提供区域级WAF保护和路由
- 组合使用可实现全球分布式应用架构

### 2. 与API管理集成

- 应用网关提供WAF保护和SSL终止
- API管理处理API版本控制、限流和认证
- 部署在同一虚拟网络中实现安全通信

### 3. 与Azure Kubernetes Service集成

- 使用应用网关入口控制器(AGIC)
- 自动创建和更新应用网关规则
- 为Kubernetes服务提供WAF保护和SSL终止

### 4. 与Azure Monitor和Application Insights集成

- 发送应用网关日志到Log Analytics
- 使用Application Insights监控后端应用性能
- 创建仪表板和警报监控端到端性能

## 常见问题解答

### 应用网关与Azure负载均衡器有什么区别？

- **应用网关**：工作在应用层(第7层)，基于HTTP属性路由流量，提供WAF、SSL终止等高级功能
- **负载均衡器**：工作在传输层(第4层)，基于IP地址和端口分发流量，适用于任何TCP/UDP应用

### 如何选择应用网关SKU？

- 对于需要WAF保护的应用，选择WAF_v2 SKU
- 对于不需要WAF的应用，选择Standard_v2 SKU
- V2 SKU提供自动扩展和更好的性能，建议用于所有新部署

### 应用网关如何处理会话持久性？

应用网关通过基于Cookie的亲和性实现会话持久性：
- 当启用时，应用网关创建一个名为"ApplicationGatewayAffinity"的Cookie
- 此Cookie用于将后续请求路由到同一后端服务器
- 可以在HTTP设置中配置此功能

### 如何排查应用网关性能问题？

- 检查容量单位使用率，确保没有资源限制
- 分析后端健康状态和响应时间
- 检查WAF规则是否过于严格导致合法请求被阻止
- 查看网络连接和NSG规则是否限制了流量

### 应用网关是否支持WebSocket和HTTP/2？

- 应用网关支持WebSocket协议
- 对于HTTP/2，应用网关支持前端连接使用HTTP/2，但到后端的连接仍使用HTTP/1.1

## 参考资源

- [Azure应用网关官方文档](https://docs.microsoft.com/azure/application-gateway/)
- [应用网关WAF文档](https://docs.microsoft.com/azure/web-application-firewall/)
- [应用网关故障排除指南](https://docs.microsoft.com/azure/application-gateway/application-gateway-troubleshooting)
- [应用网关最佳实践](https://docs.microsoft.com/azure/architecture/reference-architectures/dmz/secure-vnet-dmz)

---

> 本文档将持续更新，欢迎提供反馈和建议。 