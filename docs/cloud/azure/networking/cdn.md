# Azure 内容分发网络 (CDN)

> [!NOTE]
> 本文档提供了Azure CDN的详细介绍，包括基本概念、配置方法和最佳实践。

## 概述

Azure 内容分发网络 (CDN) 是一项全球分布式内容交付服务，可以将静态和动态Web内容缓存在靠近用户的位置，从而加速内容传输并提高用户体验。通过减少延迟、提高吞吐量和分散源服务器的负载，CDN成为现代Web应用程序不可或缺的组成部分。

Azure CDN通过在全球战略位置部署的边缘节点网络，将内容存储在靠近终端用户的位置，无论用户身在何处，都能提供快速、可靠的内容访问体验。

## CDN提供商和定价层

Azure CDN提供多种CDN产品，每种都有不同的功能和定价：

### 1. Microsoft CDN标准版

- **特点**：由Microsoft直接管理和支持
- **优势**：与Azure服务紧密集成，简单易用
- **适用场景**：基本的内容加速需求，一般Web应用

### 2. Akamai标准版

- **特点**：利用Akamai的全球网络
- **优势**：广泛的全球覆盖，特别是亚洲地区
- **适用场景**：需要广泛全球覆盖的应用

### 3. Verizon标准版

- **特点**：使用Verizon的CDN基础设施
- **优势**：稳定可靠的性能
- **适用场景**：一般Web内容交付

### 4. Verizon高级版

- **特点**：Verizon的高级功能
- **优势**：高级分析、报告和安全功能
- **适用场景**：需要高级功能和详细分析的企业应用

### 5. Microsoft CDN高级版（由Front Door支持）

- **特点**：与Azure Front Door集成
- **优势**：高级路由功能、WAF保护、全球负载均衡
- **适用场景**：需要高级安全性和全球负载均衡的企业应用

## 核心功能

### 1. 内容加速

- **静态内容加速**：缓存图片、CSS、JavaScript等静态资源
- **动态内容加速**：优化动态内容的传输路径
- **大文件优化**：提高大文件下载速度

### 2. 缓存控制

- **缓存规则**：自定义缓存行为和过期策略
- **缓存清除**：按需刷新CDN上的内容
- **缓存预加载**：预先加载内容到CDN边缘节点

### 3. 安全功能

- **HTTPS支持**：使用自定义或CDN管理的证书加密内容
- **地理筛选**：限制特定国家/地区的访问
- **令牌认证**：防止未授权访问敏感内容

### 4. 优化和分析

- **实时监控**：查看CDN使用情况和性能指标
- **高级HTTP功能**：支持HTTP/2、IPv6
- **压缩**：自动压缩内容减少传输大小

### 5. 规则引擎（高级功能）

- **URL重定向/重写**：修改请求和响应
- **条件规则**：基于请求属性应用不同行为
- **标头修改**：添加、修改或删除HTTP标头

## CDN架构和工作原理

### 工作流程

1. **首次请求**：用户首次请求内容时，请求发送到最近的CDN边缘节点
2. **缓存未命中**：如果边缘节点没有缓存内容，它会从源服务器请求内容
3. **源获取**：边缘节点从源服务器获取内容并缓存
4. **内容交付**：边缘节点将内容返回给用户并保留缓存副本
5. **后续请求**：同一区域的后续请求直接从边缘节点获取内容，无需访问源服务器

### 架构图

```
┌─────────────┐         ┌───────────────┐         ┌───────────────┐
│             │  请求   │               │  缓存未命中│              │
│    用户     │ ───────>│  CDN边缘节点  │ ───────>│  源服务器     │
│             │         │               │         │ (Azure/其他)  │
└─────────────┘         └───────┬───────┘         └───────┬───────┘
       ▲                        │                         │
       │                        │                         │
       │                        │                         │
       │                        │ 缓存                    │
       └────────────────────────┘ 内容                    │
                                                         │
                                                         │
┌─────────────┐         ┌───────────────┐                │
│             │  请求   │               │                │
│  其他用户   │ ───────>│  CDN边缘节点  │ <──────────────┘
│             │         │  (已缓存内容) │    内容
└─────────────┘         └───────────────┘
```

## 配置Azure CDN

### 使用Azure门户创建CDN配置文件和端点

1. **创建CDN配置文件**：
   - 登录Azure门户
   - 创建新的CDN配置文件资源
   - 选择定价层（Microsoft标准版、Akamai标准版、Verizon标准版或高级版）
   - 指定名称和资源组

2. **创建CDN端点**：
   - 在CDN配置文件中添加端点
   - 指定端点名称（将成为 `<endpoint-name>.azureedge.net` 的一部分）
   - 选择源类型（存储、Web应用、云服务或自定义源）
   - 配置源主机名、源路径、源主机标头等
   - 配置优化类型（一般Web交付、大型文件、视频媒体或动态站点加速）

3. **配置缓存规则**：
   - 设置全局缓存规则
   - 创建基于路径的自定义缓存规则

### 使用Azure CLI配置CDN

```bash
# 创建CDN配置文件
az cdn profile create \
  --name myProfile \
  --resource-group myResourceGroup \
  --sku Standard_Microsoft

# 创建CDN端点
az cdn endpoint create \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --origin www.example.com \
  --origin-host-header www.example.com \
  --enable-compression

# 创建自定义域
az cdn custom-domain create \
  --endpoint-name myEndpoint \
  --hostname cdn.example.com \
  --name MyCustomDomain \
  --profile-name myProfile \
  --resource-group myResourceGroup

# 启用HTTPS
az cdn custom-domain enable-https \
  --endpoint-name myEndpoint \
  --name MyCustomDomain \
  --profile-name myProfile \
  --resource-group myResourceGroup
```

### 使用ARM模板部署CDN

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "profileName": {
      "type": "string",
      "defaultValue": "myCDNProfile"
    },
    "endpointName": {
      "type": "string",
      "defaultValue": "myCDNEndpoint"
    },
    "originUrl": {
      "type": "string",
      "defaultValue": "www.example.com"
    }
  },
  "resources": [
    {
      "type": "Microsoft.Cdn/profiles",
      "apiVersion": "2020-09-01",
      "name": "[parameters('profileName')]",
      "location": "global",
      "sku": {
        "name": "Standard_Microsoft"
      },
      "properties": {},
      "resources": [
        {
          "type": "endpoints",
          "apiVersion": "2020-09-01",
          "name": "[parameters('endpointName')]",
          "location": "global",
          "dependsOn": [
            "[resourceId('Microsoft.Cdn/profiles', parameters('profileName'))]"
          ],
          "properties": {
            "originHostHeader": "[parameters('originUrl')]",
            "isHttpAllowed": true,
            "isHttpsAllowed": true,
            "queryStringCachingBehavior": "IgnoreQueryString",
            "contentTypesToCompress": [
              "text/plain",
              "text/html",
              "text/css",
              "application/x-javascript",
              "application/javascript",
              "application/json",
              "image/svg+xml"
            ],
            "isCompressionEnabled": true,
            "origins": [
              {
                "name": "origin1",
                "properties": {
                  "hostName": "[parameters('originUrl')]",
                  "httpPort": 80,
                  "httpsPort": 443
                }
              }
            ]
          }
        }
      ]
    }
  ],
  "outputs": {
    "hostName": {
      "type": "string",
      "value": "[reference(parameters('endpointName')).hostName]"
    }
  }
}
```

## 高级配置场景

### 1. 自定义域和HTTPS

为CDN端点配置自定义域名并启用HTTPS：

1. **添加CNAME记录**：
   - 在DNS提供商处创建CNAME记录，将自定义域名指向CDN端点
   - 例如：`cdn.example.com` -> `myendpoint.azureedge.net`

2. **验证域所有权**：
   - Azure验证您对域名的所有权
   - 可能需要创建额外的DNS记录进行验证

3. **启用HTTPS**：
   - 选择CDN管理的证书（自动管理）或
   - 使用自己的证书（需要Key Vault集成）

```bash
# 验证自定义域
az cdn custom-domain create \
  --endpoint-name myEndpoint \
  --hostname cdn.example.com \
  --name MyCustomDomain \
  --profile-name myProfile \
  --resource-group myResourceGroup

# 启用HTTPS
az cdn custom-domain enable-https \
  --endpoint-name myEndpoint \
  --name MyCustomDomain \
  --profile-name myProfile \
  --resource-group myResourceGroup
```

### 2. 缓存规则和查询字符串处理

配置高级缓存规则以优化性能：

1. **全局缓存规则**：
   - 设置默认缓存持续时间
   - 配置查询字符串处理（忽略、包含所有、包含指定参数）

2. **基于路径的缓存规则**：
   - 为不同内容类型设置不同的缓存持续时间
   - 例如：图像缓存更长时间，API响应缓存更短时间

```bash
# 设置查询字符串缓存行为
az cdn endpoint update \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --query-string-caching-behavior IncludeSpecifiedQueryStrings \
  --query-strings param1 param2

# 添加缓存规则
az cdn endpoint rule add \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --order 1 \
  --rule-name "CacheImages" \
  --match-variable UrlPath \
  --operator BeginsWith \
  --match-values "/images/" \
  --action-name CacheExpiration \
  --cache-behavior Override \
  --cache-duration "7.00:00:00"
```

### 3. 地理筛选

限制或允许特定国家/地区访问CDN内容：

1. **创建地理筛选规则**：
   - 选择允许或阻止模式
   - 选择国家/地区代码

```bash
# 添加地理筛选规则
az cdn endpoint rule add \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --order 2 \
  --rule-name "GeoFilter" \
  --action-name "GeoFilter" \
  --country-codes CN IN JP \
  --operator "Block"
```

### 4. 压缩设置

配置内容压缩以减少传输大小：

1. **启用压缩**：
   - 在端点设置中启用压缩
   - 选择要压缩的MIME类型

```bash
# 启用压缩
az cdn endpoint update \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --content-types-to-compress \
    "text/plain" \
    "text/html" \
    "text/css" \
    "application/javascript" \
    "application/json" \
    "image/svg+xml" \
  --is-compression-enabled true
```

### 5. 规则引擎（高级功能）

使用规则引擎创建复杂的内容交付规则（仅在Verizon高级版和Microsoft高级版中可用）：

1. **URL重定向**：
   - 将请求从一个URL重定向到另一个URL
   - 配置重定向类型（301、302等）

2. **URL重写**：
   - 修改请求URL路径
   - 保持用户看到的URL不变

3. **标头修改**：
   - 添加、修改或删除HTTP请求或响应标头
   - 例如：添加安全标头如HSTS

4. **条件规则**：
   - 基于请求属性（如设备类型、浏览器）应用不同行为
   - 自定义缓存键以优化缓存命中率

## 监控和分析

### 1. 实时监控

监控CDN性能和使用情况：

- **带宽使用情况**：查看CDN流量
- **缓存命中率**：评估缓存效率
- **延迟**：监控内容交付速度
- **HTTP状态代码**：识别错误和问题

### 2. 诊断日志

配置诊断日志以深入分析CDN性能：

```bash
# 启用诊断日志
az monitor diagnostic-settings create \
  --name myDiagnosticSettings \
  --resource-id $(az cdn endpoint show --name myEndpoint --profile-name myProfile --resource-group myResourceGroup --query id -o tsv) \
  --logs '[{"category":"CoreAnalytics","enabled":true}]' \
  --storage-account $(az storage account show --name mystorageaccount --resource-group myResourceGroup --query id -o tsv)
```

### 3. Azure Monitor集成

使用Azure Monitor创建仪表板和警报：

- 创建自定义仪表板显示CDN指标
- 设置警报通知异常流量或错误率增加
- 与Log Analytics集成进行高级分析

## 缓存管理

### 1. 缓存清除

手动刷新CDN上的缓存内容：

```bash
# 清除单个文件
az cdn endpoint purge \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --content-paths "/images/logo.png" "/css/style.css"

# 清除所有内容
az cdn endpoint purge \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --content-paths "/*"
```

### 2. 缓存预加载

预先加载内容到CDN边缘节点（仅Verizon配置文件支持）：

```bash
# 预加载内容
az cdn endpoint load \
  --name myEndpoint \
  --profile-name myProfile \
  --resource-group myResourceGroup \
  --content-paths "/images/*" "/videos/intro.mp4"
```

### 3. 缓存控制标头

使用源服务器的缓存控制标头影响CDN缓存行为：

- **Cache-Control: max-age=3600**：指定内容在CDN缓存3600秒
- **Cache-Control: no-cache**：要求CDN每次都验证内容是否更新
- **Cache-Control: no-store**：指示CDN不要缓存内容

## 安全最佳实践

### 1. 内容保护

保护CDN上的敏感内容：

- **令牌认证**：要求请求包含有效令牌
- **地理筛选**：限制特定区域的访问
- **引用站点限制**：防止未授权的网站嵌入您的内容

### 2. HTTPS配置

确保安全的内容交付：

- 为所有端点启用HTTPS
- 强制使用HTTPS（重定向HTTP请求）
- 使用最新的TLS协议版本
- 配置HSTS标头

### 3. 访问控制

管理对CDN配置的访问：

- 使用Azure RBAC分配最小权限
- 审核CDN配置更改
- 使用Azure Policy强制执行安全标准

## 性能优化最佳实践

### 1. 缓存优化

最大化缓存命中率：

- 为静态内容设置较长的缓存时间
- 使用版本化URL或查询参数处理内容更新
- 避免不必要的缓存失效

### 2. 内容优化

优化要通过CDN交付的内容：

- 压缩文本内容（HTML、CSS、JavaScript）
- 优化图像（适当格式和压缩）
- 使用现代格式（如WebP图像、HTTP/2）

### 3. 源优化

确保源服务器配置正确：

- 配置适当的源超时设置
- 实施源故障转移
- 监控源健康状况和性能

### 4. 选择正确的优化类型

根据内容类型选择适当的CDN优化：

- **一般Web交付**：适用于网站和应用程序
- **动态站点加速**：适用于动态内容和API
- **大型文件优化**：适用于大文件下载
- **视频流优化**：适用于视频点播内容

## 常见场景与解决方案

### 1. 静态网站加速

使用CDN加速静态网站：

- 将Azure存储静态网站作为源
- 配置自定义域和HTTPS
- 设置长缓存时间和自动压缩

### 2. 媒体流分发

优化视频和音频内容交付：

- 选择视频流优化
- 配置渐进式下载或自适应比特率流
- 使用地理筛选满足内容许可要求

### 3. 动态内容加速

优化动态Web应用和API：

- 使用动态站点加速优化类型
- 配置适当的缓存规则和查询字符串处理
- 考虑使用Azure Front Door获得更好的动态内容性能

### 4. 全球分布式应用

构建全球分布式应用架构：

- 结合使用Azure Traffic Manager和CDN
- 在多个区域部署源服务器
- 使用地理路由将用户定向到最近的区域

## 与其他Azure服务的集成

### 1. Azure存储集成

直接从Azure存储加速内容交付：

- Blob存储作为CDN源
- 静态网站托管
- SAS令牌与CDN令牌认证结合

### 2. Azure Web应用集成

加速Web应用内容：

- 将App Service应用作为源
- 使用CDN缓存静态资源
- 配置X-Cache标头以区分CDN和源响应

### 3. Azure Front Door集成

结合使用Front Door和CDN：

- Front Door提供全球入口点和WAF保护
- CDN提供静态内容缓存
- 实现多层安全和性能优化

### 4. Azure Media Services集成

优化媒体内容交付：

- 将Media Services端点作为CDN源
- 使用动态打包和流式传输
- 配置令牌认证保护高价值内容

## 常见问题解答

### CDN缓存内容更新需要多长时间？

当源内容更新时，CDN不会立即反映这些更改。内容将继续从缓存提供，直到：
- 缓存内容过期（基于Cache-Control标头或CDN缓存规则）
- 手动清除缓存
- 使用查询字符串或版本化URL提供新内容

### 如何处理频繁变化的内容？

对于频繁变化的内容，可以：
- 设置较短的缓存持续时间
- 使用版本化URL（如`style.css?v=123`）
- 实施内容更新后的自动缓存清除
- 对动态内容使用动态站点加速

### 如何监控CDN成本？

监控CDN成本的方法：
- 使用Azure成本管理查看CDN支出
- 监控带宽使用情况和请求数量
- 设置预算警报
- 考虑预留定价（适用于稳定工作负载）

### CDN与Azure Front Door的区别是什么？

- **CDN**：主要专注于静态内容缓存和加速
- **Front Door**：提供动态站点加速、全球负载均衡、WAF和更高级的路由功能
- 对于需要全面的应用交付和安全功能的复杂应用，可以考虑Front Door
- 对于主要需要静态内容加速的简单应用，CDN可能更具成本效益

## 参考资源

- [Azure CDN官方文档](https://docs.microsoft.com/azure/cdn/)
- [Azure CDN定价](https://azure.microsoft.com/pricing/details/cdn/)
- [CDN最佳实践](https://docs.microsoft.com/azure/cdn/cdn-optimization-overview)
- [Azure CDN与Front Door比较](https://docs.microsoft.com/azure/frontdoor/front-door-cdn-comparison)

---

> 本文档将持续更新，欢迎提供反馈和建议。 