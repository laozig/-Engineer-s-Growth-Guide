# 密钥管理

> [!NOTE]
> 本文档提供了Azure Key Vault的详细介绍，包括核心概念、配置方法、最佳实践和常见场景。

## 目录

- [Azure Key Vault概述](#azure-key-vault概述)
- [核心概念](#核心概念)
- [Key Vault层级和功能](#key-vault层级和功能)
- [访问控制和身份验证](#访问控制和身份验证)
- [密钥管理](#密钥管理)
- [机密管理](#机密管理)
- [证书管理](#证书管理)
- [备份和恢复](#备份和恢复)
- [监控和审计](#监控和审计)
- [与Azure服务集成](#与azure服务集成)
- [高可用性和灾难恢复](#高可用性和灾难恢复)
- [安全最佳实践](#安全最佳实践)
- [常见应用场景](#常见应用场景)
- [故障排除](#故障排除)

## Azure Key Vault概述

Azure Key Vault是一项云服务，用于安全存储和访问机密信息，如API密钥、密码、证书和加密密钥。它提供集中式保护，帮助保护敏感数据，并简化密钥和机密的管理。

### 主要优势

- **集中式安全存储**：集中管理密钥、机密和证书
- **安全性**：硬件安全模块(HSM)保护，FIPS 140-2 Level 2验证
- **监控和日志记录**：详细的访问日志和监控
- **集成**：与多种Azure服务无缝集成
- **高可用性**：99.99%的可用性SLA
- **合规性**：满足FIPS 140-2、HIPAA、PCI DSS等标准

### 使用场景

- 存储应用程序机密和配置
- 管理加密密钥
- 存储和管理SSL/TLS证书
- 硬件安全模块(HSM)保护的密钥存储
- 密钥轮换和生命周期管理

## 核心概念

### Key Vault资源

Key Vault是一个Azure资源，包含以下主要组件：

- **密钥(Keys)**：用于加密操作的密码密钥
- **机密(Secrets)**：小型敏感数据块(如密码、连接字符串)
- **证书(Certificates)**：X.509证书和相关私钥

### 安全对象类型

1. **密钥**：
   - RSA密钥：用于加密/解密、签名/验证
   - EC密钥：用于签名/验证
   - 支持软件保护或HSM保护

2. **机密**：
   - 最大25KB的文本/二进制数据
   - 版本化存储
   - 可设置过期和激活日期

3. **证书**：
   - X.509证书和私钥
   - 支持自签名或CA签发
   - 自动续订选项

### 数据平面和管理平面

Key Vault操作分为两个平面：

- **管理平面**：创建和管理Key Vault实例(通过Azure Resource Manager)
- **数据平面**：存储和检索Key Vault中的数据(通过Key Vault REST API)

## Key Vault层级和功能

Azure Key Vault提供两种服务层级：

### 标准层

- 软件保护的密钥
- 机密和证书管理
- 适用于大多数应用场景
- 成本效益高

### 高级层

- 硬件安全模块(HSM)保护的密钥
- FIPS 140-2 Level 2验证
- 适用于高安全性要求
- 支持导入HSM保护的密钥

### Azure专用HSM

对于最高级别的安全需求，Azure提供专用HSM服务：

- FIPS 140-2 Level 3验证
- 单租户HSM设备
- 完全控制管理和操作
- 适用于金融和监管要求严格的场景

### 功能比较

| 功能 | 标准层 | 高级层 | 专用HSM |
|------|--------|--------|---------|
| 软件保护的密钥 | ✓ | ✓ | ✓ |
| HSM保护的密钥 | - | ✓ | ✓ |
| 机密管理 | ✓ | ✓ | - |
| 证书管理 | ✓ | ✓ | - |
| FIPS验证级别 | - | Level 2 | Level 3 |
| 租户模型 | 多租户 | 多租户 | 单租户 |
| 控制级别 | 服务管理 | 服务管理 | 完全控制 |

## 访问控制和身份验证

### 身份验证方法

访问Key Vault需要适当的身份验证：

1. **Azure Active Directory**：
   - 主要身份验证机制
   - 支持用户、服务主体和托管身份
   - 与条件访问策略集成

2. **访问策略模式**：
   - 传统访问控制方法
   - 基于Key Vault级别的粒度
   - 分别控制密钥、机密和证书权限

3. **基于角色的访问控制(RBAC)**：
   - 更细粒度的访问控制
   - 与Azure RBAC集成
   - 支持自定义角色

### 访问策略配置

访问策略定义了特定安全主体对Key Vault对象的权限：

```json
{
  "accessPolicies": [
    {
      "tenantId": "tenant-id",
      "objectId": "object-id",
      "permissions": {
        "keys": ["get", "list", "create"],
        "secrets": ["get", "list"],
        "certificates": ["get", "list"]
      }
    }
  ]
}
```

### RBAC角色

Key Vault提供内置RBAC角色：

- **Key Vault管理员**：完全控制Key Vault
- **Key Vault证书官员**：证书管理权限
- **Key Vault密码官员**：密钥管理权限
- **Key Vault机密官员**：机密管理权限
- **Key Vault读取者**：只读访问
- **Key Vault密码用户**：加密操作权限

### 网络访问控制

控制网络级别的Key Vault访问：

1. **防火墙和虚拟网络**：
   - 限制特定IP地址或范围
   - 限制特定虚拟网络和子网
   - 允许受信任的Azure服务

2. **专用终结点**：
   - 通过Azure专用链接访问
   - 完全私有连接
   - 绕过公共网络

**网络规则配置**：

```json
{
  "properties": {
    "networkAcls": {
      "defaultAction": "Deny",
      "bypass": "AzureServices",
      "ipRules": [
        {
          "value": "40.112.49.0/24"
        }
      ],
      "virtualNetworkRules": [
        {
          "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/subnet1"
        }
      ]
    }
  }
}
```

## 密钥管理

### 密钥类型

Key Vault支持多种密钥类型：

1. **RSA密钥**：
   - 支持2048、3072和4096位密钥
   - 用于加密/解密和签名/验证
   - 支持多种填充模式

2. **EC密钥**：
   - 支持P-256、P-384、P-521和SECP256K1曲线
   - 用于签名/验证
   - 比同等安全级别的RSA密钥更小更快

### 密钥操作

Key Vault支持以下密钥操作：

- **创建**：生成新密钥
- **导入**：导入现有密钥
- **更新**：更新密钥属性
- **轮换**：创建新版本
- **备份/恢复**：备份和恢复密钥
- **加密/解密**：使用密钥加密和解密数据
- **签名/验证**：使用密钥签名和验证数据
- **包装/解包**：包装和解包对称密钥

### 密钥版本控制

Key Vault自动维护密钥的版本历史：

- 每次创建新密钥版本时生成唯一标识符
- 保留所有历史版本
- 可以引用特定版本或最新版本
- 支持禁用旧版本

### 密钥轮换

定期轮换密钥是安全最佳实践：

1. **手动轮换**：
   - 创建新版本
   - 更新应用程序引用

2. **自动轮换**：
   - 配置轮换策略
   - 基于时间或事件触发
   - 与Event Grid集成通知应用程序

**轮换策略配置**：

```json
{
  "attributes": {
    "expiryTime": "P90D",
    "rotationPolicy": {
      "lifetimeActions": [
        {
          "trigger": {
            "timeBeforeExpiry": "P30D"
          },
          "action": {
            "type": "Rotate"
          }
        }
      ]
    }
  }
}
```

## 机密管理

### 机密特性

Key Vault机密是安全存储的文本或二进制数据：

- 最大25KB大小
- 强加密保护
- 版本控制
- 可设置过期时间
- 软删除保护

### 机密操作

Key Vault支持以下机密操作：

- **设置**：创建或更新机密
- **获取**：检索机密值
- **列出**：列出所有机密或版本
- **删除**：删除机密
- **备份/恢复**：备份和恢复机密

### 机密版本控制

与密钥类似，机密也支持版本控制：

- 每次更新机密时创建新版本
- 保留历史版本
- 可以引用特定版本或最新版本

### 机密轮换

机密轮换策略：

1. **定期轮换**：
   - 定期更新机密值
   - 使用函数应用自动化

2. **事件驱动轮换**：
   - 基于安全事件轮换
   - 与监控系统集成

3. **应用程序集成**：
   - 通知应用程序机密已更新
   - 使用Event Grid触发更新

## 证书管理

### 证书功能

Key Vault提供完整的证书生命周期管理：

- 创建自签名或CA签发的证书
- 导入现有证书
- 存储证书和私钥
- 自动续订
- 与证书颁发机构集成

### 证书操作

Key Vault支持以下证书操作：

- **创建**：生成新证书
- **导入**：导入现有证书
- **更新**：更新证书属性
- **获取**：检索证书
- **列出**：列出所有证书或版本
- **删除**：删除证书
- **导出**：导出公钥部分

### 证书颁发者

Key Vault可以与多种证书颁发机构集成：

1. **集成CA提供商**：
   - DigiCert
   - GlobalSign

2. **自定义CA**：
   - 内部企业CA
   - 其他第三方CA

3. **自签名证书**：
   - 用于测试和开发
   - 内部使用场景

### 证书续订

Key Vault支持自动证书续订：

1. **自动续订策略**：
   - 基于百分比生命周期
   - 基于天数
   - 电子邮件通知

2. **续订流程**：
   - 自动触发续订
   - 与CA交互
   - 存储新证书版本

**证书策略配置**：

```json
{
  "policy": {
    "x509CertificateProperties": {
      "subject": "CN=example.com",
      "validityInMonths": 12
    },
    "issuerParameters": {
      "name": "Self"
    },
    "keyProperties": {
      "keyType": "RSA",
      "keySize": 2048,
      "reuseKey": false
    },
    "lifetimeActions": [
      {
        "trigger": {
          "lifetimePercentage": 80
        },
        "action": {
          "actionType": "AutoRenew"
        }
      }
    ]
  }
}
```

## 备份和恢复

### 对象备份

Key Vault允许备份和恢复单个对象：

1. **密钥备份**：
   - 包括密钥材料和属性
   - 加密保护
   - 可跨区域和Key Vault恢复

2. **机密备份**：
   - 包括机密值和属性
   - 加密保护
   - 可跨区域和Key Vault恢复

3. **证书备份**：
   - 包括证书和私钥
   - 加密保护
   - 可跨区域和Key Vault恢复

### 软删除

软删除保护防止意外删除：

- 默认启用，保留期90天
- 删除的对象保持可恢复状态
- 可以恢复或永久清除
- 删除的名称在保留期内不可重用

### 清除保护

清除保护防止强制删除：

- 可选功能，建议启用
- 防止在软删除保留期内永久删除
- 需要等待保留期过期
- 保护关键密钥和机密

## 监控和审计

### 日志记录

Key Vault提供全面的日志记录：

1. **Azure Monitor日志**：
   - 详细操作日志
   - 支持查询和分析
   - 长期存储

2. **诊断日志**：
   - 控制平面操作
   - 数据平面操作
   - 可发送到多个目标

3. **Azure Monitor指标**：
   - 请求率和延迟
   - 可用性指标
   - 错误率

### 审计

Key Vault审计功能：

- 记录所有API请求
- 包括请求者身份
- 包括时间戳和操作
- 支持合规性要求

**审计日志示例**：

```json
{
  "time": "2020-08-25T04:14:54.2566667Z",
  "resourceId": "/SUBSCRIPTIONS/...",
  "operationName": "SecretGet",
  "operationVersion": "7.0",
  "category": "AuditEvent",
  "resultType": "Success",
  "resultSignature": "OK",
  "resultDescription": "",
  "durationMs": "78",
  "callerIpAddress": "40.112.49.891",
  "correlationId": "d6bd63d0-0b22-4d9a-a6bd-e6f6ffef321f",
  "identity": {
    "claim": {
      "appid": "app-id",
      "oid": "object-id",
      "name": "service-principal-name",
      "puid": "...",
      "rh": "...",
      "scp": "user_impersonation",
      "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "user@example.com"
    }
  },
  "properties": {
    "clientInfo": "azure-keyvault-nodejs/1.0.0",
    "requestUri": "https://vault-name.vault.azure.net/secrets/secret-name/?api-version=7.0",
    "id": "https://vault-name.vault.azure.net/secrets/secret-name/version-id",
    "httpStatusCode": 200
  }
}
```

### 警报和通知

设置Key Vault监控警报：

1. **活动日志警报**：
   - 基于特定操作
   - 管理平面事件

2. **指标警报**：
   - 基于性能指标
   - 可用性和延迟

3. **日志查询警报**：
   - 基于自定义查询
   - 复杂模式检测

## 与Azure服务集成

Key Vault与多种Azure服务集成，提供无缝的机密管理。

### 应用服务集成

与Azure应用服务集成：

1. **Key Vault引用**：
   - 在应用设置中引用机密
   - 自动检索和更新
   - 支持托管身份认证

2. **证书集成**：
   - 绑定SSL/TLS证书
   - 自动续订

**应用设置配置**：

```json
{
  "ConnectionString": "@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/ConnectionString/version)"
}
```

### 虚拟机集成

与Azure虚拟机集成：

1. **磁盘加密**：
   - 使用Key Vault存储加密密钥
   - 支持Windows和Linux VM

2. **证书存储**：
   - 存储VM证书
   - 支持自动部署

### 数据服务集成

与Azure数据服务集成：

1. **Azure SQL**：
   - 透明数据加密(TDE)
   - Always Encrypted
   - 客户管理的密钥(CMK)

2. **Azure存储**：
   - 客户管理的密钥
   - 存储账户访问密钥管理

3. **Cosmos DB**：
   - 客户管理的密钥
   - 数据加密

### 其他服务集成

与其他Azure服务集成：

1. **Azure Functions**：
   - 应用设置引用
   - 托管身份访问

2. **Logic Apps**：
   - 工作流中使用机密
   - 连接器集成

3. **Azure DevOps**：
   - 变量组集成
   - 管道机密

## 高可用性和灾难恢复

### 可用性保证

Key Vault提供高可用性：

- 99.99%的可用性SLA
- 区域内冗余
- 自动故障转移
- 无计划维护停机

### 地理冗余

Key Vault地理冗余选项：

1. **配对区域复制**：
   - 自动复制到配对区域
   - 区域故障保护

2. **多区域部署**：
   - 在多个区域部署Key Vault
   - 应用程序级故障转移

### 灾难恢复策略

Key Vault灾难恢复最佳实践：

1. **备份关键对象**：
   - 定期备份密钥和机密
   - 安全存储备份

2. **区域故障计划**：
   - 记录恢复步骤
   - 定期测试恢复

3. **多区域策略**：
   - 实施主动-被动或主动-主动策略
   - 自动同步内容

## 安全最佳实践

### 访问控制最佳实践

1. **最小权限原则**：仅授予必要的权限
2. **使用RBAC**：利用细粒度访问控制
3. **分离职责**：不同角色管理不同对象
4. **定期审核**：审核访问策略和权限
5. **使用托管身份**：避免存储凭据

### 网络安全最佳实践

1. **启用防火墙**：限制网络访问
2. **使用专用终结点**：实施私有连接
3. **禁用公共访问**：除非必要
4. **启用高级威胁保护**：检测异常访问

### 密钥管理最佳实践

1. **使用HSM保护的密钥**：关键应用使用高级层
2. **实施密钥轮换**：定期轮换密钥
3. **备份密钥**：安全备份关键密钥
4. **监控使用情况**：跟踪密钥使用情况
5. **使用强密钥**：适当的密钥大小和算法

### 监控最佳实践

1. **启用诊断日志**：记录所有操作
2. **配置警报**：关键操作的警报
3. **定期审核**：审核访问和使用模式
4. **集成SIEM**：与安全信息和事件管理系统集成

## 常见应用场景

### 应用程序机密管理

使用Key Vault存储应用程序机密：

1. **配置管理**：
   - 存储连接字符串
   - 存储API密钥
   - 存储应用程序设置

2. **集成方法**：
   - 使用Key Vault SDK
   - 使用Key Vault引用
   - 使用托管身份认证

**代码示例(C#)**：

```csharp
// 创建Key Vault客户端
var client = new SecretClient(
    new Uri("https://myvault.vault.azure.net/"),
    new DefaultAzureCredential());

// 获取机密
KeyVaultSecret secret = await client.GetSecretAsync("ConnectionString");
string connectionString = secret.Value;
```

### 证书管理

使用Key Vault管理SSL/TLS证书：

1. **证书存储**：
   - 集中存储证书
   - 安全管理私钥

2. **自动续订**：
   - 配置续订策略
   - 与应用服务集成

3. **部署方法**：
   - 绑定到应用服务
   - 导出公钥部分
   - 使用Key Vault SDK

### 客户管理的密钥(CMK)

使用Key Vault实施客户管理的密钥：

1. **支持的服务**：
   - Azure存储
   - Azure SQL
   - Cosmos DB
   - Azure磁盘加密

2. **实施步骤**：
   - 创建HSM保护的密钥
   - 配置服务使用CMK
   - 设置密钥轮换策略

3. **安全控制**：
   - 撤销密钥访问
   - 监控密钥使用情况
   - 审计密钥操作

### DevSecOps集成

将Key Vault集成到DevSecOps流程：

1. **CI/CD管道集成**：
   - 安全存储管道机密
   - 部署期间访问机密
   - 自动化证书部署

2. **基础设施即代码**：
   - 使用ARM模板或Terraform
   - 安全引用机密
   - 自动化Key Vault配置

3. **安全测试**：
   - 验证机密访问
   - 测试轮换流程
   - 审核安全配置

## 故障排除

### 常见问题

1. **访问被拒绝**：
   - 检查访问策略或RBAC
   - 验证身份认证
   - 检查网络规则

2. **性能问题**：
   - 检查请求限制
   - 考虑缓存机制
   - 监控延迟指标

3. **集成错误**：
   - 验证引用URI
   - 检查托管身份配置
   - 查看详细错误日志

### 诊断工具

用于诊断Key Vault问题的工具：

1. **Azure CLI**：
   - 验证配置
   - 测试访问
   - 检查权限

2. **Azure Monitor**：
   - 分析操作日志
   - 查看性能指标
   - 跟踪请求失败

3. **网络诊断**：
   - 测试网络连接
   - 验证防火墙规则
   - 检查DNS解析

### 常见错误代码

| 错误代码 | 描述 | 解决方法 |
|---------|------|---------|
| 401 | 未授权 | 检查身份验证凭据 |
| 403 | 禁止访问 | 检查访问策略或RBAC |
| 429 | 请求过多 | 实施重试策略和限流 |
| 404 | 未找到 | 验证资源名称和版本 |
| 400 | 错误请求 | 检查请求格式和参数 |

## 结论

Azure Key Vault是一个强大的服务，提供安全的密钥、机密和证书管理。通过实施本文档中描述的最佳实践，组织可以建立强大的密钥管理基础，保护敏感数据并满足合规性要求。

随着安全威胁的不断发展，密钥管理变得越来越重要。Azure Key Vault提供了必要的工具和功能，帮助组织实施强大的密钥管理策略，保护其最敏感的资产。

## 参考资源

- [Azure Key Vault文档](https://docs.microsoft.com/azure/key-vault/)
- [Key Vault安全性文档](https://docs.microsoft.com/azure/key-vault/general/security-features)
- [Key Vault最佳实践](https://docs.microsoft.com/azure/key-vault/general/best-practices)
- [Key Vault RBAC文档](https://docs.microsoft.com/azure/key-vault/general/rbac-guide)
- [Key Vault密钥轮换](https://docs.microsoft.com/azure/key-vault/keys/how-to-configure-key-rotation)
- [Key Vault与应用服务集成](https://docs.microsoft.com/azure/app-service/app-service-key-vault-references)

---

> 本文档将持续更新，欢迎提供反馈和建议。 