# Azure SQL 数据库服务

> [!NOTE]
> 本文档提供了Azure SQL数据库服务的全面概述，包括其特性、部署选项、性能级别、管理方法和最佳实践。

## 概述

Azure SQL 是Microsoft在云中提供的关系型数据库服务系列，基于Microsoft SQL Server引擎构建。它提供了多种部署选项，从完全托管的数据库即服务(DBaaS)到自托管的虚拟机中的SQL Server，满足不同的应用需求和管理偏好。Azure SQL服务具有高可用性、自动备份、自动修补、内置智能和安全性等特点，同时保持与SQL Server的高度兼容性。

## 部署选项

Azure SQL提供三种主要部署选项，每种选项都有不同的管理责任和控制级别：

### 1. Azure SQL数据库

完全托管的数据库即服务(DBaaS)，提供最新稳定版本的SQL Server数据库引擎：

- **管理模式**：平台即服务(PaaS)
- **管理责任**：微软管理基础设施、操作系统和数据库引擎
- **适用场景**：新应用开发、现代化SaaS应用、需要最小管理开销的应用
- **部署选项**：
  - 单一数据库（每个数据库作为独立资源）
  - 弹性池（共享资源的多个数据库）
  - 无服务器（自动缩放和按使用付费）

### 2. Azure SQL托管实例

完全托管的实例级SQL Server体验，提供近乎100%的SQL Server兼容性：

- **管理模式**：平台即服务(PaaS)
- **管理责任**：微软管理基础设施和操作系统，用户可访问实例级功能
- **适用场景**：大规模迁移SQL Server工作负载、需要实例级功能的应用
- **特点**：
  - 支持跨数据库查询、SQL Agent作业、Service Broker等实例级功能
  - 与本地SQL Server高度兼容，简化迁移
  - 部署在虚拟网络中，提供增强的隔离

### 3. Azure虚拟机中的SQL Server

在Azure虚拟机上运行的SQL Server，提供最大的控制和配置灵活性：

- **管理模式**：基础设施即服务(IaaS)
- **管理责任**：微软管理基础设施，用户管理操作系统和数据库引擎
- **适用场景**：需要完全控制数据库环境、特定版本/功能需求、复杂的许可场景
- **特点**：
  - 完全控制SQL Server实例和操作系统
  - 支持所有SQL Server版本和功能
  - 可使用现有的SQL Server许可证（通过Azure混合权益）

## 服务层级和性能

### Azure SQL数据库服务层

Azure SQL数据库提供多种服务层级，以满足不同的性能和预算需求：

#### 1. 基本、标准和高级层级（基于DTU）

传统的基于DTU（数据库事务单元）的性能模型：

- **基本**：适用于小型数据库，支持少量并发操作
- **标准**：适用于中小型应用，支持中等并发操作
- **高级**：适用于业务关键型应用，支持高并发操作和快速响应时间

#### 2. 通用和业务关键层级（基于vCore）

更灵活的基于虚拟核心(vCore)的性能模型：

- **通用**：
  - 经济实惠的均衡计算和存储选项
  - 适用于大多数业务工作负载
  - 提供第3代和第5代硬件选项

- **业务关键**：
  - 最高弹性和性能的选项
  - 适用于低延迟要求的关键业务应用
  - 提供本地SSD存储和高可用性配置
  - 支持读取副本和区域冗余

- **超大规模**：
  - 适用于大型数据库（最高100TB）
  - 高度可扩展的读取性能
  - 支持数据分片和高级分析工作负载

#### 3. 无服务器计算层

- 自动按需缩放计算资源
- 按实际使用的计算资源计费
- 支持自动暂停和恢复功能
- 适用于间歇性或不可预测的工作负载

### Azure SQL托管实例服务层

- **通用**：适用于大多数业务工作负载，提供经济实惠的计算和存储平衡
- **业务关键**：适用于高IO要求的应用，提供最高的弹性和性能

## 高可用性和灾难恢复

Azure SQL提供内置的高可用性和灾难恢复功能：

### 1. 内置高可用性

- **99.99%的可用性SLA**（适用于高级/业务关键层级）
- 基于Azure Premium存储的本地HA
- 自动故障检测和恢复
- 透明的应用程序故障转移

### 2. 主动地理复制

- 创建最多四个可读取的辅助副本
- 副本可以位于不同区域
- 支持手动故障转移
- 可用于读取工作负载分流

### 3. 自动故障转移组

- 自动将多个数据库作为一个组进行故障转移
- 提供单一DNS终结点进行连接
- 自动重定向连接到新的主数据库

### 4. 区域冗余备份

- 所有服务层级自动备份
- 备份存储在区域冗余存储中
- 支持时间点恢复（通常最多35天）

## 安全功能

Azure SQL提供全面的安全功能，保护数据和访问：

### 1. 网络安全

- **防火墙规则**：限制IP地址访问
- **私有链接**：通过私有终结点访问
- **虚拟网络服务终结点**：限制在Azure虚拟网络内访问
- **强制SSL连接**：加密传输中的数据

### 2. 访问管理

- **Azure Active Directory集成**：集中身份管理
- **多因素认证**：增强登录安全
- **基于角色的访问控制**：细粒度权限管理
- **行级安全性**：基于用户身份的数据过滤

### 3. 数据保护

- **透明数据加密(TDE)**：静态数据加密
- **动态数据掩码**：限制敏感数据的显示
- **Always Encrypted**：客户端加密敏感数据
- **列级加密**：加密特定列数据

### 4. 威胁防护

- **高级威胁防护**：检测异常活动
- **漏洞评估**：识别数据库安全风险
- **审计**：记录数据库事件和访问
- **数据发现与分类**：识别和标记敏感数据

## 智能性能优化

Azure SQL提供内置的智能性能优化功能：

### 1. 查询性能洞察

- 识别性能问题查询
- 提供历史性能趋势
- 推荐性能优化措施

### 2. 自动调优

- **自动索引管理**：创建和删除索引
- **自动统计信息更新**：优化查询计划
- **自动参数化**：减少编译开销

### 3. 智能诊断

- 主动性能监控
- 自动检测性能异常
- 提供根本原因分析

## 数据迁移

将现有数据库迁移到Azure SQL的多种方法：

### 1. Azure数据库迁移服务(DMS)

- 支持在线和离线迁移
- 最小化停机时间
- 自动评估兼容性问题

### 2. 备份和恢复

- 使用本地备份文件恢复到Azure SQL
- 支持完整、差异和事务日志备份

### 3. 事务复制

- 最小化停机时间的迁移
- 支持大型数据库迁移
- 保持源和目标同步直到切换

### 4. SQL Server数据工具(SSDT)

- 架构比较和同步
- 数据库项目部署
- 增量更新支持

## 监控与管理

### 1. Azure门户

- 可视化管理界面
- 性能监控和指标
- 配置和管理数据库设置

### 2. Azure Monitor和Log Analytics

- 收集和分析遥测数据
- 创建自定义仪表板
- 设置警报和通知

### 3. Azure CLI和PowerShell

- 自动化管理任务
- 脚本化配置和部署
- 集成到CI/CD管道

### 4. SQL Server Management Studio (SSMS)和Azure Data Studio

- 熟悉的数据库管理工具
- 查询编辑和执行
- 性能调优和监控

## 成本优化

### 1. 服务层级选择

- 根据性能需求选择合适的服务层级
- 考虑预留实例折扣
- 利用无服务器选项处理间歇性工作负载

### 2. 弹性池

- 共享资源的多个数据库
- 优化不同使用模式的数据库成本
- 简化性能管理

### 3. Azure混合权益

- 使用现有SQL Server许可证
- 降低Azure SQL成本
- 适用于软件保障客户

### 4. 自动缩放

- 无服务器选项自动缩放
- 按使用量付费
- 自动暂停非活动数据库

## 代码示例

### 连接到Azure SQL数据库

```csharp
// C#连接示例
string connectionString = "Server=tcp:yourserver.database.chinacloudapi.cn,1433;Database=yourdb;User ID=yourusername;Password=yourpassword;Encrypt=true;Connection Timeout=30;";
using (SqlConnection connection = new SqlConnection(connectionString))
{
    connection.Open();
    // 执行数据库操作
}
```

```python
# Python连接示例
import pyodbc
conn_str = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=yourserver.database.chinacloudapi.cn;DATABASE=yourdb;UID=yourusername;PWD=yourpassword'
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()
# 执行数据库操作
```

```javascript
// Node.js连接示例
const sql = require('mssql')
const config = {
  user: 'yourusername',
  password: 'yourpassword',
  server: 'yourserver.database.chinacloudapi.cn',
  database: 'yourdb',
  options: {
    encrypt: true
  }
}
async function connectAndQuery() {
  try {
    await sql.connect(config)
    // 执行数据库操作
  } catch (err) {
    console.error(err)
  }
}
```

### 创建和管理Azure SQL资源

```powershell
# PowerShell创建Azure SQL数据库
$resourceGroup = "myResourceGroup"
$server = "myserver"
$location = "chinaeast2"
$database = "myDatabase"

# 创建资源组
New-AzResourceGroup -Name $resourceGroup -Location $location

# 创建SQL Server
New-AzSqlServer -ResourceGroupName $resourceGroup `
    -ServerName $server `
    -Location $location `
    -SqlAdministratorCredentials $(New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "adminuser", $(ConvertTo-SecureString -String "ComplexPassword123!" -AsPlainText -Force))

# 创建数据库
New-AzSqlDatabase -ResourceGroupName $resourceGroup `
    -ServerName $server `
    -DatabaseName $database `
    -Edition "GeneralPurpose" `
    -VCore 2 `
    -ComputeGeneration "Gen5" `
    -MinimumCapacity 2
```

```bash
# Azure CLI创建Azure SQL数据库
# 创建资源组
az group create --name myResourceGroup --location chinaeast2

# 创建SQL Server
az sql server create --name myserver \
    --resource-group myResourceGroup \
    --location chinaeast2 \
    --admin-user adminuser \
    --admin-password ComplexPassword123!

# 创建数据库
az sql db create --name myDatabase \
    --resource-group myResourceGroup \
    --server myserver \
    --edition GeneralPurpose \
    --family Gen5 \
    --capacity 2
```

## 常见场景与最佳实践

### 1. 选择合适的部署选项

| 需求 | 推荐选项 |
|------|---------|
| 新应用开发 | Azure SQL数据库 |
| 迁移现有SQL Server | Azure SQL托管实例 |
| 需要完全控制 | Azure VM中的SQL Server |
| 间歇性工作负载 | Azure SQL数据库无服务器 |
| 多个小型数据库 | Azure SQL数据库弹性池 |

### 2. 性能优化

- 使用查询性能洞察识别性能问题
- 启用自动调优功能
- 定期检查索引使用情况和碎片
- 优化查询和数据库架构
- 考虑使用内存中OLTP技术（适用的服务层级）

### 3. 安全最佳实践

- 启用Azure AD身份验证
- 实施最小权限原则
- 启用透明数据加密
- 配置高级威胁防护
- 定期审查审计日志
- 使用私有链接或服务终结点限制网络访问

### 4. 高可用性和业务连续性

- 为关键应用选择业务关键服务层级
- 配置活动地理复制
- 实施自动故障转移组
- 测试故障转移过程
- 监控RPO（恢复点目标）和RTO（恢复时间目标）

### 5. 迁移策略

- 使用数据库迁移助手评估兼容性
- 对大型数据库考虑分阶段迁移
- 测试应用程序与Azure SQL的兼容性
- 计划适当的停机时间窗口
- 实施回滚计划

## 常见问题解答

### 如何选择Azure SQL数据库和SQL托管实例之间的选项？

选择取决于您的需求：
- 如果需要实例级功能（如跨数据库查询、SQL Agent作业）或需要高度兼容性，选择SQL托管实例
- 如果是新应用或不需要实例级功能，选择Azure SQL数据库，它提供更简单的管理和更多的弹性选项

### Azure SQL数据库支持哪些SQL Server功能？

Azure SQL数据库支持大多数SQL Server数据库引擎功能，但有一些限制，如：
- 不支持跨数据库事务（单一数据库模式）
- 不支持SQL Server Agent（使用Azure逻辑应用或Functions替代）
- 不支持文件组和文件流
- 部分系统存储过程和表不可用或行为不同

### 如何处理Azure SQL数据库的连接问题？

常见连接问题解决方法：
- 检查防火墙设置是否允许客户端IP
- 验证连接字符串是否正确
- 确认服务器是否在线（通过Azure门户）
- 检查是否达到连接限制
- 实施连接重试逻辑

### 如何监控和优化Azure SQL数据库性能？

- 使用查询性能洞察识别问题查询
- 启用自动调优功能
- 监控DTU/vCore使用率和资源限制
- 分析等待统计信息
- 考虑升级服务层级或增加资源

### Azure SQL数据库的备份如何工作？

- 自动执行完整、差异和事务日志备份
- 完整备份每周执行，差异备份每12小时，日志备份每5-10分钟
- 支持时间点恢复（取决于服务层级，通常为7-35天）
- 可配置长期备份保留（最多10年）

## 参考资源

- [Azure SQL官方文档](https://docs.microsoft.com/zh-cn/azure/azure-sql/)
- [Azure SQL数据库定价](https://azure.microsoft.com/zh-cn/pricing/details/sql-database/)
- [Azure SQL托管实例定价](https://azure.microsoft.com/zh-cn/pricing/details/azure-sql-managed-instance/)
- [SQL Server迁移助手](https://docs.microsoft.com/zh-cn/sql/dma/dma-overview)
- [Azure数据库迁移服务](https://docs.microsoft.com/zh-cn/azure/dms/dms-overview)

---

> 本文档将持续更新，欢迎提供反馈和建议。 