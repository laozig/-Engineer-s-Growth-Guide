# MongoDB 安全策略：认证、授权与加密

在生产环境中，保护 MongoDB 数据库的安全至关重要。本指南将介绍 MongoDB 的核心安全功能：认证、授权、加密以及其他安全最佳实践。

## 1. 认证 (Authentication)

认证是验证用户身份的过程。MongoDB 支持多种认证机制，确保只有合法用户才能访问数据库。

### 启用认证

默认情况下，MongoDB 不启用认证。要在 `mongod.conf` 中启用认证，请添加以下配置：

```yaml
security:
  authorization: enabled
```

或者使用命令行参数 `--auth` 启动 `mongod`。

### 认证机制

- **SCRAM (Salted Challenge Response Authentication Mechanism)**：默认且推荐的机制，基于用户名和密码。它使用加盐和哈希来保护密码。
- **x.509 证书认证**：使用客户端或服务器的 x.509 证书进行认证。常用于服务之间的安全通信。
- **LDAP 代理认证**：允许 MongoDB 将认证委托给 LDAP 服务器。
- **Kerberos 认证**：在大型企业环境中，可以使用 Kerberos 服务进行认证。

### 创建管理员用户

启用认证后，您需要先创建一个具有管理权限的用户。连接到数据库后，运行以下命令：

```javascript
// 切换到 admin 数据库
use admin

// 创建用户管理员
db.createUser({
  user: "myAdmin",
  pwd: passwordPrompt(), // 或直接输入密码
  roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
})
```

## 2. 授权 (Authorization)

授权是确定已认证用户有权执行哪些操作的过程。MongoDB 使用基于角色的访问控制（RBAC）来管理权限。

### 内置角色

MongoDB 提供了一系列内置角色，可以授予用户不同级别的权限：

- **数据库用户角色**：`read`、`readWrite`
- **数据库管理角色**：`dbAdmin`、`dbOwner`、`userAdmin`
- **集群管理角色**：`clusterAdmin`、`clusterManager`、`hostManager`
- **备份与恢复角色**：`backup`、`restore`
- **所有数据库角色**：`readAnyDatabase`、`readWriteAnyDatabase`、`userAdminAnyDatabase`、`dbAdminAnyDatabase`
- **超级用户角色**：`root` (拥有所有权限)

### 创建自定义角色

如果内置角色不满足需求，您可以创建自定义角色，精确定义权限。

```javascript
use myAppDB

db.createRole({
  role: "inventoryManager",
  privileges: [
    { resource: { db: "myAppDB", collection: "products" }, actions: [ "find", "update", "insert" ] },
    { resource: { db: "myAppDB", collection: "orders" }, actions: [ "find" ] }
  ],
  roles: [] // 可以继承其他角色的权限
})
```

### 将角色分配给用户

```javascript
db.createUser({
  user: "john.doe",
  pwd: "password",
  roles: [
    { role: "inventoryManager", db: "myAppDB" },
    { role: "read", db: "reportingDB" }
  ]
})
```

## 3. 加密 (Encryption)

加密是保护数据免遭未经授权访问的关键措施。MongoDB 支持两种主要类型的加密：传输中加密和静态加密。

### 传输中加密 (Encryption in Transit)

使用 TLS/SSL 来加密客户端与服务器之间以及副本集成员之间的所有网络流量。

**配置 TLS/SSL**：

在 `mongod.conf` 中配置：

```yaml
net:
  port: 27017
  bindIp: 127.0.0.1
  tls:
    mode: requireTLS
    certificateKeyFile: /etc/ssl/mongodb.pem
    CAFile: /etc/ssl/ca.pem
```

- `mode`: `requireTLS` 强制所有连接使用 TLS。
- `certificateKeyFile`: 服务器证书和私钥的路径。
- `CAFile`: 证书颁发机构（CA）的根证书。

### 静态加密 (Encryption at Rest)

MongoDB Enterprise 支持静态加密，对存储在磁盘上的数据文件进行加密。

- **WiredTiger 存储引擎的本地加密**：数据在写入磁盘时被加密，在从磁盘读取时被解密。密钥管理是加密的关键。
- **密钥管理**：
  - **本地密钥管理**：加密密钥存储在服务器本地的文件中。
  - **KMIP 集成**：通过密钥管理互操作性协议（KMIP）与第三方密钥管理器集成，如 HashiCorp Vault、AWS KMS 等。

## 4. 其他安全最佳实践

- **网络安全**：
  - **绑定 IP**：在 `net.bindIp` 中限制服务器监听的 IP 地址，避免暴露在公网上。
  - **防火墙**：使用防火墙限制只有受信任的应用程序服务器才能访问 MongoDB 端口。
- **最小权限原则**：始终为用户和应用程序分配完成其任务所需的最小权限。
- **审计 (Auditing)**：MongoDB Enterprise 提供审计功能，可以记录对数据库的访问和操作，用于安全分析和合规性检查。
- **定期更新**：保持 MongoDB 版本为最新，以获取最新的安全补丁。
- **禁用 Server-Side Scripting**：如果不需要，请使用 `--noscripting` 选项禁用服务器端脚本执行，以减少攻击面。
- **保护备份**：确保数据库备份也受到与数据库本身同样严格的安全保护。
