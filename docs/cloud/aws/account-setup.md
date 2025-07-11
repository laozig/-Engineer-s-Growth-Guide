# AWS账户管理与安全

本文档提供了AWS账户的设置、管理和安全保护的全面指南，从初始配置到高级安全实践。正确的账户管理是AWS云安全的基础，对于保护云资源和降低安全风险至关重要。

## 1. AWS账户结构与组织

### AWS账户基础

AWS账户是AWS资源的基本容器，提供安全边界并作为计费单位。每个AWS账户具有：

- 唯一的12位账号ID
- 根用户凭证
- 独立的资源集
- 单独的计费信息

### 使用AWS Organizations

AWS Organizations允许您集中管理和管控多个AWS账户：

```bash
# 创建组织
aws organizations create-organization

# 邀请现有账户加入组织
aws organizations invite-account --target '{"Id":"111122223333"}'

# 创建新成员账户
aws organizations create-account --email user@example.com --account-name "Development Account"
```

### 组织单位(OU)结构

推荐的OU结构示例：
```
Root
├── Security
│   ├── Log Archive
│   └── Security Tooling
├── Infrastructure
│   ├── Network
│   └── Shared Services
└── Workloads
    ├── Development
    ├── Test
    └── Production
```

```bash
# 创建组织单位
aws organizations create-organizational-unit --parent-id r-exampleroot --name "Workloads"

# 将账户移动到OU
aws organizations move-account --account-id 111122223333 --source-parent-id r-exampleroot --destination-parent-id ou-exampleroot-workloads
```

## 2. 根用户安全

### 根用户的特殊权限

根用户拥有不可限制的权限，包括：

- 关闭AWS账户
- 更改账户设置和账户恢复选项
- 修改支持计划
- 注册为AWS卖家
- 为CloudFront创建签名URL

### 保护根用户的最佳实践

1. **使用复杂密码**：设置强密码（至少20个字符）
2. **启用MFA**：必须为根用户启用MFA
3. **删除或轮换访问密钥**：根用户不应有长期访问密钥
4. **安全存储恢复信息**：谨慎保管恢复邮箱和电话
5. **限制根用户使用**：仅用于必须使用根用户的任务

```bash
# 启用MFA后，API调用需要包含MFA令牌
aws iam get-account-summary --serial-number arn:aws:iam::123456789012:mfa/root-account-mfa-device --token-code 123456
```

## 3. 账户设置与配置

### 基本账户设置

创建AWS账户后，应该立即配置以下设置：

1. **联系信息**：更新并验证账单、操作和安全联系人
2. **备用联系人**：添加备用账户联系人
3. **支持计划**：选择适合需求的支持计划

### 账户级安全设置

```bash
# 设置账户密码策略
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-symbols \
  --require-numbers \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --max-password-age 90 \
  --password-reuse-prevention 24 \
  --max-password-age 90
```

### 区域控制

限制可以使用的AWS区域，以减少攻击面：

```bash
# 禁用特定区域
aws account disable-region --region-name ap-northeast-3
```

## 4. 组织安全控制

### 服务控制策略(SCP)

SCP限制组织内账户的最大权限，即使是管理员也受限：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAccessToSpecificRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": ["sa-east-1", "ca-central-1"]
        }
      }
    }
  ]
}
```

### 标签策略

标签策略确保资源标记的一致性：

```json
{
  "tags": {
    "CostCenter": {
      "tag_key": {
        "@@assign": "CostCenter"
      },
      "tag_value": {
        "@@assign": [
          "100", 
          "200"
        ]
      },
      "enforced_for": {
        "@@assign": [
          "ec2:instance",
          "s3:bucket"
        ]
      }
    }
  }
}
```

### 备份策略

组织备份策略确保关键资源得到一致的备份：

```json
{
  "plans": {
    "DailyBackups": {
      "regions": { "@@assign": ["us-east-1", "eu-west-1"] },
      "rules": {
        "daily": {
          "schedule_expression": { "@@assign": "cron(0 5 ? * * *)" },
          "start_backup_window_minutes": { "@@assign": "60" },
          "target_backup_vault_name": { "@@assign": "Default" },
          "lifecycle": {
            "move_to_cold_storage_after_days": { "@@assign": "30" },
            "delete_after_days": { "@@assign": "365" }
          },
          "copy_actions": {
            "arn:aws:backup:us-west-1:$account:backup-vault:secondary-vault": {
              "target_backup_vault_arn": {
                "@@assign": "arn:aws:backup:us-west-1:$account:backup-vault:secondary-vault"
              },
              "lifecycle": {
                "delete_after_days": { "@@assign": "365" }
              }
            }
          }
        }
      },
      "selections": {
        "tags": {
          "datatype": {
            "iam_role_arn": { "@@assign": "arn:aws:iam::$account:role/backup-role" },
            "tag_key": { "@@assign": "backup" },
            "tag_value": { "@@assign": ["true", "yes"] }
          }
        }
      }
    }
  }
}
```

## 5. IAM身份中心(前AWS SSO)

### 设置IAM身份中心

IAM身份中心为AWS账户提供集中身份管理：

```bash
# 启用IAM身份中心
aws sso-admin create-instance
```

### 身份源配置

1. **内置目录**：适合小型组织和测试
2. **Active Directory**：通过AWS Managed Microsoft AD或自管理AD集成
3. **外部IdP**：集成Okta、Azure AD等第三方IdP

```bash
# 配置身份源为外部IdP
aws sso-admin put-identity-provider-config \
  --sso-region us-east-1 \
  --identity-provider-type SAML \
  --meta-data fileb://metadata.xml
```

### 权限集和分配

1. 创建权限集定义访问级别
2. 将权限集分配给用户或组
3. 将分配的权限集关联到AWS账户

```bash
# 创建权限集
aws sso-admin create-permission-set \
  --name "ReadOnlyAccess" \
  --description "Read-only access to AWS resources" \
  --instance-arn "arn:aws:sso:::instance/ssoins-1234567890abcdef0"

# 分配权限集
aws sso-admin create-account-assignment \
  --instance-arn "arn:aws:sso:::instance/ssoins-1234567890abcdef0" \
  --permission-set-arn "arn:aws:sso:::permissionSet/ssoins-1234567890abcdef0/ps-1234567890abcdef0" \
  --principal-id "user-id" \
  --principal-type "USER" \
  --target-id "111122223333" \
  --target-type "AWS_ACCOUNT"
```

## 6. 多账户管理最佳实践

### 账户结构设计

设计账户结构时考虑以下因素：

1. 安全隔离要求
2. 业务组织架构
3. 成本管理需求
4. 合规要求
5. 操作模式

### 跨账户访问设计

使用IAM角色实现跨账户访问：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::111122223333:role/CrossAccountAdminRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
```

### 集中式日志记录

在多账户环境中设置集中日志记录：

1. 创建专用日志存档账户
2. 配置CloudTrail组织跟踪
3. 设置CloudWatch Logs集中管理
4. 使用S3存储长期日志

```bash
# 创建组织跟踪
aws cloudtrail create-trail \
  --name org-trail \
  --s3-bucket-name org-logs-bucket \
  --is-organization-trail \
  --is-multi-region-trail
```

## 7. 成本管理

### 账户级别的成本控制

1. **服务配额**：设置默认服务限额
2. **预算和告警**：为账户设置预算和超支警报

```bash
# 创建账户预算
aws budgets create-budget \
  --account-id 111122223333 \
  --budget file://budget.json \
  --notifications-with-subscribers file://notifications.json
```

### 成本分配标签

实施标记策略以分析和分配成本：

```bash
# 启用成本分配标签
aws ce update-cost-allocation-tags-status \
  --cost-allocation-tags "TagStatus=Active,TagKey=CostCenter" "TagStatus=Active,TagKey=Project"
```

### AWS成本异常检测

启用成本异常检测以识别意外支出：

```bash
# 创建成本异常监控
aws ce create-anomaly-monitor \
  --anomaly-monitor '{"MonitorName":"Account Monitor","MonitorType":"DIMENSIONAL","MonitorDimension":"SERVICE"}'
```

## 8. 安全监控与合规

### AWS Config

使用AWS Config评估资源配置：

```bash
# 启用AWS Config
aws config put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::123456789012:role/ConfigServiceRole \
  --recording-group allSupported=true,includeGlobalResources=true

# 启用记录
aws config start-configuration-recorder --configuration-recorder-name default
```

### 安全检测与响应

1. **GuardDuty**：持续安全监控和威胁检测
2. **Security Hub**：安全检查和最佳实践合规
3. **Detective**：安全调查分析
4. **Inspector**：漏洞扫描

```bash
# 启用GuardDuty
aws guardduty create-detector --enable

# 启用Security Hub
aws securityhub enable-security-hub
```

### AWS Audit Manager

设置持续合规监控：

```bash
# 创建审计评估
aws auditmanager create-assessment \
  --name "Annual-Compliance-Assessment" \
  --description "Annual compliance review" \
  --assessment-reports-destination destinationType=S3,destination=s3://audit-reports-bucket \
  --scope awsAccounts=[{id=123456789012}],awsServices=[{serviceName=S3}] \
  --framework-id a1b2c3d4-5678-90ab-cdef-EXAMPLE11111
```

## 9. 账户恢复与紧急访问

### 账户恢复计划

制定和测试账户恢复计划：

1. 确保根用户电子邮件可访问
2. 维护和验证备用联系人信息
3. 记录MFA设备信息和恢复码
4. 定期测试恢复流程

### 紧急访问(Break Glass)流程

设置紧急访问流程：

1. 创建有限数量的紧急访问账户
2. 安全存储这些账户的凭证
3. 需要多人批准才能访问
4. 任何使用后进行审计和密码轮换

```bash
# 创建Break Glass用户
aws iam create-user --user-name emergency-admin

# 添加管理员权限
aws iam attach-user-policy --user-name emergency-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 创建访问密钥(仅在需要时)
aws iam create-access-key --user-name emergency-admin
```

## 10. 账户关闭和数据导出

### 账户关闭准备

关闭账户前的检查清单：

1. 备份所有数据
2. 删除或迁移所有资源
3. 确认所有导出数据已验证
4. 检查账单和付款状态
5. 记录存档日志和报告

### 数据导出过程

```bash
# 导出S3数据
aws s3 sync s3://my-important-bucket /backup/s3/

# 导出RDS数据库
aws rds create-db-snapshot \
  --db-instance-identifier my-database \
  --db-snapshot-identifier final-snapshot

# 导出DynamoDB表
aws dynamodb export-table-to-point-in-time \
  --table-arn arn:aws:dynamodb:us-east-1:123456789012:table/my-table \
  --s3-bucket dynamodb-exports \
  --s3-prefix my-table-export \
  --export-format DYNAMODB_JSON
```

### 账户关闭流程

1. 登录AWS账户
2. 导航到"我的账户"页面
3. 滚动到"关闭账户"部分
4. 阅读并确认关闭条款
5. 点击"关闭账户"

注意：关闭后90天内账户可重新打开，90天后账户将永久关闭。

## 实战案例：企业级AWS账户架构

### 场景描述

一家中型企业(500名员工)正在迁移到AWS，需要设计安全且可扩展的多账户环境。

### 账户结构设计

**组织结构**：
```
Management Account (billing, audit, governance)
├── Security OU
│   ├── Log Archive Account
│   └── Security Tooling Account
├── Infrastructure OU
│   ├── Network Account
│   └── Shared Services Account
├── Workloads OU
│   ├── Development Account
│   ├── Test Account
│   └── Production Account
└── Sandbox OU
    └── Developer Sandbox Account
```

**安全控制**：
1. 使用SCP限制删除安全资源
2. 仅允许在核心区域运营
3. 强制执行资源标记
4. 集中管理IAM用户

**身份管理**：
1. 与公司Active Directory集成
2. 使用IAM身份中心管理权限
3. 配置预定义权限集(ReadOnly, Developer, Admin)

**实施步骤**：
1. 创建组织和OU结构
2. 设置集中日志和监控
3. 实施安全基线(GuardDuty, Security Hub, Config)
4. 建立身份联合访问
5. 配置跨账户角色
6. 实施资源标记战略

## 总结

有效的AWS账户管理和安全配置是构建安全云环境的基础。通过实施多账户策略、强化根用户安全、设置集中式身份管理、实施组织控制策略以及配置适当的监控和合规工具，您可以创建一个既安全又高效的AWS环境。记住定期审查和更新这些设置，以适应不断变化的业务需求和安全威胁。

## 参考资源

- [AWS组织文档](https://docs.aws.amazon.com/organizations/)
- [IAM身份中心文档](https://docs.aws.amazon.com/singlesignon/)
- [AWS账户安全最佳实践](https://aws.amazon.com/blogs/security/getting-started-follow-security-best-practices-as-you-configure-your-aws-resources/)
- [多账户策略](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html)
- [AWS控制塔](https://aws.amazon.com/controltower/) 