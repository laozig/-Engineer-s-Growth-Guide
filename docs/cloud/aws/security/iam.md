# IAM身份与访问管理

AWS Identity and Access Management (IAM) 是管理AWS服务和资源访问的关键安全服务。本文档将详细介绍IAM的核心概念、最佳实践和实际应用方法，帮助您正确配置和维护AWS环境的安全性。

## 1. IAM基础概念

### 什么是IAM？

IAM是一项Web服务，使您能够安全地控制对AWS资源的访问。通过IAM，您可以创建和管理AWS用户和组，使用各种权限来允许或拒绝他们访问AWS资源。

### IAM的核心组件

- **用户 (User)**：代表与AWS交互的个人或服务
- **组 (Group)**：用户的集合，可统一应用权限
- **角色 (Role)**：可由用户、应用程序或AWS服务临时担任的身份
- **策略 (Policy)**：定义权限的JSON文档
- **身份提供商 (Identity Provider)**：与AWS集成的外部身份系统
- **资源 (Resource)**：用户可以访问的AWS服务对象

### IAM的工作原理

IAM基于以下原则运作：

1. **认证 (Authentication)**：验证尝试访问的身份
2. **授权 (Authorization)**：决定该身份是否有权执行请求的操作
3. **访问控制 (Access Control)**：根据策略允许或拒绝访问

## 2. IAM用户管理

### 创建和配置IAM用户

#### 使用控制台

1. 登录AWS管理控制台
2. 导航到IAM服务
3. 选择"用户" > "添加用户"
4. 设置用户名和访问类型（编程访问和/或AWS管理控制台访问）
5. 设置密码或生成访问密钥
6. 分配权限（直接附加策略、添加到组或复制现有用户权限）
7. 添加标签（可选）
8. 查看并创建用户

#### 使用AWS CLI

```bash
# 创建IAM用户
aws iam create-user --user-name johndoe

# 创建访问密钥
aws iam create-access-key --user-name johndoe

# 创建控制台登录配置文件
aws iam create-login-profile --user-name johndoe --password "InitialPassword123!" --password-reset-required
```

### 管理访问密钥和凭证

```bash
# 列出用户的访问密钥
aws iam list-access-keys --user-name johndoe

# 更新访问密钥状态（激活/停用）
aws iam update-access-key --user-name johndoe --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive

# 删除访问密钥
aws iam delete-access-key --user-name johndoe --access-key-id AKIAIOSFODNN7EXAMPLE
```

### 安全最佳实践

- 启用多因素认证(MFA)
- 定期轮换访问密钥
- 不要共享访问密钥或IAM用户
- 遵循最小权限原则
- 使用强密码策略

```bash
# 为用户启用MFA
aws iam enable-mfa-device --user-name johndoe --serial-number arn:aws:iam::123456789012:mfa/johndoe --authentication-code1 123456 --authentication-code2 789012
```

## 3. IAM组管理

### 创建和管理组

#### 使用控制台

1. 导航到IAM服务
2. 选择"用户组" > "创建新组"
3. 设置组名称
4. 附加策略
5. 查看并创建组

#### 使用AWS CLI

```bash
# 创建IAM组
aws iam create-group --group-name Developers

# 将策略附加到组
aws iam attach-group-policy --group-name Developers --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 将用户添加到组
aws iam add-user-to-group --group-name Developers --user-name johndoe
```

### 组结构最佳实践

- 按职能划分组（如开发人员、系统管理员）
- 按项目或应用划分组
- 考虑基于角色的访问控制模型
- 定期审查组成员和权限

## 4. IAM角色

### 角色的用途和类型

IAM角色是一种无需长期凭证即可获取权限的方式，适用于：

- AWS服务访问其他服务
- 跨账户访问
- 联合身份用户临时访问
- EC2实例上运行的应用程序

### 创建和配置角色

```bash
# 创建EC2服务角色
aws iam create-role --role-name EC2-S3-Role --assume-role-policy-document file://trust-policy.json

# 附加策略到角色
aws iam attach-role-policy --role-name EC2-S3-Role --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

信任策略示例(trust-policy.json)：
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### 角色切换和承担

```bash
# 临时承担角色
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/CrossAccount-Role --role-session-name MySession
```

### 使用实例配置文件

实例配置文件是IAM角色的容器，用于向EC2实例提供临时凭证：

```bash
# 创建实例配置文件
aws iam create-instance-profile --instance-profile-name EC2-Profile

# 将角色添加到实例配置文件
aws iam add-role-to-instance-profile --instance-profile-name EC2-Profile --role-name EC2-S3-Role

# 将实例配置文件附加到EC2实例
aws ec2 associate-iam-instance-profile --instance-id i-1234567890abcdef0 --iam-instance-profile Name=EC2-Profile
```

## 5. IAM策略

### 策略结构和元素

IAM策略是定义权限的JSON文档，包含以下元素：

- **版本 (Version)**：策略语言版本，通常是"2012-10-17"
- **ID (Id)**：可选的策略标识符
- **语句 (Statement)**：权限语句数组
  - **Sid**：可选的语句标识符
  - **Effect**：Allow或Deny
  - **Principal**：适用的用户、角色或服务
  - **Action**：允许或拒绝的API操作
  - **Resource**：适用的资源
  - **Condition**：可选的条件

### 策略类型

- **AWS托管策略**：由AWS创建和管理
- **客户托管策略**：由您创建和管理
- **内联策略**：直接嵌入用户、组或角色中

### 创建自定义策略

```bash
# 创建客户托管策略
aws iam create-policy --policy-name MyS3Policy --policy-document file://s3policy.json
```

策略文档示例(s3policy.json)：
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
```

### 权限边界

权限边界是一种高级功能，用于设置IAM实体可以获得的最大权限：

```bash
# 设置权限边界
aws iam put-user-permissions-boundary --user-name johndoe --permissions-boundary arn:aws:iam::aws:policy/PowerUserAccess
```

## 6. 高级IAM功能

### 基于身份的策略与基于资源的策略

- **基于身份的策略**：附加到IAM用户、组或角色
- **基于资源的策略**：附加到资源，如S3存储桶、Lambda函数

### 策略条件和上下文键

条件允许您根据请求上下文更精细地控制权限：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::my-bucket",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        },
        "StringEquals": {
          "aws:PrincipalTag/Department": "IT"
        }
      }
    }
  ]
}
```

### 服务控制策略(SCP)

SCP是组织管理的一部分，用于定义成员账户中权限的上限：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:RunInstances",
        "ec2:StartInstances"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "ec2:InstanceType": ["t2.micro", "t3.micro"]
        }
      }
    }
  ]
}
```

### 基于标签的访问控制(ABAC)

ABAC允许您基于标签定义权限，支持更灵活、可扩展的访问控制策略：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:StartInstances", "ec2:StopInstances"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Department": "${aws:PrincipalTag/Department}"
        }
      }
    }
  ]
}
```

## 7. 联合身份认证

### 外部身份提供商(IdP)集成

AWS IAM支持与外部身份提供商集成，包括：

- SAML 2.0联合身份验证
- OIDC兼容身份提供商
- AWS SSO/IAM Identity Center
- Amazon Cognito

### 配置SAML联合身份

```bash
# 创建SAML提供商
aws iam create-saml-provider --name MyADFS --saml-metadata-document file://metadata.xml --tags Key=Department,Value=IT

# 创建SAML联合身份角色
aws iam create-role --role-name SAML-Role --assume-role-policy-document file://saml-trust.json
```

SAML信任策略(saml-trust.json)：
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:saml-provider/MyADFS"
      },
      "Action": "sts:AssumeRoleWithSAML",
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
```

### 设置Web身份联合身份验证

```bash
# 创建OIDC提供商
aws iam create-open-id-connect-provider --url https://accounts.google.com --client-id-list 123456789012.apps.googleusercontent.com --thumbprint-list a9d53002e97e00e043244f3d170d6f4c414104fd

# 创建Web联合身份角色
aws iam create-role --role-name WebIdentity-Role --assume-role-policy-document file://web-identity-trust.json
```

Web身份信任策略(web-identity-trust.json)：
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "accounts.google.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:aud": "123456789012.apps.googleusercontent.com"
        }
      }
    }
  ]
}
```

## 8. IAM安全最佳实践

### 最小权限原则

仅授予执行任务所需的最小权限，定期审查权限并移除不必要的权限。

### 使用MFA

为所有具有密码的IAM用户启用多因素认证：

```bash
# 强制要求MFA的策略示例
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowViewAccountInfo",
      "Effect": "Allow",
      "Action": [
        "iam:ListVirtualMFADevices",
        "iam:ListUsers"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowManageOwnVirtualMFA",
      "Effect": "Allow",
      "Action": [
        "iam:CreateVirtualMFADevice",
        "iam:DeactivateMFADevice",
        "iam:DeleteVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ResyncMFADevice"
      ],
      "Resource": [
        "arn:aws:iam::*:mfa/$${aws:username}",
        "arn:aws:iam::*:user/$${aws:username}"
      ]
    },
    {
      "Sid": "DenyAllExceptListedIfNoMFA",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:ListMFADevices",
        "iam:ListUsers",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

### 定期轮换凭证

建立凭证轮换策略并强制执行：

```bash
# 启用密码策略
aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90
```

### 使用IAM访问分析器

IAM访问分析器可以识别资源策略中可能导致外部访问的权限：

```bash
# 创建分析器
aws accessanalyzer create-analyzer --analyzer-name MyAccountAnalyzer --type ACCOUNT
```

### IAM权限边界

使用权限边界限制管理员创建的用户的最大权限：

```bash
# 创建IAM管理员，但限制其权限边界
aws iam create-user --user-name IAMManager
aws iam attach-user-policy --user-name IAMManager --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
aws iam put-user-permissions-boundary --user-name IAMManager --permissions-boundary arn:aws:iam::aws:policy/PowerUserAccess
```

## 9. 监控和审计IAM

### CloudTrail与IAM集成

AWS CloudTrail记录IAM操作，帮助您监控账户中发生的活动：

```bash
# 创建记录IAM事件的跟踪
aws cloudtrail create-trail --name IAMAuditTrail --s3-bucket-name my-cloudtrail-bucket --is-multi-region-trail
aws cloudtrail start-logging --name IAMAuditTrail
```

### IAM凭证报告

获取账户中所有IAM用户的凭证状态报告：

```bash
# 生成凭证报告
aws iam generate-credential-report

# 获取凭证报告
aws iam get-credential-report
```

### IAM访问顾问

使用IAM访问顾问分析服务最后访问时间，清理未使用的权限：

```bash
# 生成服务最后访问数据
aws iam generate-service-last-accessed-details --arn arn:aws:iam::123456789012:user/johndoe

# 检索服务最后访问数据
aws iam get-service-last-accessed-details --job-id 98a765b4-3210-4567-8901-a1b2c3d4e5f6
```

## 10. IAM故障排除

### 常见问题和解决方案

#### 访问被拒绝错误

1. 检查IAM策略
2. 验证资源策略
3. 检查组成员关系
4. 验证策略变量
5. 检查会话标签
6. 验证SCP限制

#### 使用策略模拟器

策略模拟器可以测试IAM策略的效果，帮助诊断权限问题：

```bash
# 使用CLI进行策略模拟
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:user/johndoe --action-names s3:ListBucket
```

#### IAM策略疑难解答

查看"访问分析器"策略验证结果：

```bash
# 使用IAM Access Analyzer验证策略
aws accessanalyzer validate-policy --policy-document file://policy.json --policy-type IDENTITY_POLICY
```

## 实战示例：多团队AWS环境权限管理

### 场景描述

一家公司有多个团队（开发、测试、运维）共享AWS资源，需要实施最佳安全实践。

### 权限架构设计

1. **根帐户安全**：
   - 启用MFA
   - 仅用于关键操作
   - 安全存储凭证

2. **用户和组结构**：
   ```
   /
   ├─ Developers/
   │  ├─ Frontend-Devs
   │  ├─ Backend-Devs
   │  └─ Mobile-Devs
   ├─ Operations/
   │  ├─ SysAdmins
   │  ├─ DBAdmins
   │  └─ NetworkAdmins
   └─ Security/
      └─ Auditors
   ```

3. **IAM角色设计**：
   - `DevRole`: 开发环境完全访问
   - `TestRole`: 测试环境完全访问
   - `ProdReadRole`: 生产环境只读访问
   - `ProdDeployRole`: 仅允许部署操作

4. **策略示例**：
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "*",
         "Resource": "*",
         "Condition": {
           "StringEquals": {
             "aws:RequestedRegion": "ap-northeast-1"
           },
           "StringLike": {
             "aws:ResourceTag/Environment": "Dev"
           }
         }
       }
     ]
   }
   ```

5. **权限边界和Guard Rails**：
   - 使用SCP限制区域
   - 禁止删除日志和审计资源
   - 强制资源标签

### 实施步骤

1. 创建IAM组结构
2. 定义基本权限策略
3. 实施跨账户角色
4. 配置权限边界
5. 设置紧急访问流程
6. 建立持续的审计和合规检查

## 总结

AWS IAM是AWS安全模型的核心，提供了强大的工具来控制资源访问。通过理解和应用本文档中的概念、功能和最佳实践，您可以构建安全的多层次权限模型，遵循最小权限原则，并保护您的云资源免受未经授权的访问。

## 参考资源

- [IAM官方文档](https://docs.aws.amazon.com/iam/)
- [IAM最佳实践](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [IAM策略参考](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html)
- [IAM安全工具](https://docs.aws.amazon.com/IAM/latest/UserGuide/security-tools.html)
- [AWS STS文档](https://docs.aws.amazon.com/STS/latest/APIReference/) 