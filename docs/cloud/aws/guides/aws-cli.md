# AWS CLI使用指南

本指南详细介绍AWS命令行界面(CLI)的安装、配置和使用方法，帮助您更高效地管理AWS资源。

## 目录
- [安装配置](#安装配置)
- [基础用法](#基础用法)
- [常用命令](#常用命令)
- [最佳实践](#最佳实践)
- [故障排除](#故障排除)

## 安装配置

### 安装AWS CLI
```bash
# Windows (PowerShell)
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi

# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# 验证安装
aws --version
```

### 配置凭证
```bash
# 交互式配置
aws configure

# 配置示例
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: ap-northeast-1
Default output format [None]: json

# 配置多个配置文件
aws configure --profile prod
aws configure --profile dev
```

### 配置文件位置
```yaml
配置文件:
  Windows: 
    - "%UserProfile%\\.aws\\credentials"
    - "%UserProfile%\\.aws\\config"
  
  Linux/macOS:
    - "~/.aws/credentials"
    - "~/.aws/config"
```

## 基础用法

### 命令结构
```yaml
命令格式:
  基本结构: aws <service> <command> [options]
  
  示例:
    - aws s3 ls
    - aws ec2 describe-instances
    - aws lambda list-functions

  常用选项:
    - --profile: 指定配置文件
    - --region: 指定区域
    - --output: 指定输出格式
    - --query: 使用JMESPath查询
```

### 输出格式
```bash
# JSON格式（默认）
aws ec2 describe-instances --output json

# 表格格式
aws ec2 describe-instances --output table

# 文本格式
aws ec2 describe-instances --output text

# YAML格式
aws ec2 describe-instances --output yaml
```

### 使用JMESPath查询
```bash
# 查询特定字段
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name]'

# 过滤结果
aws ec2 describe-instances --query 'Reservations[*].Instances[?State.Name==`running`]'

# 格式化输出
aws ec2 describe-instances --query 'Reservations[*].Instances[*].{ID:InstanceId,State:State.Name}'
```

## 常用命令

### EC2管理
```bash
# 列出实例
aws ec2 describe-instances

# 启动实例
aws ec2 start-instances --instance-ids i-1234567890abcdef0

# 停止实例
aws ec2 stop-instances --instance-ids i-1234567890abcdef0

# 创建实例
aws ec2 run-instances \
    --image-id ami-12345678 \
    --instance-type t2.micro \
    --key-name MyKeyPair \
    --security-group-ids sg-12345678

# 终止实例
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0
```

### S3操作
```bash
# 列出存储桶
aws s3 ls

# 列出存储桶内容
aws s3 ls s3://my-bucket

# 上传文件
aws s3 cp file.txt s3://my-bucket/

# 下载文件
aws s3 cp s3://my-bucket/file.txt ./

# 同步目录
aws s3 sync local-dir s3://my-bucket/dir/

# 删除文件
aws s3 rm s3://my-bucket/file.txt

# 删除存储桶
aws s3 rb s3://my-bucket --force
```

### IAM管理
```bash
# 列出用户
aws iam list-users

# 创建用户
aws iam create-user --user-name MyUser

# 创建访问密钥
aws iam create-access-key --user-name MyUser

# 添加用户到组
aws iam add-user-to-group --user-name MyUser --group-name MyGroup

# 列出策略
aws iam list-policies

# 附加策略
aws iam attach-user-policy \
    --user-name MyUser \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

### Lambda函数
```bash
# 列出函数
aws lambda list-functions

# 调用函数
aws lambda invoke \
    --function-name my-function \
    --payload '{"key": "value"}' \
    output.txt

# 更新函数代码
aws lambda update-function-code \
    --function-name my-function \
    --zip-file fileb://function.zip

# 获取函数配置
aws lambda get-function-configuration \
    --function-name my-function
```

### CloudWatch日志
```bash
# 获取日志组
aws logs describe-log-groups

# 获取日志流
aws logs describe-log-streams \
    --log-group-name /aws/lambda/my-function

# 获取日志事件
aws logs get-log-events \
    --log-group-name /aws/lambda/my-function \
    --log-stream-name 2023/03/14/[$LATEST]58419525dade

# 创建日志组
aws logs create-log-group \
    --log-group-name my-log-group
```

## 最佳实践

### 安全性建议
```yaml
安全实践:
  凭证管理:
    - 使用IAM角色而不是访问密钥
    - 定期轮换访问密钥
    - 避免在代码中硬编码凭证
    - 使用多因素认证(MFA)
  
  权限控制:
    - 遵循最小权限原则
    - 使用IAM策略条件
    - 定期审查权限
    - 启用CloudTrail审计
```

### 效率提升
```yaml
使用技巧:
  命令行效率:
    - 使用命令别名
    - 利用自动补全
    - 使用命令历史
    - 创建脚本自动化
  
  输出处理:
    - 使用JMESPath查询
    - 结合jq处理JSON
    - 使用管道和过滤
    - 保存输出到文件
```

### 自动化脚本示例
```bash
#!/bin/bash
# 批量启动带特定标签的EC2实例
aws ec2 describe-instances \
    --filters "Name=tag:Environment,Values=Production" \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text | \
    xargs -n1 aws ec2 start-instances --instance-ids

# 清理过期的EBS快照
aws ec2 describe-snapshots \
    --owner-ids self \
    --query 'Snapshots[?StartTime<=`2023-01-01`].SnapshotId' \
    --output text | \
    xargs -n1 aws ec2 delete-snapshot --snapshot-id

# 批量标签更新
aws ec2 describe-instances \
    --query 'Reservations[*].Instances[*].InstanceId' \
    --output text | \
    xargs -I {} aws ec2 create-tags \
        --resources {} \
        --tags Key=Environment,Value=Production
```

## 故障排除

### 常见问题
1. **凭证问题**
   - 检查凭证文件权限
   - 验证凭证是否过期
   - 确认IAM权限配置
   - 检查环境变量设置

2. **连接问题**
   - 检查网络连接
   - 验证代理设置
   - 确认区域配置
   - 检查VPN状态

3. **命令错误**
   - 检查命令语法
   - 验证参数格式
   - 查看错误消息
   - 使用--debug选项

### 调试技巧
```bash
# 启用调试模式
aws ec2 describe-instances --debug

# 检查AWS CLI版本
aws --version

# 验证凭证
aws sts get-caller-identity

# 测试API访问
aws ec2 describe-regions

# 检查配置
aws configure list
```

### 环境变量
```yaml
常用环境变量:
  凭证相关:
    - AWS_ACCESS_KEY_ID
    - AWS_SECRET_ACCESS_KEY
    - AWS_SESSION_TOKEN
    - AWS_PROFILE
  
  配置相关:
    - AWS_DEFAULT_REGION
    - AWS_DEFAULT_OUTPUT
    - AWS_CA_BUNDLE
    - AWS_CLI_FILE_ENCODING
``` 