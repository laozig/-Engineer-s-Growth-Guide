# AWS CloudFormation 基础设施即代码

AWS CloudFormation 是一项基础设施即代码（IaC）服务，允许用户通过模板文件定义和部署 AWS 资源，实现自动化、版本控制和可重复的基础设施管理。本文档详细介绍 CloudFormation 的核心功能、模板结构、配置方法、最佳实践与常见问题排查。

## 目录

- [服务简介](#服务简介)
- [核心概念](#核心概念)
- [模板结构](#模板结构)
- [资源管理](#资源管理)
- [堆栈操作](#堆栈操作)
- [参数与输出](#参数与输出)
- [内置函数](#内置函数)
- [嵌套堆栈](#嵌套堆栈)
- [变更集](#变更集)
- [漂移检测](#漂移检测)
- [安全与合规](#安全与合规)
- [与其他服务集成](#与其他服务集成)
- [最佳实践](#最佳实践)
- [常见问题排查](#常见问题排查)
- [参考资源](#参考资源)

## 服务简介

AWS CloudFormation 是一项使用代码定义和部署 AWS 基础设施的服务，具有以下主要特点：

- 使用声明式模板描述所需的 AWS 资源
- 自动处理资源之间的依赖关系
- 支持版本控制和基础设施变更追踪
- 实现可重复、一致的环境部署
- 提供回滚机制，确保部署安全
- 无需额外费用，仅为创建的 AWS 资源付费

## 核心概念

### 模板（Template）

- 描述 AWS 资源的 JSON 或 YAML 格式文件
- 定义资源属性、关系和配置
- 支持参数、映射、条件、输出等元素
- 可存储在本地或 S3 存储桶中

### 堆栈（Stack）

- 通过模板创建的 AWS 资源集合
- 作为单个单元进行管理
- 支持创建、更新、删除操作
- 提供资源状态和事件跟踪

### 资源（Resource）

- 模板中定义的 AWS 组件（如 EC2、S3、RDS 等）
- 每个资源都有唯一的逻辑 ID
- 包含类型、属性和依赖关系
- 由 CloudFormation 自动创建和管理

### 变更集（Change Set）

- 描述对堆栈的拟议更改
- 允许在执行前预览更改
- 帮助评估更改的潜在影响
- 可以执行或拒绝变更

## 模板结构

CloudFormation 模板由以下主要部分组成：

### 格式版本（Format Version）

```yaml
AWSTemplateFormatVersion: '2010-09-09'
```

### 描述（Description）

```yaml
Description: 'A sample template for creating EC2 instances'
```

### 元数据（Metadata）

```yaml
Metadata:
  Interface:
    ParameterGroups:
      - Label:
          default: "Network Configuration"
        Parameters:
          - VpcId
          - SubnetId
```

### 参数（Parameters）

```yaml
Parameters:
  InstanceType:
    Description: EC2 instance type
    Type: String
    Default: t2.micro
    AllowedValues:
      - t2.micro
      - t2.small
      - t2.medium
```

### 映射（Mappings）

```yaml
Mappings:
  RegionMap:
    us-east-1:
      AMI: ami-0ff8a91507f77f867
    us-west-1:
      AMI: ami-0bdb828fd58c52235
```

### 条件（Conditions）

```yaml
Conditions:
  CreateProdResources: !Equals [ !Ref EnvType, prod ]
```

### 资源（Resources）

```yaml
Resources:
  MyEC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: !Ref InstanceType
      ImageId: !FindInMap [RegionMap, !Ref "AWS::Region", AMI]
```

### 输出（Outputs）

```yaml
Outputs:
  InstanceId:
    Description: The Instance ID
    Value: !Ref MyEC2Instance
```

## 资源管理

### 支持的资源类型

CloudFormation 支持大多数 AWS 服务的资源类型，包括但不限于：

- 计算：EC2、Lambda、ECS、EKS
- 存储：S3、EBS、EFS
- 数据库：RDS、DynamoDB、ElastiCache
- 网络：VPC、子网、安全组、负载均衡器
- 安全：IAM、KMS、WAF
- 监控：CloudWatch、SNS

### 资源属性

- 每种资源类型都有特定的必需和可选属性
- 属性可以是静态值或动态引用（如参数、函数）
- 某些属性可以在创建后更新，有些则不可更新

### 资源依赖关系

- 显式依赖：使用 DependsOn 属性
  ```yaml
  MyEC2Instance:
    Type: AWS::EC2::Instance
    DependsOn: MyVPC
  ```
- 隐式依赖：通过引用（!Ref、!GetAtt）自动建立

### 删除策略

- 控制资源在堆栈删除时的行为
  ```yaml
  MyS3Bucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain  # 可选值：Delete、Retain、Snapshot
  ```

## 堆栈操作

### 创建堆栈

1. 通过 AWS 控制台、AWS CLI 或 SDK 创建堆栈
2. 指定模板文件（本地文件或 S3 URL）
3. 提供参数值
4. 设置堆栈选项（标签、权限、超时等）
5. 查看并创建堆栈

### 更新堆栈

1. 修改模板或参数
2. 提交更新请求
3. CloudFormation 确定更改内容
4. 应用更改，仅修改必要的资源

### 删除堆栈

1. 请求删除堆栈
2. CloudFormation 按依赖关系的相反顺序删除资源
3. 应用删除策略（删除、保留或快照）
4. 完成后移除堆栈

### 堆栈状态

- CREATE_COMPLETE：创建成功
- UPDATE_IN_PROGRESS：更新进行中
- UPDATE_COMPLETE：更新成功
- DELETE_IN_PROGRESS：删除进行中
- ROLLBACK_IN_PROGRESS：回滚进行中
- ROLLBACK_COMPLETE：回滚完成

## 参数与输出

### 参数类型

- 字符串：String
- 数字：Number
- 列表：CommaDelimitedList
- AWS 特定类型：如 AWS::EC2::VPC::Id
- SSM 参数：AWS::SSM::Parameter::Value

### 参数约束

- 默认值：Default
- 允许值：AllowedValues
- 最小/最大长度：MinLength、MaxLength
- 最小/最大值：MinValue、MaxValue
- 正则表达式模式：AllowedPattern
- NoEcho：隐藏敏感参数值

### 输出使用

- 在控制台或 CLI 中查看
- 导出到其他堆栈使用
- 用于跨堆栈引用
  ```yaml
  Outputs:
    VPCId:
      Description: The VPC ID
      Value: !Ref MyVPC
      Export:
        Name: !Sub "${AWS::StackName}-VPCID"
  ```

## 内置函数

CloudFormation 提供多种内置函数处理模板中的值：

### 引用函数

- **!Ref**：引用资源或参数
- **!GetAtt**：获取资源的属性
  ```yaml
  !GetAtt MyEC2Instance.PrivateIp
  ```

### 转换函数

- **!Base64**：将字符串转换为 Base64
- **!Join**：将值连接为字符串
  ```yaml
  !Join [ ":", [ a, b, c ] ]  # 结果：a:b:c
  ```
- **!Split**：将字符串拆分为列表
- **!Sub**：替换变量
  ```yaml
  !Sub "Hello ${Name}"
  ```

### 条件函数

- **!If**：条件判断
- **!Equals**、**!Not**、**!And**、**!Or**：逻辑比较

### 查找函数

- **!FindInMap**：在映射中查找值
- **!Select**：从列表中选择值
- **!ImportValue**：导入其他堆栈的输出

## 嵌套堆栈

### 定义与用途

- 将复杂基础设施分解为可管理的组件
- 重用通用模板
- 模块化基础设施设计

### 实现方式

```yaml
Resources:
  NetworkStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: https://s3.amazonaws.com/templates/network.yaml
      Parameters:
        VPCCidr: 10.0.0.0/16
```

### 嵌套堆栈传参

- 父堆栈向子堆栈传递参数
- 子堆栈通过输出返回值
- 父堆栈可以引用子堆栈输出
  ```yaml
  !GetAtt NetworkStack.Outputs.VPCId
  ```

## 变更集

### 变更集用途

- 预览对堆栈的更改
- 评估潜在影响
- 在执行前确认更改

### 变更集操作

1. 创建变更集
2. 查看拟议的更改
3. 执行或拒绝变更集

### 变更类型

- 添加：新增资源
- 修改：更新现有资源属性
- 删除：移除资源
- 替换：需要重新创建的资源

## 漂移检测

### 漂移概念

- 识别堆栈资源与模板定义的差异
- 检测堆栈外部的手动更改
- 维护基础设施的一致性

### 漂移操作

1. 启动漂移检测
2. 查看检测结果
3. 解决漂移（更新模板或资源）

### 漂移状态

- DRIFTED：资源已偏离模板定义
- NOT_CHECKED：资源未检查漂移
- IN_SYNC：资源与模板一致
- DELETED：资源已在模板外删除

## 安全与合规

### IAM 集成

- 使用服务角色部署堆栈
- 控制谁可以创建、更新和删除堆栈
- 资源级权限控制

### 堆栈策略

- 防止堆栈资源被意外更新或删除
- JSON 格式的策略文档
- 可应用于整个堆栈或特定资源

### 合规性验证

- 使用 AWS Config 规则验证资源配置
- 与 AWS CloudTrail 集成审计更改
- 支持自动修复不合规资源

## 与其他服务集成

### AWS CodePipeline

- 自动化 CloudFormation 部署
- 实现 CI/CD 流程
- 多环境部署策略

### AWS Service Catalog

- 创建和管理经批准的 CloudFormation 模板
- 为终端用户提供自助服务门户
- 实施治理和合规性控制

### AWS Config

- 跟踪资源配置变更
- 评估资源合规性
- 自动修复不合规资源

### AWS CDK

- 使用编程语言（TypeScript、Python、Java 等）定义基础设施
- 生成 CloudFormation 模板
- 利用面向对象编程的优势

## 最佳实践

### 模板设计

- 使用参数提高模板灵活性
- 使用映射处理环境差异
- 模块化设计，使用嵌套堆栈
- 为资源添加有意义的逻辑 ID 和描述
- 使用 YAML 格式提高可读性

### 安全性

- 使用参数约束和验证
- 实施堆栈策略保护关键资源
- 使用 NoEcho 保护敏感参数
- 最小权限原则配置 IAM 角色
- 启用堆栈终止保护

### 部署策略

- 使用变更集预览更改
- 实施蓝绿部署或金丝雀发布
- 配置回滚触发器
- 为关键资源设置适当的删除策略
- 定期执行漂移检测

### 版本控制与协作

- 将模板存储在版本控制系统中
- 使用代码审查流程
- 实施 CI/CD 管道自动化部署
- 使用 linting 和验证工具
- 记录模板设计和参数

## 常见问题排查

### 创建和更新失败

- 检查资源属性和依赖关系
- 验证 IAM 权限
- 查看堆栈事件和资源状态
- 检查服务限制和配额

### 删除卡住

- 检查删除保护设置
- 验证资源依赖关系
- 检查 DeletionPolicy 设置
- 手动删除卡住的资源（谨慎操作）

### 漂移问题

- 定期执行漂移检测
- 教育团队使用 CloudFormation 进行所有更改
- 实施控制防止手动更改
- 使用 AWS Config 规则强制合规性

### 性能优化

- 优化大型模板的部署时间
- 使用嵌套堆栈分解复杂基础设施
- 并行创建独立资源
- 考虑资源依赖关系的影响

## 参考资源

- [CloudFormation 官方文档](https://docs.aws.amazon.com/cloudformation/)
- [AWS CloudFormation 模板参考](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-reference.html)
- [CloudFormation 设计器](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/working-with-templates-cfn-designer.html)
- [CloudFormation 示例模板](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-sample-templates.html)
- [CloudFormation 最佳实践](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html) 