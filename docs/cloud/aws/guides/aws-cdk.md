# AWS CDK开发指南

本指南详细介绍如何使用AWS Cloud Development Kit (CDK)通过代码定义和管理AWS基础设施。

## 目录
- [CDK概述](#cdk概述)
- [环境配置](#环境配置)
- [基础概念](#基础概念)
- [常见模式](#常见模式)
- [最佳实践](#最佳实践)
- [故障排除](#故障排除)

## CDK概述

### 什么是CDK
```yaml
核心特性:
  基本概念:
    - 基础设施即代码(IaC)
    - 使用熟悉的编程语言
    - 面向对象的架构
    - 自动生成CloudFormation
  
  支持语言:
    - TypeScript/JavaScript
    - Python
    - Java
    - C#/.NET
    - Go
```

### CDK vs 其他IaC工具
```yaml
对比分析:
  CloudFormation:
    优势:
      - 更高级的抽象
      - 代码复用
      - 类型安全
      - 更好的开发体验
    
  Terraform:
    差异:
      - 原生AWS集成
      - 自动依赖管理
      - AWS最佳实践
      - 完整IDE支持
```

## 环境配置

### 安装和初始化
```bash
# 安装CDK CLI
npm install -g aws-cdk

# 验证安装
cdk --version

# 创建新项目
mkdir my-cdk-app && cd my-cdk-app

# TypeScript项目
cdk init app --language typescript

# Python项目
cdk init app --language python

# 安装依赖
npm install   # TypeScript
pip install -r requirements.txt   # Python

# 引导环境
cdk bootstrap
```

### TypeScript配置
```typescript
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2018",
    "module": "commonjs",
    "lib": ["es2018"],
    "declaration": true,
    "strict": true,
    "noImplicitAny": true,
    "strictNullChecks": true,
    "noImplicitThis": true,
    "alwaysStrict": true,
    "noUnusedLocals": false,
    "noUnusedParameters": false,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": false,
    "inlineSourceMap": true,
    "inlineSources": true,
    "experimentalDecorators": true,
    "strictPropertyInitialization": false,
    "typeRoots": ["./node_modules/@types"]
  },
  "exclude": ["cdk.out"]
}
```

### Python配置
```python
# app.py
#!/usr/bin/env python3
import os
import aws_cdk as cdk
from my_stack import MyStack

app = cdk.App()
MyStack(app, "MyStack",
    env=cdk.Environment(
        account=os.getenv('CDK_DEFAULT_ACCOUNT'),
        region=os.getenv('CDK_DEFAULT_REGION')
    )
)

app.synth()
```

## 基础概念

### 构造级别
```typescript
// Level 1 (L1) - CloudFormation资源
new s3.CfnBucket(this, 'MyL1Bucket', {
  bucketName: 'my-l1-bucket'
});

// Level 2 (L2) - 经过封装的构造
new s3.Bucket(this, 'MyL2Bucket', {
  versioned: true,
  encryption: s3.BucketEncryption.S3_MANAGED
});

// Level 3 (L3) - 模式构造
new s3patterns.BucketDeployment(this, 'MyL3Deployment', {
  sources: [s3deploy.Source.asset('./website')],
  destinationBucket: myBucket
});
```

### 堆栈定义
```typescript
// TypeScript示例
import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';

export class MyStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // 创建S3存储桶
    const bucket = new s3.Bucket(this, 'MyBucket', {
      versioned: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true
    });

    // 创建Lambda函数
    const handler = new lambda.Function(this, 'MyHandler', {
      runtime: lambda.Runtime.NODEJS_18_X,
      code: lambda.Code.fromAsset('lambda'),
      handler: 'index.handler',
      environment: {
        BUCKET_NAME: bucket.bucketName
      }
    });

    // 授予Lambda访问S3的权限
    bucket.grantRead(handler);
  }
}
```

### 资源属性和依赖
```typescript
// 资源引用
const bucket = new s3.Bucket(this, 'MyBucket');
const bucketName = bucket.bucketName;  // 获取物理名称

// 依赖管理
const handler = new lambda.Function(this, 'MyHandler', {
  // ... 其他配置
  environment: {
    BUCKET_NAME: bucket.bucketName  // 自动处理依赖
  }
});

// 显式依赖
handler.node.addDependency(bucket);
```

## 常见模式

### VPC网络
```typescript
import * as ec2 from 'aws-cdk-lib/aws-ec2';

// 创建VPC
const vpc = new ec2.Vpc(this, 'MyVPC', {
  maxAzs: 2,
  subnetConfiguration: [
    {
      cidrMask: 24,
      name: 'Public',
      subnetType: ec2.SubnetType.PUBLIC,
    },
    {
      cidrMask: 24,
      name: 'Private',
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    }
  ]
});

// 添加安全组
const securityGroup = new ec2.SecurityGroup(this, 'MySG', {
  vpc,
  description: 'Allow HTTP traffic',
  allowAllOutbound: true
});

securityGroup.addIngressRule(
  ec2.Peer.anyIpv4(),
  ec2.Port.tcp(80),
  'Allow HTTP traffic'
);
```

### 容器服务
```typescript
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as ecsp from 'aws-cdk-lib/aws-ecs-patterns';

// 创建Fargate服务
const service = new ecsp.ApplicationLoadBalancedFargateService(this, 'MyService', {
  vpc,
  memoryLimitMiB: 512,
  cpu: 256,
  taskImageOptions: {
    image: ecs.ContainerImage.fromRegistry('nginx:latest'),
    containerPort: 80
  },
  desiredCount: 2,
  publicLoadBalancer: true
});

// 自动扩缩容
const scaling = service.service.autoScaleTaskCount({
  maxCapacity: 4,
  minCapacity: 2
});

scaling.scaleOnCpuUtilization('CpuScaling', {
  targetUtilizationPercent: 70
});
```

### 无服务器应用
```typescript
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

// 创建DynamoDB表
const table = new dynamodb.Table(this, 'MyTable', {
  partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  removalPolicy: cdk.RemovalPolicy.DESTROY
});

// 创建Lambda函数
const handler = new lambda.Function(this, 'MyHandler', {
  runtime: lambda.Runtime.NODEJS_18_X,
  code: lambda.Code.fromAsset('lambda'),
  handler: 'index.handler',
  environment: {
    TABLE_NAME: table.tableName
  }
});

// 创建API Gateway
const api = new apigateway.RestApi(this, 'MyApi');
const items = api.root.addResource('items');

items.addMethod('GET', new apigateway.LambdaIntegration(handler));
items.addMethod('POST', new apigateway.LambdaIntegration(handler));

// 授予权限
table.grantReadWriteData(handler);
```

## 最佳实践

### 项目结构
```yaml
项目组织:
  目录结构:
    - bin/: CDK应用入口
    - lib/: 堆栈定义
    - test/: 单元测试
    - cdk.json: CDK配置
    - package.json: 项目配置
  
  代码组织:
    - 按功能分层
    - 资源分组
    - 共享构造
    - 环境配置
```

### 测试策略
```typescript
// 单元测试示例
import { Template } from 'aws-cdk-lib/assertions';
import * as cdk from 'aws-cdk-lib';
import * as MyStack from '../lib/my-stack';

test('Stack creates S3 bucket', () => {
  const app = new cdk.App();
  const stack = new MyStack(app, 'TestStack');
  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::S3::Bucket', {
    VersioningConfiguration: {
      Status: 'Enabled'
    }
  });
});
```

### 部署策略
```yaml
部署最佳实践:
  环境管理:
    - 使用cdk.json配置
    - 环境变量注入
    - 参数存储
    - 标签管理
  
  CI/CD集成:
    - 使用cdk diff
    - 自动化测试
    - 部署审批
    - 回滚策略
```

## 故障排除

### 常见问题
1. **部署错误**
   - 检查IAM权限
   - 验证资源限制
   - 查看CloudFormation日志
   - 确认依赖关系

2. **构建问题**
   - TypeScript编译错误
   - 依赖版本冲突
   - 资源命名冲突
   - 内存限制

3. **运行时问题**
   - 资源访问权限
   - 网络连接
   - 配置错误
   - 资源限制

### 调试技巧
```bash
# 查看CloudFormation模板
cdk synth

# 比较变更
cdk diff

# 调试部署
cdk deploy --debug

# 查看事件
aws cloudformation describe-stack-events --stack-name MyStack
```

### 最佳实践建议
1. **开发阶段**
   - 使用cdk diff预览变更
   - 编写单元测试
   - 遵循命名规范
   - 文档注释

2. **部署阶段**
   - 环境隔离
   - 渐进式部署
   - 监控告警
   - 备份策略

3. **维护阶段**
   - 版本控制
   - 定期更新
   - 成本优化
   - 安全审计 