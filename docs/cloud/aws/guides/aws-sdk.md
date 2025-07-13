# AWS SDK应用指南

本指南详细介绍如何使用AWS SDK在各种编程语言中访问和管理AWS资源。

## 目录
- [SDK概述](#sdk概述)
- [环境配置](#环境配置)
- [常见操作](#常见操作)
- [最佳实践](#最佳实践)
- [故障排除](#故障排除)

## SDK概述

### 支持的语言
```yaml
主要SDK:
  - AWS SDK for Java
  - AWS SDK for Python (Boto3)
  - AWS SDK for JavaScript
  - AWS SDK for .NET
  - AWS SDK for Go
  - AWS SDK for PHP
  - AWS SDK for Ruby
```

### 核心功能
```yaml
功能特性:
  基础功能:
    - 凭证管理
    - 会话管理
    - 重试机制
    - 错误处理
  
  高级特性:
    - 异步操作
    - 分页处理
    - 并发控制
    - 请求签名
```

## 环境配置

### Python (Boto3)
```python
# 安装
pip install boto3

# 基础配置
import boto3

# 使用默认凭证
s3 = boto3.client('s3')

# 指定凭证
s3 = boto3.client(
    's3',
    aws_access_key_id='YOUR_ACCESS_KEY',
    aws_secret_access_key='YOUR_SECRET_KEY',
    region_name='ap-northeast-1'
)

# 使用配置文件
session = boto3.Session(profile_name='dev')
s3 = session.client('s3')
```

### Java
```xml
<!-- Maven依赖 -->
<dependency>
    <groupId>com.amazonaws</groupId>
    <artifactId>aws-java-sdk-s3</artifactId>
    <version>1.12.261</version>
</dependency>
```

```java
// 基础配置
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;

// 使用默认凭证
AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
    .withRegion("ap-northeast-1")
    .build();

// 指定凭证
BasicAWSCredentials credentials = new BasicAWSCredentials(
    "YOUR_ACCESS_KEY",
    "YOUR_SECRET_KEY"
);

AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
    .withCredentials(new AWSStaticCredentialsProvider(credentials))
    .withRegion("ap-northeast-1")
    .build();
```

### Node.js
```javascript
// 安装
npm install @aws-sdk/client-s3

// 基础配置
const { S3Client } = require("@aws-sdk/client-s3");

// 使用默认凭证
const s3Client = new S3Client({ region: "ap-northeast-1" });

// 指定凭证
const s3Client = new S3Client({
    region: "ap-northeast-1",
    credentials: {
        accessKeyId: "YOUR_ACCESS_KEY",
        secretAccessKey: "YOUR_SECRET_KEY"
    }
});
```

### Go
```go
// 安装
go get github.com/aws/aws-sdk-go-v2

// 基础配置
import (
    "github.com/aws/aws-sdk-go-v2/aws"
    "github.com/aws/aws-sdk-go-v2/service/s3"
)

// 使用默认凭证
cfg, err := config.LoadDefaultConfig(context.TODO(),
    config.WithRegion("ap-northeast-1"),
)
s3Client := s3.NewFromConfig(cfg)

// 指定凭证
cfg, err := config.LoadDefaultConfig(context.TODO(),
    config.WithRegion("ap-northeast-1"),
    config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
        "YOUR_ACCESS_KEY",
        "YOUR_SECRET_KEY",
        "",
    )),
)
```

## 常见操作

### S3操作示例

#### Python (Boto3)
```python
import boto3

# 创建S3客户端
s3 = boto3.client('s3')

# 上传文件
s3.upload_file(
    'local_file.txt',
    'my-bucket',
    'remote_file.txt'
)

# 下载文件
s3.download_file(
    'my-bucket',
    'remote_file.txt',
    'local_file.txt'
)

# 列出存储桶
response = s3.list_buckets()
for bucket in response['Buckets']:
    print(bucket['Name'])

# 列出对象
response = s3.list_objects_v2(Bucket='my-bucket')
for obj in response['Contents']:
    print(obj['Key'])
```

#### Java
```java
// 上传文件
s3Client.putObject(
    "my-bucket",
    "remote_file.txt",
    new File("local_file.txt")
);

// 下载文件
s3Client.getObject(
    new GetObjectRequest("my-bucket", "remote_file.txt"),
    new File("local_file.txt")
);

// 列出存储桶
List<Bucket> buckets = s3Client.listBuckets();
for (Bucket bucket : buckets) {
    System.out.println(bucket.getName());
}

// 列出对象
ObjectListing objects = s3Client.listObjects("my-bucket");
for (S3ObjectSummary obj : objects.getObjectSummaries()) {
    System.out.println(obj.getKey());
}
```

### DynamoDB操作示例

#### Python (Boto3)
```python
import boto3

# 创建DynamoDB客户端
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Users')

# 插入项目
table.put_item(
    Item={
        'user_id': '123',
        'name': 'John Doe',
        'email': 'john@example.com'
    }
)

# 获取项目
response = table.get_item(
    Key={
        'user_id': '123'
    }
)
item = response['Item']

# 更新项目
table.update_item(
    Key={
        'user_id': '123'
    },
    UpdateExpression='SET email = :val',
    ExpressionAttributeValues={
        ':val': 'new_email@example.com'
    }
)

# 删除项目
table.delete_item(
    Key={
        'user_id': '123'
    }
)
```

### Lambda函数操作

#### Python (Boto3)
```python
import boto3
import json

# 创建Lambda客户端
lambda_client = boto3.client('lambda')

# 调用函数
response = lambda_client.invoke(
    FunctionName='my-function',
    InvocationType='RequestResponse',
    Payload=json.dumps({'key': 'value'})
)

# 读取响应
payload = json.loads(response['Payload'].read())

# 创建函数
with open('function.zip', 'rb') as f:
    lambda_client.create_function(
        FunctionName='my-function',
        Runtime='python3.9',
        Role='arn:aws:iam::123456789012:role/lambda-role',
        Handler='index.handler',
        Code={'ZipFile': f.read()},
        Description='My Lambda function'
    )

# 更新函数代码
with open('function.zip', 'rb') as f:
    lambda_client.update_function_code(
        FunctionName='my-function',
        ZipFile=f.read()
    )
```

## 最佳实践

### 错误处理
```python
# Python示例
try:
    response = s3.get_object(Bucket='my-bucket', Key='my-key')
except s3.exceptions.NoSuchKey:
    print("对象不存在")
except s3.exceptions.NoSuchBucket:
    print("存储桶不存在")
except Exception as e:
    print(f"发生错误: {str(e)}")
```

```java
// Java示例
try {
    s3Client.getObject("my-bucket", "my-key");
} catch (AmazonS3Exception e) {
    if (e.getErrorCode().equals("NoSuchKey")) {
        System.out.println("对象不存在");
    } else if (e.getErrorCode().equals("NoSuchBucket")) {
        System.out.println("存储桶不存在");
    } else {
        System.out.println("发生错误: " + e.getMessage());
    }
}
```

### 重试策略
```python
# Python配置重试
import boto3
from botocore.config import Config

config = Config(
    retries = dict(
        max_attempts = 3,
        mode = 'standard'
    )
)

s3 = boto3.client('s3', config=config)
```

```java
// Java配置重试
ClientConfiguration config = new ClientConfiguration()
    .withMaxErrorRetry(3)
    .withRetryPolicy(PredefinedRetryPolicies.DEFAULT);

AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
    .withClientConfiguration(config)
    .build();
```

### 性能优化
```yaml
最佳实践:
  连接管理:
    - 复用客户端实例
    - 配置连接池
    - 设置超时时间
    - 使用异步操作
  
  数据处理:
    - 批量操作
    - 并发请求
    - 分页处理
    - 数据压缩
```

## 故障排除

### 常见问题
1. **认证错误**
   - 检查凭证配置
   - 验证IAM权限
   - 确认令牌有效性
   - 检查时钟同步

2. **连接问题**
   - 网络连接检查
   - 代理配置验证
   - 防火墙设置
   - VPC配置

3. **性能问题**
   - 客户端配置优化
   - 连接池设置
   - 重试策略调整
   - 资源限制检查

### 调试技巧
```python
# Python开启调试日志
import boto3
import logging

# 开启详细日志
logging.basicConfig(level=logging.DEBUG)
```

```java
// Java开启调试日志
System.setProperty("org.apache.commons.logging.Log", 
    "org.apache.commons.logging.impl.SimpleLog");
System.setProperty("org.apache.commons.logging.simplelog.log.org.apache.http", 
    "DEBUG");
```

### 监控和日志
```yaml
监控方案:
  基础监控:
    - API调用次数
    - 错误率统计
    - 延迟监控
    - 流量统计
  
  日志记录:
    - 请求日志
    - 错误日志
    - 性能指标
    - 审计日志
``` 