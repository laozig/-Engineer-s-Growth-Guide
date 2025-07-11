# AWS EKS (Elastic Kubernetes Service)

AWS EKS（Elastic Kubernetes Service）是一项托管的Kubernetes服务，使您能够在AWS上轻松运行Kubernetes而无需安装、操作和维护自己的Kubernetes控制平面。

## 目录
- [概述](#概述)
- [核心概念与组件](#核心概念与组件)
- [EKS架构](#eks架构)
- [部署EKS集群](#部署eks集群)
- [节点管理](#节点管理)
- [工作负载部署](#工作负载部署)
- [网络](#网络)
- [存储](#存储)
- [安全性](#安全性)
- [监控与日志](#监控与日志)
- [扩展性](#扩展性)
- [集成与插件](#集成与插件)
- [成本优化](#成本优化)
- [最佳实践](#最佳实践)
- [常见问题排查](#常见问题排查)
- [实际应用案例](#实际应用案例)

## 概述

Amazon Elastic Kubernetes Service (EKS) 是一项完全托管的 Kubernetes 服务，具有以下关键特点：

- **托管控制平面**：AWS负责管理、维护和升级Kubernetes控制平面，确保高可用性
- **多区域部署**：支持在多个可用区部署工作节点，提高应用程序的可用性
- **AWS集成**：无缝集成其他AWS服务，如弹性负载均衡器、IAM、VPC等
- **符合标准**：完全兼容上游Kubernetes，支持标准的Kubernetes工具和API

## 核心概念与组件

### EKS控制平面
- **API服务器**：处理Kubernetes API请求的入口点
- **etcd**：分布式键值存储，保存集群所有状态数据
- **控制器管理器**：运行核心控制循环，确保集群状态符合期望
- **调度器**：决定在哪些节点上运行新创建的Pod

### 节点类型
- **托管节点组**：AWS管理的EC2实例组，自动化节点配置和生命周期
- **自行管理的节点**：用户完全控制的EC2实例，提供更高的灵活性
- **Fargate配置文件**：无服务器计算选项，无需管理底层节点

### 其他关键组件
- **集群**：一组运行Kubernetes软件的EC2计算实例
- **VPC CNI**：集成AWS VPC的容器网络接口插件
- **IAM认证器**：使用AWS IAM进行Kubernetes认证

## EKS架构

EKS采用分离式架构，将Kubernetes控制平面与工作节点分开：

```
┌─────────────────────────┐     ┌─────────────────────────┐
│   EKS控制平面(AWS管理)   │     │      工作节点(客户管理)     │
│                         │     │                         │
│  ┌───────┐ ┌─────────┐  │     │  ┌─────┐ ┌─────┐ ┌─────┐│
│  │API服务器│ │  etcd   │  │     │  │节点1 │ │节点2 │ │节点N ││
│  └───────┘ └─────────┘  │     │  └─────┘ └─────┘ └─────┘│
│                         │     │                         │
│  ┌───────┐ ┌─────────┐  │     │  ┌─────────────────────┐│
│  │控制器  │ │ 调度器   │  │     │  │      工作负载       ││
│  └───────┘ └─────────┘  │     │  └─────────────────────┘│
└─────────────────────────┘     └─────────────────────────┘
```

- **控制平面**：跨多个可用区部署，由AWS管理
- **数据平面**：由用户管理的工作节点，运行实际应用程序

## 部署EKS集群

### 先决条件
- AWS账户和适当的IAM权限
- 已配置的VPC和子网
- AWS CLI、eksctl和kubectl工具

### 使用eksctl创建集群

```bash
eksctl create cluster \
  --name my-eks-cluster \
  --region ap-northeast-1 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 5 \
  --managed
```

### 使用AWS控制台创建集群
1. 访问EKS控制台
2. 选择"创建集群"
3. 配置集群名称、Kubernetes版本和网络设置
4. 配置日志记录和访问管理
5. 创建集群后，添加节点组或Fargate配置文件

### 配置kubectl访问

```bash
aws eks update-kubeconfig --name my-eks-cluster --region ap-northeast-1
```

## 节点管理

### 托管节点组
托管节点组自动处理EC2实例的预置和生命周期管理：

```bash
eksctl create nodegroup \
  --cluster my-eks-cluster \
  --region ap-northeast-1 \
  --name managed-nodes \
  --node-type t3.medium \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 5 \
  --managed
```

### 自行管理的节点
为有特定自定义需求的用户提供更多控制权：

```bash
eksctl create nodegroup \
  --cluster my-eks-cluster \
  --region ap-northeast-1 \
  --name self-managed-nodes \
  --node-type t3.medium \
  --nodes 3 \
  --node-private-networking \
  --ssh-access \
  --ssh-public-key my-key
```

### Fargate配置文件
无需管理EC2实例的无服务器计算选项：

```bash
eksctl create fargateprofile \
  --cluster my-eks-cluster \
  --name my-fargate-profile \
  --namespace default
```

## 工作负载部署

### 部署示例应用程序

```yaml
# nginx-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.21
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx-service
spec:
  selector:
    app: nginx
  ports:
    - port: 80
      targetPort: 80
  type: LoadBalancer
```

使用kubectl应用配置：

```bash
kubectl apply -f nginx-deployment.yaml
```

### Helm部署
使用Helm图表管理复杂应用：

```bash
# 添加Helm仓库
helm repo add bitnami https://charts.bitnami.com/bitnami

# 部署WordPress
helm install my-wordpress bitnami/wordpress
```

## 网络

### VPC CNI
EKS默认使用AWS VPC CNI插件，为Pod分配VPC IP地址：
- 每个Pod获取VPC中的IP地址
- 与AWS网络功能无缝集成
- 支持安全组和网络策略

### 配置服务和入口控制器

1. **ClusterIP服务**：集群内部访问
2. **NodePort服务**：通过节点端口访问
3. **LoadBalancer服务**：自动创建AWS ELB
4. **AWS Load Balancer Controller**：高级入口控制器

```yaml
# ALB入口示例
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ingress-demo
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
spec:
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: nginx-service
                port:
                  number: 80
```

## 存储

### 存储选项

1. **EBS CSI驱动程序**：持久卷使用Amazon EBS

```yaml
# 创建持久卷声明
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ebs-claim
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: gp2
  resources:
    requests:
      storage: 10Gi
```

2. **EFS CSI驱动程序**：多读多写文件系统

```yaml
# 使用EFS的持久卷
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: efs-claim
spec:
  accessModes:
    - ReadWriteMany
  storageClassName: efs-sc
  resources:
    requests:
      storage: 5Gi
```

3. **FSx for Lustre**：高性能文件系统

## 安全性

### 身份和访问管理

1. **AWS IAM与Kubernetes RBAC集成**

```yaml
# IAM角色映射到Kubernetes用户
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
data:
  mapRoles: |
    - rolearn: arn:aws:iam::ACCOUNT_ID:role/EKS-AdminRole
      username: admin
      groups:
        - system:masters
```

2. **服务账户的IAM角色**：
```bash
eksctl create iamserviceaccount \
  --name s3-reader \
  --namespace default \
  --cluster my-eks-cluster \
  --attach-policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \
  --approve
```

### 网络安全

1. **安全组配置**
2. **网络策略**
3. **私有集群设置**

### 数据保护

1. **Secret加密**：使用KMS保护Kubernetes Secrets
2. **Pod安全策略**：限制Pod的权限和能力

## 监控与日志

### CloudWatch Container Insights

设置CloudWatch Container Insights监控集群性能：

```bash
# 应用Container Insights
curl https://raw.githubusercontent.com/aws-samples/amazon-cloudwatch-container-insights/master/k8s-deployment-manifest-templates/deployment-mode/daemonset/container-insights-monitoring/quickstart/cwagent-fluentd-quickstart.yaml | \
sed "s/{{cluster_name}}/my-eks-cluster/;s/{{region_name}}/ap-northeast-1/" | \
kubectl apply -f -
```

### Prometheus和Grafana

使用Helm部署Prometheus和Grafana：

```bash
# 添加Prometheus Helm仓库
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts

# 安装Prometheus
helm install prometheus prometheus-community/prometheus

# 安装Grafana
helm repo add grafana https://grafana.github.io/helm-charts
helm install grafana grafana/grafana
```

## 扩展性

### 水平Pod自动缩放

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: nginx-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: nginx-deployment
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### 集群自动扩缩器

```bash
# 安装集群自动扩缩器
helm repo add autoscaler https://kubernetes.github.io/autoscaler
helm install cluster-autoscaler autoscaler/cluster-autoscaler \
  --set autoDiscovery.clusterName=my-eks-cluster \
  --set awsRegion=ap-northeast-1
```

## 集成与插件

### AWS服务集成
- **AWS Load Balancer Controller**：管理ALB/NLB
- **Container Insights**：提供监控数据
- **App Mesh**：服务网格集成
- **ACK (AWS Controllers for Kubernetes)**：管理AWS资源

### 常用插件
- **CoreDNS**：DNS服务
- **kube-proxy**：网络代理
- **Amazon VPC CNI**：网络接口
- **CloudWatch**：日志和监控

## 成本优化

### 优化策略
1. **正确选择实例类型**：根据工作负载需求选择适当的实例
2. **使用Spot实例**：对非关键工作负载使用Spot实例节省成本
3. **Fargate按需计费**：无需管理节点，按实际使用付费
4. **自动扩缩容**：根据需求自动调整资源
5. **优化存储使用**：选择适当的存储类型和大小

### 成本监控工具
- **AWS Cost Explorer**
- **Kubecost**
- **CloudWatch Container Insights**

## 最佳实践

1. **使用多可用区部署**：提高可用性
2. **合理配置自动扩缩容**：节约成本同时满足需求
3. **采用基础设施即代码**：使用eksctl或CloudFormation管理EKS
4. **正确设置IAM权限**：遵循最小权限原则
5. **备份关键数据**：使用Velero等工具备份Kubernetes资源
6. **保持版本更新**：定期更新EKS版本以获取新功能和安全补丁
7. **设置资源限制和请求**：避免资源耗尽
8. **实施监控和告警**：及时发现并解决问题

## 常见问题排查

### 连接问题
- 检查安全组配置
- 验证VPC和子网设置
- 确认IAM权限正确

### Pod无法启动
- 检查节点资源
- 查看Pod事件和日志
- 验证镜像可用性

### 网络问题
- 检查CNI插件状态
- 验证网络策略配置
- 检查CoreDNS功能

### 调试命令示例

```bash
# 查看Pod状态
kubectl get pods -A

# 描述Pod详情
kubectl describe pod <pod-name>

# 查看Pod日志
kubectl logs <pod-name>

# 检查节点状态
kubectl get nodes -o wide

# 执行Shell进入容器
kubectl exec -it <pod-name> -- /bin/bash
```

## 实际应用案例

### 微服务架构部署
部署包含多个微服务的电商应用：
- 前端服务：使用Ingress控制器和ALB
- 后端服务：无状态API服务
- 数据服务：有状态服务，使用持久卷
- 消息队列：使用Amazon MQ或自托管消息队列

### CI/CD管道集成
结合AWS CodePipeline和EKS实现持续部署：
1. 代码提交到CodeCommit/GitHub
2. CodeBuild构建容器镜像
3. 推送镜像到ECR
4. 使用ArgoCD/Flux部署到EKS
5. 自动测试和验证

### 大数据处理
利用EKS进行大规模数据处理：
- 使用Spark on Kubernetes
- 动态扩展计算资源
- 集成S3存储
- 使用Spot实例降低成本

### 机器学习工作负载
在EKS上运行分布式机器学习任务：
- 使用Kubeflow平台
- GPU节点支持
- 模型训练和推理服务部署
- 与SageMaker集成
