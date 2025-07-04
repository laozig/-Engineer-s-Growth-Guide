# 实战项目案例二：构建一个微服务电商平台

本项目是一个高度综合性的实战案例，旨在模拟一个真实的、生产级的电商平台。它将全面运用 Spring Cloud 生态系统，将之前学习的单体应用开发技能提升到分布式、微服务架构的层面。

---

## 1. 项目概述与架构设计

### 1.1. 核心业务域 (微服务划分)

我们将遵循 **领域驱动设计 (Domain-Driven Design, DDD)** 的原则，将复杂的电商业务划分为独立的、高内聚、低耦合的微服务：

-   **用户服务 (user-service)**: 负责用户注册、登录、个人信息管理、收货地址管理。
-   **商品服务 (product-service)**: 负责商品信息的管理（SPU/SKU）、分类、品牌、库存。
-   **购物车服务 (cart-service)**: 负责购物车的添加、删除、查看等操作。购物车数据通常存储在 Redis 中以提高性能。
-   **订单服务 (order-service)**: 核心服务，负责创建订单、管理订单状态、计算价格。
-   **支付服务 (payment-service)**: 与第三方支付平台（如支付宝、微信支付）集成，处理支付逻辑。
-   **搜索服务 (search-service)**: 提供商品搜索功能。通常使用 Elasticsearch 构建，通过消息队列与商品服务同步数据。
-   **后台管理服务 (admin-service)**: 为运营人员提供一个统一的后台管理界面，用于管理用户、商品、订单等。

### 1.2. 基础设施与技术组件

-   **API 网关 (API Gateway)**:
    -   **技术**: Spring Cloud Gateway
    -   **职责**: 作为系统唯一入口，处理路由、认证、限流、日志等。
-   **服务注册与发现 (Service Discovery)**:
    -   **技术**: Alibaba Nacos (或 Eureka)
    -   **职责**: 管理所有微服务的网络地址，实现服务的动态发现。
-   **配置中心 (Configuration Center)**:
    -   **技术**: Alibaba Nacos (或 Spring Cloud Config)
    -   **职责**: 集中管理所有微服务的配置。
-   **服务间通信**:
    -   **同步调用**: Spring Cloud OpenFeign (实现声明式的 RESTful 调用)
    -   **异步通信 (消息队列)**: RabbitMQ / RocketMQ / Kafka
        -   **场景**: 用户下单后异步扣减库存、订单支付成功后通知发货、商品信息变更后同步到搜索服务等。
-   **分布式事务**:
    -   **技术**: Seata
    -   **场景**: 解决跨多个微服务的数据一致性问题，例如"创建订单"操作需要同时调用订单服务、库存服务和用户积分服务。
-   **数据库**: MySQL (每个服务拥有自己独立的数据库) + Redis (缓存、购物车) + Elasticsearch (搜索)。
-   **容器化与编排**: Docker + Kubernetes。

### 1.3. 架构图

```mermaid
graph TD
    subgraph "客户端 (Browser/APP)"
        Client
    end

    subgraph "基础设施"
        Gateway[API 网关<br/>Spring Cloud Gateway]
        Nacos[服务注册与发现<br/>配置中心]
        MQ[消息队列<br/>RabbitMQ/Kafka]
        Seata[分布式事务]
    end

    subgraph "核心微服务"
        Auth[认证服务<br/>(集成在网关或独立)]
        UserService[用户服务<br/>MySQL, Redis]
        ProductService[商品服务<br/>MySQL]
        OrderService[订单服务<br/>MySQL]
        SearchService[搜索服务<br/>Elasticsearch]
        CartService[购物车服务<br/>Redis]
    end
    
    Client --> Gateway
    
    Gateway --> Auth
    Gateway --> UserService
    Gateway --> ProductService
    Gateway --> OrderService
    Gateway --> SearchService
    Gateway --> CartService

    UserService -- Feign --> ProductService
    OrderService -- Feign --> UserService
    OrderService -- Feign --> ProductService
    
    ProductService -- 异步消息 --> MQ
    OrderService -- 异步消息 --> MQ
    MQ --> SearchService

    Auth -.-> Nacos
    UserService -.-> Nacos
    ProductService -.-> Nacos
    OrderService -.-> Nacos
    SearchService -.-> Nacos
    CartService -.-> Nacos
    Gateway -.-> Nacos

    OrderService -- 分布式事务 --> Seata
    ProductService -- 分布式事务 --> Seata
```

---

## 2. 关键流程设计

### 2.1. 用户登录流程 (JWT)

1.  用户在客户端输入用户名密码，请求发送到 API 网关。
2.  网关将登录请求路由到 **用户服务**。
3.  用户服务验证凭证，成功后生成 JWT，返回给客户端。
4.  客户端存储 JWT。后续请求在 `Authorization` 头中携带 JWT 访问网关。
5.  网关配置安全过滤器，拦截所有请求，验证 JWT 的合法性。如果合法，解析出用户信息（用户ID、角色）并放入请求头，再将请求转发给下游微服务。下游服务可以直接从请求头中获取用户信息，无需再次验证。

### 2.2. 下单流程 (分布式事务)

1.  客户端发起创建订单请求，携带商品ID、数量等信息，请求到达 **订单服务**。
2.  订单服务开启一个 **Seata 全局事务**。
3.  **[分支事务1]** 订单服务通过 Feign 调用 **商品服务**，请求锁定并扣减库存。
4.  **[分支事务2]** 订单服务通过 Feign 调用 **用户服务**，请求扣减用户积分或优惠券。
5.  **[本地事务]** 订单服务在自己的数据库中创建订单记录，状态为"待支付"。
6.  如果所有分支事务都成功，Seata 提交全局事务。
7.  如果任何一个分支事务失败，Seata 会协调所有其他已成功的分支事务进行 **回滚**（例如，恢复库存、返还积分），保证数据最终一致性。

---

## 3. 开发挑战与学习重点

-   **分布式系统复杂性**: 理解服务治理、容错、负载均衡等核心概念。
-   **数据一致性**: 掌握分布式事务（最终一致性、TCC、SAGA、Seata）的原理和应用场景。
-   **服务间通信**: 熟练使用 Feign 和消息队列，并理解它们各自的适用场景。
-   **可观测性**: 如何实现日志聚合 (ELK/EFK Stack)、分布式追踪 (SkyWalking/Zipkin) 和监控告警 (Prometheus + Grafana)。
-   **DevOps**: 熟悉 CI/CD 流程，能够将微服务自动化地部署到 Kubernetes 集群。

这个项目是一个长期、复杂的工程，但完成它将使你对现代大型互联网应用的架构设计和实现有深刻的理解，是成为一名高级 Java 工程师或架构师的必经之路。
