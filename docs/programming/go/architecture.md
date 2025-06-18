# Go语言代码组织与架构

随着项目规模的增长，良好的代码组织和清晰的架构变得至关重要。它能确保项目的可维护性、可扩展性和团队协作的效率。本章将介绍Go社区中一些行之有效的项目布局和架构模式。

## 1. 包的设计原则 (Package Design)

在Go中，包（`package`）是组织代码的基本单元。

- **单一职责**: 一个包应该只做一件事，并把它做好。例如，`http`包处理HTTP通信，`json`包处理JSON序列化。
- **高内聚，低耦合**: 包内的功能应该紧密相关（高内聚），而包与包之间的依赖应该尽可能少（低耦合）。
- **清晰的包名**: 包名应该是简短、清晰、有意义的小写单词，避免使用下划线或混合大小写。例如，使用`net/http`而不是`net/my_http_client`。
- **明确的API**: 只有需要被外部包使用的函数、类型和变量才应该大写导出。内部实现应保持私有（小写）。
- **避免循环依赖**: 如果包A导入了包B，那么包B就不能再导入包A，否则会导致编译错误。合理的依赖关系应该是一个有向无环图（DAG）。

## 2. 常见的项目布局

没有一个"万能"的项目布局，应根据项目规模和复杂性选择合适的模式。

### 2.1 扁平结构 (Flat Structure)
对于非常小的项目或库，可以将所有`.go`文件放在根目录下。
```
my-project/
├── go.mod
├── main.go
├── lib.go
└── lib_test.go
```

### 2.2 标准项目布局 (Standard Go Project Layout)
这是一个在社区中被广泛采用的、更具扩展性的布局。
[参考链接: golang-standards/project-layout](https://github.com/golang-standards/project-layout)

```
my-project/
├── go.mod
├── cmd/                # 项目的可执行文件入口
│   └── my-app/
│       └── main.go
├── pkg/                # 可以被外部应用使用的公共库代码
│   └── my-public-lib/
├── internal/           # 项目内部私有的代码，外部无法导入
│   ├── app/            # 应用程序的核心逻辑
│   │   └── my-app/
│   ├── domain/         # 业务领域模型
│   └── platform/       # 平台相关的实现 (如数据库、缓存)
├── api/                # API定义文件 (如.proto, OpenAPI/Swagger)
├── configs/            # 配置文件
├── scripts/            # 用于构建、安装、分析等的脚本
└── web/                # Web前端资源
```

- **/cmd**: 包含项目的主程序入口。每个子目录都是一个可执行文件。
- **/pkg**: 放置可以被外部项目安全导入的公共代码。
- **/internal**: 核心业务逻辑。这里的代码只能被项目内部（`my-project/`下）的其他代码导入，编译器会强制执行这个规则。这是Go 1.4之后引入的特性，非常适合用来隐藏不应暴露的实现细节。

## 3. 分层架构 (Layered Architecture)

分层是一种将软件关注点分离的经典架构模式。一个典型的分层架构可能如下：

1.  **领域层 (Domain Layer)**:
    - 包含核心的业务逻辑和业务实体（Models/Entities）。
    - 这一层不依赖任何其他层，是整个应用的核心。
    - 存放于 `internal/domain`。

2.  **应用层 (Application Layer)**:
    - 编排领域层的对象来执行具体的业务用例（Use Cases）。
    - 定义了应用的业务流程。
    - 存放于 `internal/app` 或 `internal/service`。

3.  **接口层 (Interface/Adapter Layer)**:
    - 适配外部世界与应用层。
    - 包括HTTP处理器（Handlers）、RPC服务器、CLI命令等。
    - 存放于 `internal/transport` 或 `internal/handler`。

4.  **基础设施层 (Infrastructure Layer)**:
    - 提供与外部系统交互的具体实现，如数据库访问、消息队列、第三方API客户端等。
    - 这一层实现了应用层或领域层定义的接口。
    - 存放于 `internal/platform` 或 `internal/repository`。

**依赖规则**: 外层可以依赖内层，但内层永远不能依赖外层。所有依赖都指向核心的领域层。

## 4. 依赖注入 (Dependency Injection)

为了实现层与层之间的解耦，我们通常使用依赖注入（DI）。核心思想是：一个组件不应该自己创建它所依赖的组件，而应该由外部提供（注入）。

在Go中，通常通过**接口**和**构造函数**来实现DI。

```go
// domain/user.go
package domain

type UserRepository interface {
    GetUser(id int) (*User, error)
}

// app/user_service.go
package app

import "my-project/internal/domain"

type UserService struct {
    repo domain.UserRepository
}

// NewUserService是构造函数，用于注入依赖
func NewUserService(repo domain.UserRepository) *UserService {
    return &UserService{repo: repo}
}

func (s *UserService) GetUser(id int) (*domain.User, error) {
    return s.repo.GetUser(id)
}
```
在`main.go`中组装应用：
```go
// cmd/my-app/main.go
func main() {
    // 1. 创建基础设施层的实例
    dbRepo := platform.NewPostgresUserRepository(...)
    
    // 2. 注入到应用层
    userService := app.NewUserService(dbRepo)
    
    // 3. 注入到接口层
    httpHandler := transport.NewUserHandler(userService)
    
    // 4. 启动服务器
    http.ListenAndServe(":8080", httpHandler)
}
```

## 5. Clean Architecture & DDD

- **整洁架构 (Clean Architecture)**: 一种强调关注点分离和依赖规则的架构思想，与上述的分层架构非常相似。其核心思想是，软件应该围绕独立的业务领域模型构建，而不是围绕框架或工具。

- **领域驱动设计 (Domain-Driven Design, DDD)**: 一种软件开发方法论，强调与领域专家的紧密合作，以业务领域为核心来构建软件模型。DDD中的概念，如实体（Entity）、值对象（Value Object）、聚合（Aggregate）、仓储（Repository）、服务（Service）等，可以很好地融入Go的分层架构中。 