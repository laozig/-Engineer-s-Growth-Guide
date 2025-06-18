# Go示例项目：构建一个微服务

本文将通过一个完整的示例，展示如何使用Go语言和流行的库（如Gin和gRPC）来构建一个真实的微服务。这个示例将包括服务间通信、配置管理和基本的HTTP/gRPC服务。

## 1. 项目概述

我们将构建一个用户服务（`UserService`），它负责管理用户信息。该服务将暴露两个端点：
- 一个 **HTTP/JSON API**，用于外部客户端（如Web前端）调用。
- 一个 **gRPC API**，用于内部服务间的高效通信。

### 技术栈
- **HTTP框架**: [Gin](https://github.com/gin-gonic/gin)
- **gRPC框架**: [gRPC-Go](https://github.com/grpc/grpc-go)
- **配置文件**: Viper
- **日志**: Logrus
- **项目布局**: 标准Go项目布局

## 2. 项目结构

一个结构良好的项目目录是微服务可维护性的关键。

```
/user-service
|-- /api
|   |-- /grpc
|   |   |-- user.proto      # gRPC接口定义
|   |   `-- user_grpc.pb.go # gRPC生成代码
|   `-- /http
|       `-- handler.go      # Gin HTTP处理器
|-- /cmd
|   `-- /server
|       `-- main.go         # 程序入口
|-- /internal
|   |-- config
|   |   `-- config.go       # 配置加载
|   |-- service
|   |   `-- user.go         # 业务逻辑
|   `-- storage
|       `-- memory.go       # 内存数据存储
|-- go.mod
|-- go.sum
`-- config.yaml             # 配置文件
```

## 3. 定义API (gRPC)

我们首先使用Protocol Buffers (`.proto`文件)来定义我们的用户服务接口。

`api/grpc/user.proto`:
```protobuf
syntax = "proto3";

package user;

option go_package = "user-service/api/grpc";

// UserService定义
service UserService {
  // GetUser根据ID获取用户信息
  rpc GetUser(GetUserRequest) returns (GetUserResponse);
}

// User模型
message User {
  string id = 1;
  string name = 2;
  string email = 3;
}

// GetUser请求
message GetUserRequest {
  string id = 1;
}

// GetUser响应
message GetUserResponse {
  User user = 1;
}
```

### 生成Go代码
使用`protoc`工具从`.proto`文件生成Go代码：
```bash
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    api/grpc/user.proto
```
这将在`api/grpc/`目录下生成`user.pb.go`和`user_grpc.pb.go`。

## 4. 实现业务逻辑

业务逻辑与具体的API（HTTP或gRPC）实现分离，这有助于保持代码整洁。

`internal/service/user.go`:
```go
package service

import (
	"context"
	"fmt"
	pb "user-service/api/grpc" // 导入生成的gRPC代码
	"user-service/internal/storage"
)

// UserService实现了gRPC生成的UserServiceServer接口
type UserService struct {
	pb.UnimplementedUserServiceServer // 用于向前兼容
	storage *storage.UserStorage
}

func NewUserService(storage *storage.UserStorage) *UserService {
	return &UserService{storage: storage}
}

// GetUser是gRPC方法的具体实现
func (s *UserService) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	user, err := s.storage.Get(req.Id)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return &pb.GetUserResponse{
		User: &pb.User{
			Id:    user.ID,
			Name:  user.Name,
			Email: user.Email,
		},
	}, nil
}
```

`internal/storage/memory.go` (数据存储):
```go
package storage

import "fmt"

type User struct {
	ID    string
	Name  string
	Email string
}

// UserStorage用于模拟数据库
type UserStorage struct {
	users map[string]User
}

func NewUserStorage() *UserStorage {
	return &UserStorage{
		users: map[string]User{
			"1": {ID: "1", Name: "Alice", Email: "alice@example.com"},
			"2": {ID: "2", Name: "Bob", Email: "bob@example.com"},
		},
	}
}

func (s *UserStorage) Get(id string) (User, error) {
	user, ok := s.users[id]
	if !ok {
		return User{}, fmt.Errorf("user with id %s not found", id)
	}
	return user, nil
}
```

## 5. 实现API端点

### gRPC服务器
在`main.go`中设置gRPC服务器。

`cmd/server/main.go` (部分):
```go
// ...
lis, err := net.Listen("tcp", ":50051") // gRPC监听端口
if err != nil {
    log.Fatalf("failed to listen: %v", err)
}

s := grpc.NewServer()
pb.RegisterUserServiceServer(s, userService) // 注册服务

log.Println("gRPC server listening at", lis.Addr())
go func() {
    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve gRPC: %v", err)
    }
}()
// ...
```

### HTTP服务器 (Gin)
HTTP处理器将调用我们的业务逻辑服务。

`api/http/handler.go`:
```go
package http

import (
	"net/http"
	"user-service/internal/service"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	service *service.UserService
}

func NewUserHandler(service *service.UserService) *UserHandler {
	return &UserHandler{service: service}
}

func (h *UserHandler) GetUser(c *gin.Context) {
	id := c.Param("id")
	
    // 在这里，HTTP处理器可以直接调用业务逻辑
    // 或者通过gRPC客户端调用（在更复杂的架构中）
    // 为简单起见，我们直接调用service
	
    // 模拟gRPC请求
    gRPCReq := &pb.GetUserRequest{Id: id}
    userResp, err := h.service.GetUser(c.Request.Context(), gRPCReq)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, userResp.User)
}
```

## 6. 组装服务 (`main.go`)

现在，我们将所有部分在`main.go`中组装起来。

`cmd/server/main.go`:
```go
package main

import (
	"log"
	"net"

	"github.com/gin-gonic/gin"
	"google.golang.org/grpc"

	pb "user-service/api/grpc"
	"user-service/api/http"
	"user-service/internal/service"
	"user-service/internal/storage"
)

func main() {
	// 1. 初始化依赖
	userStorage := storage.NewUserStorage()
	userService := service.NewUserService(userStorage)
	userHandler := http.NewUserHandler(userService)

	// 2. 启动gRPC服务器
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterUserServiceServer(grpcServer, userService)

	log.Println("gRPC server listening at", lis.Addr())
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("failed to serve gRPC: %v", err)
		}
	}()

	// 3. 启动HTTP服务器
	router := gin.Default()
	router.GET("/users/:id", userHandler.GetUser)

	log.Println("HTTP server listening at :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("failed to serve HTTP: %v", err)
	}
}
```

## 7. 运行和测试

1.  **安装依赖**: `go mod tidy`
2.  **运行服务**: `go run cmd/server/main.go`
3.  **测试HTTP端点**:
    ```bash
    curl http://localhost:8080/users/1
    # {"id":"1","name":"Alice","email":"alice@example.com"}
    ```
4.  **测试gRPC端点** (使用`grpcurl`):
    ```bash
    grpcurl -plaintext -d '{"id": "2"}' localhost:50051 user.UserService/GetUser
    # {
    #   "user": {
    #     "id": "2",
    #     "name": "Bob",
    #     "email": "bob@example.com"
    #   }
    # }
    ```

## 结论

这个示例展示了如何构建一个包含HTTP和gRPC接口的简单微服务。在真实世界的应用中，你还需要考虑：
- **配置管理**: 使用Viper等库从文件或环境变量加载配置。
- **数据库集成**: 替换内存存储为真实的数据库（如PostgreSQL）。
- **可观测性**: 添加结构化日志、指标（Prometheus）和分布式追踪（Jaeger）。
- **错误处理**: 建立更健壮的错误处理和返回机制。
- **服务发现**: 使用Consul或Etcd进行服务注册和发现。
- **安全性**: 添加认证和授权（如JWT、OAuth2）。 