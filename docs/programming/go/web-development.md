# Go语言Web开发

Go语言因其高性能、简洁的并发模型和强大的标准库，成为构建Web服务和API的绝佳选择。其`net/http`标准库本身就足以构建生产级的Web应用，同时社区也提供了许多优秀的Web框架来简化开发。

## 1. 使用`net/http`标准库

`net/http`包提供了构建HTTP服务器和客户端所需的一切。

### 1.1 创建一个简单的Web服务器
```go
package main

import (
    "fmt"
    "log"
    "net/http"
)

// handler函数处理所有进入的请求
func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World! You've requested: %s\n", r.URL.Path)
}

func main() {
    // 将所有请求路由到handler函数
    http.HandleFunc("/", handler)

    // 启动服务器，监听8080端口
    log.Println("Listening on :8080...")
    err := http.ListenAndServe(":8080", nil)
    if err != nil {
        log.Fatal(err)
    }
}
```
- `http.ResponseWriter`: 一个接口，用于构建HTTP响应，如写入响应头和响应体。
- `http.Request`: 一个结构体，包含了客户端HTTP请求的所有信息，如URL、请求头、请求体等。
- `http.HandleFunc`: 注册一个处理器函数来处理特定路径的请求。
- `http.ListenAndServe`: 启动HTTP服务器并开始监听请求。

### 1.2 路由 (Routing)
使用`http.ServeMux`可以创建一个请求多路复用器，将不同的URL路径路由到不同的处理器。
```go
func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", homeHandler)
    mux.HandleFunc("/users", usersHandler)

    log.Println("Listening on :8080...")
    http.ListenAndServe(":8080", mux)
}
```

## 2. 处理HTTP请求

### 2.1 解析查询参数和表单
```go
func searchHandler(w http.ResponseWriter, r *http.Request) {
    // 解析查询参数: /search?q=golang
    query := r.URL.Query().Get("q")
    fmt.Fprintf(w, "Searching for: %s\n", query)

    // 解析POST表单
    if r.Method == http.MethodPost {
        r.ParseForm()
        username := r.FormValue("username")
        fmt.Fprintf(w, "Posted username: %s\n", username)
    }
}
```

### 2.2 处理JSON
现代Web服务通常使用JSON进行通信。
```go
type User struct {
    Name  string `json:"name"`
    Email string `json:"email"`
}

// 处理JSON请求体
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    var u User
    err := json.NewDecoder(r.Body).Decode(&u)
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }
    fmt.Fprintf(w, "User created: %+v", u)
}

// 返回JSON响应
func getUserHandler(w http.ResponseWriter, r *http.Request) {
    u := User{Name: "Alice", Email: "alice@example.com"}
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(u)
}
```

## 3. 模板渲染 (`html/template`)

对于需要服务端渲染HTML的场景，`html/template`包非常有用，并且它能自动处理HTML转义，防止XSS攻击。

```go
// templates/profile.html
<!DOCTYPE html>
<html>
<head>
    <title>User Profile</title>
</head>
<body>
    <h1>Hello, {{.Name}}!</h1>
    <p>Your email is: {{.Email}}</p>
</body>
</html>
```
```go
// main.go
var profileTmpl = template.Must(template.ParseFiles("templates/profile.html"))

func profileHandler(w http.ResponseWriter, r *http.Request) {
    user := User{Name: "Bob", Email: "bob@example.com"}
    profileTmpl.Execute(w, user)
}
```

## 4. 中间件 (Middleware)

中间件是一个函数，它包装了另一个HTTP处理器，用于在请求被实际处理前后执行一些通用逻辑，如日志记录、认证、压缩等。

```go
// 日志中间件
func loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        log.Printf("Started %s %s", r.Method, r.URL.Path)
        
        // 调用下一个处理器
        next.ServeHTTP(w, r)
        
        log.Printf("Completed in %v", time.Since(start))
    })
}

func main() {
    mux := http.NewServeMux()
    mux.HandleFunc("/", homeHandler)
    
    // 将中间件应用到处理器上
    loggedMux := loggingMiddleware(mux)
    
    http.ListenAndServe(":8080", loggedMux)
}
```

## 5. 流行的Web框架

虽然标准库很强大，但Web框架可以提供更简洁的路由、中间件管理、参数绑定和验证等功能，从而加速开发。

### 为什么使用框架？
- **简洁的API**: 更方便的路由、分组和中间件链。
- **自动化**: 自动将请求数据（JSON、表单等）绑定到Go结构体。
- **性能**: 许多流行框架（如Gin、Echo）都以高性能著称。

### Gin框架示例
[Gin](https://github.com/gin-gonic/gin)是一个非常流行的高性能Web框架。

```go
package main

import "github.com/gin-gonic/gin"

func main() {
    r := gin.Default() // Default()自带了Logger和Recovery中间件

    r.GET("/ping", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message": "pong",
        })
    })

    r.POST("/users", func(c *gin.Context) {
        var user User
        if err := c.ShouldBindJSON(&user); err != nil {
            c.JSON(400, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, gin.H{"status": "user created", "user": user})
    })

    r.Run(":8080") // 默认监听8080端口
}
```

## 6. 构建RESTful API的最佳实践

- **使用正确的HTTP方法**: GET（查询），POST（创建），PUT/PATCH（更新），DELETE（删除）。
- **使用HTTP状态码**: 明确返回`200 OK`, `201 Created`, `204 No Content`, `400 Bad Request`, `404 Not Found`, `500 Internal Server Error`等。
- **版本化API**: 在URL中加入版本号，如`/api/v1/users`。
- **结构化的JSON响应**: 定义统一的JSON响应格式，如包含`data`和`error`字段。
- **文档化**: 使用Swagger/OpenAPI等工具为你的API生成文档。 