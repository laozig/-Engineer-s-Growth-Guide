# 示例项目：简易Web服务器

这个示例将展示如何使用Go的`net/http`标准库来构建一个功能虽简单但完整的Web服务器。

## 功能
1.  **根路径 (`/`)**: 显示一条欢迎信息。
2.  **`/hello`路径**: 根据URL中的`name`参数，向用户问好。
3.  **`/headers`路径**: 显示客户端发送的所有HTTP请求头。
4.  **提供静态文件**: 从`/static/`目录提供CSS或JS文件。

## 项目结构
```
go-web-server/
├── main.go
└── static/
    └── style.css
```

## 代码实现

### `static/style.css`
```css
body {
    font-family: Arial, sans-serif;
    background-color: #f0f0f0;
    color: #333;
    padding: 2em;
}

h1 {
    color: #007BFF;
}
```

### `main.go`
```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// 欢迎处理器
func welcomeHandler(w http.ResponseWriter, r *http.Request) {
	// 如果不是根路径，返回404
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintln(w, "<h1>Welcome to the Simple Web Server!</h1>")
	fmt.Fprintln(w, "<p>Try visiting <a href='/hello?name=Guest'>/hello?name=Guest</a> or <a href='/headers'>/headers</a>.</p>")
}

// 问好处理器
func helloHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "World"
	}
	fmt.Fprintf(w, "<h1>Hello, %s!</h1>", name)
}

// 显示请求头处理器
func headersHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Request Headers:")
	for name, headers := range r.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

// 日志中间件
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("-> %s %s", r.Method, r.URL.Path)
		
		next.ServeHTTP(w, r)
		
		log.Printf("<- %s %s (%v)", r.Method, r.URL.Path, time.Since(start))
	})
}

func main() {
	mux := http.NewServeMux()

	// 注册处理器
	mux.HandleFunc("/", welcomeHandler)
	mux.HandleFunc("/hello", helloHandler)
	mux.HandleFunc("/headers", headersHandler)

	// 创建一个文件服务器来提供静态文件
	// http.StripPrefix会移除URL中的/static/前缀，然后在./static/目录中查找文件
	fs := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))
	
	// 应用日志中间件
	loggedMux := loggingMiddleware(mux)

	log.Println("Starting server on :8080")
	err := http.ListenAndServe(":8080", loggedMux)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
```

## 如何运行
1.  创建一个名为`go-web-server`的目录。
2.  在`go-web-server`下创建`static`子目录，并在其中放入`style.css`文件。
3.  在`go-web-server`下创建`main.go`文件并拷贝上面的代码。
4.  运行服务器:
    ```bash
    go run main.go
    ```
5.  在浏览器中访问:
    - `http://localhost:8080`
    - `http://localhost:8080/hello?name=Alice`
    - `http://localhost:8080/headers`
    - `http://localhost:8080/static/style.css` 