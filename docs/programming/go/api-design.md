# Go API设计指南

无论你是在设计一个供团队内部使用的Go包，还是在构建一个供全球用户访问的Web API，良好的API设计都是至关重要的。一个设计良好的API应该是易于理解、难以误用、并且具备良好扩展性的。

## 1. Go包的API设计

这是指你导出的函数、类型和变量，它们构成了你的包的公共接口。

### 1.1 简洁与清晰
- **最小化API表面**: 只导出绝对必要的部分。如果一个函数或类型只在包内部使用，应保持其为私有（首字母小写）。
- **有意义的命名**: 函数名和类型名应该清晰地描述其用途和行为。例如，`http.ListenAndServe`比`http.StartServer`更具体。
- **避免过多的参数**: 如果一个函数需要很多参数，可以考虑将它们组织到一个配置结构体中。

### 1.2 一致性
- 遵循Go社区的惯例。例如，接受`context.Context`作为第一个参数，将`error`作为最后一个返回值。
- 在你的包内保持一致的命名和行为模式。

### 1.3 可靠性
- **返回错误，而不是`panic`**: 在公共API中，`panic`应该只用于表示不可恢复的、灾难性的错误。对于可预期的错误（如"文件未找到"），应返回一个`error`值。
- **零值可用 (Zero Value Usability)**: 如果可能，让你的结构体在零值状态下（即未初始化的状态）就是可用的。例如，`sync.Mutex`的零值就是一个未锁定的互斥锁。

### 1.4 良好的文档
- 为所有导出的标识符编写清晰的godoc注释。
- 提供可直接运行的示例代码（`Example`函数），这是最好的文档形式之一。

## 2. RESTful API 设计

REST (Representational State Transfer) 是一种流行的Web API架构风格。

### 2.1 面向资源
- **URL应该代表资源**: 例如，`/users`代表用户集合，`/users/123`代表ID为123的特定用户。
- **使用名词而非动词**: `/getUsers` (错误) vs `/users` (正确)。

### 2.2 正确使用HTTP方法
- **GET**: 获取资源（幂等）。
- **POST**: 创建新资源（非幂等）。
- **PUT**: 替换整个资源（幂等）。
- **PATCH**: 部分更新资源（非幂等）。
- **DELETE**: 删除资源（幂等）。

### 2.3 使用HTTP状态码
- **2xx (成功)**: `200 OK`, `201 Created`, `204 No Content`。
- **4xx (客户端错误)**: `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`。
- **5xx (服务器错误)**: `500 Internal Server Error`, `502 Bad Gateway`。

### 2.4 版本化
在API发生不兼容的变更时，版本化是必须的。最常见的方式是在URL中加入版本号。
- `https://api.example.com/v1/users`
- `https://api.example.com/v2/users`

### 2.5 结构化的响应
- **JSON是事实标准**: 使用JSON作为数据交换格式。
- **统一的错误响应格式**:
  ```json
  {
      "error": {
          "code": "INVALID_ARGUMENT",
          "message": "The 'email' field is not a valid email address."
      }
  }
  ```
- **数据包装 (Envelope)**:
  ```json
  {
      "data": [
          {"id": 1, "name": "Alice"},
          {"id": 2, "name": "Bob"}
      ],
      "pagination": {
          "total": 100,
          "limit": 10,
          "offset": 0
      }
  }
  ```

## 3. gRPC API 设计

gRPC专注于高性能的RPC通信。其API设计在`.proto`文件中定义。

- **面向服务和方法**: 与REST的面向资源不同，gRPC更关注服务及其提供的方法。
- **强类型**: Protocol Buffers是强类型的，提供了比JSON更严格的数据契约。
- **使用标准消息类型**: Google为常见类型（如时间戳、时长、包装器类型）提供了标准proto定义，应优先使用它们。
- **错误处理**: gRPC有自己的一套标准错误码，比HTTP状态码更丰富，能更精确地描述错误原因。通过`status`包来创建和解析gRPC错误。

## 4. API 安全性

### 4.1 认证 (Authentication) - "你是谁？"
- **API密钥 (API Keys)**: 简单，适用于服务器到服务器的通信。
- **JWT (JSON Web Tokens)**: 适用于Web和移动应用，可以在令牌中携带用户信息，实现无状态认证。
- **OAuth 2.0**: 一个授权框架，允许第三方应用在用户授权下访问其在某个服务上的资源。

### 4.2 授权 (Authorization) - "你能做什么？"
- **RBAC (Role-Based Access Control)**: 基于角色的访问控制。用户被分配到角色（如`admin`, `viewer`），权限被授予给角色。
- **ABAC (Attribute-Based Access Control)**: 基于属性的访问控制。访问决策基于用户、资源和环境的属性，更灵活但更复杂。

### 4.3 其他安全措施
- **输入验证**: 永远不要相信用户的输入。对所有输入数据（URL参数、请求体、请求头）进行严格的验证。
- **速率限制 (Rate Limiting)**: 防止API被滥用或遭受DDoS攻击。
- **使用HTTPS**: 始终使用TLS来加密API通信，防止中间人攻击。 