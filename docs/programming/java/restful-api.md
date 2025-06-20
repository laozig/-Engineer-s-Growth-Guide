# 构建 RESTful API: Spring MVC, API 设计原则, 数据校验

**REST (Representational State Transfer)** 是一种软件架构风格，用于设计网络应用。它不是一个标准，而是一组架构约束。当一个 API 符合 REST 的约束时，我们称之为 **RESTful API**。在 Spring Boot 中，构建 RESTful API 的核心模块是 **Spring MVC**。

---

## 1. Spring MVC 核心概念

Spring MVC 是 Spring 框架中用于构建 Web 应用的模块。在 Spring Boot 中，通过 `spring-boot-starter-web` 依赖自动集成和配置。

-   **`@RestController`**: 如前所述，这是一个便利的注解，它组合了 `@Controller` 和 `@ResponseBody`。它告诉 Spring，这个控制器处理的请求将直接返回数据（如 JSON），而不是视图名。
-   **`@RequestMapping` 及其变体**: 这些注解用于将 Web 请求映射到控制器中的特定处理方法。
    -   `@RequestMapping("/path")`: 可以处理所有 HTTP 方法。
    -   `@GetMapping("/path")`: 只处理 GET 请求。
    -   `@PostMapping("/path")`: 只处理 POST 请求。
    -   `@PutMapping("/path/{id}")`: 只处理 PUT 请求。
    -   `@DeleteMapping("/path/{id}")`: 只处理 DELETE 请求。
    -   `@PatchMapping("/path/{id}")`: 只处理 PATCH 请求。
-   **请求参数绑定**: Spring MVC 可以自动将请求中的参数绑定到方法的参数上。
    -   `@PathVariable`: 从 URL 路径中提取变量。 (e.g., `/users/{id}`)
    -   `@RequestParam`: 从查询参数中提取值。 (e.g., `/users?name=john`)
    -   `@RequestBody`: 将 HTTP 请求的 body (通常是 JSON) 反序列化为 Java 对象。
    -   `@RequestHeader`: 从请求头中提取值。
-   **`ResponseEntity`**: 一个强大的类，允许你完全控制 HTTP 响应，包括状态码、响应头和响应体。

### 示例：一个完整的 `User` 资源的 CRUD API
```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService; // 注入业务逻辑服务

    // 创建用户 (POST /api/users)
    @PostMapping
    public ResponseEntity<User> createUser(@Valid @RequestBody UserDTO userDTO) {
        User createdUser = userService.createUser(userDTO);
        return new ResponseEntity<>(createdUser, HttpStatus.CREATED);
    }

    // 获取所有用户 (GET /api/users)
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.getAllUsers();
        return ResponseEntity.ok(users); // ok() 是 status(HttpStatus.OK).body() 的快捷方式
    }

    // 获取单个用户 (GET /api/users/{id})
    @GetMapping("/{id}")
    public ResponseEntity<User> getUserById(@PathVariable Long id) {
        return userService.getUserById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // 更新用户 (PUT /api/users/{id})
    @PutMapping("/{id}")
    public ResponseEntity<User> updateUser(@PathVariable Long id, @Valid @RequestBody UserDTO userDTO) {
        User updatedUser = userService.updateUser(id, userDTO);
        return ResponseEntity.ok(updatedUser);
    }

    // 删除用户 (DELETE /api/users/{id})
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build(); // 204 No Content
    }
}
```

---

## 2. RESTful API 设计原则

一个设计良好的 RESTful API 应该是直观、一致且易于使用的。

1.  **使用名词而不是动词**: URL 应该表示资源 (Resource)，而不是动作。
    -   **推荐**: `GET /api/users` (获取所有用户)
    -   **不推荐**: `GET /api/getAllUsers`
2.  **使用 HTTP 方法表达动作**: 利用 HTTP 动词 (GET, POST, PUT, DELETE, PATCH) 来表示对资源的操作。
    -   `GET`: 读取资源。
    -   `POST`: 创建新资源。
    -   `PUT`: **完整**替换、更新现有资源。
    -   `DELETE`: 删除资源。
    -   `PATCH`: **部分**更新现有资源。
3.  **使用复数名词**: 保持 API 端点的一致性，使用复数名词表示资源集合。
    -   **推荐**: `/users`, `/orders`, `/products`
    -   **不推荐**: `/user`, `/order`
4.  **版本化你的 API**: 当 API 发生不兼容的变更时，版本化可以防止破坏现有客户端。
    -   **URL 版本化**: `/api/v1/users`, `/api/v2/users` (最常见)
    -   **Header 版本化**: `Accept: application/vnd.company.v1+json`
5.  **使用合适的 HTTP 状态码**: 准确地返回操作结果的状态。
    -   **2xx (成功)**: `200 OK`, `201 Created`, `204 No Content`
    -   **3xx (重定向)**: `301 Moved Permanently`
    -   **4xx (客户端错误)**: `400 Bad Request`, `401 Unauthorized`, `403 Forbidden`, `404 Not Found`
    -   **5xx (服务端错误)**: `500 Internal Server Error`, `503 Service Unavailable`
6.  **提供清晰的错误信息**: 当发生错误时，返回一个有意义的 JSON 错误体。
    ```json
    {
      "timestamp": "2023-10-27T10:30:00Z",
      "status": 400,
      "error": "Bad Request",
      "message": "Validation failed for object 'userDTO'. Error count: 1",
      "errors": [
        {
          "field": "email",
          "defaultMessage": "must be a well-formed email address"
        }
      ],
      "path": "/api/users"
    }
    ```
    可以通过自定义 `@ControllerAdvice` 和 `ExceptionHandler` 来实现统一的异常处理。
7.  **支持过滤、排序和分页**: 对于集合资源，提供查询参数来处理大量数据。
    -   **过滤**: `GET /users?status=active`
    -   **排序**: `GET /users?sort=name,asc`
    -   **分页**: `GET /users?page=1&size=20`

---

## 3. 数据校验 (Validation)

在将数据存入数据库之前，校验其有效性是至关重要的。Spring Boot 通过集成 **Bean Validation** (JSR-380/JSR-303 规范，实现为 Hibernate Validator) 来简化这一过程。

1.  **添加依赖**: `spring-boot-starter-validation` (通常由 `spring-boot-starter-web` 传递引入)。
2.  **在 DTO/Model 上添加注解**: 在用于接收输入的类（通常是 DTO，Data Transfer Object）的字段上添加校验注解。
    ```java
    public class UserDTO {
        @NotBlank(message = "Name cannot be blank")
        @Size(min = 2, max = 30)
        private String name;

        @NotBlank(message = "Email cannot be blank")
        @Email(message = "Must be a well-formed email address")
        private String email;

        @NotNull(message = "Age cannot be null")
        @Min(value = 18, message = "User must be at least 18 years old")
        private Integer age;
    }
    ```
    **常用注解**:
    -   `@NotNull`: 不能为 null。
    -   `@NotEmpty`: 不能为 null 且长度大于 0 (用于集合或字符串)。
    -   `@NotBlank`: 不能为 null 且去除首尾空格后长度大于 0 (仅用于字符串)。
    -   `@Size`, `@Min`, `@Max`, `@Pattern` (正则表达式), `@Email`, 等。
3.  **在 Controller 中启用校验**: 在 `@RequestBody` 标注的参数前添加 `@Valid` 注解。
    ```java
    @PostMapping
    public ResponseEntity<?> createUser(@Valid @RequestBody UserDTO userDTO) {
        // ...
    }
    ```
    如果校验失败，Spring Boot 默认会抛出 `MethodArgumentNotValidException` 异常，这会导致一个 400 Bad Request 响应。你可以通过 `@ControllerAdvice` 捕获这个异常，并自定义返回的错误信息格式，如上文"清晰的错误信息"示例所示。
