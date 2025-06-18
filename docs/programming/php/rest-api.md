# 使用PHP构建REST API

REST (Representational State Transfer) 是一种用于构建Web服务的架构风格。一个RESTful API通过标准的HTTP方法操作"资源"。本指南将介绍如何使用纯PHP构建一个简单的REST API。

## REST API 核心概念

-   **资源 (Resource)**: API中可以操作的任何实体，例如用户、文章、产品等。每个资源都有一个唯一的标识符（URI），例如 `/api/posts/1`。
-   **HTTP动词 (Verbs)**: 我们使用不同的HTTP方法来对资源执行不同的操作。
    -   `GET`: 读取资源。
    -   `POST`: 创建新资源。
    -   `PUT` / `PATCH`: 更新现有资源。
    -   `DELETE`: 删除资源。
-   **HTTP状态码 (Status Codes)**: 服务器使用状态码来告知客户端请求的结果。
    -   `200 OK`: 请求成功。
    -   `201 Created`: 资源创建成功。
    -   `204 No Content`: 请求成功，但没有内容返回（例如，DELETE成功后）。
    -   `400 Bad Request`: 客户端请求有误。
    -   `401 Unauthorized`: 未经授权。
    -   `403 Forbidden`: 禁止访问。
    -   `404 Not Found`: 请求的资源不存在。
    -   `500 Internal Server Error`: 服务器内部错误。
-   **JSON (JavaScript Object Notation)**: REST API最常用的数据交换格式。

## 一个简单的API示例：文章管理

我们将创建一个API来管理文章 (`posts`)，支持以下操作：
-   `GET /api/posts`: 获取所有文章列表。
-   `GET /api/posts/{id}`: 获取单篇文章。
-   `POST /api/posts`: 创建一篇新文章。
-   `DELETE /api/posts/{id}`: 删除一篇文章。

### 项目结构
```
/api/
|-- .htaccess       # URL重写规则 (Apache)
|-- config.php      # 数据库配置
|-- Database.php    # 数据库连接类
|-- PostController.php # 处理文章相关请求的逻辑
|-- index.php       # 应用入口和路由器
```

### 1. URL重写 (`.htaccess` for Apache)
为了让我们的URL看起来更友好（例如 `/api/posts/1` 而不是 `/api/index.php?resource=posts&id=1`），我们需要配置Web服务器进行URL重写。

**`.htaccess`:**
```apache
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?path=$1 [QSA,L]
```
这个规则将所有不存在的文件或目录的请求都重定向到`index.php`，并将原始路径作为`path`查询参数。

### 2. 数据库配置和连接
**`config.php`:**
```php
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', 'my_api_db');
define('DB_USER', 'db_user');
define('DB_PASS', 'db_password');
?>
```

**`Database.php` (使用PDO):**
```php
<?php
class Database {
    private static $instance = null;
    private $conn;

    private function __construct() {
        require_once 'config.php';
        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
        try {
            $this->conn = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ]);
        } catch (PDOException $e) {
            die('Connection Failed: ' . $e->getMessage());
        }
    }

    public static function getInstance() {
        if (self::$instance == null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->conn;
    }
}
?>
```

### 3. 控制器 (`PostController.php`)
控制器负责处理与文章资源相关的业务逻辑。
```php
<?php
require_once 'Database.php';

class PostController {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance()->getConnection();
    }

    public function handleRequest($method, $id = null) {
        switch ($method) {
            case 'GET':
                $response = $id ? $this->getPost($id) : $this->getPosts();
                break;
            case 'POST':
                $response = $this->createPost();
                break;
            case 'DELETE':
                $response = $this->deletePost($id);
                break;
            default:
                $response = $this->notFoundResponse();
                break;
        }
        $this->sendResponse($response);
    }

    private function getPosts() {
        $stmt = $this->db->query("SELECT * FROM posts");
        return ['status_code' => 200, 'body' => $stmt->fetchAll()];
    }

    private function getPost($id) {
        $stmt = $this->db->prepare("SELECT * FROM posts WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $post = $stmt->fetch();
        if (!$post) return $this->notFoundResponse();
        return ['status_code' => 200, 'body' => $post];
    }

    private function createPost() {
        $data = json_decode(file_get_contents('php://input'), true);
        if (!isset($data['title']) || !isset($data['body'])) {
            return ['status_code' => 400, 'body' => ['error' => 'Missing title or body']];
        }
        $sql = "INSERT INTO posts (title, body) VALUES (:title, :body)";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['title' => $data['title'], 'body' => $data['body']]);
        $id = $this->db->lastInsertId();
        return ['status_code' => 201, 'body' => ['id' => $id, 'message' => 'Post created']];
    }

    private function deletePost($id) {
        $sql = "DELETE FROM posts WHERE id = :id";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['id' => $id]);
        return ['status_code' => 204, 'body' => null];
    }
    
    private function notFoundResponse() {
        return ['status_code' => 404, 'body' => ['error' => 'Not Found']];
    }

    private function sendResponse($response) {
        header('Content-Type: application/json; charset=UTF-8');
        http_response_code($response['status_code']);
        if ($response['body']) {
            echo json_encode($response['body']);
        }
    }
}
?>
```

### 4. 入口和路由器 (`index.php`)
这是所有请求的入口。它解析URL，确定请求的资源和方法，并将请求分派给相应的控制器。
```php
<?php
require_once 'PostController.php';

// 基本的路由器
$path = trim($_GET['path'] ?? '', '/');
$path_parts = explode('/', $path);

// 我们只处理 /posts 资源
$resource = $path_parts[0] ?? null;
$id = $path_parts[1] ?? null;

if ($resource !== 'posts') {
    header("HTTP/1.1 404 Not Found");
    exit();
}

$method = $_SERVER['REQUEST_METHOD'];

// 实例化控制器并处理请求
$controller = new PostController();
$controller->handleRequest($method, $id);
?>
```

### 如何使用这个API？

你可以使用`cURL`或任何API客户端工具（如Postman）来测试API。
-   **获取所有文章:**
    ```bash
    curl http://localhost/api/posts
    ```
-   **获取ID为1的文章:**
    ```bash
    curl http://localhost/api/posts/1
    ```
-   **创建新文章:**
    ```bash
    curl -X POST http://localhost/api/posts -H "Content-Type: application/json" -d '{"title":"新标题","body":"新内容"}'
    ```
-   **删除ID为1的文章:**
    ```bash
    curl -X DELETE http://localhost/api/posts/1
    ```

这个示例展示了使用纯PHP构建REST API的核心思想。在实际项目中，你很可能会使用一个框架（如Laravel或Symfony），它们已经为你处理好了路由、请求/响应对象、依赖注入等底层细节，让你能更高效地构建功能强大的API。 