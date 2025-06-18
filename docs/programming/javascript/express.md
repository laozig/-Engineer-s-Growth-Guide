# Express.js 实战入门指南

<div align="center">
  <img src="../../../assets/programming/express-logo.png" alt="Express Logo" width="300">
</div>

> Express 是 Node.js 世界中最流行、最经典的Web应用框架。它以其极简的设计和强大的中间件架构，成为快速构建健壮、高效的API和Web应用的基石。本指南将通过构建一个完整的"待办事项"API，带你实战掌握Express的核心。

## 目录

1.  [**Express 是什么？为什么选择它？**](#1-express-是什么为什么选择它)
2.  [**项目初始化与第一个服务器**](#2-项目初始化与第一个服务器)
3.  [**核心概念：路由 (Routing)**](#3-核心概念路由-routing)
    -   [设计 RESTful API 路由](#设计-restful-api-路由)
    -   [处理路由参数与查询](#处理路由参数与查询)
4.  [**核心概念：中间件 (Middleware)**](#4-核心概念中间件-middleware)
    -   [中间件的"洋葱模型"](#中间件的洋葱模型)
    -   [常用内置中间件](#常用内置中间件)
    -   [必备第三方中间件](#必备第三方中间件)
5.  [**构建一个完整的 To-Do API**](#5-构建一个完整的-to-do-api)
    -   [项目结构](#项目结构)
    -   [实现路由模块](#实现路由模块)
    -   [主应用文件 (`app.js`)](#主应用文件-appjs)
6.  [**优雅的错误处理**](#6-优雅的错误处理)
7.  [**总结与下一步**](#7-总结与下一步)

---

## 1. Express 是什么？为什么选择它？
如果你用 Node.js 的原生 `http` 模块来构建一个复杂的应用，你会发现需要写大量的模板代码来处理路由、解析请求体、管理cookie等。

Express 将这些繁琐的工作进行了封装，提供了一套简洁而强大的API，让你能更专注于业务逻辑。它成功的关键在于其**中间件架构**。

## 2. 项目初始化与第一个服务器
1.  **创建项目**:
    ```bash
    mkdir express-todo-api
    cd express-todo-api
    npm init -y
    ```
2.  **安装 Express**:
    ```bash
    npm install express
    ```
3.  **创建 `app.js`**:
    ```javascript
    import express from 'express';

    const app = express();
    const port = 3000;

    app.get('/', (req, res) => {
      res.send('欢迎使用 To-Do API!');
    });

    app.listen(port, () => {
      console.log(`服务器正在 http://localhost:${port} 上运行...`);
    });
    ```
4.  **配置 `package.json` 以使用 ES Modules**:
    在 `package.json` 中添加 `"type": "module"`。
    ```json
    {
      // ...
      "type": "module",
      // ...
    }
    ```
5.  **启动服务器**: `node app.js`

## 3. 核心概念：路由 (Routing)
路由定义了应用如何响应客户端对特定端点（URI）和特定HTTP方法（GET, POST等）的请求。

### 设计 RESTful API 路由
REST (Representational State Transfer) 是一种流行的API设计风格。对于一个"待办事项"资源，其路由通常如下设计：

| HTTP 方法 | 路径 | 描述 |
| :--- | :--- | :--- |
| `GET` | `/todos` | 获取所有待办事项 |
| `GET` | `/todos/:id` | 获取单个待办事项 |
| `POST`| `/todos` | 创建一个新的待办事项 |
| `PUT` | `/todos/:id` | 更新一个待办事项 |
| `DELETE`| `/todos/:id` | 删除一个待办事项 |

### 处理路由参数与查询
- **路由参数 (`req.params`)**: 用于捕获URL中的动态部分，如 `/todos/123` 中的 `123`。
- **查询字符串 (`req.query`)**: 用于处理URL `?` 之后的部分，如 `/todos?completed=true`。

```javascript
// 示例: /todos/123
app.get('/todos/:id', (req, res) => {
  const { id } = req.params;
  res.send(`正在获取 ID 为 ${id} 的待办事项...`);
});

// 示例: /search?keyword=learning
app.get('/search', (req, res) => {
  const { keyword } = req.query;
  res.send(`正在搜索关键词: ${keyword}`);
});
```

## 4. 核心概念：中间件 (Middleware)
中间件本质上是一个函数，它可以访问请求对象 (`req`)、响应对象 (`res`) 和 `next` 函数。

### 中间件的"洋葱模型"
你可以把中间件想象成一层层的洋葱。一个请求进来，会从最外层的中间件开始，一层层向内传递（通过调用 `next()`），直到某个中间件发送了响应。
![洋葱模型](https://i.imgur.com/gHh4mQk.png)

### 常用内置中间件
Express 提供了几个非常有用的内置中间件：
-   `express.json()`: 解析请求体中的JSON数据，并通过 `req.body` 访问。
-   `express.urlencoded({ extended: true })`: 解析URL编码的请求体（如表单提交）。
-   `express.static('public')`: 提供静态文件服务（如图片、CSS、JS文件）。

```javascript
// 在所有路由前使用，以解析进来的JSON请求
app.use(express.json());
```

### 必备第三方中间件
-   **`cors`**: 解决跨域资源共享（CORS）问题。`npm install cors`
-   **`morgan`**: 打印详细的HTTP请求日志。`npm install morgan`
-   **`dotenv`**: 从 `.env` 文件加载环境变量。`npm install dotenv`
-   **`helmet`**: 通过设置各种HTTP头来提高应用的安全性。`npm install helmet`

## 5. 构建一个完整的 To-Do API

### 项目结构
为了保持代码整洁，我们将路由逻辑拆分到单独的文件中。
```
/express-todo-api
|-- /routes
|   `-- todos.js     # 关于todo的所有路由
|-- app.js           # 主应用文件
`-- package.json
```

### 实现路由模块 (`routes/todos.js`)
```javascript
import { Router } from 'express';
const router = Router();

// 使用内存中的数组模拟数据库
let todos = [
  { id: 1, task: '学习 Node.js', completed: false },
  { id: 2, task: '掌握 Express', completed: false },
];

// GET /todos
router.get('/', (req, res) => {
  res.json(todos);
});

// POST /todos
router.post('/', (req, res) => {
  const { task } = req.body;
  if (!task) {
    return res.status(400).json({ error: '任务内容不能为空' });
  }
  const newTodo = {
    id: todos.length + 1,
    task,
    completed: false,
  };
  todos.push(newTodo);
  res.status(201).json(newTodo);
});

// ... 其他路由 (GET by id, PUT, DELETE) ...

export default router;
```

### 主应用文件 (`app.js`)
```javascript
import express from 'express';
import todoRoutes from './routes/todos.js';

const app = express();
const port = 3000;

// 应用中间件
app.use(express.json()); // 解析JSON请求体

// 挂载路由模块
// 所有到 /api/todos 的请求都将由 todoRoutes 处理
app.use('/api/todos', todoRoutes);

app.get('/', (req, res) => {
  res.send('欢迎使用 To-Do API! 请访问 /api/todos');
});

app.listen(port, () => {
  console.log(`服务器正在 http://localhost:${port} 上运行...`);
});
```

## 6. 优雅的错误处理
创建一个集中的错误处理中间件是最佳实践。它是一个有4个参数的特殊中间件。

```javascript
// 在 app.js 的末尾，所有 app.use() 和路由之后添加
function errorHandler(err, req, res, next) {
  console.error(err.stack); // 在控制台打印错误堆栈

  const statusCode = err.status || 500; // 如果错误有状态码则使用,否则用500
  const message = err.message || '服务器内部错误';

  res.status(statusCode).json({ error: message });
}

app.use(errorHandler);
```
> 现在，如果在任何路由中调用 `next(error)`，这个中间件就会被触发。

## 7. 总结与下一步
你现在已经掌握了Express的核心：
-   如何启动一个服务器。
-   如何使用路由来定义API端点。
-   中间件如何处理请求。
-   如何将代码模块化。

下一步，你可以探索：
-   **连接数据库**: 将内存中的数组换成真实的数据库（如MongoDB或PostgreSQL）。
-   **身份验证**: 使用JWT等技术保护你的API。
-   **测试**: 为你的路由编写单元测试和集成测试。 