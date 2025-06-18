# 设计与实现 RESTful API

REST (Representational State Transfer) 是一种软件架构风格，而非一个硬性标准。它定义了一组约束和原则，用于创建可伸缩、可维护、易于理解的 Web 服务。一个遵循 REST 风格的 API 被称为 RESTful API。它是现代 Web 开发中客户端与服务器通信的事实标准。

## 1. RESTful 核心原则

一个真正 "RESTful" 的 API 应当遵循以下六个核心原则：

1.  **客户端-服务器分离 (Client-Server)**: 客户端（如前端应用）和服务器（后端）的逻辑应完全分离。服务器负责数据存储和业务逻辑，客户端负责用户界面和用户体验。它们之间仅通过定义良好的 API 进行通信。
2.  **无状态 (Stateless)**: 服务器不应存储任何关于客户端会话（Context）的信息。每个从客户端发来的请求都必须包含所有必要的信息，以便服务器能够理解和处理它。这极大地提高了系统的可伸缩性和可靠性。
3.  **可缓存 (Cacheable)**: 来自服务器的响应应明确标记其是否可以被缓存。这允许客户端或中间代理（如 CDN）缓存响应，从而减少延迟，提高性能。
4.  **统一接口 (Uniform Interface)**: 这是 REST 设计的基石，它简化并解耦了架构。统一接口包含四个子约束：
    *   **资源标识 (Identification of resources)**: 使用统一资源标识符 (URI) 来唯一标识资源，例如 `/users/123`。
    *   **通过表述来操作资源 (Manipulation of resources through representations)**: 客户端通过获取资源的表述（如 JSON 或 XML）来操作资源。这个表述应包含足够的信息来修改或删除该资源。
    *   **自描述消息 (Self-descriptive messages)**: 每个请求和响应都应包含足够的信息来描述如何处理它，例如使用 HTTP 方法 (`GET`, `POST`) 和媒体类型 (`Content-Type: application/json`)。
    *   **超媒体作为应用状态的引擎 (HATEOAS)**: 响应中应包含链接（URLs），指导客户端可以执行的下一步操作。例如，一个 `/users/123` 的响应可能包含一个链接指向 `/users/123/posts`。
5.  **分层系统 (Layered System)**: 客户端通常不知道它连接的是最终的服务器还是中间层（如负载均衡器、代理）。这使得我们可以在不影响客户端的情况下，为系统增加安全、性能等中间层。
6.  **按需代码 (Code on demand, 可选)**: 服务器可以将可执行代码（如 JavaScript）传输到客户端，从而扩展客户端的功能。这是唯一一个可选的原则。

---

## 2. API 设计指南

### (1) 资源命名 (URI)

使用名词复数形式来命名资源集合，并用路径参数表示单个资源。

| 目的 | 好的实践 (Good) | 不好的实践 (Bad) |
|---|---|---|
| 获取所有用户 | `GET /users` | `GET /getAllUsers` |
| 获取单个用户 | `GET /users/123` | `GET /getUserById?id=123`|
| 创建新用户 | `POST /users` | `POST /createUser` |
| 获取某用户的所有文章 | `GET /users/123/posts` | `GET /getUserPosts?userId=123`|

### (2) HTTP 方法 (Verbs)

使用正确的 HTTP 动词来表示对资源的操作，这被称为 "语义化方法"。

| HTTP 方法 | 操作 | 描述 |
|---|---|---|
| `GET` | **读取 (Read)** | 安全且幂等。用于检索资源，不应有副作用。|
| `POST` | **创建 (Create)** | 非幂等。用于在集合中创建一个新资源。|
| `PUT` | **全量更新 (Update/Replace)** | 幂等。用请求的完整负载替换目标资源。|
| `PATCH` | **部分更新 (Partial Update)** | 非幂等（但可设计为幂等）。用请求的部分负载修改目标资源。|
| `DELETE` | **删除 (Delete)** | 幂等。删除指定资源。|

> **幂等性 (Idempotency)** 是指一个操作执行一次和执行多次产生的效果是相同的。例如，`DELETE /users/123` 执行一次后用户被删除，再执行N次，结果仍然是该用户不存在（已被删除）。而 `POST /users` 每执行一次都会创建一个新用户，因此是非幂等的。

### (3) HTTP 状态码 (Status Codes)

状态码是服务器告知客户端请求结果的关键。使用标准的状态码能让客户端更容易地处理响应。

-   **2xx (成功)**
    -   `200 OK`: 请求成功。`GET`, `PUT`, `PATCH` 的标准成功响应。
    -   `201 Created`: 资源创建成功。`POST` 的标准成功响应。响应头中通常包含 `Location` 指向新资源的 URL。
    -   `204 No Content`: 请求成功，但响应体中没有内容。`DELETE` 的标准成功响应。
-   **4xx (客户端错误)**
    -   `400 Bad Request`: 请求无效，例如请求体格式错误、参数缺失等。
    -   `401 Unauthorized`: 未经授权。客户端需要提供身份凭证。
    -   `403 Forbidden`: 已认证，但无权访问该资源。
    -   `404 Not Found`: 请求的资源不存在。
    -   `409 Conflict`: 请求冲突，例如尝试创建一个已存在的唯一资源。
-   **5xx (服务器错误)**
    -   `500 Internal Server Error`: 服务器内部发生未知错误。这是一个通用的服务器错误码。

### (4) 查询参数 (Query Parameters)

对于资源集合 (`/users`)，使用查询参数来实现过滤、排序、分页和字段选择。

-   **过滤**: `GET /users?status=active`
-   **排序**: `GET /users?sortBy=createdAt&order=desc`
-   **分页**: `GET /users?page=2&limit=20`
-   **字段选择**: `GET /users?fields=id,name,email`

---

## 3. 使用 Express 实现专业级 RESTful API

下面的示例将演示如何组织一个结构清晰、可维护的 Express 项目。

### (1) 项目结构

```
/my-api
├── node_modules/
├── package.json
└── src/
    ├── app.js             # Express 应用配置和中间件
    ├── server.js          # 服务器启动入口
    ├── routes/
    │   └── user.routes.js # 用户相关的路由定义
    ├── controllers/
    │   └── user.controller.js # 处理请求的控制器逻辑
    ├── services/
    │   └── user.service.js  # 封装数据操作（模拟数据库）
    └── middlewares/
        ├── errorHandler.js  # 统一错误处理中间件
        └── validate.js      # 数据验证中间件
```

### (2) 依赖安装

```bash
npm install express
```

### (3) 代码实现

#### `src/services/user.service.js` (数据层)

这里我们模拟数据库操作。在真实应用中，这里会调用 ORM/ODM (如 Sequelize, Mongoose)。

```javascript
// src/services/user.service.js
let users = [
  { id: 1, name: 'Alice', email: 'alice@example.com' },
  { id: 2, name: 'Bob', email: 'bob@example.com' },
];
let nextId = 3;

// 使用 async/await 模拟异步数据库操作
export const userService = {
  findAll: async () => {
    return users;
  },

  findById: async (id) => {
    return users.find(user => user.id === id);
  },

  create: async (userData) => {
    const newUser = { id: nextId++, ...userData };
    users.push(newUser);
    return newUser;
  },

  update: async (id, userData) => {
    const userIndex = users.findIndex(user => user.id === id);
    if (userIndex === -1) return null;

    const updatedUser = { ...users[userIndex], ...userData };
    users[userIndex] = updatedUser;
    return updatedUser;
  },

  delete: async (id) => {
    const userIndex = users.findIndex(user => user.id === id);
    if (userIndex === -1) return false;

    users.splice(userIndex, 1);
    return true;
  }
};
```

#### `src/controllers/user.controller.js` (控制器层)

控制器负责解析请求、调用服务、并构建响应。

```javascript
// src/controllers/user.controller.js
import { userService } from '../services/user.service.js';

export const userController = {
  getAllUsers: async (req, res, next) => {
    try {
      const users = await userService.findAll();
      res.status(200).json({ status: 'success', data: users });
    } catch (error) {
      next(error); // 将错误传递给错误处理中间件
    }
  },

  getUserById: async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const user = await userService.findById(id);
      if (!user) {
        return res.status(404).json({ status: 'fail', message: 'User not found' });
      }
      res.status(200).json({ status: 'success', data: user });
    } catch (error) {
      next(error);
    }
  },

  createUser: async (req, res, next) => {
    try {
      const newUser = await userService.create(req.body);
      res.status(201).json({ status: 'success', data: newUser });
    } catch (error) {
      next(error);
    }
  },

  updateUser: async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const updatedUser = await userService.update(id, req.body);
      if (!updatedUser) {
        return res.status(404).json({ status: 'fail', message: 'User not found' });
      }
      res.status(200).json({ status: 'success', data: updatedUser });
    } catch (error) {
      next(error);
    }
  },

  deleteUser: async (req, res, next) => {
    try {
      const id = parseInt(req.params.id);
      const success = await userService.delete(id);
      if (!success) {
        return res.status(404).json({ status: 'fail', message: 'User not found' });
      }
      res.status(204).send(); // 成功删除，无内容返回
    } catch (error) {
      next(error);
    }
  }
};
```

#### `src/routes/user.routes.js` (路由层)

路由定义了 API 的端点 (Endpoints) 和它们对应的控制器方法。

```javascript
// src/routes/user.routes.js
import { Router } from 'express';
import { userController } from '../controllers/user.controller.js';

const router = Router();

router.route('/')
  .get(userController.getAllUsers)
  .post(userController.createUser);

router.route('/:id')
  .get(userController.getUserById)
  .patch(userController.updateUser) // 使用 PATCH 进行部分更新
  .put(userController.updateUser)   // 也可支持 PUT 进行全量更新
  .delete(userController.deleteUser);

export default router;
```

#### `src/middlewares/errorHandler.js` (错误处理)

一个集中的错误处理器可以捕获所有在控制器中通过 `next(error)` 传递的错误。

```javascript
// src/middlewares/errorHandler.js
export const errorHandler = (err, req, res, next) => {
  console.error(err.stack); // 在控制台记录详细错误

  // 默认500错误
  const statusCode = err.statusCode || 500;
  const message = err.message || 'Internal Server Error';

  res.status(statusCode).json({
    status: 'error',
    statusCode,
    message,
  });
};
```

#### `src/app.js` (应用配置)

这里我们将所有部分组合起来。

```javascript
// src/app.js
import express from 'express';
import userRouter from './routes/user.routes.js';
import { errorHandler } from './middlewares/errorHandler.js';

const app = express();

// 1. 内置中间件
app.use(express.json()); // 解析 JSON 请求体
app.use(express.urlencoded({ extended: true })); // 解析 URL-encoded 请求体

// 2. 路由
app.use('/api/v1/users', userRouter);

// 3. 404 Not Found 中间件
app.use((req, res, next) => {
  res.status(404).json({ status: 'fail', message: `Can't find ${req.originalUrl} on this server!` });
});

// 4. 统一错误处理中间件
app.use(errorHandler);

export default app;
```

#### `src/server.js` (启动入口)

```javascript
// src/server.js
import app from './app.js';

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
```

### (4) 启动应用

在 `package.json` 中添加启动脚本：

```json
{
  "name": "my-api",
  "version": "1.0.0",
  "type": "module",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
```

现在，运行 `npm start` 即可启动这个结构清晰的 RESTful API 服务器。这种分层结构极大地提高了代码的可读性、可维护性和可测试性，是构建专业 Node.js 应用的推荐模式。 