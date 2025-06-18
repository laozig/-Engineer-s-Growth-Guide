# 深入理解JavaScript中间件模式

<div align="center">
  <img src="../../../assets/programming/middleware-pipeline.png" alt="Middleware Pipeline" width="400">
</div>

> 中间件（Middleware）是现代后端开发中一种极其强大且普遍的设计模式，尤其在 Node.js 生态中。它允许我们将复杂的请求处理流程拆分成一系列独立的、可复用的功能单元，像乐高积木一样自由组合。本指南将从中间件的通用概念入手，深入探讨其在 Express 和 Koa 中的实现，并提供一系列可直接用于项目中的实战中间件。

## 目录

1.  [**中间件设计模式：核心思想**](#1-中间件设计模式核心思想)
    -   [它是什么？](#它是什么)
    -   [它解决了什么问题？](#它解决了什么问题)
2.  [**Express 中间件：经典的 `next()` 模式**](#2-express-中间件经典的-next-模式)
    -   [中间件的"洋葱模型"](#中间件的洋ö葱模型)
    -   [中间件的注册顺序至关重要](#中间件的注册顺序至关重要)
3.  [**Koa 中间件：`async/await` 的优雅**](#3-koa-中间件asyncawait-的优雅)
4.  [**实战：构建可复用的中间件系列**](#4-实战构建可复用的中间件系列)
    -   [① 请求日志记录器 (`requestLogger`)](#-请求日志记录器-requestlogger)
    -   [② API 密钥验证器 (`apiKeyValidator`)](#-api-密钥验证器-apikeyvalidator)
    -   [③ 异步错误处理器 (`asyncErrorHandler`)](#-异步错误处理器-asyncerrorhandler)
    -   [④ 网站维护模式开关 (`maintenanceMode`)](#-网站维护模式开关-maintenancemode)
5.  [**总结与最佳实践**](#5-总结与最佳实践)

---

## 1. 中间件设计模式：核心思想

### 它是什么？
中间件是一个函数，它位于接收请求和发送响应之间。它可以访问请求和响应对象，并能决定是将请求传递给"下一个"中间件，还是直接终止请求-响应周期。

![中间件流程](https://i.imgur.com/gHh4mQk.png)

### 它解决了什么问题？
-   **关注点分离 (Separation of Concerns)**：每个中间件只做一件事（如日志记录、身份验证、数据解析），使代码更清晰。
-   **代码复用**：身份验证逻辑可以写成一个中间件，然后在多个需要保护的路由中复用。
-   **可组合性**：可以像管道一样串联多个中间件，构建复杂的处理流程。

## 2. Express 中间件：经典的 `next()` 模式
在 Express 中，中间件是一个接收 `(req, res, next)` 三个参数的函数。

### 中间件的"洋葱模型"
一个请求会像穿过洋葱一样，逐层进入中间件。调用 `next()` 会将控制权交给下一层。当内层处理完毕后，控制权会"冒泡"回外层。

```javascript
app.use((req, res, next) => {
  console.log('1. 进入第一层');
  next();
  console.log('4. 离开第一层');
});
app.use((req, res, next) => {
  console.log('2. 进入第二层');
  res.send('Hello'); // 响应在这里发出
  // 注意：res.send() 之后，请求周期结束，但代码仍会继续执行
  console.log('3. 离开第二层');
});
// 客户端收到 "Hello"，控制台输出:
// 1. 进入第一层
// 2. 进入第二层
// 3. 离开第二层
// 4. 离开第一层
```

### 中间件的注册顺序至关重要
Express 中的中间件是严格按照注册顺序执行的。

-   **解析中间件必须在前**：`express.json()` 必须在任何需要读取 `req.body` 的路由之前。
-   **通用中间件在前，具体路由在后**：日志、CORS等应放在前面。
-   **错误处理中间件必须在最后**：这是 Express 捕获所有错误的保证。

## 3. Koa 中间件：`async/await` 的优雅
Koa 的中间件原生基于 `async/await`，代码更简洁，错误处理更直观。
```javascript
// Koa 的洋葱模型
app.use(async (ctx, next) => {
  console.log('1. 进入第一层');
  try {
    await next(); // 等待内层中间件全部完成
  } catch(err) {
    // 在这里集中捕获所有下游错误
  }
  console.log('4. 离开第一层');
});
app.use(async (ctx, next) => {
  console.log('2. 进入第二层');
  ctx.body = "Hello from Koa";
  console.log('3. 离开第二层');
});
```
> Koa 的模型更符合现代异步编程的直觉，`await next()` 会真正"等待"内层逻辑执行完毕。

## 4. 实战：构建可复用的中间件系列

以下所有示例均基于 Express。

### ① 请求日志记录器 (`requestLogger`)
一个简单的自定义日志中间件。
```javascript
// middlewares/logger.js
export function requestLogger(req, res, next) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.originalUrl}`);
  next();
}

// 在 app.js 中使用
// import { requestLogger } from './middlewares/logger.js';
// app.use(requestLogger);
```

### ② API 密钥验证器 (`apiKeyValidator`)
一个保护特定路由的简单认证中间件。
```javascript
// middlewares/auth.js
const VALID_API_KEY = "my-secret-key";

export function apiKeyValidator(req, res, next) {
  const apiKey = req.get('X-API-Key'); // 从请求头获取 API Key
  if (apiKey && apiKey === VALID_API_KEY) {
    return next(); // 密钥有效，继续
  }
  res.status(401).json({ error: 'Unauthorized: Invalid API Key' });
}

// 在 app.js 中使用
// import { apiKeyValidator } from './middlewares/auth.js';
// app.use('/api/protected', apiKeyValidator, protectedRoutes);
```

### ③ 异步错误处理器 (`asyncErrorHandler`)
Express 默认不捕获 `async` 函数中的 Promise rejections。这个辅助函数可以包装异步路由，将错误自动传递给 `next()`。
```javascript
// utils/asyncHandler.js
export function asyncHandler(fn) {
  return function (req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// 在路由文件中使用
// import { asyncHandler } from '../utils/asyncHandler.js';
// router.get('/', asyncHandler(async (req, res) => {
//   const data = await someAsyncOperationThatMightFail();
//   res.json(data);
// }));
```

### ④ 网站维护模式开关 (`maintenanceMode`)
一个通过环境变量来控制网站是否进入维护模式的中间件。
```javascript
// middlewares/maintenance.js
export function maintenanceMode(req, res, next) {
  if (process.env.MAINTENANCE_MODE === 'true') {
    res.status(503).send('<h1>Site is temporarily down for maintenance.</h1>');
  } else {
    next();
  }
}

// 在 app.js 中使用 (通常放在最前面)
// import { maintenanceMode } from './middlewares/maintenance.js';
// app.use(maintenanceMode);
```
> 你可以通过设置环境变量 `MAINTENANCE_MODE=true` 来开启此模式。

## 5. 总结与最佳实践
-   **保持精简**：让每个中间件只做一件事，并把它做好。
-   **明确顺序**：仔细规划中间件的注册顺序。
-   **错误处理**：为你的应用实现一个健壮的、集中的错误处理中间件。
-   **异步包装**：在Express中，使用辅助函数来处理异步路由的错误。
-   **参数化**：让你的中间件更灵活，例如，允许传入配置选项。

---

中间件模式是现代JavaScript Web应用架构的重要组成部分，掌握它能够帮助开发者构建更加模块化、可维护的应用程序。通过本文档，您应该能够理解中间件的核心概念，并能够在Express和Koa等框架中合理应用或开发自己的中间件。 