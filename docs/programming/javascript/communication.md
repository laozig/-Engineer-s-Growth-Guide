# 前后端通信模式

现代 Web 应用的复杂性要求前端与后端之间有高效、可靠的数据交换机制。根据应用场景的不同，我们可以选择多种通信模式。本章将探讨从经典的请求-响应模型到实时双向通信的各种技术。

## 1. 客户端发起的通信 (请求-响应)

这是最常见也最基础的通信模式：客户端（浏览器）发起请求，服务器处理后返回响应。

### (1) `XMLHttpRequest` (历史的基石)

`XMLHttpRequest` (XHR) 是 AJAX 技术的底层 API，是所有现代网络请求库的鼻祖。虽然现在我们很少直接使用它，但了解其工作方式有助于理解网络请求的本质。

> **注意**: 在新项目中，推荐使用下面介绍的 `Fetch API` 或 `Axios`，它们提供了更简洁、更强大的接口。

### (2) Fetch API (现代标准)

`Fetch API` 是浏览器内置的、用于替代 `XMLHttpRequest` 的现代网络请求接口。它基于 Promise，语法更简洁，逻辑更清晰。

#### GET 请求与错误处理

```javascript
async function getUsers() {
  try {
    const response = await fetch('https://api.example.com/users');

    // fetch() 本身不会因 4xx/5xx 错误而 reject，需要手动检查响应状态
    if (!response.ok) {
      // .ok 属性在响应状态码为 200-299 时为 true
      throw new Error(`HTTP Error! Status: ${response.status}`);
    }

    const users = await response.json(); // 解析 JSON 响应体
    console.log(users);
  } catch (error) {
    // 这个 catch 块会捕获网络故障或上面手动抛出的错误
    console.error('Failed to fetch users:', error);
  }
}
```

#### POST 请求

```javascript
async function createUser(userData) {
  try {
    const response = await fetch('https://api.example.com/users', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(userData), // 请求体必须是字符串
    });

    if (!response.ok) {
      throw new Error(`HTTP Error! Status: ${response.status}`);
    }

    const newUser = await response.json();
    console.log('User created:', newUser);
  } catch (error) {
    console.error('Failed to create user:', error);
  }
}

createUser({ name: 'John Doe', email: 'john.doe@example.com' });
```

### (3) Axios (强大的第三方库)

[Axios](https://axios-http.com/) 是一个非常流行的、基于 Promise 的 HTTP 客户端，可用于浏览器和 Node.js。它在 `Fetch API` 的基础上提供了更多便捷功能。

**Axios vs Fetch**
-   **自动转换**: Axios 自动将请求体和响应数据转换为 JSON，无需手动 `JSON.stringify` 和 `response.json()`。
-   **更好的错误处理**: 网络错误或 4xx/5xx 响应都会直接返回一个被 rejected 的 Promise，简化了错误捕获逻辑。
-   **拦截器**: 允许在请求发送前或响应处理前拦截并修改它们，非常适合实现统一的认证、日志和错误处理。
-   **取消请求**: 支持取消请求。

#### 示例：使用 Axios 实例和拦截器

```javascript
import axios from 'axios';

// 1. 创建一个 Axios 自定义实例
const apiClient = axios.create({
  baseURL: 'https://api.example.com',
  timeout: 5000, // 请求超时时间
});

// 2. 设置请求拦截器
apiClient.interceptors.request.use(
  (config) => {
    // 在每个请求发送前，附加认证令牌
    const token = localStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    // 处理请求错误
    return Promise.reject(error);
  }
);

// 3. 设置响应拦截器
apiClient.interceptors.response.use(
  (response) => {
    // 对成功的响应数据进行处理
    return response.data; // 直接返回 data 部分，简化后续调用
  },
  (error) => {
    // 处理 HTTP 错误
    if (error.response?.status === 401) {
      // 例如：处理 token 过期，重定向到登录页
      console.error('Unauthorized! Redirecting to login...');
    }
    return Promise.reject(error);
  }
);


// 4. 使用封装好的实例
async function fetchUsers() {
  try {
    const users = await apiClient.get('/users');
    console.log(users);
  } catch (error) {
    console.error('API call failed:', error.message);
  }
}
```

## 2. 服务端发起的通信 (实时)

当需要服务器主动将数据推送给客户端时，请求-响应模型就不再适用。

### (1) WebSockets

WebSocket 提供了持久的、双向的通信通道。它适用于需要高频、低延迟交互的场景，如在线聊天、多人协作编辑、实时游戏等。

> 👉 **详情请查阅**: [WebSocket 实时通信](./websockets.md)

### (2) Server-Sent Events (SSE)

SSE 是一种更简单的实时技术，它允许服务器向客户端进行 **单向** 的数据推送。如果你的场景只需要从服务器流式传输数据到客户端（如新闻推送、状态更新、通知），SSE 是一个比 WebSocket 更轻量、更容易实现的选择。

SSE 基于标准的 HTTP，因此无需特殊协议或服务器实现。

**服务端 (`server.js`)**
```javascript
import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors()); // 允许跨域请求

app.get('/events', (req, res) => {
  // 1. 设置 SSE 的响应头
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders(); // 发送头信息

  let eventId = 0;
  const intervalId = setInterval(() => {
    // 2. 按照 SSE 格式发送数据
    const data = { timestamp: new Date().toISOString() };
    res.write(`id: ${eventId++}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`); // 注意末尾的两个换行符
  }, 2000); // 每2秒发送一次

  // 3. 当客户端关闭连接时，停止发送
  req.on('close', () => {
    clearInterval(intervalId);
    res.end();
  });
});

app.listen(3000, () => console.log('SSE server running on port 3000'));
```

**客户端 (`client.html`)**
```html
<ul id="events"></ul>
<script>
  const eventsList = document.getElementById('events');
  const sse = new EventSource('http://localhost:3000/events');

  // 监听 'message' 事件 (默认事件)
  sse.onmessage = (event) => {
    const data = JSON.parse(event.data);
    const item = document.createElement('li');
    item.textContent = `Event ID ${event.lastEventId}: ${data.timestamp}`;
    eventsList.appendChild(item);
  };
  
  sse.onerror = (error) => {
    console.error('SSE Error:', error);
    sse.close(); // 发生错误时关闭连接
  };
</script>
```

## 3. 常见问题：CORS 跨域资源共享

**CORS (Cross-Origin Resource Sharing)** 是一个浏览器安全机制，它限制了网页从与其来源不同的另一个域请求资源。这是为了防止恶意网站读取另一个网站的敏感数据。

-   **源 (Origin)** 由协议、域名、端口三者共同定义。`http://localhost:3000` 和 `http://localhost:8080` 是不同的源。

当你的前端应用（如 `http://localhost:3000`）尝试请求后端 API（如 `http://api.example.com` 或 `http://localhost:8080`）时，浏览器会发起一个跨域 HTTP 请求。如果后端服务器没有在响应头中明确允许来自前端这个源的请求，浏览器就会阻止这个请求。

**解决方案**: 在后端服务器上启用 CORS。使用 `cors` 中间件是 Express 中最简单的方式。

```bash
npm install cors
```

```javascript
// server.js
import express from 'express';
import cors from 'cors';

const app = express();

// 简单的用法：允许所有跨域请求
// app.use(cors());

// 推荐的用法：配置具体的 CORS 选项
const corsOptions = {
  origin: 'http://localhost:3000', // 只允许这个源的请求
  methods: 'GET,POST,PUT,DELETE', // 允许的 HTTP 方法
  allowedHeaders: ['Content-Type', 'Authorization'], // 允许的请求头
};
app.use(cors(corsOptions));

app.get('/api/data', (req, res) => {
  res.json({ message: 'This data is protected by CORS' });
});

app.listen(8080);
```

## 4. 新兴模式：GraphQL

GraphQL 是一种用于 API 的查询语言，也是一个满足这些查询的运行时。它不是 REST 的直接替代品，而是一种不同的 API 设计范式。

-   **核心思想**: 客户端精确地请求其所需要的数据，不多也不少。
-   **解决的问题**: 避免了 REST 中常见的 **过度获取 (Over-fetching)**（返回了不需要的数据）和 **请求不足 (Under-fetching)**（需要多次请求才能获取所有数据）的问题。

**GraphQL 查询示例 (客户端)**
```javascript
// 客户端可以定义它需要的数据结构
const query = `
  query {
    user(id: "1") {
      id
      name
      posts {
        title
        comments(first: 2) {
          text
        }
      }
    }
  }
`;

fetch('/graphql', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ query })
})
.then(res => res.json())
.then(data => console.log(data));
```
构建 GraphQL 服务器通常需要使用 [Apollo Server](https://www.apollographql.com/docs/apollo-server/) 或 [graphql.js](https://graphql.org/) 等库。 