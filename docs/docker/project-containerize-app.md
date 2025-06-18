# 11. 容器化 Web 应用

在本章中，我们将为 `todo-list` 应用的前端和后端服务分别编写应用代码和 `Dockerfile`。我们将特别关注如何使用多阶段构建来创建针对生产环境优化的、小而安全的镜像。

## 第一部分：容器化后端 API (Node.js / Express)

我们的后端服务负责处理业务逻辑和与数据库交互。

### 1. 编写应用代码

**`backend/package.json`**:
```json
{
  "name": "backend",
  "version": "1.0.0",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js"
  },
  "dependencies": {
    "cors": "^2.8.5",
    "express": "^4.18.2",
    "pg": "^8.11.3"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```

**`backend/src/server.js`**:
```javascript
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// 从环境变量中获取数据库连接信息
const pool = new Pool({
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DB,
  password: process.env.POSTGRES_PASSWORD,
  port: 5432,
});

// 初始化数据库表的函数
const initDb = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS todos (
        id SERIAL PRIMARY KEY,
        text VARCHAR(255) NOT NULL,
        completed BOOLEAN DEFAULT false
      );
    `);
    console.log('Database table initialized');
  } catch (err) {
    console.error('Error initializing database table', err.stack);
    // 在初始连接失败时重试
    setTimeout(initDb, 5000);
  }
};

// API Endpoints
app.get('/api/todos', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM todos ORDER BY id ASC');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/todos', async (req, res) => {
  try {
    const { text } = req.body;
    const result = await pool.query(
      'INSERT INTO todos (text) VALUES ($1) RETURNING *',
      [text]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ... (可以添加 PUT 和 DELETE 的 endpoint) ...

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Backend server is running on port ${PORT}`);
  initDb();
});
```

### 2. 编写 `backend/Dockerfile`

我们将使用**多阶段构建**来为开发和生产创建不同的环境。

```Dockerfile
# ---- Base Stage ----
# 基础阶段，用于共享依赖
FROM node:18-alpine AS base
WORKDIR /app
COPY package*.json ./

# ---- Production Stage ----
# 生产阶段，创建最终的生产镜像
FROM base AS production
ENV NODE_ENV=production
# 只安装生产依赖
RUN npm ci --only=production
COPY . .
CMD ["node", "src/server.js"]

# ---- Development Stage ----
# 开发阶段，用于本地开发和热重载
FROM base AS development
ENV NODE_ENV=development
# 安装所有依赖，包括 devDependencies (nodemon)
RUN npm install
COPY . .
# 使用 nodemon 启动服务
CMD ["npm", "run", "dev"]
```

**多阶段构建解析**:
-   `base` 阶段: 复制 `package.json` 并设置为工作目录，可被其他阶段共享。
-   `production` 阶段: 使用 `npm ci` 只安装生产依赖，最终镜像不包含 `nodemon` 等开发工具，更小更安全。
-   `development` 阶段: 安装所有依赖，并使用 `nodemon` 来启动应用，以支持代码热重载。
我们将在 `docker-compose.yml` 中选择使用哪个阶段。

### 3. 编写 `backend/.dockerignore`
```
node_modules
.git
npm-debug.log
```

## 第二部分：容器化前端 (React)

前端部分将使用 Nginx 来服务构建好的静态文件。

### 1. 编写应用代码

假设你已经使用 `npx create-react-app frontend` 创建了项目。这里只展示核心的修改。

**`frontend/src/App.js`** (一个简化的例子):
```javascript
import React, { useState, useEffect } from 'react';

// API 的地址将通过 Nginx 反向代理来访问
const API_URL = '/api/todos';

function App() {
  const [todos, setTodos] = useState([]);
  const [text, setText] = useState('');

  useEffect(() => {
    fetch(API_URL)
      .then(res => res.json())
      .then(data => setTodos(data));
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    })
      .then(res => res.json())
      .then(newTodo => {
        setTodos([...todos, newTodo]);
        setText('');
      });
  };

  return (
    <div>
      <h1>Todo List</h1>
      <ul>
        {todos.map(todo => (
          <li key={todo.id}>{todo.text}</li>
        ))}
      </ul>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <button type="submit">Add Todo</button>
      </form>
    </div>
  );
}

export default App;
```

### 2. 编写 `frontend/Dockerfile`

前端同样使用**多阶段构建**。

```Dockerfile
# ---- Build Stage ----
# 构建阶段：使用 Node.js 环境来构建 React 应用
FROM node:18-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# ---- Production Stage ----
# 生产阶段：使用 Nginx 来服务构建好的静态文件
FROM nginx:1.23-alpine

# 将构建阶段生成的静态文件复制到 Nginx 的 HTML 目录
COPY --from=build /app/build /usr/share/nginx/html

# (可选但推荐) 复制自定义的 Nginx 配置
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Nginx 默认会暴露 80 端口
EXPOSE 80

# Nginx 镜像的默认 CMD 就是启动 Nginx 服务
CMD ["nginx", "-g", "daemon off;"]
```
**多阶段构建解析**:
-   `build` stage: 这是一个临时的构建环境。它安装所有依赖，运行 `npm run build`，最终产物是 `/app/build` 目录下的静态文件。
-   `production` stage: 我们从一个非常轻量的 `nginx` 镜像开始，只做一件事：从 `build` 阶段拷贝最终的静态文件。最终的生产镜像非常小，并且不包含任何 Node.js 或 npm 的痕迹。

### 3. `frontend/nginx.conf`
为了让前端能调用后端 API，我们需要配置 Nginx 作为反向代理，将所有 `/api` 开头的请求转发给后端服务。
```nginx
server {
    listen 80;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
        try_files $uri /index.html;
    }

    location /api {
        # 'backend' 是我们在 docker-compose.yml 中定义的后端服务的名称
        # '4000' 是后端服务监听的端口
        proxy_pass http://backend:4000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```
*你需要在 `frontend` 目录下创建这个文件，并在 `frontend/Dockerfile` 中取消对 `COPY nginx.conf` 指令的注释。*

至此，我们已经为前后端服务都准备好了可用于生产的 Dockerfile。下一步，就是使用 Docker Compose 将它们和数据库一起编排起来。 