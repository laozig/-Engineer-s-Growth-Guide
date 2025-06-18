# 示例项目：全栈博客平台 - 前端界面开发

完成后端 API 后，现在我们转向用户直接交互的前端。本章将指导你使用 Vite 和 React 构建一个现代化、响应式的博客前端应用，并与我们之前创建的后端服务进行通信。

## 1. 环境搭建与项目初始化

我们将项目根目录下的 `frontend` 文件夹作为前端应用的工作区。

### (1) 初始化 React 项目
使用 Vite 快速创建一个基于 TypeScript 的 React 项目。

```bash
# 确保你在项目根目录 (fullstack-blog)
pnpm create vite frontend --template react-ts
cd frontend
```

### (2) 安装核心依赖
我们需要 `axios` 来发送 HTTP 请求，`react-router-dom` 来处理客户端路由。

```bash
pnpm install axios react-router-dom
```

### (3) 配置 Vite 代理
为了在开发环境中避免 CORS 跨域问题，我们可以配置 Vite 的开发服务器，将所有 `/api` 开头的请求代理到后端服务器 (默认运行在 `http://localhost:3000`)。

创建或修改 `frontend/vite.config.ts` 文件：

```typescript
// vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
})
```
这样，在前端代码中请求 `/api/posts` 就会被 Vite 自动转发到 `http://localhost:3000/api/posts`。

---

## 2. 项目结构与 API 服务

### (1) 搭建前端目录结构
在 `frontend/src` 目录下，创建以下文件夹来组织我们的代码：

```
/frontend
└── /src
    ├── /assets
    ├── /components     # 可复用的小组件 (如 Button, Input, Header)
    ├── /hooks          # 自定义 React Hooks (如 useAuth)
    ├── /pages          # 页面级组件 (如 HomePage, LoginPage)
    ├── /services       # API 请求服务
    └── main.tsx        # 应用入口
```

### (2) 创建 API 服务
创建一个集中的 API 服务模块，用于封装 `axios` 的所有请求。这让代码更易于维护，也便于我们统一处理认证 Token。

```typescript
// src/services/api.ts
import axios from 'axios';

const apiClient = axios.create({
  baseURL: '/api', // Vite 代理会处理这个前缀
});

// 添加请求拦截器，在每个请求头中附带 JWT
apiClient.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default apiClient;
```

---

## 3. 核心页面与路由

### (1) 设置应用路由
使用 `react-router-dom` 在 `src/main.tsx` 中设置应用的主路由。

```tsx
// src/main.tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import App from './App' // 假设 App 组件包含 Header 和公共布局
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import PostPage from './pages/PostPage';
// ... 其他页面导入

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <Router>
      <Routes>
        <Route path="/" element={<App />}>
          <Route index element={<HomePage />} />
          <Route path="login" element={<LoginPage />} />
          <Route path="post/:id" element={<PostPage />} />
          {/* 其他路由 */}
        </Route>
      </Routes>
    </Router>
  </React.StrictMode>,
)
```

### (2) 状态管理与认证
对于全局的用户认证状态，我们可以使用 React Context 来实现一个简单的 `AuthContext`。

#### 创建 `AuthContext`
```typescript
// src/hooks/useAuth.tsx (示例)
import { createContext, useContext, useState } from 'react';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  // ... login, logout 函数 ...

  const login = (userData, token) => {
    localStorage.setItem('token', token);
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('token');
    setUser(null);
  };
  
  // ...

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
```
然后在 `main.tsx` 中用 `AuthProvider` 包裹整个应用。

### (3) 页面实现示例

#### `HomePage.tsx`
此页面获取并展示博客文章列表。

```tsx
// src/pages/HomePage.tsx
import React, { useEffect, useState } from 'react';
import apiClient from '../services/api';
import { Link } from 'react-router-dom';

function HomePage() {
  const [posts, setPosts] = useState([]);

  useEffect(() => {
    const fetchPosts = async () => {
      try {
        const response = await apiClient.get('/posts');
        setPosts(response.data);
      } catch (error) {
        console.error("Failed to fetch posts:", error);
      }
    };
    fetchPosts();
  }, []);

  return (
    <div>
      <h1>博客文章</h1>
      <ul>
        {posts.map(post => (
          <li key={post.id}>
            <Link to={`/post/${post.id}`}>{post.title}</Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default HomePage;
```

#### `LoginPage.tsx`
处理用户登录表单的提交，并调用 `AuthContext` 中的 `login` 方法。

```tsx
// src/pages/LoginPage.tsx
import React, { useState } from 'react';
import apiClient from '../services/api';
import { useAuth } from '../hooks/useAuth';
import { useNavigate } from 'react-router-dom';

function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await apiClient.post('/auth/login', { email, password });
      login(response.data.user, response.data.token);
      navigate('/'); // 登录成功后跳转到首页
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  // ... 返回 JSX 表单
  return (
    <form onSubmit={handleSubmit}>
      {/* ... email 和 password input ... */}
      <button type="submit">登录</button>
    </form>
  );
}

export default LoginPage;
```

### (4) 受保护的路由
对于像"创建文章"这样的页面，我们需要确保只有登录用户才能访问。我们可以创建一个 `ProtectedRoute` 组件。

```tsx
// src/components/ProtectedRoute.tsx
import React from 'react';
import { useAuth } from '../hooks/useAuth';
import { Navigate, Outlet } from 'react-router-dom';

function ProtectedRoute() {
  const { user } = useAuth();

  if (!user) {
    // 如果用户未登录，重定向到登录页
    return <Navigate to="/login" replace />;
  }

  return <Outlet />; // 如果已登录，渲染子路由
}
```

然后在路由配置中使用它：
```tsx
// src/main.tsx 中的 Routes
<Route element={<ProtectedRoute />}>
  <Route path="create-post" element={<CreatePostPage />} />
  {/* 其他需要保护的路由 */}
</Route>
```
## 4. 总结
本章我们搭建了一个功能齐全的 React 前端应用。它通过 Vite 实现高效开发，通过 `react-router-dom` 管理页面导航，通过 `axios` 和代理与后端 API 安全通信，并利用 Context API 实现了用户状态管理和路由保护。

下一章，我们将讨论如何将这个全栈应用部署到线上。 