# 12. 路由管理: React Router

在单页面应用 (SPA) 中，虽然只有一个 HTML 页面，但我们仍然希望能够通过 URL 来导航到应用的不同部分，并能够分享指向特定页面的链接。这就是**客户端路由 (client-side routing)** 的作用，而在 React 生态中，**React Router** 是实现这一功能的事实标准。

## 核心概念

React Router 的核心是**组件**。它利用组件的可组合性，让你能够以声明式的方式定义应用的路由。

- **`<BrowserRouter>`**: 通常作为应用的最外层包裹组件。它使用 HTML5 History API (pushState, replaceState, popstate) 来保持你的 UI 和 URL 的同步。
- **`<Routes>`**: 一个容器，用于包裹多个 `<Route>` 组件。当 URL 变化时，它会查找其子 `<Route>` 中路径（path）最匹配的一个，并渲染其对应的元素（element）。
- **`<Route>`**: 定义一条路由规则。它有两个主要的 props：
    - `path`: 一个字符串，用于匹配 URL 的路径。
    - `element`: 当 `path` 匹配时，需要被渲染的 React 元素。
- **`<Link>`**: 用于在应用中创建导航链接。它最终会被渲染成一个 `<a>` 标签，但它会阻止浏览器的默认页面跳转行为，而是通过改变 URL 来触发 React Router 的路由更新。

## 基础设置

首先，需要安装 React Router:
```bash
npm install react-router-dom
```

然后，在你的应用入口（如 `index.js` 或 `App.js`）中设置路由。

```jsx
import React from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link
} from "react-router-dom";

// 定义一些页面组件
function Home() {
  return <h2>Home</h2>;
}

function About() {
  return <h2>About</h2>;
}

function Dashboard() {
  return <h2>Dashboard</h2>;
}

// 设置应用的主组件
export default function App() {
  return (
    <Router>
      <div>
        <nav>
          <ul>
            <li>
              <Link to="/">Home</Link>
            </li>
            <li>
              <Link to="/about">About</Link>
            </li>
            <li>
              <Link to="/dashboard">Dashboard</Link>
            </li>
          </ul>
        </nav>

        {/* Routes 定义了路由的匹配规则 */}
        <Routes>
          <Route path="/about" element={<About />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/" element={<Home />} />
        </Routes>
      </div>
    </Router>
  );
}
```

## URL 参数

有时候，你需要捕获 URL 中的动态部分，例如一个用户的 ID。你可以在 `path` 中使用冒号 `:` 来定义一个参数。

```jsx
<Route path="/users/:userId" element={<UserProfile />} />
```
在这个例子中，当 URL 为 `/users/123` 时，`UserProfile` 组件会被渲染。

为了在 `UserProfile` 组件中获取到 `userId` 这个参数，我们可以使用 `useParams` Hook。

```jsx
import { useParams } from 'react-router-dom';

function UserProfile() {
  // useParams 返回一个包含所有 URL 参数的键值对对象
  let { userId } = useParams();
  
  return <h2>User Profile for ID: {userId}</h2>;
}
```

## 嵌套路由 (Nested Routes)

嵌套路由是一个强大的功能，它允许你构建复杂的布局，其中一部分 UI 保持不变，而另一部分则根据 URL 变化。

例如，一个 Dashboard 页面可能有自己的子导航，用于显示图表或用户设置。

```jsx
function Dashboard() {
  return (
    <div>
      <h2>Dashboard</h2>
      <nav>
        <Link to="charts">Charts</Link> | {" "}
        <Link to="settings">Settings</Link>
      </nav>
      
      {/* Outlet 用于渲染子路由匹配的组件 */}
      <Outlet />
    </div>
  );
}

// 在主路由配置中
<Routes>
  <Route path="/dashboard" element={<Dashboard />}>
    {/* 子路由，注意 path 是相对父路由的 */}
    <Route path="charts" element={<DashboardCharts />} />
    <Route path="settings" element={<DashboardSettings />} />
  </Route>
</Routes>
```
`Dashboard` 组件中的 `<Outlet>` 组件是一个占位符。当 URL 匹配到 `/dashboard/charts` 时，`<DashboardCharts />` 组件就会被渲染在 `<Outlet />` 的位置。

## 编程方式导航

除了使用 `<Link>` 组件进行声明式导航外，有时你也需要在事件处理函数或 effect 中进行编程式导航（例如，在用户成功登录后跳转到 dashboard）。

`useNavigate` Hook 提供了这个功能。

```jsx
import { useNavigate } from 'react-router-dom';

function LoginButton() {
  let navigate = useNavigate();

  function handleLogin() {
    // ... 执行登录逻辑
    // 登录成功后，跳转到 dashboard
    navigate('/dashboard');
  }

  return <button onClick={handleLogin}>Login</button>;
}
```

## "No Match" (404) 路由

如果没有任何 `path` 能够匹配当前的 URL，你可以提供一个"捕获所有"的路由来显示一个 404 Not Found 页面。

在 `<Routes>` 的最后，添加一个 `path="*"` 的路由即可。

```jsx
<Routes>
  <Route path="/" element={<Home />} />
  <Route path="/about" element={<About />} />
  {/* ... 其他路由 */}
  <Route path="*" element={<NotFoundPage />} />
</Routes>
```
React Router 会按顺序查找匹配的路由，所以这个"捕获所有"的路由必须放在最后。

React Router 提供了构建功能丰富、可导航的单页面应用所需的所有工具。通过其组件化的 API，你可以清晰、声明式地管理应用的路由逻辑。 