# 21. 服务器端渲染 (SSR) 与 Nuxt.js

服务器端渲染 (Server-Side Rendering, SSR) 是一种将 Vue 应用在服务器端预渲染成 HTML 字符串的技术，直接发送到浏览器，然后在客户端将静态标记"激活"为完全可交互的应用程序。

## 什么是 SSR？

### 客户端渲染 (CSR) vs 服务器端渲染 (SSR)

在传统的单页应用 (SPA) 中，所有的 JavaScript 都在浏览器中执行，生成 HTML DOM 并处理交互。这被称为客户端渲染 (CSR)。而在 SSR 中，应用的初始渲染发生在服务器上，然后将渲染好的 HTML 发送到浏览器。

### SSR 的优势

1. **更好的 SEO**：搜索引擎爬虫可以直接看到完全渲染的页面。
2. **更快的内容到达时间**：用户无需等待所有 JavaScript 下载并执行就能看到内容。
3. **更好的在低性能设备上的表现**：减轻了客户端渲染的负担。
4. **改善核心 Web 指标**：如首次内容绘制 (FCP) 和最大内容绘制 (LCP)。

### SSR 的挑战

1. **开发约束**：某些代码只能在特定环境（服务器或客户端）中运行。
2. **更复杂的设置**：需要 Node.js 服务器环境。
3. **更高的服务器负载**：渲染 HTML 需要更多服务器资源。

## Nuxt.js 简介

Nuxt.js 是一个基于 Vue.js 的高层框架，它抽象了服务器端渲染的复杂性，提供了一个流畅的开发体验。

### 主要特性

- **自动路由配置**：基于 `/pages` 目录结构自动生成路由配置。
- **服务器端渲染**：无需配置的开箱即用 SSR。
- **静态站点生成 (SSG)**：预渲染页面为静态 HTML。
- **基于文件的路由系统**：简化了应用程序路由。
- **代码拆分**：自动的代码分割。
- **数据获取钩子**：专门为 SSR 设计的数据获取机制。
- **强大的模块系统**：易于集成第三方库。

## 创建 Nuxt 项目

### 使用 Nuxt 3

```bash
# 使用 npx
npx nuxi init my-nuxt-app

# 进入项目目录
cd my-nuxt-app

# 安装依赖
npm install

# 启动开发服务器
npm run dev
```

### Nuxt 3 项目结构

```
my-nuxt-app/
  ├── .nuxt/             # 构建目录（自动生成）
  ├── assets/            # 未编译的静态资源
  ├── components/        # Vue 组件
  ├── composables/       # 组合式函数
  ├── content/           # 内容目录（用于内容管理）
  ├── layouts/           # 应用布局
  ├── middleware/        # 路由中间件
  ├── pages/             # 应用页面（自动路由）
  ├── plugins/           # 应用插件
  ├── public/            # 静态文件（直接提供）
  ├── server/            # 服务器端代码
  ├── app.vue            # 应用入口组件
  ├── nuxt.config.ts     # Nuxt 配置文件
  └── package.json       # 项目依赖
```

## 路由系统

Nuxt 提供了一个基于文件的路由系统，会根据 `pages/` 目录中的文件结构自动生成路由配置。

### 基本路由

```
pages/
  ├── index.vue          # / 路由
  ├── about.vue          # /about 路由
  └── users/
      ├── index.vue      # /users 路由
      └── [id].vue       # /users/:id 动态路由
```

### 嵌套路由

要创建嵌套路由，只需创建与父页面同名的目录，并在其中放置子页面：

```
pages/
  ├── parent.vue         # /parent 路由
  └── parent/
      └── child.vue      # /parent/child 路由
```

在 `parent.vue` 中，你需要包含 `<NuxtPage />` 组件来显示子路由的内容。

### 动态路由

使用方括号语法创建动态路由参数：

```
pages/
  └── users/
      └── [id].vue       # 匹配 /users/123, /users/abc 等
```

在组件中访问路由参数：

```vue
<script setup>
const route = useRoute()
console.log(route.params.id) // 访问动态参数
</script>
```

## 数据获取

Nuxt 提供了几种在服务器端和客户端获取数据的方法。

### `useFetch`

这是最常用的数据获取组合式函数，它在服务器端和客户端都能工作：

```vue
<script setup>
// 自动在服务器端获取数据，并在客户端水合
const { data, pending, error, refresh } = await useFetch('/api/users')
</script>

<template>
  <div v-if="pending">Loading...</div>
  <div v-else-if="error">Error: {{ error }}</div>
  <div v-else>
    <h1>Users</h1>
    <ul>
      <li v-for="user in data" :key="user.id">{{ user.name }}</li>
    </ul>
    <button @click="refresh">Refresh</button>
  </div>
</template>
```

### `useAsyncData`

当你需要更多控制时，可以使用 `useAsyncData`：

```vue
<script setup>
const { data: users, pending, error, refresh } = await useAsyncData(
  'users', // 唯一键
  () => $fetch('/api/users')
)
</script>
```

### 服务器路由处理程序

Nuxt 3 允许你在 `server/api` 目录中创建 API 端点：

```js
// server/api/users.js
export default defineEventHandler(async (event) => {
  // 这段代码只在服务器端运行
  return [
    { id: 1, name: 'John Doe' },
    { id: 2, name: 'Jane Smith' }
  ]
})
```

## 布局系统

Nuxt 提供了一个布局系统，可以复用通用的 UI 结构。

### 默认布局

创建 `layouts/default.vue`：

```vue
<template>
  <div>
    <header>
      <nav>
        <NuxtLink to="/">Home</NuxtLink>
        <NuxtLink to="/about">About</NuxtLink>
      </nav>
    </header>
    
    <main>
      <!-- 页面内容将被插入到这里 -->
      <slot />
    </main>
    
    <footer>
      <p>© 2023 My Nuxt App</p>
    </footer>
  </div>
</template>
```

### 自定义布局

创建 `layouts/custom.vue`：

```vue
<template>
  <div class="custom-layout">
    <slot />
  </div>
</template>
```

在页面中使用自定义布局：

```vue
<script setup>
// 指定使用自定义布局
definePageMeta({
  layout: 'custom'
})
</script>
```

## 中间件

中间件在路由导航之前或期间运行，可用于验证、重定向等功能。

### 创建中间件

```js
// middleware/auth.js
export default defineNuxtRouteMiddleware((to, from) => {
  // 模拟检查用户是否已认证
  const isAuthenticated = localStorage.getItem('token')
  
  // 如果未认证且试图访问需要认证的页面
  if (!isAuthenticated && to.path.startsWith('/dashboard')) {
    // 重定向到登录页
    return navigateTo('/login')
  }
})
```

### 使用中间件

全局中间件会自动应用于所有路由。对于特定页面的中间件，可以在页面组件中指定：

```vue
<script setup>
definePageMeta({
  middleware: ['auth']
})
</script>
```

## 插件系统

插件允许你在 Nuxt 应用启动之前注册和配置功能。

### 创建插件

```js
// plugins/toast.js
export default defineNuxtPlugin((nuxtApp) => {
  // 创建一个简单的 toast 函数
  const toast = (message) => {
    // 实现 toast 逻辑
    alert(message)
  }
  
  // 使其在整个应用中可用
  return {
    provide: {
      toast
    }
  }
})
```

### 使用插件

在组件中：

```vue
<script setup>
const { $toast } = useNuxtApp()

function showMessage() {
  $toast('Hello from plugin!')
}
</script>
```

## 构建和部署

### 开发模式

```bash
npm run dev
```

### 生产构建

对于 SSR 应用：

```bash
npm run build
```

这将生成一个可以部署到任何支持 Node.js 的主机的应用程序。

### 静态站点生成 (SSG)

如果你的应用可以预渲染为静态 HTML：

```bash
npm run generate
```

这将生成一个 `.output/public` 目录，可以部署到任何静态主机（如 Netlify、Vercel、GitHub Pages 等）。

### 部署到 Vercel

Nuxt 与 Vercel 有很好的集成：

1. 推送你的代码到 GitHub 仓库
2. 在 Vercel 中导入项目
3. 选择 Nuxt.js 框架预设
4. 点击部署

## 进阶功能

### 状态管理

Nuxt 提供了一个简单的状态管理解决方案：

```js
// composables/states.js
export const useCounter = () => useState('counter', () => 0)
```

在组件中使用：

```vue
<script setup>
const counter = useCounter()

function increment() {
  counter.value++
}
</script>
```

### SEO 和元标签

Nuxt 使用 `useHead` 来管理 `<head>` 部分：

```vue
<script setup>
useHead({
  title: 'My Amazing App',
  meta: [
    { name: 'description', content: 'This is my amazing Nuxt 3 app' }
  ],
  link: [
    { rel: 'icon', type: 'image/png', href: '/favicon.png' }
  ]
})
</script>
```

## 总结

Nuxt.js 极大地简化了构建服务器端渲染的 Vue 应用程序的过程。它提供了一套全面的功能，包括自动路由、数据获取、布局系统等，使得开发人员可以专注于构建功能，而不是配置细节。无论是追求更好的 SEO、性能还是开发体验，Nuxt.js 都是 Vue 开发者的一个强大工具。 