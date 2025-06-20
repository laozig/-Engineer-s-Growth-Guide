# 路由管理: Vue Router

Vue Router 是 Vue.js 的官方路由管理器。它与 Vue.js 核心深度集成，让构建单页面应用 (SPA) 变得易如反掌。

## 核心概念

-   **路由器 (Router)**: 路由系统的核心，负责管理路由规则和导航。
-   **路由 (Route)**: 定义了 URL 路径与组件之间的映射关系。
-   **导航守卫 (Navigation Guards)**: 提供了在导航过程中执行自定义逻辑的能力，例如权限检查、数据获取等。

## 安装与配置

```bash
npm install vue-router@4
```

在你的主应用文件 (`main.js` 或 `main.ts`) 中，创建并使用路由实例：

```javascript
// main.js
import { createApp } from 'vue';
import { createRouter, createWebHistory } from 'vue-router';
import App from './App.vue';
import Home from './views/Home.vue';
import About from './views/About.vue';

// 1. 定义路由组件

// 2. 定义一些路由
// 每个路由都需要映射到一个组件。
const routes = [
  { path: '/', component: Home },
  { path: '/about', component: About },
];

// 3. 创建路由实例并传递 `routes` 配置
const router = createRouter({
  // 4. 内部提供了 history 模式的实现。为了简单起见，我们在这里使用 hash 模式。
  history: createWebHistory(),
  routes, // `routes: routes` 的缩写
});

// 5. 创建并挂载根实例
const app = createApp(App);
// 确保要挂载的根组件中有 <router-view>
app.use(router);

app.mount('#app');
```

## 路由出口

在你的根组件 (例如 `App.vue`) 中，你需要使用 `<router-view>` 组件来渲染匹配当前 URL 的组件。

```vue
<template>
  <div id="app">
    <h1>Hello App!</h1>
    <p>
      <!-- 使用 router-link 组件进行导航 -->
      <!-- 通过 `to` 指定目标路径 -->
      <router-link to="/">Go to Home</router-link>
      <router-link to="/about">Go to About</router-link>
    </p>
    <!-- 路由出口 -->
    <!-- 路由匹配到的组件将渲染在这里 -->
    <router-view></router-view>
  </div>
</template>
```

## 动态路由

当需要将给定模式的 URL 映射到同一个组件时，可以使用动态路由。例如，我们可能有一个 `User` 组件，它应该对所有用户进行渲染，但用户 ID 不同。

```javascript
const routes = [
  // 动态字段以冒号开始
  { path: '/users/:id', component: User },
];
```

在 `User` 组件中，你可以通过 `$route.params` 来访问动态参数：

```vue
<template>
  <div>User {{ $route.params.id }}</div>
</template>

<script>
export default {
  // 你也可以在 setup 中通过 useRoute 访问
  setup() {
    const route = useRoute();
    const userId = route.params.id;
    // ...
  }
}
</script>
```

## 导航守卫

Vue Router 提供了全局、路由独享和组件内的导航守卫，用于控制导航流程。

-   `router.beforeEach`: 全局前置守卫，在每次导航之前都会触发。
-   `beforeEnter`: 路由独享守卫，只在进入特定路由时触发。
-   `beforeRouteEnter`, `beforeRouteUpdate`, `beforeRouteLeave`: 组件内守卫。

### 全局前置守卫示例

```javascript
router.beforeEach((to, from, next) => {
  if (to.meta.requiresAuth && !isAuthenticated()) {
    // 此路由需要授权，请检查是否已登录
    // 如果没有，则重定向到登录页面
    next({ name: 'Login' });
  } else {
    next(); // 确保一定要调用 next()
  }
});
```

这只是 Vue Router 功能的冰山一角。更多高级用法，如嵌套路由、命名视图、过渡效果等，请查阅官方文档。 