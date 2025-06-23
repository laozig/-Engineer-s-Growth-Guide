# 项目实战：构建项目骨架与基础配置

在上一章中，我们完成了项目规划和技术选型。现在，让我们开始动手构建项目骨架并进行基础配置。

## 1. 创建项目

首先，使用Vite创建一个新的Vue 3项目：

```bash
# 使用npm
npm create vite@latest todo-app -- --template vue

# 或使用yarn
yarn create vite todo-app --template vue

# 或使用pnpm
pnpm create vite todo-app --template vue
```

创建完成后，进入项目目录并安装依赖：

```bash
cd todo-app
npm install
```

## 2. 添加路由和状态管理

安装Vue Router和Pinia：

```bash
npm install vue-router@4 pinia
```

## 3. 项目结构设置

按照我们的规划，创建必要的目录结构：

```bash
mkdir -p src/assets src/components src/router src/store src/views
```

## 4. 配置路由

创建`src/router/index.js`文件：

```js
import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'

const routes = [
  {
    path: '/',
    name: 'home',
    component: HomeView
  },
  {
    path: '/active',
    name: 'active',
    component: HomeView,
    props: { filter: 'active' }
  },
  {
    path: '/completed',
    name: 'completed',
    component: HomeView,
    props: { filter: 'completed' }
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  linkActiveClass: 'active'
})

export default router
```

## 5. 配置Pinia状态管理

创建`src/store/todos.js`文件：

```js
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export const useTodosStore = defineStore('todos', () => {
  // 状态
  const todos = ref([])
  
  // Getters
  const completedTodos = computed(() => todos.value.filter(todo => todo.completed))
  const activeTodos = computed(() => todos.value.filter(todo => !todo.completed))
  const totalCount = computed(() => todos.value.length)
  const activeCount = computed(() => activeTodos.value.length)
  const completedCount = computed(() => completedTodos.value.length)
  
  // Actions
  function addTodo(title) {
    if (!title.trim()) return
    todos.value.push({
      id: Date.now(),
      title,
      completed: false
    })
    saveTodos()
  }
  
  function removeTodo(id) {
    const index = todos.value.findIndex(todo => todo.id === id)
    if (index !== -1) {
      todos.value.splice(index, 1)
      saveTodos()
    }
  }
  
  function toggleTodo(id) {
    const todo = todos.value.find(todo => todo.id === id)
    if (todo) {
      todo.completed = !todo.completed
      saveTodos()
    }
  }
  
  function updateTodoTitle(id, title) {
    const todo = todos.value.find(todo => todo.id === id)
    if (todo && title.trim()) {
      todo.title = title
      saveTodos()
    }
  }
  
  function clearCompleted() {
    todos.value = todos.value.filter(todo => !todo.completed)
    saveTodos()
  }
  
  // 本地存储
  function loadTodos() {
    const savedTodos = localStorage.getItem('todos')
    if (savedTodos) {
      todos.value = JSON.parse(savedTodos)
    }
  }
  
  function saveTodos() {
    localStorage.setItem('todos', JSON.stringify(todos.value))
  }
  
  // 初始加载
  loadTodos()
  
  return {
    todos,
    completedTodos,
    activeTodos,
    totalCount,
    activeCount,
    completedCount,
    addTodo,
    removeTodo,
    toggleTodo,
    updateTodoTitle,
    clearCompleted
  }
})
```

## 6. 创建主视图组件

创建`src/views/HomeView.vue`文件：

```vue
<template>
  <div class="todo-app">
    <h1>待办事项</h1>
    <div class="container">
      <!-- 待办事项输入框将在下一章实现 -->
      <!-- 任务列表将在下一章实现 -->
      <!-- 过滤器将在路由章节实现 -->
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useTodosStore } from '../store/todos'
import { useRoute } from 'vue-router'

// 接收路由传递的props
const props = defineProps({
  filter: {
    type: String,
    default: 'all'
  }
})

const todosStore = useTodosStore()
const route = useRoute()

// 根据当前路由过滤任务
const currentFilter = computed(() => props.filter || route.name || 'all')
</script>

<style>
/* 基础样式 */
body {
  font-family: 'Arial', sans-serif;
  background-color: #f5f5f5;
  margin: 0;
  padding: 0;
}

.todo-app {
  max-width: 550px;
  margin: 0 auto;
  padding: 20px;
}

h1 {
  text-align: center;
  color: #333;
}

.container {
  background-color: white;
  border-radius: 8px;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  overflow: hidden;
}
</style>
```

## 7. 更新入口文件

修改`src/main.js`文件，集成路由和状态管理：

```js
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './assets/main.css'

const app = createApp(App)

app.use(createPinia())
app.use(router)

app.mount('#app')
```

## 8. 更新根组件

修改`src/App.vue`文件：

```vue
<template>
  <router-view />
</template>

<style>
/* 全局样式可以放在这里 */
</style>
```

## 9. 创建全局样式文件

创建`src/assets/main.css`文件：

```css
/* 重置样式 */
* {
  box-sizing: border-box;
  margin: 0;
  padding: 0;
}

body {
  font-family: 'Arial', sans-serif;
  line-height: 1.6;
  color: #333;
}

button {
  cursor: pointer;
  border: none;
  background: none;
}

input:focus, button:focus {
  outline: none;
}
```

## 10. 启动项目

现在我们已经完成了项目骨架的搭建和基础配置，可以启动项目进行验证：

```bash
npm run dev
```

访问 http://localhost:5173/ 应该能看到一个简单的页面，显示"待办事项"标题和一个空白容器。

## 下一步

现在我们已经搭建好了项目的基础结构，下一章将开始实现 **[核心功能：任务列表的增删改查](project-crud-operations.md)**。
