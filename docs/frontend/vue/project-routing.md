# 项目实战：路由实现 - 任务过滤与视图切换

在前面的章节中，我们已经实现了待办事项应用的核心功能和状态管理。本章将重点介绍如何使用Vue Router来实现任务过滤和视图切换功能，让用户可以方便地查看不同状态的任务。

## 1. Vue Router 简介

[Vue Router](https://router.vuejs.org/) 是Vue.js官方的路由管理器。它与Vue.js核心深度集成，让构建单页面应用变得轻而易举。主要功能包括：

- 嵌套路由映射
- 动态路由选择
- 模块化、基于组件的路由配置
- 路由参数、查询、通配符
- 过渡效果
- 细粒度的导航控制
- 自动激活CSS类的链接

## 2. 回顾我们的路由配置

在项目脚手架搭建时，我们已经初步配置了路由。让我们回顾一下`src/router/index.js`的内容：

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

我们设置了三个路由：
- `/`: 显示所有任务
- `/active`: 只显示未完成的任务
- `/completed`: 只显示已完成的任务

注意我们使用了`props`选项将路由参数传递给组件，这是Vue Router的一个很好的实践，可以使组件与路由解耦。

## 3. 优化路由过滤功能

现在，让我们优化`TodoList.vue`组件，使其能够根据路由参数显示不同的任务：

```vue
<template>
  <div class="todo-list">
    <p v-if="filteredTodos.length === 0" class="empty-list">
      {{ emptyMessage }}
    </p>
    <TodoItem 
      v-for="todo in filteredTodos" 
      :key="todo.id" 
      :todo="todo" 
    />
  </div>
</template>

<script setup>
import { computed } from 'vue'
import TodoItem from './TodoItem.vue'
import { useTodosStore } from '../store/todos'

const props = defineProps({
  filter: {
    type: String,
    default: 'all'
  }
})

const todosStore = useTodosStore()

// 使用store中的getTodosByFilter getter
const filteredTodos = computed(() => {
  return todosStore.getTodosByFilter(props.filter)
})

const emptyMessage = computed(() => {
  switch (props.filter) {
    case 'active':
      return '没有待完成的任务'
    case 'completed':
      return '没有已完成的任务'
    default:
      return '暂无任务，请添加新任务'
  }
})
</script>
```

## 4. 优化导航组件

我们已经在`TodoFooter.vue`中实现了基本的导航链接，但现在让我们进一步优化它，添加一些交互效果：

```vue
<template>
  <div v-if="todosStore.totalCount > 0" class="todo-footer">
    <span class="todo-count">
      <strong>{{ todosStore.activeCount }}</strong> 项待办
    </span>
    <ul class="filters">
      <li>
        <router-link to="/" exact>全部</router-link>
      </li>
      <li>
        <router-link to="/active">进行中</router-link>
      </li>
      <li>
        <router-link to="/completed">已完成</router-link>
      </li>
    </ul>
    <button 
      v-if="todosStore.completedCount > 0" 
      class="clear-completed"
      @click="todosStore.clearCompleted"
    >
      清除已完成
    </button>
  </div>
</template>

<script setup>
import { useTodosStore } from '../store/todos'
import { useRoute } from 'vue-router'

const todosStore = useTodosStore()
const route = useRoute()
</script>

<style scoped>
.todo-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px;
  border-top: 1px solid #e6e6e6;
  color: #777;
  font-size: 14px;
}

.todo-count {
  flex: 1;
}

.filters {
  display: flex;
  list-style: none;
  margin: 0;
  padding: 0;
}

.filters li {
  margin: 0 5px;
}

.filters a {
  color: inherit;
  text-decoration: none;
  padding: 3px 7px;
  border-radius: 3px;
  transition: all 0.3s ease;
}

.filters a:hover {
  border-color: rgba(175, 47, 47, 0.1);
}

.filters a.active {
  border: 1px solid rgba(175, 47, 47, 0.2);
}

.clear-completed {
  background: none;
  border: none;
  color: #777;
  cursor: pointer;
  transition: color 0.3s ease;
}

.clear-completed:hover {
  color: #333;
}
</style>
```

## 5. 使用编程式导航

除了使用`<router-link>`进行声明式导航外，我们还可以使用编程式导航。例如，我们可以在任务完成后自动跳转到相应的视图：

```js
import { useRouter } from 'vue-router'

const router = useRouter()

function handleTaskComplete(todo) {
  todosStore.toggleTodo(todo.id)
  
  // 如果当前在"进行中"视图，且任务被标记为完成，则自动跳转到"全部"视图
  if (route.path === '/active' && todo.completed) {
    router.push('/')
  }
}
```

## 6. 路由守卫

Vue Router提供了强大的导航守卫功能，可以用来控制导航行为。例如，我们可以添加一个全局前置守卫，在用户访问应用时记录访问日志：

```js
// src/router/index.js
router.beforeEach((to, from) => {
  console.log(`从 ${from.path} 导航到 ${to.path}`)
  // 可以在这里添加分析代码或权限检查
  return true // 允许导航继续
})
```

## 7. 路由元信息

我们还可以给路由添加元信息，用于存储与路由相关的自定义数据：

```js
const routes = [
  {
    path: '/',
    name: 'home',
    component: HomeView,
    meta: { 
      title: '全部任务',
      requiresAuth: false
    }
  },
  {
    path: '/active',
    name: 'active',
    component: HomeView,
    props: { filter: 'active' },
    meta: { 
      title: '进行中任务',
      requiresAuth: false
    }
  },
  {
    path: '/completed',
    name: 'completed',
    component: HomeView,
    props: { filter: 'completed' },
    meta: { 
      title: '已完成任务',
      requiresAuth: false
    }
  }
]
```

然后可以使用路由守卫动态设置页面标题：

```js
router.beforeEach((to, from) => {
  // 设置文档标题
  document.title = to.meta.title ? `${to.meta.title} - Todo App` : 'Todo App'
  return true
})
```

## 8. 路由懒加载

在大型应用中，我们可能希望将路由组件分割成不同的代码块，然后在路由被访问时才加载相应组件。这可以通过Vue Router的动态导入功能实现：

```js
const routes = [
  {
    path: '/',
    name: 'home',
    component: () => import('../views/HomeView.vue')
  },
  {
    path: '/active',
    name: 'active',
    component: () => import('../views/HomeView.vue'),
    props: { filter: 'active' }
  },
  {
    path: '/completed',
    name: 'completed',
    component: () => import('../views/HomeView.vue'),
    props: { filter: 'completed' }
  }
]
```

不过，对于我们的小型待办事项应用，这种优化可能不是必要的。

## 9. 处理404页面

最后，让我们添加一个404页面，处理用户访问不存在的路由的情况：

1. 创建`src/views/NotFoundView.vue`：

```vue
<template>
  <div class="not-found">
    <h1>404</h1>
    <p>页面不存在</p>
    <router-link to="/">返回首页</router-link>
  </div>
</template>

<style scoped>
.not-found {
  text-align: center;
  padding: 50px 20px;
}

h1 {
  font-size: 72px;
  color: #e74c3c;
  margin-bottom: 20px;
}

p {
  font-size: 24px;
  margin-bottom: 30px;
}

a {
  color: #3498db;
  text-decoration: none;
  padding: 10px 20px;
  border: 1px solid #3498db;
  border-radius: 4px;
  transition: all 0.3s;
}

a:hover {
  background-color: #3498db;
  color: white;
}
</style>
```

2. 在路由配置中添加通配符路由：

```js
const routes = [
  // ... 其他路由
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('../views/NotFoundView.vue'),
    meta: { title: '页面不存在' }
  }
]
```

## 10. 测试路由功能

现在我们已经完成了路由的实现，让我们启动应用并测试以下功能：

1. 点击不同的过滤器链接，查看任务列表是否正确过滤
2. 添加新任务，查看任务是否显示在正确的过滤视图中
3. 完成任务，查看任务是否从"进行中"视图中移除
4. 访问不存在的路由，查看404页面是否正确显示

```bash
npm run dev
```

## 总结

在本章中，我们学习了如何使用Vue Router实现任务过滤和视图切换功能：

1. 配置基本路由
2. 使用路由参数过滤任务
3. 实现导航组件
4. 使用编程式导航
5. 添加路由守卫和元信息
6. 处理404页面

通过这些技术，我们的待办事项应用现在具有了完整的路由功能，用户可以方便地在不同视图之间切换。在下一章中，我们将探讨 **[组件重构与代码优化](project-refactoring.md)**。
