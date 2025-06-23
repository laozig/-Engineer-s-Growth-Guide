# 项目实战：状态管理 - 使用 Pinia 管理应用状态

在之前的章节中，我们已经实现了待办事项应用的基本功能，并在创建项目骨架时简单配置了Pinia状态管理。本章将深入探讨如何使用Pinia有效地管理应用状态，并进一步优化我们的状态管理代码。

## 1. Pinia 简介

[Pinia](https://pinia.vuejs.org/) 是Vue官方推荐的新一代状态管理库，它具有以下优势：

- 直观简单的API设计
- 完整的TypeScript支持
- 基于Vue 3的响应式系统
- 开发工具支持（Vue DevTools集成）
- 模块化设计，无需手动注册模块
- 极轻量级（约1KB）

## 2. 重新审视我们的状态管理需求

在待办事项应用中，我们需要管理的状态主要包括：

- 任务列表数据
- 任务的过滤状态
- 任务的增删改查操作
- 数据持久化

## 3. 优化 Todos Store

让我们重新审视并优化我们在`src/store/todos.js`中的代码：

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
  
  // 根据过滤条件获取任务
  const getTodosByFilter = computed(() => {
    return (filter) => {
      switch (filter) {
        case 'active':
          return activeTodos.value
        case 'completed':
          return completedTodos.value
        default:
          return todos.value
      }
    }
  })
  
  // Actions
  function addTodo(title) {
    const trimmedTitle = title.trim()
    if (!trimmedTitle) return
    
    todos.value.push({
      id: Date.now(),
      title: trimmedTitle,
      completed: false,
      createdAt: new Date().toISOString()
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
    const trimmedTitle = title.trim()
    if (!trimmedTitle) return
    
    const todo = todos.value.find(todo => todo.id === id)
    if (todo) {
      todo.title = trimmedTitle
      todo.updatedAt = new Date().toISOString()
      saveTodos()
    }
  }
  
  function clearCompleted() {
    todos.value = todos.value.filter(todo => !todo.completed)
    saveTodos()
  }
  
  // 本地存储
  function loadTodos() {
    try {
      const savedTodos = localStorage.getItem('todos')
      if (savedTodos) {
        todos.value = JSON.parse(savedTodos)
      }
    } catch (e) {
      console.error('Error loading todos from localStorage:', e)
    }
  }
  
  function saveTodos() {
    try {
      localStorage.setItem('todos', JSON.stringify(todos.value))
    } catch (e) {
      console.error('Error saving todos to localStorage:', e)
    }
  }
  
  // 初始加载
  loadTodos()
  
  return {
    // 状态
    todos,
    // Getters
    completedTodos,
    activeTodos,
    totalCount,
    activeCount,
    completedCount,
    getTodosByFilter,
    // Actions
    addTodo,
    removeTodo,
    toggleTodo,
    updateTodoTitle,
    clearCompleted
  }
})
```

## 4. 使用 Pinia 的高级功能

### 4.1 Store 之间的相互调用

在复杂应用中，我们可能需要在一个 store 中调用另一个 store 的 action。Pinia 使这变得非常简单：

```js
import { useAnotherStore } from './anotherStore'

export const useMainStore = defineStore('main', () => {
  // 在action中使用另一个store
  function someAction() {
    const anotherStore = useAnotherStore()
    anotherStore.someAction()
  }
  
  return {
    someAction
  }
})
```

### 4.2 使用插件扩展 Pinia 功能

Pinia 支持插件系统，可以扩展 store 的功能。例如，我们可以创建一个简单的插件来自动记录所有 action 的调用：

```js
// src/store/plugins/logger.js
export function loggerPlugin({ store }) {
  // 保存原始actions
  const actions = {}
  for (const actionName in store.$actions) {
    actions[actionName] = store[actionName]
    
    // 重写action，添加日志
    store[actionName] = async (...args) => {
      console.log(`[${store.$id}] 调用 ${actionName}`, args)
      const result = await actions[actionName].apply(store, args)
      console.log(`[${store.$id}] ${actionName} 结果:`, result)
      return result
    }
  }
}
```

然后在创建 Pinia 实例时使用这个插件：

```js
// src/main.js
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { loggerPlugin } from './store/plugins/logger'
import App from './App.vue'

const pinia = createPinia()
pinia.use(loggerPlugin)

const app = createApp(App)
app.use(pinia)
app.mount('#app')
```

### 4.3 创建持久化插件

我们可以创建一个更通用的持久化插件，而不是在每个 store 中手动实现：

```js
// src/store/plugins/persistedState.js
export function createPersistedState({
  key = 'pinia',
  paths = null,
  storage = localStorage
} = {}) {
  return ({ store }) => {
    // 从storage中恢复状态
    const fromStorage = storage.getItem(getStoreKey(store.$id, key))
    if (fromStorage) {
      store.$patch(JSON.parse(fromStorage))
    }
    
    // 监听状态变化，保存到storage
    store.$subscribe(
      (mutation, state) => {
        let toStore = state
        
        // 如果指定了paths，只保存这些路径的状态
        if (paths) {
          toStore = {}
          paths.forEach(path => {
            const pathParts = path.split('.')
            let value = state
            let valid = true
            
            // 遍历路径获取值
            for (const part of pathParts) {
              if (value[part] === undefined) {
                valid = false
                break
              }
              value = value[part]
            }
            
            if (valid) {
              // 设置嵌套路径值
              let target = toStore
              for (let i = 0; i < pathParts.length - 1; i++) {
                const part = pathParts[i]
                target[part] = target[part] || {}
                target = target[part]
              }
              target[pathParts[pathParts.length - 1]] = value
            }
          })
        }
        
        // 保存到storage
        try {
          storage.setItem(
            getStoreKey(store.$id, key),
            JSON.stringify(toStore)
          )
        } catch (e) {
          console.error('Error saving state to storage:', e)
        }
      },
      { detached: true }
    )
  }
}

function getStoreKey(id, key) {
  return `${key}-${id}`
}
```

使用这个插件：

```js
// src/main.js
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createPersistedState } from './store/plugins/persistedState'
import App from './App.vue'

const pinia = createPinia()
pinia.use(createPersistedState())

const app = createApp(App)
app.use(pinia)
app.mount('#app')
```

然后我们可以简化 todos store，移除手动持久化代码：

```js
// src/store/todos.js (简化版)
import { defineStore } from 'pinia'
import { ref, computed } from 'vue'

export const useTodosStore = defineStore('todos', () => {
  const todos = ref([])
  
  // Getters
  const completedTodos = computed(() => todos.value.filter(todo => todo.completed))
  const activeTodos = computed(() => todos.value.filter(todo => !todo.completed))
  const totalCount = computed(() => todos.value.length)
  const activeCount = computed(() => activeTodos.value.length)
  const completedCount = computed(() => completedTodos.value.length)
  
  // Actions
  function addTodo(title) {
    const trimmedTitle = title.trim()
    if (!trimmedTitle) return
    
    todos.value.push({
      id: Date.now(),
      title: trimmedTitle,
      completed: false,
      createdAt: new Date().toISOString()
    })
  }
  
  function removeTodo(id) {
    const index = todos.value.findIndex(todo => todo.id === id)
    if (index !== -1) {
      todos.value.splice(index, 1)
    }
  }
  
  function toggleTodo(id) {
    const todo = todos.value.find(todo => todo.id === id)
    if (todo) {
      todo.completed = !todo.completed
    }
  }
  
  function updateTodoTitle(id, title) {
    const trimmedTitle = title.trim()
    if (!trimmedTitle) return
    
    const todo = todos.value.find(todo => todo.id === id)
    if (todo) {
      todo.title = trimmedTitle
      todo.updatedAt = new Date().toISOString()
    }
  }
  
  function clearCompleted() {
    todos.value = todos.value.filter(todo => !todo.completed)
  }
  
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

## 5. 在组件中使用 Store

在组件中使用 Pinia store 非常简单。以下是一些最佳实践：

### 5.1 在 setup 函数中使用 store

```vue
<script setup>
import { useTodosStore } from '../store/todos'

const todosStore = useTodosStore()

// 直接访问状态
console.log(todosStore.todos)

// 使用 getters
console.log(todosStore.activeCount)

// 调用 actions
function handleAddTodo(title) {
  todosStore.addTodo(title)
}
</script>
```

### 5.2 解构 store（使用 storeToRefs）

如果你想解构 store 中的属性，应该使用 `storeToRefs` 函数来保持响应性：

```vue
<script setup>
import { storeToRefs } from 'pinia'
import { useTodosStore } from '../store/todos'

const todosStore = useTodosStore()
// 使用 storeToRefs 保持响应性
const { todos, activeCount, completedCount } = storeToRefs(todosStore)
// actions 可以直接解构
const { addTodo, removeTodo, toggleTodo } = todosStore
</script>
```

### 5.3 在计算属性中使用 store

```vue
<script setup>
import { computed } from 'vue'
import { useTodosStore } from '../store/todos'

const todosStore = useTodosStore()

// 基于 store 创建计算属性
const hasTodos = computed(() => todosStore.totalCount > 0)
const allCompleted = computed(() => todosStore.activeCount === 0 && todosStore.totalCount > 0)
</script>
```

## 6. 调试 Pinia Store

Pinia 与 Vue DevTools 集成，使调试变得简单：

1. 安装 [Vue DevTools 浏览器扩展](https://devtools.vuejs.org/guide/installation.html)
2. 在开发过程中打开 DevTools
3. 切换到 "Pinia" 选项卡
4. 你可以：
   - 查看所有 store 的当前状态
   - 查看 action 调用的时间线
   - 查看状态变化的历史
   - 手动修改状态进行测试

## 7. 总结

在本章中，我们深入探讨了如何使用 Pinia 有效管理 Vue 应用的状态：

1. 使用 Composition API 风格的 store 定义
2. 创建和使用 getters 和 actions
3. 实现数据持久化
4. 使用 Pinia 插件扩展功能
5. 在组件中高效地使用 store
6. 调试 Pinia store

通过这些技术，我们的待办事项应用现在有了一个强大、可维护的状态管理系统。在下一章中，我们将探讨 **[路由实现：任务过滤与视图切换](project-routing.md)**。
