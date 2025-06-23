# 22. 高级状态管理模式

在复杂的 Vue 应用中，状态管理是一个核心挑战。本文将深入探讨 Vue 生态系统中的高级状态管理模式，包括响应式 API、Pinia 和 Vuex 的深入使用，以及处理复杂状态的策略。

## 原生响应式 API 进行状态管理

Vue 3 的响应式 API 可以用于创建简单的状态管理解决方案，适用于中小型应用。

### 使用 `reactive` 和 `provide/inject`

```js
// store/counter.js
import { reactive, readonly } from 'vue'

// 创建状态
const state = reactive({
  count: 0,
  history: []
})

// 创建操作方法
const actions = {
  increment() {
    state.count++
    state.history.push(`增加到 ${state.count}`)
  },
  decrement() {
    state.count--
    state.history.push(`减少到 ${state.count}`)
  },
  reset() {
    state.count = 0
    state.history = []
  }
}

// 导出只读状态和操作
export function useCounterStore() {
  return {
    state: readonly(state), // 防止组件直接修改状态
    ...actions
  }
}
```

使用 `provide/inject` 在应用中共享状态：

```vue
<!-- App.vue -->
<script setup>
import { provide } from 'vue'
import { useCounterStore } from './store/counter'

// 提供状态给整个应用
provide('counterStore', useCounterStore())
</script>
```

在任何组件中使用：

```vue
<script setup>
import { inject } from 'vue'

// 获取状态
const { state, increment, decrement, reset } = inject('counterStore')
</script>

<template>
  <div>
    <p>计数：{{ state.count }}</p>
    <button @click="increment">+</button>
    <button @click="decrement">-</button>
    <button @click="reset">重置</button>
    
    <h3>历史记录：</h3>
    <ul>
      <li v-for="(entry, index) in state.history" :key="index">
        {{ entry }}
      </li>
    </ul>
  </div>
</template>
```

## Pinia 深入使用

Pinia 是 Vue 的官方状态管理库，提供了简单、类型安全的 API。

### 组织复杂状态

对于大型应用，可以将 Pinia store 按功能域分组：

```
src/
  stores/
    auth/
      index.js     # 主认证 store
      session.js   # 会话管理
      permissions.js # 权限相关
    products/
      index.js     # 产品列表
      categories.js # 分类
      filters.js   # 筛选器
    ui/
      theme.js     # 主题设置
      notifications.js # 通知系统
```

### 组合多个 Store

Pinia 的强大之处在于 store 之间可以相互使用：

```js
// stores/auth/index.js
import { defineStore } from 'pinia'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    token: null,
    isLoggedIn: false
  }),
  actions: {
    async login(username, password) {
      // 登录逻辑...
      this.user = { id: 1, username, role: 'admin' }
      this.token = 'sample-token'
      this.isLoggedIn = true
    },
    logout() {
      this.user = null
      this.token = null
      this.isLoggedIn = false
    }
  }
})
```

```js
// stores/products/index.js
import { defineStore } from 'pinia'
import { useAuthStore } from '../auth'

export const useProductStore = defineStore('products', {
  state: () => ({
    list: [],
    loading: false
  }),
  actions: {
    async fetchProducts() {
      const authStore = useAuthStore()
      
      // 检查是否登录
      if (!authStore.isLoggedIn) {
        throw new Error('用户未登录')
      }
      
      this.loading = true
      try {
        // 使用 auth store 中的 token
        const response = await fetch('/api/products', {
          headers: {
            'Authorization': `Bearer ${authStore.token}`
          }
        })
        this.list = await response.json()
      } finally {
        this.loading = false
      }
    }
  }
})
```

### 使用 `$subscribe` 监听状态变化

Pinia 提供了 `$subscribe` 方法来监听状态变化：

```js
import { useProductStore } from '@/stores/products'

const productStore = useProductStore()

// 监听状态变化
productStore.$subscribe((mutation, state) => {
  // mutation 包含了 type, storeId, events 等信息
  console.log(`Store ${mutation.storeId} 被修改`, mutation.type)
  
  // 可以保存状态到本地存储
  localStorage.setItem('products', JSON.stringify(state))
})
```

## Vuex 与 Pinia 对比

对于已经使用 Vuex 的项目，了解两者的差异可以帮助决定是否迁移。

### 主要区别

1. **架构**：
   - Vuex 使用单一 store 和模块系统
   - Pinia 使用多个独立 store

2. **类型支持**：
   - Pinia 对 TypeScript 的支持更好，几乎不需要类型定义
   - Vuex 需要大量的类型定义和类型断言

3. **API 设计**：
   - Vuex 使用 mutations 来修改状态，需要遵循特定的模式
   - Pinia 允许直接修改状态，无需 mutations

### 从 Vuex 迁移到 Pinia

迁移示例：

```js
// Vuex 模块
// store/modules/counter.js
export default {
  namespaced: true,
  state: {
    count: 0
  },
  getters: {
    doubleCount: (state) => state.count * 2
  },
  mutations: {
    INCREMENT(state) {
      state.count++
    },
    DECREMENT(state) {
      state.count--
    }
  },
  actions: {
    incrementAsync({ commit }) {
      setTimeout(() => {
        commit('INCREMENT')
      }, 1000)
    }
  }
}
```

转换为 Pinia store：

```js
// stores/counter.js
import { defineStore } from 'pinia'

export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0
  }),
  getters: {
    doubleCount: (state) => state.count * 2
  },
  actions: {
    increment() {
      this.count++
    },
    decrement() {
      this.count--
    },
    incrementAsync() {
      return new Promise((resolve) => {
        setTimeout(() => {
          this.increment()
          resolve()
        }, 1000)
      })
    }
  }
})
```

## 状态持久化

### 使用本地存储持久化状态

使用 `pinia-plugin-persistedstate` 库：

```bash
npm install pinia-plugin-persistedstate
```

```js
// main.js
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'
import App from './App.vue'

const pinia = createPinia()
pinia.use(piniaPluginPersistedstate)

createApp(App).use(pinia).mount('#app')
```

在 store 中配置持久化：

```js
import { defineStore } from 'pinia'

export const useUserStore = defineStore('user', {
  state: () => ({
    preferences: {},
    sessionData: {}
  }),
  actions: {
    updatePreferences(prefs) {
      this.preferences = { ...this.preferences, ...prefs }
    }
  },
  // 持久化配置
  persist: {
    // 使用自定义名称
    key: 'user-store',
    // 只持久化某些状态
    paths: ['preferences'],
    // 使用 sessionStorage 而非 localStorage
    storage: sessionStorage,
    // 可以自定义序列化/反序列化
    serializer: {
      serialize: JSON.stringify,
      deserialize: JSON.parse
    }
  }
})
```

## 状态规范化

在处理复杂关系数据时，规范化状态是一种重要策略。

### 规范化复杂关系数据

```js
// 不规范化的数据
const unormalizedState = {
  posts: [
    {
      id: 1,
      title: '关于 Vue',
      content: '...',
      author: {
        id: 101,
        name: '张三',
        posts: [/* 可能会循环引用 */]
      },
      comments: [
        {
          id: 201,
          text: '很好的文章',
          author: {
            id: 102,
            name: '李四'
          }
        }
        // 更多评论...
      ]
    }
    // 更多文章...
  ]
}

// 规范化后的数据
const normalizedState = {
  posts: {
    byId: {
      1: {
        id: 1,
        title: '关于 Vue',
        content: '...',
        authorId: 101,
        commentIds: [201, 202]
      }
      // 更多文章...
    },
    allIds: [1, 2, 3]
  },
  authors: {
    byId: {
      101: {
        id: 101,
        name: '张三',
        postIds: [1, 2]
      },
      102: {
        id: 102,
        name: '李四',
        postIds: []
      }
    },
    allIds: [101, 102]
  },
  comments: {
    byId: {
      201: {
        id: 201,
        text: '很好的文章',
        authorId: 102,
        postId: 1
      }
      // 更多评论...
    },
    allIds: [201, 202]
  }
}
```

## 复杂应用架构

对于大型应用，可能需要更先进的状态管理架构。

### 领域驱动设计 (DDD) 与状态管理

将应用按业务域组织：

```
src/
  domains/
    auth/
      stores/     # 领域特定的 stores
      services/   # 业务逻辑服务
      components/ # 领域特定的组件
      
    products/
      stores/
      services/
      components/
      
    orders/
      stores/
      services/
      components/
```

### 使用服务层分离业务逻辑

```js
// domains/auth/services/authService.js
import { useAuthStore } from '../stores/auth'
import { useUserStore } from '../stores/user'

export function useAuthService() {
  const authStore = useAuthStore()
  const userStore = useUserStore()
  
  // 复杂业务逻辑
  async function login(username, password) {
    try {
      // 1. 执行登录
      const { token, refreshToken } = await authStore.login(username, password)
      
      // 2. 获取用户信息
      const userData = await userStore.fetchUserData(token)
      
      // 3. 设置初始权限
      await userStore.setPermissions(userData.permissions)
      
      return { success: true, userData }
    } catch (error) {
      // 统一错误处理
      console.error('Login failed:', error)
      return { success: false, error }
    }
  }
  
  return {
    login,
    // 其他服务方法...
  }
}
```

## 最佳实践与性能优化

### 避免大型单一 Store

将状态分解为多个功能域 store，每个 store 只关注其特定的责任。

### 精细控制组件更新

使用 Pinia 的 `storeToRefs` 来获取响应式引用，避免不必要的组件更新：

```vue
<script setup>
import { storeToRefs } from 'pinia'
import { useUserStore } from '@/stores/user'

const userStore = useUserStore()
// 使用 storeToRefs 解构，保持响应性
const { name, email, preferences } = storeToRefs(userStore)
// 动作可以直接解构
const { updateProfile, logout } = userStore
</script>
```

### 使用计算属性和记忆化

避免在模板中进行复杂计算，而是使用计算属性和记忆化：

```js
import { defineStore } from 'pinia'

export const useProductStore = defineStore('products', {
  state: () => ({
    items: [],
    filters: {
      category: null,
      minPrice: 0,
      maxPrice: 1000
    }
  }),
  getters: {
    // 过滤后的产品
    filteredProducts: (state) => {
      return state.items.filter(product => {
        const matchesCategory = !state.filters.category || 
                               product.category === state.filters.category
        const matchesPrice = product.price >= state.filters.minPrice && 
                            product.price <= state.filters.maxPrice
        return matchesCategory && matchesPrice
      })
    },
    // 记忆化函数：按类别获取产品
    getProductsByCategory: (state) => {
      // 创建记忆化缓存
      const cache = {}
      
      // 返回一个函数，接受类别参数
      return (category) => {
        // 检查缓存
        if (cache[category]) return cache[category]
        
        // 计算结果并缓存
        const result = state.items.filter(product => product.category === category)
        cache[category] = result
        return result
      }
    }
  }
})
```

## 总结

高级状态管理是构建复杂 Vue 应用的关键组成部分。通过组合使用 Vue 的响应式 API、Pinia 或 Vuex，以及适当的架构模式，可以有效管理从简单到复杂的应用状态。关键是选择适合你的应用规模和复杂性的解决方案，并坚持一致的模式。
 