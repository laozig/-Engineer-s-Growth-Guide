# 20. TypeScript 集成

Vue 3 是用 TypeScript 编写的，因此它提供了出色的 TypeScript 支持。通过将 TypeScript 与 Vue 结合使用，你可以获得更好的开发体验，包括类型检查、IDE 智能提示和更可靠的代码重构能力。

## 项目设置

### 创建一个支持 TypeScript 的 Vue 项目

使用 `create-vue` 创建新项目时，可以选择 TypeScript 支持：

```bash
npm create vue@latest

# 在提示中选择 TypeScript 支持
# ✓ Add TypeScript? Yes
```

### 向现有项目添加 TypeScript

如果你有一个现有的 Vue 项目想要添加 TypeScript 支持，可以按照以下步骤操作：

1. 安装所需依赖：

```bash
npm install -D typescript @vue/tsconfig @types/node
```

2. 创建 `tsconfig.json` 文件：

```json
{
  "extends": "@vue/tsconfig/tsconfig.web.json",
  "include": ["env.d.ts", "src/**/*", "src/**/*.vue"],
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "references": [
    {
      "path": "./tsconfig.config.json"
    }
  ]
}
```

3. 创建 `tsconfig.config.json` 文件：

```json
{
  "extends": "@vue/tsconfig/tsconfig.node.json",
  "include": ["vite.config.*", "vitest.config.*", "cypress.config.*"],
  "compilerOptions": {
    "composite": true,
    "types": ["node"]
  }
}
```

4. 创建 `env.d.ts` 文件以提供 `.vue` 文件的类型定义：

```typescript
/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}
```

## 组件中使用 TypeScript

### 在 `<script setup>` 中使用 TypeScript

在单文件组件 (SFC) 中，可以在 `<script setup>` 中使用 TypeScript：

```vue
<script setup lang="ts">
import { ref } from 'vue'

// 定义类型
interface User {
  id: number
  name: string
  email: string
}

// 使用类型
const user = ref<User>({
  id: 1,
  name: 'John Doe',
  email: 'john@example.com'
})

// 带类型的函数
function greet(name: string): string {
  return `Hello, ${name}!`
}
</script>

<template>
  <div>
    <h1>{{ greet(user.name) }}</h1>
    <p>Email: {{ user.email }}</p>
  </div>
</template>
```

### Props 类型定义

使用 `defineProps` 宏可以在 `<script setup>` 中定义带类型的 props：

```vue
<script setup lang="ts">
// 方式 1: 使用类型声明
const props = defineProps<{
  title: string
  likes?: number // 可选 prop
  author: {
    name: string
    bio?: string
  }
  callback: (id: number) => void
}>()

// 方式 2: 使用运行时验证 + 类型推断
// const props = defineProps({
//   title: {
//     type: String,
//     required: true
//   },
//   likes: Number,
//   author: {
//     type: Object,
//     required: true
//   },
//   callback: {
//     type: Function,
//     required: true
//   }
// })
</script>
```

### 默认 Props 值

要为使用类型声明的 props 提供默认值，需要使用 `withDefaults` 编译器宏：

```vue
<script setup lang="ts">
interface Props {
  title?: string
  likes?: number
}

const props = withDefaults(defineProps<Props>(), {
  title: 'Default Title',
  likes: 0
})
</script>
```

### Emits 类型定义

同样，可以使用类型声明为 `defineEmits` 提供类型：

```vue
<script setup lang="ts">
// 定义发出的事件及其参数类型
const emit = defineEmits<{
  (e: 'change', id: number): void
  (e: 'update', value: string): void
}>()

// 发出事件
function onChange() {
  emit('change', 1)
  emit('update', 'new value')
}
</script>
```

## 响应式 API 与 TypeScript

### `ref` 和 `reactive`

`ref` 和 `reactive` 在 TypeScript 中可以推断大多数类型，但有时需要显式指定：

```ts
import { ref, reactive } from 'vue'

// 推断为 Ref<number>
const count = ref(0)

// 显式指定复杂类型
interface User {
  name: string
  age: number
}

// 推断为 Ref<User | null>
const user = ref<User | null>(null)

// 推断为 User
const userState = reactive<User>({
  name: 'John',
  age: 30
})
```

### 计算属性类型

计算属性会自动推断其返回类型：

```ts
import { ref, computed } from 'vue'

const count = ref(0)

// 推断为 ComputedRef<number>
const doubleCount = computed(() => count.value * 2)

// 显式指定类型
const doubleCountTyped = computed<number>(() => {
  // 需要返回 number 类型
  return count.value * 2
})
```

## 类型化的组合式函数 (Composables)

组合式函数是 Vue 中复用逻辑的主要方式，在 TypeScript 中使用它们可以获得很好的类型安全：

```ts
// useUser.ts
import { ref } from 'vue'

interface User {
  id: number
  name: string
  email: string
}

export function useUser(userId: number) {
  const user = ref<User | null>(null)
  const loading = ref(true)
  const error = ref<Error | null>(null)

  const fetchUser = async () => {
    loading.value = true
    try {
      // 假设这是一个 API 调用
      const response = await fetch(`/api/users/${userId}`)
      user.value = await response.json()
    } catch (e) {
      error.value = e as Error
    } finally {
      loading.value = false
    }
  }

  return {
    user,
    loading,
    error,
    fetchUser
  }
}
```

然后在组件中使用：

```vue
<script setup lang="ts">
import { useUser } from './composables/useUser'

const { user, loading, error, fetchUser } = useUser(1)

// 调用时会自动触发获取用户数据
fetchUser()
</script>

<template>
  <div v-if="loading">Loading...</div>
  <div v-else-if="error">Error: {{ error.message }}</div>
  <div v-else-if="user">
    <h1>{{ user.name }}</h1>
    <p>{{ user.email }}</p>
  </div>
</template>
```

## 扩展全局属性

如果你需要扩展 Vue 的全局属性（例如添加自定义属性到 `this` 或全局组件），可以使用模块扩展：

```ts
// typings.d.ts
import { ComponentCustomProperties } from 'vue'

declare module 'vue' {
  interface ComponentCustomProperties {
    $translate: (key: string) => string
    $api: {
      get: (url: string) => Promise<any>
      post: (url: string, data: any) => Promise<any>
    }
  }
}

// 必须导出，这样才是一个模块声明文件而不是一个脚本文件
export {}
```

## 插件与类型

创建带类型的 Vue 插件：

```ts
// plugins/i18n.ts
import { App, Plugin } from 'vue'

interface I18nOptions {
  locale?: string
  messages?: Record<string, Record<string, string>>
}

export const i18nPlugin: Plugin = {
  install(app: App, options: I18nOptions = {}) {
    const locale = options.locale || 'en'
    const messages = options.messages || {}

    app.config.globalProperties.$translate = (key: string): string => {
      return messages[locale]?.[key] || key
    }

    app.provide('i18n', {
      locale,
      messages,
      translate: (key: string): string => {
        return messages[locale]?.[key] || key
      }
    })
  }
}
```

## 最佳实践

1. **使用 `<script setup lang="ts">`**：提供最简洁的类型支持。

2. **利用类型推断**：让 TypeScript 尽可能地推断类型，只在必要时显式指定。

3. **使用接口而非类型别名**：接口通常更适合 Vue 的对象和组件 API。

4. **组织类型定义**：考虑将复杂或共享的类型放在单独的文件中。

5. **使用 `strictNullChecks` 选项**：启用此选项可以捕获更多潜在错误。

通过将 TypeScript 与 Vue 结合使用，你可以构建更稳健、更可维护的应用程序，同时提高开发效率。 