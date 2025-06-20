# 状态管理: Pinia

Pinia 是 Vue 的官方推荐的状态管理库。它是一个轻量级、类型安全且易于使用的状态管理解决方案，专为 Vue 3 和 Composition API 设计。

## 核心概念

-   **Store**: 一个包含状态和业务逻辑的实体，类似于一个组件。每个 store 都是独立和模块化的。
-   **State**: 定义 store 的数据 (类似于组件的 `data`)。
-   **Getters**: 计算属性 (类似于组件的 `computed`)，用于从 state 中派生出新的状态。
-   **Actions**: 方法 (类似于组件的 `methods`)，用于修改 state。Actions 可以是异步的。

## 安装

```bash
npm install pinia
```

将 Pinia 插件安装到 Vue 应用中：

```javascript
// main.js
import { createApp } from 'vue';
import { createPinia } from 'pinia';
import App from './App.vue';

const app = createApp(App);

app.use(createPinia());
app.mount('#app');
```

## 创建和使用 Store

你可以定义任意数量的 store。建议将 store 放在一个单独的 `stores` 目录中。

### 定义 Store

```javascript
// stores/counter.js
import { defineStore } from 'pinia';

export const useCounterStore = defineStore('counter', {
  state: () => ({
    count: 0,
    name: 'Eduardo',
  }),
  getters: {
    doubleCount: (state) => state.count * 2,
  },
  actions: {
    increment() {
      this.count++;
    },
    randomizeCounter() {
      this.count = Math.round(100 * Math.random());
    },
  },
});
```

### 在组件中使用 Store

在任何组件中，你都可以导入并使用这个 store。

```vue
<template>
  <div>
    <p>Count: {{ counter.count }}</p>
    <p>Double Count: {{ counter.doubleCount }}</p>
    <button @click="counter.increment">Increment</button>
  </div>
</template>

<script setup>
import { useCounterStore } from '@/stores/counter';

const counter = useCounterStore();
</script>
```

## 访问 State、Getters 和 Actions

-   **直接访问**: 如上例所示，你可以直接从 store 实例中读取 state 和 getters，并调用 actions。
-   **解构**: 为了保持响应性，当你从 store 中解构属性时，需要使用 `storeToRefs`。

```vue
<script setup>
import { storeToRefs } from 'pinia';
import { useCounterStore } from '@/stores/counter';

const counterStore = useCounterStore();

// `storeToRefs` 将为 state 和 getters 创建 refs
const { count, doubleCount } = storeToRefs(counterStore);
const { increment } = counterStore; // Actions 可以直接解构
</script>
```

Pinia 的设计理念是提供一个简单、直观且强大的 API，让你能够以一种有组织的方式管理你的应用状态。它的模块化特性和对 TypeScript 的出色支持使其成为现代 Vue 应用的首选。 