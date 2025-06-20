# 状态管理: Vuex (传统方案)

Vuex 是一个专为 Vue.js 应用程序开发的**状态管理模式 + 库**。它采用集中式存储管理应用的所有组件的状态，并以相应的规则保证状态以一种可预测的方式发生变化。

尽管 Pinia 现在是官方推荐的下一代状态管理库，但了解 Vuex 对于维护现有项目或理解 Vue 生态系统的演进仍然很有价值。

## 核心概念

Vuex 的核心由以下几部分组成：

-   **State**: 驱动应用的数据源，存储在单一对象中。
-   **Getters**: 允许组件从 Store 中获取派生状态，类似于计算属性。
-   **Mutations**: 更改 Vuex 的 store 中的状态的唯一方法是提交 mutation。每个 mutation 都有一个字符串的 **事件类型 (type)** 和一个 **回调函数 (handler)**。
-   **Actions**: Action 类似于 mutation，不同在于：
    -   Action 提交的是 mutation，而不是直接变更状态。
    -   Action 可以包含任意异步操作。
-   **Modules**: 允许我们将 store 分割成模块。每个模块拥有自己的 state、mutation、action、getter。

## 安装与配置

```bash
npm install vuex@4
```

在 `main.js` 中创建和使用 Vuex store：

```javascript
// main.js
import { createApp } from 'vue';
import { createStore } from 'vuex';
import App from './App.vue';

// 创建一个新的 store 实例
const store = createStore({
  state() {
    return {
      count: 0,
    };
  },
  mutations: {
    increment(state) {
      state.count++;
    },
    incrementBy(state, payload) {
      state.count += payload.amount;
    }
  },
  actions: {
    incrementAsync({ commit }) {
      setTimeout(() => {
        commit('increment');
      }, 1000);
    },
  },
  getters: {
    doubleCount(state) {
      return state.count * 2;
    }
  }
});

const app = createApp(App);
app.use(store);
app.mount('#app');
```

## 在组件中使用

### 访问 State 和 Getters

你可以使用 `this.$store.state` 来访问 state，或使用 `this.$store.getters` 访问 getters。在 Composition API 中，可以使用 `useStore` 钩子。

```vue
<template>
  <p>Count: {{ $store.state.count }}</p>
  <p>Double Count: {{ $store.getters.doubleCount }}</p>
</template>
```

### 提交 Mutations 和分发 Actions

使用 `this.$store.commit` 来提交 mutation，或使用 `this.$store.dispatch` 来分发 action。

```vue
<template>
  <button @click="$store.commit('increment')">Increment</button>
  <button @click="$store.dispatch('incrementAsync')">Increment Async</button>
</template>
```

### `mapState`, `mapGetters`, `mapActions`, `mapMutations`

为了方便，Vuex 提供了辅助函数，可以将 store 中的 state、getters、actions 和 mutations 映射到组件的局部计算属性和方法中。

```vue
import { mapState, mapActions } from 'vuex';

export default {
  computed: {
    ...mapState(['count'])
  },
  methods: {
    ...mapActions(['incrementAsync'])
  }
}
```

Vuex 曾经是 Vue 生态系统不可或缺的一部分，它引入的单向数据流和可预测状态管理的概念对许多大型应用至关重要。虽然 Pinia 提供了更简单的 API 和更好的 TypeScript 支持，但 Vuex 的核心思想仍然具有影响力。 