# 14. 状态管理: MobX / Zustand (现代轻量级方案)

虽然 Redux (特别是 Redux Toolkit) 是一个非常强大和成熟的状态管理方案，但对于某些项目或开发者来说，它可能显得过于复杂或"重"。社区中也涌现出了许多其他优秀的状态管理库，它们提供了不同的范式和更简洁的 API。

本章我们介绍两个流行的现代状态管理库：**MobX** 和 **Zustand**。

## MobX: 简单、可扩展的状态管理

MobX 的核心思想是：**任何源于应用状态的东西都应该自动地获得。**

它通过**响应式 (Reactivity)** 的方式工作。你定义你的**可观察状态 (observable state)**，当这些状态变化时，所有依赖于它们的**观察者 (observers)**（例如 React 组件）都会自动更新。

### MobX 的核心概念

- **Observable State (可观察状态)**: 你希望跟踪的任何数据（对象、数组、原始类型）。MobX 会将它们转换成响应式的。
- **Action (动作)**: 任何修改 `state` 的代码。将修改逻辑包裹在 `action` 中可以帮助 MobX 更好地优化和追踪变更。
- **Computed Value (计算值)**: 根据现有 `state` 派生出的值。MobX 会缓存它们，只有当其依赖的 `state` 改变时才会重新计算。
- **Reaction (反应)**: 当可观察 `state` 改变时需要自动执行的副作用。在 React 中，组件的 `render` 就是最主要的 Reaction。

### MobX 与 React 结合使用

首先，安装依赖：
```bash
npm install mobx mobx-react-lite
```
`mobx-react-lite` 是将 MobX 与 React 函数组件连接的库。

**示例：一个简单的计数器 Store**

1.  **创建 Store (`counterStore.js`)**

```javascript
import { makeAutoObservable } from "mobx";

class CounterStore {
  count = 0;
  
  constructor() {
    // makeAutoObservable 会自动将所有属性标记为 observable,
    //所有方法标记为 action, 所有 getter 标记为 computed。
    makeAutoObservable(this);
  }

  increment() {
    this.count += 1;
  }

  decrement() {
    this.count -= 1;
  }
  
  get double() {
    return this.count * 2;
  }
}

const counterStore = new CounterStore();
export default counterStore;
```

2.  **在组件中使用 (`Counter.jsx`)**

```jsx
import React from 'react';
import { observer } from 'mobx-react-lite';
import counterStore from './counterStore';

// `observer` HOC 会将组件转换成一个 Reaction，
// 当其依赖的 observable state 改变时，它会自动重新渲染。
const Counter = observer(() => {
  return (
    <div>
      <h1>Count: {counterStore.count}</h1>
      <h2>Double: {counterStore.double}</h2>
      <button onClick={() => counterStore.increment()}>+</button>
      <button onClick={() => counterStore.decrement()}>-</button>
    </div>
  );
});

export default Counter;
```
MobX 的代码非常直观，就像在操作普通的 JavaScript 对象一样。你不需要 `dispatch` actions，也不需要 `useSelector`。`observer` HOC 会为你处理所有的订阅和更新。

## Zustand: 极简的 Hooks 式状态管理

Zustand 是一个轻量级、快速、灵活的状态管理库。它的 API 设计深受 Hooks 的启发，非常易于上手。

### Zustand 的核心特点

- **极简 API**: 通常只需要一个 `create` 函数。
- **无样板代码**: 无需定义 actions, reducers, 或 dispatchers。
- **不依赖 Context Provider**: 你可以在任何地方调用 hook 来访问 store，无需用 `<Provider>` 包裹你的应用。
- **基于 Hooks**: 它的 API 就是一个 Hook，与 React 的心智模型无缝集成。

### Zustand 示例

首先，安装依赖：
```bash
npm install zustand
```

1.  **创建 Store (`store.js`)**

```javascript
import create from 'zustand';

const useStore = create((set) => ({
  count: 0,
  increment: () => set((state) => ({ count: state.count + 1 })),
  decrement: () => set((state) => ({ count: state.count - 1 })),
  removeAllBears: () => set({ count: 0 }),
}));

export default useStore;
```
`create` 函数接收一个回调，该回调返回你的 store 对象。`set` 函数用于更新 state。

2.  **在组件中使用 (`Counter.jsx`)**

```jsx
import React from 'react';
import useStore from './store';

function Counter() {
  // 直接调用 hook 即可获取整个 store
  const store = useStore();

  return (
    <div>
      <h1>{store.count}</h1>
      <button onClick={store.increment}>+</button>
    </div>
  );
}
```

如果你只关心 store 中的某个特定值，可以传递一个 selector 函数来避免不必要的重渲染。

```jsx
function Counter() {
  // 只订阅 count 的变化
  const count = useStore((state) => state.count);
  const increment = useStore((state) => state.increment);

  return (
    <div>
      <h1>{count}</h1>
      <button onClick={increment}>+</button>
    </div>
  );
}
```

## MobX vs. Zustand vs. Redux Toolkit

| 特性 | Redux Toolkit | MobX | Zustand |
| :--- | :--- | :--- | :--- |
| **范式** | 函数式 (Flux 架构) | 响应式 (OOP/Reactive) | 极简 Hooks |
| **核心** | Reducers, Actions | Observables, Actions | Store, Setters |
| **样板代码** | 较少 (比纯Redux少) | 很少 (面向对象风格) | 几乎没有 |
| **学习曲线** | 中等 | 简单 | 非常简单 |
| **DevTools** | 强大，时间旅行调试 | 支持，但不如 Redux 强大 | 基础支持 |
| **生态系统** | 非常庞大和成熟 | 较大，成熟 | 快速增长，现代 |
| **适用场景** | 大型、复杂、需要严格数据流和可追溯性的应用 | 喜欢OOP、需要快速开发、对响应式编程有偏好的项目 | 中小型项目、快速原型、喜欢极简和 Hooks 风格的开发者 |

**结论**:
- 如果你来自一个面向对象的背景，或者喜欢通过"魔术"般的方式自动追踪依赖和更新，**MobX** 会是一个非常自然的选择。
- 如果你热爱 React Hooks，想要一个极简、无样板代码、开箱即用的解决方案，**Zustand** 可能是你的最佳选择。
- 如果你正在构建一个大型企业级应用，需要严格的、可预测的单向数据流和强大的开发者工具（如时间旅行调试），**Redux Toolkit** 仍然是黄金标准。

选择哪个库没有绝对的对错，关键在于理解它们的哲学和权衡，然后选择最适合你的项目需求和团队偏好的那一个。 