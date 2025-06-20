# 13. 状态管理: Redux & Redux Toolkit

当你的应用变得越来越复杂时，组件之间的 `state` 传递和管理也会变得困难。Props 逐层传递（"prop drilling"）会让代码难以维护，而组件自身的状态可能需要在应用的多个不相关部分之间共享。

**Redux** 是一个用于 JavaScript 应用的可预测的状态容器。它帮助你以一种集中、可预测的方式管理整个应用的状态。

## Redux 的核心概念

Redux 主要由三个核心概念组成：

1.  **Store (单一数据源)**:
    - 整个应用的**所有状态**都存储在一个单一的 JavaScript 对象中，这个对象被称为 `store`。
    - 这是 Redux 的核心原则：**单一数据源 (Single Source of Truth)**。这使得调试、序列化状态、实现撤销/重做等功能变得简单。

2.  **Action (状态是只读的)**:
    - 改变 `state` 的唯一方法是**派发 (dispatch) 一个 action**。
    - Action 是一个普通的 JavaScript 对象，用于描述"发生了什么"。它必须有一个 `type` 属性（通常是字符串），以及可选的 `payload`（携带的数据）。
    - 例如: `{ type: 'todos/todoAdded', payload: 'Buy milk' }`。

3.  **Reducer (使用纯函数来执行修改)**:
    - Reducer 是一个**纯函数**，它接收当前的 `state` 和一个 `action` 对象，然后返回**一个新的 `state`**。
    - `(state, action) => newState`
    - 它**绝不能**做任何异步操作，或者直接修改旧的 `state`。它必须是可预测的。

### 数据流

Redux 的数据流是**单向**的：
1.  UI 组件派发一个 **action** (例如，用户点击按钮)。
2.  Redux `store` 调用 **reducer** 函数，并将当前的 `state` 和 `action` 传递给它。
3.  Reducer 根据 `action` 的类型计算出**新的 `state`** 并返回。
4.  `store` 保存 reducer 返回的新 `state`。
5.  `store` 通知所有订阅了它的 UI 组件。
6.  UI 组件从 `store` 中获取最新的 `state` 并重新渲染。

## 为什么使用 Redux Toolkit?

虽然 Redux 的核心概念很简单，但手写所有的 Redux 逻辑（action creators, reducers, store setup）可能会非常繁琐和重复。

**Redux Toolkit (RTK)** 是官方推荐的、用于高效 Redux 开发的工具集。它封装了 Redux 的最佳实践，并大大简化了代码。我们**强烈推荐**在新项目中使用 Redux Toolkit。

RTK 的主要优点：
- **简化 Store 设置**: `configureStore` 自动配置了 store，并集成了常用的中间件（如 Redux Thunk）。
- **简化 Reducer 编写**: `createSlice` 让你能够在一个地方定义 reducer 和相关的 actions。它内部使用 Immer 库，让你可以在 reducer 中编写"看似可变"的逻辑，而它会自动为你生成正确的不可变更新。
- **无需手写 Action Creators**: `createSlice` 会自动根据你的 reducer 函数名生成 action creators。

## 使用 Redux Toolkit 的示例

### 1. 安装依赖

```bash
npm install @reduxjs/toolkit react-redux
```
`react-redux` 是将 Redux 与 React 组件连接起来的官方库。

### 2. 创建一个 Redux Store

在 `src/app/store.js` 中：
```javascript
import { configureStore } from '@reduxjs/toolkit';

export const store = configureStore({
  reducer: {}, // 暂时为空，稍后添加
});
```

### 3. 创建一个 State "Slice"

Slice 是应用中单个功能的 state、reducers 和 actions 的集合。
在 `src/features/counter/counterSlice.js` 中：

```javascript
import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  value: 0,
};

export const counterSlice = createSlice({
  name: 'counter', // slice 的名称
  initialState,
  // 定义 reducers 和相关的 actions
  reducers: {
    increment: (state) => {
      // Redux Toolkit 允许我们在 reducers 中编写 "可变" 的逻辑。
      // 它实际上并没有改变 state，因为它使用了 Immer 库，
      // 它会检测到 "草稿 state" 的变化并产生一个全新的不可变 state。
      state.value += 1;
    },
    decrement: (state) => {
      state.value -= 1;
    },
    // 使用 PayloadAction 类型来声明 `action.payload` 的内容
    incrementByAmount: (state, action) => {
      state.value += action.payload;
    },
  },
});

// 为每个 reducer 函数 case 生成 Action creators
export const { increment, decrement, incrementByAmount } = counterSlice.actions;

// 导出 reducer
export default counterSlice.reducer;
```

### 4. 将 Slice Reducers 添加到 Store

回到 `src/app/store.js`：
```javascript
import { configureStore } from '@reduxjs/toolkit';
import counterReducer from '../features/counter/counterSlice'; // 导入 reducer

export const store = configureStore({
  reducer: {
    counter: counterReducer, // 将 reducer 添加到 store
  },
});
```

### 5. 在 React 组件中使用

首先，在应用的根组件（如 `index.js`）使用 `<Provider>` 来包裹你的应用，并将 `store` 传递给它。
```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import App from './App';
import { store } from './app/store';
import { Provider } from 'react-redux';

ReactDOM.render(
  <Provider store={store}>
    <App />
  </Provider>,
  document.getElementById('root')
);
```

然后，在你的组件中，使用 `react-redux` 提供的 Hooks 来与 `store` 交互。
- **`useSelector`**: 用于从 `store` 中**读取** state。
- **`useDispatch`**: 用于向 `store` **派发** actions。

在 `src/features/counter/Counter.js` 中：
```jsx
import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { decrement, increment } from './counterSlice';

export function Counter() {
  // 从 store 中读取 counter state
  const count = useSelector((state) => state.counter.value);
  // 获取 dispatch 函数
  const dispatch = useDispatch();

  return (
    <div>
      <div>
        <button
          aria-label="Increment value"
          onClick={() => dispatch(increment())}
        >
          Increment
        </button>
        <span>{count}</span>
        <button
          aria-label="Decrement value"
          onClick={() => dispatch(decrement())}
        >
          Decrement
        </button>
      </div>
    </div>
  );
}
```
通过 Redux Toolkit，我们以一种清晰、可维护且代码量很少的方式实现了一个全局状态管理系统。它解决了纯 Redux 的样板代码问题，同时保留了其强大的可预测性和调试能力，是现代 React 应用中进行复杂状态管理的首选方案。 