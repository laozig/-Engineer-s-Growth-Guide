# 8. Hooks 介绍与 `useState`

## 什么是 Hooks？

Hooks 是 React 16.8 版本中引入的新特性。它们让你**在不编写 class 的情况下使用 state 以及其他的 React 特性**。

在此之前，如果你想为一个函数组件添加 `state`，你需要把它转换成一个 Class 组件。现在，你可以直接在现有的函数组件中使用 Hooks。

### 为什么引入 Hooks？

Hooks 解决了 React 社区多年来遇到的各种看似不相关的问题：

1.  **在组件之间复用状态逻辑很难**: React 没有提供一种将可复用的行为"附加"到组件上的方式（例如，连接到 store）。虽然有 render props 和高阶组件 (HOC) 等模式，但这些模式会要求你重构组件结构，并可能导致"包装器地狱 (wrapper hell)"。Hooks 允许你复用状态逻辑，而无需改变组件层次结构。
2.  **复杂的组件变得难以理解**: 在 Class 组件中，状态逻辑和副作用（如数据获取、订阅）经常被分散在不同的生命周期方法中（`componentDidMount`, `componentDidUpdate`, `componentWillUnmount`）。一个功能（如获取数据）的代码被拆分，而一个生命周期方法（如`componentDidMount`）却常常包含多个不相关的逻辑。Hooks 允许你根据**相关性**（例如，设置订阅或获取数据）将一个组件分割成更小的函数，而不是基于生命周期方法来强制分割。
3.  **Class 令人困惑**: Class 的 `this` 关键字是学习 JavaScript 的一大障碍。你必须记住绑定事件处理程序，并且理解它在不同上下文中的指向。Class 组件也使得代码的优化和压缩更加困难。Hooks 让你可以在没有 Class 的情况下使用更多的 React 特性。

## State Hook: `useState`

`useState` 是一个 Hook，它允许你向函数组件添加 React state。

### 示例：一个计数器

让我们来看一个简单的计数器例子。首先是 Class 组件的版本：
```jsx
class Example extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      count: 0
    };
  }

  render() {
    return (
      <div>
        <p>You clicked {this.state.count} times</p>
        <button onClick={() => this.setState({ count: this.state.count + 1 })}>
          Click me
        </button>
      </div>
    );
  }
}
```

现在，这是使用 `useState` Hook 的函数组件版本：
```jsx
import React, { useState } from 'react';

function Example() {
  // 声明一个新的 state 变量，我们称之为 "count"
  const [count, setCount] = useState(0);

  return (
    <div>
      <p>You clicked {count} times</p>
      <button onClick={() => setCount(count + 1)}>
        Click me
      </button>
    </div>
  );
}
```

### `useState` 解析

**1. 如何调用 `useState`?**
我们通过在函数组件内部调用 `useState` 来声明一个 "state 变量"。它返回一个包含两个值的数组：
- 当前的 state 值。
- 一个让你更新这个 state 值的函数。

```jsx
const [count, setCount] = useState(0);
```
这里我们使用了**数组解构 (Array Destructuring)** 语法。`useState(0)` 的意思是，我们用 `0` 作为 `count` 的初始值。`setCount` 就是那个用于更新 `count` 值的函数。

**2. 如何读取 State?**
在 Class 组件中，你需要用 `this.state.count` 来读取。在函数组件中，你可以直接使用变量名 `count`。

**3. 如何更新 State?**
在 Class 组件中，你需要调用 `this.setState()`。在函数组件中，你直接调用 `setCount` 函数。

```jsx
// Class
this.setState({ count: this.state.count + 1 });

// Function with Hook
setCount(count + 1);
```

### State 更新函数的特性

与 Class 组件的 `setState` 方法不同，`useState` 的更新函数**不会**自动合并旧的 state 和新的 state。如果你想更新一个对象类型的 state，你需要手动进行合并。

```jsx
const [state, setState] = useState({ left: 0, top: 0, width: 100 });

// 错误的方式，这会丢失 top 和 width
// setState({ left: 10 }); 

// 正确的方式：使用扩展语法手动合并
setState(prevState => ({ ...prevState, left: 10 }));
```

### 声明多个 State 变量

你可以多次调用 `useState` 来声明多个 state 变量。

```jsx
function ExampleWithManyStates() {
  // 声明多个 state 变量！
  const [age, setAge] = useState(42);
  const [fruit, setFruit] = useState('banana');
  const [todos, setTodos] = useState([{ text: 'Learn Hooks' }]);
  // ...
}
```
将 state 拆分成多个独立的 state 变量通常是更好的做法，这有助于将相关的逻辑组织在一起。

## Hooks 的规则

Hooks 就是 JavaScript 函数，但它们有两个额外的规则：

1.  **只能在顶层调用 Hooks**: 不要在循环、条件或嵌套函数中调用 Hook。确保 Hooks 总是在你的 React 函数的顶层被调用。这有助于 React 在多次渲染之间保持 Hook 的状态。
2.  **只能在 React 函数中调用 Hooks**: 不要在普通的 JavaScript 函数中调用 Hook。你可以在 React 函数组件或自定义 Hook 中调用 Hook。

`useState` 是我们遇到的第一个 Hook，但它只是一个开始。接下来，我们将学习另一个非常重要的 Hook：[`useEffect`](useeffect-in-depth.md)。 