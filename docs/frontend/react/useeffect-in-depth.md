# 9. `useEffect` 详解

`useEffect` Hook 让你在函数组件中执行**副作用 (side effects)**。

什么是副作用？数据获取、设置订阅、以及手动更改 React 组件中的 DOM 都属于副作用。你可以把 `useEffect` Hook 看作是 Class 组件中 `componentDidMount`，`componentDidUpdate` 和 `componentWillUnmount` 这三个生命周期函数的组合。

## 基本用法

让我们来看一个例子：一个组件在渲染后，将网页的标题更新为它被点击的次数。

在 Class 组件中，我们需要在两个生命周期方法中重复这个逻辑：
```jsx
class Example extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      count: 0
    };
  }

  componentDidMount() {
    document.title = `You clicked ${this.state.count} times`;
  }

  componentDidUpdate() {
    document.title = `You clicked ${this.state.count} times`;
  }

  // ...
}
```

使用 `useEffect`，我们可以更简洁地实现：
```jsx
import React, { useState, useEffect } from 'react';

function Example() {
  const [count, setCount] = useState(0);

  useEffect(() => {
    // 这个函数会在每次渲染后运行
    document.title = `You clicked ${count} times`;
  });

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

### `useEffect` 解析

- **`useEffect` 做了什么？** 通过使用这个 Hook，你告诉 React 你的组件需要在渲染后执行某些操作。React 会记住你传递的函数（我们称之为"effect"），并且在执行 DOM 更新之后调用它。
- **为什么在组件内部调用 `useEffect`？** 将 `useEffect` 放在组件内部，让我们可以在 effect 中直接访问 `count` state 变量（或其他 props）。我们不需要特殊的 API 来读取它——它已经存在于函数作用域中。
- **`useEffect` 在每次渲染后都会运行吗？** 是的，默认情况下，它在第一次渲染**之后**和每次更新**之后**都会运行。（我们稍后会学习如何控制它）。

## 需要清理的 Effect

有些副作用是需要"清理"的。例如，如果你设置了一个订阅，那么在组件卸载时就必须取消这个订阅，以防止内存泄漏。

在 Class 组件中，我们通常在 `componentDidMount` 中设置订阅，在 `componentWillUnmount` 中清理它。

```jsx
class FriendStatus extends React.Component {
  // ...
  componentDidMount() {
    ChatAPI.subscribeToFriendStatus(
      this.props.friend.id,
      this.handleStatusChange
    );
  }

  componentWillUnmount() {
    ChatAPI.unsubscribeFromFriendStatus(
      this.props.friend.id,
      this.handleStatusChange
    );
  }
  // ...
}
```

在 `useEffect` 中，实现这个的方式是**从 effect 函数中返回一个函数**。这个返回的函数就是清理函数。

```jsx
import React, { useState, useEffect } from 'react';

function FriendStatus(props) {
  const [isOnline, setIsOnline] = useState(null);

  useEffect(() => {
    function handleStatusChange(status) {
      setIsOnline(status.isOnline);
    }

    ChatAPI.subscribeToFriendStatus(props.friend.id, handleStatusChange);

    // 返回一个清理函数
    return function cleanup() {
      ChatAPI.unsubscribeFromFriendStatus(props.friend.id, handleStatusChange);
    };
  });

  // ...
}
```

**为什么 `useEffect` 要在 effect 内部返回一个函数？** 这是 `useEffect` API 的一个可选特性。如果你的 effect 返回一个函数，React 将会在执行下一次 effect 之前，以及在组件卸载时运行它。这保证了清理操作的一致性。

## 控制 Effect 的运行时机

默认情况下，`useEffect` 在每次组件渲染后都会执行。但有时这是不必要的。例如，如果 `props.friend.id` 没有改变，我们就不需要重新订阅。

我们可以通过给 `useEffect` 传递**第二个参数**来优化它。这个参数是一个数组，我们称之为**依赖项数组 (dependency array)**。

```jsx
useEffect(() => {
  document.title = `You clicked ${count} times`;
}, [count]); // 仅在 count 改变时，才重新运行 effect
```

- **工作原理**: React 会比较本次渲染和上一次渲染时依赖项数组中的每一个值。如果数组中的**任何一个值**发生了变化，React 就会执行 effect。
- **如果只想运行一次**: 如果你想让 effect 只在组件挂载时运行一次（类似于 `componentDidMount`），你可以传递一个**空数组 `[]`**作为第二个参数。

```jsx
useEffect(() => {
  // 这个 effect 只在挂载时运行一次
  fetchData();
}, []);
```
这告诉 React，你的 effect 不依赖于任何 props 或 state，所以它永远不需要重新运行。

### 使用依赖项数组的注意事项

依赖项数组是 `useEffect` 中一个非常强大但也容易出错的部分。

**规则：你必须包含 effect 函数中用到的所有来自组件作用域的值（props 和 state）。**

```jsx
function FriendStatus(props) {
  // ...
  useEffect(() => {
    function handleStatusChange(status) {
      setIsOnline(status.isOnline);
    }
    ChatAPI.subscribeToFriendStatus(props.friend.id, handleStatusChange);
    return () => {
      ChatAPI.unsubscribeFromFriendStatus(props.friend.id, handleStatusChange);
    };
  }, [props.friend.id]); // 正确：effect 依赖于 props.friend.id
  // ...
}
```
如果你忘记在依赖项数组中包含 `props.friend.id`，那么 effect 将会捕获到第一次渲染时的 `id` 值，并且永远不会在 `id` 改变时重新订阅，从而导致 bug。

推荐安装 `eslint-plugin-react-hooks` 插件，它会自动检查并警告你遗漏的依赖项。

`useEffect` 是一个功能强大的 Hook，它统一了 Class 组件中多个生命周期方法的功能，并鼓励你将相关的副作用逻辑组织在一起。掌握它的用法，特别是依赖项数组的正确使用，是精通 React Hooks 的关键。 