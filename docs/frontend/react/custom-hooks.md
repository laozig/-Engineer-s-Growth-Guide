# 11. 自定义 Hooks

**自定义 Hook (Custom Hook) 是一个 JavaScript 函数，其名称以 `use` 开头，并且可以调用其他的 Hook。**

这是 React 提供的一个强大的机制，允许你在不同的组件之间提取和复用**状态逻辑**，而不是UI。

## 为什么需要自定义 Hooks？

假设我们有两个组件，都需要知道一个好友是否在线。我们可以复制粘贴相同的逻辑到两个组件中，但这显然不是一个好的做法。

```jsx
// 组件一：好友状态指示器
function FriendStatus(props) {
  const [isOnline, setIsOnline] = useState(null);

  useEffect(() => {
    function handleStatusChange(status) {
      setIsOnline(status.isOnline);
    }
    ChatAPI.subscribeToFriendStatus(props.friend.id, handleStatusChange);
    return () => {
      ChatAPI.unsubscribeFromFriendStatus(props.friend.id, handleStatusChange);
    };
  }, [props.friend.id]);

  if (isOnline === null) {
    return 'Loading...';
  }
  return isOnline ? 'Online' : 'Offline';
}

// 组件二：好友列表项
function FriendListItem(props) {
  const [isOnline, setIsOnline] = useState(null);

  useEffect(() => {
    function handleStatusChange(status) {
      setIsOnline(status.isOnline);
    }
    ChatAPI.subscribeToFriendStatus(props.friend.id, handleStatusChange);
    return () => {
      ChatAPI.unsubscribeFromFriendStatus(props.friend.id, handleStatusChange);
    };
  }, [props.friend.id]);

  return (
    <li style={{ color: isOnline ? 'green' : 'black' }}>
      {props.friend.name}
    </li>
  );
}
```
可以看到，`useState` 和 `useEffect` 的逻辑在这两个组件中是完全一样的。

## 创建你的第一个自定义 Hook

让我们把这个共享的逻辑提取到一个名为 `useFriendStatus` 的自定义 Hook 中。

一个自定义 Hook：
- 是一个以 `use` 开头的 JavaScript 函数。
- 它可以调用其他 Hooks (如 `useState`, `useEffect`)。

```jsx
import { useState, useEffect } from 'react';

function useFriendStatus(friendID) {
  const [isOnline, setIsOnline] = useState(null);

  useEffect(() => {
    function handleStatusChange(status) {
      setIsOnline(status.isOnline);
    }

    ChatAPI.subscribeToFriendStatus(friendID, handleStatusChange);
    return () => {
      ChatAPI.unsubscribeFromFriendStatus(friendID, handleStatusChange);
    };
  }, [friendID]); // 依赖于 friendID

  return isOnline; // 返回状态
}
```

### 使用自定义 Hook

现在，我们可以用这个自定义 Hook 来简化我们的组件：

```jsx
function FriendStatus(props) {
  const isOnline = useFriendStatus(props.friend.id);

  if (isOnline === null) {
    return 'Loading...';
  }
  return isOnline ? 'Online' : 'Offline';
}

function FriendListItem(props) {
  const isOnline = useFriendStatus(props.friend.id);

  return (
    <li style={{ color: isOnline ? 'green' : 'black' }}>
      {props.friend.name}
    </li>
  );
}
```
代码变得更简洁、更易于理解，并且我们成功地复用了状态逻辑。

## 自定义 Hook 的规则

- **命名**: 必须以 `use` 开头。这个命名约定非常重要，它让 React 和 ESLint 插件能够自动检查你是否违反了 Hooks 的规则。
- **状态隔离**: **不同的组件使用同一个自定义 Hook，它们所拥有的 state 是完全独立的。** 自定义 Hook 只是复用了**状态逻辑**，而不是**状态本身**。每次调用 Hook，它内部的所有 state 和 effects 都是完全隔离的。

## 常见的自定义 Hook 示例

社区已经创建了许多非常有用的自定义 Hooks。你可以把自定义 Hooks 看作是你工具箱里的新工具。

### 示例 1: `useDebounce`

在处理用户输入时（例如搜索框），你可能不希望在用户每次按键时都触发API请求。`useDebounce` 可以延迟一个值的更新，只有当该值在一定时间内没有变化时才更新它。

```jsx
function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(
    () => {
      // 在 value 变化后设置一个定时器
      const handler = setTimeout(() => {
        setDebouncedValue(value);
      }, delay);

      // 如果 value 在 delay 时间内再次变化，则清除旧的定时器
      return () => {
        clearTimeout(handler);
      };
    },
    [value, delay] // 仅在 value 或 delay 改变时重新运行
  );

  return debouncedValue;
}

// 使用
function SearchComponent() {
  const [searchTerm, setSearchTerm] = useState('');
  const debouncedSearchTerm = useDebounce(searchTerm, 500); // 500ms 延迟

  useEffect(() => {
    if (debouncedSearchTerm) {
      // 在这里发起 API 请求
      api.search(debouncedSearchTerm);
    }
  }, [debouncedSearchTerm]);
  
  // ...
}
```

### 示例 2: `useLocalStorage`

这个 Hook 可以让你像使用 `useState` 一样方便地读写浏览器的 `localStorage`。

```jsx
function useLocalStorage(key, initialValue) {
  const [storedValue, setStoredValue] = useState(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.log(error);
      return initialValue;
    }
  });

  const setValue = (value) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
    } catch (error) {
      console.log(error);
    }
  };

  return [storedValue, setValue];
}

// 使用
function App() {
  const [name, setName] = useLocalStorage('name', 'Bob');
  
  return (
    <div>
      <input
        type="text"
        placeholder="Enter your name"
        value={name}
        onChange={e => setName(e.target.value)}
      />
    </div>
  );
}
```

自定义 Hooks 是 React 中一个极其强大的抽象机制。它鼓励我们创建更小、更专注、可独立测试和复用的逻辑单元，从而让我们的组件保持简洁和聚焦于渲染。 