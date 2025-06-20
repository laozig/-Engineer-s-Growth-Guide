# 21. React 上下文 (Context) 深入应用

我们在[第10章](core-hooks.md)已经了解了 Context 的基本用法和 `useContext` Hook。Context 的主要目的是解决"属性钻孔 (prop drilling)"问题，即避免在组件树中逐层手动传递 props。

本章我们将探讨一些更高级的 Context 使用模式和注意事项。

## 更新 Context 的值

Context 不仅仅能传递静态值，它还可以传递**状态和更新状态的函数**。这使得 Context 成为一种轻量级的、内置的状态管理方案。

**示例：一个主题切换器**

1.  **创建 `ThemeContext.js`**:
    我们不仅要提供当前的 `theme`，还要提供一个 `toggleTheme` 函数。

    ```jsx
    import React, { useState, useContext } from 'react';

    // 1. 创建 Context，可以提供一个默认值
    const ThemeContext = React.createContext({
      theme: 'light',
      toggleTheme: () => {}, // 默认的空函数
    });

    // 2. 创建一个自定义的 Provider 组件，封装状态逻辑
    export function ThemeProvider({ children }) {
      const [theme, setTheme] = useState('light');

      const toggleTheme = () => {
        setTheme(prevTheme => (prevTheme === 'light' ? 'dark' : 'light'));
      };

      // 将 state 和更新函数作为 value 传递下去
      const value = { theme, toggleTheme };

      return (
        <ThemeContext.Provider value={value}>
          {children}
        </ThemeContext.Provider>
      );
    }

    // 3. (可选) 创建一个自定义 Hook，简化消费过程
    export function useTheme() {
      return useContext(ThemeContext);
    }
    ```

2.  **在 `App.js` 中包裹应用**:

    ```jsx
    import { ThemeProvider } from './ThemeContext';
    import MyComponent from './MyComponent';

    function App() {
      return (
        <ThemeProvider>
          <MyComponent />
        </ThemeProvider>
      );
    }
    ```

3.  **在任意子组件中消费 Context**:

    ```jsx
    // MyComponent.js
    import { useTheme } from './ThemeContext';

    function MyComponent() {
      // 使用自定义 Hook 获取 theme 和 toggleTheme
      const { theme, toggleTheme } = useTheme();

      const style = {
        background: theme === 'dark' ? '#333' : '#FFF',
        color: theme === 'dark' ? '#FFF' : '#333',
        padding: '2rem',
      };

      return (
        <div style={style}>
          <h1>Current Theme: {theme}</h1>
          <button onClick={toggleTheme}>Toggle Theme</button>
        </div>
      );
    }
    ```
通过这种模式，我们将状态逻辑（`useState`）封装在了 `ThemeProvider` 中，任何被其包裹的子组件都可以通过 `useTheme` Hook 方便地访问和更新全局状态，而无需关心其实现细节。

## Context 的性能问题

Context 的一个主要缺点是**性能**。当 `Provider` 的 `value` prop 发生变化时，**所有**消费该 Context 的子组件都会**重新渲染**，无论它们是否真正用到了 `value` 中发生变化的那一部分。

**问题场景**:
假设我们的 `value` 对象包含 `user` 和 `theme`。
```jsx
const value = { user, theme, login, logout, toggleTheme };
```
当 `toggleTheme` 被调用，`theme` 状态改变，`value` 对象会重新创建。这会导致消费这个 Context 的所有组件都重新渲染，即使某个组件只用到了 `user` 信息，而 `user` 并未发生任何变化。

### 优化策略

#### 1. 将 Context 拆分成多个

这是最推荐的优化方法。将不常变化的状态和常变化的状态分离到不同的 Context 中。

```jsx
// UserContext.js
const UserContext = React.createContext();
// 在 UserProvider 中只管理 user, login, logout

// ThemeContext.js
const ThemeContext = React.createContext();
// 在 ThemeProvider 中只管理 theme, toggleTheme
```

然后在使用时，将两者组合起来：
```jsx
function App() {
  return (
    <UserProvider>
      <ThemeProvider>
        <Layout />
      </ThemeProvider>
    </UserProvider>
  );
}
```
现在，如果一个组件只消费 `UserContext`，它将不会在主题变化时重新渲染。

#### 2. 使用 `useMemo` 稳定 `value` 对象

如果你不能或不想拆分 Context，可以使用 `useMemo` 来确保 `value` 对象只有在真正需要时才重新创建。

```jsx
function AuthProvider({ children }) {
  const [user, setUser] = useState(null);

  const login = useCallback((userData) => {
    setUser(userData);
  }, []);

  const logout = useCallback(() => {
    setUser(null);
  }, []);

  // 使用 useMemo 来记忆 value 对象
  // 只有当 user 改变时，value 对象才会重新创建
  const value = useMemo(() => ({
    user,
    login,
    logout,
  }), [user, login, logout]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}
```
这里需要注意的是，`login` 和 `logout` 函数也需要用 `useCallback` 来包裹，否则它们在每次 `AuthProvider` 渲染时都会是新的函数实例，导致 `useMemo` 的依赖项发生变化。

## 何时使用 Context？

Context 主要用于管理那些**不经常变化**的**低频全局状态**，例如：
- 主题 (UI theme)
- 用户认证信息 (Authentication)
- 语言偏好 (Localization)
- 路由

对于那些**高频变化**的应用级状态（例如复杂的表单状态、实时数据流等），使用像 Redux, Zustand 或 MobX 这样的专用状态管理库通常是更好的选择。这些库为处理频繁更新提供了更精细的性能优化和更强大的开发者工具。

**总结**:
- Context 是 React 内置的、解决 props 钻孔问题的利器。
- 通过将 state 和更新函数放入 Context，可以实现轻量级的全局状态管理。
- 要注意 Context 可能带来的性能问题，主要的优化手段是**拆分 Context**。
- 将 Context 用于低频更新的全局数据，而将更复杂、高频的状态交给专用的状态管理库。 