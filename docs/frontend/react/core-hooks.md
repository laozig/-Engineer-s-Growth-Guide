# 10. 核心 Hooks: `useContext`, `useReducer`, `useCallback`, `useMemo`

除了 `useState` 和 `useEffect`，React 还提供了一些其他内置的 Hooks，它们为我们解决特定问题提供了强大的工具。

## `useContext`

`useContext` 让你能够不通过 props，直接订阅和读取 React 的 Context。

**背景：什么是 Context？**
Context 提供了一种在组件树中共享数据的方式，而无需手动地在每一层都传递 props。它主要用于那些对于一个组件树而言是"全局"的数据，比如当前认证的用户、主题或首选语言。

### 如何使用

1.  **创建一个 Context 对象**: 使用 `React.createContext`。
2.  **提供 Context**: 使用 `<MyContext.Provider>` 组件将值提供给其下的所有子组件。
3.  **消费 Context**: 在函数组件中使用 `useContext` Hook 来读取 Context 的值。

```jsx
// 1. 创建 Context
const ThemeContext = React.createContext('light');

// 2. 在 App 组件中提供 Context
function App() {
  return (
    <ThemeContext.Provider value="dark">
      <Toolbar />
    </ThemeContext.Provider>
  );
}

// 3. 在中间组件 Toolbar 中，无需关心 theme
function Toolbar() {
  return (
    <div>
      <ThemedButton />
    </div>
  );
}

// 4. 在最终的组件中，使用 useContext 消费 Context
function ThemedButton() {
  // 接收一个 context 对象（React.createContext 的返回值）
  // 并返回该 context 的当前值。
  const theme = useContext(ThemeContext);
  
  return <button>Current theme is: {theme}</button>;
}
```
当 `Provider` 的 `value` 发生变化时，所有消费该 Context 的组件都会重新渲染。`useContext` 让函数组件消费 Context 变得极其简单，避免了 render props 或高阶组件的嵌套。

## `useReducer`

`useReducer` 是 `useState` 的一个替代方案。它在处理包含多个子值的复杂 state 逻辑，或者下一个 state 依赖于前一个 state 的情况下，通常比 `useState` 更可取。

它接收一个 `(state, action) => newState` 形式的 **reducer 函数**，并返回当前的 `state` 以及一个 `dispatch` 方法。

### 计数器示例

```jsx
const initialState = {count: 0};

// Reducer 函数
function reducer(state, action) {
  switch (action.type) {
    case 'increment':
      return {count: state.count + 1};
    case 'decrement':
      return {count: state.count - 1};
    default:
      throw new Error();
  }
}

function Counter() {
  // useReducer 返回 state 和 dispatch
  const [state, dispatch] = useReducer(reducer, initialState);

  return (
    <>
      Count: {state.count}
      <button onClick={() => dispatch({type: 'decrement'})}>-</button>
      <button onClick={() => dispatch({type: 'increment'})}>+</button>
    </>
  );
}
```
**何时使用 `useReducer`?**
- 当 state 逻辑复杂，涉及多个子值时。
- 当下一个 state 依赖于前一个 state 时。
- 当你希望将 state 更新逻辑从组件中分离出来，以便于测试和复用时。
- 在大型应用中，`useReducer` 还能通过向下传递 `dispatch` 而不是回调函数来优化性能，因为 `dispatch` 函数是稳定不变的。

## `useCallback`

`useCallback` 返回一个 **memoized (记忆化的) 回调函数**。

**问题：**
在 React 中，当一个组件重新渲染时，它内部定义的函数也会被重新创建。如果我们将这个函数作为 prop 传递给一个被 `React.memo` 优化的子组件，即使函数的内容没有改变，子组件也会因为接收到了一个新的函数引用而重新渲染。

```jsx
function ParentComponent({ term }) {
  const [count, setCount] = useState(0);
  
  // 每次 ParentComponent 渲染，这个函数都会被重新创建
  const handleClick = () => {
    console.log(`Searching for ${term}`);
  };
  
  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>Increment: {count}</button>
      {/* 即使 term 不变，ExpensiveChild 也会因为 handleClick 的变化而重新渲染 */}
      <ExpensiveChild onClick={handleClick} />
    </div>
  );
}
```

**解决方案：`useCallback`**
`useCallback` 会返回一个函数的 memoized 版本，该函数仅在某个依赖项改变时才会更新。

```jsx
import { useCallback } from 'react';

function ParentComponent({ term }) {
  // ...
  
  // 只有当 term 改变时，handleClick 才会重新创建
  const handleClick = useCallback(() => {
    console.log(`Searching for ${term}`);
  }, [term]);
  
  return <ExpensiveChild onClick={handleClick} />;
}
```
现在，只要 `term` prop 不变，传递给 `ExpensiveChild` 的 `handleClick` prop 就不会变，从而避免了不必要的子组件渲染。

`useCallback(fn, deps)` 等价于 `useMemo(() => fn, deps)`。

## `useMemo`

`useMemo` 返回一个 **memoized (记忆化的) 值**。

**问题：**
如果一个组件在渲染过程中有开销很大的计算，我们不希望在每次渲染时都重新执行这个计算，特别是当计算的依赖项没有改变时。

```jsx
function MyComponent({ list, filter }) {
  // 每次渲染都会重新计算
  const visibleList = expensiveFilter(list, filter);
  
  return <div>{/* ... renders visibleList ... */}</div>;
}
```

**解决方案：`useMemo`**
`useMemo` 会"记住"计算的结果。只有当依赖项数组中的某个值发生变化时，它才会重新计算。

```jsx
import { useMemo } from 'react';

function MyComponent({ list, filter }) {
  // 只有当 list 或 filter 改变时，才会重新调用 expensiveFilter
  const visibleList = useMemo(
    () => expensiveFilter(list, filter), 
    [list, filter]
  );
  
  return <div>{/* ... renders visibleList ... */}</div>;
}
```

**`useCallback` vs `useMemo`**
- `useCallback` 记忆一个**函数**。
- `useMemo` 记忆一个**值**（函数的返回值）。

**何时使用 `useCallback` 和 `useMemo`?**
这两个 Hooks 主要用于性能优化。过早或不必要的优化可能会让代码更复杂。通常，只有在你遇到实际的性能问题，或者想要防止向子组件传递新的函数/对象引用时，才需要使用它们。 