# 18. 性能优化

React 本身已经通过虚拟 DOM (Virtual DOM) 和高效的 diffing 算法为我们提供了很好的性能基础。然而，在大型或复杂的应用中，我们仍然可能遇到性能瓶颈。本章将介绍几种在 React 中最常用、最有效的性能优化技术。

## 1. 使用 `React.memo` 优化函数组件

当一个组件的 `props` 没有改变时，重新渲染它是一种浪费。`React.memo` 是一个高阶组件 (HOC)，它可以包裹一个函数组件，并"记住"它的渲染结果。只有当组件的 `props` 发生变化时，它才会重新渲染。

**问题场景**:
假设一个父组件的状态改变，导致它重新渲染。即使传递给子组件 `MyComponent` 的 `props` 没有变化，`MyComponent` 默认情况下也会跟着重新渲染。
```jsx
function Parent() {
  const [count, setCount] = useState(0);
  
  return (
    <div>
      <button onClick={() => setCount(c => c + 1)}>
        Parent Count: {count}
      </button>
      {/* 即使 props 没变, MyComponent 也会在 Parent 渲染时重新渲染 */}
      <MyComponent value="some_static_value" /> 
    </div>
  );
}
```

**解决方案**:
使用 `React.memo` 包裹 `MyComponent`。
```jsx
import React, { memo } from 'react';

const MyComponent = memo(function MyComponent(props) {
  /* 只有当 props.value 改变时，才会重新渲染 */
  console.log("MyComponent is rendering");
  return <div>{props.value}</div>;
});
```
现在，当 `Parent` 组件因为 `count` 状态变化而重新渲染时，`MyComponent` 将不会重新渲染，因为它的 `value` prop 保持不变。

**注意**: `React.memo` 只进行浅层比较。如果你的 `props` 是复杂对象或函数，你需要配合 `useMemo` 和 `useCallback` 来使用。

## 2. 使用 `useCallback` 和 `useMemo`

这两个 Hooks 是 `React.memo` 的重要搭档。

- `useMemo`: 记忆一个**值**。用于避免在每次渲染时都进行昂贵的计算。
- `useCallback`: 记忆一个**函数**。用于避免在每次渲染时都创建一个新的函数实例，这在将函数作为 prop 传递给被 `React.memo` 优化的子组件时尤其重要。

（关于 `useCallback` 和 `useMemo` 的详细用法，请参考 [第10章：核心 Hooks](core-hooks.md)）

## 3. 代码分割 (Code Splitting)

默认情况下，Webpack 等打包工具会将你所有的 JavaScript 代码打包到一个单一的文件（bundle）中。当应用变得庞大时，这个文件也会变得巨大，导致首次加载时间过长。

**代码分割** 是一种将这个巨大的 bundle 拆分成多个小块，并按需加载的技术。

React 通过 `React.lazy` 和 `Suspense` 内置了对代码分割的支持。

- **`React.lazy`**: 让你能够像渲染普通组件一样，渲染一个动态导入的组件。
- **`Suspense`**: 让你能够在懒加载的组件还在加载时，显示一个"加载中"的 fallback UI。

**如何实现**:

```jsx
import React, { Suspense } from 'react';

// 使用 React.lazy 进行动态导入
const OtherComponent = React.lazy(() => import('./OtherComponent'));
const AnotherComponent = React.lazy(() => import('./AnotherComponent'));

function MyComponent() {
  return (
    <div>
      <h1>My App</h1>
      {/* Suspense 包裹懒加载组件 */}
      <Suspense fallback={<div>Loading...</div>}>
        <section>
          <OtherComponent />
          <AnotherComponent />
        </section>
      </Suspense>
    </div>
  );
}
```
现在，`OtherComponent` 和 `AnotherComponent` 的代码会被打包到独立的 chunk 文件中，只有当 `MyComponent` 首次渲染它们时，浏览器才会去下载和执行这些代码。这可以极大地减少应用的初始加载体积。

## 4. 列表虚拟化 (List Virtualization)

如果你需要渲染一个包含成百上千个条目的长列表，一次性将它们全部渲染到 DOM 中会导致严重的性能问题，因为会创建大量的 DOM 节点，消耗大量内存和 CPU。

**列表虚拟化** (也称为窗口化 "windowing") 是一种只渲染长列表中**当前在视口内可见部分**的技术。

虽然 React 本身没有内置虚拟化库，但社区有两个非常流行的解决方案：
- `react-window`
- `react-virtualized` (功能更强大，但体积更大)

**`react-window` 示例**:

首先，安装库：
```bash
npm install react-window
```

然后，使用 `FixedSizeList` 组件来渲染你的长列表：
```jsx
import React from 'react';
import { FixedSizeList as List } from 'react-window';

// 假设我们有 1000 个条目的数据
const items = Array.from({ length: 1000 }, (_, index) => `Item ${index + 1}`);

// 定义列表中的单行如何渲染
const Row = ({ index, style }) => (
  <div style={style}>
    {items[index]}
  </div>
);

// 渲染虚拟化列表
const MyList = () => (
  <List
    height={400}      // 列表容器的高度
    itemCount={1000}  // 列表项总数
    itemSize={35}     // 每个列表项的高度
    width={300}       // 列表容器的宽度
  >
    {Row}
  </List>
);
```
`react-window` 只会渲染在 400px 高度内可见的几十个 `Row` 组件，而不是全部 1000 个。当你滚动列表时，它会高效地回收旧的组件并渲染新的组件，始终保持 DOM 节点的数量在一个很小的范围内，从而带来极大的性能提升。

## 总结

性能优化是一个持续的过程。在进行优化前，首先应该使用 **React Developer Tools Profiler** 来定位应用的性能瓶颈。不要进行过早或不必要的优化。通常，上述四种技术（组件记忆化、代码分割、列表虚拟化）能够解决绝大部分 React 应用遇到的性能问题。 