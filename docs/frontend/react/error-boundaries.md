# 19. 错误边界 (Error Boundaries)

在过去，React 组件内的 JavaScript 错误常常会破坏整个应用的状态，并导致下一次渲染时出现隐晦的错误，甚至白屏。为了解决这个问题，React 16 引入了**错误边界 (Error Boundaries)** 的概念。

错误边界是一种特殊的 React 组件，它可以**捕获其子组件树中任何位置的 JavaScript 错误，记录这些错误，并显示一个备用的 UI**，而不是让组件树崩溃。

## 错误边界的工作方式

错误边界可以捕获在渲染期间、生命周期方法中以及其整个树的构造函数中发生的错误。

一个 class 组件如果定义了以下两个生命周期方法中的任何一个（或两个），它就成了一个错误边界：

- **`static getDerivedStateFromError(error)`**:
    - 这是一个静态方法。当后代组件抛出错误时，它会被调用。
    - 它应该返回一个对象来更新 `state`，从而在下一次渲染中显示备用 UI。
- **`componentDidCatch(error, errorInfo)`**:
    - 这个方法在错误被捕获后调用。
    - 你可以在这里执行副作用，例如将错误信息记录到外部服务。
    - `error`: 抛出的错误对象。
    - `errorInfo`: 一个包含 `componentStack` 键的对象，提供了关于哪个组件引发错误的组件栈信息。

### 创建一个错误边界组件

下面是一个典型的错误边界组件示例：

```jsx
import React from 'react';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  // 通过此方法更新 state，以便下一次渲染可以显示降级后的 UI
  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  // 此方法用于记录错误信息
  componentDidCatch(error, errorInfo) {
    // 你也可以将错误日志上报给服务器
    console.error("Uncaught error:", error, errorInfo);
    // logErrorToMyService(error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      // 你可以渲染任何自定义的降级 UI
      return <h1>Something went wrong.</h1>;
    }

    // 如果没有错误，则正常渲染子组件
    return this.props.children; 
  }
}

export default ErrorBoundary;
```

### 如何使用它

创建了错误边界组件后，你就可以像使用普通组件一样，用它来包裹你的其他组件。

```jsx
import React from 'react';
import ErrorBoundary from './ErrorBoundary';

// 这是一个可能会抛出错误的组件
const BuggyComponent = () => {
  throw new Error("I crashed!");
  return <div>Never reached</div>;
};

function App() {
  return (
    <div>
      <h1>My App</h1>
      <p>This part will always be visible.</p>
      <hr />
      <ErrorBoundary>
        <p>These components are inside the error boundary.</p>
        <BuggyComponent />
      </ErrorBoundary>
      <hr />
      <ErrorBoundary>
        <p>This is another error boundary.</p>
        {/* <AnotherComponent /> */}
      </ErrorBoundary>
    </div>
  );
}
```
在这个例子中：
- `BuggyComponent` 抛出的错误会被它最近的 `ErrorBoundary` 捕获。
- `ErrorBoundary` 会更新自己的 `state` 并渲染 `<h1>Something went wrong.</h1>` 这个备用 UI。
- **重要的是，应用的其他部分（如 "My App" 标题和另一个 `ErrorBoundary`）不会受到影响，它们会保持可交互状态。**

## 错误边界的限制

错误边界**不能**捕获以下场景中产生的错误：

1.  **事件处理程序 (Event handlers)**:
    - 事件处理程序中的错误不会在渲染期间发生。如果需要捕获它们，需要使用常规的 JavaScript `try...catch` 语句。
    ```jsx
    class MyComponent extends React.Component {
      constructor(props) {
        super(props);
        this.state = { error: null };
      }
      
      handleClick = () => {
        try {
          // 做一些可能会抛错的事情
        } catch (error) {
          this.setState({ error });
        }
      }
      
      render() {
        if (this.state.error) {
          return <h1>Caught an error.</h1>
        }
        return <button onClick={this.handleClick}>Click Me</button>;
      }
    }
    ```
2.  **异步代码 (e.g., `setTimeout` or `requestAnimationFrame` callbacks)**
3.  **服务端渲染 (Server-side rendering)**
4.  **错误边界自身抛出的错误** (而不是其子组件)

## 在哪里放置错误边界？

放置错误边界的位置取决于你的应用。你可以选择一个"重量级"的策略，在顶层路由组件外包裹一个，用于展示一个通用的"应用崩溃"信息。

或者，你也可以采用更"精细"的策略，将应用中的独立模块（widgets）分别用错误边界包裹起来，这样即使一个模块崩溃了，也不会影响页面的其他部分。例如，在社交媒体的动态流中，一条动态的崩溃不应该影响整个页面的渲染。

> **关于 Hooks**:
> 截至目前，还没有一个与 `getDerivedStateFromError` 和 `componentDidCatch` 功能完全对应的 Hook。因此，如果你需要实现一个错误边界，你**必须**使用 Class 组件。但这并不影响你在应用的其余部分使用函数组件和 Hooks。

错误边界是构建健壮、有弹性的 React 应用的关键工具。它可以防止局部 UI 的错误蔓延到整个应用，从而极大地提升用户体验。 