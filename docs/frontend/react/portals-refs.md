# 20. Portals 与 Refs

本章我们介绍两个 React 中用于解决特定问题的高级特性：**Portals** 用于将子节点渲染到父组件以外的 DOM 节点，而 **Refs** 则提供了一种访问 DOM 节点或 React 元素的途径。

## Portals

通常情况下，当你从一个组件的 `render` 方法返回一个元素时，它会被挂载到 DOM 树中离它最近的父节点上。但有时，你需要将一个子节点渲染到 DOM 树的不同位置，这就是 Portals 的用武之地。

一个典型的用例是**模态框 (Modals)、对话框 (Dialogs) 和提示框 (Tooltips)**。从视觉上看，这些组件似乎"浮"在你的应用之上，但从 DOM 结构上，为了避免 `z-index` 和 `overflow` 的样式问题，将它们直接挂载到 `<body>` 标签下通常是更干净的做法。

### 如何使用 Portals

`ReactDOM.createPortal(child, container)` 是 Portal 的 API。
- `child`: 任何可渲染的 React 子元素，例如一个元素，字符串或 fragment。
- `container`: 一个真实的 DOM 元素。

**示例**:

1.  **在你的 `index.html` 中，为 Portal 添加一个挂载点**:
    ```html
    <!-- public/index.html -->
    <body>
      <noscript>You need to enable JavaScript to run this app.</noscript>
      <div id="root"></div>
      <div id="modal-root"></div> <!-- Portal 的挂载点 -->
    </body>
    ```
2.  **创建一个使用 Portal 的 `Modal` 组件**:
    ```jsx
    // components/Modal.js
    import React from 'react';
    import ReactDOM from 'react-dom';

    const modalRoot = document.getElementById('modal-root');

    class Modal extends React.Component {
      constructor(props) {
        super(props);
        this.el = document.createElement('div');
      }

      componentDidMount() {
        // 在 Modal 组件挂载后，将 el 元素添加到 modalRoot 中
        modalRoot.appendChild(this.el);
      }

      componentWillUnmount() {
        // 在 Modal 组件卸载后，从 modalRoot 中移除 el 元素
        modalRoot.removeChild(this.el);
      }

      render() {
        // 使用 createPortal 将 this.props.children 渲染到 this.el 中
        return ReactDOM.createPortal(
          this.props.children,
          this.el
        );
      }
    }
    ```
3.  **在父组件中使用 `Modal`**:
    ```jsx
    class Parent extends React.Component {
      constructor(props) {
        super(props);
        this.state = {clicks: 0};
      }

      handleClick = () => {
        this.setState(state => ({
          clicks: state.clicks + 1
        }));
      }

      render() {
        return (
          <div onClick={this.handleClick}>
            <p>Number of clicks: {this.state.clicks}</p>
            <Modal>
              <div className="modal">
                I'm in a portal!
                <button>Close</button>
              </div>
            </Modal>
          </div>
        );
      }
    }
    ```
**重要特性：事件冒泡 (Event Bubbling)**
尽管 Portal 可以被放置在 DOM 树的任何地方，但在其他方面，它的行为和普通的 React 子节点一样。例如，从 Portal 内部触发的事件会**向上冒泡到 React 树中的祖先**，即使这些祖先在 DOM 树中不是它的直接父节点。在上面的例子中，点击 `Modal` 内部的 `button` 仍然会触发 `Parent` 组件的 `handleClick` 方法。

## Refs 和 DOM

Refs 提供了一种方式，允许我们访问在 `render` 方法中创建的 DOM 节点或 React 元素。

在典型的 React 数据流中，`props` 是父子组件交互的唯一方式。要修改一个子组件，你需要用新的 `props` 来重新渲染它。然而，在某些情况下，你可能需要命令式地修改一个子组件，而脱离典型的 React 数据流。这些情况包括：
- 管理焦点、文本选择或媒体播放。
- 触发强制性的动画。
- 集成第三方的 DOM 库。

### 创建和使用 Refs

**`React.createRef()`**:
在 Class 组件中，通常在构造函数中通过 `React.createRef()` 创建 Refs。

**`useRef` Hook**:
在函数组件中，使用 `useRef` Hook 来创建 Refs。`useRef` 返回一个可变的 `ref` 对象，其 `.current` 属性被初始化为传入的参数。返回的 `ref` 对象在组件的整个生命周期内保持不变。

**示例：使用 `useRef` 来聚焦一个输入框**
```jsx
import React, { useRef, useEffect } from 'react';

function TextInputWithFocusButton() {
  // 1. 创建一个 ref
  const inputEl = useRef(null);

  useEffect(() => {
    // 3. 在组件挂载后，通过 ref.current 来访问 DOM 节点并聚焦
    inputEl.current.focus();
  }, []); // 空依赖数组确保只在挂载时运行一次

  return (
    <>
      {/* 2. 将 ref 附加到 DOM 元素上 */}
      <input ref={inputEl} type="text" />
    </>
  );
}
```

### Refs 转发 (Ref Forwarding)

默认情况下，你不能在函数组件上使用 `ref` 属性，因为它们没有实例。如果你想让一个父组件能够获取其子组件内部的某个 DOM 节点的 ref，你需要使用 **`React.forwardRef`**。

`React.forwardRef` 接受一个渲染函数，该函数接收 `props` 和 `ref` 两个参数，并返回一个 React 节点。

**示例：**
假设我们想创建一个 `FancyButton` 组件，但希望其父组件能够直接访问到底层的 `<button>` DOM 元素。

```jsx
import React, { forwardRef } from 'react';

// 1. 使用 forwardRef 包裹组件
const FancyButton = forwardRef((props, ref) => (
  <button ref={ref} className="FancyButton">
    {props.children}
  </button>
));

// 现在，父组件可以获取到 ref
function App() {
  const ref = useRef(null);
  
  useEffect(() => {
    // ref.current 指向了底层的 <button> DOM 元素
    ref.current.focus(); 
  }, []);

  return <FancyButton ref={ref}>Click me!</FancyButton>;
}
```
`forwardRef` 在创建可复用的组件库时尤其有用，因为它允许库的使用者能够与库组件内部的 DOM 节点进行交互。

**总结**:
- **Portals** 提供了一种将组件渲染到 DOM 树中不同位置的"传送门"，是处理模态框等悬浮 UI 的首选方案。
- **Refs** 则提供了一个"逃生舱口"，让你在必要时能够脱离单向数据流，直接与 DOM 节点交互。
- **`forwardRef`** 使得父组件可以获取子组件内部的 DOM ref，增强了组件的封装性和可复用性。

谨慎使用 Refs，尽量优先考虑声明式的 `props` 来实现功能。只有在处理焦点、动画或集成第三方库等场景下，才应该使用 Refs。 