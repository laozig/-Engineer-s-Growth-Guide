# 5. 事件处理

在 React 中处理事件与在原生 DOM 中处理事件非常相似，但有一些语法上的区别：

1.  React 事件的命名采用**小驼峰命名法 (camelCase)**，而不是纯小写。例如，HTML 的 `onclick` 在 React 中是 `onClick`。
2.  使用 JSX，你传递一个**函数**作为事件处理程序，而不是一个字符串。例如，`onClick={handleClick}` 而不是 `onclick="handleClick()"`。

## 基本的事件处理

看一个例子：
```jsx
function ActionLink() {
  function handleClick(e) {
    e.preventDefault(); // 阻止默认行为
    console.log('The link was clicked.');
  }

  return (
    <a href="#" onClick={handleClick}>
      Click me
    </a>
  );
}
```
在这里，`e` 是一个**合成事件 (SyntheticEvent)**。React 根据 W3C 规范定义了这些合成事件，所以你不需要担心跨浏览器的兼容性问题。

## `this` 在 Class 组件中的绑定

在 Class 组件中，一个常见的模式是让一个方法作为事件处理程序。当在事件处理程序中需要访问组件实例（例如，访问 `this.props` 或 `this.state`）时，你需要特别注意 `this` 的指向问题。

在 JavaScript 中，类的方法默认是**不绑定 `this`** 的。如果你忘记绑定 `this.handleClick` 并把它传给 `onClick`，当这个函数被实际调用时，`this` 的值会是 `undefined`。

看一个例子，这在运行时会出错：
```jsx
class Toggle extends React.Component {
  constructor(props) {
    super(props);
    this.state = {isToggleOn: true};
    // this.handleClick 没有被绑定
  }

  handleClick() {
    // 当 handleClick 被直接调用时，这里的 `this` 是 undefined
    this.setState(prevState => ({
      isToggleOn: !prevState.isToggleOn
    }));
  }

  render() {
    // 这会导致一个错误，因为 this.handleClick 中的 this 是 undefined
    return (
      <button onClick={this.handleClick}>
        {this.state.isToggleOn ? 'ON' : 'OFF'}
      </button>
    );
  }
}
```

有几种常见的方法来解决这个问题：

### 方法一：在构造函数中绑定 (推荐)

这是官方文档过去推荐的、最经典的方式。在构造函数中明确地将事件处理方法绑定到组件实例上。

```jsx
class Toggle extends React.Component {
  constructor(props) {
    super(props);
    this.state = {isToggleOn: true};

    // 为了在回调中使用 `this`，这个绑定是必不可少的
    this.handleClick = this.handleClick.bind(this);
  }

  handleClick() {
    this.setState(prevState => ({
      isToggleOn: !prevState.isToggleOn
    }));
  }

  render() {
    return (
      <button onClick={this.handleClick}>
        {this.state.isToggleOn ? 'ON' : 'OFF'}
      </button>
    );
  }
}
```

### 方法二：Public Class Fields 语法 (现代推荐)

如果你正在使用 Create React App 或其他支持该语法的现代脚手架，你可以使用 public class fields 语法来正确地绑定回调。

```jsx
class Toggle extends React.Component {
  state = {isToggleOn: true};

  // 使用箭头函数，`this` 会被自动绑定
  handleClick = () => {
    this.setState(prevState => ({
      isToggleOn: !prevState.isToggleOn
    }));
  }

  render() {
    return (
      <button onClick={this.handleClick}>
        {this.state.isToggleOn ? 'ON' : 'OFF'}
      </button>
    );
  }
}
```
这种写法更简洁，也是目前在Class组件中处理事件的常用方式。

### 方法三：在回调中使用箭头函数 (有性能隐患)

你也可以在渲染时直接使用箭头函数来传递事件处理。

```jsx
class Toggle extends React.Component {
  // ...
  render() {
    return (
      <button onClick={() => this.handleClick()}>
        {this.state.isToggleOn ? 'ON' : 'OFF'}
      </button>
    );
  }
}
```
这种方法的问题在于，**每次 `Toggle` 组件渲染时，都会创建一个新的函数**。如果这个回调被作为 prop 传递给子组件，它可能会导致子组件进行不必要的重新渲染，从而带来性能问题。因此，通常不推荐这种方式，除非在非常简单的场景下。

> **对于函数组件**: 在函数组件中，你通常不需要担心 `this` 的问题。你可以在组件内部直接定义一个函数，并将其传递给事件处理器，它自然就能访问到组件作用域内的 props 和 state。
> ```jsx
> function Toggle() {
>   const [isToggleOn, setIsToggleOn] = React.useState(true);
> 
>   function handleClick() {
>     setIsToggleOn(!isToggleOn);
>   }
> 
>   return <button onClick={handleClick}>{isToggleOn ? 'ON' : 'OFF'}</button>;
> }
> ```

## 向事件处理程序传递参数

在循环中，通常需要向事件处理程序传递一个额外的参数。例如，你想知道是哪一行的删除按钮被点击了。

```jsx
// 错误的方式，函数会被立即调用
// <button onClick={this.deleteRow(id)}>Delete Row</button>

// 正确的方式
<button onClick={() => this.deleteRow(id)}>Delete Row</button>

// 或者使用 .bind
<button onClick={this.deleteRow.bind(this, id)}>Delete Row</button>
```
这两种方式都是可行的。箭头函数的方式更易读。在这两种情况下，React 的事件对象 `e` 会作为第二个参数被隐式传递。例如，使用箭头函数时，如果你需要事件对象，可以这样写：`onClick={(e) => this.deleteRow(id, e)}`。使用 `.bind` 时，事件对象会自动在所有显式传递的参数之后追加。 