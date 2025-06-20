# 4. State 与生命周期

如果说 `props` 是从父组件传递给子组件的"参数"，那么 `state` 就是组件内部自己管理和维护的数据。`state` 的变化是驱动UI更新的核心。

本章我们主要使用Class组件来介绍State和生命周期的概念，因为这些概念最初是在Class组件中引入的。在后续的[Hooks章节](intro-to-hooks-usestate.md)中，你将学会如何使用`useState`等Hooks在函数组件中实现同样的功能。

## 认识 State

让我们以一个每秒更新一次的时钟组件为例。

首先，我们尝试只用`props`来实现。`Clock`组件从`props`接收一个`date`对象并显示时间：
```jsx
function Clock(props) {
  return (
    <div>
      <h1>Hello, world!</h1>
      <h2>It is {props.date.toLocaleTimeString()}.</h2>
    </div>
  );
}

function tick() {
  ReactDOM.render(
    <Clock date={new Date()} />,
    document.getElementById('root')
  );
}

setInterval(tick, 1000);
```
这段代码能工作，但它有一个问题：`Clock`组件是"被动"的。它自身无法更新时间，而是依赖外部的`setInterval`每秒调用`ReactDOM.render`来重新渲染。这违背了组件应该自我管理的原则。

理想情况下，我们希望`Clock`组件能够自己管理时间更新的逻辑。它应该有自己的定时器，并每秒更新自己的UI。为了实现这一点，我们需要为`Clock`组件添加`state`。

## 将函数组件转换为 Class 组件

为了使用`state`和生命周期方法，我们首先需要将`Clock`这个函数组件转换为Class组件：

1.  创建一个同名的 ES6 `class`，并继承 `React.Component`。
2.  添加一个空的 `render()` 方法。
3.  将函数体内的代码移动到 `render()` 方法中。
4.  在 `render()` 方法中使用 `this.props` 替换 `props`。

```jsx
class Clock extends React.Component {
  render() {
    return (
      <div>
        <h1>Hello, world!</h1>
        <h2>It is {this.props.date.toLocaleTimeString()}.</h2>
      </div>
    );
  }
}
```

## 为 Class 组件添加 State

现在，我们将`date`从`props`中移除，并将其作为组件自身的`state`来管理。

1.  在 `render` 方法中，将 `this.props.date` 修改为 `this.state.date`。
2.  添加一个**类构造函数 (constructor)**，在其中初始化`state`。

```jsx
class Clock extends React.Component {
  constructor(props) {
    super(props); // 必须在构造函数中调用 super(props)
    this.state = { date: new Date() }; // 初始化 state
  }

  render() {
    return (
      <div>
        <h1>Hello, world!</h1>
        <h2>It is {this.state.date.toLocaleTimeString()}.</h2>
      </div>
    );
  }
}
```
`state`是一个普通的JavaScript对象。

## 添加生命周期方法

在一个组件的生命周期中，随着它的创建、更新和销毁，会自动调用一些特殊的方法，我们称之为**生命周期方法**。

- `componentDidMount()`: 当组件**首次被渲染到DOM中**后，这个方法会被调用。这是设置定时器、发起网络请求等副作用操作的理想位置。
- `componentWillUnmount()`: 当组件**即将从DOM中被移除**时，这个方法会被调用。这是清理定时器、取消网络请求等操作的理想位置。

让我们在`Clock`组件中使用这两个生命周期方法来设置和清理定时器：

```jsx
class Clock extends React.Component {
  constructor(props) {
    super(props);
    this.state = {date: new Date()};
  }

  // 组件挂载后，设置一个定时器
  componentDidMount() {
    this.timerID = setInterval(
      () => this.tick(),
      1000
    );
  }

  // 组件卸载前，清理定时器
  componentWillUnmount() {
    clearInterval(this.timerID);
  }

  tick() {
    // 使用 setState 来更新组件的 state
    this.setState({
      date: new Date()
    });
  }

  render() {
    return (
      <div>
        <h1>Hello, world!</h1>
        <h2>It is {this.state.date.toLocaleTimeString()}.</h2>
      </div>
    );
  }
}

// 现在我们只需渲染一次 Clock 组件
ReactDOM.render(<Clock />, document.getElementById('root'));
```
现在，`Clock`组件已经完全自洽了。它自己设置定时器，自己更新状态，并自己清理资源。

## 正确地使用 State

关于`setState()`，有三个非常重要的规则需要遵守：

### 1. 不要直接修改 State

直接修改`this.state`不会触发组件的重新渲染。

```jsx
// 错误
this.state.comment = 'Hello';
```

必须使用`this.setState()`方法来修改`state`。

```jsx
// 正确
this.setState({comment: 'Hello'});
```
唯一可以给`this.state`赋值的地方是在构造函数中。

### 2. State 的更新可能是异步的

React 为了性能考虑，可能会将多个`setState()`调用合并成一次更新。因为`this.props`和`this.state`可能是异步更新的，所以你不应该依赖它们的值来计算下一个`state`。

例如，下面的代码可能无法正确地更新计数器：
```jsx
// 错误
this.setState({
  counter: this.state.counter + this.props.increment,
});
```

要解决这个问题，可以让`setState()`接收一个**函数**作为参数，而不是一个对象。这个函数将接收前一个`state`作为第一个参数，并将此次更新被应用时的`props`作为第二个参数：

```jsx
// 正确
this.setState((state, props) => ({
  counter: state.counter + props.increment
}));
```

### 3. State 的更新是合并的

当你调用`setState()`时，React 会将你提供的对象合并到当前的`state`中。这个合并是**浅合并 (shallow merge)**。

例如，你的`state`可能包含多个独立的变量：
```javascript
constructor(props) {
  super(props);
  this.state = {
    posts: [],
    comments: []
  };
}
```
你可以用独立的`setState()`调用来分别更新它们：
```javascript
componentDidMount() {
  fetchPosts().then(response => {
    this.setState({
      posts: response.posts
    });
  });

  fetchComments().then(response => {
    this.setState({
      comments: response.comments
    });
  });
}
```
这里的合并是浅合并，所以你调用`this.setState({comments: ...})`时，`this.state.posts`会保持不变。

## 总结

`state`让组件拥有了"记忆"，能够响应事件和时间的变化。生命周期方法则为我们在组件的不同阶段执行副作用（如数据获取、订阅、手动DOM操作）提供了钩子。理解`state`和生命周期是掌握Class组件的关键，也为我们理解函数组件中的`useState`和`useEffect` Hooks打下了坚实的基础。 