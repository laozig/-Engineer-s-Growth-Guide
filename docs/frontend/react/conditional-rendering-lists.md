# 6. 条件渲染与列表

在 React 中，你可以根据组件的状态（state）或属性（props）来创建不同的元素，从而控制应用的UI展现。

## 条件渲染 (Conditional Rendering)

条件渲染的工作方式与 JavaScript 中的条件语句一样。你可以使用 `if` 语句或三元运算符等 JavaScript 操作符来创建表示当前状态的元素，然后让 React 更新 UI 以匹配它们。

### `if` 语句

我们可以编写一个组件，根据用户是否已登录来显示不同的问候语。

```jsx
function Greeting(props) {
  const isLoggedIn = props.isLoggedIn;
  if (isLoggedIn) {
    return <h1>Welcome back!</h1>;
  }
  return <h1>Please sign up.</h1>;
}

ReactDOM.render(
  <Greeting isLoggedIn={false} />,
  document.getElementById('root')
);
```

### 元素变量

你可以使用变量来存储元素。这可以帮助你有条件地渲染组件的一部分，而其他部分保持不变。

```jsx
function LoginButton(props) {
  return <button onClick={props.onClick}>Login</button>;
}

function LogoutButton(props) {
  return <button onClick={props.onClick}>Logout</button>;
}

class LoginControl extends React.Component {
  constructor(props) {
    super(props);
    this.state = {isLoggedIn: false};
  }

  // ... handleLoginClick 和 handleLogoutClick ...

  render() {
    const isLoggedIn = this.state.isLoggedIn;
    let button; // 声明一个变量来存储按钮元素

    if (isLoggedIn) {
      button = <LogoutButton onClick={this.handleLogoutClick} />;
    } else {
      button = <LoginButton onClick={this.handleLoginClick} />;
    }

    return (
      <div>
        <Greeting isLoggedIn={isLoggedIn} />
        {button}
      </div>
    );
  }
}
```

### 内联 `if` 与逻辑 `&&` 运算符

如果你想在 JSX 中直接嵌入条件逻辑，可以使用 JavaScript 的语法。

`{ condition && <Component /> }` 这种写法非常方便。它表示**只有当 `condition` 为 `true` 时，才会渲染 `&&` 右侧的元素**。如果 `condition` 为 `false`，则什么也不渲染。

```jsx
function Mailbox(props) {
  const unreadMessages = props.unreadMessages;
  return (
    <div>
      <h1>Hello!</h1>
      {unreadMessages.length > 0 &&
        <h2>
          You have {unreadMessages.length} unread messages.
        </h2>
      }
    </div>
  );
}
```

### 内联 `if-else` 与三元运算符

另一种内联条件渲染的方式是使用 JavaScript 的三元运算符 `condition ? true : false`。

```jsx
render() {
  const isLoggedIn = this.state.isLoggedIn;
  return (
    <div>
      The user is <b>{isLoggedIn ? 'currently' : 'not'}</b> logged in.
    </div>
  );
}
```
这对于处理更复杂的 `if-else` 逻辑也非常有用。

```jsx
render() {
  const isLoggedIn = this.state.isLoggedIn;
  return (
    <div>
      {isLoggedIn
        ? <LogoutButton onClick={this.handleLogoutClick} />
        : <LoginButton onClick={this.handleLoginClick} />
      }
    </div>
  );
}
```

## 渲染列表

你可以使用 JavaScript 的 `map()` 方法来构建元素列表。

下面的代码中，我们使用 `map()` 函数来遍历 `numbers` 数组，并为每个数组项返回一个 `<li>` 元素。

```jsx
const numbers = [1, 2, 3, 4, 5];
const listItems = numbers.map((number) =>
  <li>{number}</li>
);

ReactDOM.render(
  <ul>{listItems}</ul>,
  document.getElementById('root')
);
```

通常，我们会将列表渲染逻辑封装在组件中。

```jsx
function NumberList(props) {
  const numbers = props.numbers;
  const listItems = numbers.map((number) =>
    <li>{number}</li>
  );
  return (
    <ul>{listItems}</ul>
  );
}
```

### `key` 属性

 