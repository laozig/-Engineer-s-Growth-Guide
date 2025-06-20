# 2. JSX 深入理解

JSX（JavaScript XML）是 React 的一个核心特性。它是一种 JavaScript 的语法扩展，允许我们在 JavaScript 文件中编写类似 HTML 的代码。

需要明确的是，**浏览器并不直接理解 JSX**。React 应用的开发环境（如 Create React App 中集成的 Babel）会在代码执行前，将 JSX 编译成常规的 JavaScript 对象。

## 为什么使用 JSX？

React 拥抱一个理念：**渲染逻辑本质上与 UI 逻辑是内在耦合的**。例如，UI 如何响应事件、状态如何随时间变化以及数据如何准备以供显示，这些逻辑都是紧密相关的。

与其将标记（HTML）和逻辑（JavaScript）分离在不同的文件中，React 选择将它们组合在一个称为"组件"的松散耦合单元中。JSX 使得在组件内部编写 UI 结构变得直观和富有表现力。

例如，这段 JSX 代码：
```jsx
const element = <h1>Hello, world!</h1>;
```

会被 Babel 编译成如下的 JavaScript 对象：
```javascript
const element = React.createElement(
  'h1',
  null,
  'Hello, world!'
);
```
这个对象被称为 **React 元素 (React Element)**，它本质上是对要渲染的 DOM 节点的一个轻量级描述。React 读取这些对象，并使用它们来构建和更新浏览器的 DOM。

## JSX 中的规则

### 1. 嵌入 JavaScript 表达式

你可以在 JSX 中使用花括号 `{}` 来嵌入任何有效的 JavaScript **表达式**。

```jsx
const name = 'Ada Lovelace';
const element = <h1>Hello, {name}</h1>; // 嵌入变量

function formatUser(user) {
  return user.firstName + ' ' + user.lastName;
}
const user = { firstName: 'Harper', lastName: 'Perez' };
const element2 = <h1>Hello, {formatUser(user)}</h1>; // 嵌入函数调用
```
任何放在 `{}` 中的内容都会被求值并作为结果输出。

### 2. JSX 也是一个表达式

经过编译后，JSX 表达式会变成常规的 JavaScript 对象。这意味着你可以在 `if` 语句和 `for` 循环中使用 JSX，将其赋值给变量，作为参数传递，以及从函数中返回。

```jsx
function getGreeting(user) {
  if (user) {
    return <h1>Hello, {formatUser(user)}!</h1>; // 从函数返回 JSX
  }
  return <h1>Hello, Stranger.</h1>;
}
```

### 3. 指定属性 (Attributes)

你可以使用类似 HTML 的语法来为 JSX 元素指定属性。

```jsx
const element = <div tabIndex="0"></div>; // 字符串字面量

const avatarUrl = 'https://example.com/avatar.jpg';
const element2 = <img src={avatarUrl} />; // 使用花括号嵌入表达式
```

**注意**:
- React DOM 使用**小驼峰命名法 (camelCase)** 来命名属性，而不是 HTML 的属性名。例如，`class` 变成 `className`，`tabindex` 变成 `tabIndex`。
- 这是因为 `class` 是 JavaScript 的保留关键字。

### 4. 子元素

如果一个标签是空的，你可以像 XML 一样，使用 `/>` 来立即闭合它。

```jsx
const element = <img src={user.avatarUrl} />;
```

JSX 标签也可以包含子元素：

```jsx
const element = (
  <div>
    <h1>Hello!</h1>
    <h2>Good to see you here.</h2>
  </div>
);
```

### 5. 必须有一个根元素

一个组件返回的 JSX 表达式必须被包裹在一个**单一的根元素**中。

```jsx
// 错误！相邻的 JSX 元素必须被包裹在一个闭合标签中
// function App() {
//   return (
//     <h1>Title</h1>
//     <p>Paragraph</p>
//   );
// }

// 正确：使用 <div> 包裹
function App() {
  return (
    <div>
      <h1>Title</h1>
      <p>Paragraph</p>
    </div>
  );
}
```

如果你不希望在真实的 DOM 中增加一个额外的 `<div>` 节点，可以使用 **Fragment**（片段）来包裹。

```jsx
import React, { Fragment } from 'react';

function App() {
  return (
    <Fragment>
      <h1>Title</h1>
      <p>Paragraph</p>
    </Fragment>
  );
}

// 还有一种更简洁的短语法
// function App() {
//   return (
//     <>
//       <h1>Title</h1>
//       <p>Paragraph</p>
//     </>
//   );
// }
```

### 6. 防止注入攻击 (XSS)

React DOM 在渲染之前，默认会**转义 (escapes)**所有嵌入在 JSX 中的值。这意味着你的应用可以免受 XSS (跨站脚本) 攻击。所有内容在渲染前都会被转换成字符串。

例如，即使用户输入了恶意代码，它也不会被执行：
```jsx
const title = response.potentiallyMaliciousInput;
// 这是安全的：
const element = <h1>{title}</h1>;
```
React 会将 `title` 中的任何 HTML 标签字符（如 `<` 和 `>`）进行转义，因此它会被当作纯文本来渲染。

JSX 通过提供一种直观、安全且富有表现力的方式来描述 UI，极大地提升了 React 的开发体验。理解 JSX 如何被编译成 `React.createElement()` 调用是掌握 React 工作原理的关键一步。 