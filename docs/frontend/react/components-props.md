# 3. 组件与 Props

组件是 React 的核心。它们是独立的、可复用的代码片段，让你能够将复杂的UI拆分成一个个独立的部分。从概念上讲，组件就像是 JavaScript 函数。它们接收任意的输入（称为"props"），并返回用于描述页面展示内容的 React 元素。

## 函数组件与 Class 组件

在 React 中，定义组件最简单的方式是编写一个 JavaScript 函数：

```javascript
function Welcome(props) {
  return <h1>Hello, {props.name}</h1>;
}
```
这个函数就是一个有效的 React 组件，因为它接收一个单一的 `props` (properties) 对象作为参数，并返回一个 React 元素。我们称之为**函数组件 (Function Component)**。

你也可以使用 ES6 的 `class` 来定义一个组件：

```javascript
class Welcome extends React.Component {
  render() {
    return <h1>Hello, {this.props.name}</h1>;
  }
}
```
我们称之为**Class 组件 (Class Component)**。

在现代 React 开发中（React 16.8+），我们**强烈推荐使用函数组件和 Hooks**，而不是 Class 组件。函数组件更简洁，更容易理解和测试。本指南将主要使用函数组件。

## 渲染组件

之前，我们只遇到过代表 DOM 标签的 React 元素：
```jsx
const element = <div />;
```
然而，元素也可以代表我们自定义的组件：
```jsx
const element = <Welcome name="Sara" />;
```
当 React 遇到一个代表用户自定义组件的元素时，它会将 JSX 属性（attributes）以及子元素（children）作为一个单一的对象传递给这个组件。这个对象就是 **`props`**。

在上面的例子中，`Welcome` 组件会收到 `{name: 'Sara'}` 作为它的 `props`。

## Props (属性)

`props` 是 "properties" 的缩写。它是从父组件向子组件传递数据的方式。

### 将组件组合起来

组件可以在它们的输出中引用其他组件。这让我们能够使用同一个组件来进行任意层次的抽象。一个按钮，一个表单，一个对话框，一个屏：在 React 应用中，这些都通常被表达为组件。

例如，我们可以创建一个 `App` 组件，它渲染了多个 `Welcome` 组件：

```jsx
function Welcome(props) {
  return <h1>Hello, {props.name}</h1>;
}

function App() {
  return (
    <div>
      <Welcome name="Sara" />
      <Welcome name="Cahal" />
      <Welcome name="Edite" />
    </div>
  );
}
```
这个例子展示了 React 组件的**可组合性**。

### 提取组件

不要害怕将组件拆分成更小的组件。

思考一下这个 `Comment` 组件：
```jsx
function Comment(props) {
  return (
    <div className="Comment">
      <div className="UserInfo">
        <img className="Avatar"
          src={props.author.avatarUrl}
          alt={props.author.name}
        />
        <div className="UserInfo-name">
          {props.author.name}
        </div>
      </div>
      <div className="Comment-text">
        {props.text}
      </div>
      <div className="Comment-date">
        {formatDate(props.date)}
      </div>
    </div>
  );
}
```
它接收 `author` (一个对象), `text` (一个字符串), 和 `date` (一个日期) 作为 props，并描述了一个社交媒体网站上的评论。

这个组件因为嵌套过深，很难被修改，而且它的各个部分也很难被复用。让我们从中提取出一些组件。

首先，我们提取 `Avatar`：
```jsx
function Avatar(props) {
  return (
    <img className="Avatar"
      src={props.user.avatarUrl}
      alt={props.user.name}
    />
  );
}
```
`Avatar` 组件不需要知道它正在 `Comment` 内部被渲染。因此，我们给它的 prop 起了一个更通用的名字：`user` 而不是 `author`。

现在我们可以简化 `Comment` 组件：
```jsx
function Comment(props) {
  return (
    <div className="Comment">
      <div className="UserInfo">
        <Avatar user={props.author} />
        <div className="UserInfo-name">
          {props.author.name}
        </div>
      </div>
      {/* ... */}
    </div>
  );
}
```
接下来，我们提取 `UserInfo` 组件，它在 `Avatar` 旁边渲染用户名：
```jsx
function UserInfo(props) {
  return (
    <div className="UserInfo">
      <Avatar user={props.user} />
      <div className="UserInfo-name">
        {props.user.name}
      </div>
    </div>
  );
}
```
`Comment` 组件现在变得更简单了：
```jsx
function Comment(props) {
  return (
    <div className="Comment">
      <UserInfo user={props.author} />
      <div className="Comment-text">
        {props.text}
      </div>
      <div className="Comment-date">
        {formatDate(props.date)}
      </div>
    </div>
  );
}
```
提取组件在一开始可能像是一项繁重的工作，但它在大型应用中能够带来巨大的回报。一个好的经验法则是，如果你 UI 的一部分被多次使用（`Button`, `Panel`, `Avatar`），或者它本身就足够复杂（`App`, `FeedStory`, `Comment`），那么它就是一个很好的提取成组件的候选者。

## Props 是只读的

**无论你使用函数组件还是 Class 组件来声明一个组件，它都绝不能修改自己的 props。**

思考一下这个 `sum` 函数：
```javascript
function sum(a, b) {
  return a + b;
}
```
这样的函数被称为**"纯函数" (Pure Function)**，因为它们不会试图改变它们的输入，并且对于相同的输入，总是返回相同的结果。

相反，下面这个函数是不纯的，因为它改变了它自己的输入：
```javascript
function withdraw(account, amount) {
  account.total -= amount;
}
```
React 遵循一个重要的规则：
**所有 React 组件都必须像纯函数一样，保护它们的 props 不被修改。**

当然，应用的 UI 是动态的，并且会随时间变化。在下一章，我们将介绍一个新的概念："state"。State 允许 React 组件响应用户的操作、网络响应等，来改变它们的输出，而无需违反上述规则。 