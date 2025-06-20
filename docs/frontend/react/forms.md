# 7. 表单处理

在 React 中，HTML 表单元素（如 `<input>`, `<textarea>`, 和 `<select>`）的工作方式与其他 DOM 元素略有不同，因为表单元素本身会保留一些内部状态。例如，这个纯 HTML 表单接收一个单一的 name：
```html
<form>
  <label>
    Name:
    <input type="text" name="name" />
  </label>
  <input type="submit" value="Submit" />
</form>
```
这个表单具有默认的 HTML 表单行为：当用户提交时，会跳转到一个新页面。如果你想在 React 中保持这种行为，也是可以的。但大多数情况下，我们希望用一个 JavaScript 函数来方便地处理表单的提交，并访问用户输入的数据。实现这一点的标准方式是一种被称为**"受控组件" (Controlled Components)** 的技术。

## 受控组件

在 HTML 中，像 `<input>`, `<textarea>`, 和 `<select>` 这样的表单元素通常自己维护 `state`，并根据用户输入进行更新。在 React 中，可变的状态通常保存在组件的 `state` 属性中，并且只能通过 `setState()` 来更新。

我们可以通过将两者结合起来，使 React 的 `state` 成为"唯一的数据源"。这样，渲染表单的 React 组件也控制着在后续用户输入中表单发生的事情。一个其值由 React 控制的输入表单元素被称为"受控组件"。

### `input` 示例

```jsx
class NameForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {value: ''};
  }

  handleChange = (event) => {
    // 每次按键都更新 state
    this.setState({value: event.target.value});
  }

  handleSubmit = (event) => {
    alert('A name was submitted: ' + this.state.value);
    event.preventDefault();
  }

  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <label>
          Name:
          <input type="text" value={this.state.value} onChange={this.handleChange} />
        </label>
        <input type="submit" value="Submit" />
      </form>
    );
  }
}
```

工作流程如下：
1.  `<input>` 元素的 `value` 属性被设置为组件 `state` 中的 `this.state.value`。
2.  当用户在输入框中键入时，`onChange` 事件被触发。
3.  `handleChange` 方法被调用。它通过 `event.target.value` 获取输入框的当前值。
4.  `setState()` 被调用，用新的值来更新组件的 `state`。
5.  由于 `state` 改变，组件重新渲染，`<input>` 的 `value` 被更新为 `state` 中的最新值。

通过这种方式，React 组件的 `state` 始终与输入框中显示的值保持同步，成为"唯一数据源"。

### `textarea` 标签

在 HTML 中, `<textarea>` 元素通过其子元素来定义它的文本：
```html
<textarea>Hello there, this is some text in a text area</textarea>
```
在 React 中, `<textarea>` 使用 `value` 属性来代替。这样，使用 `<textarea>` 的表单可以写得非常像使用单行 `<input>` 的表单：

```jsx
class EssayForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      value: 'Please write an essay about your favorite DOM element.'
    };
  }
  // ... handleChange 和 handleSubmit ...
  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <label>
          Essay:
          <textarea value={this.state.value} onChange={this.handleChange} />
        </label>
        <input type="submit" value="Submit" />
      </form>
    );
  }
}
```

### `select` 标签

在 HTML 中, `<select>` 创建一个下拉列表。例如，这个 HTML 创建一个水果的下拉列表：
```html
<select>
  <option value="grapefruit">Grapefruit</option>
  <option value="lime">Lime</option>
  <option selected value="coconut">Coconut</option>
  <option value="mango">Mango</option>
</select>
```
注意 `Coconut` 选项是如何通过 `selected` 属性被初始选中的。

在 React 中，我们不在 `option` 标签上使用 `selected` 属性，而是在根 `select` 标签上使用一个 `value` 属性。这在受控组件中更方便，因为你只需要在一个地方更新它。

```jsx
class FlavorForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {value: 'coconut'};
  }
  // ... handleChange 和 handleSubmit ...
  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <label>
          Pick your favorite flavor:
          <select value={this.state.value} onChange={this.handleChange}>
            <option value="grapefruit">Grapefruit</option>
            <option value="lime">Lime</option>
            <option value="coconut">Coconut</option>
            <option value="mango">Mango</option>
          </select>
        </label>
        <input type="submit" value="Submit" />
      </form>
    );
  }
}
```
总的来说, `<input type="text">`, `<textarea>`, 和 `<select>` 都工作得非常相似 —— 它们都接受一个 `value` 属性，你可以用它来实现一个受控组件。

## 处理多个输入

当你有多个受控的 `input` 元素时，你可以给每个元素添加一个 `name` 属性，并让处理函数根据 `event.target.name` 的值来选择做什么。

```jsx
class Reservation extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      isGoing: true,
      numberOfGuests: 2
    };
  }

  handleInputChange = (event) => {
    const target = event.target;
    const value = target.type === 'checkbox' ? target.checked : target.value;
    const name = target.name;

    this.setState({
      [name]: value // 使用 ES6 的计算属性名语法来更新正确的 state 字段
    });
  }
  
  // ...
}
```
这里的 `[name]` 是 ES6 的**计算属性名 (computed property name)** 语法，它允许你在方括号内使用表达式来作为对象的属性名。

## 非受控组件 (Uncontrolled Components)

在某些情况下，使用受控组件可能很繁琐，因为你需要为数据的每一次变化都编写事件处理程序，并通过一个 React 组件来传递所有的 `state`。

在这种情况下，你可能想使用**非受控组件**。非受控组件由 DOM 本身来处理表单数据。要编写一个非受控组件，你需要使用 **ref** 来从 DOM 中获取表单值。

```jsx
class NameForm extends React.Component {
  constructor(props) {
    super(props);
    this.input = React.createRef(); // 创建一个 ref
  }

  handleSubmit = (event) => {
    alert('A name was submitted: ' + this.input.current.value);
    event.preventDefault();
  }

  render() {
    return (
      <form onSubmit={this.handleSubmit}>
        <label>
          Name:
          <input type="text" ref={this.input} />
        </label>
        <input type="submit" value="Submit" />
      </form>
    );
  }
}
```

- **何时使用非受控组件？** 如果你想要快速实现，或者不想管理每个输入的`state`，非受控组件会更简单。当你需要集成非React代码，或者处理文件输入（`<input type="file">`，其`value`是只读的）时，它们也很有用。
- **何时使用受控组件？** 绝大多数情况下，推荐使用受控组件来处理表单。它使得对输入进行即时验证、有条件地禁用/启用按钮、强制输入格式等操作变得非常直接。

理解和掌握受控组件是 React 开发中的一项关键技能。它虽然需要编写更多的代码，但却能让你以一种"React"的方式来管理和验证表单数据。 