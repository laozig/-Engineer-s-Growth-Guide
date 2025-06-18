# JavaScript DOM 操作完全指南

<div align="center">
  <img src="../../../assets/programming/dom-manipulation.png" alt="DOM Manipulation" width="250">
</div>

> DOM (文档对象模型) 是 Web 开发的基石，它将 HTML 文档转化为一个可供 JavaScript 操作的对象树。精通 DOM 操作，意味着你拥有了用代码动态改变网页内容、结构和样式的能力。本指南将带你从零开始，系统地掌握现代 DOM 操作的方方面面。

## 目录

1.  [**DOM 是什么？**](#1-dom-是什么)
2.  [**第一步：查找元素**](#2-第一步查找元素)
    -   [现代首选：`querySelector` / `querySelectorAll`](#现代首选queryselector--queryselectorall)
    -   [传统方法：`getElementById` 等](#传统方法getelementbyid-等)
3.  [**第二步：修改元素**](#3-第二步修改元素)
    -   [改变内容：`textContent` vs `innerHTML`](#改变内容textcontent-vs-innerhtml)
    -   [改变样式：`style` 与 `classList`](#改变样式style-与-classlist)
    -   [操作属性：`setAttribute`, `getAttribute` 与 `dataset`](#操作属性setattribute-getattribute-与-dataset)
4.  [**第三步：创建与移动元素**](#4-第三步创建与移动元素)
    -   [创建新元素：`createElement`](#创建新元素createelement)
    -   [插入元素：`append`, `prepend`, `before`, `after`](#插入元素append-prepend-before-after)
    -   [移动与移除元素](#移动与移除元素)
5.  [**第四步：响应用户交互 (事件处理)**](#5-第四步响应用户交互-事件处理)
    -   [核心：`addEventListener`](#核心addeventlistener)
    -   [事件对象 (Event Object)](#事件对象-event-object)
    -   [事件冒泡、捕获与委托](#事件冒泡捕获与委托)
6.  [**性能优化与最佳实践**](#6-性能优化与最佳实践)
    -   [批量操作：使用 `DocumentFragment`](#批量操作使用-documentfragment)
    -   [理解重排 (Reflow) 与重绘 (Repaint)](#理解重排-reflow-与-重绘-repaint)

---

## 1. DOM 是什么？
简单来说，浏览器在加载一个HTML文件时，会根据其内容创建一个树状的结构来表示这个文档，这个树状结构就是DOM。JavaScript 可以通过操作这个"树"上的节点（元素、属性、文本等）来改变页面的呈现。

## 2. 第一步：查找元素
要操作一个元素，首先得找到它。

### 现代首选：`querySelector` / `querySelectorAll`
这两个方法使用 CSS 选择器语法，功能强大且灵活，是现代开发的首选。

-   **`querySelector()`**：返回匹配的**第一个**元素。如果找不到，返回 `null`。
-   **`querySelectorAll()`**：返回所有匹配的元素，形式为一个 `NodeList`（一个类数组对象）。

```html
<!-- HTML 示例 -->
<div id="app">
  <p class="content">这是一个段落。</p>
  <ul>
    <li class="item">列表项 1</li>
    <li class="item">列表项 2</li>
  </ul>
</div>
```
```javascript
// 查找第一个 class 为 "item" 的元素
const firstItem = document.querySelector('.item');
console.log(firstItem.textContent); // "列表项 1"

// 查找所有的 li 元素
const allItems = document.querySelectorAll('#app li');

// 遍历 NodeList
allItems.forEach(item => {
  console.log(item.textContent);
});
```

### 传统方法：`getElementById` 等
这些方法速度更快，但在选择器灵活性上受限。

-   `getElementById('id')`: 通过 ID 获取，速度最快。
-   `getElementsByClassName('class')`: 通过类名获取。
-   `getElementsByTagName('tag')`: 通过标签名获取。
> **注意**：后两者返回的是一个 `HTMLCollection`，它是一个"实时"的集合，并且没有 `forEach` 方法（需要用 `Array.from()` 转换后才能使用）。

## 3. 第二步：修改元素

### 改变内容：`textContent` vs `innerHTML`
-   **`textContent`**：只处理纯文本。它会获取或设置元素内的所有文本内容，自动对特殊字符进行转义。**这是更安全、更推荐的方式**。
-   **`innerHTML`**：会解析并渲染 HTML 标签。只有当你确实需要插入HTML结构时才使用它，并要确保内容来源是可信的，以防 [XSS攻击](https://developer.mozilla.org/zh-CN/docs/Glossary/Cross-site_scripting)。

```javascript
const heading = document.querySelector('h1');

heading.textContent = '全新的纯文本标题';
// 浏览器显示: 全新的纯文本标题

heading.innerHTML = '<em>斜体的标题</em>';
// 浏览器显示: (斜体的标题)
```

### 改变样式：`style` 与 `classList`
-   **`.style` 属性**：用于直接修改元素的**内联样式**。属性名需使用小驼峰式命名 (e.g., `backgroundColor`)。
-   **`.classList`**：是操作元素 `class` 属性的最佳方式，它提供 `add()`, `remove()`, `toggle()`, `contains()` 等便捷方法。

```javascript
const button = document.querySelector('button');

// 直接修改样式 (不推荐用于复杂样式)
button.style.color = 'white';
button.style.backgroundColor = 'blue';

// 使用 class (推荐)
button.classList.add('active');      // 添加 'active' 类
button.classList.remove('disabled'); // 移除 'disabled' 类
button.classList.toggle('highlight'); // 如果有 'highlight' 则移除，反之则添加
```

### 操作属性：`setAttribute`, `getAttribute` 与 `dataset`
-   **`getAttribute()` / `setAttribute()`**: 通用的属性获取和设置方法。
-   **直接访问**: 对于标准属性（如 `id`, `src`, `href`），可以直接通过点号访问。
-   **`dataset`**: 专门用于操作 `data-*` 自定义属性。

```javascript
const link = document.querySelector('a');
link.setAttribute('href', 'https://www.mozilla.org');
link.id = 'main-link'; // 直接设置 id

// 操作 data-* 属性
const userProfile = document.querySelector('#profile');
userProfile.dataset.userId = '12345'; // 设置 data-user-id
console.log(userProfile.dataset.userName); // 读取 data-user-name
```

## 4. 第三步：创建与移动元素

### 创建新元素：`createElement`
```javascript
const newParagraph = document.createElement('p');
newParagraph.textContent = '这是一个新创建的段落。';
```

### 插入元素：`append`, `prepend`, `before`, `after`
这些现代方法非常直观，并且可以一次性插入多个节点或文本。

```html
<div id="container"></div>
```
```javascript
const container = document.querySelector('#container');
const p1 = document.createElement('p');
p1.textContent = '段落1';
const p2 = document.createElement('p');
p2.textContent = '段落2';

// .append(): 在元素的子节点末尾插入
container.append(p1, p2, '这是文本。');

// .prepend(): 在元素的子节点开头插入
// .before(): 在元素本身之前插入
// .after(): 在元素本身之后插入
```

### 移动与移除元素
-   **移动**: 如果你将一个已存在于文档中的元素 `append` 或 `insertBefore` 到新的位置，它会自动从原位置被移动过去，而不是被复制。
-   **移除**: `element.remove()` 是最简单的自我移除方式。

```javascript
// 移动 p1 到 container 的开头
container.prepend(p1);

// 移除 p2
p2.remove();
```

## 5. 第四步：响应用户交互 (事件处理)

### 核心：`addEventListener`
这是绑定事件监听的现代标准方法。

```javascript
const button = document.querySelector('button');

function handleClick() {
  console.log('按钮被点击了！');
}

button.addEventListener('click', handleClick);

// 你也可以使用匿名函数或箭头函数
button.addEventListener('mouseover', () => {
  console.log('鼠标悬停！');
});
```

### 事件对象 (Event Object)
当事件被触发时，一个事件对象会自动作为第一个参数传递给监听函数。它包含了事件的详细信息。

```javascript
document.addEventListener('mousemove', (event) => {
  // event.clientX 和 event.clientY 包含了鼠标的坐标
});

const input = document.querySelector('input');
input.addEventListener('keydown', (event) => {
  // event.key 包含了被按下的键
});
```

### 事件冒泡、捕获与委托
- **事件冒泡 (Bubbling)**: 事件从被触发的元素开始，逐级向上传播到根节点。这是默认的行为。
- **事件委托 (Delegation)**: 利用事件冒泡，我们可以将事件监听器设置在父元素上，用来管理所有子元素的事件。这在处理动态添加的元素时非常高效。

```html
<ul id="item-list">
  <li>项目 1</li>
  <li>项目 2</li>
</ul>
```
```javascript
// 事件委托示例
const list = document.querySelector('#item-list');
list.addEventListener('click', (event) => {
  // 检查事件是否由一个 LI 元素触发
  if (event.target.tagName === 'LI') {
    event.target.style.textDecoration = 'line-through';
  }
});
// 现在，即使你动态地向列表中添加新的 <li>，点击事件依然有效！
```

## 6. 性能优化与最佳实践

### 批量操作：使用 `DocumentFragment`
当需要向DOM中添加大量元素时，直接在循环中逐个 `append` 会导致多次**重排**，性能很差。正确的做法是先将元素添加到 `DocumentFragment`（一个内存中的DOM片段），然后一次性地将该片段添加到主DOM中。

```javascript
const list = document.querySelector('#list');
const fragment = document.createDocumentFragment();

for (let i = 0; i < 100; i++) {
  const item = document.createElement('li');
  item.textContent = `Item ${i + 1}`;
  fragment.append(item);
}

// 只需一次DOM操作
list.append(fragment);
```

### 理解重排 (Reflow) 与重绘 (Repaint)
- **重排**: 当元素的几何属性（如尺寸、位置）改变时发生，浏览器需要重新计算布局。这是一个非常耗费性能的操作。
- **重绘**: 当元素的视觉外观（如颜色、背景）改变，但布局不变时发生。
> **最佳实践**: 尽量减少重排的次数。例如，通过 `classList` 一次性改变多个样式，而不是逐个修改 `.style` 属性。

```javascript
// 示例：使用 class 一次性改变多个样式
const button = document.querySelector('button');
button.classList.add('active', 'highlight');
```

## 浏览器兼容性注意事项

- 较新的DOM API（如`classList`、`dataset`等）在旧浏览器中可能不可用
- 使用特性检测确定是否支持特定API
- 考虑使用polyfill或转译工具支持旧浏览器

```javascript
// 特性检测示例
if ('querySelector' in document) {
  // 浏览器支持querySelector
  const element = document.querySelector('.myClass');
} else {
  // 降级为传统方法
  const elements = document.getElementsByClassName('myClass');
  const element = elements[0];
}
```

## 实际应用示例

### 创建动态表格

```javascript
function createTable(data) {
  const table = document.createElement('table');
  const thead = document.createElement('thead');
  const tbody = document.createElement('tbody');
  
  // 创建表头
  const headerRow = document.createElement('tr');
  Object.keys(data[0]).forEach(key => {
    const th = document.createElement('th');
    th.textContent = key;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  
  // 创建数据行
  data.forEach(item => {
    const row = document.createElement('tr');
    Object.values(item).forEach(value => {
      const td = document.createElement('td');
      td.textContent = value;
      row.appendChild(td);
    });
    tbody.appendChild(row);
  });
  
  table.appendChild(thead);
  table.appendChild(tbody);
  return table;
}

// 使用示例
const userData = [
  { id: 1, name: '张三', age: 28 },
  { id: 2, name: '李四', age: 32 },
  { id: 3, name: '王五', age: 25 }
];

document.body.appendChild(createTable(userData));
```

### 实现简单的标签页功能

```javascript
function initTabs() {
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // 移除所有活动状态
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(content => content.classList.remove('active'));
      
      // 设置当前活动标签
      tab.classList.add('active');
      const tabId = tab.getAttribute('data-tab');
      document.getElementById(tabId).classList.add('active');
    });
  });
  
  // 默认激活第一个标签
  if (tabs.length > 0) {
    tabs[0].click();
  }
}

// HTML结构示例
/*
<div class="tabs">
  <div class="tab active" data-tab="tab1">标签1</div>
  <div class="tab" data-tab="tab2">标签2</div>
  <div class="tab" data-tab="tab3">标签3</div>
</div>

<div class="tab-contents">
  <div id="tab1" class="tab-content">内容1</div>
  <div id="tab2" class="tab-content">内容2</div>
  <div id="tab3" class="tab-content">内容3</div>
</div>
*/
``` 