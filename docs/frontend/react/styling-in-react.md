# 15. 样式解决方案: CSS Modules & Styled-components

在 React 中为组件添加样式有多种方式。传统的全局 CSS 文件虽然简单，但容易导致命名冲突和样式覆盖问题。为了解决这些问题，社区发展出了多种**组件化的 CSS 解决方案**，它们旨在将样式的作用域限制在单个组件内部。

本章我们重点介绍两种最流行的方案：**CSS Modules** 和 **Styled-components**。

## CSS Modules

CSS Modules 并不是一个库，而是一个构建步骤（通常由 Webpack 或 Parcel 等打包工具处理）。它允许你像往常一样编写 CSS，但在构建时，它会自动为你的类名生成一个**独一无二的哈希字符串**，从而实现了样式的局部作用域。

Create React App 内置了对 CSS Modules 的支持。你只需要将你的 CSS 文件命名为 `[name].module.css` 即可。

### 如何使用

1.  **创建一个 `.module.css` 文件 (`Button.module.css`)**:

```css
/* Button.module.css */
.button {
  background-color: #61dafb;
  color: white;
  padding: 10px 20px;
  border: none;
  border-radius: 5px;
  cursor: pointer;
}

.button:hover {
  background-color: #4fa8c5;
}
```

2.  **在组件中导入并使用 (`Button.js`)**:

```jsx
import React from 'react';
import styles from './Button.module.css'; // 导入样式模块

function Button() {
  // `styles` 是一个对象，key 是你的原始类名，value 是生成的唯一哈希类名
  // 例如：styles.button => "Button_button__1_a_b_c_d_e"
  return (
    <button className={styles.button}>
      Click Me
    </button>
  );
}
```

### 优点
- **局部作用域**: 彻底解决了全局命名冲突的问题。
- **标准的 CSS**: 你仍然在编写标准的 CSS，没有新的语法学习成本。
- **与 Sass/Less 结合**: 可以轻松地与 CSS 预处理器结合使用。

### 缺点
- **动态样式**: 处理基于 props 的动态样式比较麻烦，通常需要内联样式或多个条件类名。
- **IDE 支持**: 类名的自动补全可能需要特定的 IDE 插件。

## Styled-components

Styled-components 是一个流行的 **CSS-in-JS** 库。它允许你直接在 JavaScript 文件中编写实际的 CSS 代码来为组件添加样式。它利用了 ES6 的**标签模板字面量 (tagged template literals)**。

### 如何使用

首先，安装依赖：
```bash
npm install styled-components
```

1.  **创建样式化组件 (`Button.js`)**:

```jsx
import React from 'react';
import styled from 'styled-components';

// 创建一个 <button> 组件，并附带一些样式
const StyledButton = styled.button`
  background-color: #61dafb;
  color: white;
  padding: 10px 20px;
  border: none;
  border-radius: 5px;
  cursor: pointer;

  &:hover {
    background-color: #4fa8c5;
  }
`;

function Button() {
  return (
    <StyledButton>
      Click Me
    </StyledButton>
  );
}
```

### 动态样式

Styled-components 最强大的功能之一是能够轻松地根据组件的 `props` 来调整样式。

```jsx
const StyledButton = styled.button`
  /* ... */
  background-color: ${props => (props.primary ? '#61dafb' : 'gray')};
  
  /* 如果有 large prop，则应用更大的 padding */
  padding: ${props => (props.large ? '15px 30px' : '10px 20px')};
`;

// 使用
function App() {
  return (
    <div>
      <StyledButton>Normal</StyledButton>
      <StyledButton primary>Primary</StyledButton>
      <StyledButton large>Large</StyledButton>
    </div>
  );
}
```

### 优点
- **自动作用域**: 样式自动与组件绑定，无需担心命名冲突。
- **动态样式**: 基于 props 的动态样式处理非常直观和强大。
- **代码共存**: 样式和组件逻辑在同一个文件中，便于管理和维护单个组件。
- **移除了类名映射**: 你不再需要管理 `className` 和 CSS 文件之间的映射。

### 缺点
- **学习曲线**: 需要适应 CSS-in-JS 的思维方式和标签模板字面量的语法。
- **运行时开销**: 样式是在运行时生成的，相比于构建时生成的 CSS Modules，可能会有一些微小的性能开销（但在大多数应用中可以忽略不计）。
- **增加了包体积**: 需要在你的应用中额外引入一个库。

## 如何选择？

| 特性 | CSS Modules | Styled-components (CSS-in-JS) |
| :--- | :--- | :--- |
| **范式** | 编写 CSS，导入到 JS | 在 JS 中编写 CSS |
| **作用域** | 文件级别 | 组件级别 |
| **动态样式** | 较弱 (通过切换类名) | 非常强大 (通过 props) |
| **依赖** | 构建工具 (内置于 CRA) | 需要安装库 |
| **学习成本** | 低 | 中 |
| **团队协作** | CSS 和 JS 分离，可能适合不同角色的开发者协作 | 样式和逻辑紧密耦合 |

- **选择 CSS Modules**:
    - 如果你的团队更习惯于传统的 CSS 工作流。
    - 如果你希望将样式与组件逻辑完全分离。
    - 如果你对引入新的库和运行时开销非常敏感。

- **选择 Styled-components**:
    - 如果你构建的是一个高度动态、组件化的设计系统。
    - 如果你喜欢将所有与组件相关的代码（逻辑、模板、样式）放在同一个地方。
    - 如果你的应用大量使用基于状态或 props 的动态样式。

两种方案都很好地解决了 React 中的样式作用域问题。现代 React 生态中，**CSS-in-JS**（以 Styled-components 和 Emotion 为代表）因其强大的动态样式能力和组件化思想而越来越受欢迎。 