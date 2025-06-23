# CSS3 核心概念

CSS3 在原有的基础上引入了大量强大的新特性，极大地增强了开发者的样式控制能力。本章将重点介绍其中最核心、最常用的部分：高级选择器、增强的盒子模型、以及强大的伪类和伪元素。

## 1. 高级选择器

CSS3 引入了多种新的选择器，使得我们能够更精确、更高效地选中目标元素，而无需依赖过多的 class 或 id。

| 选择器                 | 示例                             | 描述                                           |
| ---------------------- | -------------------------------- | ---------------------------------------------- |
| **属性选择器**         |                                  |                                                |
| [attr^="val"]        | [href^="https"]                | 选中 href 属性值以 "https" 开头的 <a> 元素。 |
| [attr$="val"]        | img[src$=".png"]                | 选中 src 属性值以 ".png" 结尾的 <img> 元素。  |
| [attr*="val"]        | p[class*="warning"]             | 选中 class 属性值包含 "warning" 的 <p> 元素。|
| **结构伪类选择器**     |                                  |                                                |
| :root                | :root { --main-color: #333; }   | 选中文档的根元素，通常是 <html>。常用于定义全局 CSS 变量。 |
| :nth-child(n)        | li:nth-child(2n)                | 选中所有偶数位的 <li> 元素。                 |
| :nth-of-type(n)      | p:nth-of-type(2)                | 选中其父元素下第二个 <p> 元素。              |
| :first-of-type       | h2:first-of-type                | 选中其父元素下第一个 <h2> 元素。              |
| :last-of-type        | p:last-of-type                  | 选中其父元素下最后一个 <p> 元素。              |
| :only-child          | p:only-child                    | 选中作为其父元素唯一子元素的 <p> 元素。      |
| :only-of-type        | span:only-of-type               | 选中其父元素下唯一的 <span> 元素。           |
| :empty               | div:empty                       | 选中没有任何子元素（包括文本节点）的 <div>。 |
| **UI 状态伪类选择器** |                                  |                                                |
| :enabled / :disabled | input:disabled                  | 选中被禁用的 <input> 元素。                  |
| :checked             | input[type="checkbox"]:checked | 选中被勾选的复选框或单选按钮。                 |
| :not(s)              | p:not(.intro)                   | 选中所有不包含 .intro 类的 <p> 元素。      |

## 2. 盒子模型 (ox-sizing)

在传统的 content-box 模型下，一个元素的总宽度 = width + padding + order。这常常导致布局计算变得复杂。

CSS3 引入了 ox-sizing 属性，允许我们改变盒子模型的计算方式。

- **content-box (默认值)**: width 和 height 只包含内容区的尺寸。
- **order-box**: width 和 height 包含了内容区、内边距（padding）和边框（border）。

`css
/*
  当设置一个元素的 width 为 100px 时，
  无论其 padding 和 border 如何变化，
  它在屏幕上占据的总宽度始终是 100px。
  这使得布局更加直观和可预测。
*/
.element {
  box-sizing: border-box;
  width: 100px;
  padding: 10px;
  border: 2px solid black; /* 总宽度仍然是 100px */
}
`

**最佳实践**:
通常建议对所有元素设置 order-box，以统一布局行为。

`css
*,
*::before,
*::after {
  box-sizing: border-box;
}
`

## 3. 伪类 (Pseudo-classes) 与伪元素 (Pseudo-elements)

### 伪类
伪类用于向选择器添加特殊的效果，基于元素的不同状态。例如 :hover, :active, :focus。CSS3 扩展了伪类的能力，如上文提到的结构伪类和 UI 状态伪类。

### 伪元素
伪元素用于创建一些不在文档树中的元素，并为其添加样式。CSS3 规范要求使用双冒号 :: 来区分伪元素和伪类，但浏览器为了兼容性通常也支持单冒号。

- **::before 和 ::after**:
  这两个是最强大的伪元素，可以在一个元素的内容之前或之后插入生成的内容。常用于清除浮动、添加装饰性图标等。

  `css
  .clearfix::after {
    content: ""; /* 伪元素必须设置 content 属性 */
    display: table;
    clear: both;
  }

  a::before {
    content: " ";
  }
  `

- **::first-line 和 ::first-letter**:
  可以为元素的第一行或第一个字母设置特殊样式。

  `css
  p::first-letter {
    font-size: 2em;
    font-weight: bold;
    color: #8A2BE2;
  }
  `

- **::selection**:
  可以自定义用户在页面上选中文本时的外观。

  `css
  ::selection {
    background-color: #ffb7b7;
    color: #fff;
  }
  `

掌握了这些核心概念，你就为学习更高级的 CSS 技术（如 Flexbox 和 Grid）打下了坚实的基础。下一章，我们将学习 **[背景、边框与阴影](backgrounds-borders-shadows.md)**。
