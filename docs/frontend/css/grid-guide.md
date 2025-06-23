# Grid 网格布局指南

CSS 网格布局 (Grid Layout) 是一种二维布局系统，它将页面分割成行和列，使得复杂的网页布局设计变得前所未有的简单。与 Flexbox 主要用于一维布局不同，Grid 专为二维布局而生。

## 1. Grid 核心概念

与 Flexbox 类似，Grid 布局也包含 **Grid 容器 (Grid Container)** 和 **Grid 项目 (Grid Item)**。

![Grid 模型](https://css-tricks.com/wp-content/uploads/2018/11/grid-anatomy.png)
*图片来源: CSS-Tricks*

- **Grid 容器**: 应用了 display: grid 或 display: inline-grid 的父元素。
- **Grid 项目**: Grid 容器的直接子元素。
- **Grid 线 (Grid Line)**: 构成网格结构的分界线，包括水平和垂直的。
- **Grid 轨道 (Grid Track)**: 两条相邻 Grid 线之间的空间，即网格的行或列。
- **Grid 单元格 (Grid Cell)**: 两条相邻行和两条相邻列 Grid 线组成的最小单位。
- **Grid 区域 (Grid Area)**: 四条 Grid 线包围的矩形区域，可以由一个或多个单元格组成。

## 2. Grid 容器属性 (Properties for the Parent)

### display
- grid: 将元素变为一个块级的 Grid 容器。
- inline-grid: 将元素变为一个内联级的 Grid 容器。

### grid-template-columns 和 grid-template-rows
定义网格的行和列的轨道尺寸。
- **长度单位**: px, %, em 等。
- **r 单位**: (fractional unit) 代表网格容器中可用空间的一等份。
- **epeat() 函数**: 用于创建重复的轨道模式。
- **minmax() 函数**: 定义一个长度范围，minmax(min, max)。
- **uto**: 由浏览器决定轨道的尺寸。

**示例**:
`css
.container {
  /* 创建一个三列网格，第一列100px，第二列自动，第三列占剩余空间的1份 */
  grid-template-columns: 100px auto 1fr;
  /* 创建两个等高的行 */
  grid-template-rows: repeat(2, 100px);
  /* 创建一个响应式的列布局，每列最小200px，最大1fr */
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
}
`

### grid-template-areas
用于定义网格区域的名称，并将其放置在网格中。
`css
.container {
  grid-template-areas:
    "header header header"
    "sidebar main main"
    "footer footer footer";
}
/* 然后在项目上使用 grid-area 属性 */
.page-header { grid-area: header; }
`

### gap (简写), ow-gap, column-gap
定义 Grid 线的大小，即轨道之间的间距。
- 示例: gap: 20px 10px; (行间距20px，列间距10px)

### justify-items 和 lign-items
定义项目在 **单元格内部** 的对齐方式。
- justify-items: 水平对齐 (行轴)。
- lign-items: 垂直对齐 (列轴)。
- 值: start, end, center, stretch (默认)。

### justify-content 和 lign-content
定义 **整个网格** 在容器内的对齐方式（当网格总尺寸小于容器时）。
- justify-content: 水平对齐。
- lign-content: 垂直对齐。
- 值: start, end, center, space-between, space-around, space-evenly, stretch。

## 3. Grid 项目属性 (Properties for the Children)

### grid-column-start, grid-column-end, grid-row-start, grid-row-end
通过指定 Grid 线的起始和结束位置，来确定一个 Grid 项目的位置和跨度。
- 可以使用数字（第几条线）或 span 关键字（跨越多少个轨道）。

**简写属性**: grid-column 和 grid-row
- 示例: grid-column: 1 / 3; (从第1条列线开始，到第3条列线结束)
- 示例: grid-row: 2 / span 3; (从第2条行线开始，跨越3个行轨道)

### grid-area
给项目命名，用于 grid-template-areas，或者是 grid-row-start / grid-column-start / grid-row-end / grid-column-end 的简写。
- 示例: grid-area: 1 / 2 / 3 / 4;

### justify-self 和 lign-self
允许单个项目覆盖容器的 justify-items 和 lign-items。
- 值: start, end, center, stretch (默认)。

## Flexbox vs. Grid

- **Flexbox**: 更适合一维布局。比如导航栏、项目列表、对齐一组按钮。它的设计初衷是内容优先，让项目在一条轴线上灵活地分配空间。
- **Grid**: 更适合二维布局。比如整个页面的宏观布局、复杂的卡片式布局、棋盘式布局。它的设计初衷是布局优先，先定义网格结构，再将项目放入其中。

在实际开发中，两者经常结合使用，发挥各自的优势。例如，用 Grid 做页面整体布局，用 Flexbox 对齐导航栏中的链接。

---
**下一章**: **[定位（Positioning）详解](positioning.md)**
