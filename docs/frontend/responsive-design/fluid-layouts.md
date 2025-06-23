# 构建流式布局：Flexbox与Grid的响应式应用

流式布局是响应式设计的核心，它让我们的页面能够像液体一样适应不同尺寸的容器。虽然早期的流式布局依赖于 loat 和百分比宽度，但现代 CSS 提供了两个强大的多的工具：**Flexbox** 和 **Grid**。本章将深入探讨如何利用它们来构建健壮、灵活的响应式布局。

## 1. 为何选择 Flexbox 和 Grid？

- **可预测性**: 它们提供了比 loat 更强大、更可预测的空间分配和对齐能力。
- **简化的对齐**: 垂直居中在 loat 布局中是一个臭名昭著的难题，而在 Flexbox 和 Grid 中只是一行代码的事。
- **源码顺序无关性**: order 属性和 Grid 的放置能力允许我们改变元素的视觉呈现顺序，而无需改动 HTML 源码，这对于响应式设计非常有利。
- **内在的灵活性**: 它们的设计初衷就是为了处理未知尺寸的内容和可变的容器空间。

## 2. Flexbox：一维布局的瑞士军刀

Flexbox 在处理 **一维** 空间（无论是行还是列）的布局时表现出色。它非常适合组件级别的布局。

### 场景一：响应式导航栏

一个常见的模式是，导航栏在桌面端是水平排列的，在移动端则变为垂直堆叠。

**HTML:**
`html
<nav class="main-nav">
  <a href="#" class="nav-logo">LOGO</a>
  <ul class="nav-menu">
    <li><a href="#">Home</a></li>
    <li><a href="#">About</a></li>
    <li><a href="#">Services</a></li>
    <li><a href="#">Contact</a></li>
  </ul>
</nav>
`

**CSS (Mobile First):**
`css
.main-nav {
  /* 在移动端，让LOGO和菜单垂直堆叠 */
  display: flex;
  flex-direction: column;
  align-items: center; /* 居中对齐 */
}

.nav-menu {
  list-style: none;
  padding: 0;
  display: flex;
  flex-direction: column; /* 菜单项也是垂直的 */
  width: 100%;
  text-align: center;
}

.nav-menu li {
  margin: 0.5rem 0;
}

/* 在桌面端，变为水平排列 */
@media (min-width: 768px) {
  .main-nav {
    flex-direction: row; /* 主方向变为水平 */
    justify-content: space-between; /* LOGO和菜单两端对齐 */
  }

  .nav-menu {
    flex-direction: row; /* 菜单项也变为水平 */
    width: auto;
  }

  .nav-menu li {
    margin: 0 1rem;
  }
}
`

### 场景二：等高卡片列

当一行中有多个卡片，而卡片内容高度不一时，Flexbox 可以轻松实现等高对齐。

`css
.card-container {
  display: flex;
  flex-wrap: wrap; /* 允许换行 */
  gap: 1rem;
}

.card {
  flex: 1 1 300px; /* 关键点 */
  border: 1px solid #ccc;
  padding: 1rem;
  display: flex;
  flex-direction: column;
}

.card-content {
  flex-grow: 1; /* 让内容区占据所有可用空间，将按钮推到底部 */
}

.card-button {
  margin-top: auto; /* 将按钮推到卡片底部 */
}
`
- **lex: 1 1 300px** 的解释：
  - lex-grow: 1: 允许卡片放大以填充剩余空间。
  - lex-shrink: 1: 允许卡片收缩。
  - lex-basis: 300px: 卡片的理想基础宽度是300px。当容器足够宽时，一行可以放下多个300px的卡片；当容器变窄时，卡片会自动收缩并换行。这实现了无需媒体查询的响应式行为。

## 3. Grid：二维布局的王者

Grid 专为 **二维** 布局而生，是进行页面级宏观布局（Page Layout）的最佳选择。

### 场景一：经典的圣杯布局

圣杯布局（Header, Footer, Main Content, Left/Right Sidebars）是 Grid 的完美应用场景。

**HTML:**
`html
<div class="page-container">
  <header>Header</header>
  <main>Main Content</main>
  <aside class="sidebar-left">Left Sidebar</aside>
  <aside class="sidebar-right">Right Sidebar</aside>
  <footer>Footer</footer>
</div>
`

**CSS (Mobile First):**
`css
.page-container {
  display: grid;
  gap: 1rem;
  /* 在移动端，所有区域按源码顺序单列堆叠 */
  grid-template-areas:
    "header"
    "main"
    "sidebar-left"
    "sidebar-right"
    "footer";
}

/* 将元素分配到网格区域 */
header { grid-area: header; }
main { grid-area: main; }
.sidebar-left { grid-area: sidebar-left; }
.sidebar-right { grid-area: sidebar-right; }
footer { grid-area: footer; }


/* 在桌面端，重新定义网格结构 */
@media (min-width: 1024px) {
  .page-container {
    /* 定义一个三列网格，侧边栏固定宽度，主内容区自适应 */
    grid-template-columns: 200px 1fr 200px;
    grid-template-areas:
      "header header header"
      "sidebar-left main sidebar-right"
      "footer footer footer";
  }
}
`
通过 grid-template-areas，我们可以直观地画出布局，然后在不同的断点重新绘制，极其强大且易于理解。

### 场景二：无需媒体查询的响应式网格

Grid 结合 epeat(), uto-fit 和 minmax() 可以创建出一种内在响应式的布局，它甚至不需要任何媒体查询。

`css
.photo-gallery {
  display: grid;
  gap: 1rem;
  /* 魔法发生在这里 */
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
}
`
**这行代码的解释**:
- **epeat(auto-fit, ...)**: 告诉网格尽可能多地在可用空间内容纳轨道。
- **minmax(250px, 1fr)**: 定义了每个轨道的尺寸范围。
  - min: 每个轨道的最小宽度是 250px。
  - max: 在分配完最小宽度后，将剩余空间按比例（1fr）分配给每个轨道。

**效果**:
- 当容器很宽时，浏览器会自动计算一行能放下多少个最小为 250px 的列，然后将它们等宽拉伸填满空间。
- 当容器变窄，不足以放下那么多列时，uto-fit 会自动减少列数，并将被挤下去的项移动到新的一行。
- 这仅仅用一行 CSS 就实现了一个完美的、自适应的响应式图片画廊。

## 4. Flexbox 与 Grid 结合使用

在真实项目中，两者通常结合使用，发挥各自的优势。一个常见的模式是：
- 使用 **Grid** 进行页面的整体、宏观布局划分。
- 在由 Grid 创建的某个网格区域（如 header 或 main）内部，使用 **Flexbox** 来对齐和排列该区域内的具体内容项。

`css
/* 宏观布局 */
.page {
  display: grid;
  grid-template-columns: 1fr 3fr; /* 两列布局 */
}

/* 在 Grid Item 内部使用 Flexbox */
.page-header {
  grid-column: 1 / -1; /* 头部横跨所有列 */
  display: flex;
  justify-content: space-between;
  align-items: center;
}
`

---
**下一章**: **[弹性媒体处理](flexible-media.md)**
