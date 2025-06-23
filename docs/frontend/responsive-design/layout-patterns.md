# 常见的响应式布局模式

随着响应式设计的发展，社区沉淀出了一些行之有效的、可复用的布局模式。理解这些模式可以帮助我们更快地做出设计决策，并构建出用户体验更佳的响应式网站。

这些模式并不是相互排斥的，一个复杂的页面通常会组合使用多种模式。

## 1. 列下沉 (Column Drop)

这是最常见、最基础的响应式模式之一。

- **描述**: 在宽屏设备上，内容以多列（例如两列、三列）的形式呈现。当屏幕宽度减小到某个断点时，后面的列会依次下沉到前一列的下方，最终在最窄的屏幕上形成一个单列布局。
- **适用场景**: 简单的、内容驱动的网站，如博客、文章列表、简单的营销页面。
- **实现技术**:
  - **Flexbox**: 给容器设置 display: flex 和 lex-wrap: wrap，并为子项设置 lex: 1 1 <base-width> (例如 lex: 1 1 250px)。
  - **Grid**: 使用 grid-template-columns: repeat(auto-fit, minmax(<min-width>, 1fr)) 可以优雅地实现，通常无需媒体查询。
  - **媒体查询 + loat 或 inline-block**: 传统但仍然有效的方法。

**示例 (Flexbox):**
`css
.container {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
}

.item {
  /* 当空间允许时，每个item的基础宽度是300px，并且可以放大缩小 */
  flex: 1 1 300px; 
}
`

## 2. 布局切换 (Layout Shifter)

这种模式比列下沉更进一步，它在不同的断点不仅仅是重新排列列，而是对整个布局结构进行更根本性的改变。

- **描述**: 随着屏幕尺寸的变化，页面各个模块的位置和行为会发生显著变化。例如，一个侧边栏在桌面上位于右侧，在平板上可能移动到内容下方，在手机上则可能完全消失或变为一个可展开的菜单。
- **适用场景**: 复杂的Web应用、新闻门户、电商网站等需要根据可用空间重新组织内容优先级的场景。
- **实现技术**:
  - **CSS Grid + grid-template-areas**: 这是实现布局切换模式最强大、最直观的工具。通过在不同的媒体查询断点中重新定义 grid-template-areas 和 grid-template-columns/ows，可以轻松地实现布局的巨大转变。

**示例 (Grid):**
`css
.page {
  display: grid;
  grid-template-columns: 1fr;
  grid-template-areas: "header" "nav" "main" "ads" "footer";
}

/* 平板 */
@media (min-width: 700px) {
  .page {
    grid-template-columns: 3fr 1fr;
    grid-template-areas: 
      "header header"
      "nav    nav"
      "main   ads"
      "footer footer";
  }
}

/* 桌面 */
@media (min-width: 1000px) {
  .page {
    grid-template-columns: 1fr 4fr 1fr;
    grid-template-areas:
      "header header  header"
      "nav    main    ads"
      "footer footer  footer";
  }
}
/* ...然后使用 grid-area 将元素分配到对应的区域... */
`

## 3. 画布外/滑出 (Off-Canvas)

这种模式主要用于在小屏幕上节省空间，特别是对于复杂的导航菜单。

- **描述**: 在小屏幕上，一些次要内容或导航菜单被默认隐藏在屏幕的可视区域之外（即画布外）。当用户点击一个特定的触发器（通常是汉堡包图标 `）时，这些内容会以动画的形式滑入或覆盖到主内容之上。
- **适用场景**: 复杂的主导航、筛选器侧边栏、用户个人资料面板等。
- **实现技术**:
  - **CSS 	ransform: translateX()**: 通过改变元素的 	ransform 属性，将其在屏幕内外移动。这是性能最好的方式，因为它通常能触发 GPU 加速。
  - **CSS position: absolute/fixed + left/right**: 改变绝对或固定定位元素的位置。
  - **JavaScript**: 用于监听用户的点击事件，并切换一个 CSS 类（例如 .is-nav-open）来触发展示/隐藏的 CSS 过渡或动画。

**示例 (Transform):**
`css
.off-canvas-nav {
  position: fixed;
  top: 0;
  right: 0;
  width: 280px;
  height: 100vh;
  background: #333;
  transform: translateX(100%); /* 默认隐藏在右侧 */
  transition: transform 0.3s ease-in-out;
}

.is-nav-open .off-canvas-nav {
  transform: translateX(0); /* 滑入屏幕 */
}

/* 页面内容也可能需要一些效果 */
.page-content {
  transition: transform 0.3s ease-in-out;
}
.is-nav-open .page-content {
  transform: translateX(-280px); /* 当菜单滑出时，主内容也向左移动 */
}
`

## 4. 微小调整 (Tiny Tweaks)

这是一种普遍适用、贯穿始终的模式。

- **描述**: 它不涉及大的布局改变，而是对页面元素进行一些细微的调整以适应不同的屏幕尺寸。例如，随着屏幕变窄，可以适当减小字体大小、减少 padding 或 margin、或者将一个复杂的按钮组简化为一个带下拉菜单的按钮。
- **适用场景**: 所有响应式网站。它是对上述宏观布局模式的补充和细化。
- **实现技术**: 简单的媒体查询。

**示例:**
`css
h1 {
  font-size: 3rem;
}
.container {
  padding: 2rem;
}

@media (max-width: 600px) {
  h1 {
    font-size: 2.2rem; /* 减小字体大小 */
  }
  .container {
    padding: 1rem; /* 减小内边距 */
  }
}
`

## 5. 基本流式 (Mostly Fluid)

这是早期响应式网站非常流行的一种模式，现在依然很实用。

- **描述**: 布局的主体部分（通常是一个居中的容器）在大屏幕上有一个 max-width，表现为固定宽度布局。当视口宽度小于这个 max-width 时，容器宽度变为 100%，布局开始流动，像一个流式布局。
- **适用场景**: 简单的、以内容为中心的网站，如博客、文档。
- **实现技术**: 一个简单的容器类。

**示例:**
`css
.wrapper {
  width: 90%; /* 在小屏幕上，占据90%宽度 */
  max-width: 1140px; /* 在大屏幕上，最大宽度为1140px */
  margin: 0 auto; /* 实现水平居中 */
}
`
这个模式非常简单有效，它结合了固定布局的稳定性和流式布局的灵活性。

---
**下一章**: **[响应式图片高级技巧](responsive-images.md)**
