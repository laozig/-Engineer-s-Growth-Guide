# 响应式设计与媒体查询

响应式网页设计 (Responsive Web Design, RWD) 是一种网页设计方法，旨在使网页在各种设备和屏幕尺寸上都能提供最佳的查看和交互体验从桌面电脑到移动电话。实现响应式设计的核心技术就是 CSS 媒体查询 (Media Queries)。

## 1. 响应式设计的核心原则

响应式设计主要基于三个核心概念：

1.  **流式网格 (Fluid Grids)**:
    使用相对单位（如百分比 % 或 w）而不是绝对单位（如 px）来创建布局。这使得布局可以随着浏览器视口的缩放而平滑地伸缩。Flexbox 和 Grid 布局是构建现代流式网格的理想工具。

2.  **弹性图片/媒体 (Flexible Images/Media)**:
    确保图片、视频等媒体资源也能在布局中缩放。最基本的方法是：
    `css
    img, video {
      max-width: 100%;
      height: auto;
    }
    `
    这可以防止媒体元素超出其容器的宽度，并保持其原始的宽高比。

3.  **媒体查询 (Media Queries)**:
    允许我们根据设备的特定特征（最常见的是视口宽度）来应用不同的CSS样式。这是响应式设计的关键，它让我们可以在关键的断点处改变布局。

## 2. 设置 Viewport 元标签

为了确保网页在移动设备上能被正确地缩放和渲染，你必须在 HTML 的 <head> 标签中添加 viewport 元标签。

`html
<meta name="viewport" content="width=device-width, initial-scale=1.0">
`
- width=device-width: 指示浏览器将视口的宽度设置为设备的屏幕宽度。
- initial-scale=1.0: 设置页面首次加载时的初始缩放级别为 100%。

**没有这个标签，移动设备通常会以桌面屏幕的宽度来渲染页面，然后将其缩小，导致文本变得极小，难以阅读。**

## 3. CSS 媒体查询 (Media Queries)

媒体查询是响应式设计的魔法棒。它允许我们有条件地应用 CSS 规则。

### 基本语法

媒体查询由一个媒体类型（可选）和一个或多个媒体特性表达式组成。

`css
@media media-type and (media-feature-expression) {
  /* CSS 规则 */
}
`
- **@media**: 开启一个媒体查询块。
- **media-type**: 指定设备类型，如 ll, screen, print, speech。在现代web开发中，通常省略或使用 screen。
- **nd**: 逻辑操作符，用于连接多个媒体特性。其他操作符还有 
ot 和 only。逗号 , 则相当于 or。
- **(media-feature-expression)**: 媒体特性表达式，是应用样式的条件。

### 常见的媒体特性

- width, height: 视口的宽度和高度。
- min-width, max-width: 最常用的特性，用于定义应用样式的宽度阈值（断点）。
- orientation: 视口的方向 (portrait 竖屏或 landscape 横屏)。
- spect-ratio: 视口的宽高比。
- prefers-color-scheme: 检测用户是否设置了浅色 (light) 或深色 (dark) 的系统主题。
- prefers-reduced-motion: 检测用户是否希望减少不必要的动画。

## 4. "移动优先" vs "桌面优先"

这是两种设计和开发响应式网站的策略。

### 移动优先 (Mobile First)

这是现代Web开发 **推荐** 的方法。
1.  **先为移动设备编写基础CSS样式**。这些样式简洁、布局为单列。
2.  **然后使用 min-width 的媒体查询**，为更大屏幕（如平板、桌面电脑）添加更复杂的样式和布局。

`css
/* 1. 基础样式 (移动设备) */
.container {
  width: 90%;
  margin: 0 auto;
}
.sidebar {
  display: none; /* 移动端不显示侧边栏 */
}

/* 2. 平板设备及以上 (例如，大于768px) */
@media (min-width: 768px) {
  .container {
    display: flex;
  }
  .main-content {
    flex: 3;
  }
  .sidebar {
    display: block; /* 在大屏上显示侧边栏 */
    flex: 1;
    margin-left: 20px;
  }
}
`
**优点**:
- 强制你优先考虑内容和核心功能。
- 移动设备加载的 CSS 更少、更简单，提升性能。
- 代码更具扩展性。

### 桌面优先 (Desktop First)

1.  先为桌面设备编写完整的、复杂的布局。
2.  然后使用 max-width 的媒体查询，为更小屏幕移除或简化样式。

`css
/* 1. 桌面样式 */
.container {
  display: flex;
  width: 960px;
  margin: 0 auto;
}
/* ...其他桌面样式... */

/* 2. 平板设备及以下 (例如，小于768px) */
@media (max-width: 768px) {
  .container {
    flex-direction: column; /* 变为单列布局 */
  }
  /* ...其他覆盖样式... */
}
`
**缺点**:
- 移动设备需要加载所有桌面样式，然后再加载移动端样式来覆盖它们，性能较差。
- 容易导致 CSS 代码冗长和复杂。

---
**下一章**: **[过渡（Transitions）与动画（Animations）](transitions-animations.md)**
