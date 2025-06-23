# CSS 性能优化

CSS 看似简单，但糟糕的 CSS 会严重影响网页的渲染性能，导致页面卡顿、响应迟缓。优化 CSS 是前端性能优化的重要一环，其核心目标是 **加快渲染速度、避免不必要的重排和重绘**。

## 1. 理解浏览器的渲染过程

1.  **解析 HTML** -> 构建 DOM (文档对象模型)。
2.  **解析 CSS** -> 构建 CSSOM (CSS对象模型)。
3.  **合并 DOM 和 CSSOM** -> 构建渲染树 (Render Tree)。渲染树只包含需要显示在页面上的可见节点。
4.  **布局 (Layout/Reflow)**: 根据渲染树，计算每个节点在屏幕上的精确位置和大小。
5.  **绘制 (Paint/Repaint)**: 将渲染树的每个节点绘制到屏幕上。
6.  **合成 (Composite)**: 将多个绘制层按照正确的顺序合并，并显示在屏幕上。

## 2. 减少和避免重排 (Reflow) 与重绘 (Repaint)

- **重排 (Reflow)**: 当元素的几何属性（如 width, height, margin, left）发生变化，影响了页面布局时，浏览器需要重新计算布局。这是一个非常昂贵的操作，会影响其所有子节点乃至祖先节点。
- **重绘 (Repaint)**: 当元素的非几何属性（如 color, ackground-color, isibility）发生变化，不影响布局时，浏览器只需重新绘制该元素。这个操作开销较小。

### 优化策略

- **优先使用 	ransform 和 opacity 进行动画**:
  这两个属性的变化通常可以由 GPU 直接处理，从而绕过昂贵的布局和绘制阶段，直接进入合成阶段。这被称为硬件加速。这是实现流畅动画的最佳方式。

- **避免频繁修改样式**:
  如果需要用 JavaScript 对 DOM 进行多次样式修改，最好将它们合并为一次操作。
  `javascript
  // 不推荐
  const el = document.getElementById('my-element');
  el.style.width = '100px';
  el.style.height = '100px';
  el.style.margin = '10px';

  // 推荐：一次性修改 class
  el.classList.add('new-styles'); 
  `

- **避免在布局信息上进行循环**:
  不要在循环中读取会触发重排的属性（如 offsetTop, offsetLeft, clientWidth）。
  `javascript
  // 不推荐：每次循环都会触发重排
  for (let i = 0; i < elements.length; i++) {
    elements[i].style.left = elements[i].offsetLeft + 10 + 'px';
  }

  // 推荐：先读后写
  const widths = [];
  for (let i = 0; i < elements.length; i++) {
    widths[i] = elements[i].offsetLeft;
  }
  for (let i = 0; i < elements.length; i++) {
    elements[i].style.left = widths[i] + 10 + 'px';
  }
  `

- **使用 will-change 属性**:
  will-change 属性可以提前告知浏览器某个元素即将发生变化，让浏览器可以提前进行优化。但应谨慎使用，不要滥用，因为它会持续占用 GPU 资源。
  `css
  .element-about-to-animate {
    will-change: transform, opacity;
  }
  `

## 3. 优化选择器的性能

虽然现代浏览器在 CSS 选择器解析上已经非常高效，但遵循最佳实践仍然有益。
- **避免使用通用选择器 ***: 除非必要，否则它会匹配所有元素，增加匹配开销。
- **避免使用深层的后代选择器**: .nav ul li a span 的效率低于 .nav-link-text。BEM 命名规范有助于解决这个问题。
- **ID 选择器最快**: 如果可能，使用 ID 进行精确匹配。
- **类选择器次之**: 类选择器非常高效。
- **移除不必要的规则**: 定期审查和清理无用的 CSS。

## 4. 优化 CSS 文件加载

- **压缩 CSS**: 在生产环境中，应使用工具（如 cssnano）移除 CSS 文件中的空格、注释等，减小文件体积。
- **使用 <link> 而不是 @import**: @import 会阻塞并行下载，而 <link> 标签允许浏览器并行下载 CSS 文件。
- **关键 CSS (Critical CSS)**:
  这是一种高级优化策略。将页面首屏（Above The Fold）渲染所必需的最小化 CSS 直接内联到 HTML 的 <head> 中，可以极大地加快首次渲染时间。剩余的 CSS 则通过 <link> 标签异步加载。
  `html
  <head>
    <style>
      /* 关键 CSS */
      .header { ... }
      .hero-section { ... }
    </style>
    <link rel="stylesheet" href="styles.css" media="print" onload="this.media='all'">
    <noscript><link rel="stylesheet" href="styles.css"></noscript>
  </head>
  `
  media="print" 和 onload 技巧是一种常见的异步加载 CSS 的方式。

通过遵循这些原则，你可以编写出不仅美观、功能强大，而且性能卓越的 CSS。
