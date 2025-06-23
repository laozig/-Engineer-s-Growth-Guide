# 定位 (Positioning) 详解

CSS position 属性用于指定一个元素的定位类型。配合 	op, ight, ottom, left 和 z-index 属性，我们可以精确地控制元素在页面上的位置。

## 1. 定位类型

### static (静态定位)
这是所有元素的 **默认值**。元素按照正常的文档流（Normal Flow）进行排列。
在这种模式下，	op, ight, ottom, left 和 z-index 属性 **无效**。

### elative (相对定位)
元素首先按照正常的文档流进行排列，然后 **相对于其原始位置** 进行偏移。
- 使用 	op, ight, ottom, left 属性来设置偏移量。
- **关键点**: 相对定位的元素 **仍在文档流中占据其原始空间**，即使它被移动到了别处。它后面的元素不会去填充它留下的空白。
- 相对定位是设置 position: absolute 元素的一个重要参照物。

`css
.box {
  position: relative;
  top: -20px; /* 向上移动20px */
  left: 30px; /* 向右移动30px */
}
`

### bsolute (绝对定位)
元素会 **完全脱离正常的文档流**，不再占据任何空间。
它的位置是相对于 **最近的、非 static 的祖先元素** 进行定位的。如果找不到这样的祖先元素，则相对于初始包含块（通常是 <html> 元素）进行定位。
- 使用 	op, ight, ottom, left 属性来定义最终位置。
- **最常见的用法**: 将父元素设置为 position: relative，然后将子元素设置为 position: absolute，从而实现子元素在父元素内部的精确定位。

`css
.parent {
  position: relative; /* 为子元素创建定位上下文 */
}
.child {
  position: absolute;
  top: 0;
  right: 0;
  /* 这个元素会出现在父元素的右上角 */
}
`

### ixed (固定定位)
元素同样会 **完全脱离正常的文档流**。
它的位置是相对于 **浏览器视口 (viewport)** 进行定位的。这意味着即使页面滚动，它也会固定在屏幕的同一个位置。
- 常见的应用：固定的导航栏、回到顶部按钮、模态框的遮罩层。

`css
.cookie-banner {
  position: fixed;
  bottom: 0;
  left: 0;
  width: 100%;
  background-color: #333;
  color: white;
}
`

### sticky (粘性定位)
这是 elative 和 ixed 的混合体。
元素在跨越特定阈值（通过 	op, ight, ottom 或 left 定义）之前表现为 elative 定位，之后表现为 ixed 定位。
- **关键点**: 粘性定位的元素仅在其直接父元素的内容可滚动时才会生效。
- 常见的应用：粘性的侧边栏、表格的表头。

`css
.sticky-header {
  position: sticky;
  top: 0; /* 当滚动到顶部时，固定在这里 */
  background-color: white;
  z-index: 100;
}
`

## 2. z-index 与堆叠上下文

z-index 属性用于设置元素的堆叠顺序。拥有更高 z-index 值的元素会显示在拥有较低 z-index 值的元素前面。

**重要规则**:
- z-index 只对 **定位元素** (即 position 值为 elative, bsolute, ixed, sticky 的元素) 生效。
- z-index 不是一个绝对的全局层级。它只在同一个 **堆叠上下文 (Stacking Context)** 中有意义。

**堆叠上下文 (Stacking Context)**:
当一个元素满足以下任一条件时，它会创建一个新的堆叠上下文：
- 根元素 (<html>)。
- 定位元素 (非 static) 且 z-index 值不为 uto。
- opacity 属性值小于 1 的元素。
- 	ransform, ilter, perspective, clip-path 属性值不为 
one 的元素。
- position: fixed 或 position: sticky 的元素。
- ...以及其他一些情况。

一旦一个元素创建了堆叠上下文，它的所有子元素的 z-index 值都只在该上下文内部进行比较。这个元素整体作为一个单元，再与其兄弟元素在父堆叠上下文中进行 z-index 比较。这解释了为什么有时候一个 z-index: 9999 的元素会被一个 z-index: 10 的元素遮挡。

---
**下一章**: **[响应式设计与媒体查询](responsive-design.md)**
