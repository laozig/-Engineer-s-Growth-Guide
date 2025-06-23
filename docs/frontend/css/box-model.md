# 深入理解盒子模型 (Box Model)

在 CSS 中，每一个元素都被看作是一个矩形的盒子。CSS 盒子模型描述了这些盒子是如何由内容(content)、内边距(padding)、边框(border)和外边距(margin)组成的。

![盒子模型图](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_Box_Model/Introduction_to_the_CSS_box_model/box-model-standard-small.png)
*图片来源: MDN*

## 1. 盒子模型的组成部分

- **Content (内容区)**: 盒子的核心，显示文本、图片等内容。它的尺寸由 width 和 height 属性控制。
- **Padding (内边距)**: 包围在内容区之外的透明区域。它位于内容和边框之间。使用 padding 属性设置。
- **Border (边框)**: 包围在内边距之外的区域。它是盒子的可见边界。使用 order 属性设置。
- **Margin (外边距)**: 包围在边框之外的透明区域。它用于控制元素与其他元素之间的距离。使用 margin 属性设置。

## 2. ox-sizing 属性

ox-sizing 是理解和控制盒子模型的关键。它决定了元素的 width 和 height 属性包含了哪些部分。

### content-box (默认值)

在 content-box 模型下，你设置的 width 和 height **只应用于内容区 (Content)**。
元素的总宽度和总高度需要额外计算：

- **总宽度 = width + padding-left + padding-right + order-left + order-right**
- **总高度 = height + padding-top + padding-bottom + order-top + order-bottom**

**示例：**
`css
.element {
  box-sizing: content-box; /* 默认值 */
  width: 200px;
  padding: 20px;
  border: 10px solid red;
}
`
这个元素的实际渲染宽度是 200px + 20px + 20px + 10px + 10px = 260px。
这种计算方式很不直观，给布局带来了困难。

### order-box (推荐)

在 order-box 模型下，你设置的 width 和 height **包含了内容区、内边距和边框**。
元素的总宽度和总高度就是你设置的 width 和 height。内容区的尺寸会自动收缩以适应内边距和边框。

- **总宽度 = width**
- **总高度 = height**

**示例：**
`css
.element {
  box-sizing: border-box;
  width: 200px;
  padding: 20px;
  border: 10px solid blue;
}
`
这个元素的实际渲染宽度就是 200px。padding 和 order 都被包含在这 200px 之内了。
这种模型更加直观，大大简化了布局计算。

## 3. 全局重置 ox-sizing

为了避免 content-box 带来的布局问题，现代 Web 开发的最佳实践是为所有元素设置 ox-sizing: border-box;。

通常在项目的CSS文件开头进行如下设置：

`css
html {
  box-sizing: border-box;
}

*,
*::before,
*::after {
  box-sizing: inherit; /* 从html元素继承 */
}
`
- ox-sizing: inherit; 确保了所有元素（包括伪元素）都能继承 html 元素上设置的 order-box，同时保留了未来局部修改 ox-sizing 的灵活性。

## 4. 外边距折叠 (Margin Collapsing)

这是一个重要的概念，仅发生在 **垂直方向**。当两个或多个垂直方向的块级元素的外边距相遇时，它们会合并成一个外边距。合并后的外边距高度等于两个发生折叠的外边距中的较大者。

**常见场景：**
1.  **相邻的兄弟元素**:
    `html
    <p style="margin-bottom: 20px;">段落一</p>
    <p style="margin-top: 30px;">段落二</p>
    `
    这两个 <p> 之间的实际间距是 30px，而不是 20px + 30px = 50px。

2.  **父元素和第一个/最后一个子元素**:
    如果父元素没有 padding 或 order 来分隔，父元素的 margin-top 会和第一个子元素的 margin-top 折叠。

**如何防止外边距折叠？**
- 使用 padding 或 order 将外边距隔开。
- 创建新的块级格式化上下文 (Block Formatting Context, BFC)，例如设置 overflow: auto; 或 display: flow-root;。
- 使用 Flexbox 或 Grid 布局，它们的子项不会发生外边距折叠。

---
**下一章**: **[层叠、特异性与继承](specificity-cascade.md)**
