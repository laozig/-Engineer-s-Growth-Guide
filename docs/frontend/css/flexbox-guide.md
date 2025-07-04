﻿# Flexbox 弹性布局指南

CSS 弹性盒子布局 (Flexible Box Layout)，通常称为 Flexbox，是一种一维布局模型，旨在为容器中的项目提供一种更加高效、可预测的方式来对齐和分配空间即使它们的尺寸是未知或动态的。

Flexbox 的核心思想是让容器能够改变其项目的宽度、高度（和顺序），以最好地填充可用空间。Flex 容器可以扩展项目以填充可用空间，或收缩它们以防止溢出。

## 1. Flexbox 核心概念

要理解 Flexbox，首先需要了解两个基本组件：**Flex 容器 (Flex Container)** 和 **Flex 项目 (Flex Item)**。

![Flexbox 模型](https://css-tricks.com/wp-content/uploads/2018/10/flexbox-axes.svg)
*图片来源: CSS-Tricks*

- **Flex 容器**: 应用了 display: flex 或 display: inline-flex 的父元素。
- **Flex 项目**: Flex 容器的直接子元素。
- **主轴 (Main Axis)**: Flex 项目沿其排列的主要轴线。默认为水平方向（从左到右）。
- **交叉轴 (Cross Axis)**: 与主轴垂直的轴线。默认为垂直方向（从上到下）。

## 2. Flex 容器属性 (Properties for the Parent)

这些属性设置在 Flex 容器上，用于控制其内部项目的整体布局。

### display
定义一个 Flex 容器。
- lex: 将元素变为一个块级的 Flex 容器。
- inline-flex: 将元素变为一个内联级的 Flex 容器。

### lex-direction
设置主轴的方向，决定了 Flex 项目的排列方向。
- ow (默认): 从左到右水平排列。
- ow-reverse: 从右到左水平排列。
- column: 从上到下垂直排列。
- column-reverse: 从下到上垂直排列。

### lex-wrap
定义当 Flex 项目在一条轴线上排不下时是否换行。
- 
owrap (默认): 不换行，项目会收缩以适应容器。
- wrap: 换行，从上到下。
- wrap-reverse: 换行，从下到上。

### lex-flow (简写属性)
lex-direction 和 lex-wrap 的简写。
- 示例: lex-flow: row wrap;

### justify-content
定义项目在 **主轴** 上的对齐方式。
- lex-start (默认): 向主轴起点对齐。
- lex-end: 向主轴终点对齐。
- center: 居中对齐。
- space-between: 两端对齐，项目之间的间隔都相等。
- space-around: 每个项目两侧的间隔相等。项目之间的间隔比项目与边框的间隔大一倍。
- space-evenly: 每个项目之间的间隔以及项目与边框之间的间隔都完全相等。

### lign-items
定义项目在 **交叉轴** 上的对齐方式。
- stretch (默认): 如果项目未设置高度或设为 uto，将占满整个容器的高度。
- lex-start: 向交叉轴起点对齐。
- lex-end: 向交叉轴终点对齐。
- center: 居中对齐。
- aseline: 项目的第一行文字的基线对齐。

### lign-content
定义了 **多根轴线** 的对齐方式。如果项目只有一行（即 lex-wrap: nowrap），该属性不起作用。
- lex-start, lex-end, center, space-between, space-around, space-evenly, stretch (默认)。

## 3. Flex 项目属性 (Properties for the Children)

这些属性设置在 Flex 项目上，用于控制单个项目的行为。

### order
定义项目的排列顺序。数值越小，排列越靠前。默认为  。
- 示例: order: -1; 会让该项目排在最前面。

### lex-grow
定义项目的放大比例，默认为   (即如果存在剩余空间，也不放大)。
- 如果所有项目的 lex-grow 都为 1，它们将等分剩余空间。
- 如果一个项目的 lex-grow 为 2，其他项目都为 1，则前者获取的剩余空间将是后者的两倍。

### lex-shrink
定义项目的缩小比例，默认为 1 (即如果空间不足，该项目将缩小)。
- 如果所有项目的 lex-shrink 都为 1，当空间不足时，都将等比例缩小。
- 如果一个项目的 lex-shrink 为  ，则该项目不缩小。

### lex-basis
定义了在分配多余空间之前，项目占据的主轴空间。默认为 uto，即项目本来的大小。
- 可以设为具体的长度值（如 20%, 10rem）。

### lex (简写属性)
lex-grow, lex-shrink 和 lex-basis 的简写，建议使用此属性。
- 默认值:   1 auto
- 常见值:
  - lex: auto (等同于 1 1 auto)
  - lex: none (等同于   0 auto)
  - lex: 1 (等同于 1 1 0%)，通常用于让项目等分空间。

### lign-self
允许单个项目有与其他项目不一样的对齐方式，可覆盖 lign-items 属性。
- 属性值: uto (默认), lex-start, lex-end, center, aseline, stretch。

---
**下一章**: **[Grid网格布局指南](grid-guide.md)**
