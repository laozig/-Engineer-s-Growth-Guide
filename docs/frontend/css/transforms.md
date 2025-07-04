﻿# 2D/3D 变换 (Transforms)

CSS 	ransform 属性允许你对元素进行旋转、缩放、倾斜和移动，而不会影响到周围元素的布局。这是创建现代、动态界面的关键技术之一，并且具有很高的性能。

## 1. 	ransform 属性

	ransform 属性可以接受一个或多个变换函数 (<transform-function>)作为其值。当提供多个函数时，它们会从左到右依次应用。

## 2. 2D 变换函数

这些函数在二维平面上操作元素。

### 	ranslate(tx, ty)
移动元素。	x 是水平方向的距离，	y 是垂直方向的距离。如果只提供一个值，则表示水平移动。
- 	ranslateX(tx): 只在水平方向移动。
- 	ranslateY(ty): 只在垂直方向移动。
- 单位可以是 px, %, em 等。% 是相对于元素自身的尺寸。

`css
.element {
  /* 向右移动50px，向下移动20px */
  transform: translate(50px, 20px); 
}
`
**居中技巧**: 使用 position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); 可以完美地将一个元素在其父容器中水平和垂直居中。

### scale(sx, sy)
缩放元素。sx 是水平方向的缩放比例，sy 是垂直方向的缩放比例。如果只提供一个值，则等比缩放。
- scaleX(sx): 只在水平方向缩放。
- scaleY(sy): 只在垂直方向缩放。
- 1 表示原始大小，2 表示放大一倍， .5 表示缩小一半。

`css
.element:hover {
  /* 放大到1.2倍 */
  transform: scale(1.2); 
}
`

### otate(angle)
旋转元素。ngle 是旋转的角度。
- 单位是 deg (度), grad (百分度), ad (弧度), 	urn (圈)。
- 正值表示顺时针旋转，负值表示逆时针旋转。

`css
.loader {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
`

### skew(ax, ay)
倾斜元素。x 是水平方向的倾斜角度，y 是垂直方向的_倾斜角度。
- skewX(ax): 只在水平方向倾斜。
- skewY(ay): 只在垂直方向倾斜。
- 单位是 deg。

`css
.element {
  /* 在X轴上倾斜20度 */
  transform: skewX(20deg); 
}
`

### matrix()
是 	ranslate, scale, otate, skew 的一种底层、数学化的简写方式。matrix(a, b, c, d, e, f) 包含了所有2D变换的信息，通常由工具生成。

## 3. 3D 变换函数

要启用3D变换，元素的父元素或自身需要设置 	ransform-style: preserve-3d 和 perspective 属性。

- **perspective**: 设置在父元素上，定义了观察者与Z=0平面的距离，这会给子元素的3D变换带来透视效果。值越小，透视效果越强。
- **	ransform-style: preserve-3d**: 设置在父元素上，指示其子元素应位于3D空间中，而不是被扁平化到父元素的2D平面中。

### 3D 变换函数

- 	ranslate3d(tx, ty, tz) / 	ranslateZ(tz): 在Z轴上移动元素。
- scale3d(sx, sy, sz) / scaleZ(sz): 在Z轴上缩放元素。
- otate3d(x, y, z, angle): 沿一个自定义的3D向量 [x, y, z] 旋转元素。
- otateX(angle), otateY(angle), otateZ(angle): 分别沿X、Y、Z轴旋转元素。
- perspective(n): 设置在变换元素自身，为该元素提供透视效果。

**示例：创建一个3D翻转卡片**
`html
<div class="card">
  <div class="card-inner">
    <div class="card-front">...</div>
    <div class="card-back">...</div>
  </div>
</div>
`
`css
.card {
  perspective: 1000px;
}
.card-inner {
  position: relative;
  width: 100%;
  height: 100%;
  transform-style: preserve-3d;
  transition: transform 0.6s;
}
.card:hover .card-inner {
  transform: rotateY(180deg);
}
.card-front, .card-back {
  position: absolute;
  width: 100%;
  height: 100%;
  backface-visibility: hidden; /* 隐藏元素的背面 */
}
.card-back {
  transform: rotateY(180deg);
}
`

## 4. 	ransform-origin

	ransform-origin 属性用于改变一个元素变换的原点。默认情况下，变换的原点是元素的中心 (50% 50%)。

`css
.element {
  /* 设置旋转原点为左上角 */
  transform-origin: top left; 
  transform: rotate(45deg);
}
`

---
**下一章**: **[CSS变量（自定义属性）](custom-properties.md)**
