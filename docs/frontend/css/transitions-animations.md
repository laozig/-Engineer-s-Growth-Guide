﻿# 过渡 (Transitions) 与动画 (Animations)

CSS 过渡和动画可以让网页从静态变得生动，极大地提升用户体验。它们都能创建动态效果，但应用场景和复杂性有所不同。

## 1. 过渡 (Transitions)

过渡用于在元素的某个 CSS 属性发生变化时，提供平滑的视觉效果。它是一种从 **起始状态** 到 **终止状态** 的自动动画。

### 核心属性

- **	ransition-property**: 指定要应用过渡效果的 CSS 属性名称（如 ackground-color, 	ransform）。ll 是默认值，表示所有可动画的属性。
- **	ransition-duration**: 指定过渡效果完成所需的时间（如  .3s, 500ms）。
- **	ransition-timing-function**: 指定过渡的速度曲线（缓动函数）。
  - ease (默认): 慢速开始，然后加快，然后慢速结束。
  - linear: 匀速。
  - ease-in: 慢速开始。
  - ease-out: 慢速结束。
  - ease-in-out: 慢速开始和结束。
  - cubic-bezier(n,n,n,n): 自定义贝塞尔曲线。
- **	ransition-delay**: 指定在属性变化后，等待多久才开始过渡。

### 简写属性 	ransition

通常使用简写属性 	ransition 来设置过渡效果，顺序通常是 property duration timing-function delay。

`css
.button {
  background-color: #3498db;
  color: white;
  /* 简写形式 */
  transition: background-color 0.3s ease, transform 0.3s ease;
}

.button:hover {
  background-color: #2980b9;
  transform: scale(1.1);
}
`
**要点**:
- 过渡需要一个明确的触发条件，最常见的是伪类（如 :hover, :focus）或通过 JavaScript 添加/删除类。
- 只有具有可计算的中间值的属性才能应用过渡，例如 width, color, opacity, 	ransform。而 display, ont-family 等属性则不能。

## 2. 动画 (Animations)

动画比过渡更强大，它允许你通过定义关键帧 (@keyframes) 来创建复杂的、多步骤的动画序列，而无需任何外部触发。

### 核心属性

- **nimation-name**: 指定要绑定的 @keyframes 规则的名称。
- **nimation-duration**: 指定动画完成一个周期所需的时间。
- **nimation-timing-function**: 指定动画的速度曲线（同 	ransition-timing-function）。
- **nimation-delay**: 指定动画开始前的延迟时间。
- **nimation-iteration-count**: 指定动画播放的次数。可以是数字，也可以是 infinite（无限循环）。
- **nimation-direction**: 指定动画是否应该反向播放。
  - 
ormal (默认): 正常播放。
  - everse: 反向播放。
  - lternate: 正向和反向交替播放。
  - lternate-reverse: 反向和正向交- nimation-play-state: 指定动画是正在运行 (unning) 还是暂停 (paused)。
- **nimation-fill-mode**: 指定动画在非播放时间（如播放前或播放后）的状态。
  - 
one (默认): 动画结束后，元素返回到其原始样式。
  - orwards: 动画结束后，元素将保持最后一个关键帧的样式。
  - ackwards: 在 nimation-delay 期间，元素将应用第一个关键帧的样式。
  - oth: 同时应用 orwards 和 ackwards 的规则。

### 定义关键帧 @keyframes

使用 @keyframes 规则，你可以定义动画在不同时间点的样式。

`css
/* 定义一个名为 'pulse' 的动画 */
@keyframes pulse {
  0% {
    transform: scale(1);
    opacity: 1;
  }
  50% {
    transform: scale(1.2);
    opacity: 0.7;
  }
  100% {
    transform: scale(1);
    opacity: 1;
  }
}
`
rom 关键字等同于  %，	o 关键字等同于 100%。

### 简写属性 nimation

`css
.heart-icon {
  /* 动画名称 持续时间 速度曲线 延迟 迭代次数 方向 填充模式 */
  animation: pulse 2s ease-in-out 0s infinite normal forwards;
}
`

## 过渡 vs. 动画

| 特性 | 过渡 (Transition) | 动画 (Animation) |
| :--- | :--- | :--- |
| **定义** | 定义属性从一个状态到另一个状态的变化。 | 定义一个包含多个步骤的复杂动画序列。 |
| **触发** | 需要明确的触发器 (如 :hover 或 JS)。 | 无需触发器，页面加载时即可自动播放。 |
| **控制** | 简单，只有起止状态。 | 精细，可以定义多个关键帧。 |
| **循环** | 不能。 | 可以，通过 nimation-iteration-count。 |
| **适用场景**| 简单的悬停效果、UI状态变化。 | 加载指示器、复杂的入场/出场效果、循环动画。 |

## 性能考量

为了获得流畅的动画效果，应优先对 	ransform 和 opacity 这两个属性进行动画处理。因为浏览器可以非常高效地处理这两个属性的变化（通常通过 GPU 加速），而不会引发昂贵的重绘 (repaint) 和重排 (reflow)。

---
**下一章**: **[2D/3D变换（Transforms）](transforms.md)**
