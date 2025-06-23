# 渲染性能优化

渲染性能优化关注浏览器的渲染过程，目标是减少布局抖动、优化动画效果并提高页面交互的流畅度。本文档介绍如何优化浏览器的渲染管道，减少重排（reflow）和重绘（repaint），提升用户体验。

## 目录

- [浏览器渲染流程](#浏览器渲染流程)
- [减少重排与重绘](#减少重排与重绘)
- [高性能动画](#高性能动画)
- [虚拟DOM优化](#虚拟dom优化)
- [渲染阻塞资源](#渲染阻塞资源)
- [关键渲染路径优化](#关键渲染路径优化)
- [Web Workers](#web-workers)
- [渲染性能调试](#渲染性能调试)

## 浏览器渲染流程

了解浏览器的渲染流程是优化渲染性能的基础：

1. **DOM解析**: HTML解析为DOM树
2. **CSSOM解析**: CSS解析为CSSOM树
3. **渲染树构建**: 合并DOM和CSSOM
4. **布局计算**: 计算元素位置和大小
5. **绘制**: 将渲染树绘制到屏幕上

![浏览器渲染流程](https://web.dev/static/articles/critical-rendering-path/image/render-tree-construction-9facaebd872e8_856.png)

## 减少重排与重绘

### 避免频繁的样式修改

合并多次样式修改：

```js
// 不推荐 - 导致多次重排
const element = document.getElementById('box');
element.style.width = '100px';
element.style.height = '100px';
element.style.margin = '10px';

// 推荐 - 只触发一次重排
const element = document.getElementById('box');
element.style.cssText = 'width: 100px; height: 100px; margin: 10px;';

// 或者使用类名切换
element.classList.add('new-style');
```

### 使用文档片段

批量DOM操作使用文档片段：

```js
// 不推荐 - 每次添加都会触发重排
const list = document.getElementById('list');
for (let i = 0; i < 100; i++) {
  const item = document.createElement('li');
  item.textContent = `Item ${i}`;
  list.appendChild(item); // 每次都会触发重排
}

// 推荐 - 使用文档片段，只触发一次重排
const list = document.getElementById('list');
const fragment = document.createDocumentFragment();
for (let i = 0; i < 100; i++) {
  const item = document.createElement('li');
  item.textContent = `Item ${i}`;
  fragment.appendChild(item);
}
list.appendChild(fragment); // 只触发一次重排
```

### 避免强制同步布局

避免在修改DOM后立即查询布局信息：

```js
// 不推荐 - 强制同步布局
const boxes = document.querySelectorAll('.box');
boxes.forEach(box => {
  box.style.width = '100px';
  const height = box.offsetHeight; // 强制浏览器执行布局计算
  box.style.height = `${height * 2}px`;
});

// 推荐 - 先读取所有布局信息，再修改样式
const boxes = document.querySelectorAll('.box');
const heights = Array.from(boxes).map(box => box.offsetHeight); // 一次性读取
boxes.forEach((box, i) => {
  box.style.width = '100px';
  box.style.height = `${heights[i] * 2}px`;
});
```

### 使用绝对定位脱离文档流

对于频繁变化的元素，使用绝对定位脱离文档流：

```css
.animated-element {
  position: absolute;
  top: 0;
  left: 0;
  will-change: transform;
}
```

## 高性能动画

### 使用transform和opacity

优先使用不触发重排的属性：

```css
/* 不推荐 - 触发重排 */
@keyframes move-bad {
  from { left: 0; top: 0; }
  to { left: 100px; top: 100px; }
}

/* 推荐 - 只触发合成 */
@keyframes move-good {
  from { transform: translate(0, 0); }
  to { transform: translate(100px, 100px); }
}

.animate {
  animation: move-good 1s ease infinite;
}
```

### 硬件加速

使用3D变换触发GPU加速：

```css
.hardware-accelerated {
  transform: translateZ(0);
  /* 或使用 */
  will-change: transform, opacity;
}
```

### 使用requestAnimationFrame

使用requestAnimationFrame替代setTimeout进行动画：

```js
// 不推荐
function animateBad() {
  const element = document.getElementById('box');
  let position = 0;
  
  function step() {
    position += 5;
    element.style.left = position + 'px';
    if (position < 300) {
      setTimeout(step, 16); // 约60fps
    }
  }
  
  step();
}

// 推荐
function animateGood() {
  const element = document.getElementById('box');
  let position = 0;
  
  function step(timestamp) {
    position += 5;
    element.style.transform = `translateX(${position}px)`;
    if (position < 300) {
      requestAnimationFrame(step);
    }
  }
  
  requestAnimationFrame(step);
}
```

## 虚拟DOM优化

### React组件优化

使用React.memo和useMemo减少不必要的渲染：

```jsx
// 使用React.memo包装函数组件
const MemoizedComponent = React.memo(function MyComponent(props) {
  return (
    <div>{props.name}</div>
  );
});

// 在函数组件中使用useMemo
function MyComponent({ data }) {
  const processedData = React.useMemo(() => {
    return expensiveCalculation(data);
  }, [data]); // 只有当data变化时才重新计算
  
  return <div>{processedData}</div>;
}
```

### 列表渲染优化

为列表项提供稳定的key：

```jsx
// React列表渲染
function ItemList({ items }) {
  return (
    <ul>
      {items.map(item => (
        <li key={item.id}>{item.name}</li> // 使用唯一ID作为key
      ))}
    </ul>
  );
}

// Vue列表渲染
<template>
  <ul>
    <li v-for="item in items" :key="item.id">{{ item.name }}</li>
  </ul>
</template>
```

### 避免不必要的渲染

使用shouldComponentUpdate或PureComponent：

```jsx
// 使用shouldComponentUpdate
class OptimizedComponent extends React.Component {
  shouldComponentUpdate(nextProps, nextState) {
    return nextProps.value !== this.props.value;
  }
  
  render() {
    return <div>{this.props.value}</div>;
  }
}

// 或使用PureComponent
class PureOptimizedComponent extends React.PureComponent {
  render() {
    return <div>{this.props.value}</div>;
  }
}
```

## 渲染阻塞资源

### 异步加载CSS

非关键CSS可以异步加载：

```html
<link rel="stylesheet" href="main.css" media="print" onload="this.media='all'">
```

### 延迟加载JavaScript

非关键JavaScript使用defer或async：

```html
<!-- 解析HTML时异步下载，下载完后立即执行，可能阻断HTML解析 -->
<script async src="analytics.js"></script>

<!-- 解析HTML时异步下载，等HTML解析完成后执行，按顺序执行 -->
<script defer src="app.js"></script>
```

## 关键渲染路径优化

### 减少关键资源数量

内联首屏关键CSS：

```html
<head>
  <style>
    /* 关键CSS */
    header, main { display: block; }
    header { background: #f8f8f8; padding: 20px; }
    /* ... */
  </style>
</head>
```

### 减少关键路径长度

优化资源加载顺序：

```html
<!-- 首先加载关键CSS -->
<link rel="stylesheet" href="critical.css">

<!-- 预加载关键JS但延迟执行 -->
<link rel="preload" href="app.js" as="script">

<!-- 在HTML底部加载非关键JS -->
<script src="app.js" defer></script>
```

## Web Workers

### 将复杂计算移至Web Worker

使用Web Worker处理耗时计算，避免阻塞主线程：

```js
// main.js
const worker = new Worker('worker.js');

worker.onmessage = function(e) {
  console.log('计算结果：', e.data);
};

worker.postMessage({
  numbers: Array.from({ length: 10000000 }, (_, i) => i)
});

// worker.js
self.onmessage = function(e) {
  const numbers = e.data.numbers;
  const sum = numbers.reduce((acc, curr) => acc + curr, 0);
  self.postMessage(sum);
};
```

### 使用OffscreenCanvas

将Canvas渲染操作移至Worker线程：

```js
// main.js
const canvas = document.getElementById('myCanvas');
const offscreen = canvas.transferControlToOffscreen();
const worker = new Worker('canvas-worker.js');

worker.postMessage({ canvas: offscreen }, [offscreen]);

// canvas-worker.js
self.onmessage = function(e) {
  const canvas = e.data.canvas;
  const ctx = canvas.getContext('2d');
  
  // 在worker中执行绘制
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillRect(Math.random() * canvas.width, Math.random() * canvas.height, 10, 10);
    requestAnimationFrame(draw);
  }
  
  draw();
};
```

## 渲染性能调试

### 使用Chrome DevTools性能面板

分析渲染性能瓶颈：

1. 打开Chrome DevTools (F12)
2. 切换到Performance标签
3. 点击Record按钮
4. 执行需要分析的操作
5. 点击Stop
6. 分析火焰图，查找长任务和布局抖动

### 监控布局抖动

使用Performance API监控布局抖动：

```js
// 监控长任务
const observer = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    console.log('长任务检测:', entry.toJSON());
  }
});

observer.observe({ entryTypes: ['longtask'] });

// 监控布局偏移
const layoutShiftObserver = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    console.log('布局偏移:', entry.toJSON());
  }
});

layoutShiftObserver.observe({ type: 'layout-shift', buffered: true });
```

## 最佳实践清单

- ✅ 避免频繁的DOM操作，批量处理DOM更新
- ✅ 使用transform和opacity进行动画，避免触发重排
- ✅ 对动画元素使用will-change提示浏览器
- ✅ 使用requestAnimationFrame进行视觉更新
- ✅ 避免强制同步布局
- ✅ 使用虚拟DOM和列表优化技术
- ✅ 延迟加载非关键JavaScript
- ✅ 将耗时计算移至Web Worker
- ✅ 定期使用性能工具分析渲染瓶颈
- ✅ 监控核心Web指标(CLS、FID、LCP)

## 参考资源

- [渲染性能](https://web.dev/rendering-performance/) - Google Web开发者指南
- [避免大型、复杂的布局和布局抖动](https://web.dev/avoid-large-complex-layouts-and-layout-thrashing/) - Web性能最佳实践
- [高性能动画](https://www.html5rocks.com/en/tutorials/speed/high-performance-animations/) - HTML5 Rocks教程 