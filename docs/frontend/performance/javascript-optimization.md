# JavaScript性能优化

JavaScript性能优化关注如何提高JavaScript代码的执行效率、减少内存占用并优化运行时性能。本文档介绍JavaScript性能优化的核心策略和最佳实践，帮助开发者编写高效的JavaScript代码。

## 目录

- [代码执行优化](#代码执行优化)
- [内存管理](#内存管理)
- [数据结构与算法选择](#数据结构与算法选择)
- [异步编程优化](#异步编程优化)
- [避免阻塞主线程](#避免阻塞主线程)
- [框架特定优化](#框架特定优化)
- [JavaScript引擎优化](#javascript引擎优化)
- [调试与分析](#调试与分析)

## 代码执行优化

### 减少昂贵的操作

避免在循环中执行昂贵的操作：

```js
// 不推荐
for (let i = 0; i < 1000; i++) {
  document.getElementById('result').innerHTML += `<div>${i}</div>`;  // 每次迭代都操作DOM
}

// 推荐
let html = '';
for (let i = 0; i < 1000; i++) {
  html += `<div>${i}</div>`;  // 在内存中构建字符串
}
document.getElementById('result').innerHTML = html;  // 一次性更新DOM
```

### 使用适当的循环

根据场景选择合适的循环方式：

```js
const arr = new Array(10000).fill(0);

// 性能测试
console.time('for');
for (let i = 0; i < arr.length; i++) {
  // 操作arr[i]
}
console.timeEnd('for');

console.time('for...of');
for (const item of arr) {
  // 操作item
}
console.timeEnd('for...of');

console.time('forEach');
arr.forEach(item => {
  // 操作item
});
console.timeEnd('forEach');

// 一般情况下: for > for...of > forEach
// 但具体性能特征取决于浏览器引擎和操作类型
```

### 减少作用域查找

缓存频繁访问的变量和对象属性：

```js
// 不推荐
function badPerformance() {
  const items = document.querySelectorAll('.item');
  for (let i = 0; i < items.length; i++) {  // 每次迭代都会访问items.length
    items[i].style.color = 'red';
  }
}

// 推荐
function goodPerformance() {
  const items = document.querySelectorAll('.item');
  const len = items.length;  // 缓存长度
  for (let i = 0; i < len; i++) {
    items[i].style.color = 'red';
  }
}
```

### 避免混合类型

保持变量类型稳定，避免类型转换：

```js
// 不推荐 - 变量类型不稳定
function sum(a, b) {
  let result = 0;
  result = a + b;  // 数字加法
  result = result + ' total';  // 转为字符串
  return result;
}

// 推荐 - 保持类型稳定
function sumNumbers(a, b) {
  return a + b;  // 始终是数字加法
}

function formatTotal(num) {
  return num + ' total';  // 明确的类型转换
}
```

## 内存管理

### 避免内存泄漏

清理不再使用的引用和事件监听器：

```js
// 不推荐 - 潜在的内存泄漏
function setupListener() {
  const button = document.getElementById('button');
  let data = fetchLargeData();  // 获取大量数据
  
  button.addEventListener('click', function() {
    console.log(data);  // 闭包引用了data，即使不再需要也不会被垃圾回收
  });
}

// 推荐 - 适当清理
function setupListenerProperly() {
  const button = document.getElementById('button');
  let data = fetchLargeData();
  
  const handleClick = function() {
    console.log('Button clicked');
    // 使用完data后不再引用
  };
  
  button.addEventListener('click', handleClick);
  
  // 提供清理方法
  return function cleanup() {
    button.removeEventListener('click', handleClick);
    data = null;  // 允许垃圾回收
  };
}

// 使用
const cleanup = setupListenerProperly();
// 不再需要时
cleanup();
```

### 对象池复用

对于频繁创建和销毁的对象，使用对象池模式：

```js
class ObjectPool {
  constructor(createFn, resetFn, initialSize = 10) {
    this.createFn = createFn;
    this.resetFn = resetFn;
    this.pool = [];
    
    // 预创建对象
    for (let i = 0; i < initialSize; i++) {
      this.pool.push(this.createFn());
    }
  }
  
  get() {
    if (this.pool.length === 0) {
      return this.createFn();
    }
    return this.pool.pop();
  }
  
  release(obj) {
    this.resetFn(obj);
    this.pool.push(obj);
  }
}

// 使用示例 - 粒子系统
const particlePool = new ObjectPool(
  () => ({ x: 0, y: 0, vx: 0, vy: 0, life: 0 }),
  (particle) => {
    particle.x = 0;
    particle.y = 0;
    particle.vx = 0;
    particle.vy = 0;
    particle.life = 0;
  },
  100
);

function createParticle() {
  const particle = particlePool.get();
  // 配置粒子
  return particle;
}

function removeParticle(particle) {
  particlePool.release(particle);  // 回收而不是销毁
}
```

### 使用适当的数据结构

根据操作类型选择合适的数据结构：

```js
// 频繁查找操作 - 使用Map或对象
const userMap = new Map();
for (let i = 0; i < 10000; i++) {
  userMap.set(`user${i}`, { name: `User ${i}` });
}

// 快速查找
console.time('map lookup');
const user999 = userMap.get('user999');
console.timeEnd('map lookup');

// 唯一值集合 - 使用Set
const uniqueIds = new Set();
for (let i = 0; i < 10000; i++) {
  uniqueIds.add(`id-${i % 1000}`);  // 有意重复
}

console.log(uniqueIds.size);  // 1000，自动去重
```

## 数据结构与算法选择

### 高效数组操作

使用高效的数组方法：

```js
const numbers = Array.from({ length: 10000 }, (_, i) => i);

// 不推荐 - 创建多个中间数组
const result1 = numbers
  .map(x => x * 2)
  .filter(x => x % 3 === 0)
  .map(x => x + 1);

// 推荐 - 减少中间数组
const result2 = numbers.reduce((acc, x) => {
  const doubled = x * 2;
  if (doubled % 3 === 0) {
    acc.push(doubled + 1);
  }
  return acc;
}, []);
```

### 优化搜索算法

使用适当的搜索算法：

```js
// 线性搜索 - O(n)
function linearSearch(arr, target) {
  for (let i = 0; i < arr.length; i++) {
    if (arr[i] === target) return i;
  }
  return -1;
}

// 二分搜索 - O(log n)，但要求数组已排序
function binarySearch(arr, target) {
  let left = 0;
  let right = arr.length - 1;
  
  while (left <= right) {
    const mid = Math.floor((left + right) / 2);
    if (arr[mid] === target) return mid;
    if (arr[mid] < target) left = mid + 1;
    else right = mid - 1;
  }
  
  return -1;
}

// 对于大型已排序数组，二分搜索更高效
const sortedArray = Array.from({ length: 1000000 }, (_, i) => i);
const target = 876543;

console.time('linear');
linearSearch(sortedArray, target);
console.timeEnd('linear');

console.time('binary');
binarySearch(sortedArray, target);
console.timeEnd('binary');
```

## 异步编程优化

### 使用Promise.all并行处理

并行执行独立的异步操作：

```js
// 不推荐 - 串行执行
async function fetchDataSequentially() {
  console.time('sequential');
  const userData = await fetchUserData();
  const productData = await fetchProductData();
  const orderData = await fetchOrderData();
  console.timeEnd('sequential');
  return { userData, productData, orderData };
}

// 推荐 - 并行执行
async function fetchDataInParallel() {
  console.time('parallel');
  const [userData, productData, orderData] = await Promise.all([
    fetchUserData(),
    fetchProductData(),
    fetchOrderData()
  ]);
  console.timeEnd('parallel');
  return { userData, productData, orderData };
}
```

### 避免不必要的异步/等待

不要在不需要的地方使用async/await：

```js
// 不推荐 - 不必要的异步包装
async function unnecessaryAsync() {
  const result = await Promise.resolve(42);  // 不需要await一个已解析的Promise
  return result;
}

// 推荐
function simpleSync() {
  return 42;
}

// 或者如果必须返回Promise
function simpleSyncPromise() {
  return Promise.resolve(42);
}
```

## 避免阻塞主线程

### 任务分割

将长时间运行的任务分割成小块：

```js
// 不推荐 - 长时间运行的循环阻塞主线程
function processLargeArray(array) {
  for (let i = 0; i < array.length; i++) {
    // 处理每个元素...
    heavyOperation(array[i]);
  }
}

// 推荐 - 使用时间分片
function processLargeArrayChunked(array, chunkSize = 100) {
  let index = 0;
  
  function processChunk() {
    const start = performance.now();
    
    while (index < array.length && performance.now() - start < 50) {
      // 处理当前元素
      heavyOperation(array[index]);
      index++;
    }
    
    if (index < array.length) {
      // 还有更多元素要处理，安排下一个时间片
      setTimeout(processChunk, 0);
    } else {
      // 处理完成
      console.log('Processing complete');
    }
  }
  
  // 开始处理
  processChunk();
}
```

### 使用Web Workers

将计算密集型任务移至Web Worker：

```js
// main.js
function startHeavyComputation() {
  const worker = new Worker('worker.js');
  
  worker.onmessage = function(e) {
    console.log('计算结果:', e.data.result);
    console.log('耗时:', e.data.time, 'ms');
  };
  
  worker.postMessage({
    data: generateLargeDataset(),
    operation: 'complexCalculation'
  });
}

// worker.js
self.onmessage = function(e) {
  const { data, operation } = e.data;
  
  const start = performance.now();
  let result;
  
  switch (operation) {
    case 'complexCalculation':
      result = performComplexCalculation(data);
      break;
    // 其他操作...
  }
  
  const time = performance.now() - start;
  
  self.postMessage({
    result,
    time
  });
};
```

## 框架特定优化

### React优化

使用React优化技术：

```jsx
// 使用React.memo避免不必要的重新渲染
const MemoizedComponent = React.memo(function Component(props) {
  return <div>{props.value}</div>;
});

// 使用useCallback缓存回调函数
function ParentComponent() {
  const [count, setCount] = useState(0);
  
  // 避免每次渲染都创建新函数
  const handleClick = useCallback(() => {
    setCount(c => c + 1);
  }, []);
  
  return <ChildComponent onClick={handleClick} />;
}

// 使用useMemo缓存计算结果
function DataProcessor({ data }) {
  // 只有当data变化时才重新计算
  const processedData = useMemo(() => {
    return expensiveOperation(data);
  }, [data]);
  
  return <div>{processedData}</div>;
}
```

### Vue优化

Vue性能优化技术：

```js
// 使用v-once处理一次性内容
<template>
  <div v-once>{{ expensiveComputation() }}</div>
</template>

// 使用计算属性缓存结果
export default {
  data() {
    return {
      items: []
    }
  },
  computed: {
    filteredItems() {
      return this.items.filter(item => item.isActive);
    }
  }
}

// 使用v-show代替v-if进行频繁切换
<template>
  <div v-show="isVisible">频繁切换的内容</div>
</template>
```

## JavaScript引擎优化

### 利用V8优化

编写对JavaScript引擎友好的代码：

```js
// 对象属性顺序一致性
// 推荐 - 保持对象结构一致
function createUser(name, age) {
  return { name, age };  // 属性顺序一致
}

const users = [];
for (let i = 0; i < 1000; i++) {
  users.push(createUser(`User ${i}`, 20 + i % 50));
}

// 隐藏类优化
// 不推荐 - 动态添加属性
function BadClass() {
  this.x = 0;
  // 稍后再添加属性
  setTimeout(() => {
    this.y = 0;  // 创建新的隐藏类
  }, 100);
}

// 推荐 - 在构造函数中初始化所有属性
function GoodClass() {
  this.x = 0;
  this.y = 0;  // 立即初始化所有属性
}
```

### 避免优化杀手

避免破坏JavaScript引擎优化的模式：

```js
// 避免使用eval
// 不推荐
function dynamicCode(code) {
  return eval(code);  // 破坏作用域优化
}

// 推荐
function safeOperation(operation, a, b) {
  switch (operation) {
    case 'add': return a + b;
    case 'subtract': return a - b;
    // ...其他操作
  }
}

// 避免arguments对象
// 不推荐
function sum() {
  let total = 0;
  for (let i = 0; i < arguments.length; i++) {
    total += arguments[i];  // 阻止优化
  }
  return total;
}

// 推荐
function sum(...numbers) {
  return numbers.reduce((total, num) => total + num, 0);
}
```

## 调试与分析

### 使用Performance API

使用Performance API测量代码性能：

```js
// 测量函数执行时间
function measureExecutionTime(fn, ...args) {
  const label = fn.name || 'anonymous function';
  performance.mark(`${label}-start`);
  
  const result = fn(...args);
  
  performance.mark(`${label}-end`);
  performance.measure(label, `${label}-start`, `${label}-end`);
  
  const measurements = performance.getEntriesByName(label);
  console.log(`${label} took ${measurements[0].duration.toFixed(2)}ms`);
  
  return result;
}

// 使用示例
function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

measureExecutionTime(fibonacci, 30);
```

### 使用Chrome DevTools分析

使用Chrome DevTools分析JavaScript性能：

1. 打开Chrome DevTools (F12)
2. 切换到Performance或Memory标签
3. 点击Record按钮
4. 执行需要分析的操作
5. 点击Stop
6. 分析结果，查找性能瓶颈

## 最佳实践清单

- ✅ 避免在循环中执行昂贵操作，特别是DOM操作
- ✅ 缓存频繁访问的值和计算结果
- ✅ 保持变量类型稳定，避免类型转换
- ✅ 适当管理内存，避免泄漏
- ✅ 选择合适的数据结构和算法
- ✅ 并行执行独立的异步操作
- ✅ 将长时间运行的任务分割或移至Web Worker
- ✅ 使用框架提供的性能优化技术
- ✅ 编写对JavaScript引擎友好的代码
- ✅ 定期分析和优化性能瓶颈

## 参考资源

- [V8 JavaScript引擎性能优化](https://v8.dev/blog/cost-of-javascript-2019) - V8团队博客
- [MDN Web性能](https://developer.mozilla.org/zh-CN/docs/Web/Performance) - Mozilla开发者网络
- [JavaScript性能优化](https://web.dev/fast/) - Google Web开发者指南 