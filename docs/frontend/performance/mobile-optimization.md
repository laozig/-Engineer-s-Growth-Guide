# 移动端性能优化

移动端性能优化是前端开发中的重要环节，由于移动设备硬件性能、网络条件和交互方式的特殊性，需要采取针对性的优化策略。本文档介绍移动端性能优化的关键技术和最佳实践。

## 目录

- [移动端性能挑战](#移动端性能挑战)
- [网络优化](#网络优化)
- [渲染性能优化](#渲染性能优化)
- [资源优化](#资源优化)
- [交互性能优化](#交互性能优化)
- [电池和内存优化](#电池和内存优化)
- [移动端测试与监控](#移动端测试与监控)
- [最佳实践清单](#最佳实践清单)

## 移动端性能挑战

移动端开发面临的独特挑战：

1. **网络连接不稳定** - 移动网络信号强度变化大，延迟高
2. **硬件性能限制** - CPU、内存和GPU性能受限
3. **电池寿命考量** - 耗电优化至关重要
4. **多样化设备** - 不同屏幕尺寸、分辨率和性能
5. **触摸交互** - 不同于桌面端的交互模式
6. **操作系统限制** - 不同移动操作系统的特性和限制

## 网络优化

### 减少网络请求

```js
// 合并多个小图标为一个sprite图
.icon-home {
  background-image: url('sprite.png');
  background-position: 0 0;
}

.icon-search {
  background-image: url('sprite.png');
  background-position: -20px 0;
}

// 使用内联关键CSS
<style>
  /* 关键渲染路径CSS */
  body { margin: 0; font-family: sans-serif; }
  .header { height: 50px; background: #f8f8f8; }
</style>
```

### 实现离线功能

使用Service Worker缓存关键资源：

```js
// 注册Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then(registration => {
        console.log('SW注册成功:', registration.scope);
      })
      .catch(err => {
        console.log('SW注册失败:', err);
      });
  });
}

// sw.js - Service Worker文件
const CACHE_NAME = 'mobile-app-v1';
const urlsToCache = [
  '/',
  '/styles/main.css',
  '/scripts/main.js',
  '/images/logo.png',
  '/offline.html'
];

// 安装阶段缓存资源
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        return cache.addAll(urlsToCache);
      })
  );
});

// 请求拦截
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // 缓存命中，返回缓存的资源
        if (response) {
          return response;
        }
        
        // 缓存未命中，发起网络请求
        return fetch(event.request)
          .then(response => {
            // 检查响应是否有效
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }
            
            // 克隆响应（因为响应流只能被消费一次）
            const responseToCache = response.clone();
            
            // 将新请求的资源加入缓存
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
              });
              
            return response;
          })
          .catch(() => {
            // 网络请求失败，可以返回离线页面
            if (event.request.mode === 'navigate') {
              return caches.match('/offline.html');
            }
          });
      })
  );
});
```

### 网络状态感知

根据网络状态调整应用行为：

```js
// 检测网络状态
function updateNetworkStatus() {
  const connection = navigator.connection || 
                    navigator.mozConnection || 
                    navigator.webkitConnection;
                    
  if (connection) {
    const type = connection.effectiveType; // 4g, 3g, 2g, slow-2g
    const saveData = connection.saveData; // 是否启用数据节省模式
    
    // 根据网络类型调整策略
    if (type === '4g') {
      loadHighResImages();
    } else if (type === '3g') {
      loadMediumResImages();
    } else {
      loadLowResImages();
      disableAutoplay();
    }
    
    // 如果用户开启了数据节省模式
    if (saveData) {
      disableNonEssentialRequests();
    }
  }
}

// 监听网络变化
if (navigator.connection) {
  navigator.connection.addEventListener('change', updateNetworkStatus);
  updateNetworkStatus(); // 初始检查
}
```

## 渲染性能优化

### 减少重排和重绘

```js
// 不好的做法 - 多次DOM操作导致多次重排
function addItems(items) {
  const list = document.getElementById('list');
  
  items.forEach(item => {
    list.appendChild(document.createElement('li')).textContent = item;
  });
}

// 好的做法 - 使用文档片段减少重排
function addItemsOptimized(items) {
  const fragment = document.createDocumentFragment();
  const list = document.getElementById('list');
  
  items.forEach(item => {
    fragment.appendChild(document.createElement('li')).textContent = item;
  });
  
  list.appendChild(fragment); // 只有一次DOM更新
}

// 使用CSS属性触发GPU加速
.accelerated {
  transform: translateZ(0);
  will-change: transform;
}
```

### 优化滚动性能

```js
// 使用节流函数优化滚动事件
function throttle(fn, delay) {
  let lastCall = 0;
  return function(...args) {
    const now = Date.now();
    if (now - lastCall >= delay) {
      lastCall = now;
      fn.apply(this, args);
    }
  };
}

// 应用节流到滚动事件
window.addEventListener('scroll', throttle(function() {
  // 滚动处理逻辑
  updateElementsInViewport();
}, 100));

// 使用IntersectionObserver优化可见性检测
const observer = new IntersectionObserver(entries => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      // 元素进入视口
      const lazyImage = entry.target;
      lazyImage.src = lazyImage.dataset.src;
      observer.unobserve(lazyImage); // 加载后停止观察
    }
  });
});

// 观察所有延迟加载的图片
document.querySelectorAll('.lazy-image').forEach(img => {
  observer.observe(img);
});
```

### 避免长任务阻塞主线程

```js
// 不好的做法 - 长时间运行的任务阻塞主线程
function processLargeDataset(data) {
  const results = [];
  
  for (let i = 0; i < data.length; i++) {
    const processed = heavyProcessing(data[i]);
    results.push(processed);
  }
  
  return results;
}

// 好的做法 - 使用Web Worker处理耗时任务
function processLargeDatasetWithWorker(data) {
  return new Promise((resolve, reject) => {
    const worker = new Worker('processor.js');
    
    worker.onmessage = function(e) {
      resolve(e.data);
      worker.terminate();
    };
    
    worker.onerror = function(error) {
      reject(error);
      worker.terminate();
    };
    
    worker.postMessage(data);
  });
}

// processor.js - Web Worker文件
self.onmessage = function(e) {
  const data = e.data;
  const results = [];
  
  for (let i = 0; i < data.length; i++) {
    const processed = heavyProcessing(data[i]);
    results.push(processed);
  }
  
  self.postMessage(results);
};
```

## 资源优化

### 响应式图片

```html
<!-- 使用srcset和sizes属性 -->
<img src="small.jpg"
     srcset="small.jpg 320w,
             medium.jpg 800w,
             large.jpg 1200w"
     sizes="(max-width: 320px) 280px,
            (max-width: 800px) 760px,
            1140px"
     alt="响应式图片示例">

<!-- 使用picture元素 -->
<picture>
  <source media="(max-width: 600px)" srcset="small.webp" type="image/webp">
  <source media="(max-width: 600px)" srcset="small.jpg" type="image/jpeg">
  <source media="(min-width: 601px)" srcset="large.webp" type="image/webp">
  <source media="(min-width: 601px)" srcset="large.jpg" type="image/jpeg">
  <img src="fallback.jpg" alt="响应式图片示例">
</picture>
```

### 字体优化

```css
/* 使用font-display控制字体加载行为 */
@font-face {
  font-family: 'CustomFont';
  src: url('custom-font.woff2') format('woff2'),
       url('custom-font.woff') format('woff');
  font-display: swap; /* 使用系统字体直到自定义字体加载完成 */
}

/* 使用系统字体栈 */
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;
}
```

### 资源预加载和预连接

```html
<!-- 预连接到关键域名 -->
<link rel="preconnect" href="https://api.example.com">
<link rel="preconnect" href="https://fonts.googleapis.com">

<!-- 预加载关键资源 -->
<link rel="preload" href="critical.css" as="style">
<link rel="preload" href="main.js" as="script">
<link rel="preload" href="hero.webp" as="image">

<!-- 预取可能需要的资源 -->
<link rel="prefetch" href="next-page.js">
```

## 交互性能优化

### 触摸事件优化

```js
// 实现自定义触摸反馈
document.addEventListener('touchstart', function(e) {
  if (e.target.classList.contains('btn')) {
    e.target.classList.add('btn-active');
  }
}, { passive: true }); // 使用passive选项提高滚动性能

document.addEventListener('touchend', function(e) {
  if (e.target.classList.contains('btn')) {
    e.target.classList.remove('btn-active');
  }
});

// 消除300ms点击延迟
// 方法1: 使用meta viewport标签
// <meta name="viewport" content="width=device-width">

// 方法2: 使用touch-action CSS属性
.btn {
  touch-action: manipulation;
}
```

### 手势优化

```js
// 使用Pointer Events统一处理不同输入方式
function setupSwipeHandler(element) {
  let startX, startY;
  let currentX, currentY;
  
  element.addEventListener('pointerdown', function(e) {
    startX = e.clientX;
    startY = e.clientY;
    element.setPointerCapture(e.pointerId);
  });
  
  element.addEventListener('pointermove', function(e) {
    if (!startX) return;
    
    currentX = e.clientX;
    currentY = e.clientY;
    
    const deltaX = currentX - startX;
    
    // 应用实时变换，提供即时视觉反馈
    element.style.transform = `translateX(${deltaX}px)`;
  });
  
  element.addEventListener('pointerup', function(e) {
    if (!startX) return;
    
    const deltaX = currentX - startX;
    
    if (Math.abs(deltaX) > 100) {
      // 足够的滑动距离，执行操作
      if (deltaX > 0) {
        // 向右滑动
        slideToNext();
      } else {
        // 向左滑动
        slideToPrevious();
      }
    } else {
      // 滑动距离不够，恢复原位
      element.style.transform = '';
    }
    
    startX = null;
    startY = null;
  });
  
  element.addEventListener('pointercancel', function() {
    startX = null;
    startY = null;
    element.style.transform = '';
  });
}
```

## 电池和内存优化

### 降低电池消耗

```js
// 使用requestIdleCallback在浏览器空闲时执行非关键任务
function scheduleNonEssentialWork(tasks) {
  if ('requestIdleCallback' in window) {
    requestIdleCallback(deadline => {
      while (deadline.timeRemaining() > 0 && tasks.length > 0) {
        const task = tasks.shift();
        task();
      }
      
      if (tasks.length > 0) {
        scheduleNonEssentialWork(tasks);
      }
    });
  } else {
    // 回退方案
    setTimeout(() => {
      const task = tasks.shift();
      task();
      
      if (tasks.length > 0) {
        scheduleNonEssentialWork(tasks);
      }
    }, 1);
  }
}

// 使用Page Visibility API在页面不可见时暂停非必要操作
document.addEventListener('visibilitychange', function() {
  if (document.hidden) {
    // 页面隐藏，暂停非必要操作
    pauseAnimations();
    stopPolling();
    unsubscribeFromUpdates();
  } else {
    // 页面可见，恢复操作
    resumeAnimations();
    startPolling();
    subscribeToUpdates();
  }
});
```

### 内存管理

```js
// 避免内存泄漏 - 清理事件监听器
function setupComponent() {
  const button = document.getElementById('action-button');
  const handler = () => performAction();
  
  button.addEventListener('click', handler);
  
  // 返回清理函数
  return function cleanup() {
    button.removeEventListener('click', handler);
  };
}

// 在React组件中
useEffect(() => {
  const cleanup = setupComponent();
  
  // 组件卸载时清理
  return cleanup;
}, []);

// 避免闭包导致的意外引用
function createLargeDataProcessor() {
  // 不好的做法 - 闭包捕获了largeData引用
  const largeData = getLargeData();
  
  return function process() {
    return largeData.map(item => item.value * 2);
  };
}

// 好的做法 - 不保留对大数据的引用
function betterCreateProcessor() {
  // 处理后释放对原始数据的引用
  const processedData = getLargeData().map(item => item.value);
  
  return function process() {
    return processedData.map(value => value * 2);
  };
}
```

## 移动端测试与监控

### 移动端性能测试工具

1. **Lighthouse移动测试** - 使用移动设备仿真进行性能审计
2. **Chrome DevTools** - 使用设备模式和网络节流
3. **WebPageTest** - 在真实移动设备上进行测试
4. **Firebase Performance Monitoring** - 监控应用在真实用户设备上的性能

### 真机测试

```js
// 使用User-Agent检测移动设备
function isMobileDevice() {
  return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
}

// 根据设备类型调整功能
if (isMobileDevice()) {
  enableMobileOptimizations();
} else {
  enableDesktopFeatures();
}

// 检测设备性能
function detectDevicePerformance() {
  const start = performance.now();
  let iterations = 0;
  
  // 执行一些计算密集型操作
  while (performance.now() - start < 100) {
    // 一些计算
    Math.pow(iterations, iterations % 10);
    iterations++;
  }
  
  // 根据迭代次数评估设备性能
  if (iterations > 10000) {
    return 'high';
  } else if (iterations > 5000) {
    return 'medium';
  } else {
    return 'low';
  }
}

// 根据设备性能调整应用
const devicePerformance = detectDevicePerformance();
adjustApplicationSettings(devicePerformance);
```

### 监控关键移动指标

```js
// 监控首次内容绘制(FCP)和最大内容绘制(LCP)
import {getFCP, getLCP} from 'web-vitals';

// 监控首次输入延迟(FID)
import {getFID} from 'web-vitals';

// 监控累积布局偏移(CLS)
import {getCLS} from 'web-vitals';

// 上报数据
function sendToAnalytics({name, delta, id}) {
  const body = JSON.stringify({
    name,
    delta,
    id,
    deviceType: 'mobile',
    networkType: navigator.connection ? navigator.connection.effectiveType : 'unknown'
  });
  
  // 使用Beacon API发送数据
  navigator.sendBeacon('/analytics', body);
}

// 注册监控
getFCP(sendToAnalytics);
getLCP(sendToAnalytics);
getFID(sendToAnalytics);
getCLS(sendToAnalytics);
```

## 最佳实践清单

### 网络优化

- [ ] 实现应用资源的离线缓存
- [ ] 根据网络质量动态调整资源加载
- [ ] 优先加载关键路径资源
- [ ] 使用HTTP/2减少连接开销
- [ ] 压缩所有文本资源(HTML, CSS, JS)

### 渲染优化

- [ ] 避免大型、复杂的DOM结构
- [ ] 使用CSS硬件加速属性
- [ ] 优化滚动性能
- [ ] 减少重排和重绘
- [ ] 使用Web Workers处理复杂计算

### 资源优化

- [ ] 实现响应式图片策略
- [ ] 优化字体加载
- [ ] 延迟加载非关键资源
- [ ] 预加载关键资源
- [ ] 使用现代图片格式(WebP, AVIF)

### 交互优化

- [ ] 确保触摸目标足够大(至少48x48px)
- [ ] 消除点击延迟
- [ ] 提供即时视觉反馈
- [ ] 优化手势识别
- [ ] 确保键盘可访问性

### 电池和内存优化

- [ ] 使用Page Visibility API暂停后台工作
- [ ] 避免内存泄漏
- [ ] 优化动画性能
- [ ] 定期清理不需要的数据和DOM元素
- [ ] 使用requestIdleCallback处理非关键任务

## 参考资源

- [移动Web性能优化 - Google](https://developers.google.com/web/fundamentals/performance/why-performance-matters)
- [移动端Web最佳实践 - MDN](https://developer.mozilla.org/zh-CN/docs/Web/Guide/Mobile)
- [PWA文档 - web.dev](https://web.dev/progressive-web-apps/)
- [移动端性能模式 - Patterns.dev](https://www.patterns.dev/posts/performance-patterns)
