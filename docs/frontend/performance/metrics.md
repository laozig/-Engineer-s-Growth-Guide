# 性能指标与测量

性能指标是衡量Web应用性能的量化标准，帮助开发者客观评估用户体验并发现性能瓶颈。本文档介绍关键性能指标及测量方法。

## 核心Web指标

Google定义的核心Web指标(Core Web Vitals)是评估用户体验的关键指标：

### LCP (Largest Contentful Paint)

最大内容绘制，衡量加载性能。

```js
import {getLCP} from 'web-vitals';
getLCP(({value}) => console.log(`LCP: ${value}ms`));
```

**评分标准**：
- 良好：≤ 2.5秒
- 需改进：2.5秒 - 4秒
- 较差：> 4秒

### FID (First Input Delay)

首次输入延迟，衡量交互性能。

```js
import {getFID} from 'web-vitals';
getFID(({value}) => console.log(`FID: ${value}ms`));
```

**评分标准**：
- 良好：≤ 100毫秒
- 需改进：100毫秒 - 300毫秒
- 较差：> 300毫秒

### CLS (Cumulative Layout Shift)

累积布局偏移，衡量视觉稳定性。

```js
import {getCLS} from 'web-vitals';
getCLS(({value}) => console.log(`CLS: ${value}`));
```

**评分标准**：
- 良好：≤ 0.1
- 需改进：0.1 - 0.25
- 较差：> 0.25

## 其他重要性能指标

### TTFB (Time to First Byte)

首字节时间，衡量服务器响应速度。

```js
const ttfb = performance.getEntriesByType('navigation')[0].responseStart;
console.log(`TTFB: ${ttfb}ms`);
```

### FCP (First Contentful Paint)

首次内容绘制，首次显示DOM内容的时间。

```js
import {getFCP} from 'web-vitals';
getFCP(({value}) => console.log(`FCP: ${value}ms`));
```

### TTI (Time to Interactive)

可交互时间，页面完全可交互的时间点。

```js
// 通常通过Lighthouse测量
```

### TBT (Total Blocking Time)

总阻塞时间，主线程阻塞的总时长。

```js
// 通常通过Lighthouse测量
```

### INP (Interaction to Next Paint)

交互到下一帧，衡量交互响应性。

```js
import {getINP} from 'web-vitals';
getINP(({value}) => console.log(`INP: ${value}ms`));
```

## 自定义性能指标

### 使用Performance API创建自定义指标

```js
// 标记开始点
performance.mark('process-start');

// 执行需测量的操作
doSomethingExpensive();

// 标记结束点并测量
performance.mark('process-end');
performance.measure('process-duration', 'process-start', 'process-end');

// 获取测量结果
const duration = performance.getEntriesByName('process-duration')[0].duration;
console.log(`Process took ${duration}ms`);
```

### 业务相关性能指标

```js
// 测量产品添加到购物车的时间
const startTime = performance.now();
addProductToCart(productId).then(() => {
  const duration = performance.now() - startTime;
  console.log(`Add to cart took ${duration}ms`);
});
```

## 性能测量工具

### Lighthouse

综合性能评估工具，提供性能、可访问性、最佳实践等评分。

```bash
# 命令行使用
lighthouse https://example.com --output=json --output-path=./report.json
```

### Web Vitals库

测量核心Web指标的JavaScript库。

```js
import {getCLS, getFID, getLCP} from 'web-vitals';

// 注册所有指标的回调
function sendToAnalytics({name, value}) {
  console.log(`${name}: ${value}`);
  // 发送到分析服务
}

getCLS(sendToAnalytics);
getFID(sendToAnalytics);
getLCP(sendToAnalytics);
```

### Performance API

浏览器原生Performance API。

```js
// 获取导航计时信息
const navigation = performance.getEntriesByType('navigation')[0];
const timing = {
  dnsLookup: navigation.domainLookupEnd - navigation.domainLookupStart,
  tcpConnection: navigation.connectEnd - navigation.connectStart,
  requestResponse: navigation.responseEnd - navigation.requestStart,
  domProcessing: navigation.domComplete - navigation.responseEnd,
  pageLoad: navigation.loadEventEnd - navigation.startTime
};
console.table(timing);
```

## 性能预算

设定性能目标和阈值：

```js
// 性能预算示例
const PERFORMANCE_BUDGET = {
  // 时间预算 (毫秒)
  timing: {
    fcp: 1800,
    lcp: 2500,
    tbt: 200,
    tti: 3800,
    cls: 0.1
  },
  
  // 资源大小预算 (KB)
  size: {
    total: 1000,
    js: 300,
    css: 100,
    images: 500,
    fonts: 100
  }
};
```

## 实时用户监控 (RUM)

收集真实用户的性能数据：

```js
// 使用web-vitals实现基本RUM
import {getCLS, getFCP, getFID, getLCP, getTTFB} from 'web-vitals';

// 发送数据到分析服务
function sendToAnalytics({name, value, id}) {
  const url = 'https://analytics.example.com/collect';
  const body = JSON.stringify({
    name, 
    value, 
    id,
    url: window.location.href,
    userAgent: navigator.userAgent
  });
  
  navigator.sendBeacon(url, body);
}

// 注册所有指标的回调
getCLS(sendToAnalytics);
getFCP(sendToAnalytics);
getFID(sendToAnalytics);
getLCP(sendToAnalytics);
getTTFB(sendToAnalytics);
```

## 最佳实践清单

- ✅ 监控核心Web指标(LCP、FID/INP、CLS)
- ✅ 建立性能预算并在CI/CD中自动检查
- ✅ 实施真实用户监控(RUM)收集实际用户数据
- ✅ 使用自定义指标衡量业务关键流程
- ✅ 定期进行实验室测试(Lighthouse等)
- ✅ 按设备类型和网络条件细分性能数据
- ✅ 将性能指标与业务指标关联分析

## 参考资源

- [Web Vitals](https://web.dev/vitals/) - Google的Web性能指标
- [Lighthouse](https://developers.google.com/web/tools/lighthouse) - 网站审计工具
- [Performance API](https://developer.mozilla.org/zh-CN/docs/Web/API/Performance) - MDN文档
- [web-vitals库](https://github.com/GoogleChrome/web-vitals) - 测量核心Web指标的JavaScript库 