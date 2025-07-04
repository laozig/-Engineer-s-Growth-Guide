# 性能监控与分析

性能监控与分析是前端性能优化的关键环节，通过科学的测量和分析，可以识别性能瓶颈、验证优化效果并建立长期的性能监控机制。本文档介绍前端性能监控的工具、方法和最佳实践。

## 目录

- [性能指标](#性能指标)
- [浏览器性能API](#浏览器性能api)
- [性能监控工具](#性能监控工具)
- [实时用户监控(RUM)](#实时用户监控rum)
- [性能数据分析](#性能数据分析)
- [性能监控系统搭建](#性能监控系统搭建)
- [最佳实践](#最佳实践)

## 性能指标

### 核心Web指标

Google定义的关键用户体验指标：

1. **最大内容绘制(LCP)** - 页面主要内容加载完成的时间
   - 良好：≤ 2.5秒
   - 需要改进：≤ 4秒
   - 较差：> 4秒

2. **首次输入延迟(FID)** - 页面响应用户交互的时间
   - 良好：≤ 100毫秒
   - 需要改进：≤ 300毫秒
   - 较差：> 300毫秒

3. **累积布局偏移(CLS)** - 页面视觉稳定性的度量
   - 良好：≤ 0.1
   - 需要改进：≤ 0.25
   - 较差：> 0.25

### 其他重要指标

1. **首次内容绘制(FCP)** - 页面首次显示内容的时间
2. **首次有意义绘制(FMP)** - 页面主要内容变得可见的时间
3. **可交互时间(TTI)** - 页面完全可交互的时间
4. **总阻塞时间(TBT)** - 主线程被阻塞且影响输入响应的总时间
5. **速度指数(SI)** - 页面内容填充的速度

## 浏览器性能API

### Performance API

使用浏览器内置的Performance API收集性能数据：

```js
// 获取导航和资源加载时间
const perfData = window.performance.timing;
const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
const domReadyTime = perfData.domComplete - perfData.domLoading;

console.log(`页面加载时间: ${pageLoadTime}ms`);
console.log(`DOM准备时间: ${domReadyTime}ms`);

// 获取资源加载详情
const resources = performance.getEntriesByType('resource');
resources.forEach(resource => {
  console.log(`资源: ${resource.name}`);
  console.log(`加载时间: ${resource.duration}ms`);
  console.log(`大小: ${resource.transferSize} bytes`);
});

// 创建自定义性能标记
performance.mark('custom-start');
// 执行需要测量的操作
doSomething();
performance.mark('custom-end');

// 测量两个标记之间的时间
performance.measure('custom-measure', 'custom-start', 'custom-end');
const measures = performance.getEntriesByName('custom-measure');
console.log(`自定义测量时间: ${measures[0].duration}ms`);
```

### PerformanceObserver

监控性能事件并实时响应：

```js
// 创建性能观察器
const observer = new PerformanceObserver((list) => {
  for (const entry of list.getEntries()) {
    // 处理性能条目
    console.log(`${entry.name}: ${entry.startTime}ms, 持续时间: ${entry.duration}ms`);
    
    // 上报到分析服务
    sendToAnalyticsService({
      metric: entry.name,
      value: entry.duration,
      timestamp: new Date().toISOString()
    });
  }
});

// 监控长任务
observer.observe({ entryTypes: ['longtask'] });

// 监控绘制事件
observer.observe({ entryTypes: ['paint'] });

// 监控布局偏移
observer.observe({ entryTypes: ['layout-shift'] });

// 监控最大内容绘制
observer.observe({ entryTypes: ['largest-contentful-paint'] });
```

### Web Vitals库

使用Google的Web Vitals库简化核心指标收集：

```js
import {getCLS, getFID, getLCP} from 'web-vitals';

function sendToAnalytics(metric) {
  const body = JSON.stringify({
    name: metric.name,
    value: metric.value,
    id: metric.id,
    delta: metric.delta
  });
  
  // 使用Beacon API异步发送，不阻塞页面卸载
  navigator.sendBeacon('/analytics', body);
}

// 监控并上报核心Web指标
getCLS(sendToAnalytics);
getFID(sendToAnalytics);
getLCP(sendToAnalytics);
```

## 性能监控工具

### 浏览器开发者工具

Chrome DevTools提供多种性能分析功能：

1. **Performance面板** - 记录和分析页面加载和运行时性能
2. **Network面板** - 分析网络请求和资源加载
3. **Lighthouse** - 自动化性能审计工具
4. **Memory面板** - 分析内存使用和泄漏

### Lighthouse

使用Lighthouse进行自动化性能审计：

```js
// 使用Node.js API运行Lighthouse
const lighthouse = require('lighthouse');
const chromeLauncher = require('chrome-launcher');

async function runLighthouse(url) {
  const chrome = await chromeLauncher.launch({chromeFlags: ['--headless']});
  const options = {
    logLevel: 'info',
    output: 'json',
    port: chrome.port
  };
  
  const result = await lighthouse(url, options);
  await chrome.kill();
  
  // 处理结果
  const report = result.report;
  const scores = {
    performance: result.lhr.categories.performance.score * 100,
    accessibility: result.lhr.categories.accessibility.score * 100,
    bestPractices: result.lhr.categories['best-practices'].score * 100,
    seo: result.lhr.categories.seo.score * 100
  };
  
  console.log(`性能得分: ${scores.performance}`);
  
  return { report, scores };
}

// 使用示例
runLighthouse('https://example.com')
  .then(results => {
    // 保存报告或发送通知
    if (results.scores.performance < 80) {
      sendAlert('性能得分低于80，需要优化');
    }
  });
```

### WebPageTest

使用WebPageTest进行多地区、多设备的性能测试：

```js
// 使用WebPageTest API
const WebPageTest = require('webpagetest');
const wpt = new WebPageTest('www.webpagetest.org', 'YOUR_API_KEY');

wpt.runTest('https://example.com', {
  location: 'Beijing:Chrome',
  connectivity: '4G',
  runs: 3,
  firstViewOnly: false
}, (err, result) => {
  if (err) {
    console.error('测试失败:', err);
    return;
  }
  
  // 分析测试结果
  const firstView = result.data.average.firstView;
  console.log(`首屏时间: ${firstView.firstContentfulPaint}ms`);
  console.log(`可交互时间: ${firstView.TimeToInteractive}ms`);
  console.log(`完全加载时间: ${firstView.loadTime}ms`);
  console.log(`速度指数: ${firstView.SpeedIndex}`);
});
```

## 实时用户监控(RUM)

### 自定义RUM实现

构建基本的实时用户监控系统：

```js
// 性能监控客户端
class PerformanceMonitor {
  constructor(options = {}) {
    this.apiEndpoint = options.apiEndpoint || '/api/performance';
    this.sampleRate = options.sampleRate || 1.0; // 采样率
    this.userId = this.generateUserId();
    this.sessionId = this.generateSessionId();
    this.metrics = {};
    
    // 只对部分用户进行采样
    this.isMonitored = Math.random() <= this.sampleRate;
    
    if (this.isMonitored) {
      this.initMonitoring();
    }
  }
  
  generateUserId() {
    // 生成或从cookie获取用户ID
    return localStorage.getItem('user_id') || 
      `user_${Math.random().toString(36).substring(2, 15)}`;
  }
  
  generateSessionId() {
    // 生成会话ID
    return `session_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }
  
  initMonitoring() {
    // 监控页面加载性能
    window.addEventListener('load', () => {
      setTimeout(() => {
        this.captureNavigationTiming();
        this.capturePaintTiming();
      }, 0);
    });
    
    // 监控核心Web指标
    this.captureWebVitals();
    
    // 监控JavaScript错误
    this.captureErrors();
    
    // 监控网络请求
    this.captureNetworkRequests();
    
    // 页面离开前发送最终数据
    window.addEventListener('beforeunload', () => {
      this.sendMetrics(true);
    });
  }
  
  captureNavigationTiming() {
    const timing = performance.timing;
    const navigationStart = timing.navigationStart;
    
    this.metrics.timing = {
      dns: timing.domainLookupEnd - timing.domainLookupStart,
      tcp: timing.connectEnd - timing.connectStart,
      ttfb: timing.responseStart - timing.requestStart,
      domLoad: timing.domContentLoadedEventEnd - navigationStart,
      load: timing.loadEventEnd - navigationStart
    };
  }
  
  capturePaintTiming() {
    const paintEntries = performance.getEntriesByType('paint');
    paintEntries.forEach(entry => {
      this.metrics[entry.name] = entry.startTime;
    });
  }
  
  captureWebVitals() {
    // 使用web-vitals库
    import('web-vitals').then(({getCLS, getFID, getLCP}) => {
      getCLS(metric => {
        this.metrics.cls = metric.value;
        this.sendMetricsDebounced();
      });
      
      getFID(metric => {
        this.metrics.fid = metric.value;
        this.sendMetricsDebounced();
      });
      
      getLCP(metric => {
        this.metrics.lcp = metric.value;
        this.sendMetricsDebounced();
      });
    });
  }
  
  captureErrors() {
    window.addEventListener('error', (event) => {
      const error = {
        message: event.message,
        source: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        timestamp: Date.now()
      };
      
      if (!this.metrics.errors) {
        this.metrics.errors = [];
      }
      
      this.metrics.errors.push(error);
      this.sendMetricsDebounced();
    });
  }
  
  captureNetworkRequests() {
    const originalFetch = window.fetch;
    const monitor = this;
    
    window.fetch = async function(...args) {
      const startTime = performance.now();
      const url = args[0] instanceof Request ? args[0].url : args[0];
      
      try {
        const response = await originalFetch.apply(this, args);
        const duration = performance.now() - startTime;
        
        monitor.recordNetworkRequest(url, duration, response.status);
        return response;
      } catch (error) {
        const duration = performance.now() - startTime;
        monitor.recordNetworkRequest(url, duration, 0, error.message);
        throw error;
      }
    };
  }
  
  recordNetworkRequest(url, duration, status, error = null) {
    if (!this.metrics.network) {
      this.metrics.network = [];
    }
    
    // 排除性能监控API自身的请求
    if (url.includes(this.apiEndpoint)) {
      return;
    }
    
    this.metrics.network.push({
      url: url.split('?')[0], // 移除查询参数
      duration,
      status,
      error,
      timestamp: Date.now()
    });
    
    this.sendMetricsDebounced();
  }
  
  sendMetricsDebounced() {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    
    this.debounceTimer = setTimeout(() => {
      this.sendMetrics();
    }, 3000);
  }
  
  sendMetrics(isFinal = false) {
    if (!this.isMonitored || Object.keys(this.metrics).length === 0) {
      return;
    }
    
    const payload = {
      userId: this.userId,
      sessionId: this.sessionId,
      url: window.location.href,
      userAgent: navigator.userAgent,
      timestamp: Date.now(),
      metrics: this.metrics,
      isFinal
    };
    
    // 使用Beacon API发送数据，不阻塞页面卸载
    if (navigator.sendBeacon) {
      navigator.sendBeacon(this.apiEndpoint, JSON.stringify(payload));
    } else {
      // 回退到fetch
      fetch(this.apiEndpoint, {
        method: 'POST',
        body: JSON.stringify(payload),
        keepalive: true,
        headers: {
          'Content-Type': 'application/json'
        }
      }).catch(e => console.error('性能数据发送失败:', e));
    }
    
    // 清除已发送的错误和网络请求数据
    if (this.metrics.errors) {
      this.metrics.errors = [];
    }
    
    if (this.metrics.network) {
      this.metrics.network = [];
    }
  }
}

// 初始化监控
const monitor = new PerformanceMonitor({
  apiEndpoint: 'https://analytics.example.com/performance',
  sampleRate: 0.1 // 10%的用户
});
```

## 性能数据分析

### 数据聚合与可视化

使用ELK栈处理和可视化性能数据：

```js
// 服务器端代码 (Node.js + Express)
const express = require('express');
const elasticsearch = require('@elastic/elasticsearch');
const app = express();

// 创建Elasticsearch客户端
const esClient = new elasticsearch.Client({
  node: 'http://localhost:9200'
});

// 解析JSON请求体
app.use(express.json());

// 性能数据接收端点
app.post('/api/performance', async (req, res) => {
  try {
    const performanceData = req.body;
    
    // 添加服务器时间戳
    performanceData.serverTimestamp = new Date();
    
    // 存储到Elasticsearch
    await esClient.index({
      index: 'performance-metrics',
      body: performanceData
    });
    
    res.status(200).send({ status: 'success' });
  } catch (error) {
    console.error('存储性能数据失败:', error);
    res.status(500).send({ status: 'error', message: error.message });
  }
});

// 启动服务器
app.listen(3000, () => {
  console.log('性能监控服务器运行在端口3000');
});
```

## 最佳实践

### 性能监控策略

1. **分层监控**：同时监控前端、网络和后端性能
2. **采样策略**：对高流量网站使用适当的采样率
3. **关键路径**：重点监控用户关键路径和转化流程
4. **地域分布**：考虑不同地域用户的性能差异
5. **设备细分**：区分移动端和桌面端的性能指标
6. **网络条件**：考虑不同网络条件下的性能表现
7. **自动化警报**：设置合理的警报阈值，避免警报疲劳
8. **持续基准测试**：定期进行基准测试，跟踪长期趋势

### 性能预算实施

建立和维护性能预算：

```js
// 性能预算配置
const PERFORMANCE_BUDGET = {
  // 时间预算 (ms)
  timing: {
    fcp: 1000,  // 首次内容绘制
    lcp: 2500,  // 最大内容绘制
    tbt: 300,   // 总阻塞时间
    tti: 3500,  // 可交互时间
    cls: 0.1    // 累积布局偏移
  },
  
  // 资源预算 (KB)
  resources: {
    total: 1000,
    js: 300,
    css: 100,
    images: 500,
    fonts: 100
  }
};

// 检查性能预算
async function checkPerformanceBudget(url) {
  // 使用Lighthouse测量性能
  const result = await runLighthouse(url);
  const audits = result.lhr.audits;
  
  const violations = [];
  
  // 检查时间预算
  if (audits['first-contentful-paint'].numericValue > PERFORMANCE_BUDGET.timing.fcp) {
    violations.push({
      metric: 'FCP',
      budget: PERFORMANCE_BUDGET.timing.fcp,
      actual: Math.round(audits['first-contentful-paint'].numericValue),
      unit: 'ms'
    });
  }
  
  if (audits['largest-contentful-paint'].numericValue > PERFORMANCE_BUDGET.timing.lcp) {
    violations.push({
      metric: 'LCP',
      budget: PERFORMANCE_BUDGET.timing.lcp,
      actual: Math.round(audits['largest-contentful-paint'].numericValue),
      unit: 'ms'
    });
  }
  
  // 检查资源预算
  const resourceSummary = audits['resource-summary'].details.items;
  const totalBytes = resourceSummary.find(item => item.resourceType === 'total').transferSize / 1024;
  
  if (totalBytes > PERFORMANCE_BUDGET.resources.total) {
    violations.push({
      metric: '总资源大小',
      budget: PERFORMANCE_BUDGET.resources.total,
      actual: Math.round(totalBytes),
      unit: 'KB'
    });
  }
  
  // 检查JavaScript资源
  const jsBytes = resourceSummary.find(item => item.resourceType === 'script').transferSize / 1024;
  
  if (jsBytes > PERFORMANCE_BUDGET.resources.js) {
    violations.push({
      metric: 'JavaScript大小',
      budget: PERFORMANCE_BUDGET.resources.js,
      actual: Math.round(jsBytes),
      unit: 'KB'
    });
  }
  
  return {
    url,
    timestamp: new Date(),
    passed: violations.length === 0,
    violations
  };
}

// 在CI/CD流程中使用
async function enforcePerformanceBudget() {
  const result = await checkPerformanceBudget('https://staging.example.com');
  
  if (!result.passed) {
    console.error('性能预算检查失败:');
    result.violations.forEach(v => {
      console.error(`- ${v.metric}: ${v.actual}${v.unit} (预算: ${v.budget}${v.unit})`);
    });
    
    // 在CI中失败构建
    process.exit(1);
  } else {
    console.log('性能预算检查通过！');
  }
}
```

## 参考资源

- [Web Vitals - web.dev](https://web.dev/vitals/)
- [Performance API - MDN](https://developer.mozilla.org/zh-CN/docs/Web/API/Performance_API)
- [Lighthouse - Google](https://developers.google.com/web/tools/lighthouse)
- [WebPageTest API](https://docs.webpagetest.org/api/)
- [OpenTelemetry - 分布式追踪](https://opentelemetry.io/)
- [Grafana - 数据可视化](https://grafana.com/)
