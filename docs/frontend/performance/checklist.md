# 前端性能优化清单

本文档提供了一个全面的前端性能优化检查清单，涵盖了从初始加载到运行时性能的各个方面。开发者可以使用此清单来评估和改进网站或应用的性能。

## 目录

- [初始加载性能](#初始加载性能)
- [资源优化](#资源优化)
- [渲染性能](#渲染性能)
- [JavaScript性能](#javascript性能)
- [CSS优化](#css优化)
- [字体优化](#字体优化)
- [图片和媒体优化](#图片和媒体优化)
- [网络优化](#网络优化)
- [缓存策略](#缓存策略)
- [第三方资源优化](#第三方资源优化)
- [移动端优化](#移动端优化)
- [性能监控](#性能监控)
- [构建优化](#构建优化)

## 初始加载性能

### 关键渲染路径优化

- [ ] 识别并优化关键渲染路径
- [ ] 内联关键CSS到HTML头部
- [ ] 延迟加载非关键CSS
- [ ] 避免阻塞渲染的JavaScript
- [ ] 使用async或defer属性加载非关键脚本
- [ ] 优先加载首屏内容

### 核心Web指标

- [ ] 优化最大内容绘制(LCP) ≤ 2.5秒
- [ ] 优化首次输入延迟(FID) ≤ 100毫秒
- [ ] 优化累积布局偏移(CLS) ≤ 0.1
- [ ] 优化首次内容绘制(FCP) ≤ 1.8秒
- [ ] 优化可交互时间(TTI) ≤ 3.8秒
- [ ] 优化总阻塞时间(TBT) ≤ 200毫秒
- [ ] 优化速度指数(SI) ≤ 3.4秒

## 资源优化

### 文件大小

- [ ] 压缩HTML、CSS和JavaScript文件
- [ ] 使用Brotli或Gzip进行文本资源压缩
- [ ] 移除未使用的代码和依赖
- [ ] 实施代码拆分和懒加载
- [ ] 使用tree-shaking移除未使用的JavaScript
- [ ] 优化依赖包大小，考虑使用更轻量的替代品

### 资源加载

- [ ] 实现资源优先级加载
- [ ] 使用`<link rel="preload">`预加载关键资源
- [ ] 使用`<link rel="preconnect">`提前建立连接
- [ ] 使用`<link rel="dns-prefetch">`提前解析DNS
- [ ] 使用`<link rel="prefetch">`预取可能需要的资源
- [ ] 延迟加载非首屏内容
- [ ] 避免资源加载瀑布

## 渲染性能

### DOM操作

- [ ] 批量DOM操作，避免布局抖动
- [ ] 使用DocumentFragment减少重排
- [ ] 使用虚拟DOM或高效的DOM操作库
- [ ] 避免强制同步布局
- [ ] 使用CSS transform和opacity进行动画
- [ ] 使用requestAnimationFrame进行视觉更新

### 布局和绘制

- [ ] 简化CSS选择器
- [ ] 避免过度使用CSS阴影和滤镜
- [ ] 使用will-change属性提示浏览器
- [ ] 减少重绘和重排
- [ ] 使用CSS containment优化渲染性能
- [ ] 优化滚动性能

## JavaScript性能

### 代码质量

- [ ] 避免长时间运行的JavaScript
- [ ] 优化循环和递归
- [ ] 使用高效的数据结构和算法
- [ ] 避免内存泄漏
- [ ] 使用Web Workers处理计算密集型任务
- [ ] 实现代码拆分和懒执行

### 事件处理

- [ ] 使用事件委托减少事件监听器
- [ ] 节流(throttle)和防抖(debounce)高频事件
- [ ] 移除未使用的事件监听器
- [ ] 使用被动事件监听器提高滚动性能
- [ ] 避免在滚动事件中进行复杂计算

### 框架优化

- [ ] 使用生产模式构建
- [ ] 实施组件懒加载
- [ ] 优化状态管理
- [ ] 使用memo/useMemo/useCallback减少不必要的重渲染
- [ ] 实施虚拟滚动处理长列表
- [ ] 使用服务端渲染或静态生成提高首屏性能

## CSS优化

- [ ] 使用CSS预处理器优化代码组织
- [ ] 移除未使用的CSS
- [ ] 避免使用@import
- [ ] 优化CSS选择器性能
- [ ] 使用现代CSS布局技术(Grid, Flexbox)
- [ ] 使用CSS变量提高可维护性
- [ ] 避免过度使用CSS动画

## 字体优化

- [ ] 使用font-display控制字体加载行为
- [ ] 优先使用系统字体
- [ ] 使用WOFF2字体格式
- [ ] 只加载必要的字体变体和字符
- [ ] 使用font-subsetting减小字体文件大小
- [ ] 预加载关键字体
- [ ] 使用字体加载API控制字体加载

## 图片和媒体优化

- [ ] 使用适当的图片格式(WebP, AVIF)
- [ ] 实现响应式图片
- [ ] 使用srcset和sizes属性
- [ ] 优化图片尺寸和质量
- [ ] 延迟加载非关键图片
- [ ] 为图片设置宽度和高度属性避免布局偏移
- [ ] 使用CSS sprite或SVG图标
- [ ] 优化视频播放(延迟加载，使用适当的格式)
- [ ] 压缩图片和视频资源

## 网络优化

- [ ] 使用HTTP/2或HTTP/3
- [ ] 减少HTTP请求数量
- [ ] 优化服务器响应时间
- [ ] 使用内容分发网络(CDN)
- [ ] 实施域名分片(适用于HTTP/1.1)
- [ ] 避免重定向
- [ ] 优化API请求(批处理，缓存)
- [ ] 实施CORS优化

## 缓存策略

- [ ] 配置适当的HTTP缓存头
- [ ] 实施Service Worker缓存
- [ ] 使用Cache API存储关键资源
- [ ] 使用IndexedDB存储应用数据
- [ ] 实施应用程序缓存策略
- [ ] 使用localStorage/sessionStorage适当缓存数据
- [ ] 为静态资源使用长期缓存并添加内容哈希

## 第三方资源优化

- [ ] 审核并减少第三方脚本
- [ ] 延迟加载非关键第三方资源
- [ ] 使用资源提示优化第三方资源加载
- [ ] 使用Subresource Integrity确保资源完整性
- [ ] 实施超时处理第三方资源失败
- [ ] 评估第三方资源对性能的影响
- [ ] 使用self-hosted第三方资源(如字体、常用库)

## 移动端优化

- [ ] 优化触摸响应
- [ ] 消除点击延迟
- [ ] 确保适当的触摸目标大小
- [ ] 优化键盘输入体验
- [ ] 适应不同网络条件
- [ ] 实施渐进式Web应用(PWA)功能
- [ ] 优化电池使用

## 性能监控

- [ ] 实施真实用户监控(RUM)
- [ ] 监控核心Web指标
- [ ] 设置性能预算
- [ ] 使用Lighthouse进行性能审计
- [ ] 监控JavaScript错误和异常
- [ ] 实施性能回归测试
- [ ] 使用WebPageTest进行性能测试
- [ ] 监控服务器响应时间

## 构建优化

- [ ] 优化模块打包
- [ ] 实施高效的代码分割
- [ ] 使用现代JavaScript功能并提供回退
- [ ] 优化依赖管理
- [ ] 使用高效的构建工具和配置
- [ ] 实施差异化打包策略
- [ ] 优化构建输出大小

## 性能优化工具

- [ ] [Lighthouse](https://developers.google.com/web/tools/lighthouse)
- [ ] [WebPageTest](https://www.webpagetest.org/)
- [ ] [Chrome DevTools Performance面板](https://developers.google.com/web/tools/chrome-devtools/evaluate-performance)
- [ ] [PageSpeed Insights](https://pagespeed.web.dev/)
- [ ] [Web Vitals扩展](https://chrome.google.com/webstore/detail/web-vitals/ahfhijdlegdabablpippeagghigmibma)
- [ ] [Webpack Bundle Analyzer](https://github.com/webpack-contrib/webpack-bundle-analyzer)
- [ ] [Perfume.js](https://github.com/Zizzamia/perfume.js)
- [ ] [Sentry](https://sentry.io/)
- [ ] [New Relic](https://newrelic.com/)
- [ ] [Datadog](https://www.datadoghq.com/)

## 参考资源

- [Web Vitals - web.dev](https://web.dev/vitals/)
- [性能优化指南 - MDN](https://developer.mozilla.org/zh-CN/docs/Web/Performance)
- [高性能网站建设指南](https://book.douban.com/subject/3132277/)
- [高性能JavaScript](https://book.douban.com/subject/5362856/)
- [性能优化实战 - web.dev](https://web.dev/fast/)
- [前端性能清单 - GitHub](https://github.com/thedaviddias/Front-End-Performance-Checklist)
