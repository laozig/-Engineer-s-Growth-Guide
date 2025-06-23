# 资源加载优化

资源加载优化是前端性能提升的关键环节，直接影响页面的首次加载速度和用户体验。本文档介绍如何通过减少资源体积和优化加载策略来提升网站性能。

## 目录

- [资源压缩与合并](#资源压缩与合并)
- [代码分割](#代码分割)
- [资源优先级](#资源优先级)
- [预加载与预连接](#预加载与预连接)
- [懒加载技术](#懒加载技术)
- [HTTP/2优化](#http2优化)
- [构建工具优化](#构建工具优化)
- [最佳实践清单](#最佳实践清单)

## 资源压缩与合并

### 文本资源压缩

对HTML、CSS和JavaScript等文本资源进行压缩可以显著减少文件体积：

1. **代码压缩（Minification）**

   移除空格、注释和不必要的字符：

   ```js
   // 使用terser压缩JavaScript
   const terser = require('terser');
   
   const code = `
     // 这是一个示例函数
     function add(a, b) {
       const result = a + b; // 计算结果
       return result;
     }
   `;
   
   const minified = terser.minify(code);
   console.log(minified.code); // function add(a,b){return a+b}
   ```

2. **Gzip/Brotli压缩**

   在服务器端配置Gzip或Brotli压缩：

   ```nginx
   # Nginx配置示例
   server {
     # ...
     gzip on;
     gzip_comp_level 6;
     gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
     
     # Brotli配置（需要安装模块）
     brotli on;
     brotli_comp_level 6;
     brotli_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
   }
   ```

### 资源合并

减少HTTP请求数量可以提高加载性能：

```js
// Webpack配置示例 - 合并多个CSS文件
module.exports = {
  // ...
  optimization: {
    splitChunks: {
      cacheGroups: {
        styles: {
          name: 'styles',
          test: /\.css$/,
          chunks: 'all',
          enforce: true,
        }
      }
    }
  }
};
```

## 代码分割

### 动态导入

使用动态导入实现按需加载：

```js
// React组件懒加载示例
import React, { lazy, Suspense } from 'react';

// 懒加载组件
const LazyComponent = lazy(() => import('./LazyComponent'));

function App() {
  return (
    <div>
      <Suspense fallback={<div>Loading...</div>}>
        <LazyComponent />
      </Suspense>
    </div>
  );
}
```

```js
// Vue组件懒加载示例
const router = createRouter({
  routes: [
    {
      path: '/dashboard',
      component: () => import('./views/Dashboard.vue') // 动态导入
    }
  ]
});
```

### 路由级代码分割

按路由拆分代码，实现按页面加载资源：

```js
// Vue Router示例
const routes = [
  {
    path: '/',
    component: () => import('./views/Home.vue')
  },
  {
    path: '/about',
    component: () => import('./views/About.vue')
  }
];
```

## 资源优先级

### 资源提示

使用资源提示指令优化加载顺序：

```html
<!-- 预加载关键资源 -->
<link rel="preload" href="critical.css" as="style">
<link rel="preload" href="main.js" as="script">

<!-- 预连接到将要使用的域名 -->
<link rel="preconnect" href="https://api.example.com">

<!-- 预获取可能需要的资源 -->
<link rel="prefetch" href="next-page.js">
```

### 关键CSS内联

将首屏渲染所需的CSS直接内联到HTML中：

```html
<head>
  <style>
    /* 关键CSS */
    body { margin: 0; font-family: sans-serif; }
    .header { background: #f0f0f0; padding: 1rem; }
    /* ... */
  </style>
  <!-- 其余CSS异步加载 -->
  <link rel="preload" href="main.css" as="style" onload="this.onload=null;this.rel='stylesheet'">
  <noscript><link rel="stylesheet" href="main.css"></noscript>
</head>
```

## 预加载与预连接

### 预加载字体

优化字体加载体验：

```html
<link rel="preload" href="fonts/roboto.woff2" as="font" type="font/woff2" crossorigin>
```

### DNS预解析

提前解析第三方域名：

```html
<link rel="dns-prefetch" href="https://fonts.googleapis.com">
<link rel="dns-prefetch" href="https://analytics.google.com">
```

## 懒加载技术

### 图片懒加载

使用原生懒加载或Intersection Observer API：

```html
<!-- 原生懒加载 -->
<img src="placeholder.jpg" data-src="actual-image.jpg" loading="lazy" alt="懒加载图片">
```

```js
// 使用Intersection Observer实现懒加载
document.addEventListener("DOMContentLoaded", function() {
  const lazyImages = document.querySelectorAll('img[data-src]');
  
  const imageObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        img.src = img.dataset.src;
        img.removeAttribute('data-src');
        imageObserver.unobserve(img);
      }
    });
  });
  
  lazyImages.forEach(img => {
    imageObserver.observe(img);
  });
});
```

### 组件懒加载

根据视口位置加载组件：

```js
// React中使用react-lazyload
import LazyLoad from 'react-lazyload';

function Gallery() {
  return (
    <div>
      {items.map(item => (
        <LazyLoad height={200} once key={item.id}>
          <Card item={item} />
        </LazyLoad>
      ))}
    </div>
  );
}
```

## HTTP/2优化

### 服务器推送

配置服务器推送关键资源：

```nginx
# Nginx配置示例
location / {
  # ...
  http2_push /styles/main.css;
  http2_push /scripts/main.js;
}
```

### 多路复用

利用HTTP/2的多路复用特性，不再需要过度合并资源：

```js
// 现代构建配置 - 可以适当拆分资源
module.exports = {
  // ...
  optimization: {
    splitChunks: {
      chunks: 'all',
      maxInitialRequests: 10, // HTTP/2环境下可以增加并行请求数
    }
  }
};
```

## 构建工具优化

### Webpack优化

优化Webpack构建输出：

```js
// webpack.config.js
const TerserPlugin = require('terser-webpack-plugin');
const CssMinimizerPlugin = require('css-minimizer-webpack-plugin');

module.exports = {
  // ...
  optimization: {
    minimizer: [
      new TerserPlugin({
        terserOptions: {
          compress: {
            drop_console: true, // 移除console
          },
        },
      }),
      new CssMinimizerPlugin(),
    ],
    splitChunks: {
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all',
        },
      },
    },
  },
};
```

### Tree Shaking

移除未使用的代码：

```js
// package.json
{
  "sideEffects": false, // 或指定有副作用的文件 ["*.css"]
}
```

```js
// 使用ES模块语法以启用Tree Shaking
// 好的做法
import { Button } from 'ui-library';

// 避免这样做，会导入整个库
import UILibrary from 'ui-library';
const { Button } = UILibrary;
```

## 最佳实践清单

- ✅ 压缩所有文本资源（HTML、CSS、JavaScript）
- ✅ 启用Gzip/Brotli压缩
- ✅ 实施代码分割和懒加载
- ✅ 内联关键CSS
- ✅ 使用资源提示（preload、prefetch、preconnect）
- ✅ 优化图片和字体加载
- ✅ 利用浏览器缓存策略
- ✅ 采用HTTP/2或HTTP/3
- ✅ 移除未使用的代码（Tree Shaking）
- ✅ 减少第三方脚本的影响

## 参考资源

- [Web Vitals](https://web.dev/vitals/) - Google的Web性能指标
- [PageSpeed Insights](https://developers.google.com/speed/pagespeed/insights/) - 性能分析工具
- [Webpack性能优化](https://webpack.js.org/guides/build-performance/) - 官方指南 