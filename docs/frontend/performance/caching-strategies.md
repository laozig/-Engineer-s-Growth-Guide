# 缓存策略

缓存是前端性能优化的关键技术，通过合理利用各级缓存机制，可以显著减少网络请求、降低服务器负载并提升用户体验。本文档介绍Web应用中常用的缓存策略及其实现方法。

## 目录

- [HTTP缓存](#http缓存)
- [服务工作线程(Service Worker)](#服务工作线程service-worker)
- [内存缓存](#内存缓存)
- [本地存储缓存](#本地存储缓存)
- [CDN缓存](#cdn缓存)
- [缓存失效策略](#缓存失效策略)
- [最佳实践](#最佳实践)

## HTTP缓存

HTTP缓存是最基础的缓存机制，通过HTTP头控制浏览器对资源的缓存行为。

### 强缓存

强缓存不需要向服务器发送请求，直接从本地获取资源：

```http
# 使用Cache-Control（HTTP/1.1）
Cache-Control: max-age=31536000, immutable

# 使用Expires（HTTP/1.0，不推荐单独使用）
Expires: Wed, 21 Oct 2023 07:28:00 GMT
```

主要的Cache-Control指令：

```http
# 缓存时间（秒）
Cache-Control: max-age=3600

# 共享缓存（CDN等）
Cache-Control: public

# 私有缓存（浏览器）
Cache-Control: private

# 不缓存
Cache-Control: no-store

# 每次使用前验证
Cache-Control: no-cache

# 内容不会变化（配合长max-age使用）
Cache-Control: immutable
```

### 协商缓存

当强缓存失效时，浏览器会向服务器发送请求验证资源是否更新：

```http
# 基于最后修改时间的协商缓存
# 请求头
If-Modified-Since: Wed, 21 Oct 2022 07:28:00 GMT

# 响应头
Last-Modified: Wed, 21 Oct 2022 07:28:00 GMT

# 基于内容指纹的协商缓存
# 请求头
If-None-Match: "33a64df551425fcc55e4d42a148795d9f25f89d4"

# 响应头
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

### 服务器配置示例

```nginx
# Nginx配置
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}

location ~* \.(html|htm)$ {
    add_header Cache-Control "no-cache";
    etag on;
}
```

## 服务工作线程(Service Worker)

Service Worker是浏览器在后台运行的脚本，可以拦截网络请求并进行缓存控制，即使在离线状态下也能提供服务。

### 注册Service Worker

```js
// 检查浏览器是否支持Service Worker
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js')
      .then(registration => {
        console.log('Service Worker注册成功:', registration.scope);
      })
      .catch(error => {
        console.error('Service Worker注册失败:', error);
      });
  });
}
```

### 缓存策略实现

```js
// sw.js - Service Worker文件
const CACHE_NAME = 'my-site-cache-v1';
const urlsToCache = [
  '/',
  '/styles/main.css',
  '/scripts/main.js',
  '/images/logo.png'
];

// 安装阶段缓存资源
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('缓存已打开');
        return cache.addAll(urlsToCache);
      })
  );
});

// 拦截请求并从缓存中提供资源
self.addEventListener('fetch', event => {
  event.respondWith(
    caches.match(event.request)
      .then(response => {
        // 缓存命中，直接返回
        if (response) {
          return response;
        }
        
        // 缓存未命中，发起网络请求
        return fetch(event.request)
          .then(response => {
            // 检查是否有效响应
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }
            
            // 克隆响应（因为响应流只能使用一次）
            const responseToCache = response.clone();
            
            // 将新资源添加到缓存
            caches.open(CACHE_NAME)
              .then(cache => {
                cache.put(event.request, responseToCache);
              });
              
            return response;
          });
      })
  );
});

// 清理旧缓存
self.addEventListener('activate', event => {
  const cacheWhitelist = [CACHE_NAME];
  
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            // 删除不在白名单中的缓存
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});
```

### 常见缓存策略

1. **仅缓存优先**：先查缓存，没有则网络请求但不缓存结果
2. **缓存优先，网络备用**：先查缓存，没有则网络请求并缓存
3. **网络优先，缓存备用**：先尝试网络请求，失败则使用缓存
4. **仅网络**：只使用网络请求，不使用缓存
5. **缓存后备网络**：同时发起缓存和网络请求，先返回缓存结果，网络请求成功后更新缓存

```js
// 网络优先，缓存备用策略
self.addEventListener('fetch', event => {
  event.respondWith(
    fetch(event.request)
      .then(response => {
        // 网络请求成功，更新缓存
        const responseClone = response.clone();
        caches.open(CACHE_NAME).then(cache => {
          cache.put(event.request, responseClone);
        });
        return response;
      })
      .catch(() => {
        // 网络请求失败，使用缓存
        return caches.match(event.request);
      })
  );
});
```

## 内存缓存

内存缓存用于存储运行时频繁使用的数据，提高应用响应速度。

### 简单内存缓存实现

```js
class MemoryCache {
  constructor(maxSize = 100) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }
  
  get(key) {
    const item = this.cache.get(key);
    if (!item) return null;
    
    // 检查是否过期
    if (item.expiry && item.expiry < Date.now()) {
      this.cache.delete(key);
      return null;
    }
    
    return item.value;
  }
  
  set(key, value, ttlSeconds = 0) {
    // 如果缓存已满，删除最早添加的项
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    
    const expiry = ttlSeconds > 0 ? Date.now() + (ttlSeconds * 1000) : 0;
    this.cache.set(key, { value, expiry });
    return true;
  }
  
  delete(key) {
    return this.cache.delete(key);
  }
  
  clear() {
    this.cache.clear();
  }
}

// 使用示例
const cache = new MemoryCache(50);
cache.set('user:123', { name: 'Alice', role: 'admin' }, 300); // 缓存5分钟
const user = cache.get('user:123');
```

### 使用memoization优化计算

```js
// 简单的memoize函数
function memoize(fn) {
  const cache = new Map();
  
  return function(...args) {
    const key = JSON.stringify(args);
    if (cache.has(key)) {
      return cache.get(key);
    }
    
    const result = fn.apply(this, args);
    cache.set(key, result);
    return result;
  };
}

// 使用示例 - 斐波那契数列
function fibonacci(n) {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}

const memoizedFibonacci = memoize(function(n) {
  if (n <= 1) return n;
  return memoizedFibonacci(n - 1) + memoizedFibonacci(n - 2);
});

// 性能比较
console.time('Regular');
fibonacci(35);
console.timeEnd('Regular');

console.time('Memoized');
memoizedFibonacci(35);
console.timeEnd('Memoized');
```

## 本地存储缓存

浏览器本地存储可以持久化存储数据，即使在页面刷新或浏览器重启后仍然可用。

### LocalStorage

```js
// 存储数据
localStorage.setItem('user', JSON.stringify({
  id: 123,
  name: 'Alice',
  lastLogin: new Date().toISOString()
}));

// 读取数据
const user = JSON.parse(localStorage.getItem('user'));

// 删除数据
localStorage.removeItem('user');

// 清空所有数据
localStorage.clear();
```

### 封装带过期时间的LocalStorage

```js
const storageCache = {
  set(key, value, ttlSeconds = 0) {
    const item = {
      value,
      expiry: ttlSeconds > 0 ? Date.now() + (ttlSeconds * 1000) : 0
    };
    localStorage.setItem(key, JSON.stringify(item));
  },
  
  get(key) {
    const itemStr = localStorage.getItem(key);
    if (!itemStr) return null;
    
    const item = JSON.parse(itemStr);
    if (item.expiry && item.expiry < Date.now()) {
      localStorage.removeItem(key);
      return null;
    }
    
    return item.value;
  },
  
  remove(key) {
    localStorage.removeItem(key);
  },
  
  clear() {
    localStorage.clear();
  }
};

// 使用示例
storageCache.set('userPreferences', { theme: 'dark', fontSize: 'medium' }, 86400); // 缓存1天
const prefs = storageCache.get('userPreferences');
```

### IndexedDB

对于更复杂的客户端存储需求，可以使用IndexedDB：

```js
// 打开数据库
const request = indexedDB.open('MyDatabase', 1);

// 创建对象存储
request.onupgradeneeded = event => {
  const db = event.target.result;
  const store = db.createObjectStore('users', { keyPath: 'id' });
  store.createIndex('name', 'name', { unique: false });
};

// 添加数据
request.onsuccess = event => {
  const db = event.target.result;
  const transaction = db.transaction(['users'], 'readwrite');
  const store = transaction.objectStore('users');
  
  store.add({
    id: 1,
    name: 'Alice',
    email: 'alice@example.com',
    lastVisit: Date.now()
  });
  
  // 查询数据
  const getRequest = store.get(1);
  getRequest.onsuccess = () => {
    console.log(getRequest.result);
  };
  
  transaction.oncomplete = () => {
    db.close();
  };
};
```

## CDN缓存

内容分发网络(CDN)可以将静态资源缓存在全球各地的边缘节点，减少网络延迟。

### CDN配置最佳实践

1. **使用长期缓存**：为静态资源设置长期缓存，并在文件名中包含内容哈希
2. **设置正确的缓存控制头**：根据资源类型设置适当的Cache-Control头
3. **启用压缩**：配置Gzip或Brotli压缩
4. **使用HTTP/2或HTTP/3**：利用多路复用减少连接开销

```html
<!-- 使用CDN加载资源 -->
<link rel="stylesheet" href="https://cdn.example.com/styles/main.a1b2c3d4.css">
<script src="https://cdn.example.com/scripts/app.e5f6g7h8.js" defer></script>
```

## 缓存失效策略

合理的缓存失效策略可以确保用户获取最新内容，同时最大化缓存效益。

### 基于内容的缓存失效

在文件名或URL中包含内容哈希，当内容变化时自动失效缓存：

```html
<!-- 构建工具自动生成带哈希的文件名 -->
<link rel="stylesheet" href="/styles/main.a1b2c3d4.css">
<script src="/scripts/app.e5f6g7h8.js"></script>
```

### 版本化URL

在URL中包含版本号：

```html
<link rel="stylesheet" href="/styles/main.css?v=1.0.5">
<script src="/scripts/app.js?v=1.0.5"></script>
```

### 手动清除Service Worker缓存

```js
// 在应用更新时清除所有缓存
function clearCache() {
  if ('caches' in window) {
    caches.keys().then(cacheNames => {
      cacheNames.forEach(cacheName => {
        caches.delete(cacheName);
      });
    });
  }
}

// 注册新版本Service Worker时清除缓存
navigator.serviceWorker.register('/sw.js?v=2')
  .then(registration => {
    if (registration.active) {
      clearCache();
    }
  });
```

## 最佳实践

### 缓存策略决策流程

1. **不变的静态资源**：使用强缓存(Cache-Control: max-age=31536000, immutable)
2. **可能变化的静态资源**：使用协商缓存(ETag/If-None-Match)
3. **频繁变化的API数据**：使用短期缓存或不缓存，考虑使用内存缓存
4. **离线功能**：使用Service Worker缓存关键资源

### 缓存层次结构

从快到慢的缓存层次：

1. **内存缓存**：运行时数据，页面刷新后丢失
2. **Service Worker缓存**：持久化资源，可离线使用
3. **HTTP缓存**：浏览器缓存，受HTTP头控制
4. **CDN缓存**：边缘节点缓存，减少网络延迟
5. **服务器缓存**：减轻数据库负载

### 监控缓存效果

```js
// 监控资源加载性能
function monitorResourceCache() {
  const resources = performance.getEntriesByType('resource');
  
  const cacheStats = {
    fromCache: 0,
    fromNetwork: 0,
    totalSize: 0
  };
  
  resources.forEach(resource => {
    // transferSize为0表示从缓存加载
    if (resource.transferSize === 0 && resource.decodedBodySize > 0) {
      cacheStats.fromCache++;
    } else {
      cacheStats.fromNetwork++;
      cacheStats.totalSize += resource.transferSize;
    }
  });
  
  console.log(`从缓存加载: ${cacheStats.fromCache}个资源`);
  console.log(`从网络加载: ${cacheStats.fromNetwork}个资源`);
  console.log(`网络传输总大小: ${Math.round(cacheStats.totalSize / 1024)}KB`);
  
  return cacheStats;
}

// 页面加载完成后监控
window.addEventListener('load', () => {
  setTimeout(monitorResourceCache, 0);
});
```

## 参考资源

- [HTTP缓存 - MDN](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Caching)
- [Service Worker API - MDN](https://developer.mozilla.org/zh-CN/docs/Web/API/Service_Worker_API)
- [Web存储 - MDN](https://developer.mozilla.org/zh-CN/docs/Web/API/Web_Storage_API)
- [IndexedDB API - MDN](https://developer.mozilla.org/zh-CN/docs/Web/API/IndexedDB_API)
- [Workbox - Google的Service Worker工具库](https://developers.google.com/web/tools/workbox)
 