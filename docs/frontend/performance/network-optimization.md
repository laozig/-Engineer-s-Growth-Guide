# 网络优化

网络性能是前端性能优化的关键环节，直接影响用户体验和转化率。本文档介绍如何优化HTTP连接、减少网络延迟并提高资源传输效率。

## 目录

- [HTTP协议优化](#http协议优化)
- [请求优化](#请求优化)
- [响应优化](#响应优化)
- [DNS优化](#dns优化)
- [TCP优化](#tcp优化)
- [TLS/SSL优化](#tlsssl优化)
- [网络监控与分析](#网络监控与分析)
- [最佳实践](#最佳实践)

## HTTP协议优化

### HTTP/2

HTTP/2相比HTTP/1.1有显著性能提升：

```nginx
# Nginx配置HTTP/2
server {
    listen 443 ssl http2;
    server_name example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    # 其他配置...
}
```

HTTP/2主要优势：

1. **多路复用**：在单个TCP连接上并行处理多个请求
2. **服务器推送**：主动推送关联资源
3. **头部压缩**：减少请求头大小
4. **二进制格式**：更高效的解析
5. **优先级和依赖**：资源加载优先级控制

### HTTP/3 (QUIC)

基于UDP的新一代HTTP协议：

```nginx
# Nginx配置HTTP/3 (需要特定版本支持)
server {
    listen 443 ssl http2;
    listen 443 quic;
    http3 on;
    
    # 通知客户端支持HTTP/3
    add_header Alt-Svc 'h3=":443"; ma=86400';
    
    # 其他配置...
}
```

HTTP/3优势：

1. **消除队头阻塞**：独立数据流不会相互影响
2. **快速连接建立**：减少握手延迟
3. **改进的拥塞控制**：更好的网络适应性
4. **连接迁移**：网络切换时保持连接

### 服务器推送

HTTP/2服务器推送可以主动发送关键资源：

```html
<!-- 在HTML中指示服务器推送资源 -->
<link rel="stylesheet" href="/styles.css">
<link rel="preload" href="/scripts.js" as="script">
```

```nginx
# Nginx服务器推送配置
location / {
    http2_push /styles.css;
    http2_push /scripts.js;
}
```

## 请求优化

### 减少请求数量

合并资源减少HTTP请求：

```js
// Webpack配置示例 - 合并JS
module.exports = {
  entry: './src/index.js',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist')
  },
  optimization: {
    splitChunks: {
      chunks: 'all',
      cacheGroups: {
        vendor: {
          test: /[\\/]node_modules[\\/]/,
          name: 'vendors',
          chunks: 'all'
        }
      }
    }
  }
};
```

### 资源提示

使用资源提示优化加载顺序：

```html
<!-- DNS预解析 -->
<link rel="dns-prefetch" href="//fonts.googleapis.com">

<!-- 预连接 -->
<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>

<!-- 预加载关键资源 -->
<link rel="preload" href="/fonts/roboto.woff2" as="font" type="font/woff2" crossorigin>

<!-- 预获取可能需要的资源 -->
<link rel="prefetch" href="/js/non-critical.js">

<!-- 预渲染 -->
<link rel="prerender" href="https://example.com/next-page">
```

### 批处理API请求

合并多个API请求减少网络往返：

```js
// 不推荐 - 多个独立请求
async function fetchUserData(userId) {
  const profile = await fetch(`/api/profile/${userId}`).then(r => r.json());
  const posts = await fetch(`/api/posts?userId=${userId}`).then(r => r.json());
  const followers = await fetch(`/api/followers/${userId}`).then(r => r.json());
  
  return { profile, posts, followers };
}

// 推荐 - 批处理请求
async function fetchUserDataBatch(userId) {
  return fetch(`/api/user-data-batch/${userId}`)
    .then(r => r.json());
}

// 后端实现
app.get('/api/user-data-batch/:userId', async (req, res) => {
  const userId = req.params.userId;
  const [profile, posts, followers] = await Promise.all([
    getProfile(userId),
    getPosts(userId),
    getFollowers(userId)
  ]);
  
  res.json({ profile, posts, followers });
});
```

### GraphQL

使用GraphQL减少过度获取和请求数量：

```js
// 客户端查询
const query = `
  query UserData($userId: ID!) {
    user(id: $userId) {
      id
      name
      email
      posts {
        id
        title
        summary
      }
      followers {
        id
        name
      }
    }
  }
`;

fetch('/graphql', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    query,
    variables: { userId: '123' }
  })
}).then(r => r.json());
```

## 响应优化

### 压缩

启用Gzip或Brotli压缩：

```nginx
# Nginx配置Gzip
gzip on;
gzip_comp_level 6;
gzip_min_length 256;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml text/javascript;

# Nginx配置Brotli (需要安装模块)
brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/json application/javascript text/xml application/xml text/javascript;
```

```js
// Express中启用压缩
const compression = require('compression');
app.use(compression());
```

### 响应流

使用流式传输大型响应：

```js
// Node.js流式传输
const fs = require('fs');

app.get('/large-file', (req, res) => {
  const fileStream = fs.createReadStream('large-file.json');
  fileStream.pipe(res);
});

// 流式API响应
app.get('/api/large-data', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.write('{"items":[');
  
  let first = true;
  const processItems = (items) => {
    for (const item of items) {
      res.write(`${first ? '' : ','} ${JSON.stringify(item)}`);
      first = false;
    }
  };
  
  // 分批处理数据
  processItems(getFirstBatch());
  processItems(getSecondBatch());
  // ...
  
  res.write(']}');
  res.end();
});
```

## DNS优化

### DNS预解析

提前解析将要使用的域名：

```html
<!-- 预解析关键域名 -->
<link rel="dns-prefetch" href="//api.example.com">
<link rel="dns-prefetch" href="//cdn.example.com">
<link rel="dns-prefetch" href="//fonts.googleapis.com">
```

### 减少域名数量

减少不同域名可以减少DNS查询：

```html
<!-- 不推荐 - 使用多个域名 -->
<link rel="stylesheet" href="https://styles.example.com/main.css">
<script src="https://scripts.example.com/app.js"></script>
<img src="https://images.example.com/logo.png">

<!-- 推荐 - 使用统一域名 -->
<link rel="stylesheet" href="https://cdn.example.com/styles/main.css">
<script src="https://cdn.example.com/scripts/app.js"></script>
<img src="https://cdn.example.com/images/logo.png">
```

## TCP优化

### 连接复用

使用持久连接减少TCP握手开销：

```nginx
# Nginx配置持久连接
http {
    keepalive_timeout 65;
    keepalive_requests 100;
}
```

```js
// Node.js HTTP客户端保持连接
const http = require('http');
const agent = new http.Agent({ keepAlive: true });

http.get({
  hostname: 'example.com',
  path: '/',
  agent: agent
}, (res) => {
  // 处理响应
});
```

### TCP Fast Open

减少TCP连接建立时间：

```nginx
# 在Linux系统上启用TCP Fast Open
# 编辑/etc/sysctl.conf
# net.ipv4.tcp_fastopen = 3

# Nginx配置
http {
    tcp_fastopen on;
}
```

## TLS/SSL优化

### OCSP装订

减少SSL握手时间：

```nginx
# Nginx配置OCSP装订
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/ca.pem;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
```

### TLS会话恢复

减少重复连接的握手开销：

```nginx
# Nginx配置TLS会话恢复
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets on;
```

## 网络监控与分析

### Resource Timing API

测量资源加载性能：

```js
function analyzeNetworkPerformance() {
  const resources = performance.getEntriesByType('resource');
  
  resources.forEach(resource => {
    console.log(`资源: ${resource.name}`);
    console.log(`DNS查询时间: ${resource.domainLookupEnd - resource.domainLookupStart}ms`);
    console.log(`TCP连接时间: ${resource.connectEnd - resource.connectStart}ms`);
    console.log(`TLS握手时间: ${resource.secureConnectionStart ? (resource.connectEnd - resource.secureConnectionStart) : 0}ms`);
    console.log(`请求时间: ${resource.responseStart - resource.requestStart}ms`);
    console.log(`响应时间: ${resource.responseEnd - resource.responseStart}ms`);
    console.log(`总加载时间: ${resource.duration}ms`);
    console.log(`传输大小: ${resource.transferSize} bytes`);
    console.log(`-----------------------`);
  });
}

window.addEventListener('load', analyzeNetworkPerformance);
```

### 网络信息API

根据网络状况调整应用行为：

```js
if ('connection' in navigator) {
  const connection = navigator.connection;
  
  // 监听网络类型变化
  connection.addEventListener('change', () => {
    updateForNetworkChange(connection);
  });
  
  function updateForNetworkChange(connection) {
    const networkType = connection.effectiveType; // 4g, 3g, 2g, slow-2g
    const saveData = connection.saveData;
    const downlink = connection.downlink; // Mbps
    const rtt = connection.rtt; // ms
    
    console.log(`网络类型: ${networkType}`);
    console.log(`省流模式: ${saveData}`);
    console.log(`下行速度: ${downlink} Mbps`);
    console.log(`往返时间: ${rtt} ms`);
    
    // 根据网络状况调整体验
    if (networkType === '4g') {
      loadHighQualityAssets();
    } else {
      loadLowQualityAssets();
    }
    
    if (saveData) {
      disableNonEssentialRequests();
    }
  }
  
  // 初始检查
  updateForNetworkChange(connection);
}
```

## 最佳实践

### 网络优化清单

1. **升级到HTTP/2或HTTP/3**：利用多路复用和头部压缩
2. **启用压缩**：对文本资源使用Gzip或Brotli压缩
3. **减少请求数量**：合并资源、使用CSS Sprites、内联小资源
4. **优化TLS**：配置OCSP装订、会话恢复和现代密码套件
5. **使用CDN**：将静态资源分发到离用户更近的位置
6. **预连接关键域名**：使用dns-prefetch和preconnect
7. **批处理API请求**：减少网络往返次数
8. **启用持久连接**：复用TCP连接
9. **优化DNS解析**：减少不同域名数量
10. **根据网络条件调整**：使用Network Information API适配不同网络

### 网络性能预算

设定网络性能目标：

```js
const NETWORK_BUDGET = {
  // 请求数量预算
  requests: {
    total: 50,
    js: 15,
    css: 5,
    images: 20,
    fonts: 5,
    other: 5
  },
  
  // 传输大小预算 (KB)
  size: {
    total: 1000,
    js: 300,
    css: 100,
    images: 500,
    fonts: 100,
    other: 100
  },
  
  // 时间预算 (ms)
  timing: {
    dns: 50,
    connection: 100,
    ttfb: 200,
    download: 300
  }
};

// 检查是否超出预算
function checkNetworkBudget() {
  const resources = performance.getEntriesByType('resource');
  const stats = {
    requests: {
      total: resources.length,
      js: resources.filter(r => r.initiatorType === 'script').length,
      css: resources.filter(r => r.initiatorType === 'css').length,
      images: resources.filter(r => r.initiatorType === 'img').length,
      fonts: resources.filter(r => r.name.match(/\.(woff2?|ttf|otf|eot)/)).length,
      other: resources.filter(r => !['script', 'css', 'img'].includes(r.initiatorType) && !r.name.match(/\.(woff2?|ttf|otf|eot)/)).length
    },
    
    size: {
      total: resources.reduce((sum, r) => sum + r.transferSize, 0) / 1024,
      js: resources.filter(r => r.initiatorType === 'script').reduce((sum, r) => sum + r.transferSize, 0) / 1024,
      css: resources.filter(r => r.initiatorType === 'css').reduce((sum, r) => sum + r.transferSize, 0) / 1024,
      images: resources.filter(r => r.initiatorType === 'img').reduce((sum, r) => sum + r.transferSize, 0) / 1024,
      fonts: resources.filter(r => r.name.match(/\.(woff2?|ttf|otf|eot)/)).reduce((sum, r) => sum + r.transferSize, 0) / 1024,
      other: resources.filter(r => !['script', 'css', 'img'].includes(r.initiatorType) && !r.name.match(/\.(woff2?|ttf|otf|eot)/)).reduce((sum, r) => sum + r.transferSize, 0) / 1024
    }
  };
  
  // 检查是否超出预算
  const violations = [];
  
  // 检查请求数量
  Object.keys(NETWORK_BUDGET.requests).forEach(key => {
    if (stats.requests[key] > NETWORK_BUDGET.requests[key]) {
      violations.push({
        type: 'requests',
        category: key,
        budget: NETWORK_BUDGET.requests[key],
        actual: stats.requests[key]
      });
    }
  });
  
  // 检查传输大小
  Object.keys(NETWORK_BUDGET.size).forEach(key => {
    if (stats.size[key] > NETWORK_BUDGET.size[key]) {
      violations.push({
        type: 'size',
        category: key,
        budget: NETWORK_BUDGET.size[key],
        actual: Math.round(stats.size[key])
      });
    }
  });
  
  return {
    stats,
    violations,
    passedBudget: violations.length === 0
  };
}

// 页面加载完成后检查
window.addEventListener('load', () => {
  setTimeout(() => {
    const result = checkNetworkBudget();
    console.log('网络性能预算检查结果:', result);
    
    if (result.violations.length > 0) {
      console.warn('超出网络性能预算:', result.violations);
    }
  }, 0);
});
```

## 参考资源

- [HTTP/2 - MDN](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/HTTP2)
- [HTTP/3 - MDN](https://developer.mozilla.org/zh-CN/docs/Glossary/HTTP_3)
- [Resource Timing API - MDN](https://developer.mozilla.org/zh-CN/docs/Web/API/Resource_Timing_API)
- [Network Information API - MDN](https://developer.mozilla.org/zh-CN/docs/Web/API/Network_Information_API)
- [Web性能优化 - web.dev](https://web.dev/fast/)
