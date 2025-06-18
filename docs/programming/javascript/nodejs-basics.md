# Node.js 核心基础入门指南

<div align="center">
  <img src="../../../assets/programming/nodejs-logo.png" alt="Node.js Logo" width="250">
</div>

> Node.js 不是一门新的语言，而是一个让 JavaScript "挣脱"浏览器束缚、在服务器端运行的强大环境。它以其独特的非阻塞、事件驱动模型，成为构建高性能网络应用（如API服务、实时应用）的理想选择。本指南将带您深入理解Node.js的核心概念，并掌握其实际应用。

## 目录

1.  [**Node.js 是什么？为什么选择它？**](#1-nodejs-是什么为什么选择它)
2.  [**你的第一个 Node.js 应用**](#2-你的第一个-nodejs-应用)
3.  [**模块系统：代码的组织方式**](#3-模块系统代码的组织方式)
    -   [现代标准：ES Modules (`import`/`export`)](#现代标准es-modules-importexport)
    -   [传统方式：CommonJS (`require`/`module.exports`)](#传统方式commonjs-requiremoduleexports)
4.  [**NPM：Node.js 的包管理器与生态**](#4-npmnodejs-的包管理器与生态)
    -   [理解 `package.json`](#理解-packagejson)
    -   [强大的 `npm scripts`](#强大的-npm-scripts)
    -   [`npx`：运行包命令的利器](#npx运行包命令的利器)
5.  [**核心API模块实战**](#5-核心api模块实战)
    -   [`path`：处理文件路径](#path处理文件路径)
    -   [`fs` (File System)：读写文件](#fs-file-system读写文件)
    -   [`http`：创建你的第一个Web服务器](#http创建你的第一个web服务器)
6.  [**Node.js 的心脏：事件循环与异步I/O**](#6-nodejs-的心脏事件循环与异步io)
    -   [一个生动的比喻](#一个生动的比喻)
    -   [深入事件驱动编程：`EventEmitter`](#深入事件驱动编程eventemitter)

---

## 1. Node.js 是什么？为什么选择它？

想象一个餐厅只有一个服务员（**单线程**），但他非常高效。当一个客人点了一道耗时很长的菜（如烤全羊，这是一个**I/O密集型任务**），服务员不会站在原地等待，而是把订单交给厨房（**底层系统**），然后立即去为其他客人点单或上菜（**处理其他请求**）。当厨房把菜做好后，会通知服务员（**回调**），服务员再把菜端给客人。

这就是Node.js的工作模式——**非阻塞、事件驱动的I/O**。它使得Node.js在处理大量并发连接时表现出色，特别适合：
-   **API服务器**：为前端应用、移动应用提供数据接口。
-   **实时应用**：如在线聊天、协作工具、游戏服务器。
-   **微服务**：构建小而快的独立服务。
-   **构建工具**：如 Webpack, Vite 等都基于Node.js构建。

## 2. 你的第一个 Node.js 应用

1.  创建一个名为 `app.js` 的文件。
2.  写入以下代码：
    ```javascript
    const message = "Hello, Node.js!";
    console.log(message);
    ```
3.  在终端中运行它：
    ```bash
    node app.js
    ```
4.  你将会在终端看到输出：`Hello, Node.js!`。恭喜！

## 3. 模块系统：代码的组织方式

模块化允许我们将复杂的程序拆分成小的、可复用的文件。

### 现代标准：ES Modules (`import`/`export`)
这是JavaScript的官方标准，也是现代Node.js项目推荐的使用方式。

1.  在项目根目录创建一个 `package.json` 文件，并添加 `"type": "module"`。
    ```bash
    npm init -y
    # 然后在 package.json 中添加 "type": "module"
    ```
2.  创建模块和主文件：
    -   **`math.js`**
        ```javascript
        export function add(a, b) {
          return a + b;
        }
        ```
    -   **`app.js`**
        ```javascript
        import { add } from './math.js'; // 注意需要文件扩展名 .js
        console.log(add(5, 10)); // 15
        ```

### 传统方式：CommonJS (`require`/`module.exports`)
如果你在旧项目中看到 `require()`，那就是CommonJS。
-   **`math.js`**
    ```javascript
    function add(a, b) { return a + b; }
    module.exports = { add };
    ```
-   **`app.js`**
    ```javascript
    const { add } = require('./math');
    console.log(add(5, 10)); // 15
    ```

## 4. NPM：Node.js 的包管理器与生态

NPM (Node Package Manager) 是世界上最大的软件注册表，你可以找到任何你需要的开源包。

### 理解 `package.json`
这个文件是项目的核心配置文件。
-   `dependencies`: 生产环境需要的包（如 Express）。
-   `devDependencies`: 只在开发环境需要的包（如 Nodemon, antd）。
-   `scripts`: 定义可运行的脚本命令。

### 强大的 `npm scripts`
在 `package.json` 的 `scripts` 字段中，你可以定义自己的命令。
```json
"scripts": {
  "start": "node app.js",
  "dev": "nodemon app.js"
}
```
现在，你可以通过 `npm start` 来启动应用，或 `npm run dev` 来以开发模式启动。

### `npx`：运行包命令的利器
`npx` 允许你直接运行一个npm包中的可执行文件，而无需全局或本地安装它。
```bash
# 临时创建一个 React 应用，而无需全局安装 create-react-app
npx create-react-app my-cool-app
```

## 5. 核心API模块实战

### `path`：处理文件路径
`path` 模块帮助我们以跨平台的方式处理文件和目录路径。
```javascript
import path from 'path';

const notesPath = path.join(__dirname, 'files', 'notes.txt');
console.log(notesPath); // 会生成正确的跨平台路径
```

### `fs` (File System)：读写文件
`fs` 模块提供了与文件系统交互的功能。推荐使用其 Promise 版本的API。
```javascript
import fs from 'fs/promises';
import path from 'path';

const filePath = path.join(__dirname, 'example.txt');

async function fileOperations() {
  try {
    // 写入文件
    await fs.writeFile(filePath, 'Hello from fs/promises!');
    // 读取文件
    const data = await fs.readFile(filePath, 'utf8');
    console.log(data); // "Hello from fs/promises!"
    // 追加内容
    await fs.appendFile(filePath, '\nThis is a new line.');
  } catch (err) {
    console.error('Error:', err);
  }
}

fileOperations();
```

### `http`：创建你的第一个Web服务器
```javascript
import http from 'http';

const server = http.createServer((req, res) => {
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('欢迎来到首页！');
  } else if (req.url === '/about') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('关于我们页面');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('404 - 页面未找到');
  }
});

const PORT = 3000;
server.listen(PORT, () => {
  console.log(`服务器正在 http://localhost:${PORT}/ 上运行...`);
});
```
> 保存代码后，运行 `node your-file.js`，然后在浏览器中访问 `http://localhost:3000`。

## 6. Node.js 的心脏：事件循环与异步I/O

### 一个生动的比喻
事件循环就是那个高效的服务员。它不断地检查是否有"事件"发生（比如，客人的新订单、厨房做好的菜、客人结账请求）。它会优先处理那些最快的任务（如倒杯水），并将耗时的任务"外包"出去，然后继续服务。这保证了服务员（主线程）永远不会被"卡住"。

### 深入事件驱动编程：`EventEmitter`
Node.js 中的许多核心对象（如HTTP服务器、流）都是 `EventEmitter` 的实例。它允许你监听和触发自定义事件。
```javascript
import { EventEmitter } from 'events';

const myEmitter = new EventEmitter();

// 监听 'userLogin' 事件
myEmitter.on('userLogin', (username) => {
  console.log(`${username} 刚刚登录了！发送欢迎邮件...`);
});

// 监听另一个事件
myEmitter.on('newUser', (user) => {
  console.log(`新用户注册: ${user.name}, 年龄: ${user.age}`);
});

// 触发事件
myEmitter.emit('userLogin', 'Alice');
myEmitter.emit('newUser', { name: 'Bob', age: 30 });
```
这种模式是构建松耦合、可扩展应用的基础。