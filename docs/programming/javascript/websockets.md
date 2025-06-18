# WebSocket 实时通信

HTTP 协议基于请求-响应模型，客户端发起请求，服务器响应，连接随之关闭。这种模式非常适合传统的网页浏览，但对于需要服务器主动、低延迟地向客户端推送数据的场景，如在线聊天、实时股票报价、多人在线游戏等，则显得力不从心。

为了解决这个问题，**WebSocket** 应运而生。

## 1. 什么是 WebSocket？

WebSocket 是一种在单个 TCP 连接上进行 **全双工 (full-duplex)** 通信的协议。它允许客户端和服务器之间建立持久性连接，并进行双向数据传输。

-   **持久连接**: 不同于 HTTP 的"一次性"请求，WebSocket 连接一旦建立，除非显式关闭，否则会一直保持开放状态。
-   **双向通信**: 服务器可以随时主动向客户端发送数据，客户端也可以随时向服务器发送数据。
-   **低开销**: 连接建立后，数据帧的头部开销非常小（最小仅2字节），大大减少了网络开销。

WebSocket 协议通过一个初始的 HTTP `Upgrade` 请求来建立连接，其 URL 方案为 `ws://` (非加密) 和 `wss://` (TLS加密)。

## 2. 浏览器端 WebSocket API

现代浏览器提供了原生的 `WebSocket` 对象，用于创建和管理 WebSocket 连接。

### (1) 创建与连接

```javascript
// client.js

// 建议使用 wss:// 以保证通信安全
const socket = new WebSocket('wss://api.example.com/chat');
```

### (2) 核心事件处理

```javascript
// client.js

// 1. 当连接成功建立时触发
socket.onopen = (event) => {
  console.log('✅ WebSocket connection established.');
  // 连接成功后，可以向服务器发送消息
  socket.send(JSON.stringify({ type: 'greeting', payload: 'Hello Server!' }));
};

// 2. 当从服务器接收到消息时触发
socket.onmessage = (event) => {
  // event.data 包含服务器发送的数据 (通常是字符串或二进制数据)
  const message = JSON.parse(event.data);
  console.log('📬 Message from server:', message);
  // 在这里根据消息类型更新 UI
};

// 3. 当连接关闭时触发
socket.onclose = (event) => {
  if (event.wasClean) {
    console.log(`🔌 Connection closed cleanly, code=${event.code} reason=${event.reason}`);
  } else {
    // 例如：服务器进程被杀死或网络断开
    console.error('❌ Connection died');
  }
};

// 4. 当发生错误时触发
socket.onerror = (error) => {
  console.error(`💥 WebSocket Error: ${error.message}`);
};
```

### (3) 发送数据与关闭连接

```javascript
// 发送结构化数据
function sendMessage(payload) {
  if (socket.readyState === WebSocket.OPEN) {
    const data = { type: 'chat-message', payload };
    socket.send(JSON.stringify(data));
  }
}

// 主动关闭连接
function closeConnection() {
  socket.close(1000, 'User logged out'); // 1000 表示正常关闭
}
```

---

## 3. Node.js 服务端实现

在 Node.js 中，我们通常不直接操作 TCP 套接字，而是使用成熟的库来处理 WebSocket 协议的复杂性。

### 方案一: `ws` - 轻量高性能的选择

[ws](https://github.com/websockets/ws) 是一个流行、简单、高性能的 WebSocket 库。它严格实现了 WebSocket 协议，不包含额外的抽象层，是追求极致性能和灵活性的首选。

#### 示例：一个简单的多人聊天室

**项目结构**
```
/chat-app
├── server.js
└── client.html
```

**服务端: `server.js`**
```javascript
import { WebSocketServer } from 'ws';
import http from 'http';

// 创建一个基础的 HTTP server
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('WebSocket server is running.');
});

const wss = new WebSocketServer({ server });

console.log('🚀 WebSocket server started on port 8080');

// 广播函数：将消息发送给所有连接的客户端
function broadcast(data) {
  wss.clients.forEach(client => {
    if (client.readyState === client.OPEN) {
      client.send(JSON.stringify(data));
    }
  });
}

wss.on('connection', (ws) => {
  console.log('✨ New client connected');
  
  // 向所有客户端广播新用户加入的消息
  broadcast({ type: 'system', payload: 'A new user has joined the chat.' });

  ws.on('message', (message) => {
    try {
      const parsedMessage = JSON.parse(message);
      console.log('Received message:', parsedMessage);
      // 将收到的聊天消息广播出去
      broadcast({ type: 'chat', payload: parsedMessage.payload });
    } catch (e) {
      console.error('Failed to parse message:', e);
    }
  });

  ws.on('close', () => {
    console.log('👋 Client disconnected');
    // 广播用户离开的消息
    broadcast({ type: 'system', payload: 'A user has left the chat.' });
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });

  // 设置心跳检测，防止连接因不活动而被中间代理断开
  const interval = setInterval(() => {
    if (ws.readyState === ws.OPEN) {
      ws.ping();
    }
  }, 30000); // 每30秒发送一次 ping

  ws.on('pong', () => {
    // console.log('pong received'); // 用于调试
  });
});

server.listen(8080);
```

**客户端: `client.html`**
```html
<!DOCTYPE html>
<html>
<head>
  <title>WebSocket Chat</title>
  <style>
    body { font-family: sans-serif; }
    #messages { list-style-type: none; margin: 0; padding: 0; border: 1px solid #ccc; height: 300px; overflow-y: scroll; }
    #messages li { padding: 8px 12px; }
    #messages li:nth-child(odd) { background: #f0f0f0; }
  </style>
</head>
<body>
  <h1>WebSocket Chat</h1>
  <ul id="messages"></ul>
  <form id="form">
    <input id="input" autocomplete="off" /><button>Send</button>
  </form>

  <script>
    const messages = document.getElementById('messages');
    const form = document.getElementById('form');
    const input = document.getElementById('input');

    const socket = new WebSocket('ws://localhost:8080');

    socket.onopen = () => {
      addMessage('System: Connected to the server.');
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'system') {
        addMessage(`System: ${data.payload}`);
      } else if (data.type === 'chat') {
        addMessage(`Someone: ${data.payload}`);
      }
    };
    
    socket.onclose = () => {
      addMessage('System: Disconnected from server.');
    };

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (input.value) {
        socket.send(JSON.stringify({ type: 'chat', payload: input.value }));
        addMessage(`Me: ${input.value}`);
        input.value = '';
      }
    });

    function addMessage(message) {
      const item = document.createElement('li');
      item.textContent = message;
      messages.appendChild(item);
      messages.scrollTop = messages.scrollHeight;
    }
  </script>
</body>
</html>
```

### 方案二: `Socket.IO` - 功能丰富的实时应用框架

[Socket.IO](https://socket.io/) 是一个在 WebSocket 基础上构建的库，它提供了更多开箱即用的高级功能，极大地简化了实时应用的开发。

**`Socket.IO` vs `ws`**

| 特性 | `ws` (WebSocket) | `Socket.IO` |
|---|---|---|
| **核心** | 严格的 WebSocket 协议实现 | 基于事件的实时框架 |
| **回退机制** | 不支持 | **自动回退**到 HTTP 长轮询 |
| **自动重连** | 不支持 (需手动实现) | **内置自动重连**机制 |
| **广播** | 支持 (需手动遍历客户端) | 提供更丰富的广播和 **Rooms** 功能 |
| **消息格式** | 仅字符串和二进制数据 | 可直接发送任何可序列化的数据结构 |
| **使用场景** | 追求底层控制和极致性能 | 快速构建健壮、功能丰富的实时应用 |

#### 示例：功能增强的聊天室 (使用 Socket.IO)

**服务端: `server-socketio.js`**
```javascript
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// 提供客户端静态文件
app.get('/', (req, res) => {
  res.sendFile(new URL('./client-socketio.html', import.meta.url).pathname);
});

io.on('connection', (socket) => {
  console.log('✨ User connected:', socket.id);

  // 广播新用户加入
  io.emit('system message', 'A new user has joined.');

  // 监听聊天消息
  socket.on('chat message', (msg) => {
    // 广播给除发送者外的所有客户端
    socket.broadcast.emit('chat message', { user: socket.id, msg });
  });
  
  // 监听用户输入状态
  socket.on('typing', () => {
    socket.broadcast.emit('typing', `${socket.id} is typing...`);
  });

  // 监听断开连接
  socket.on('disconnect', () => {
    console.log('👋 User disconnected:', socket.id);
    io.emit('system message', 'A user has left.');
  });
});

server.listen(3000, () => {
  console.log('🚀 Socket.IO server listening on *:3000');
});
```

**客户端: `client-socketio.html`**
```html
<!DOCTYPE html>
<html>
<head>
  <title>Socket.IO Chat</title>
  <!-- 引入 Socket.IO 客户端库 -->
  <script src="/socket.io/socket.io.js"></script>
</head>
<body>
  <!-- ... (HTML 结构与上一个示例类似) ... -->
  <p id="typing-status"></p>

  <script>
    const socket = io(); // 自动连接到提供页面的服务器
    const typingStatus = document.getElementById('typing-status');

    // ... (form, input, messages, addMessage 的定义与上一个示例类似) ...

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (input.value) {
        socket.emit('chat message', input.value);
        addMessage(`Me: ${input.value}`);
        input.value = '';
      }
    });
    
    let typingTimer;
    input.addEventListener('input', () => {
      socket.emit('typing');
      clearTimeout(typingTimer);
      typingTimer = setTimeout(() => {
        typingStatus.textContent = '';
      }, 1000);
    });

    socket.on('chat message', (data) => {
      addMessage(`${data.user.substring(0, 5)}: ${data.msg}`);
    });

    socket.on('system message', (msg) => {
      addMessage(`System: ${msg}`);
    });
    
    socket.on('typing', (msg) => {
      typingStatus.textContent = msg;
      setTimeout(() => { typingStatus.textContent = ''; }, 1000);
    });
  </script>
</body>
</html>
```

## 4. 总结与最佳实践

-   **优先使用 `wss://`**: 始终在生产环境中使用加密的 WebSocket 连接，以防止中间人攻击。
-   **心跳检测**: 对于长时间运行的连接，实现心跳（Ping/Pong）机制是保持连接稳定的关键。
-   **选择合适的工具**:
    -   如果你的需求简单，或需要最大限度地控制协议细节和性能，使用 `ws`。
    -   如果你的应用需要支持旧版浏览器、自动重连、房间管理等复杂功能，`Socket.IO` 是更高效、更健壮的选择。
-   **数据验证**: 永远不要信任来自客户端的任何数据。在服务器端对接收到的所有消息进行严格的格式和内容验证。 