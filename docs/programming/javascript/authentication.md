# 身份验证与授权

在任何需要用户登录的系统中，**身份验证 (Authentication)** 和 **授权 (Authorization)** 都是安全的核心基石。它们是两个独立但紧密相关的概念。

-   **身份验证 (Authentication)**: 验证用户的身份，回答"你是谁？"这个问题。这通常通过用户名和密码、指纹、或第三方登录来完成。
-   **授权 (Authorization)**: 验证用户是否有权执行特定操作或访问特定资源，回答"你被允许做什么？"这个问题。这在用户成功登录之后进行。

## 1. 核心基石：安全的密码存储

在讨论任何认证方案之前，必须先解决最根本的问题：如何安全地存储用户密码。**绝不、绝不、绝不能以明文形式存储密码。** 一旦数据库泄露，所有用户的账户都将面临风险。

正确的做法是使用经过充分验证的单向哈希算法，如 **bcrypt**。

-   **哈希 (Hashing)**: 将密码转换为一个固定长度、不可逆的字符串。
-   **加盐 (Salting)**: 在哈希前，为每个密码附加一个随机生成的字符串（盐）。这可以有效抵御彩虹表攻击，即使两个用户设置了相同的密码，它们存储在数据库中的哈希值也是不同的。

```bash
# 安装 bcrypt
npm install bcrypt
```

```javascript
import bcrypt from 'bcrypt';

const saltRounds = 10; // "成本因子"，数值越高，哈希越慢，越安全

// 1. 在用户注册时：对密码进行哈希处理
const plainPassword = 'password123';
const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
// 将 hashedPassword 存储到数据库

// 2. 在用户登录时：比较明文密码和哈希值
const isMatch = await bcrypt.compare(plainPassword, hashedPassword);
// isMatch 为 true 则密码正确
```

---

## 2. JWT (JSON Web Token) 无状态认证

对于现代 Web 应用，特别是前后端分离的 SPA (单页应用) 和移动应用，基于 Token 的无状态认证是主流方案。其中，**JWT (JSON Web Token)** 是最流行的标准。

### (1) JWT 认证流程

1.  **登录**: 用户提供凭证（如用户名、密码）。
2.  **验证**: 服务器验证凭证，如果成功...
3.  **签发令牌**: 服务器生成一个 **访问令牌 (Access Token)** 和一个 **刷新令牌 (Refresh Token)**，并将它们返回给客户端。
4.  **访问受保护资源**: 客户端在后续请求的 `Authorization` 头中携带访问令牌 (`Bearer <token>`)。
5.  **令牌验证**: 服务器的保护中间件验证访问令牌的签名和有效期。
6.  **令牌刷新**: 访问令牌通常有效期很短（如15分钟）。当它过期后，客户端使用长期有效的刷新令牌，向服务器请求一个新的访问令牌，从而避免用户频繁重新登录。

### (2) 令牌存储策略

-   **访问令牌 (Access Token)**: 应存储在客户端的内存中（例如，JavaScript 变量）。它不应存储在 `localStorage` 或 `sessionStorage` 中，以防止 XSS 攻击。
-   **刷新令牌 (Refresh Token)**: 应该安全地存储，通常是在一个 `httpOnly`、`secure` 的 Cookie 中。这可以防止 JavaScript 读取它，同时保证它只在 HTTPS 连接中传输。

### (3) 使用 Express 实现 JWT 认证 (含刷新令牌)

这个示例将构建一个完整的、结构化的认证 API。

**依赖安装**
```bash
npm install express jsonwebtoken bcrypt cookie-parser
```

**项目结构**
```
/auth-api
└── src/
    ├── app.js
    ├── server.js
    ├── routes/
    │   └── auth.routes.js
    ├── controllers/
    │   └── auth.controller.js
    ├── services/
    │   └── token.service.js
    └── middlewares/
        └── auth.middleware.js
```

**`services/token.service.js`**
```javascript
import jwt from 'jsonwebtoken';

// 强烈建议将密钥存储在环境变量中
const ACCESS_TOKEN_SECRET = 'your-access-token-secret';
const REFRESH_TOKEN_SECRET = 'your-refresh-token-secret';

export const tokenService = {
  generateTokens: (payload) => {
    const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
    return { accessToken, refreshToken };
  },

  verifyAccessToken: (token) => {
    try {
      return jwt.verify(token, ACCESS_TOKEN_SECRET);
    } catch (e) {
      return null;
    }
  },
  
  verifyRefreshToken: (token) => {
    try {
      return jwt.verify(token, REFRESH_TOKEN_SECRET);
    } catch(e) {
      return null;
    }
  }
};
```

**`middlewares/auth.middleware.js` (授权和角色验证)**
```javascript
import { tokenService } from '../services/token.service.js';

export const authMiddleware = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ message: 'Access token is required' });
  }

  const userData = tokenService.verifyAccessToken(token);
  if (!userData) {
    return res.status(403).json({ message: 'Invalid or expired access token' });
  }

  req.user = userData;
  next();
};

// 角色授权中间件
export const authorize = (roles = []) => {
  if (typeof roles === 'string') {
    roles = [roles];
  }

  return (req, res, next) => {
    if (!roles.length || roles.includes(req.user.role)) {
      return next();
    }
    res.status(403).json({ message: 'Forbidden: Insufficient permissions' });
  };
};
```

**`controllers/auth.controller.js`**
```javascript
import { tokenService } from '../services/token.service.js';
// 模拟数据库
let users = []; // { id, username, password, role }
let refreshTokens = []; // 存储有效的 refresh tokens

export const authController = {
  // ... (register, login 实现)
  
  login: async (req, res) => {
    // ... (在数据库中查找用户并用 bcrypt.compare 验证密码)
    const user = { id: 1, username: 'test', role: 'user' }; // 假设验证成功

    const tokens = tokenService.generateTokens({ id: user.id, role: user.role });
    refreshTokens.push(tokens.refreshToken);

    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.json({ accessToken: tokens.accessToken });
  },
  
  refreshToken: (req, res) => {
    const { refreshToken } = req.cookies;
    if (!refreshToken || !refreshTokens.includes(refreshToken)) {
      return res.status(403).json({ message: 'Refresh token is invalid' });
    }

    const userData = tokenService.verifyRefreshToken(refreshToken);
    if (!userData) {
      return res.status(403).json({ message: 'Refresh token verification failed' });
    }
    
    // 验证通过，签发新的令牌
    const tokens = tokenService.generateTokens({ id: userData.id, role: userData.role });
    
    res.json({ accessToken: tokens.accessToken });
  },

  logout: (req, res) => {
    const { refreshToken } = req.cookies;
    refreshTokens = refreshTokens.filter(t => t !== refreshToken);
    res.clearCookie('refreshToken');
    res.status(200).json({ message: 'Logged out successfully' });
  },
  
  getProfile: (req, res) => {
    // req.user 来自 authMiddleware
    res.json({ message: `Welcome user ${req.user.id}`, user: req.user });
  }
};
```

**`routes/auth.routes.js`**
```javascript
import { Router } from 'express';
import { authController } from '../controllers/auth.controller.js';
import { authMiddleware, authorize } from '../middlewares/auth.middleware.js';

const router = Router();

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/token', authController.refreshToken);
router.post('/logout', authController.logout);

// 受保护的路由
router.get('/profile', authMiddleware, authController.getProfile);

// 仅限管理员访问的路由
router.get('/admin', authMiddleware, authorize('admin'), (req, res) => {
  res.json({ message: 'Welcome to the admin panel!' });
});

export default router;
```
*(注: 完整的 `app.js` 和 `server.js` 设置可参考前面章节的结构)*

---

## 3. OAuth 2.0 与第三方登录

OAuth 2.0 是一个 **授权框架**，它允许第三方应用在用户授权下，获取用户在特定服务商（如 Google, GitHub）上的有限资源访问权限，而无需获取用户的密码。

这正是 "使用 Google 登录" 功能背后的机制。

在 Node.js 生态中，实现 OAuth 2.0 通常使用 [Passport.js](http://www.passportjs.org/) 库。它通过各种 "策略" (Strategies) 支持超过500种认证方式。

**OAuth 2.0 流程简述:**
1.  用户点击 "使用 Google 登录"。
2.  应用将用户重定向到 Google 的授权页面。
3.  用户在 Google 页面上同意授权。
4.  Google 将用户重定向回应用，并附带一个 **授权码 (Authorization Code)**。
5.  应用的后端使用此授权码，向 Google 请求一个 **访问令牌**。
6.  应用使用该访问令牌，向 Google API 请求用户信息（如姓名、邮箱）。
7.  应用根据获取的用户信息，在自己的数据库中创建或查找用户，并为该用户创建会话或签发 JWT。

由于其复杂性，这里不提供完整代码，但强烈建议在需要集成第三方登录时深入研究 Passport.js。

## 4. 总结

-   **密码安全是基础**: 始终使用 `bcrypt` 哈希和加盐密码。
-   **JWT 是现代标准**: 对于 API 和 SPA，JWT 提供了无状态、可扩展的认证方案。务必使用 **访问令牌 + 刷新令牌** 的组合，并安全地存储它们。
-   **授权是关键**: 使用中间件实现灵活的基于角色的访问控制 (RBAC)。
-   **OAuth 用于委托**: 当你需要访问用户在其他平台上的数据时，使用 OAuth 2.0。 