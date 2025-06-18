# 示例项目：全栈博客平台 - 后端 API 开发

在上一章节中，我们规划了项目的蓝图。现在，我们将卷起袖子，一步步地构建博客平台的后端服务。本章将涵盖从初始化项目、连接数据库到实现核心 API 功能的全过程。

## 1. 环境搭建与项目初始化

首先，在你的项目根目录（例如 `fullstack-blog`）下创建 `backend` 文件夹并进入。

```bash
mkdir backend
cd backend
```

### (1) 初始化 Node.js 项目
使用 `pnpm` 初始化一个新的 Node.js 项目，它会创建一个 `package.json` 文件。

```bash
pnpm init
```

### (2) 安装核心依赖
我们需要 Express 来构建服务器，Prisma 作为 ORM，`dotenv` 来管理环境变量，`bcryptjs` 用于密码加密，`jsonwebtoken` 用于生成和验证认证令牌。

```bash
pnpm install express prisma dotenv bcryptjs jsonwebtoken
pnpm install -D @types/express @types/node ts-node nodemon
```

*   **express**: Web 框架。
*   **prisma**: ORM 客户端。
*   **dotenv**: 加载 `.env` 文件中的环境变量。
*   **bcryptjs**: 对用户密码进行哈希加密，确保安全。
*   **jsonwebtoken**: 实现基于 JWT (JSON Web Token) 的身份验证。
*   **@types/express, @types/node**: 为 Express 和 Node.js 提供 TypeScript 类型定义。
*   **ts-node, nodemon**: 用于在开发环境中自动重启和运行 TypeScript 应用。

### (3) 配置开发脚本
打开 `package.json`，在 `scripts` 部分添加一个 `dev` 命令，以便使用 `nodemon` 方便地启动开发服务器。

```json
// package.json
"scripts": {
  "test": "echo \"Error: no test specified\" && exit 1",
  "dev": "nodemon src/index.ts"
},
```

---

## 2. 数据库与 Prisma 设置

### (1) 使用 Docker 启动 PostgreSQL
为了简化开发环境，我们使用 Docker 来运行数据库。在项目根目录下创建一个 `docker-compose.yml` 文件。

```yaml
# docker-compose.yml
version: '3.8'
services:
  postgres:
    image: postgres:14
    restart: always
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
      POSTGRES_DB: blog
    ports:
      - '5432:5432'
    volumes:
      - db_data:/var/lib/postgresql/data

volumes:
  db_data:
```

然后在终端中运行 `docker-compose up -d` 来启动数据库服务。

### (2) 初始化 Prisma
在 `backend` 目录下，运行 Prisma 的初始化命令，它会自动创建一个 `prisma` 目录和 `schema.prisma` 文件，并根据我们的环境配置好 `.env` 文件。

```bash
pnpm prisma init --datasource-provider postgresql
```

### (3) 配置数据库连接
打开新生成的 `.env` 文件，修改 `DATABASE_URL` 以匹配 `docker-compose.yml` 中设置的数据库凭证。

```env
# .env
DATABASE_URL="postgresql://user:password@localhost:5432/blog?schema=public"
```

### (4) 编写数据模型
现在，定义我们的核心数据模型。打开 `prisma/schema.prisma` 并写入以下内容：

```prisma
// prisma/schema.prisma
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id        Int      @id @default(autoincrement())
  email     String   @unique
  name      String?
  password  String
  posts     Post[]
  comments  Comment[]
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model Post {
  id        Int       @id @default(autoincrement())
  title     String
  content   String?
  published Boolean   @default(false)
  author    User      @relation(fields: [authorId], references: [id])
  authorId  Int
  comments  Comment[]
  createdAt DateTime  @default(now())
  updatedAt DateTime  @updatedAt
}

model Comment {
  id        Int      @id @default(autoincrement())
  content   String
  author    User     @relation(fields: [authorId], references: [id])
  authorId  Int
  post      Post     @relation(fields: [postId], references: [id])
  postId    Int
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
```

### (5) 执行数据库迁移
运行以下命令，Prisma 会读取你的数据模型，生成 SQL 迁移文件，并将其应用到数据库中，从而创建相应的表和列。

```bash
pnpm prisma migrate dev --name init
```

### (6) 生成 Prisma Client
最后，生成类型安全的 Prisma Client，我们将在代码中用它来与数据库交互。

```bash
pnpm prisma generate
```

---

## 3. 构建 Express 服务器

### (1) 创建项目结构
根据我们在 `blog-intro.md` 中规划的结构，在 `src` 目录下创建必要的文件夹和文件。

```
/src
├── /config
├── /controllers
├── /middlewares
├── /routes
├── /services
└── index.ts
```

### (2) 实现基础服务器
在 `src/index.ts` 中编写基础的 Express 服务器代码。

```typescript
// src/index.ts
import express from 'express';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json()); // 中间件，用于解析 JSON 请求体

app.get('/', (req, res) => {
  res.send('Hello, Blog API!');
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
```

现在运行 `pnpm dev`，你应该能看到服务器启动的日志。访问 `http://localhost:3000` 会看到 "Hello, Blog API!"。

---

## 4. 核心 API 功能实现

我们将按照"路由 -> 控制器 -> 服务"的分层模式来实现功能。

### (1) 用户认证 (Authentication)

#### 路由 (`src/routes/authRoutes.ts`)
```typescript
import { Router } from 'express';
import { registerUser, loginUser } from '../controllers/authController';

const router = Router();

router.post('/register', registerUser);
router.post('/login', loginUser);

export default router;
```

#### 控制器 (`src/controllers/authController.ts`)
控制器负责处理 HTTP 请求和响应，调用服务层处理业务逻辑。

```typescript
import { Request, Response } from 'express';
import * as authService from '../services/authService';

export const registerUser = async (req: Request, res: Response) => {
  try {
    const { email, password, name } = req.body;
    const user = await authService.register(email, password, name);
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

export const loginUser = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const { user, token } = await authService.login(email, password);
    res.status(200).json({ user, token });
  } catch (error) {
    res.status(401).json({ message: error.message });
  }
};
```

#### 服务 (`src/services/authService.ts`)
服务层包含核心业务逻辑，例如与数据库的交互。

```typescript
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

export const register = async (email, password, name) => {
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await prisma.user.create({
    data: { email, password: hashedPassword, name },
  });
  // 不返回密码
  delete user.password;
  return user;
};

export const login = async (email, password) => {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    throw new Error('Invalid credentials');
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    throw new Error('Invalid credentials');
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

  // 不返回密码
  delete user.password;
  return { user, token };
};
```

### (2) 文章管理 (Posts CRUD)
文章管理的实现遵循与用户认证类似的模式，包括路由、控制器和服务层。我们在这里只展示部分关键代码作为示例。

#### 认证中间件 (`src/middlewares/authMiddleware.ts`)
创建文章、更新、删除都需要用户登录。我们需要一个中间件来保护这些路由。

```typescript
import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

interface AuthRequest extends Request {
  user?: { userId: number };
}

export const authMiddleware = (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded as { userId: number };
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};
```

#### 文章路由 (`src/routes/postRoutes.ts`)
```typescript
import { Router } from 'express';
import * as postController from '../controllers/postController';
import { authMiddleware } from '../middlewares/authMiddleware';

const router = Router();

router.post('/', authMiddleware, postController.createPost);
router.get('/', postController.getAllPosts);
router.get('/:id', postController.getPostById);
// ... 其他更新和删除路由

export default router;
```

### (3) 整合路由
最后，在 `src/index.ts` 中整合所有路由。

```typescript
// src/index.ts (更新后)
import express from 'express';
import dotenv from 'dotenv';
import authRoutes from './routes/authRoutes';
import postRoutes from './routes/postRoutes';
// ... 其他导入

dotenv.config();
const app = express();
// ...

app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/posts', postRoutes);

// ...
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
```

## 5. 错误处理
创建一个统一的错误处理中间件，捕获所有未处理的错误，是提高应用健壮性的好方法。

```typescript
// src/middlewares/errorMiddleware.ts
import { Request, Response, NextFunction } from 'express';

export const errorMiddleware = (err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
};

// 在 src/index.ts 的末尾，所有路由之后注册它
// app.use(errorMiddleware);
```

至此，我们的后端 API 已经具备了核心功能。下一章节，我们将开始构建前端应用并与这些 API 进行交互。 