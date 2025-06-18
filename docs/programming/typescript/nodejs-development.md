# 后端开发 (Node.js) 与 TypeScript

TypeScript 不仅仅局限于前端开发，它在 Node.js 后端开发中同样表现出色，能帮助我们构建更健壮、更可维护的服务器端应用程序。通过为 API、数据库交互和业务逻辑添加静态类型，可以有效减少运行时错误。

## 1. 初始化项目

首先，创建一个新的 Node.js 项目：
```bash
mkdir my-node-app
cd my-node-app
npm init -y
```

接下来，安装 TypeScript 和 Node.js 的类型定义文件：
```bash
npm install --save-dev typescript @types/node
```
`@types/node` 包包含了 Node.js 核心模块（如 `fs`, `path`, `http` 等）的类型声明。

然后，初始化 `tsconfig.json` 文件：
```bash
npx tsc --init
```

建议在 `tsconfig.json` 中进行以下配置，以适应 Node.js 项目：
```json
{
  "compilerOptions": {
    "target": "es2017",         // 或更高版本，取决于你的Node.js版本
    "module": "commonjs",       // Node.js 使用的模块系统
    "outDir": "./dist",         // 编译后文件的输出目录
    "rootDir": "./src",         // TypeScript 源文件根目录
    "strict": true,             // 启用所有严格类型检查选项
    "esModuleInterop": true     // 改善模块间互操作性
  },
  "include": ["src/**/*"]       // 只编译 src 目录下的文件
}
```

## 2. 高效的开发工作流

在开发过程中，每次修改代码后都手动运行 `tsc` 再运行 `node` 会非常繁琐。我们可以使用 `ts-node` 和 `nodemon` 来自动化这个流程。

- **`ts-node`**: 一个能直接在 Node.js 中执行 TypeScript 代码的工具，它会在内存中完成编译。
- **`nodemon`**: 一个监视文件变化并自动重启应用的工具。

安装它们：
```bash
npm install --save-dev ts-node nodemon
```

在 `package.json` 中添加一个 `dev` 脚本：
```json
{
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "nodemon src/index.ts"
  }
}
```

现在，你可以运行 `npm run dev` 来启动开发服务器。每当你保存一个 `.ts` 文件时，`nodemon` 都会自动使用 `ts-node` 重新执行你的应用。

## 3. 实战：构建类型安全的 Express.js API

让我们用 TypeScript 构建一个简单的 Express 服务器。

首先，安装 Express 和它的类型定义：
```bash
npm install express
npm install --save-dev @types/express
```

创建 `src/index.ts` 文件：
```typescript
// src/index.ts
import express, { Request, Response, NextFunction } from 'express';

const app = express();
const port = 3000;

// 定义一个接口来描述我们的用户数据
interface User {
  id: number;
  name: string;
  email: string;
}

const users: User[] = [
  { id: 1, name: 'Alice', email: 'alice@example.com' },
  { id: 2, name: 'Bob', email: 'bob@example.com' },
];

// 中间件，用于解析JSON请求体
app.use(express.json());

// 获取所有用户的路由
app.get('/api/users', (req: Request, res: Response) => {
  res.json(users);
});

// 根据ID获取单个用户的路由
app.get('/api/users/:id', (req: Request, res: Response) => {
  const id = parseInt(req.params.id, 10);
  const user = users.find(u => u.id === id);

  if (user) {
    res.json(user);
  } else {
    res.status(404).send('User not found');
  }
});

// 全局错误处理中间件
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
```
在这个例子中：
- 我们为 Express 的 `Request`, `Response`, `NextFunction` 对象提供了类型。
- 我们为应用数据（`User`）创建了 `interface`。
- `req.params.id` 被正确地解析为数字。
- 所有回调和中间件都享受到了类型安全的保障。

运行 `npm run dev`，你就有了一个功能齐全、类型安全的 Node.js 后端服务。

---

代码的质量不仅取决于编写，还取决于测试。下一步，我们将学习如何进行[自动化测试](testing.md)。 