# 示例项目：全栈博客平台 - 部署上线

开发完成只是第一步，将应用部署到生产环境，让全球用户都能访问，是全栈开发者的终极考验。本章将指导你如何使用 Docker 将我们的博客应用容器化，并将其部署到服务器上。

## 1. 生产环境概述

### 部署与开发的关键区别
- **性能**: 代码需要被压缩和优化，服务需要能处理并发请求。
- **安全**: 必须使用 HTTPS，敏感信息（如密钥、密码）不能硬编码，必须通过安全的方式管理。
- **持久化**: 数据必须持久存储，服务需要能够自动重启。
- **可扩展性**: 架构应允许未来方便地进行水平或垂直扩展。

### 部署策略
我们将采用基于 **Docker** 的容器化部署方案。这能确保开发、测试和生产环境的一致性，极大地简化了部署流程。我们将使用 `docker-compose` 来编排前端、后端和数据库三个容器。

## 2. 后端部署准备

### (1) 创建后端 Dockerfile
在 `backend` 目录下创建一个名为 `Dockerfile` 的文件。这个文件定义了如何构建后端的生产镜像。

```dockerfile
# backend/Dockerfile

# --- 1. 构建阶段 ---
FROM node:18-alpine AS builder

WORKDIR /app

# 复制 package.json 和 pnpm-lock.yaml
COPY package*.json pnpm-lock.yaml ./

# 安装依赖并编译 TypeScript
RUN npm install -g pnpm && \
    pnpm install --prod=false && \
    pnpm prisma generate && \
    pnpm build # 假设你有一个 build 脚本来编译 TS -> JS

# --- 2. 生产阶段 ---
FROM node:18-alpine

WORKDIR /app

# 从构建阶段复制必要的文件
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma
COPY package.json .

# 暴露端口
EXPOSE 3000

# 运行应用的命令
CMD ["node", "dist/index.js"]
```
*注意: 为此你需要一个 `build` 脚本，例如 `"build": "tsc"` 在 `package.json` 中，以及一个 `tsconfig.json` 文件。*

## 3. 前端部署准备

### (1) 构建生产版本
Vite 的构建过程非常简单。在 `frontend` 目录下运行：

```bash
pnpm build
```
Vite 会将所有优化过的静态资源（HTML, CSS, JS）输出到 `frontend/dist` 目录。

### (2) 创建前端 Nginx 配置
我们将使用 Nginx 作为 Web 服务器来托管前端静态文件，并作为后端的反向代理。

在项目根目录创建一个 `nginx` 文件夹，并在其中创建一个 `default.conf` 文件。

```nginx
# nginx/default.conf

server {
    listen 80;
    server_name your_domain.com; # 替换成你的域名或服务器 IP

    # 托管前端静态文件
    location / {
        root   /usr/share/nginx/html;
        index  index.html;
        try_files $uri $uri/ /index.html; # 对于单页应用(SPA)至关重要
    }

    # 将 API 请求反向代理到后端服务
    location /api {
        proxy_pass http://backend:3000; # "backend" 是 docker-compose 中的服务名
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    # (可选) 配置错误页面和日志
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }
}
```

## 4. 整合部署：使用 Docker Compose

现在我们在项目根目录创建一个 `docker-compose.prod.yml` 文件来编排所有服务。

```yaml
# docker-compose.prod.yml

version: '3.8'

services:
  # 数据库服务
  database:
    image: postgres:14
    restart: always
    volumes:
      - postgres_data:/var/lib/postgresql/data
    env_file:
      - ./backend/.env.prod # 将生产环境的数据库凭证放在这里

  # 后端服务
  backend:
    build:
      context: ./backend # 指定 Dockerfile 的位置
    restart: always
    depends_on:
      - database
    env_file:
      - ./backend/.env.prod # 同样使用生产环境变量

  # 前端和反向代理服务
  proxy:
    image: nginx:alpine
    restart: always
    ports:
      - "80:80"   # 将服务器的 80 端口映射到容器的 80 端口
      - "443:443" # 为 HTTPS 预留
    volumes:
      - ./frontend/dist:/usr/share/nginx/html # 将前端构建产物挂载到 Nginx
      - ./nginx/default.conf:/etc/nginx/conf.d/default.conf # 挂载 Nginx 配置
      # - ./certbot/conf:/etc/letsencrypt # (用于 HTTPS)
      # - ./certbot/www:/var/www/certbot # (用于 HTTPS)
    depends_on:
      - backend

volumes:
  postgres_data:
```

*注意：你需要创建一个 `.env.prod` 文件在 `backend` 目录下，包含生产环境的 `DATABASE_URL` 和 `JWT_SECRET`。*

## 5. 部署步骤

1.  **准备服务器**: 获取一台云服务器 (VPS)，安装 Docker 和 Docker Compose。
2.  **克隆代码**: `git clone <your-repo-url>` 到服务器上。
3.  **构建前端**: 在本地或服务器上，进入 `frontend` 目录运行 `pnpm build`。
4.  **创建生产环境变量**: 在服务器的 `backend` 目录下创建 `.env.prod` 文件并填入安全凭证。
5.  **启动应用**: 在服务器的项目根目录下，运行：
    ```bash
    docker-compose -f docker-compose.prod.yml up --build -d
    ```
    `--build` 标志会强制重新构建镜像，`-d` 则让容器在后台运行。

现在，通过服务器的 IP 地址或域名访问，你就应该能看到你的全栈博客应用了！

## 6. 后续步骤：域名与 HTTPS

生产环境的应用必须使用 HTTPS。
-   **获取域名**: 注册一个域名并将其 DNS A 记录指向你的服务器 IP。
-   **使用 Let's Encrypt**: Certbot 是一个免费、自动化的工具，可以轻松地为你的 Nginx 配置 SSL/TLS 证书。你需要调整 `docker-compose.prod.yml` 和 `nginx/default.conf` 来集成 Certbot。

至此，整个全栈项目的开发和部署周期就完成了。你已经掌握了从零到一构建并上线一个现代化 JavaScript 应用的核心技能。 