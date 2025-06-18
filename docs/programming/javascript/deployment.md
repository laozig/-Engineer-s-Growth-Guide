# 应用部署与持续集成 (CI/CD)

将一个 JavaScript 应用从本地开发环境成功地交付到生产环境，是一个涉及多阶段、多技术的系统工程。本章将探讨从基础准备到自动化 CI/CD 流程的现代部署策略。

## 1. 部署基础

### (1) 部署环境

典型的软件开发流程包含多个环境，以确保代码在最终交付给用户前的质量和稳定性。

-   **开发 (Development)**: 你的本地机器。
-   **测试 (Testing)**: 专门用于运行自动化测试（单元、集成、E2E）的环境。
-   **预发布 (Staging)**: 生产环境的克隆版。所有代码在上线前，应先在此环境进行最终验证。
-   **生产 (Production)**: 面向最终用户的实时环境。

### (2) 部署前准备

在部署任何应用之前，必须进行构建和优化。
-   **代码优化**: 对前端资源（JS, CSS）进行压缩、混淆、Tree Shaking 和代码分割。
-   **环境变量**: 使用环境变量 (`process.env`) 管理数据库地址、API 密钥等配置，实现代码与配置的分离。**绝不能将敏感信息硬编码在代码中。**
-   **构建**: 使用 `npm run build` 或类似命令生成用于生产的优化文件。

---

## 2. 核心理念：使用 Docker 容器化

容器化是现代应用部署的基石。**Docker** 是最流行的容器化技术，它将应用及其所有依赖（代码、运行时、系统工具、库）打包到一个轻量、可移植的 **镜像 (Image)** 中。

**为什么使用 Docker?**
-   **环境一致性**: 彻底解决"在我机器上能跑"的问题。
-   **可移植性**: 镜像可以在任何支持 Docker 的机器上（本地、虚拟机、云）以完全相同的方式运行。
-   **隔离性**: 容器之间相互隔离，应用运行在一个干净、可预测的环境中。

### (1) Node.js 后端应用 `Dockerfile`

```dockerfile
# Dockerfile

# 1. 选择一个官方的 Node.js 镜像作为基础
FROM node:18-alpine

# 2. 设置工作目录
WORKDIR /usr/src/app

# 3. 复制 package.json 和 package-lock.json
# 利用 Docker 的缓存机制，仅在依赖变更时才重新安装
COPY package*.json ./

# 4. 安装应用依赖
RUN npm ci --only=production

# 5. 复制应用源代码
COPY . .

# 6. 暴露应用监听的端口
EXPOSE 3000

# 7. 定义容器启动时执行的命令
CMD [ "node", "src/server.js" ]
```

### (2) 前端应用 `Dockerfile` (多阶段构建)

多阶段构建是一个最佳实践，它能让最终的生产镜像变得非常小。

```dockerfile
# Dockerfile

# --- STAGE 1: Build ---
# 使用 Node.js 镜像来构建前端静态文件
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# 运行构建命令
RUN npm run build

# --- STAGE 2: Production ---
# 使用一个超轻量级的 Nginx 镜像来托管构建好的文件
FROM nginx:1.23-alpine

# 从 'builder' 阶段复制构建产物到 Nginx 的静态文件目录
COPY --from=builder /app/dist /usr/share/nginx/html

# （可选）复制自定义的 Nginx 配置文件
# COPY nginx.conf /etc/nginx/conf.d/default.conf

# 暴露 80 端口
EXPOSE 80

# Nginx 镜像会自动启动 Nginx 服务
CMD ["nginx", "-g", "daemon off;"]
```

---

## 3. 部署方案

### (1) 部署到虚拟机 (传统方式)

这是最基础的部署方式，你拥有对一台云服务器（如 AWS EC2, DigitalOcean Droplet）的完全控制权。

-   **进程管理**: 使用 [PM2](https://pm2.keymetrics.io/) 来作为 Node.js 应用的进程管理器。它提供了进程守护、日志管理、负载均衡和零停机重启等关键功能。
    ```bash
    # 在服务器上全局安装 PM2
    npm install -g pm2
    # 启动应用，并以集群模式利用所有 CPU 核心
    pm2 start src/server.js -i max --name "my-api"
    # 保存当前的应用列表，以便服务器重启后自动恢复
    pm2 save
    ```

-   **反向代理**: 使用 [Nginx](https://www.nginx.com/) 作为反向代理，将公网的 80/443 端口的流量转发到你应用的内部端口（如 3000）。Nginx 还可以处理 HTTPS (SSL/TLS)、Gzip 压缩、静态文件服务和限流等。

### (2) 部署到云平台 (PaaS)

平台即服务 (PaaS) 能让你只专注于代码，而将服务器、网络、扩展等底层架构的管理交给平台。

-   **Vercel / Netlify**: **前端应用的首选**。它们与 Git 仓库深度集成，你只需 `git push`，它们就会自动完成构建、部署和全球 CDN 分发。
-   **Heroku / Render**: **后端应用的绝佳选择**。它们支持直接从 `Dockerfile` 或 Node.js 源码进行部署，并提供数据库、缓存等插件服务。

### (3) 使用 `docker-compose` 部署多容器应用

当你的应用包含多个服务时（如后端 API、数据库、缓存），`docker-compose` 是一个用于定义和运行多容器 Docker 应用的强大工具。

```yaml
# docker-compose.yml
version: '3.8'

services:
  # 后端 API 服务
  api:
    build: . # 使用当前目录的 Dockerfile
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgres://user:password@db:5432/mydatabase
    depends_on:
      - db # 依赖于数据库服务

  # 数据库服务
  db:
    image: postgres:14-alpine # 直接使用官方镜像
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=mydatabase
    volumes:
      - postgres_data:/var/lib/postgresql/data # 持久化数据库数据

volumes:
  postgres_data:
```
只需一个命令 `docker-compose up`，即可同时启动和连接好 API 和数据库服务。

---

## 4. 持续集成与持续部署 (CI/CD)

CI/CD 是一种通过自动化来频繁地向客户交付应用的实践。

-   **持续集成 (Continuous Integration)**: 开发人员频繁地将代码合并到主干。每次合并都会自动触发 **构建** 和 **测试**，以尽早发现集成错误。
-   **持续部署 (Continuous Deployment)**: 通过了所有测试的代码，将自动地部署到生产环境。

**GitHub Actions** 是实现 CI/CD 的主流工具之一。

### 示例：一个完整的 Node.js 应用 CI/CD 流程

这个流程会在每次推送到 `main` 分支时，自动测试、构建 Docker 镜像，并将其推送到 GitHub Container Registry。

```yaml
# .github/workflows/ci-cd.yml
name: Node.js CI/CD

on:
  push:
    branches: [ "main" ]

jobs:
  build-and-push:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: 18

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository_owner }}/my-app:latest
```
*你需要去仓库设置中，确保 Actions 有权限写入 Package Registry。*

这个自动化的流程，就是现代 DevOps 文化的核心实践。它极大地提高了开发效率和应用交付的可靠性。 