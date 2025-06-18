# 12. 使用 Compose 整合与部署

现在我们已经为前端和后端服务准备好了 `Dockerfile`，是时候将所有部分——前端、后端和数据库——通过 Docker Compose 整合在一起了。我们将创建一个最终的 `docker-compose.yml` 文件，它将作为我们整个应用的中央控制台。

## 最终的 `docker-compose.yml`

在你的项目根目录 (`todo-app/`) 下，编辑 `docker-compose.yml` 文件，内容如下：

```yaml
version: '3.8'

services:
  # 1. 数据库服务 (PostgreSQL)
  database:
    image: postgres:14-alpine
    # 容器名称
    container_name: todo_postgres_db
    # 环境变量，用于初始化数据库
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    # 命名卷，用于持久化数据库数据
    volumes:
      - pg-data:/var/lib/postgresql/data
    # 将此服务连接到我们的网络
    networks:
      - app-network
    # 健康检查，确保数据库完全准备好后再启动依赖它的服务
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5

  # 2. 后端 API 服务 (Node.js/Express)
  backend:
    # 从 backend 目录的 Dockerfile 构建
    build:
      context: ./backend
      # 指定使用多阶段构建中的 'development' 阶段
      target: development
    container_name: todo_backend_api
    # 依赖于数据库服务
    depends_on:
      database:
        condition: service_healthy # 等待数据库健康检查通过
    # 注入环境变量，用于连接数据库
    environment:
      POSTGRES_HOST: database # 'database' 是服务名
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
      PORT: 4000
    # 绑定挂载，用于开发时的代码热重载
    volumes:
      - ./backend/src:/app/src
    networks:
      - app-network

  # 3. 前端服务 (React + Nginx)
  frontend:
    build:
      context: ./frontend
    container_name: todo_frontend_web
    depends_on:
      - backend
    # 将容器的 80 端口（Nginx）映射到宿主机的 8080 端口
    ports:
      - "8080:80"
    networks:
      - app-network

# 顶层定义网络
networks:
  app-network:
    driver: bridge

# 顶层定义卷
volumes:
  pg-data:
    driver: local
```

## 使用 `.env` 文件管理敏感信息

直接在 `docker-compose.yml` 中硬编码密码是一个坏习惯。Compose 可以自动读取与 `docker-compose.yml` 同目录下的 `.env` 文件，并将其中的变量注入到 Compose 文件中。

在项目根目录创建 `.env` 文件：

**`.env`**:
```
POSTGRES_USER=myuser
POSTGRES_PASSWORD=mypassword
POSTGRES_DB=todos
```
现在，Compose 会自动用这些值替换 `${POSTGRES_USER}` 等占位符。**切记，永远不要将 `.env` 文件提交到 Git 仓库中！**

## 服务详解

-   **`database` 服务**:
    -   我们使用了官方的 `postgres` 镜像。
    -   `volumes: - pg-data:/var/lib/postgresql/data` 是关键，它将 `pg-data` 命名卷挂载到 PostgreSQL 存储其数据的标准目录，从而实现了数据持久化。
    -   `healthcheck` 是一个非常有用的功能，它会定期检查数据库是否准备好接受连接。`depends_on` 中的 `condition: service_healthy` 会确保 `backend` 服务在数据库完全就绪后才启动，避免了启动初期的连接错误。

-   **`backend` 服务**:
    -   `build.target: development` 明确告诉 Compose 使用我们 `backend/Dockerfile` 中定义的 `development` 阶段来构建镜像，这样我们就能使用 `nodemon` 了。
    -   `volumes: - ./backend/src:/app/src` 是开发效率的关键。我们把本地的 `src` 目录直接挂载到容器的 `/app/src` 目录。当你在本地修改代码时，`nodemon` 会检测到变化并自动重启 Node.js 服务，无需重建镜像或重启容器。
    -   `POSTGRES_HOST: database`: 我们告诉后端应用，数据库的主机名是 `database`，这正是我们在 Compose 文件中定义的数据库服务的名称。Compose 内置的 DNS 服务会负责将这个名字解析为正确的容器 IP。

-   **`frontend` 服务**:
    -   它构建自 `frontend/Dockerfile`，其中包含了 Nginx 配置，能够将 `/api` 请求反向代理到 `backend` 服务。
    -   `ports: - "8080:80"` 使我们可以通过访问宿主机的 `8080` 端口来访问我们的应用。

## 部署与工作流

现在，一切准备就绪！

1.  **一键启动应用**:
    在项目根目录 (`todo-app/`) 下，运行：
    ```bash
    docker-compose up -d --build
    ```
    -   `--build` 标志会强制 Compose 重新构建 `frontend` 和 `backend` 的镜像。
    -   `-d` 会让所有服务在后台运行。

2.  **查看状态**:
    ```bash
    docker-compose ps
    ```
    你应该能看到 `database`, `backend`, `frontend` 三个服务都在运行 (Up) 状态。

3.  **访问应用**:
    打开你的浏览器，访问 `http://localhost:8080`。你应该能看到 Todo List 应用的界面，并且可以正常添加和查看待办事项。

4.  **体验热重载**:
    -   保持应用运行。
    -   打开 `backend/src/server.js` 文件，在 `GET /api/todos` 的 `console.log` 中添加一些文字。
    -   保存文件。
    -   查看后端服务的日志：`docker-compose logs -f backend`。你会看到 `nodemon` 检测到了文件变化并自动重启了服务！

5.  **停止和清理**:
    当你完成工作后，可以用以下命令停止并清理所有资源：
    ```bash
    # 停止并移除容器和网络
    docker-compose down
    
    # 如果想连同数据库卷一起删除，彻底清空数据
    docker-compose down -v
    ```

恭喜你！你已经成功地使用 Docker 和 Docker Compose 构建、容器化并部署了一个完整的多服务 Web 应用，并建立了一个高效的开发工作流。 