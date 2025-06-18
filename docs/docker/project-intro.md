# 10. 实战案例：项目介绍与准备

欢迎来到 Docker 学习路径的实战案例部分！在这里，我们将把前面所有章节学到的知识——`Dockerfile`, `docker-compose`, 网络, 卷——全部整合起来，从零开始构建、容器化并编排一个完整的多服务 Web 应用。

## 项目概述：一个 "Todo List" 应用

我们将构建一个经典的"待办事项列表" (Todo List) 应用。虽然简单，但它具备了现代 Web 应用的典型分层架构，非常适合用来演练我们的 Docker 技能。

应用将包含三个独立的服务：
1.  **前端 (Frontend)**: 一个用 **React** 构建的单页应用 (SPA)。它负责渲染用户界面，并与后端 API 进行交互来获取和修改待办事项。
2.  **后端 (Backend)**: 一个用 **Node.js/Express** 编写的 RESTful API。它负责处理业务逻辑，如创建、读取、更新和删除 (CRUD) 待办事项，并将数据存储在数据库中。
3.  **数据库 (Database)**: 一个 **PostgreSQL** 数据库实例，用于持久化地存储所有的待办事项数据。

## 应用架构

我们的目标架构如下所示：

```mermaid
graph TD
    subgraph "用户浏览器"
        A[React App]
    end

    subgraph "Docker 环境 (通过 Docker Compose 管理)"
        B[Nginx<br/><i>(用于服务前端静态文件)</i>]
        C[Backend API<br/><i>(Node.js/Express)</i>]
        D[Database<br/><i>(PostgreSQL)</i>]
        E[app-network]
        F((pg-data<br/><i>命名卷</i>))
    end

    A -- HTTP请求 --> B
    B -- API请求 --> C
    C -- "读/写" --> D
    
    B -- "连接到" --> E
    C -- "连接到" --> E
    D -- "连接到" --> E
    D -- "存储数据到" --> F

    style B fill:#f9f,stroke:#333,stroke-width:2px
    style C fill:#ccf,stroke:#333,stroke-width:2px
    style D fill:#cfc,stroke:#333,stroke-width:2px
```

**数据流解释**:
1.  用户的浏览器加载由 Nginx 服务提供的 React 应用静态文件。
2.  React 应用中的 JavaScript 代码通过 HTTP 请求，调用后端 API (例如 `GET /api/todos`)。
3.  后端 Express 服务接收到请求，执行相应的数据库查询。
4.  后端服务通过 `app-network` 网络连接到 PostgreSQL 数据库服务。
5.  数据库将数据返回给后端，后端将其格式化为 JSON 并响应给前端。
6.  React 应用接收到数据并更新 UI。
7.  PostgreSQL 的所有数据都存储在一个名为 `pg-data` 的 Docker 卷中，以确保数据持久性。

*注意：为了简化，我们将使用 Nginx 容器来服务 React 应用的静态构建产物，这是生产环境中常见的做法。*

## 项目目标

通过这个案例，我们将实现：
-   为 `frontend` 和 `backend` 服务分别编写高效、多阶段的 `Dockerfile`。
-   编写一个健壮的 `docker-compose.yml` 文件，用于声明式地定义和管理所有服务。
-   配置服务间的网络，实现 `frontend -> backend -> database` 的顺畅通信。
-   为 PostgreSQL 数据库配置命名卷，确保数据在容器重启或重建后依然存在。
-   为后端开发启用绑定挂载，实现代码热重载，提升开发效率。
-   最终目标：在项目根目录运行 `docker-compose up -d --build`，即可一键启动整个应用的完整开发环境。

## 准备工作：初始化项目结构

在开始编写代码之前，让我们先创建好项目的文件结构。

在你的工作区中，创建一个名为 `todo-app` 的根目录，并在其中创建以下文件和子目录：
```
todo-app/
├── backend/
│   ├── .dockerignore
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       └── server.js
├── frontend/
│   ├── .dockerignore
│   ├── Dockerfile
│   └── ... (React 项目文件，可以用 create-react-app 生成)
└── docker-compose.yml
```

**操作步骤**:
1.  创建 `todo-app` 目录。
2.  在其中创建 `backend` 和 `frontend` 目录。
3.  在 `backend` 目录中，创建 `src` 子目录，并创建空的 `Dockerfile`, `.dockerignore`, `package.json`, `src/server.js` 文件。
4.  在 `frontend` 目录中，你可以使用 `npx create-react-app .` 来快速生成一个 React 项目的骨架。之后再在其中创建 `Dockerfile` 和 `.dockerignore`。
5.  在根目录 `todo-app/` 下，创建一个空的 `docker-compose.yml` 文件。

在下一章，我们将开始编写 `backend` 服务的 Dockerfile 和应用代码。让我们开始吧！ 