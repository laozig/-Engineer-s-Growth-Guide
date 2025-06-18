# JavaScript 全栈开发环境配置指南

<div align="center">
  <img src="../../../assets/programming/environment-setup.png" alt="Environment Setup" width="250">
</div>

> 一个稳定、高效的开发环境是专业开发的基石。本指南将引导您配置一个适用于现代JavaScript全栈开发的完整环境，涵盖从Node.js版本管理到编辑器、工具链和容器化的所有核心环节。

## 目录

1.  [**核心基础：Node.js**](#1-核心基础nodejs)
    -   [为什么使用版本管理器？](#为什么使用版本管理器)
    -   [Windows：使用 NVM for Windows](#windows使用-nvm-for-windows)
    -   [macOS/Linux：使用 NVM](#macoslinux使用-nvm)
    -   [验证安装](#验证安装)
2.  [**包管理器：npm, yarn, pnpm**](#2-包管理器npm-yarn-pnpm)
    -   [npm 配置与镜像源](#npm-配置与镜像源)
    -   [Yarn：快速与可靠](#yarn快速与可靠)
    -   [pnpm：高效的磁盘空间利用](#pnpm高效的磁盘空间利用)
    -   [如何选择？](#如何选择)
3.  [**代码编辑器：Visual Studio Code**](#3-代码编辑器visual-studio-code)
    -   [必备核心扩展](#必备核心扩展)
    -   [推荐配置 (settings.json)](#推荐配置-settingsjson)
    -   [ESLint 与 Prettier 的协同配置](#eslint-与-prettier-的协同配置)
4.  [**前端开发工具链**](#4-前端开发工具链)
    -   [Vite：新一代前端构建工具](#vite新一代前端构建工具)
    -   [Create React App](#create-react-app)
    -   [Vue CLI](#vue-cli)
5.  [**后端开发利器**](#5-后端开发利器)
    -   [Nodemon：自动重启应用](#nodemon自动重启应用)
    -   [Dotenv：环境变量管理](#dotenv环境变量管理)
6.  [**版本控制：Git**](#6-版本控制git)
7.  [**容器化开发：Docker**](#7-容器化开发docker)
    -   [安装 Docker Desktop](#安装-docker-desktop)
    -   [使用 Docker 运行数据库](#使用-docker-运行数据库)
8.  [**总结**](#8-总结)

---

## 1. 核心基础：Node.js

Node.js 是 JavaScript 的服务器端运行环境，是全栈开发的基础。**强烈推荐使用版本管理器来安装和切换Node.js**，而不是直接从官网下载安装程序。

### 为什么使用版本管理器？

- **项目隔离**：不同项目可能需要不同版本的 Node.js。
- **轻松切换**：一条命令即可切换全局 Node.js 版本。
- **避免权限问题**：避免使用 `sudo` 全局安装包。

### Windows：使用 NVM for Windows

1.  **下载与安装**：
    -   访问 [nvm-windows Releases](https://github.com/coreybutler/nvm-windows/releases) 页面。
    -   下载最新的 `nvm-setup.zip` 并解压安装。

2.  **常用命令**：
    ```bash
    # 查看可安装的 LTS (长期支持) 版本
    nvm list available

    # 安装最新的 LTS 版本
    nvm install lts

    # 安装指定版本
    nvm install 18.17.0

    # 查看已安装的版本
    nvm list

    # 切换使用的版本
    nvm use 18.17.0
    ```

### macOS/Linux：使用 NVM

1.  **安装脚本**：
    ```bash
    # 推荐从官方仓库获取最新的安装命令
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash
    ```
    > 安装完成后，根据终端提示，可能需要将 nvm 的初始化脚本添加到 `.bashrc`, `.zshrc` 或 `.profile` 文件中，然后重启终端。

2.  **常用命令**：
    ```bash
    # 安装最新的 LTS 版本
    nvm install --lts

    # 切换到最新的 LTS 版本
    nvm use --lts

    # 设置默认版本
    nvm alias default 'lts/*'
    ```

### 验证安装

无论使用哪种方式，都可以通过以下命令验证 Node.js 和 npm 是否安装成功：
```bash
node -v   # 显示 v18.17.0 或其他版本
npm -v    # 显示 9.6.7 或其他版本
```

## 2. 包管理器：npm, yarn, pnpm

包管理器用于管理项目的依赖（第三方库）。

### npm 配置与镜像源

npm 是 Node.js 自带的包管理器。为了提高下载速度，建议配置国内镜像源。

```bash
# 使用淘宝镜像源
npm config set registry https://registry.npmmirror.com/

# 验证是否成功
npm config get registry
```

### Yarn：快速与可靠

Yarn 提供了更快的安装速度和版本锁定机制。
```bash
# 使用 npm 全局安装 Yarn
npm install -g yarn

# 验证安装
yarn --version
```

### pnpm：高效的磁盘空间利用

pnpm 通过非扁平化的 `node_modules` 目录和硬链接技术，极大地节省了磁盘空间，并提高了安装速度。
```bash
# 使用 npm 全局安装 pnpm
npm install -g pnpm

# 验证安装
pnpm --version
```

### 如何选择？

- **新手入门**：直接使用 `npm` 即可。
- **团队协作与大型项目**：推荐使用 `pnpm`，因其严格性和性能优势。
- **现有项目**：遵循项目已有的选择。

## 3. 代码编辑器：Visual Studio Code

VS Code 是目前最流行的 JavaScript 开发编辑器。

### 必备核心扩展

- **ESLint**: 实时检查代码风格和错误。
- **Prettier - Code formatter**: 统一代码格式。
- **GitLens — Git supercharged**: 强大的 Git 集成功能。
- **Path Intellisense**: 智能提示文件路径。
- **vscode-icons**: 美化文件和文件夹图标。
- **Live Server**: 快速启动一个本地开发服务器。

### 推荐配置 (settings.json)

按下 `Ctrl+Shift+P` (或 `Cmd+Shift+P`)，搜索 `Open User Settings (JSON)`，并粘贴以下配置：

```json
{
  "editor.tabSize": 2,
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "files.autoSave": "onFocusChange",
  "javascript.updateImportsOnFileMove.enabled": "always",
  "typescript.updateImportsOnFileMove.enabled": "always",
  "explorer.compactFolders": false,
  "workbench.iconTheme": "vscode-icons",
  "[javascript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescriptreact]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  }
}
```

### ESLint 与 Prettier 的协同配置

为了避免格式化规则冲突，需要安装 `eslint-config-prettier` 来关闭 ESLint 中与 Prettier 冲突的规则。

1.  **安装**: `npm install --save-dev eslint-config-prettier`
2.  **配置 `.eslintrc`**:
    ```json
    {
      "extends": [
        "eslint:recommended",
        "prettier" // 确保 'prettier' 是最后一个
      ]
    }
    ```

## 4. 前端开发工具链

现代前端开发依赖于构建工具来启动项目。

### Vite：新一代前端构建工具

Vite 提供了极速的冷启动和模块热更新（HMR），是目前前端开发的首选。

```bash
# 使用 Vite 创建一个 React + TypeScript 项目
npm create vite@latest my-react-app -- --template react-ts

# 进入项目并启动
cd my-react-app
npm install
npm run dev
```

### Create React App

虽然 Vite 更受欢迎，但 `create-react-app` 仍是学习 React 的一个稳定选择。
```bash
npx create-react-app my-app
```

### Vue CLI

对于 Vue.js 项目：
```bash
npm install -g @vue/cli
vue create my-vue-app
```

## 5. 后端开发利器

### Nodemon：自动重启应用

在开发 Node.js 后端应用时，`nodemon` 会监视文件变化并自动重启服务器。

```bash
# 全局安装
npm install -g nodemon

# 在项目中使用
nodemon server.js
```

### Dotenv：环境变量管理

使用 `.env` 文件来管理环境变量，避免将敏感信息（如数据库密码）硬编码在代码中。

1.  **安装**: `npm install dotenv`
2.  **使用**: 在项目根目录创建 `.env` 文件，并在应用入口处加载：
    ```javascript
    // server.js
    require('dotenv').config();

    const dbPassword = process.env.DB_PASSWORD;
    ```

## 6. 版本控制：Git

Git 是现代软件开发的标准版本控制系统。请确保已从 [Git 官网](https://git-scm.com/) 下载并安装。

## 7. 容器化开发：Docker

Docker 可以在隔离的容器中运行应用，确保开发、测试和生产环境的一致性。

### 安装 Docker Desktop

从 [Docker 官网](https://www.docker.com/products/docker-desktop/) 下载并安装 Docker Desktop。

### 使用 Docker 运行数据库

无需在本地安装复杂的数据库，一条命令即可启动一个 PostgreSQL 数据库容器：

```bash
docker run --name my-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 5432:5432 -d postgres
```
> 现在，您的本地应用可以通过 `localhost:5432` 连接到这个数据库了。

## 8. 总结

配置好以上环境，您就拥有了一个强大且高效的JavaScript全栈开发工作区。标准化的工具和流程不仅能提升个人效率，也能让团队协作更加顺畅。 