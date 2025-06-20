# 1. React 简介与环境搭建

## 什么是 React？

React 是一个由 Facebook 开发并维护的、用于构建用户界面（UI）的开源 JavaScript 库。它不是一个完整的框架（如 Angular），而是一个专注于UI层的库。

React 的核心思想可以总结为以下几点：
- **声明式 (Declarative)**: 你只需告诉 React 你希望 UI 是什么样子（在某个特定状态下），React 就会负责高效地更新和渲染 DOM，使其与你描述的状态保持一致。这让你无需关心底层的DOM操作细节。
- **组件化 (Component-Based)**: 你可以将复杂的UI拆分成一个个独立的、可复用的部分，称为"组件"。每个组件都有自己的逻辑和外观，你可以像搭积木一样将它们组合起来，构建出完整的应用程序。
- **一次学习，随处编写 (Learn Once, Write Anywhere)**: React 的核心思想不仅限于浏览器。通过 **React Native**，你可以使用相同的编程模型来构建原生的移动应用（iOS 和 Android）。

## 为什么要使用 React？

- **高效的虚拟DOM (Virtual DOM)**: React 不会直接操作浏览器的DOM。它会在内存中维护一个轻量级的DOM副本，称为虚拟DOM。当你更新组件的状态时，React会计算出新旧虚拟DOM之间的差异（这个过程称为 "Diffing"），然后只将**最小的、必要的变更**应用到真实的DOM上。这大大减少了昂贵的DOM操作，从而提高了应用性能。
- **庞大的生态系统**: 经过多年的发展，React 拥有一个极其庞大和活跃的生态系统。无论你需要路由（React Router）、状态管理（Redux, MobX）、UI组件库（Ant Design, Material-UI）还是测试工具，几乎都有成熟、高质量的解决方案。
- **强大的社区支持**: 作为一个广泛使用的库，你可以在网上找到大量的教程、文章、问答和开源项目，学习和解决问题都非常方便。
- **由Facebook支持**: 有一个顶级的科技公司在背后持续投入和维护，保证了其长期的稳定性和发展。

## 环境搭建

搭建一个现代化的React开发环境最简单、最推荐的方式是使用官方的脚手手架工具 **Create React App**。它会为你预先配置好所有必要的工具，如Babel（用于编译JSX）、Webpack（用于打包模块）、ESLint（用于代码检查）以及一个开发服务器，让你开箱即用，专注于编写代码。

### 前提条件

- 确保你的电脑上已经安装了 [Node.js](https://nodejs.org/) (推荐使用LTS版本) 和 npm (通常随Node.js一起安装)。

### 创建新项目

打开你的终端，运行以下命令：

```bash
npx create-react-app my-react-app
```
*(`my-react-app` 是你的项目名称，可以替换成任何你喜欢的名字)*

`npx` 是 npm 5.2+ 版本附带的一个包执行器，它会自动下载最新版的 `create-react-app` 并执行它，无需全局安装。

### 启动开发服务器

项目创建完成后，进入项目目录并启动开发服务器：

```bash
cd my-react-app
npm start
```

这个命令会启动一个本地开发服务器（通常在 `http://localhost:3000`），并在你的默认浏览器中打开项目页面。它还提供**热重载 (Hot Reloading)**功能，即当你修改并保存代码时，页面会自动刷新，让你立即看到变更效果。

### 项目结构

Create React App 会生成一个标准的项目结构：
```
my-react-app/
├── node_modules/     # 项目依赖
├── public/           # 存放公共静态文件，如 index.html, favicon.ico
│   └── index.html    # 应用的HTML入口文件，React会挂载到这个文件中的一个DOM节点上
├── src/              # 存放我们主要编写的源代码
│   ├── App.css
│   ├── App.js        # 应用的主组件
│   ├── App.test.js
│   ├── index.css
│   ├── index.js      # 应用的JavaScript入口文件
│   └── logo.svg
├── .gitignore
├── package.json      # 项目的元数据和依赖列表
└── README.md
```

- 你绝大部分的工作都会在 `src` 目录下进行。
- `public/index.html` 中的 `<div id="root"></div>` 是React应用的根挂载点。
- `src/index.js` 文件负责将我们的主组件 `<App />` 渲染到这个根挂载点上。

现在，你已经拥有了一个功能完备的React开发环境。在下一章节，我们将深入探讨React的核心语法：[JSX](jsx-deep-dive.md)。 