# 构建工具: Vite

Vite (法语意为 "快速的"，发音 `/vit/`) 是一种新型前端构建工具，能够显著提升前端开发体验。它主要由两部分组成：

1.  **一个开发服务器**，它利用浏览器原生的 ES 模块支持，实现了极快的冷启动和即时模块热更新 (HMR)。
2.  **一套构建指令**，它使用 Rollup 打包你的代码，预配置输出高度优化的静态资源，用于生产环境。

对于 Vue 开发者来说，Vite 提供了无与伦比的开发体验，是 Vue 官方脚手架 `create-vue` 的默认构建工具。

## 核心特性

-   **极速的开发服务器启动**: 无需打包，直接利用浏览器原生 ESM 能力，服务器启动时间是毫秒级的。
-   **闪电般的热更新 (HMR)**: 无论应用大小如何，HMR 始终能保持快速响应。
-   **丰富的功能**: 开箱即用，支持 TypeScript、JSX、CSS 预处理器等。
-   **优化的构建**: 预配置了 Rollup，支持多页面和库模式。
-   **通用的插件**: 基于 Rollup 的插件接口，拥有强大的插件生态。

## 创建一个 Vite + Vue 项目

最简单的方式是使用官方的 `create-vue` 脚手架：

```bash
npm create vue@latest
```

这个命令会安装和执行 `create-vue`，它是 Vue 的官方项目脚手架工具。你将会看到一些可选功能的提示，例如 TypeScript 和测试支持：

```
✔ Project name: ... <your-project-name>
✔ Add TypeScript? ... No / Yes
✔ Add JSX Support? ... No / Yes
✔ Add Vue Router for Single Page Application development? ... No / Yes
✔ Add Pinia for state management? ... No / Yes
✔ Add Vitest for Unit Testing? ... No / Yes
✔ Add an End-to-End Testing Solution? ... No / Cypress / Playwright
✔ Add ESLint for code quality? ... No / Yes

Scaffolding project in ./<your-project-name>...
Done.
```

## 常用命令

在一个基于 Vite 的项目中，`package.json` 会包含以下脚本：

-   `"dev"`: 启动开发服务器。
-   `"build"`: 为生产环境构建代码。
-   `"preview"`: 在本地预览生产构建产物。

```bash
# 启动开发服务器
npm run dev

# 构建生产版本
npm run build

# 预览生产版本
npm run preview
```

## 配置文件 `vite.config.js`

Vite 是可配置的。你可以创建一个 `vite.config.js` (或 `.ts`) 文件来自定义其行为。

一个常见的配置是为路径设置别名：

```javascript
// vite.config.js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
})
```

Vite 的出现极大地改变了前端开发的格局，它解决了传统构建工具 (如 Webpack) 在大型项目中遇到的性能瓶颈。对于任何新的 Vue 项目，Vite 都是首选的构建工具。 