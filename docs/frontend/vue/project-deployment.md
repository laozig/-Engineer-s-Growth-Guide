# 项目实战：最终部署

在前面的章节中，我们已经构建了一个功能完整的待办事项应用。现在，是时候将它部署到生产环境，让真实用户可以访问和使用它了。本章将介绍几种部署Vue应用的方法，以及部署前的优化工作。

## 1. 构建生产版本

在部署之前，我们需要构建应用的生产版本。Vite会对代码进行优化，包括压缩、tree-shaking和代码分割等，以提高应用的加载速度和运行性能。

在项目根目录运行以下命令：

```bash
npm run build
```

这个命令会在`dist`目录下生成优化后的生产版本文件。

## 2. 本地预览生产版本

在部署到服务器之前，我们可以在本地预览生产版本，确保一切正常：

```bash
npm run preview
```

这将启动一个本地静态Web服务器，运行`dist`目录中的生产版本。

## 3. 部署选项

### 3.1 静态托管服务

最简单的部署方式是使用静态托管服务。以下是几个流行的选项：

#### Netlify

1. 注册[Netlify](https://www.netlify.com/)账号
2. 点击"New site from Git"
3. 选择你的Git仓库
4. 设置构建命令为`npm run build`，发布目录为`dist`
5. 点击"Deploy site"

Netlify会自动监听你的Git仓库，每次推送代码后自动构建和部署。

#### Vercel

1. 注册[Vercel](https://vercel.com/)账号
2. 导入你的Git仓库
3. Vercel会自动检测到Vue项目，并设置正确的构建配置
4. 点击"Deploy"

#### GitHub Pages

1. 在项目根目录创建`vue.config.js`文件（如果使用Vue CLI）或修改`vite.config.js`（如果使用Vite）：

```js
// vite.config.js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: '/your-repo-name/' // 替换为你的GitHub仓库名
})
```

2. 创建部署脚本`deploy.sh`：

```bash
#!/usr/bin/env sh

# 发生错误时终止
set -e

# 构建
npm run build

# 进入构建文件夹
cd dist

# 如果你要部署到自定义域名
# echo 'www.example.com' > CNAME

git init
git add -A
git commit -m 'deploy'

# 如果你要部署在 https://<USERNAME>.github.io
# git push -f git@github.com:<USERNAME>/<USERNAME>.github.io.git main

# 如果你要部署在 https://<USERNAME>.github.io/<REPO>
git push -f git@github.com:<USERNAME>/<REPO>.git main:gh-pages

cd -
```

3. 运行部署脚本：

```bash
sh deploy.sh
```

4. 在GitHub仓库设置中，将GitHub Pages的源设置为`gh-pages`分支

### 3.2 使用Docker容器化部署

Docker可以帮助我们创建一个包含应用及其所有依赖的容器，确保应用在任何环境中都能一致运行。

1. 在项目根目录创建`Dockerfile`：

```dockerfile
# 构建阶段
FROM node:16-alpine as build-stage
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# 生产阶段
FROM nginx:stable-alpine as production-stage
COPY --from=build-stage /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

2. 构建Docker镜像：

```bash
docker build -t todo-app .
```

3. 运行容器：

```bash
docker run -p 8080:80 todo-app
```

现在，你可以通过`http://localhost:8080`访问应用。

### 3.3 传统Web服务器部署

如果你有自己的Web服务器，可以将构建后的文件上传到服务器：

1. 将`dist`目录中的所有文件上传到服务器的Web根目录
2. 配置服务器以支持SPA（单页应用）路由

#### Nginx配置示例

```nginx
server {
  listen 80;
  server_name your-domain.com;

  root /path/to/your/dist;
  index index.html;

  location / {
    try_files $uri $uri/ /index.html;
  }
}
```

#### Apache配置示例

在`dist`目录中创建`.htaccess`文件：

```apache
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteBase /
  RewriteRule ^index\.html$ - [L]
  RewriteCond %{REQUEST_FILENAME} !-f
  RewriteCond %{REQUEST_FILENAME} !-d
  RewriteRule . /index.html [L]
</IfModule>
```

## 4. 部署前的优化

### 4.1 环境变量配置

使用环境变量来区分开发环境和生产环境的配置：

1. 在项目根目录创建`.env.development`和`.env.production`文件：

```
# .env.development
VITE_API_URL=http://localhost:3000/api

# .env.production
VITE_API_URL=https://api.your-domain.com
```

2. 在代码中使用环境变量：

```js
const apiUrl = import.meta.env.VITE_API_URL
```

### 4.2 性能优化

#### 代码分割

Vite默认会进行代码分割，但我们可以通过动态导入进一步优化：

```js
// 路由懒加载
const TodoStatistics = () => import('../components/TodoStatistics.vue')
```

#### 预加载关键资源

在`index.html`中添加预加载指令：

```html
<link rel="preload" href="/assets/main.js" as="script">
<link rel="preload" href="/assets/main.css" as="style">
```

#### 压缩图片

使用`vite-plugin-imagemin`压缩图片：

```bash
npm install vite-plugin-imagemin -D
```

```js
// vite.config.js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import viteImagemin from 'vite-plugin-imagemin'

export default defineConfig({
  plugins: [
    vue(),
    viteImagemin({
      gifsicle: {
        optimizationLevel: 7,
        interlaced: false
      },
      optipng: {
        optimizationLevel: 7
      },
      mozjpeg: {
        quality: 80
      },
      pngquant: {
        quality: [0.8, 0.9],
        speed: 4
      },
      svgo: {
        plugins: [
          {
            name: 'removeViewBox'
          },
          {
            name: 'removeEmptyAttrs',
            active: false
          }
        ]
      }
    })
  ]
})
```

### 4.3 添加PWA支持

将应用转变为Progressive Web App (PWA)，使其可以离线工作并提供类似原生应用的体验：

1. 安装PWA插件：

```bash
npm install vite-plugin-pwa -D
```

2. 配置插件：

```js
// vite.config.js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  plugins: [
    vue(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.ico', 'robots.txt', 'apple-touch-icon.png'],
      manifest: {
        name: 'Todo App',
        short_name: 'Todo',
        description: '一个简单的待办事项应用',
        theme_color: '#ffffff',
        icons: [
          {
            src: 'pwa-192x192.png',
            sizes: '192x192',
            type: 'image/png'
          },
          {
            src: 'pwa-512x512.png',
            sizes: '512x512',
            type: 'image/png'
          }
        ]
      }
    })
  ]
})
```

## 5. 部署后的监控

### 5.1 错误监控

使用Sentry等服务监控生产环境中的错误：

```bash
npm install @sentry/vue @sentry/tracing
```

```js
// main.js
import { createApp } from 'vue'
import * as Sentry from '@sentry/vue'
import { BrowserTracing } from '@sentry/tracing'
import App from './App.vue'
import router from './router'

const app = createApp(App)

if (import.meta.env.PROD) {
  Sentry.init({
    app,
    dsn: 'YOUR_SENTRY_DSN',
    integrations: [
      new BrowserTracing({
        routingInstrumentation: Sentry.vueRouterInstrumentation(router),
        tracingOrigins: ['localhost', 'your-domain.com', /^\//]
      })
    ],
    tracesSampleRate: 1.0
  })
}

app.use(router)
app.mount('#app')
```

### 5.2 性能监控

使用Google Analytics或其他分析工具监控应用性能：

```bash
npm install vue-gtag-next
```

```js
// main.js
import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import VueGtag from 'vue-gtag-next'

const app = createApp(App)

app.use(VueGtag, {
  property: {
    id: 'G-XXXXXXXXXX'
  }
})

app.use(router)
app.mount('#app')
```

## 6. 持续集成/持续部署 (CI/CD)

设置CI/CD流程可以自动化测试和部署过程：

### 6.1 GitHub Actions

在项目根目录创建`.github/workflows/deploy.yml`：

```yaml
name: Deploy

on:
  push:
    branches: [ main ]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2

      - name: Setup Node.js
        uses: actions/setup-node@v2
        with:
          node-version: '16'

      - name: Install dependencies
        run: npm ci

      - name: Run tests
        run: npm test

      - name: Build
        run: npm run build

      - name: Deploy to Netlify
        uses: netlify/actions/cli@master
        env:
          NETLIFY_AUTH_TOKEN: ${{ secrets.NETLIFY_AUTH_TOKEN }}
          NETLIFY_SITE_ID: ${{ secrets.NETLIFY_SITE_ID }}
        with:
          args: deploy --dir=dist --prod
```

## 7. 自定义域名设置

如果你有自己的域名，可以将其绑定到你的应用：

1. 在你的域名注册商处添加DNS记录，指向你的托管服务
2. 在托管服务中配置自定义域名

例如，在Netlify中：
- 进入你的站点设置
- 点击"Domain management"
- 点击"Add custom domain"
- 输入你的域名并按照指示完成配置

## 总结

在本章中，我们学习了如何将Vue应用部署到生产环境：

1. 构建生产版本
2. 使用静态托管服务（Netlify、Vercel、GitHub Pages）
3. 使用Docker容器化部署
4. 在传统Web服务器上部署
5. 部署前的优化（环境变量、性能优化、PWA支持）
6. 部署后的监控（错误监控、性能监控）
7. 设置CI/CD流程
8. 配置自定义域名

通过这些步骤，我们的待办事项应用现在已经可以被全球用户访问和使用了。恭喜你成功完成了这个项目！

这个项目实战系列涵盖了Vue.js应用开发的完整流程，从项目规划、脚手架搭建、功能实现、状态管理、路由配置、代码优化到最终部署。希望这些知识能帮助你在实际工作中构建出高质量的Vue应用。
