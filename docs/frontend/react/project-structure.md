# 23. 项目结构与代码组织

随着 React 应用规模的增长，如何组织文件和目录变得至关重要。一个良好、清晰的项目结构可以提高代码的可维护性、可读性和团队协作效率。

没有一个"放之四海而皆准"的完美项目结构，最佳的结构取决于项目的规模、复杂度和团队的偏好。本章我们将探讨几种常见且经过实践检验的项目结构模式。

## 初始结构 (Create React App 默认)

对于小型项目或学习项目，Create React App (CRA) 的默认结构是一个很好的起点：
```
src/
├── App.css
├── App.js
├── App.test.js
├── index.css
├── index.js
└── ...
```
你可以直接在 `src` 目录下添加你的组件文件。这种方式简单直接，但当组件数量增多时，很快就会变得混乱。

## 按文件类型分组

这是一种常见的改进方式，即将不同类型的文件放入各自的目录中。

```
src/
├── components/      # 通用、可复用的UI组件 (Button, Modal, Input...)
├── pages/           # 页面级组件 (HomePage, ProfilePage, SettingsPage...)
├── hooks/           # 自定义 Hooks (useAuth, useDebounce...)
├── utils/           # 通用工具函数 (formatDate, validators...)
├── services/        # API 请求服务 (api.js, userService.js...)
├── contexts/        # React Context (AuthContext, ThemeContext...)
├── assets/          # 图片、字体等静态资源
│   ├── images/
│   └── fonts/
├── App.js
└── index.js
```

### 优点
- **清晰直观**: 很容易找到特定类型的文件。
- **易于理解**: 对于新加入的开发者来说，这种结构一目了然。

### 缺点
- **可扩展性差**: 当项目变大时，`components` 或 `pages` 目录可能会变得非常庞大。
- **上下文切换**: 修改一个功能可能需要你在多个目录之间来回跳转（例如，在 `pages/Profile.js`, `components/Avatar.js`, `services/userApi.js` 之间切换），这会增加心智负担。

## 按功能/特性分组 (Feature-based)

这是目前在大型项目中更受推崇的模式。它将与单个功能（feature）相关的所有文件组织在一起。

```
src/
├── components/      # 真正通用的、跨功能的UI组件 (Button, Input, Layout...)
├── features/        # 按功能划分的模块
│   ├── auth/        # 认证功能
│   │   ├── components/      # 只在认证功能中使用的组件 (LoginForm, RegisterForm)
│   │   ├── hooks/           # useAuth.js
│   │   ├── services/        # authApi.js
│   │   └── index.js         # 导出该功能的公共接口 (e.g., export * from './components/LoginForm')
│   ├── profile/     # 个人资料功能
│   │   ├── components/      # (ProfileHeader, EditProfileModal)
│   │   ├── hooks/           # useProfile.js
│   │   ├── ProfilePage.js
│   │   └── index.js
│   └── posts/       # 帖子功能
│       ├── components/      # (PostList, PostItem, CreatePost)
│       ├── hooks/           # usePosts.js
│       ├── services/        # postsApi.js
│       └── index.js
├── hooks/           # 通用自定义 Hooks
├── services/        # 通用 API 配置 (axiosInstance.js)
├── lib/ or utils/   # 通用库或工具函数
├── App.js
└── index.js
```

### 优点
- **高内聚，低耦合**: 相关的文件都在一个地方，修改一个功能时，你只需要关注一个目录。
- **可扩展性强**: 添加新功能只需要创建一个新的 `features` 子目录，不会让现有结构变得混乱。
- **代码定位快**: 你知道 `profile` 相关的所有逻辑都在 `features/profile` 下。
- **便于代码分割**: 可以轻松地按功能进行代码分割。

### 缺点
- **前期规划**: 可能需要对应用的功能边界有更清晰的认识。
- **组件共享**: 需要明确区分哪些是真正的"通用"组件（放在顶层 `components`），哪些是"功能特定"组件（放在 `features/*/components`）。

## Next.js 项目结构

如果你使用像 Next.js 这样的框架，它已经为你规定了一部分核心结构，特别是 `pages`（或 `app`）目录，它负责文件系统路由。

一个典型的 Next.js 项目结构可能如下：
```
├── public/              # 静态资源
├── src/
│   ├── app/ (或 pages/) # 路由
│   │   ├── layout.js
│   │   ├── page.js
│   │   └── (dashboard)/
│   │       ├── layout.js
│   │       └── page.js
│   ├── components/      # 通用UI组件
│   ├── features/        # 按功能组织的模块 (与上面类似)
│   ├── lib/               # 工具函数、数据库客户端等
│   └── ...
├── next.config.js
└── package.json
```
在这种结构中，你仍然可以在 `src` 目录下结合使用**按功能分组**的模式来组织你的业务逻辑和 UI 组件。

## 最佳实践与建议

1.  **保持一致性**: 无论选择哪种结构，最重要的是在整个项目中保持一致。
2.  **从小处着手**: 对于小项目，从"按文件类型分组"开始完全没问题。当项目变得复杂时，再逐步重构成"按功能分组"。
3.  **创建绝对路径导入**: 使用 `jsconfig.json` (for JS) 或 `tsconfig.json` (for TS) 来配置路径别名，避免出现丑陋的相对路径导入，如 `import Button from '../../../../components/Button'`。
    ```json
    // tsconfig.json or jsconfig.json
    {
      "compilerOptions": {
        "baseUrl": "src",
        "paths": {
          "@/components/*": ["components/*"],
          "@/features/*": ["features/*"],
          "@/hooks/*": ["hooks/*"]
        }
      }
    }
    // 现在可以这样导入: import Button from '@/components/Button';
    ```
4.  **组件文件命名**:
    - 使用帕斯卡命名法 (PascalCase)，例如 `MyComponent.js`。
    - 将组件及其样式文件放在同一个文件夹中，例如：
      ```
      components/
      └── Button/
          ├── Button.js
          ├── Button.module.css
          └── index.js  (内容为: export { default } from './Button';)
      ```
      这使得导入更简洁：`import Button from '@/components/Button';`。

选择一个好的项目结构是一项重要的架构决策。**按功能分组**的模式因其出色的可扩展性和可维护性，已成为现代大型 React 应用的首选。 