# `tsconfig.json` 详解

`tsconfig.json` 文件是 TypeScript 项目的“大脑”，它位于项目的根目录，用于指定项目所需的编译器选项和需要编译的文件列表。一个项目只要包含了 `tsconfig.json` 文件，就表明它是一个 TypeScript 项目。

## 1. 初始化 `tsconfig.json`

你可以通过在项目根目录下运行 TypeScript 编译器的初始化命令来生成一个包含推荐选项的 `tsconfig.json` 文件：

```bash
tsc --init
```

这会生成一个内容详尽、带有注释的 `tsconfig.json` 文件，是学习和配置的好起点。

## 2. `tsconfig.json` 的结构

文件主要由两部分组成：`compilerOptions` 和文件包含/排除规则。

```json
{
  "compilerOptions": {
    // 编译器选项...
  },
  "include": [
    // 要编译的文件...
  ],
  "exclude": [
    // 不希望编译的文件...
  ],
  "extends": "./base.json" // 从另一个配置文件继承
}
```

## 3. 重要的编译器选项 (`compilerOptions`)

`compilerOptions` 是 `tsconfig.json` 中最核心、最复杂的部分。下面是一些最重要和最常用的选项。

### `target`
指定编译后生成的 JavaScript 代码所遵循的 ECMAScript (ES) 版本。
- **`"es5"`**: 默认值。兼容性好，可在旧版浏览器中运行。
- **`"es6"` / `"es2015"`**: 生成 ES6 代码，使用现代语法如 `class` 和箭头函数。
- **`"esnext"`**: 针对最新的 ES 功能。

**选择建议**：根据你的目标运行环境来选择。对于现代浏览器或 Node.js 环境，`"es2017"` 或更高版本是不错的选择。

### `module`
指定编译后代码使用的模块系统。
- **`"commonjs"`**: Node.js 的标准模块系统。如果你正在开发 Node.js 应用，这是首选。
- **`"esnext"` / `"es2020"`**: 使用现代 ES 模块语法（`import`/`export`）。适用于支持 ES 模块的前端项目（如使用 Vite, Webpack 等构建工具）。
- **`"none"`**: 不生成模块代码。

**选择建议**：对于 Node.js 项目使用 `"commonjs"`。对于现代前端项目，使用 `"esnext"`。

### `strict`
这是一个"元选项"，启用它（设置为 `true`）相当于启用了一组推荐的严格类型检查规则，能极大地提升代码质量。
- **`noImplicitAny`**: 不允许隐式的 `any` 类型。
- **`strictNullChecks`**: 更严格地处理 `null` 和 `undefined`。
- **`strictFunctionTypes`**: 更严格地检查函数参数类型。
- **`strictBindCallApply`**: 对 `bind`, `call`, `apply` 进行更严格的类型检查。
...等等。

**强烈建议**：**在新项目中始终将 `strict` 设置为 `true`**。这是 TypeScript 官方的推荐，也是编写健壮代码的最佳实践。

### `lib`
指定项目中可以使用的标准库定义文件。TypeScript 自带了一系列环境的声明文件（如 `DOM` API、ES6 特性等）。
- **`"dom"`**: 包含 `window`, `document` 等浏览器环境的全局变量。
- **`"es2017"`**: 包含 ES2017 的内置 API，如 `Object.values`。
- **`"webworker"`**: 包含 Web Worker 的 API。

**选择建议**：通常你不需要手动设置它。`tsc` 会根据你的 `target` 选项来推断默认的 `lib`。例如 `target` 是 `"es6"`，`lib` 会自动包含 `"dom"`, `"es6"`, `"dom.iterable"`, `"scripthost"`。

### `outDir` 和 `rootDir`
- **`outDir`**: 指定编译后 `.js` 文件的输出目录。例如 `"./dist"`。
- **`rootDir`**: 指定 TypeScript 源文件的根目录。编译器会根据 `rootDir` 的结构在 `outDir` 中生成对应的目录结构。例如 `"./src"`。

这对于保持项目结构的整洁至关重要。

### `esModuleInterop`
设置为 `true` 时，可以更好地兼容 CommonJS 和 ES 模块之间的互操作。它允许你使用 `import React from "react"` 这样的默认导入语法来导入 CommonJS 模块。

**选择建议**：**始终设置为 `true`**。这能解决大量由不同模块系统混用带来的问题。

### `paths` 和 `baseUrl`
`paths` 允许你创建路径别名，以简化模块导入路径。它需要和 `baseUrl` 配合使用。
- **`baseUrl`**: 解析非相对模块名的基准目录。通常设置为 `"."` 或 `"./src"`。
- **`paths`**: 定义路径映射。

```json
{
  "compilerOptions": {
    "baseUrl": "./src",
    "paths": {
      "@components/*": ["components/*"],
      "@utils/*": ["utils/*"]
    }
  }
}
```
这样设置后，你就可以这样导入模块了：
`import Button from '@components/Button';`

## 4. 文件包含/排除规则

### `include`
一个 glob 模式数组，指定需要编译的文件。
`"include": ["src/**/*"]` // 包含 src 目录下的所有文件

### `exclude`
一个 glob 模式数组，指定不希望被编译的文件或目录。`node_modules` 总是默认被排除。
`"exclude": ["node_modules", "**/*.test.ts"]`

### `files`
一个文件名数组，用于指定要编译的单个文件列表。一般不常用，`include` 更灵活。

---

至此，你已经掌握了 TypeScript 项目的配置核心。接下来，我们将进入"高级实践与生态"部分，学习[装饰器 (Decorators)](decorators.md)。 