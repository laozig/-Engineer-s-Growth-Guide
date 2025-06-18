# 类型定义文件 (`.d.ts`)

TypeScript 的一个巨大优势是可以在项目中安全地使用大量的 JavaScript 库。然而，大多数 JavaScript 库本身并不包含类型信息。为了解决这个问题，TypeScript 引入了**类型定义文件**（Declaration Files），它们的扩展名是 `.d.ts`。

一个 `.d.ts` 文件不包含任何可执行代码，它只包含类型声明。这些文件用于向 TypeScript 编译器描述一个 JavaScript 模块或库的"形状"（shape）。

## 1. 类型定义文件的作用

当你 `import` 一个 JavaScript 库时（例如 `import _ from 'lodash'`），TypeScript 编译器会寻找这个库的类型定义。它会检查：
1.  库本身是否捆绑了 `.d.ts` 文件。
2.  是否存在一个 `@types/lodash` 包，其中包含了 `lodash` 的类型定义。
3.  项目中是否存在一个手写的 `.d.ts` 文件声明了 `lodash` 模块。

如果找不到任何类型定义，TypeScript 会报错，因为它不知道这个库提供了哪些函数和变量。

## 2. 使用 DefinitelyTyped (`@types`)

在大多数情况下，你不需要自己编写类型定义文件。有一个庞大的社区项目叫做 **DefinitelyTyped**，它为数千个流行的 JavaScript 库提供了高质量的类型定义文件。

这些类型定义文件都以 `@types/` 的前缀发布在 npm 上。例如，要安装 `lodash` 的类型定义，你只需运行：

```bash
npm install --save-dev @types/lodash
```

安装完成后，你就可以在 TypeScript 项目中享受 `lodash` 的完整类型提示和自动补全了。

## 3. 编写自己的 `.d.ts` 文件

有时候，你可能会使用一个没有 `@types` 包的、或者公司内部私有的 JavaScript 库。在这种情况下，你需要自己编写类型定义文件。

### `declare` 关键字
`declare` 是编写 `.d.ts` 文件时最核心的关键字。它用于告诉 TypeScript 某个变量、函数或模块是**在其他地方定义好的**，你只需要告诉编译器它的类型是什么即可，无需提供实现。

#### 声明全局变量
假设你的页面通过 `<script>` 标签引入了一个库，它在全局 `window` 对象上创建了一个名为 `myLibrary` 的变量。

```typescript
// global.d.ts
declare const myLibrary: {
  doSomething: (param: string) => void;
  version: string;
};
```
这样，你就可以在项目中的任何地方直接使用 `myLibrary` 而不会收到编译错误。

#### 声明模块
如果你想为一个没有类型定义的 npm 包（例如，一个名为 `my-untyped-module` 的包）提供类型，你可以创建一个 `.d.ts` 文件。

```typescript
// my-untyped-module.d.ts
declare module 'my-untyped-module' {
  export function someFunction(arg: number): string;
  export const someConstant: boolean;
}
```
有了这个文件，你就可以 `import { someFunction } from 'my-untyped-module';` 并获得类型检查。

### 实践：为简单库创建类型定义

假设我们有一个 `math-lib.js` 文件：
```javascript
// math-lib.js
module.exports.add = function(a, b) {
    return a + b;
}
```

我们可以为它创建一个 `math-lib.d.ts` 文件：
```typescript
// math-lib.d.ts
export function add(a: number, b: number): number;
```

如果这个库没有导出任何东西，而是修改了全局命名空间，比如 jQuery 的 `$`：
```typescript
// jquery.d.ts
declare function $(selector: string): any;
```

## 4. 文件结构

- **对于全局库**：你可以创建一个 `global.d.ts` 或类似的文件，放在项目的任何地方（只要被 `tsconfig.json` 的 `include` 覆盖到即可）。
- **对于模块**：通常会将 `.d.ts` 文件与它所描述的 `.js` 文件放在一起。如果是为一个 npm 包提供类型，可以创建一个 `types` 目录来存放这些定义。

编写 `.d.ts` 文件是一项高级技能，但它能让你将 TypeScript 的类型安全优势扩展到任何 JavaScript 项目中。

---

现在你了解了如何与 JavaScript 库协作，下一步是将 TypeScript 应用到最流行的前端生态中：[与现代框架集成](frameworks-integration.md)。 