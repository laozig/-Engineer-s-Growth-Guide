# 模块与命名空间

随着应用程序变得越来越复杂，组织代码以保持其可维护性变得至关重要。TypeScript 提供了两种主要的方式来组织代码：**模块（Modules）** 和 **命名空间（Namespaces）**。

在现代 JavaScript 和 TypeScript 开发中，**模块是组织代码的首选方式**。

## 1. 模块 (Modules)

自 ES6 (ECMAScript 2015) 起，模块已成为 JavaScript 的标准部分。TypeScript 完全支持并推荐使用 ES 模块来组织代码。

**任何包含顶级 `import` 或 `export` 的文件都被视为一个模块。**

模块在其自身的作用域里执行，而不是在全局作用域里。这意味着在模块内部声明的变量、函数、类等在模块外部是不可见的，除非它们被明确地**导出**（export）。相反，一个模块可以从其他模块**导入**（import）它们导出的值。

### 导出 (Exporting)

我们可以使用 `export` 关键字来导出一个声明（变量、函数、类、类型别名或接口）。

```typescript
// strings.ts
export const GREETING = "Hello, World!";

export function sayHello(name: string) {
    return `Hello, ${name}!`;
}
```

### 导入 (Importing)

使用 `import` 关键字从其他模块导入想要使用的内容。

```typescript
// main.ts
import { GREETING, sayHello } from './strings';

console.log(GREETING); // "Hello, World!"
console.log(sayHello("TypeScript")); // "Hello, TypeScript!"
```

### 默认导出 (Default Exports)

每个模块还可以有一个**默认导出**。默认导出使用 `export default` 标记。

```typescript
// MyClass.ts
export default class MyClass {
    // ...
}
```

导入默认导出的语法略有不同：
```typescript
// main.ts
import MyClass from './MyClass';

let instance = new MyClass();
```

**最佳实践**：推荐在每个文件中坚持一种导出风格。要么只使用命名导出，要么只使用一个默认导出。这会使代码库的导入/导出风格保持一致。

## 2. 命名空间 (Namespaces)

命名空间是 TypeScript 特有的组织代码的方式，它早于 ES 模块标准。它的主要目的是将相关的代码组织在一起，以避免全局作用域的污染。

可以把命名空间看作是一个在全局作用域下创建的、包含了相关代码的对象。

```typescript
namespace Validation {
    export interface StringValidator {
        isAcceptable(s: string): boolean;
    }

    const lettersRegexp = /^[A-Za-z]+$/;

    export class LettersOnlyValidator implements StringValidator {
        isAcceptable(s: string) {
            return lettersRegexp.test(s);
        }
    }
}

// 在命名空间外部使用
let validators: { [s: string]: Validation.StringValidator; } = {};
validators['Letters only'] = new Validation.LettersOnlyValidator();
```
在这个例子中，所有验证相关的代码都被组织在 `Validation` 命名空间下。我们使用 `export` 关键字来决定哪些成员是对外可见的。

### 命名空间的别名

为了简化对深层嵌套命名空间的使用，可以为常用的命名空间创建别名：
```typescript
import V = Validation;
let validator = new V.LettersOnlyValidator();
```

## 3. 模块 vs. 命名空间

| 特性 | 模块 (ES Modules) | 命名空间 (Namespaces) |
| :--- | :--- | :--- |
| **标准** | JavaScript (ES6) 官方标准 | TypeScript 特有 |
| **作用域** | 文件作用域 | 全局作用域（创建一个对象） |
| **依赖关系**| 通过 `import`/`export` 显式声明 | 依赖于文件加载顺序 |
| **推荐用法**| **所有现代项目**。适用于 Web、Node.js 等所有环境。 | 遗留代码库、组织全局变量、或在不使用模块加载器的旧项目中。 |

**核心思想**：在现代 TypeScript 项目中，你应该**始终优先使用 ES 模块**。命名空间主要用于维护旧项目或处理一些特殊的全局脚本场景。

随着 ES 模块的普及，命名空间的使用场景已经越来越少。如果你正在编写一个新项目，几乎没有理由选择命名空间而不是模块。

---

正确地组织代码后，下一步是学习如何配置 TypeScript 的大脑：[`tsconfig.json` 详解](tsconfig.md)。 