# TypeScript 简介与安装

## 1. 什么是 TypeScript？

TypeScript 是由微软开发和维护的一种开源编程语言。它是 JavaScript 的一个**严格超集**，意味着任何有效的 JavaScript 代码也是有效的 TypeScript 代码。TypeScript 在 JavaScript 的基础上添加了**静态类型系统**、类、接口等面向对象编程的特性。

它的主要目标是提高大型应用程序的开发效率和代码质量。通过在编译时进行类型检查，TypeScript 可以在代码运行前发现并修复大量潜在错误。

### TypeScript 与 JavaScript 的关系

可以把 TypeScript 和 JavaScript 的关系看作是 `Sass` 和 `CSS` 的关系。我们编写 TypeScript 代码（`.ts` 文件），然后使用 TypeScript 编译器（`tsc`）将其转换为纯粹的 JavaScript 代码（`.js` 文件），最终在浏览器或 Node.js 环境中运行的是编译后的 JavaScript。

这个编译过程确保了最终产物在任何支持 JavaScript 的地方都能运行，同时让开发者在编码阶段享受到静态类型的优势。

```mermaid
graph LR
    A[TypeScript 代码 (.ts)] -- tsc 编译器 --> B[JavaScript 代码 (.js)];
    B -- 在浏览器或Node.js中运行 --> C[应用程序];
```

## 2. 为什么选择 TypeScript？

- **类型安全**：这是 TypeScript 最核心的特性。它可以在编码阶段就发现类型不匹配的错误，避免了大量在运行时才会暴露的 `undefined is not a function` 或 `Cannot read property 'x' of null` 等经典 JavaScript 错误。
- **代码可读性和可维护性**：类型定义就像是代码的文档。当您看到一个函数签名时，可以立刻明白它期望接收什么样的数据以及会返回什么样的数据，这极大地降低了维护成本和团队协作的难度。
- **顶级的工具支持**：得益于静态类型系统，TypeScript 可以提供无与伦比的开发体验，包括精确的自动补全、智能的代码导航、安全的重构等。VS Code 作为微软自家的编辑器，对 TypeScript 的支持更是天衣无缝。
- **拥抱最新标准**：TypeScript 团队积极跟进 ECMAScript (ES) 的最新标准，并将其快速集成到语言中。这意味着您可以使用最新的 JavaScript 特性，并将其编译到旧版本浏览器兼容的代码。
- **逐步采用**：您可以将现有 JavaScript 项目逐步迁移到 TypeScript。只需将文件扩展名从 `.js` 改为 `.ts`，然后逐步添加类型即可。

## 3. 设置开发环境

要开始使用 TypeScript，您需要安装 `Node.js` 和 `npm` (Node Package Manager)。

### 步骤 1: 安装 Node.js

如果您尚未安装 Node.js，请访问 [Node.js 官方网站](https://nodejs.org/) 下载并安装LTS（长期支持）版本。安装过程会自动包含 `npm`。

可以通过以下命令验证安装是否成功：
```bash
node -v
# v18.17.0 或更高版本

npm -v
# 9.6.7 或更高版本
```

### 步骤 2: 全局安装 TypeScript 编译器

使用 `npm` 全局安装 TypeScript。这样您就可以在终端的任何位置使用 `tsc` 命令。

```bash
npm install -g typescript
```

安装完成后，通过以下命令验证：
```bash
tsc -v
# Version 5.3.3 或更高版本
```

### 步骤 3: 编写并编译第一个 TypeScript 文件

1.  创建一个名为 `hello.ts` 的文件：

    ```typescript
    // hello.ts
    function greet(name: string) {
      console.log(`Hello, ${name}!`);
    }

    greet("World");
    ```

2.  在终端中，使用 `tsc` 命令编译这个文件：

    ```bash
    tsc hello.ts
    ```

    执行后，您会发现同目录下生成了一个 `hello.js` 文件，内容如下：

    ```javascript
    // hello.js
    function greet(name) {
      console.log("Hello, ".concat(name, "!"));
    }
    greet("World");
    ```

3.  使用 Node.js 运行编译后的 JavaScript 文件：

    ```bash
    node hello.js
    # 输出: Hello, World!
    ```

至此，您已经成功搭建了 TypeScript 开发环境，并完成了第一个程序的编写、编译和运行。

---

接下来，我们将深入学习 TypeScript 的[基础类型](basic-types.md)。 