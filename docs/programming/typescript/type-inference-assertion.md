# 类型推断与类型断言

TypeScript 的一个核心特性是它的类型系统。本章将探讨 TypeScript 如何在没有明确类型注解的情况下自动推断类型，以及当我们比编译器更了解类型时，如何使用类型断言来“指导”编译器。

## 1. 类型推断 (Type Inference)

在 TypeScript 中，如果你没有为变量提供一个明确的类型注解，编译器会根据变量的初始值来**推断**其类型。

### 基础推断
```typescript
let x = 3; // TypeScript 推断 x 的类型是 'number'
// x = "hello"; // 错误: 不能将类型 'string' 赋值给类型 'number'

let s = "hello"; // TypeScript 推断 s 的类型是 'string'
```
这就是所谓的类型推断。这种机制可以让我们在享受类型安全的同时，减少需要编写的样板代码。

### 最佳通用类型 (Best Common Type)
当需要从多个类型中推断出一个类型时，TypeScript 会考虑所有候选类型，并试图找到一个能兼容所有候选类型的"最佳通用类型"。

```typescript
let arr = [0, 1, null]; // 推断类型为 (number | null)[]
```
在这个例子中，`arr` 的元素包含 `number` 和 `null`，所以 TypeScript 推断出数组的类型是 `(number | null)[]`。

### 上下文类型 (Contextual Typing)
类型推断也可能按照"从上到下"的方向进行，这被称为"上下文类型"。当一个表达式的类型可以从其所在的位置推断出来时，就会发生这种情况。

```typescript
window.onmousedown = function (mouseEvent) {
    // mouseEvent 被推断为 MouseEvent 类型
    console.log(mouseEvent.button);
};
```
在这个例子中，TypeScript 编译器知道 `window.onmousedown` 的值应该是一个函数，且该函数接收一个 `MouseEvent` 类型的参数。因此，`mouseEvent` 参数的类型被自动推断了出来。

## 2. 类型断言 (Type Assertions)

有时候，你会比 TypeScript 更了解某个值的类型。在这种情况下，你可以使用**类型断言**来告诉编译器某个值的确切类型。

类型断言好比其他语言里的类型转换，但是它不进行特殊的数据检查和解构。它没有运行时影响，只在编译阶段起作用。TypeScript 会假设你，程序员，已经进行了必须的检查。

类型断言有两种形式。

### "尖括号" 语法
```typescript
let someValue: any = "this is a string";

let strLength: number = (<string>someValue).length;
```

### `as` 语法
```typescript
let someValue: any = "this is a string";

let strLength: number = (someValue as string).length;
```
两种形式是等价的。然而，当你在 TypeScript 里使用 JSX 时，只有 `as` 语法是被允许的，因为它不会与 JSX 的语法产生混淆。因此，**推荐在所有情况下都使用 `as` 语法**。

### 类型断言与 `unknown`
`unknown` 类型是 `any` 的安全替代品。当你需要处理一个不确定类型的值时，`unknown` 强制你必须先进行某种形式的类型检查，然后才能使用它。类型断言是进行这种"检查"的一种方式。

```typescript
async function fetchData(): Promise<unknown> {
  const response = await fetch('/api/data');
  return await response.json();
}

interface User {
  name: string;
  email: string;
}

const data = await fetchData();

// 我们"断言"data是User类型，因为我们从API文档中知道它应该是
const user = data as User; 

console.log(user.name);
```

**警告**：类型断言是一种强大的工具，但它也可能导致运行时错误。编译器不会验证你的断言是否正确。如果你错误地断言了一个类型，可能会在运行时遇到意外的 `undefined` 或 `null` 值，从而导致程序崩溃。请仅在确信类型正确时使用它。

---

了解了类型推断和断言后，我们来学习如何组合类型，即[联合类型与交叉类型](union-intersection-types.md)。 