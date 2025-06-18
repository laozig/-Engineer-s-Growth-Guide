# 基础类型

在 TypeScript 中，类型是核心。它们允许我们为变量、函数参数和返回值等指定期望的数据类型。本章将详细介绍 TypeScript 的所有基础类型。

## 1. 布尔值 (Boolean)

最基本的数据类型，只有 `true` 和 `false` 两个值。

```typescript
let isDone: boolean = false;
```

## 2. 数字 (Number)

和 JavaScript 一样，TypeScript 中所有的数字都是浮点数。支持十进制、十六进制、二进制和八进制字面量。

```typescript
let decimal: number = 6;
let hex: number = 0xf00d;
let binary: number = 0b1010;
let octal: number = 0o744;
```

## 3. 字符串 (String)

使用 `string` 表示文本数据类型。和 JavaScript 一样，可以使用双引号 (`"`) 或单引号 (`'`) 表示字符串。

```typescript
let color: string = "blue";
color = 'red';
```

还支持模板字符串，可以定义多行文本和内嵌表达式。

```typescript
let fullName: string = `Bob Bobbington`;
let age: number = 37;
let sentence: string = `Hello, my name is ${fullName}.

I'll be ${age + 1} years old next month.`;
```

## 4. 数组 (Array)

TypeScript 中有两种方式可以定义数组。

第一种，在元素类型后面接上 `[]`，表示由此类型元素组成的一个数组：
```typescript
let list: number[] = [1, 2, 3];
```

第二种方式是使用数组泛型，`Array<元素类型>`：
```typescript
let list: Array<number> = [1, 2, 3];
```

## 5. 元组 (Tuple)

元组类型允许你表示一个**已知元素数量和类型**的数组，各元素的类型不必相同。

```typescript
// 定义一个元组类型
let x: [string, number];

// 初始化
x = ["hello", 10]; // OK

// 初始化错误
// x = [10, "hello"]; // Error

console.log(x[0].substring(1)); // OK
// console.log(x[1].substring(1)); // Error, 'number' does not have 'substring'
```

## 6. 枚举 (Enum)

`enum` 是对 JavaScript 标准数据类型的一个补充。它为一组数值赋予友好的名字。

```typescript
enum Color {
  Red,    // 0
  Green,  // 1
  Blue    // 2
}
let c: Color = Color.Green; // c 的值为 1
```

默认情况下，`enum` 从 `0` 开始为成员编号。你也可以手动指定成员的数值。

```typescript
enum Color {
  Red = 1,
  Green = 2,
  Blue = 4
}
let c: Color = Color.Green; // c 的值为 2
```

枚举类型提供的一个便利是你可以由枚举的值得到它的名字。
```typescript
enum Color {
  Red = 1,
  Green,
  Blue
}
let colorName: string = Color[2];

console.log(colorName); // 'Green'
```

## 7. Any

有时候，我们不希望类型检查器对某个值进行检查，而是想让它直接通过编译阶段的检查。这时我们可以使用 `any` 类型。`any` 类型的变量可以被赋予任何类型的值。

```typescript
let notSure: any = 4;
notSure = "maybe a string instead";
notSure = false; // okay, definitely a boolean
```

`any` 类型会让你失去 TypeScript 带来的大部分优势，因此应该尽量避免使用它。它通常用于表示那些类型非常动态的、难以预测的数据，比如来自第三方库或用户输入的数据。

## 8. Unknown

`unknown` 是 `any` 类型对应的安全类型。与 `any` 类似，任何值都可以赋给 `unknown` 类型的变量。但是，你不能对一个 `unknown` 类型的值执行任何操作，除非你首先对它进行了**类型收窄**（narrowing）。

```typescript
let notSure: unknown = 4;

// (notSure as string).toUpperCase(); // 错误: 'notSure' is of type 'unknown'.

if (typeof notSure === "string") {
  // 在这个 if 代码块中, TypeScript 知道 notSure 是 string 类型
  console.log(notSure.toUpperCase());
}
```
使用 `unknown` 比 `any` 更安全，因为它强制你在执行操作前进行类型检查。

## 9. Void

`void` 类型有点像 `any` 的反面：它表示没有任何类型。当一个函数没有返回值时，你通常会见到其返回值类型是 `void`。

```typescript
function warnUser(): void {
  console.log("This is my warning message");
}
```
声明一个 `void` 类型的变量没有什么大用，因为你只能为它赋予 `undefined` 或 `null`。

## 10. Null 和 Undefined

在 TypeScript 里，`undefined` 和 `null` 两者各自有自己的类型，分别叫做 `undefined` 和 `null`。和 `void` 相似，它们的本身的类型用处不是很大。

```typescript
let u: undefined = undefined;
let n: null = null;
```

默认情况下 `null` 和 `undefined` 是所有类型的子类型。就是说你可以把 `null` 和 `undefined` 赋值给 `number` 类型的变量。然而，当你在 `tsconfig.json` 中指定了 `--strictNullChecks` 标记后，`null` 和 `undefined` 只能赋值给 `unknown`, `any` 和它们各自的类型。

## 11. Never

`never` 类型表示的是那些永不存在的值的类型。例如， `never` 类型是那些总是会抛出异常或根本就不会有返回值的函数表达式或箭头函数表达式的返回值类型。

```typescript
// 抛出异常的函数，永远不会有返回值
function error(message: string): never {
  throw new Error(message);
}

// 无限循环的函数，永远不会有返回值
function infiniteLoop(): never {
  while (true) {}
}
```

---

掌握了基础类型后，我们接下来将学习如何在 TypeScript 中进行[变量声明](variables.md)。 