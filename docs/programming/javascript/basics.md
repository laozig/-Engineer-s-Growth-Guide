# JavaScript 核心基础指南

<div align="center">
  <img src="../../../assets/programming/javascript-basics.png" alt="JavaScript Basics" width="250">
</div>

> JavaScript 是 Web 的语言，其基础坚实与否，直接决定了您能走多远。本指南将深入探讨JavaScript的核心概念，从变量、数据类型到现代异步编程，为您构建坚实的知识体系。

## 目录

1.  [**变量声明：var, let, const**](#1-变量声明var-let-const)
2.  [**数据类型**](#2-数据类型)
    -   [基本类型](#基本类型)
    -   [引用类型](#引用类型)
    -   [类型检查与转换](#类型检查与转换)
3.  [**运算符**](#3-运算符)
4.  [**控制流**](#4-控制流)
5.  [**函数：JavaScript的基石**](#5-函数javascript的基石)
    -   [函数声明 vs 函数表达式](#函数声明-vs-函数表达式)
    -   [箭头函数 (ES6)](#箭头函数-es6)
    -   [参数处理](#参数处理)
6.  [**对象与数组**](#6-对象与数组)
    -   [对象常用操作](#对象常用操作)
    -   [数组常用方法](#数组常用方法)
7.  [**作用域、闭包与 `this`**](#7-作用域闭包与-this)
    -   [作用域与作用域链](#作用域与作用域链)
    -   [闭包](#闭包)
    -   [`this` 关键字](#this-关键字)
8.  [**现代异步编程**](#8-现代异步编程)
    -   [回调函数](#回调函数)
    -   [Promise](#promise)
    -   [Async/Await](#asyncawait)

---

## 1. 变量声明：var, let, const

在现代 JavaScript (ES6+) 中，我们主要使用 `let` 和 `const`。

-   **`const` (常量)**：用于声明一个值不会被重新赋值的变量。这是首选的声明方式。
-   **`let` (变量)**：用于声明一个值将来可能被改变的变量。
-   **`var` (旧方式)**：存在变量提升和函数作用域问题，**在现代开发中应避免使用**。

```javascript
const framework = "React"; // 声明一个常量
let version = 18;        // 声明一个变量
version = 18.2;          // 变量可以被重新赋值

// framework = "Vue"; // TypeError: Assignment to constant variable.
```
> **最佳实践**：默认使用 `const`，只有当确定变量需要被重新赋值时，才使用 `let`。

## 2. 数据类型

### 基本类型 (Primitives)
基本类型的值是不可变的，直接存储在栈内存中。

-   **String**: `let name = "Alice";`
-   **Number**: `let age = 25;`
-   **Boolean**: `let isAdmin = true;`
-   **null**: `let user = null;` (表示"无"这个对象)
-   **undefined**: `let address;` (表示未定义)
-   **Symbol**: `const id = Symbol('unique');`
-   **BigInt**: `const bigNumber = 12345678901234567890n;`

### 引用类型 (Objects)
引用类型的值是对象，存储在堆内存中，变量持有的是指向该对象的引用。

-   **Object**: `const person = { name: "Bob", age: 30 };`
-   **Array**: `const numbers = [1, 2, 3];`
-   **Function**: `const greet = () => console.log("Hello");`
-   **Date**, **RegExp** 等。

### 类型检查与转换
```javascript
// 使用 typeof 检查类型
console.log(typeof 123);           // "number"
console.log(typeof "hello");       // "string"
console.log(typeof []);            // "object" (注意：数组也是对象)
console.log(typeof null);          // "object" (这是一个历史悠久的bug)

// 字符串转数字
const countStr = "100";
const countNum = Number(countStr); // 100
const countNum2 = +countStr;       // 100 (更简洁的写法)

// 数字转字符串
const total = 500;
const totalStr = String(total);    // "500"
const totalStr2 = total + "";      // "500"
```

## 3. 运算符
JavaScript 提供了丰富的运算符，其中一些在现代JS中尤为重要。

- **严格相等**: `===` 和 `!==`。它们不会进行类型转换，是比较值的首选。
- **逻辑运算符**: `&&` (与), `||` (或)。
- **空值合并运算符 (??)**: `const name = userInput ?? "Guest";` (只有当 `userInput` 是 `null` 或 `undefined` 时，才会使用 "Guest")。
- **可选链运算符 (?.)**: `const city = user?.address?.city;` (如果 `user` 或 `address` 是 `null` 或 `undefined`，表达式会短路并返回 `undefined`，而不会报错)。

```javascript
console.log(10 === "10"); // false (类型不同)
console.log(10 == "10");  // true (不推荐，会发生类型转换)

const response = { data: { user: { name: "Carol" } } };
const userName = response.data?.user?.name; // "Carol"

const maybeNull = null;
const value = maybeNull ?? "default value"; // "default value"
```

## 4. 控制流
`if/else`, `switch`, `for`循环和`while`循环是标准的控制流语句。

```javascript
const scores = [85, 92, 78, 65, 95];
let gradeA_Count = 0;

for (const score of scores) { // for...of 循环是遍历数组的推荐方式
  if (score >= 90) {
    gradeA_Count++;
  }
}
console.log(`有 ${gradeA_Count} 个学生获得了 A。`); // "有 2 个学生获得了 A。"
```

## 5. 函数：JavaScript的基石

### 函数声明 vs 函数表达式
```javascript
// 函数声明 (会被提升)
function add(a, b) {
  return a + b;
}

// 函数表达式 (不会被提升)
const subtract = function(a, b) {
  return a - b;
};
```

### 箭头函数 (ES6)
箭头函数提供了更简洁的语法，并且不绑定自己的 `this`。
```javascript
// 传统函数表达式
const square = function(x) {
  return x * x;
};

// 箭头函数
const squareArrow = (x) => x * x;

// 带多个参数
const multiply = (a, b) => {
  return a * b;
};
```

### 参数处理
```javascript
// 默认参数
function greet(name = "Guest") {
  console.log(`Hello, ${name}!`);
}

// 剩余参数 (...)
function sum(...numbers) {
  return numbers.reduce((total, num) => total + num, 0);
}
sum(1, 2, 3, 4); // 10
```

## 6. 对象与数组

### 对象常用操作
```javascript
const user = { name: "David", age: 42, city: "New York" };

// 解构赋值
const { name, age } = user;

// 展开语法 (...) 创建副本
const userCopy = { ...user, city: "London" };

// 获取键和值
const keys = Object.keys(user);       // ["name", "age", "city"]
const values = Object.values(user);   // ["David", 42, "New York"]
const entries = Object.entries(user); // [["name", "David"], ...]
```

### 数组常用方法
`map`, `filter`, `reduce` 是处理数组时最强大的三个方法。
```javascript
const numbers = [1, 2, 3, 4, 5];

// .map(): 创建一个新数组，其中每个元素都是回调函数的结果
const doubled = numbers.map(n => n * 2); // [2, 4, 6, 8, 10]

// .filter(): 创建一个新数组，其中包含所有通过测试的元素
const evens = numbers.filter(n => n % 2 === 0); // [2, 4]

// .reduce(): 对数组中的每个元素执行一个 "reducer" 函数，将其减少为单个值
const total = numbers.reduce((sum, n) => sum + n, 0); // 15
```

## 7. 作用域、闭包与 `this`

### 作用域与作用域链
作用域决定了变量的可访问性。ES6的 `let` 和 `const` 引入了块级作用域。当查找一个变量时，JavaScript 会从当前作用域开始，沿着作用域链向上查找，直到找到该变量或到达全局作用域。

### 闭包
闭包是指一个函数能够"记住"并访问其词法作用域，即使该函数在其词法作用域之外执行。
```javascript
function createCounter() {
  let count = 0;
  return function() {
    count++;
    return count;
  };
}

const counter1 = createCounter();
console.log(counter1()); // 1
console.log(counter1()); // 2
```

### `this` 关键字
`this` 的值在函数被调用时确定。
- **全局上下文**: `this` 指向全局对象 (`window` 或 `global`)。
- **函数调用**: `this` 指向全局对象 (非严格模式)。
- **方法调用**: `user.sayHi()`，`this` 指向 `user` 对象。
- **箭头函数**: `this` 继承自其父级作用域。

> **注意**：箭头函数解决了传统函数中 `this` 指向不明确的常见问题，在回调函数中尤其有用。

## 8. 现代异步编程
JavaScript 是单线程的，通过异步操作来处理耗时任务（如网络请求）。

### 回调函数
早期的异步编程模式，容易导致"回调地狱"。
```javascript
// 回调地狱示例
fs.readFile('file1.txt', (err, data1) => {
  fs.readFile('file2.txt', (err, data2) => {
    // ...
  });
});
```

### Promise
Promise 对象代表一个异步操作的最终完成或失败。它有三种状态：`pending`（进行中）、`fulfilled`（已成功）和 `rejected`（已失败）。

```javascript
fetch('https://api.example.com/data')
  .then(response => response.json())
  .then(data => console.log(data))
  .catch(error => console.error('Error:', error));
```

### Async/Await
`async/await` 是建立在 Promise 之上的语法糖，让异步代码看起来像同步代码一样直观。
```javascript
async function fetchData() {
  try {
    const response = await fetch('https://api.example.com/data');
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    const data = await response.json();
    console.log(data);
  } catch (error) {
    console.error('Fetch error:', error);
  }
}

fetchData();
```
> **最佳实践**：在现代JavaScript项目中，应优先使用 `async/await` 来处理异步操作。 