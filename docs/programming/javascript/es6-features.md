# 现代 JavaScript 特性指南 (ES6+)

<div align="center">
  <img src="../../../assets/programming/es6-features.png" alt="ES6+ Features" width="250">
</div>

> ES6 (ECMAScript 2015) 是 JavaScript 语言的一次重大飞跃，后续版本更是不断为其增添新的活力。掌握这些现代特性是提升代码质量、开发效率和可读性的关键。本指南将系统性地介绍这些核心特性，并解释它们在实际开发中的应用场景。

## 目录

1.  [**核心语法改进**](#1-核心语法改进)
    -   [`let` 与 `const`](#let-与-const)
    -   [箭头函数](#箭头函数)
    -   [模板字符串](#模板字符串)
    -   [解构赋值](#解构赋值)
    -   [函数默认参数](#函数默认参数)
    -   [展开语法 (...) 与剩余参数 (...)](#展开语法--与-剩余参数-)
2.  [**代码组织与结构**](#2-代码组织与结构)
    -   [类 (Classes)](#类-classes)
    -   [模块 (Modules): `import` / `export`](#模块-modules-import--export)
3.  [**强大的异步编程**](#3-强大的异步编程)
    -   [Promise](#promise)
    -   [Async/Await](#asyncawait)
4.  [**数据结构与集合**](#4-数据结构与集合)
    -   [Set](#set)
    -   [Map](#map)
5.  [**新增实用工具**](#5-新增实用工具)
    -   [可选链 (?.)](#可选链-)
    -   [空值合并运算符 (??)](#空值合并运算符-)

---

## 1. 核心语法改进

这些特性极大地改善了日常编码的体验和代码的可读性。

### `let` 与 `const`
`let` 和 `const` 提供了块级作用域，解决了 `var` 的变量提升和作用域混乱问题。

-   **ES5 `var` 的问题**:
    ```javascript
    for (var i = 0; i < 3; i++) {
      setTimeout(function() { console.log(i); }, 100); // 输出三次 3
    }
    ```
-   **ES6+ `let` 的解决方案**:
    ```javascript
    for (let i = 0; i < 3; i++) {
      setTimeout(() => console.log(i), 100); // 正确输出 0, 1, 2
    }
    ```
> **最佳实践**: 始终使用 `const` 声明，除非变量需要被重新赋值，此时才用 `let`。

### 箭头函数
箭头函数以其简洁的语法和对 `this` 的词法绑定而著称。

-   **ES5 `this` 的痛点**:
    ```javascript
    function Timer() {
      this.seconds = 0;
      var self = this; // 需要一个临时变量来保存 this
      setInterval(function() {
        self.seconds++;
      }, 1000);
    }
    ```
-   **ES6+ 箭头函数的优雅**:
    ```javascript
    function Timer() {
      this.seconds = 0;
      setInterval(() => {
        this.seconds++; // `this` 指向 Timer 实例
      }, 1000);
    }
    ```

### 模板字符串
使用反引号 (`` ` ``) 可以轻松创建多行字符串和进行变量插值。

-   **ES5 字符串拼接**:
    ```javascript
    var name = "Alice";
    var message = "Hello, " + name + "!\nWelcome to our website.";
    ```
-   **ES6+ 模板字符串**:
    ```javascript
    const name = "Alice";
    const message = `Hello, ${name}!
Welcome to our website.`;
    ```

### 解构赋值
让你能够从数组或对象中便捷地提取值。

-   **对象解构**:
    ```javascript
    const user = { id: 1, name: "Bob", email: "bob@example.com" };
    const { name, email } = user;
    console.log(`${name}'s email is ${email}`);
    ```
-   **数组解构**:
    ```javascript
    const [first, second] = ["Apple", "Banana", "Cherry"];
    console.log(first); // "Apple"
    ```

### 函数默认参数
```javascript
function createApiRequest(url, method = 'GET', timeout = 5000) {
  // ...
}
createApiRequest('/users'); // method 和 timeout 使用默认值
```

### 展开语法 (...) 与剩余参数 (...)
虽然都用 `...`，但它们的应用场景不同。

-   **展开语法**: 将数组或对象"展开"成独立的元素。常用于创建数组或对象的浅拷贝和合并。
    ```javascript
    const arr1 = [1, 2];
    const arr2 = [...arr1, 3, 4]; // [1, 2, 3, 4]

    const obj1 = { a: 1 };
    const obj2 = { ...obj1, b: 2 }; // { a: 1, b: 2 }
    ```
-   **剩余参数**: 将多个独立的函数参数收集到一个数组中。
    ```javascript
    function logMessages(source, ...messages) {
      console.log(`[${source}]`, ...messages);
    }
    logMessages("API", "User logged in", "Request successful");
    ```

## 2. 代码组织与结构

### 类 (Classes)
ES6 的 `class` 是基于原型继承的语法糖，让对象和继承的写法更加清晰。

```javascript
class Animal {
  constructor(name) {
    this.name = name;
  }
  speak() {
    console.log(`${this.name} makes a noise.`);
  }
}

class Dog extends Animal {
  speak() { // 方法重写
    console.log(`${this.name} barks.`);
  }
}

const dog = new Dog('Rex');
dog.speak(); // "Rex barks."
```

### 模块 (Modules): `import` / `export`
ESM (ECMAScript Modules) 成为浏览器和 Node.js 的标准模块系统，让代码的复用和组织变得前所未有的简单。

-   **`utils.js` (导出)**:
    ```javascript
    export const PI = 3.14;
    export default function double(x) {
      return x * 2;
    }
    ```
-   **`main.js` (导入)**:
    ```javascript
    import double, { PI } from './utils.js';

    console.log(PI);        // 3.14
    console.log(double(10)); // 20
    ```
> `export default` 导出一个默认值，`export` 导出命名值。

## 3. 强大的异步编程

### Promise
Promise 是处理异步操作的利器，它将"回调地狱"转变为链式调用。

```javascript
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

delay(1000)
  .then(() => console.log('1 second passed'))
  .then(() => delay(500))
  .then(() => console.log('1.5 seconds passed'))
  .catch(err => console.error(err));
```

### Async/Await
`async/await` 是构建在 Promise 之上的语法糖，让异步代码的写法如同步代码般直观。

```javascript
async function getUserData(userId) {
  try {
    const response = await fetch(`https://api.example.com/users/${userId}`);
    if (!response.ok) throw new Error('User not found');
    
    const userData = await response.json();
    console.log(userData.name);
  } catch (error) {
    console.error(`Error fetching user: ${error.message}`);
  }
}

getUserData(1);
```
> **最佳实践**: 始终在 `async` 函数中使用 `try...catch` 块来捕获潜在的错误。

## 4. 数据结构与集合

### Set
`Set` 对象允许你存储任何类型的唯一值，无论是原始值还是对象引用。

```javascript
const numbers = [1, 2, 2, 3, 4, 3, 5];
const uniqueNumbers = [...new Set(numbers)]; // [1, 2, 3, 4, 5]
```

### Map
`Map` 对象保存键值对，并且能够记住键的原始插入顺序。任何值（对象或原始值）都可以作为一个键或一个值。

```javascript
const userRoles = new Map();
const user1 = { name: 'Alice' };
const user2 = { name: 'Bob' };

userRoles.set(user1, 'Admin');
userRoles.set(user2, 'Editor');

console.log(userRoles.get(user1)); // "Admin"
```

## 5. 新增实用工具

### 可选链 (?.)
当访问深层嵌套的对象属性时，不再需要冗长的空值检查。
```javascript
const user = {
  // profile: { address: { city: 'New York' } }
};
const city = user?.profile?.address?.city ?? 'Unknown'; // city is "Unknown"
```

### 空值合并运算符 (??)
只有当左侧表达式的值为 `null` 或 `undefined` 时，才返回右侧的默认值。这与 `||` 不同，`||` 会在左侧为任何 "falsy" 值（如 `0`, `''`, `false`）时返回右侧值。

```javascript
let volume = 0;
const setting1 = volume || 50; // 50 (不正确，0被当成falsy)
const setting2 = volume ?? 50; // 0 (正确，0不是null或undefined)
``` 