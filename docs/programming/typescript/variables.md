# 变量声明与作用域

在现代 JavaScript (ES6+) 和 TypeScript 中，变量声明主要使用 `let` 和 `const`。虽然 `var` 依然可用，但由于其作用域规则容易引发问题，通常不推荐使用。

## 1. `let` 声明

`let` 声明的是一个**块级作用域**的局部变量，可以选择性地将其初始化为一个值。

### 块级作用域 (Block Scoping)

"块"是指被大括号 `{}` 包围起来的区域，例如 `if` 语句、`for` 循环、或者直接用 `{}` 创建的代码块。`let` 和 `const` 声明的变量只在它们所在的块和子块中可用。

```typescript
function f(input: boolean) {
    let a = 100;

    if (input) {
        // 'b' 在 if 块中是可见的
        let b = a + 1;
        return b;
    }

    // 错误: 'b' 在这里是不可见的，因为它属于 if 块的作用域
    // return b; 
}
```

### 重复声明

与 `var` 不同，`let` 在同一个作用域内不允许重复声明同一个变量。

```typescript
let x = 1;
// let x = 2; // 错误: 不能在同一作用域内重复声明 'x'
```

## 2. `const` 声明

`const` 是 `let` 的一个增强，它也具有块级作用域，但它声明的变量是一个"常量"，即其引用**不可更改**。

### 不可重新赋值

使用 `const` 声明变量时，必须同时进行初始化，并且之后不能再给它赋新的值。

```typescript
const numLivesForCat = 9;
// numLivesForCat = 10; // 错误: 不能对一个常量进行赋值

const kitty = {
    name: "Aurora",
    numLives: numLivesForCat,
};

// 错误: 不能改变常量的引用
// kitty = {
//     name: "Danielle",
//     numLives: numLivesForCat
// };

// 注意: 可以修改常量引用的对象的内部状态
kitty.name = "Rory";
kitty.numLives--;
```
正如上面例子所示，`const` 保证的是变量的引用不变。如果 `const` 变量引用的是一个对象，那么对象内部的属性是可以修改的。

## 3. `let` vs. `const`

最佳实践是**默认使用 `const`**，只有当你明确知道一个变量的值需要被改变时，才使用 `let`。这能增强代码的可预测性，因为你知道一个 `const` 声明的变量不会被重新赋值。

## 4. `var` 声明 (不推荐)

`var` 声明在 JavaScript 中存在已久，但它有一些令人困惑的特性，这也是为什么在现代代码中推荐使用 `let` 和 `const`。

### 函数作用域

`var` 声明的变量是**函数作用域**或**全局作用域**，而不是块级作用域。这意味着变量在整个函数内部都是可见的，无论它在哪个块中声明。

```typescript
function varTest() {
    var x = 1;
    if (true) {
        var x = 2;  // 这里的 x 和外面的 x 是同一个变量
        console.log(x);  // 2
    }
    console.log(x);  // 2
}
```

### 变量提升 (Hoisting)

`var` 声明的变量会被"提升"到其作用域的顶部。这意味着你可以在声明之前使用它，尽管它的值会是 `undefined`。

```typescript
console.log(myVar); // 输出: undefined
var myVar = 5;
```
而 `let` 和 `const` 虽然也有提升的概念，但在声明之前访问它们会抛出一个 `ReferenceError`，这被称为"暂时性死区"（Temporal Dead Zone），能帮助我们避免很多潜在的 bug。

## 5. 解构 (Destructuring)

TypeScript 也支持解构，这是一种从数组或对象中提取数据的便捷方式。

### 数组解构
```typescript
let input = [1, 2];
let [first, second] = input;
console.log(first); // 1
console.log(second); // 2
```

### 对象解构
```typescript
let o = {
    a: "foo",
    b: 12,
    c: "bar"
};
let { a, b } = o;

console.log(a); // "foo"
console.log(b); // 12
```
解构也可以和类型注解一起使用：
```typescript
let { a, b }: { a: string, b: number } = o;
```

---

理解了变量声明后，下一步是学习 TypeScript 中非常重要的概念：[接口 (Interfaces)](interfaces.md)。 