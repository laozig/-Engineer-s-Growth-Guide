# 泛型 (Generics)

软件工程的一个主要部分是建立可重用、可组合的组件。能够处理多种数据类型而不是单一数据类型的组件将为我们提供更强的灵活性。

在 TypeScript 中，**泛型（Generics）** 就是用来创建可重用组件的工具。一个组件可以支持多种类型的数据，这样用户就可以以自己的数据类型来使用组件。

## 1. 泛型 "Hello World"

让我们从一个简单的"恒等函数"开始。这个函数会返回任何传入它的值。

如果不使用泛型，我们可能会这样写：
```typescript
function identity(arg: any): any {
    return arg;
}
```
使用 `any` 类型会导致函数丢失类型信息。我们传入一个 `number` 类型，返回的却是 `any` 类型。

现在，我们使用泛型来重写这个函数：
```typescript
function identity<T>(arg: T): T {
    return arg;
}
```
我们给 `identity` 函数添加了**类型变量** `T`。`T` 帮助我们捕获用户传入的类型（比如 `number`），然后我们就可以使用这个类型。之后，我们就可以在参数和返回值中使用它了。现在这个函数变得类型安全了。

我们可以用两种方式来调用它：

### 1. 明确指定类型
```typescript
let output = identity<string>("myString"); // output 的类型是 'string'
```
这里我们明确地将 `T` 指定为 `string`。

### 2. 类型推断
```typescript
let output = identity("myString"); // output 的类型是 'string'
```
编译器会根据传入的参数自动地确定 `T` 的类型，这个过程被称为**类型推断**。

## 2. 使用泛型变量

使用泛型时，你会发现编译器会提示你在函数体内不能使用某些方法，因为它不确定 `T` 到底是什么类型。

```typescript
function loggingIdentity<T>(arg: T): T {
    // console.log(arg.length); // 错误: T 不一定有 .length 属性
    return arg;
}
```
但是，如果我们传入一个数组，情况就不一样了：
```typescript
function loggingIdentityArray<T>(arg: T[]): T[] {
    console.log(arg.length); // OK: 数组有 .length 属性
    return arg;
}
// 或者
function loggingIdentityArray2<T>(arg: Array<T>): Array<T> {
    console.log(arg.length); // OK
    return arg;
}
```
这说明我们可以把泛型变量 `T` 当作类型的一部分来使用，从而创建出更复杂的类型。

## 3. 泛型类型 (Generic Types)

我们可以创建泛型接口、泛型类或泛型函数类型。

### 泛型函数类型
```typescript
// 定义一个泛型函数类型
let myIdentity: <U>(arg: U) => U = identity;
```
这里的 `U` 只是一个不同的类型变量名，它和函数本身的类型变量 `T` 没有关系。

### 泛型接口
```typescript
interface GenericIdentityFn<T> {
    (arg: T): T;
}

function identity<T>(arg: T): T {
    return arg;
}

let myIdentity: GenericIdentityFn<number> = identity;
```
在这个例子里，我们把泛型参数提前到接口名上。这让接口的所有其他成员都能访问这个类型参数。

## 4. 泛型类 (Generic Classes)

泛型类和泛型接口差不多。
```typescript
class GenericNumber<T> {
    zeroValue: T;
    add: (x: T, y: T) => T;
}

let myGenericNumber = new GenericNumber<number>();
myGenericNumber.zeroValue = 0;
myGenericNumber.add = function(x, y) { return x + y; };
```
这个例子有点刻意，但你可以看到类可以有一个泛型类型 `T`。`GenericNumber` 类只能处理 `number` 类型，但我们可以让它支持任何类型。

## 5. 泛型约束 (Generic Constraints)

在某些情况下，我们希望限制泛型可以接受的类型范围。例如，我们想访问一个属性 `.length`，但编译器不知道每个类型都有这个属性。这时，我们就需要使用**泛型约束**。

我们定义一个接口来描述约束条件。创建一个包含我们想要约束的属性的接口。
```typescript
interface Lengthwise {
    length: number;
}

function loggingIdentityWithConstraint<T extends Lengthwise>(arg: T): T {
    console.log(arg.length);  // 现在我们可以确定 arg 有 .length 属性
    return arg;
}
```
现在这个泛型函数被约束了，它不再对所有类型开放，而是要求类型必须带有 `.length` 属性。
```typescript
// loggingIdentityWithConstraint(3);  // 错误, number 没有 .length 属性
loggingIdentityWithConstraint({length: 10, value: 3}); // OK
```

---

理解了泛型后，下一步是深入学习 TypeScript 的[类型推断与断言](type-inference-assertion.md)。 