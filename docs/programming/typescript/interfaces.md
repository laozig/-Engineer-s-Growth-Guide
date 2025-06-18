# 接口 (Interfaces)

接口是 TypeScript 的核心原则之一，它专注于**代码的结构**而非具体实现。通过接口，我们可以定义对象的"形状"或"契约"，指定它必须包含哪些属性和方法。这在团队协作和代码检查中扮演着至关重要的角色。

## 1. 第一个接口

让我们从一个简单的例子开始。我们定义一个函数，它接收一个包含 `label` 属性的对象。

```typescript
function printLabel(labelledObj: { label: string }) {
  console.log(labelledObj.label);
}

let myObj = { size: 10, label: "Size 10 Object" };
printLabel(myObj);
```

类型检查器会检查 `printLabel` 的调用。它要求传入的对象至少要有一个名为 `label` 且类型为 `string` 的属性。

我们可以用接口来重写上面的例子，来描述这个要求：

```typescript
interface LabelledValue {
  label: string;
}

function printLabel(labelledObj: LabelledValue) {
  console.log(labelledObj.label);
}

let myObj = { size: 10, label: "Size 10 Object" };
printLabel(myObj);
```

`LabelledValue` 接口就像一个名字，用来描述上面例子里的要求。它代表有一个 `label` 属性且类型为 `string` 的对象。

## 2. 可选属性 (Optional Properties)

接口里的属性不全都是必需的。有些是只在某些条件下存在，或者根本就是可选的。可选属性在属性名后加上 `?` 符号。

```typescript
interface SquareConfig {
  color?: string;
  width?: number;
}

function createSquare(config: SquareConfig): { color: string; area: number } {
  let newSquare = { color: "white", area: 100 };
  if (config.color) {
    newSquare.color = config.color;
  }
  if (config.width) {
    newSquare.area = config.width * config.width;
  }
  return newSquare;
}

let mySquare = createSquare({ color: "black" });
```

可选属性的好处是，你可以预定义可能存在的属性，同时也能防止因属性不存在而导致的错误。

## 3. 只读属性 (Readonly Properties)

一些属性只能在对象刚刚创建的时候修改其值。你可以在属性名前用 `readonly` 来指定只读属性。

```typescript
interface Point {
  readonly x: number;
  readonly y: number;
}

let p1: Point = { x: 10, y: 20 };
// p1.x = 5; // 错误! x 是只读的.
```

TypeScript 还提供了 `ReadonlyArray<T>` 类型，它与 `Array<T>` 相似，只是把所有可变方法去掉了，因此可以确保数组创建后再也不能被修改。

```typescript
let a: number[] = [1, 2, 3, 4];
let ro: ReadonlyArray<number> = a;

// ro[0] = 12; // 错误!
// ro.push(5); // 错误!
// ro.length = 100; // 错误!
// a = ro; // 错误! 将 ReadonlyArray 赋值给普通 Array 是非法的
```
你可以用类型断言来覆盖它：
`a = ro as number[];`

## 4. 函数类型 (Function Types)

接口可以描述函数的类型。为了使用接口表示函数类型，我们需要给接口定义一个**调用签名**。它就像是一个只有参数列表和返回值类型的函数定义。

```typescript
interface SearchFunc {
  (source: string, subString: string): boolean;
}

let mySearch: SearchFunc;
mySearch = function(source: string, subString: string) {
  let result = source.search(subString);
  return result > -1;
}

// 参数名不需要与接口里定义的名字相匹配
let anotherSearch: SearchFunc;
anotherSearch = function(src: string, sub: string): boolean {
  let result = src.search(sub);
  return result > -1;
};
```

## 5. 可索引类型 (Indexable Types)

与使用接口描述函数类型相似，我们也可以描述那些能够"通过索引得到"的类型，比如 `a[10]` 或 `ageMap["daniel"]`。可索引类型具有一个**索引签名**，它描述了对象索引的类型和返回值类型。

TypeScript 支持两种索引签名：字符串和数字。

```typescript
interface StringArray {
  [index: number]: string;
}

let myArray: StringArray;
myArray = ["Bob", "Fred"];

let myStr: string = myArray[0];
```
这里，我们定义了 `StringArray` 接口，它具有一个索引签名。这个索引签名表示了当用 `number`去索引 `StringArray` 时会得到 `string` 类型的返回值。

## 6. 类类型 (Class Types)

接口在 TypeScript 中一个最主要的应用是强制类去符合某种契约。

```typescript
interface ClockInterface {
  currentTime: Date;
  setTime(d: Date): void;
}

class Clock implements ClockInterface {
  currentTime: Date = new Date();
  setTime(d: Date) {
    this.currentTime = d;
  }
  constructor(h: number, m: number) {}
}
```
你可以在接口中描述一个方法，在类里实现它。`implements` 关键字就是用来确保类满足特定接口的。

## 7. 接口继承 (Extending Interfaces)

和类一样，接口也可以相互继承。这让我们能够从一个接口里复制成员到另一个接口里，可以更灵活地将接口分割到可重用的模块里。

```typescript
interface Shape {
  color: string;
}

interface Square extends Shape {
  sideLength: number;
}

let square = {} as Square;
square.color = "blue";
square.sideLength = 10;
```
一个接口可以继承多个接口，创建出多个接口的合成接口。
```typescript
interface PenStroke {
  penWidth: number;
}

interface Square extends Shape, PenStroke {
  sideLength: number;
}
```

---

现在你已经掌握了接口的用法，让我们继续学习[函数](functions.md)在 TypeScript 中的应用。 