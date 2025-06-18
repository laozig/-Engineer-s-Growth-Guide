# 函数 (Functions)

函数是任何应用程序的基础，它帮助我们将代码逻辑封装成可重用的块。在 TypeScript 中，我们可以为函数的输入（参数）和输出（返回值）添加类型，从而创建出健壮且易于理解的函数。

## 1. 为函数添加类型

我们可以为函数的参数和返回值添加明确的类型注解。

```typescript
// 命名函数
function add(x: number, y: number): number {
  return x + y;
}

// 匿名函数 (函数表达式)
let myAdd = function(x: number, y: number): number {
  return x + y;
};
```
在上面的例子中，我们为参数 `x` 和 `y` 以及函数的返回值都指定了 `number` 类型。如果函数没有返回值，我们可以使用 `void` 类型。

## 2. 函数类型表达式

我们也可以用"函数类型表达式"来定义一个持有函数的变量的类型。

```typescript
let myAdd: (x: number, y: number) => number;

myAdd = function(x: number, y: number): number {
  return x + y;
};

// myAdd = function(x: string, y: string): number { // 错误！类型不匹配
//   return x.length + y.length;
// };
```
这种写法 `(x: number, y: number) => number` 就是函数类型表达式，它定义了参数类型和返回值类型。只要一个函数签名与之兼容，就可以赋值给 `myAdd`。

## 3. 可选参数和默认参数

在 TypeScript 里，函数的所有参数都被认为是**必需的**。然而，我们可以通过在参数名后添加 `?` 来将其标记为**可选参数**。

```typescript
function buildName(firstName: string, lastName?: string) {
  if (lastName) {
    return firstName + " " + lastName;
  } else {
    return firstName;
  }
}

let result1 = buildName("Bob"); // OK
// let result2 = buildName("Bob", "Adams", "Sr."); // 错误, 参数过多
let result3 = buildName("Bob", "Adams"); // OK
```
**重要提示**：可选参数必须放在必需参数的后面。

我们还可以为参数设置一个**默认值**，当用户没有传递该参数或传递的值是 `undefined` 时，该参数会自动使用默认值。

```typescript
function buildNameWithDefault(firstName: string, lastName = "Smith") {
  return firstName + " " + lastName;
}

let result1 = buildNameWithDefault("Bob"); // "Bob Smith"
let result2 = buildNameWithDefault("Bob", undefined); // "Bob Smith"
let result3 = buildNameWithDefault("Bob", "Adams"); // "Bob Adams"
```
与可选参数不同，带默认值的参数不必放在必需参数之后。

## 4. 剩余参数 (Rest Parameters)

当需要同时操作多个参数，或者不知道一个函数会接收多少个参数时，可以使用剩余参数。它们会被收集成一个数组。

```typescript
function buildNameWithRest(firstName: string, ...restOfName: string[]) {
  return firstName + " " + restOfName.join(" ");
}

let employeeName = buildNameWithRest("Joseph", "Samuel", "Lucas", "MacKinzie");
// "Joseph Samuel Lucas MacKinzie"
```

## 5. `this` 和箭头函数

在 JavaScript 中，`this` 的指向是一个常见的问题源头。在函数被调用时，`this` 的值才被确定。

TypeScript 让你可以在函数声明时就指定 `this` 应该是什么类型。

```typescript
interface Card {
    suit: string;
    card: number;
}
interface Deck {
    suits: string[];
    cards: number[];
    createCardPicker(this: Deck): () => Card;
}

let deck: Deck = {
    suits: ["hearts", "spades", "clubs", "diamonds"],
    cards: Array(52),
    // NOTE: a function which returns a function
    createCardPicker: function(this: Deck) {
        return () => {
            let pickedCard = Math.floor(Math.random() * 52);
            let pickedSuit = Math.floor(pickedCard / 13);
            
            return {suit: this.suits[pickedSuit], card: pickedCard % 13};
        }
    }
}

let cardPicker = deck.createCardPicker();
let pickedCard = cardPicker();

alert("card: " + pickedCard.card + " of " + pickedCard.suit);
```
通过 `this: Deck`，我们明确告诉 TypeScript `createCardPicker` 方法期望在一个 `Deck` 类型的对象上被调用。

**箭头函数**能很好地解决 `this` 的问题，因为它们会捕获其定义时所在上下文的 `this` 值，而不是在调用时重新确定。

## 6. 函数重载 (Overloads)

函数重载允许你为一个函数定义多个不同的调用签名。这在你希望一个函数根据传入参数的不同而返回不同类型的值时非常有用。

```typescript
let suits = ["hearts", "spades", "clubs", "diamonds"];

// 重载签名
function pickCard(x: {suit: string; card: number;}[]): number;
function pickCard(x: number): {suit: string; card: number;};

// 实现签名
function pickCard(x): any {
    if (typeof x == "object") {
        let pickedCard = Math.floor(Math.random() * x.length);
        return pickedCard;
    }
    else if (typeof x == "number") {
        let pickedSuit = Math.floor(x / 13);
        return { suit: suits[pickedSuit], card: x % 13 };
    }
}

let myDeck = [{ suit: "diamonds", card: 2 }, { suit: "spades", card: 10 }, { suit: "hearts", card: 4 }];
let pickedCard1 = pickCard(myDeck);
// pickedCard1 的类型是 number

let pickedCard2 = pickCard(15);
// pickedCard2 的类型是 {suit: string; card: number;}
```
TypeScript 的编译器在处理函数重载时，会查找重载列表，并尝试使用第一个匹配的定义。如果都不匹配，则会报错。**实现签名**对外部是不可见的，只用于函数内部的逻辑实现。

---

掌握了函数之后，下一个重要的主题是面向对象编程的基石：[类 (Classes)](classes.md)。 