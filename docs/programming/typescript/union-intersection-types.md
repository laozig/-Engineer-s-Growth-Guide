# 联合类型与交叉类型

在 TypeScript 中，我们可以通过组合现有类型来创建更复杂、更灵活的类型。联合类型和交叉类型是两种最基本的组合类型的方式。

## 1. 联合类型 (Union Types)

联合类型使用 `|` (管道) 操作符，表示一个值可以是几种类型之一。

```typescript
function padLeft(value: string, padding: string | number) {
    if (typeof padding === "number") {
        return Array(padding + 1).join(" ") + value;
    }
    if (typeof padding === "string") {
        return padding + value;
    }
    throw new Error(`Expected string or number, got '${padding}'.`);
}

padLeft("Hello world", 4); // returns "    Hello world"
// padLeft("Hello world", {}); // 错误: Argument of type '{}' is not assignable to parameter of type 'string | number'.
```
在这个例子中，`padding` 参数的类型是 `string | number`，意味着它可以接受字符串或数字。

### 使用联合类型的挑战

当一个值的类型是联合类型时，我们只能访问此联合类型中**所有类型都共有的成员**。

```typescript
interface Bird {
    fly(): void;
    layEggs(): void;
}

interface Fish {
    swim(): void;
    layEggs(): void;
}

function getSmallPet(): Fish | Bird {
    // ...
}

let pet = getSmallPet();
pet.layEggs(); // OK
// pet.swim();    // 错误: Property 'swim' does not exist on type 'Bird'.
```
在这个例子中，`pet` 的类型是 `Fish | Bird`。因为 `swim` 只在 `Fish` 中存在，而 `fly` 只在 `Bird` 中存在，所以 TypeScript 会报错。只有 `layEggs` 是共有的，可以安全访问。

### 类型保护与区分类型 (Type Guards and Differentiating Types)

为了解决上面的问题，我们需要一种方法来区分联合类型中的不同成员。JavaScript 中常用的 `typeof` 和 `instanceof` 操作符在 TypeScript 中可以作为**类型保护**（Type Guard）来使用。

```typescript
let pet = getSmallPet();

// 使用 'in' 操作符进行类型保护
if ("swim" in pet) {
    pet.swim();
} else {
    pet.fly();
}

// 使用自定义类型保护函数
function isFish(pet: Fish | Bird): pet is Fish {
    return (pet as Fish).swim !== undefined;
}

if (isFish(pet)) {
    pet.swim();
} else {
    pet.fly();
}
```
`pet is Fish` 就是我们的**类型谓词**。它告诉编译器，如果函数返回 `true`，那么在 `if` 块中 `pet` 的类型就是 `Fish`。

### 可区分联合 (Discriminated Unions)

这是一种强大的模式，它结合了联合类型、字面量类型和类型保护。它要求联合类型中的每个成员都有一个**共同的、类型为字面量的属性**，作为区分的标志。

```typescript
interface Square {
    kind: "square"; // 可区分的属性
    size: number;
}
interface Rectangle {
    kind: "rectangle";
    width: number;
    height: number;
}
interface Circle {
    kind: "circle";
    radius: number;
}

type Shape = Square | Rectangle | Circle;

function area(s: Shape) {
    switch (s.kind) {
        case "square": return s.size * s.size;
        case "rectangle": return s.height * s.width;
        case "circle": return Math.PI * s.radius ** 2;
    }
}
```
通过检查 `kind` 属性，TypeScript 可以在 `switch` 的每个 `case` 中智能地推断出 `s` 的确切类型，从而让我们能够安全地访问 `size`、`width` 或 `radius` 等特定属性。

## 2. 交叉类型 (Intersection Types)

交叉类型使用 `&` 操作符，它将多个类型合并为一个类型。这个新类型拥有所有成员类型的所有属性。

```typescript
interface ErrorHandling {
    success: boolean;
    error?: { message: string };
}

interface ArtworksData {
    artworks: { title: string }[];
}

interface ArtistsData {
    artists: { name: string }[];
}

// 假设这是从两个不同API端点获取的数据
type ArtworksResponse = ArtworksData & ErrorHandling;
type ArtistsResponse = ArtistsData & ErrorHandling;

const artworks: ArtworksResponse = {
    success: true,
    artworks: [{ title: "Mona Lisa" }]
};

const artists: ArtistsResponse = {
    success: false,
    error: { message: "API limit reached" },
    artists: []
};
```
交叉类型非常适合用来混合（mixins）或组合对象的行为。

---

掌握了组合类型后，我们可以探索 TypeScript 中一些更强大的工具：[高级类型](advanced-types.md)。 