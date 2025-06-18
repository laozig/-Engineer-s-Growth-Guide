# 高级类型

TypeScript 提供了许多高级类型工具，允许我们以一种富有表现力的方式来转换和操作类型。这些工具对于编写可重用的、类型安全的库或处理复杂的数据结构至关重要。

## 1. 索引类型 (Index Types)

索引类型允许你以动态的方式引用对象中的属性。`keyof` 操作符是索引类型的核心，它可以获取一个类型所有公共属性名的联合类型。

```typescript
interface Person {
    name: string;
    age: number;
}

type PersonKeys = keyof Person; // "name" | "age"

let key: PersonKeys = "name";
key = "age";
// key = "gender"; // 错误: "gender" 不是 "name" | "age"
```
`keyof` 与泛型结合使用时非常强大，可以帮助我们编写能够安全访问对象属性的函数。

```typescript
function getProperty<T, K extends keyof T>(obj: T, key: K): T[K] {
    return obj[key];
}

let person: Person = { name: "Alice", age: 30 };
let personName = getProperty(person, "name"); // string
let personAge = getProperty(person, "age"); // number
```
在这里，`K extends keyof T` 确保了 `key` 参数一定是 `obj` 对象的一个属性名，而返回值类型 `T[K]` 则准确地表示了所访问属性的类型。这就是**索引访问类型**。

## 2. 映射类型 (Mapped Types)

映射类型是一种强大的工具，它允许你通过转换一个现有类型的属性来创建一个新类型。你可以把它看作是类型级别的 `for...in` 循环。

```typescript
type Keys = 'option1' | 'option2';
type Flags = { [K in Keys]: boolean };
// 等同于:
// type Flags = {
//     option1: boolean;
//     option2: boolean;
// }
```
`[K in Keys]` 遍历 `Keys` 联合类型中的每一个字符串字面量，并将其用作新类型的属性名。

映射类型的真正威力在于它们可以基于现有类型来创建。例如，我们可以创建一个将 `Person` 类型所有属性变为只读的类型：

```typescript
interface Person {
    name: string;
    age: number;
}

type ReadonlyPerson = {
    readonly [P in keyof Person]: Person[P];
};

const alice: ReadonlyPerson = { name: "Alice", age: 30 };
// alice.age = 31; // 错误! age 是只读的.
```

## 3. 条件类型 (Conditional Types)

条件类型允许类型根据一个条件来变化，其形式为 `T extends U ? X : Y`。如果 `T` 可以赋值给 `U`，那么类型就是 `X`，否则就是 `Y`。

```typescript
type TypeName<T> =
    T extends string ? "string" :
    T extends number ? "number" :
    T extends boolean ? "boolean" :
    T extends undefined ? "undefined" :
    T extends Function ? "function" :
    "object";

type T0 = TypeName<string>;  // "string"
type T1 = TypeName<"a">;    // "string"
type T2 = TypeName<true>;   // "boolean"
type T3 = TypeName<() => void>; // "function"
type T4 = TypeName<string[]>; // "object"
```

条件类型中最强大的特性之一是 `infer` 关键字。它允许你在 `extends` 子句中声明一个待推断的类型变量。

例如，我们可以编写一个类型来获取函数返回值的类型：
```typescript
type ReturnType<T> = T extends (...args: any[]) => infer R ? R : any;

type Func = () => number;
type Num = ReturnType<Func>; // number
```
如果 `T` 是一个函数类型，我们就使用 `infer R` 来“捕获”它的返回值类型 `R`，并返回它。

## 4. 内置工具类型 (Built-in Utility Types)

TypeScript 提供了许多内置的工具类型，它们大多是基于上面介绍的高级类型实现的。这些工具类型可以极大地简化常见的类型转换。

### `Partial<T>`
将一个类型 `T` 的所有属性变为可选的。
```typescript
interface Todo {
    title: string;
    description: string;
}

function updateTodo(todo: Todo, fieldsToUpdate: Partial<Todo>) {
    return { ...todo, ...fieldsToUpdate };
}

const todo1 = { title: 'organize desk', description: 'clear clutter' };
const todo2 = updateTodo(todo1, { description: 'throw out trash' });
```

### `Readonly<T>`
将一个类型 `T` 的所有属性变为只读的。
```typescript
const todo: Readonly<Todo> = {
    title: "Delete inactive users",
    description: "..."
};
// todo.title = "Hello"; // 错误!
```

### `Record<K, T>`
构造一个对象类型，其属性键为 `K`，属性值为 `T`。
```typescript
interface PageInfo {
    title: string;
}

type Page = 'home' | 'about' | 'contact';

const nav: Record<Page, PageInfo> = {
    about: { title: 'about' },
    contact: { title: 'contact' },
    home: { title: 'home' },
};
```

### `Pick<T, K>`
从类型 `T` 中挑选出属性集 `K` 来构造一个新的类型。
```typescript
interface Todo {
    title: string;
    description: string;
    completed: boolean;
}

type TodoPreview = Pick<Todo, 'title' | 'completed'>;

const todo: TodoPreview = {
    title: 'Clean room',
    completed: false,
};
```

### `Omit<T, K>`
从类型 `T` 中移除属性集 `K` 来构造一个新的类型。
```typescript
type TodoInfo = Omit<Todo, 'completed'>;

const todoInfo: TodoInfo = {
    title: 'Pick up kids',
    description: 'Kindergarten closes at 5pm'
};
```

### `ReturnType<T>` 和 `Parameters<T>`
分别用于获取函数类型 `T` 的返回值类型和参数类型（以元组形式）。

```typescript
type T0 = ReturnType<() => string>;  // string
type T1 = Parameters<(s: string) => void>; // [s: string]
```

---

了解了这些高级类型工具后，你将能更好地组织代码，下一步是学习[模块与命名空间](modules-namespaces.md)。
