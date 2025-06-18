# 装饰器 (Decorators)

装饰器是一种特殊的声明，它能够被附加到类声明、方法、访问器、属性或参数上，用于在不修改原始代码的情况下，扩展或修改其行为。装饰器本质上是一个函数，它在运行时被调用，并接收被装饰的声明作为参数。

**重要提示**：装饰器目前是 TypeScript 的一项**实验性**特性，可能在未来的版本中发生变化。你必须在 `tsconfig.json` 中启用 `experimentalDecorators` 选项来使用它们。

```json
{
  "compilerOptions": {
    "target": "ES5",
    "experimentalDecorators": true
  }
}
```

## 1. 装饰器是什么？

装饰器是一个函数，它接收一些关于被装饰的声明的信息，并可以返回一个新的描述符来替换原始声明。

装饰器的写法是在要装饰的成员前加上 `@expression`，其中 `expression` 必须是一个求值后为函数的表达式。

## 2. 装饰器工厂 (Decorator Factories)

如果你想自定义装饰器如何应用，你可以编写一个**装饰器工厂**。它就是一个返回装饰器函数的函数。

```typescript
function color(value: string) { // 这是一个装饰器工厂
    return function (target) { //  这才是装饰器
        // do something with "target" and "value"...
    };
}
```

## 3. 装饰器组合

多个装饰器可以同时应用到一个声明上：

```typescript
@f
@g
class C {}
```

求值顺序如下：
1.  装饰器工厂 `@f` 和 `@g` 会从上到下依次求值。
2.  求值后的结果（即装饰器函数）会从下到上依次调用。

也就是说，执行顺序会是 `g(f(C))`。

## 4. 类装饰器 (Class Decorators)

类装饰器在类声明之前被声明。它应用于类的构造函数，可以用来监视，修改或替换类定义。

类装饰器函数接收一个参数：
- **`constructor`**: 被装饰的类的构造函数。

```typescript
function sealed(constructor: Function) {
    Object.seal(constructor);
    Object.seal(constructor.prototype);
}

@sealed
class Greeter {
    greeting: string;
    constructor(message: string) {
        this.greeting = message;
    }
    greet() {
        return "Hello, " + this.greeting;
    }
}
```
`@sealed` 装饰器会“封印”类的构造函数和原型，防止其被进一步扩展。

## 5. 方法装饰器 (Method Decorators)

方法装饰器声明在一个方法的声明之前。它被应用到方法的**属性描述符**（Property Descriptor）上，可以用来监视，修改或者替换方法定义。

方法装饰器函数接收三个参数：
- **`target`**: 对于静态成员来说是类的构造函数，对于实例成员是类的原型。
- **`propertyKey`**: 成员的名字 (string | symbol)。
- **`descriptor`**: 成员的属性描述符。

```typescript
function enumerable(value: boolean) {
    return function (target: any, propertyKey: string, descriptor: PropertyDescriptor) {
        descriptor.enumerable = value;
    };
}

class Greeter {
    greeting: string;
    constructor(message: string) {
        this.greeting = message;
    }

    @enumerable(false)
    greet() {
        return "Hello, " + this.greeting;
    }
}
```
`@enumerable(false)` 装饰器使得 `greet` 方法在 `for...in` 循环中不可被枚举。

## 6. 属性装饰器 (Property Decorators)

属性装饰器声明在一个属性声明之前。它不能像方法装饰器那样操作属性描述符，而是主要用来记录元数据。

属性装饰器函数接收两个参数：
- **`target`**: 对于静态成员来说是类的构造函数，对于实例成员是类的原型。
- **`propertyKey`**: 成员的名字 (string | symbol)。

```typescript
import "reflect-metadata";

const formatMetadataKey = Symbol("format");

function format(formatString: string) {
    return Reflect.metadata(formatMetadataKey, formatString);
}

class Greeter {
    @format("Hello, %s")
    greeting: string;

    constructor(message: string) {
        this.greeting = message;
    }
    greet() {
        let formatString = Reflect.getMetadata(formatMetadataKey, this, "greeting");
        return formatString.replace("%s", this.greeting);
    }
}
```
这个例子使用了 `reflect-metadata` 库来附加和读取元数据。

## 7. 参数装饰器 (Parameter Decorators)

参数装饰器声明在一个参数声明之前。它被应用到函数（构造函数或方法）的参数上。

参数装饰器函数接收三个参数：
- **`target`**: 对于静态成员来说是类的构造函数，对于实例成员是类的原型。
- **`propertyKey`**: 成员的名字 (string | symbol)。
- **`parameterIndex`**: 参数在函数参数列表中的索引。

```typescript
function required(target: any, propertyKey: string, parameterIndex: number) {
    // ... 在这里可以记录参数为“必需”的元数据
}

class Greeter {
    greet(name: @required string) {
        // ...
    }
}
```
参数装饰器常用于依赖注入框架，用来标记需要注入的依赖。

---

装饰器是元编程的强大工具，但使用时需谨慎。下一步，我们将学习如何为现有的 JavaScript 库提供类型信息，即[类型定义文件 (`.d.ts`)](declaration-files.md)。
