# 类 (Classes)

TypeScript 扩展了 JavaScript ES6 中的类，添加了更多强大的面向对象特性。类是创建可重用组件的蓝图，也是构建大型应用的基础。

## 1. 基本的类

下面是一个基本的类定义：
```typescript
class Greeter {
    greeting: string;

    constructor(message: string) {
        this.greeting = message;
    }

    greet() {
        return "Hello, " + this.greeting;
    }
}

let greeter = new Greeter("world");
console.log(greeter.greet()); // "Hello, world"
```
这个类有3个成员：一个叫做 `greeting` 的属性，一个构造函数和一个 `greet` 方法。

## 2. 继承 (Inheritance)

在 TypeScript 中，我们可以使用 `extends` 关键字来实现继承，这使得子类可以继承父类的属性和方法。

```typescript
class Animal {
    move(distanceInMeters: number = 0) {
        console.log(`Animal moved ${distanceInMeters}m.`);
    }
}

class Dog extends Animal {
    bark() {
        console.log('Woof! Woof!');
    }
}

const dog = new Dog();
dog.bark();
dog.move(10);
dog.bark();
```

子类可以重写父类的方法。通过 `super` 关键字，我们可以在子类中调用父类的方法。

```typescript
class Animal {
    name: string;
    constructor(theName: string) { this.name = theName; }
    move(distanceInMeters: number) {
        console.log(`${this.name} moved ${distanceInMeters}m.`);
    }
}

class Snake extends Animal {
    constructor(name: string) { super(name); }
    move(distanceInMeters = 5) {
        console.log("Slithering...");
        super.move(distanceInMeters);
    }
}

let sam = new Snake("Sammy the Python");
sam.move(); // "Slithering...", "Sammy the Python moved 5m."
```

## 3. 访问修饰符 (Public, Private, and Protected)

TypeScript 中，你可以为类的成员设置访问权限。

### `public` (默认)
`public` 修饰的成员在任何地方都是可见的，可以被自由访问。如果不指定修饰符，成员默认为 `public`。

```typescript
class Animal {
    public name: string;
    public constructor(theName: string) { this.name = theName; }
    public move(distanceInMeters: number) {
        console.log(`${this.name} moved ${distanceInMeters}m.`);
    }
}
```

### `private`
`private` 修饰的成员只能在其声明的类内部访问。即使是子类也不能访问 `private` 成员。

```typescript
class Animal {
    private name: string;
    constructor(theName: string) { this.name = theName; }
}

let animal = new Animal("Goat");
// animal.name; // 错误: 'name' 是私有的.

class Rhino extends Animal {
    constructor() { super("Rhino"); }
    getName() {
        // return this.name; // 错误: 'name' 是私有的.
    }
}
```

### `protected`
`protected` 修饰的成员只能在其声明的类及其子类中访问。

```typescript
class Person {
    protected name: string;
    constructor(name: string) { this.name = name; }
}

class Employee extends Person {
    private department: string;

    constructor(name: string, department: string) {
        super(name);
        this.department = department;
    }

    public getElevatorPitch() {
        // 可以在子类中访问 protected 成员
        return `Hello, my name is ${this.name} and I work in ${this.department}.`;
    }
}

let howard = new Employee("Howard", "Sales");
console.log(howard.getElevatorPitch());
// console.log(howard.name); // 错误: 'name' 是受保护的.
```

## 4. 只读修饰符 (Readonly)

你可以使用 `readonly` 关键字将属性设置为只读的。只读属性必须在声明时或构造函数里被初始化。

```typescript
class Octopus {
    readonly name: string;
    readonly numberOfLegs: number = 8;
    constructor (theName: string) {
        this.name = theName;
    }
}
let dad = new Octopus("Man with the 8 strong legs");
// dad.name = "Man with the 3-piece suit"; // 错误! name 是只读的.
```

## 5. 访问器 (Accessors)

TypeScript 支持通过 `getters/setters` 来截取对对象成员的访问。它能让你在读写成员时执行额外的逻辑。

```typescript
class Employee {
    private _fullName: string;

    get fullName(): string {
        return this._fullName;
    }

    set fullName(newName: string) {
        if (newName && newName.length > 0) {
            this._fullName = newName;
        } else {
            console.log("Error: invalid name");
        }
    }
}

let employee = new Employee();
employee.fullName = "Bob Smith";
if (employee.fullName) {
    console.log(employee.fullName);
}
```

## 6. 静态属性 (Static Properties)

静态成员存在于类本身而不是类的实例上。你可以使用 `ClassName.staticMember` 的方式来访问它们。

```typescript
class Grid {
    static origin = {x: 0, y: 0};
    calculateDistanceFromOrigin(point: {x: number; y: number;}) {
        let xDist = (point.x - Grid.origin.x);
        let yDist = (point.y - Grid.origin.y);
        return Math.sqrt(xDist * xDist + yDist * yDist) / this.scale;
    }
    constructor (public scale: number) { }
}

let grid1 = new Grid(1.0);
console.log(Grid.origin); // {x: 0, y: 0}
```

## 7. 抽象类 (Abstract Classes)

抽象类是作为其它派生类的基类的。它们一般不会直接被实例化。不同于接口，抽象类可以包含成员的实现细节。`abstract` 关键字是用于定义抽象类和在抽象类内部定义抽象方法。

抽象类中的抽象方法不包含具体实现并且必须在派生类中实现。

```typescript
abstract class Department {
    constructor(public name: string) {}

    printName(): void {
        console.log('Department name: ' + this.name);
    }

    abstract printMeeting(): void; // 必须在派生类中实现
}

class AccountingDepartment extends Department {
    constructor() {
        super('Accounting and Auditing'); // 在派生类的构造函数中必须调用 super()
    }

    printMeeting(): void {
        console.log('The Accounting Department meets each Monday at 10am.');
    }
}

let department: Department; // 允许创建一个对抽象类型的引用
// department = new Department(); // 错误: 不能创建一个抽象类的实例
department = new AccountingDepartment(); // 允许对一个抽象子类进行实例化和赋值
department.printName();
department.printMeeting();
```

---

恭喜！您已完成 TypeScript 基础入门的学习。接下来，我们将进入[进阶核心](generics.md)部分，从泛型开始。 