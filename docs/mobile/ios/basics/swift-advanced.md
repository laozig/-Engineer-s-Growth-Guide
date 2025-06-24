# Swift 进阶特性

本文档将介绍Swift语言的进阶特性，包括闭包、泛型、协议和扩展等关键概念。这些特性是构建现代化、灵活且强大的iOS应用程序的基础。

## 目录

- [闭包](#闭包)
- [泛型](#泛型)
- [协议](#协议)
- [扩展](#扩展)
- [错误处理](#错误处理)
- [模式匹配](#模式匹配)
- [函数式编程](#函数式编程)
- [属性包装器](#属性包装器)
- [结语](#结语)

## 闭包

闭包是Swift中的自包含函数代码块，可以在代码中传递和使用。闭包可以捕获和存储其所在上下文中的任何常量和变量的引用。

### 闭包语法

闭包表达式语法有如下通用形式：

```swift
{ (parameters) -> return type in
    statements
}
```

### 简单闭包示例

```swift
// 完整闭包语法
let simpleClosure = { (a: Int, b: Int) -> Int in
    return a + b
}

// 调用闭包
let result = simpleClosure(5, 3) // 结果为 8
```

### 尾随闭包

当函数的最后一个参数是闭包时，可以使用尾随闭包语法：

```swift
// 使用函数参数形式的闭包
func performOperation(_ a: Int, _ b: Int, operation: (Int, Int) -> Int) -> Int {
    return operation(a, b)
}

// 常规调用
let result1 = performOperation(5, 3, operation: { (a, b) in return a + b })

// 使用尾随闭包
let result2 = performOperation(5, 3) { (a, b) in 
    return a + b
}

// 进一步简化，当参数类型和返回值类型可以被推断时
let result3 = performOperation(5, 3) { $0 + $1 }
```

### 值捕获

闭包可以捕获其定义环境中的常量和变量：

```swift
func makeIncrementer(forIncrement amount: Int) -> () -> Int {
    var runningTotal = 0
    func incrementer() -> Int {
        runningTotal += amount
        return runningTotal
    }
    return incrementer
}

let incrementByTen = makeIncrementer(forIncrement: 10)
print(incrementByTen()) // 输出: 10
print(incrementByTen()) // 输出: 20
print(incrementByTen()) // 输出: 30
```

### 逃逸闭包

当闭包作为参数传递给函数，但在函数返回后才被调用时，闭包需要声明为逃逸闭包（使用`@escaping`标记）：

```swift
var completionHandlers: [() -> Void] = []

func someFunctionWithEscapingClosure(completionHandler: @escaping () -> Void) {
    // 将闭包存储起来，以便后续调用
    completionHandlers.append(completionHandler)
}

func someFunctionWithNonescapingClosure(closure: () -> Void) {
    // 在函数返回前直接调用闭包
    closure()
}

class SomeClass {
    var x = 10
    func doSomething() {
        someFunctionWithEscapingClosure { [weak self] in
            guard let self = self else { return }
            self.x = 100 // 引用self需要显式声明
        }
        
        someFunctionWithNonescapingClosure {
            x = 200 // 不需要显式声明self
        }
    }
}
```

### 自动闭包

自动闭包是一种自动创建的闭包，用于包装传递给函数作为参数的表达式：

```swift
func logIfTrue(_ predicate: @autoclosure () -> Bool) {
    if predicate() {
        print("True!")
    }
}

// 调用时看起来像是传递一个Bool值
logIfTrue(2 > 1) // 输出: True!
```

## 泛型

泛型允许您编写灵活、可重用的函数和类型，可以处理任何类型，而不仅限于单一类型。

### 泛型函数

```swift
func swapTwoValues<T>(_ a: inout T, _ b: inout T) {
    let temporaryA = a
    a = b
    b = temporaryA
}

var integerOne = 1
var integerTwo = 2
swapTwoValues(&integerOne, &integerTwo)
// integerOne现在是2，integerTwo现在是1

var stringOne = "hello"
var stringTwo = "world"
swapTwoValues(&stringOne, &stringTwo)
// stringOne现在是"world"，stringTwo现在是"hello"
```

### 泛型类型

```swift
struct Stack<Element> {
    var items = [Element]()
    
    mutating func push(_ item: Element) {
        items.append(item)
    }
    
    mutating func pop() -> Element? {
        return items.popLast()
    }
}

var intStack = Stack<Int>()
intStack.push(1)
intStack.push(2)
print(intStack.pop() ?? 0) // 输出: 2

var stringStack = Stack<String>()
stringStack.push("hello")
stringStack.push("world")
print(stringStack.pop() ?? "") // 输出: "world"
```

### 类型约束

泛型类型可以指定一个类型必须继承自特定的类，或者遵循特定的协议：

```swift
// T必须遵循Comparable协议
func findIndex<T: Comparable>(of valueToFind: T, in array: [T]) -> Int? {
    for (index, value) in array.enumerated() {
        if value == valueToFind {
            return index
        }
    }
    return nil
}

let strings = ["cat", "dog", "llama", "parakeet", "terrapin"]
if let foundIndex = findIndex(of: "llama", in: strings) {
    print("Found llama at index \(foundIndex)") // 输出: Found llama at index 2
}
```

### 关联类型

协议中的关联类型为协议定义中的类型提供了一个占位符名称：

```swift
protocol Container {
    associatedtype Item
    mutating func append(_ item: Item)
    var count: Int { get }
    subscript(i: Int) -> Item { get }
}

struct IntStack: Container {
    // IntStack的原始实现
    var items = [Int]()
    mutating func push(_ item: Int) {
        items.append(item)
    }
    mutating func pop() -> Int? {
        return items.popLast()
    }
    
    // Container协议的实现
    typealias Item = Int // 显式指定关联类型
    mutating func append(_ item: Int) {
        self.push(item)
    }
    var count: Int {
        return items.count
    }
    subscript(i: Int) -> Int {
        return items[i]
    }
}
```

### 泛型Where子句

泛型Where子句允许您对关联类型添加更多约束：

```swift
func allItemsMatch<C1: Container, C2: Container>
    (_ someContainer: C1, _ anotherContainer: C2) -> Bool
    where C1.Item == C2.Item, C1.Item: Equatable {
    
    // 检查两个容器包含相同数量的元素
    if someContainer.count != anotherContainer.count {
        return false
    }
    
    // 检查每对元素是否相等
    for i in 0..<someContainer.count {
        if someContainer[i] != anotherContainer[i] {
            return false
        }
    }
    
    // 所有元素都匹配
    return true
}
```

## 协议

协议定义了一个蓝图，规定了用来实现某一特定任务或功能的方法、属性和其他要求。

### 基本协议

```swift
protocol SomeProtocol {
    // 协议定义
    var mustBeSettable: Int { get set }
    var doesNotNeedToBeSettable: Int { get }
    
    func someMethod()
    static func someStaticMethod()
}
```

### 协议的采纳和实现

```swift
class SomeClass: SomeProtocol {
    // 实现协议的要求
    var mustBeSettable: Int = 0
    var doesNotNeedToBeSettable: Int {
        return 10
    }
    
    func someMethod() {
        print("SomeMethod被调用")
    }
    
    static func someStaticMethod() {
        print("SomeStaticMethod被调用")
    }
}
```

### 协议作为类型

```swift
func processItems(items: [SomeProtocol]) {
    for item in items {
        item.someMethod()
    }
}

let instance = SomeClass()
processItems(items: [instance]) // 将遵循协议的实例传递给函数
```

### 协议继承

协议可以继承一个或多个其他协议：

```swift
protocol InheritingProtocol: SomeProtocol {
    // 这个协议继承自SomeProtocol
    func anotherMethod()
}

class AnotherClass: InheritingProtocol {
    // 必须实现SomeProtocol和InheritingProtocol的所有要求
    var mustBeSettable: Int = 0
    var doesNotNeedToBeSettable: Int { return 10 }
    
    func someMethod() {
        print("someMethod被调用")
    }
    
    static func someStaticMethod() {
        print("someStaticMethod被调用")
    }
    
    func anotherMethod() {
        print("anotherMethod被调用")
    }
}
```

### 协议组合

您可以使用协议组合来要求一个类型同时遵循多个协议：

```swift
protocol Named {
    var name: String { get }
}

protocol Aged {
    var age: Int { get }
}

struct Person: Named, Aged {
    var name: String
    var age: Int
}

func wishHappyBirthday(to celebrator: Named & Aged) {
    print("Happy birthday, \(celebrator.name), you're \(celebrator.age)!")
}

let birthdayPerson = Person(name: "张三", age: 30)
wishHappyBirthday(to: birthdayPerson) // 输出: Happy birthday, 张三, you're 30!
```

### 协议扩展

协议可以通过扩展提供方法和属性的默认实现：

```swift
protocol TextRepresentable {
    var textualDescription: String { get }
}

extension TextRepresentable {
    // 提供默认实现
    var textualDescription: String {
        return "某个遵循TextRepresentable的实例"
    }
}

struct SomeStruct: TextRepresentable {
    // 使用默认实现，不需要自己实现textualDescription
}

let someStruct = SomeStruct()
print(someStruct.textualDescription) // 输出: 某个遵循TextRepresentable的实例
```

### 有条件的协议扩展

您可以为遵循特定条件的类型提供协议扩展：

```swift
extension Collection where Element: Equatable {
    func allEqual() -> Bool {
        guard let firstElement = self.first else { return true }
        return self.allSatisfy { $0 == firstElement }
    }
}

let equalNumbers = [100, 100, 100, 100]
print(equalNumbers.allEqual()) // 输出: true

let differentNumbers = [100, 100, 200, 100]
print(differentNumbers.allEqual()) // 输出: false
```

## 扩展

扩展可以向现有的类、结构体、枚举或协议添加新功能。

### 计算属性扩展

```swift
extension Double {
    var km: Double { return self * 1_000.0 }
    var m: Double { return self }
    var cm: Double { return self / 100.0 }
    var mm: Double { return self / 1_000.0 }
}

let marathon = 42.km + 195.m
print("马拉松的长度是 \(marathon) 米") // 输出: 马拉松的长度是 42195.0 米
```

### 方法扩展

```swift
extension Int {
    func repetitions(task: () -> Void) {
        for _ in 0..<self {
            task()
        }
    }
}

3.repetitions {
    print("Hello!")
}
// 输出:
// Hello!
// Hello!
// Hello!
```

### 构造器扩展

```swift
struct Size {
    var width = 0.0, height = 0.0
}

extension Size {
    init(square: Double) {
        self.width = square
        self.height = square
    }
}

let squareSize = Size(square: 10.0)
print(squareSize.width, squareSize.height) // 输出: 10.0 10.0
```

### 嵌套类型扩展

```swift
extension Int {
    enum Kind {
        case negative, zero, positive
    }
    
    var kind: Kind {
        switch self {
        case 0:
            return .zero
        case let x where x > 0:
            return .positive
        default:
            return .negative
        }
    }
}

print(1.kind) // 输出: positive
print(0.kind) // 输出: zero
print((-1).kind) // 输出: negative
```

### 为协议添加扩展

```swift
protocol Drawable {
    func draw()
}

extension Drawable {
    func draw() {
        print("绘制默认图形")
    }
    
    func prepareToDraw() {
        print("准备绘制")
    }
}

struct Circle: Drawable {
    // 使用协议的默认实现
}

struct Square: Drawable {
    // 覆盖协议的默认实现
    func draw() {
        print("绘制正方形")
    }
}

let circle = Circle()
circle.prepareToDraw() // 输出: 准备绘制
circle.draw() // 输出: 绘制默认图形

let square = Square()
square.prepareToDraw() // 输出: 准备绘制
square.draw() // 输出: 绘制正方形
```

## 错误处理

Swift提供了抛出、捕获、传递和操作可恢复错误的一等公民支持。

### 错误类型

```swift
enum VendingMachineError: Error {
    case invalidSelection
    case insufficientFunds(coinsNeeded: Int)
    case outOfStock
}
```

### 抛出错误

```swift
func vend(itemNamed name: String) throws -> String {
    guard name == "Candy Bar" else {
        throw VendingMachineError.invalidSelection
    }
    
    let price = 100
    let inventory = 0
    
    guard inventory > 0 else {
        throw VendingMachineError.outOfStock
    }
    
    guard price <= 50 else {
        throw VendingMachineError.insufficientFunds(coinsNeeded: price - 50)
    }
    
    return "Dispensing \(name)"
}
```

### 处理错误

```swift
do {
    try vend(itemNamed: "Chips")
    print("Success!")
} catch VendingMachineError.invalidSelection {
    print("Invalid Selection.")
} catch VendingMachineError.outOfStock {
    print("Out of Stock.")
} catch VendingMachineError.insufficientFunds(let coinsNeeded) {
    print("Insufficient funds. Please insert an additional \(coinsNeeded) coins.")
} catch {
    print("Unexpected error: \(error).")
}
// 输出: Invalid Selection.
```

### 可选值处理

```swift
// try? 将错误转换为可选值
let result = try? vend(itemNamed: "Candy Bar")
print(result) // 输出: nil (由于错误，返回nil)

// try! 在确保不会抛出错误时使用
func cannotFail() throws -> String {
    return "这个函数声明为throws，但实际上不会抛出错误"
}

let forcedResult = try! cannotFail()
print(forcedResult) // 输出: 这个函数声明为throws，但实际上不会抛出错误
```

### defer语句

`defer`语句用于在作用域结束时执行清理工作，无论是正常退出还是因为错误退出：

```swift
func processFile(filename: String) throws {
    let file = openFile(filename)
    defer {
        closeFile(file) // 在函数返回前执行，确保文件被关闭
    }
    
    // 处理文件...
    if let fileError = errorInFile(file) {
        throw fileError
    }
    
    // 文件处理成功
}
```

## 模式匹配

Swift的模式匹配功能非常强大，尤其在switch语句中。

### 值绑定模式

```swift
let point = (3, 2)

switch point {
case (let x, 0):
    print("x轴上的点，x = \(x)")
case (0, let y):
    print("y轴上的点，y = \(y)")
case let (x, y):
    print("其他点：(\(x), \(y))")
}
// 输出: 其他点：(3, 2)
```

### 元组模式

```swift
let somePoint = (1, 1)

switch somePoint {
case (0, 0):
    print("原点")
case (_, 0):
    print("x轴上")
case (0, _):
    print("y轴上")
case (-2...2, -2...2):
    print("在盒子内")
default:
    print("在盒子外")
}
// 输出: 在盒子内
```

### where子句

```swift
let yetAnotherPoint = (1, -1)

switch yetAnotherPoint {
case let (x, y) where x == y:
    print("在y = x线上")
case let (x, y) where x == -y:
    print("在y = -x线上")
case let (x, y):
    print("在其他位置: (\(x), \(y))")
}
// 输出: 在y = -x线上
```

## 函数式编程

Swift支持函数式编程范式，提供了高阶函数和函数式构造。

### map

转换集合中的每个元素：

```swift
let numbers = [1, 2, 3, 4, 5]
let squared = numbers.map { $0 * $0 }
print(squared) // 输出: [1, 4, 9, 16, 25]

let strings = ["one", "two", "three"]
let uppercased = strings.map { $0.uppercased() }
print(uppercased) // 输出: ["ONE", "TWO", "THREE"]
```

### filter

筛选满足条件的元素：

```swift
let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
let evens = numbers.filter { $0 % 2 == 0 }
print(evens) // 输出: [2, 4, 6, 8, 10]

let words = ["apple", "banana", "pear", "orange"]
let longWords = words.filter { $0.count > 5 }
print(longWords) // 输出: ["banana", "orange"]
```

### reduce

将集合合并为单个值：

```swift
let numbers = [1, 2, 3, 4, 5]
let sum = numbers.reduce(0) { $0 + $1 }
print(sum) // 输出: 15

let words = ["Hello", " ", "World", "!"]
let greeting = words.reduce("") { $0 + $1 }
print(greeting) // 输出: "Hello World!"
```

### flatMap 和 compactMap

处理嵌套集合和可选值：

```swift
// flatMap: 扁平化嵌套集合
let nestedNumbers = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
let flattened = nestedNumbers.flatMap { $0 }
print(flattened) // 输出: [1, 2, 3, 4, 5, 6, 7, 8, 9]

// compactMap: 过滤nil并解包可选值
let possibleNumbers = ["1", "2", "three", "4", "five"]
let mappedNumbers = possibleNumbers.map { Int($0) }
print(mappedNumbers) // 输出: [Optional(1), Optional(2), nil, Optional(4), nil]

let compactMappedNumbers = possibleNumbers.compactMap { Int($0) }
print(compactMappedNumbers) // 输出: [1, 2, 4]
```

## 属性包装器

属性包装器为属性的定义添加了一层封装，可以重用对属性的访问模式。

### 基本属性包装器

```swift
@propertyWrapper
struct TwelveOrLess {
    private var number: Int
    
    init() {
        self.number = 0
    }
    
    var wrappedValue: Int {
        get { return number }
        set { number = min(newValue, 12) }
    }
}

struct SmallRectangle {
    @TwelveOrLess var height: Int
    @TwelveOrLess var width: Int
}

var rectangle = SmallRectangle()
print(rectangle.height) // 输出: 0

rectangle.height = 10
print(rectangle.height) // 输出: 10

rectangle.height = 24
print(rectangle.height) // 输出: 12 (被限制为12)
```

### 带有投影值的属性包装器

属性包装器可以提供一个投影值，用于暴露额外功能：

```swift
@propertyWrapper
struct PositiveNumber {
    private var number: Int
    private(set) var projectedValue: Bool
    
    init() {
        self.number = 0
        self.projectedValue = false
    }
    
    var wrappedValue: Int {
        get { return number }
        set {
            if newValue > 0 {
                number = newValue
                projectedValue = true
            } else {
                number = 0
                projectedValue = false
            }
        }
    }
}

struct User {
    @PositiveNumber var score: Int
}

var user = User()
user.score = 10
print(user.score) // 输出: 10
print(user.$score) // 输出: true (通过$访问投影值)

user.score = -5
print(user.score) // 输出: 0
print(user.$score) // 输出: false
```

## 结语

Swift的进阶特性如闭包、泛型、协议和扩展为开发者提供了强大的工具，使代码更加灵活、可重用和表达力强。这些特性的组合使Swift成为一种既安全又高效的现代编程语言，特别适合iOS和macOS应用开发。

在掌握这些进阶特性后，您将能够编写更加简洁、可维护的代码，并利用Swift的全部潜力来构建高质量的应用程序。

## 进一步学习

要深入了解Swift的进阶特性，请参考以下资源：

- [Swift内存管理](swift-memory.md) - 深入了解ARC和引用循环
- [Swift函数式编程](../advanced/functional-programming.md) - 探索更多函数式编程技术
- [Swift并发编程](../async/async-await.md) - 学习Swift的现代并发特性 