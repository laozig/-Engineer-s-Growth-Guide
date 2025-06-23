# Swift 语言基础

Swift 是 Apple 开发的强大、直观且安全的编程语言，用于开发 iOS、macOS、watchOS 和 tvOS 应用。本教程将带您了解 Swift 的核心概念和基础语法。

## 目录

- [语言特点](#语言特点)
- [基本语法](#基本语法)
- [变量与常量](#变量与常量)
- [基本数据类型](#基本数据类型)
- [运算符](#运算符)
- [控制流](#控制流)
- [函数](#函数)
- [集合类型](#集合类型)
- [可选类型](#可选类型)
- [类型转换](#类型转换)
- [字符串处理](#字符串处理)
- [练习题](#练习题)

## 语言特点

Swift 语言具有以下主要特点：

- **安全性** - 强类型、可选值、错误处理机制
- **现代化** - 简洁语法、函数式编程支持
- **高性能** - 与 C 语言性能相当
- **互操作性** - 与 Objective-C 代码完全兼容
- **开源** - 跨平台支持

与 Objective-C 相比，Swift 移除了指针和空值的不安全访问，引入了元组和枚举关联值等现代语言特性，同时提供更简洁的语法。

## 基本语法

### Swift 程序结构

Swift 程序不需要 main() 函数，也不需要在每个语句后添加分号（虽然可以使用）：

```swift
// 这是单行注释

/*
 这是多行注释
 可以跨越多行
 */

// 直接开始编写代码，不需要 main() 函数
print("Hello, Swift!")

// 导入模块
import Foundation
```

## 变量与常量

Swift 使用 `var` 关键字声明变量，使用 `let` 关键字声明常量：

```swift
// 声明变量（可以更改值）
var greeting = "Hello"
greeting = "Hello, world!"

// 声明常量（值不可更改）
let maximumLoginAttempts = 10
// maximumLoginAttempts = 11 // 这会产生编译错误

// 显式类型标注
var message: String = "Hello"
let pi: Double = 3.14159
```

### 命名规则

- 变量和常量名可以包含几乎任何字符，包括 Unicode 字符
- 不能包含空格、数学符号、箭头等
- 不能以数字开头
- Swift 标识符区分大小写

```swift
let π = 3.14159
let 你好 = "你好世界"
let 🐶 = "dog"
```

## 基本数据类型

Swift 提供了以下基本数据类型：

### 整数类型

```swift
// 有符号整数
let minInt8: Int8 = -128
let maxInt8: Int8 = 127

// 无符号整数
let maxUInt8: UInt8 = 255

// 常用的整数类型（根据平台自动选择位数）
let someInteger: Int = 42
```

### 浮点类型

```swift
// 32位浮点数
let float32: Float = 3.14159

// 64位浮点数（更精确，推荐使用）
let double64: Double = 3.14159265359

// 默认的浮点字面量是 Double 类型
let pi = 3.14159 // 类型是 Double
```

### 布尔类型

```swift
let orangesAreOrange: Bool = true
let turnipsAreDelicious: Bool = false

// 条件语句中的布尔值不需要与 true 比较
if turnipsAreDelicious {
    print("好吃!")
} else {
    print("不好吃!")
}
```

### 类型别名

类型别名为现有类型定义了一个替代名称：

```swift
typealias AudioSample = UInt16
let maxAmplitude: AudioSample = 32767
```

## 运算符

Swift 支持大多数标准 C 运算符，并改进了一些功能以消除常见编程错误。

### 算术运算符

```swift
let sum = 5 + 3           // 加法: 8
let difference = 10 - 2   // 减法: 8
let product = 4 * 5       // 乘法: 20
let quotient = 10.0 / 2.5 // 除法: 4.0
let remainder = 10 % 3    // 求余: 1
```

### 复合赋值运算符

```swift
var value = 10
value += 5 // 等同于 value = value + 5
value -= 2 // 等同于 value = value - 2
value *= 2 // 等同于 value = value * 2
value /= 4 // 等同于 value = value / 4
```

### 比较运算符

```swift
let isEqual = 1 == 1         // true
let isNotEqual = 1 != 2      // true
let isGreater = 2 > 1        // true
let isLess = 1 < 2           // true
let isGreaterOrEqual = 2 >= 1 // true
let isLessOrEqual = 1 <= 1   // true
```

### 逻辑运算符

```swift
let allowEntry = true
let isLocked = false

// 逻辑非
if !isLocked {
    print("欢迎进入")
}

// 逻辑与
if allowEntry && !isLocked {
    print("欢迎进入")
}

// 逻辑或
if allowEntry || !isLocked {
    print("欢迎进入")
}
```

### 范围运算符

```swift
// 闭区间运算符
for index in 1...5 {
    print(index) // 打印 1 到 5
}

// 半开区间运算符
for index in 1..<5 {
    print(index) // 打印 1 到 4
}

// 单侧区间
let names = ["Anna", "Alex", "Brian", "Jack"]
for name in names[2...] {
    print(name) // 打印 "Brian" 和 "Jack"
}

for name in names[...2] {
    print(name) // 打印 "Anna", "Alex" 和 "Brian"
}
```

## 控制流

Swift 提供多种控制流语句：条件语句、循环语句和控制转移语句。

### 条件语句

#### if-else 语句

```swift
let temperature = 25

if temperature < 12 {
    print("很冷。请穿上外套。")
} else if temperature < 18 {
    print("凉爽。带上一件夹克。")
} else {
    print("温暖。穿 T 恤就好。")
}
```

#### switch 语句

Swift 的 switch 语句非常强大，支持任意类型的值和各种比较操作：

```swift
let someCharacter: Character = "z"

switch someCharacter {
case "a":
    print("第一个字母")
case "z":
    print("最后一个字母")
default:
    print("其他字母")
}
```

不需要显式的 break 语句，不存在隐式贯穿：

```swift
let anotherCharacter: Character = "a"
switch anotherCharacter {
case "a", "A":
    print("字母 A")
case "b", "B":
    print("字母 B")
default:
    print("其他字符")
}
```

可以使用区间匹配：

```swift
let approximateCount = 62
let naturalCount: String
switch approximateCount {
case 0:
    naturalCount = "没有"
case 1..<5:
    naturalCount = "几个"
case 5..<12:
    naturalCount = "很多"
case 12..<100:
    naturalCount = "几十个"
default:
    naturalCount = "很多很多"
}
```

### 循环语句

#### for-in 循环

```swift
// 遍历区间
for index in 1...5 {
    print("\(index) 乘以 5 等于 \(index * 5)")
}

// 遍历数组
let fruits = ["苹果", "香蕉", "橙子"]
for fruit in fruits {
    print("我喜欢吃 \(fruit)")
}

// 遍历字典
let numberOfLegs = ["蜘蛛": 8, "蚂蚁": 6, "猫": 4]
for (animal, legCount) in numberOfLegs {
    print("\(animal) 有 \(legCount) 条腿")
}
```

#### while 循环

```swift
var countdown = 5
while countdown > 0 {
    print("\(countdown)...")
    countdown -= 1
}
print("发射!")

// repeat-while 循环（相当于其他语言的 do-while）
var attempts = 0
repeat {
    attempts += 1
    print("尝试连接...")
} while attempts < 3
```

### 控制转移语句

```swift
// continue 跳过本次循环
for number in 1...10 {
    if number % 2 == 0 {
        continue // 跳过偶数
    }
    print(number) // 只打印奇数
}

// break 结束整个循环
for number in 1...10 {
    if number > 5 {
        break // 当 number 大于 5 时结束循环
    }
    print(number)
}

// fallthrough 用于 switch 语句中的贯穿
let integerToDescribe = 5
var description = "数字 \(integerToDescribe) 是"
switch integerToDescribe {
case 2, 3, 5, 7, 11, 13, 17, 19:
    description += "质数, "
    fallthrough
default:
    description += "整数."
}
print(description) // 输出 "数字 5 是质数, 整数."
```

## 函数

函数是执行特定任务的独立代码块。Swift 的函数功能强大且灵活。

### 函数定义和调用

```swift
// 定义一个简单函数
func greet(person: String) -> String {
    return "Hello, " + person + "!"
}

// 调用函数
let greeting = greet(person: "John")
print(greeting) // 输出 "Hello, John!"
```

### 参数和返回值

```swift
// 无参数无返回值
func sayHello() {
    print("Hello!")
}
sayHello()

// 多参数
func greet(person: String, alreadyGreeted: Bool) -> String {
    if alreadyGreeted {
        return "又见面了, \(person)!"
    } else {
        return "你好, \(person)!"
    }
}
print(greet(person: "Tim", alreadyGreeted: true))

// 无返回值的函数实际返回 Void 类型
func logMessage(message: String) {
    print("日志: \(message)")
}
```

### 参数标签和参数名称

```swift
// 参数标签 from，参数名 hometown
func sayHello(to person: String, from hometown: String) -> String {
    return "Hello \(person)! Glad you could visit from \(hometown)."
}
print(sayHello(to: "Bill", from: "Beijing"))

// 省略参数标签使用下划线
func multiply(_ a: Int, by b: Int) -> Int {
    return a * b
}
print(multiply(10, by: 5)) // 输出 50
```

### 默认参数值

```swift
func createProfile(name: String, age: Int = 30, occupation: String = "开发者") -> String {
    return "\(name), \(age)岁, 职业: \(occupation)"
}

print(createProfile(name: "李明")) // 使用默认值
print(createProfile(name: "王红", age: 25)) // 覆盖部分默认值
print(createProfile(name: "张伟", age: 40, occupation: "设计师")) // 覆盖所有默认值
```

### 可变参数

```swift
func calculateAverage(_ numbers: Double...) -> Double {
    var total: Double = 0
    for number in numbers {
        total += number
    }
    return total / Double(numbers.count)
}

print(calculateAverage(1, 2, 3, 4, 5)) // 输出 3.0
```

### 输入输出参数

```swift
func swapTwoInts(_ a: inout Int, _ b: inout Int) {
    let temporaryA = a
    a = b
    b = temporaryA
}

var someInt = 3
var anotherInt = 107
swapTwoInts(&someInt, &anotherInt)
print("someInt 现在是 \(someInt), anotherInt 现在是 \(anotherInt)")
```

### 函数类型

```swift
// add 函数的类型是 (Int, Int) -> Int
func add(_ a: Int, _ b: Int) -> Int {
    return a + b
}

// 函数类型作为变量类型
var mathFunction: (Int, Int) -> Int = add
print(mathFunction(2, 3)) // 输出 5

// 函数类型作为参数类型
func printMathResult(_ mathFunction: (Int, Int) -> Int, _ a: Int, _ b: Int) {
    print("结果: \(mathFunction(a, b))")
}
printMathResult(add, 3, 5) // 输出 "结果: 8"

// 函数类型作为返回类型
func stepForward(_ input: Int) -> Int {
    return input + 1
}
func stepBackward(_ input: Int) -> Int {
    return input - 1
}

func chooseStepFunction(backward: Bool) -> (Int) -> Int {
    return backward ? stepBackward : stepForward
}

var currentValue = 3
let moveNearerToZero = chooseStepFunction(backward: currentValue > 0)
print("从 \(currentValue) 开始")

while currentValue != 0 {
    currentValue = moveNearerToZero(currentValue)
    print("现在的值是 \(currentValue)")
}
```

## 集合类型

Swift 提供三种主要的集合类型：数组、集合和字典。

### 数组

数组用于存储相同类型的有序值列表：

```swift
// 创建空数组
var emptyArray: [String] = []
var anotherEmptyArray = [String]()

// 创建有初始值的数组
var fruits = ["苹果", "香蕉", "橙子"]

// 访问和修改数组
print(fruits[0]) // 输出 "苹果"
fruits[1] = "草莓"
print(fruits) // 输出 ["苹果", "草莓", "橙子"]

// 添加元素
fruits.append("芒果")
fruits += ["葡萄"]
print(fruits) // 输出 ["苹果", "草莓", "橙子", "芒果", "葡萄"]

// 插入元素
fruits.insert("梨", at: 2)
print(fruits) // 输出 ["苹果", "草莓", "梨", "橙子", "芒果", "葡萄"]

// 删除元素
let orange = fruits.remove(at: 3)
print("删除了 \(orange)") // 输出 "删除了 橙子"

// 数组属性和方法
print("数组长度: \(fruits.count)")
print("数组是否为空: \(fruits.isEmpty)")

// 遍历数组
for fruit in fruits {
    print(fruit)
}

// 带索引遍历
for (index, fruit) in fruits.enumerated() {
    print("第 \(index + 1) 个水果是: \(fruit)")
}
```

### 集合

集合用于存储相同类型的无序且唯一的值：

```swift
// 创建空集合
var emptySet = Set<String>()

// 从数组创建集合
var genres: Set<String> = ["摇滚", "古典", "嘻哈"]

// 添加元素
genres.insert("爵士")

// 删除元素
if let removedGenre = genres.remove("嘻哈") {
    print("\(removedGenre) 已被删除")
}

// 检查元素
if genres.contains("古典") {
    print("我喜欢古典音乐")
}

// 集合操作
let oddDigits: Set = [1, 3, 5, 7, 9]
let evenDigits: Set = [0, 2, 4, 6, 8]
let singleDigitPrimeNumbers: Set = [2, 3, 5, 7]

// 并集
let unionSet = oddDigits.union(evenDigits)
print(unionSet) // [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

// 交集
let intersectionSet = oddDigits.intersection(singleDigitPrimeNumbers)
print(intersectionSet) // [3, 5, 7]

// 差集
let differenceSet = oddDigits.subtracting(singleDigitPrimeNumbers)
print(differenceSet) // [1, 9]

// 对称差
let symmetricDifference = oddDigits.symmetricDifference(singleDigitPrimeNumbers)
print(symmetricDifference) // [1, 2, 9]
```

### 字典

字典用于存储相同类型的键和相同类型的值的关联：

```swift
// 创建空字典
var emptyDictionary = [String: Int]()

// 创建有初始值的字典
var airports = ["TYO": "东京", "DUB": "都柏林", "PEK": "北京"]

// 访问和修改字典
print(airports["PEK"]!) // 输出 "北京"
airports["LHR"] = "伦敦"
print(airports) // 输出 ["TYO": "东京", "DUB": "都柏林", "PEK": "北京", "LHR": "伦敦"]

// 修改值
airports["LHR"] = "伦敦希思罗"
print(airports["LHR"]!) // 输出 "伦敦希思罗"

// 使用 updateValue 方法更新值（返回旧值）
if let oldValue = airports.updateValue("都柏林机场", forKey: "DUB") {
    print("DUB 的旧值是 \(oldValue)")
}

// 删除键值对
airports["TYO"] = nil // 删除 TYO

if let removedValue = airports.removeValue(forKey: "DUB") {
    print("删除了 \(removedValue)")
}

// 字典属性
print("字典包含 \(airports.count) 个项目")
print("字典是否为空: \(airports.isEmpty)")

// 遍历字典
for (airportCode, airportName) in airports {
    print("\(airportCode): \(airportName)")
}

// 获取所有的键或值
let airportCodes = Array(airports.keys)
let airportNames = Array(airports.values)
```

## 可选类型

可选类型表示一个值可能存在或不存在。这是 Swift 安全特性的重要部分。

### 可选类型基础

```swift
// 声明一个可选类型
var possibleNumber: Int? = nil
possibleNumber = 42

// 使用 if 语句判断可选值是否包含值
if possibleNumber != nil {
    print("possibleNumber 包含值 \(possibleNumber!)")
}

// 使用可选绑定更安全地解包
if let actualNumber = possibleNumber {
    print("possibleNumber 包含值 \(actualNumber)")
} else {
    print("possibleNumber 不包含值")
}
```

### 强制解包

```swift
// 使用感叹号强制解包
let possibleNumber: Int? = 42
let forcedNumber: Int = possibleNumber! // 确定有值时才使用强制解包
```

### 可选绑定

```swift
// 单个可选绑定
if let firstNumber = Int("4") {
    print("第一个数字是 \(firstNumber)")
}

// 多个可选绑定
if let firstNumber = Int("4"), let secondNumber = Int("42") {
    print("第一个数字是 \(firstNumber)，第二个数字是 \(secondNumber)")
}

// 带条件的可选绑定
if let firstNumber = Int("4"), let secondNumber = Int("42"), firstNumber < secondNumber {
    print("\(firstNumber) < \(secondNumber)")
}
```

### 隐式解包可选类型

```swift
// 隐式解包可选类型（在确定初始化后总会有值的情况下使用）
let possibleString: String? = "一个可选字符串"
let forcedString: String = possibleString! // 需要强制解包

let assumedString: String! = "一个隐式解包可选字符串"
let implicitString: String = assumedString // 不需要感叹号
```

### nil 合并运算符

```swift
// 使用 nil 合并运算符（??）提供默认值
let defaultName = "游客"
var userDefinedName: String? = nil

let greeting = "你好, \(userDefinedName ?? defaultName)"
print(greeting) // 输出 "你好, 游客"
```

### 可选链

```swift
// 可选链
class Person {
    var residence: Residence?
}

class Residence {
    var numberOfRooms = 1
}

let john = Person()

// 使用可选链（如果 residence 为 nil，整个表达式为 nil）
let roomCount = john.residence?.numberOfRooms
print(roomCount as Any) // 输出 nil

// 为 residence 赋值
john.residence = Residence()
if let roomCount = john.residence?.numberOfRooms {
    print("John 的房子有 \(roomCount) 个房间")
} else {
    print("无法获取房间数量")
}
```

## 类型转换

Swift 提供了两种类型转换：
- 向下转型（Downcasting）：将父类类型转换为子类类型
- 类型检查：确定实例类型

### 类型检查

```swift
// 使用 is 运算符检查类型
let someValue: Any = 42

if someValue is Int {
    print("someValue 是一个整数")
}
```

### 向下转型

```swift
class MediaItem {
    var name: String
    init(name: String) {
        self.name = name
    }
}

class Movie: MediaItem {
    var director: String
    init(name: String, director: String) {
        self.director = director
        super.init(name: name)
    }
}

class Song: MediaItem {
    var artist: String
    init(name: String, artist: String) {
        self.artist = artist
        super.init(name: name)
    }
}

// 创建一个包含 Movie 和 Song 实例的数组
let library = [
    Movie(name: "流浪地球", director: "郭帆"),
    Song(name: "Shake It Off", artist: "Taylor Swift"),
    Movie(name: "长津湖", director: "陈凯歌")
]

// 数组类型为 [MediaItem]，需要向下转型才能访问 Movie 或 Song 的特有属性
for item in library {
    if let movie = item as? Movie {
        print("电影: \(movie.name), 导演: \(movie.director)")
    } else if let song = item as? Song {
        print("歌曲: \(song.name), 歌手: \(song.artist)")
    }
}
```

### Any 和 AnyObject

```swift
// Any 可以表示任何类型的实例，包括函数类型
// AnyObject 可以表示任何类类型的实例

var things: [Any] = []
things.append(0)
things.append(0.0)
things.append("hello")
things.append((3.0, 5.0))
things.append({ (name: String) -> String in "Hello, \(name)" })

for thing in things {
    switch thing {
    case let someInt as Int:
        print("整数值: \(someInt)")
    case let someDouble as Double:
        print("浮点值: \(someDouble)")
    case let someString as String:
        print("字符串值: \"\(someString)\"")
    case let (x, y) as (Double, Double):
        print("坐标: \(x), \(y)")
    case let stringConverter as (String) -> String:
        print(stringConverter("Swift"))
    default:
        print("其他类型")
    }
}
```

## 字符串处理

Swift 的字符串是 Unicode 字符的集合，提供了强大的字符串处理功能。

### 字符串字面量

```swift
// 创建字符串
let singleLineString = "这是一个字符串"

// 多行字符串
let multilineString = """
这是一个多行字符串。
它可以包含多行文本。
每一行都将作为字符串的一部分。
"""

// 字符串插值
let multiplier = 3
let message = "\(multiplier) 乘以 2.5 等于 \(Double(multiplier) * 2.5)"
```

### 字符串操作

```swift
// 字符串连接
let string1 = "hello"
let string2 = " world"
let greeting = string1 + string2

// 字符串可变性
var variableString = "Horse"
variableString += " and carriage"

// 访问字符
for character in "Dog!🐶" {
    print(character)
}

// 获取字符计数
let word = "café"
print("字符数量: \(word.count)")

// 字符串索引
let greeting2 = "Hello, world!"
let index = greeting2.firstIndex(of: ",") ?? greeting2.endIndex
let beginning = greeting2[..<index] // "Hello"

// 插入和删除
var welcome = "hello"
welcome.insert("!", at: welcome.endIndex)
welcome.insert(contentsOf: " there", at: welcome.index(before: welcome.endIndex))

welcome.remove(at: welcome.index(before: welcome.endIndex))
let range = welcome.index(welcome.endIndex, offsetBy: -6)..<welcome.endIndex
welcome.removeSubrange(range)
```

### 字符串比较

```swift
// 字符串相等性
let quotation = "We're a lot alike, you and I."
let sameQuotation = "We're a lot alike, you and I."
if quotation == sameQuotation {
    print("这两个字符串相等")
}

// 前缀和后缀
let romeoAndJuliet = [
    "Act 1 Scene 1: Verona, A public place",
    "Act 1 Scene 2: Capulet's mansion",
    "Act 1 Scene 3: A room in Capulet's mansion",
    "Act 1 Scene 4: A street outside Capulet's mansion",
    "Act 1 Scene 5: The Great Hall in Capulet's mansion",
    "Act 2 Scene 1: Outside Capulet's mansion",
    "Act 2 Scene 2: Capulet's orchard",
    "Act 2 Scene 3: Outside Friar Lawrence's cell",
    "Act 2 Scene 4: A street in Verona",
    "Act 2 Scene 5: Capulet's mansion",
    "Act 2 Scene 6: Friar Lawrence's cell"
]

var act1SceneCount = 0
for scene in romeoAndJuliet {
    if scene.hasPrefix("Act 1 ") {
        act1SceneCount += 1
    }
}
print("第一幕共有 \(act1SceneCount) 个场景")

var mansionCount = 0
var cellCount = 0
for scene in romeoAndJuliet {
    if scene.hasSuffix("Capulet's mansion") {
        mansionCount += 1
    } else if scene.hasSuffix("Friar Lawrence's cell") {
        cellCount += 1
    }
}
print("\(mansionCount) 个场景在卡普莱特宅邸")
print("\(cellCount) 个场景在劳伦斯修士的牢房")
```

## 练习题

1. **基础练习**：创建一个函数，接受一个整数数组，返回数组中的最大值和最小值。

```swift
func findMinMax(numbers: [Int]) -> (min: Int, max: Int)? {
    if numbers.isEmpty { return nil }
    
    var currentMin = numbers[0]
    var currentMax = numbers[0]
    
    for number in numbers[1..<numbers.count] {
        if number < currentMin {
            currentMin = number
        } else if number > currentMax {
            currentMax = number
        }
    }
    
    return (currentMin, currentMax)
}

// 测试
if let result = findMinMax(numbers: [8, 2, 10, 4, 7, 6, 3, 9]) {
    print("最小值: \(result.min), 最大值: \(result.max)")
} else {
    print("数组为空")
}
```

2. **中级练习**：编写一个函数，检查一个字符串是否是回文（正着读和反着读都一样）。

```swift
func isPalindrome(_ text: String) -> Bool {
    // 移除非字母数字字符并转为小写
    let cleanText = text.lowercased().filter { $0.isLetter || $0.isNumber }
    
    // 创建反转字符串
    let reversed = String(cleanText.reversed())
    
    // 比较原字符串和反转字符串
    return cleanText == reversed
}

// 测试
print(isPalindrome("A man, a plan, a canal: Panama")) // true
print(isPalindrome("Hello, World!")) // false
```

3. **高级练习**：创建一个函数，将一个整数转换为罗马数字表示。

```swift
func intToRoman(_ num: Int) -> String {
    guard num > 0 && num < 4000 else {
        return "超出范围(1-3999)"
    }
    
    let values = [1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1]
    let symbols = ["M", "CM", "D", "CD", "C", "XC", "L", "XL", "X", "IX", "V", "IV", "I"]
    
    var result = ""
    var remainder = num
    
    for i in 0..<values.count {
        while remainder >= values[i] {
            remainder -= values[i]
            result += symbols[i]
        }
    }
    
    return result
}

// 测试
print(intToRoman(3)) // "III"
print(intToRoman(58)) // "LVIII"
print(intToRoman(1994)) // "MCMXCIV"
```

## 小结

本章介绍了 Swift 的基础语法和核心概念：

- 变量和常量（var、let）
- 基本数据类型（Int、Double、Bool、String）
- 运算符和表达式
- 控制流（if-else、switch、for-in、while）
- 函数定义和使用
- 集合类型（数组、集合、字典）
- 可选类型
- 类型转换
- 字符串处理

掌握这些基础知识后，您将能够编写简单的 Swift 程序，并准备好学习更高级的 Swift 概念，如类和结构体、枚举、协议和扩展等。

在下一章 [Swift 进阶特性](swift-advanced.md) 中，我们将探讨闭包、泛型、协议和扩展等更高级的 Swift 特性。 