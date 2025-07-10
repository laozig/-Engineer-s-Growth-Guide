# Combine 框架 - 响应式编程

## 目录
- [简介](#简介)
- [基础概念](#基础概念)
- [核心组件](#核心组件)
- [发布者（Publishers）](#发布者publishers)
- [订阅者（Subscribers）](#订阅者subscribers)
- [操作符（Operators）](#操作符operators)
- [实际应用](#实际应用)
- [与其他框架的集成](#与其他框架的集成)
- [调试与错误处理](#调试与错误处理)
- [性能优化](#性能优化)
- [最佳实践](#最佳实践)
- [常见问题与解决方案](#常见问题与解决方案)

## 简介

Combine 是 Apple 在 WWDC 2019 推出的响应式编程框架，它为处理异步事件提供了声明式的 Swift API。Combine 可以帮助开发者解决常见的编程场景，如网络请求、用户输入处理、数据绑定等。

### 什么是响应式编程？

响应式编程是一种专注于数据流和变化传播的编程范式。通过响应式编程，我们可以构建数据流管道，当数据源发生变化时，这些变化会自动通过管道传播到最终的接收者。

### Combine 的核心优势

- **声明式代码**：使用声明式方法定义数据处理逻辑，而不是命令式
- **组合性**：轻松组合多个操作，创建复杂的数据转换流程
- **内置错误处理**：统一的错误处理机制
- **类型安全**：利用 Swift 的类型系统提供编译时安全
- **内存管理**：自动处理订阅生命周期和内存管理
- **主线程同步**：简化在不同线程间切换的操作
- **系统集成**：与 Foundation、SwiftUI 等 Apple 框架无缝集成

### 与其他响应式框架的比较

Combine 与 RxSwift 和 ReactiveSwift 等框架有许多相似之处，但作为 Apple 官方框架，它与 Swift 和其他 Apple 技术的集成更加紧密。

| 框架 | 优势 | 劣势 |
|------|------|------|
| Combine | 系统集成、无需第三方依赖 | 仅支持 iOS 13+ |
| RxSwift | 社区活跃、跨平台支持 | 需要额外依赖 |
| ReactiveSwift | 成熟稳定 | 学习曲线较陡 |

## 基础概念

在深入了解 Combine 框架之前，先理解几个关键概念非常重要。

### 发布者（Publisher）

发布者是数据的来源，它可以随时间发出一系列值，并且可能在某个时刻完成或失败。发布者符合 `Publisher` 协议，定义了两个关联类型：

- `Output`：发布者发出的值的类型
- `Failure`：发布者可能失败的错误类型

```swift
protocol Publisher {
    associatedtype Output
    associatedtype Failure: Error
    
    func receive<S>(subscriber: S) where S: Subscriber, Self.Failure == S.Failure, Self.Output == S.Input
}
```

### 订阅者（Subscriber）

订阅者负责从发布者接收值。当订阅发布者时，订阅者可以接收三种类型的事件：

- 接收订阅（receive subscription）
- 接收值（receive value）
- 接收完成或失败（receive completion）

```swift
protocol Subscriber {
    associatedtype Input
    associatedtype Failure: Error
    
    func receive(subscription: Subscription)
    func receive(_ input: Self.Input) -> Subscribers.Demand
    func receive(completion: Subscribers.Completion<Self.Failure>)
}
```

### 订阅（Subscription）

订阅代表发布者和订阅者之间的连接。它控制发布者向订阅者发送值的节奏。

```swift
protocol Subscription: Cancellable {
    func request(_ demand: Subscribers.Demand)
}
```

### 需求（Demand）

需求表示订阅者想要接收的值的数量，它可以是有限的（如 `.max(10)`）或无限的（`.unlimited`）。

### 操作符（Operator）

操作符是发布者上的方法，用于转换、过滤或组合发布者发出的值。操作符返回新的发布者，这使得可以创建处理管道。

### 可取消（Cancellable）

可取消协议表示可以被取消的操作。当订阅被取消时，发布者应停止发送值，并清理相关资源。

## 核心组件

### 常用发布者类型

1. **Just**：发出单个值然后完成的发布者
```swift
let publisher = Just(5)
// 发出 5，然后完成
```

2. **Empty**：不发出任何值就完成的发布者
```swift
let publisher = Empty<Int, Never>()
// 立即完成，不发出任何值
```

3. **Fail**：发出错误而不发出任何值的发布者
```swift
let publisher = Fail<Int, Error>(error: SomeError())
// 立即失败，不发出任何值
```

4. **Future**：执行一次性异步操作并发出结果的发布者
```swift
let publisher = Future<Int, Error> { promise in
    // 执行异步操作
    DispatchQueue.global().async {
        // 成功时
        promise(.success(42))
        // 或失败时
        // promise(.failure(SomeError()))
    }
}
```

5. **Deferred**：延迟创建发布者直到有订阅者的发布者
```swift
let publisher = Deferred {
    Just(Date()) // 每次被订阅时创建新的 Just 发布者
}
```

6. **Publishers.Sequence**：从序列创建发布者
```swift
let publisher = [1, 2, 3, 4, 5].publisher
// 依次发出 1, 2, 3, 4, 5，然后完成
```

### 常用订阅者类型

1. **Sink**：通过闭包处理接收到的值和完成事件
```swift
let cancellable = publisher.sink(
    receiveCompletion: { completion in
        switch completion {
        case .finished:
            print("发布者正常完成")
        case .failure(let error):
            print("发布者发生错误: \(error)")
        }
    },
    receiveValue: { value in
        print("接收到值: \(value)")
    }
)
```

2. **Assign**：将接收到的值赋给对象的属性
```swift
class MyViewModel {
    var currentValue: Int = 0
}

let viewModel = MyViewModel()
let cancellable = publisher.assign(to: \.currentValue, on: viewModel)
```

3. **Subject**：既是发布者又是订阅者
```swift
// PassthroughSubject：不保留值，只将新值传递给订阅者
let passthroughSubject = PassthroughSubject<Int, Never>()

// CurrentValueSubject：保留当前值，新订阅者会立即收到当前值
let currentValueSubject = CurrentValueSubject<Int, Never>(0)
```

### AnyCancellable

`AnyCancellable` 是一个类，用于存储取消令牌。当 `AnyCancellable` 实例被释放时，它会自动取消订阅。

```swift
var cancellables = Set<AnyCancellable>() // 常用模式：存储取消令牌

publisher
    .sink { _ in }
    .store(in: &cancellables) // 存储取消令牌，避免订阅被过早释放
```

## 发布者（Publishers）

Combine 框架提供了多种发布者，可以适应不同的场景需求。

### 常见的内置发布者

#### Foundation 集成

Combine 与 Foundation 框架紧密集成，提供了许多便捷的发布者：

##### NotificationCenter 扩展
```swift
// 监听通知
let publisher = NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)

publisher
    .sink { notification in
        print("应用变为活跃状态")
    }
    .store(in: &cancellables)
```

##### URLSession 扩展
```swift
// 网络请求
let url = URL(string: "https://api.example.com/data")!
let publisher = URLSession.shared.dataTaskPublisher(for: url)

publisher
    .map { data, response in data }
    .decode(type: MyModel.self, decoder: JSONDecoder())
    .sink(
        receiveCompletion: { completion in
            if case .failure(let error) = completion {
                print("请求失败: \(error)")
            }
        },
        receiveValue: { model in
            print("接收到模型: \(model)")
        }
    )
    .store(in: &cancellables)
```

##### Timer 扩展
```swift
// 定时器
let publisher = Timer.publish(every: 1.0, on: .main, in: .common)
    .autoconnect()

publisher
    .sink { date in
        print("当前时间: \(date)")
    }
    .store(in: &cancellables)
```

##### KVO 集成
```swift
// 键值观察
class MyObject: NSObject {
    @objc dynamic var value: Int = 0
}

let object = MyObject()
let publisher = object.publisher(for: \.value)

publisher
    .sink { value in
        print("值变为: \(value)")
    }
    .store(in: &cancellables)

// 改变值
object.value = 42
```

### 自定义发布者

虽然内置发布者足以应对大多数场景，但有时候我们需要创建自定义发布者：

```swift
struct MyPublisher: Publisher {
    typealias Output = Int
    typealias Failure = Never
    
    let range: ClosedRange<Int>
    let interval: TimeInterval
    
    func receive<S>(subscriber: S) where S: Subscriber, Failure == S.Failure, Output == S.Input {
        let subscription = MySubscription(range: range, interval: interval, subscriber: subscriber)
        subscriber.receive(subscription: subscription)
    }
}

class MySubscription<S: Subscriber>: Subscription where S.Input == Int {
    private var subscriber: S?
    private let range: ClosedRange<Int>
    private let interval: TimeInterval
    private var currentValue: Int
    private var timer: Timer?
    
    init(range: ClosedRange<Int>, interval: TimeInterval, subscriber: S) {
        self.range = range
        self.interval = interval
        self.subscriber = subscriber
        self.currentValue = range.lowerBound
    }
    
    func request(_ demand: Subscribers.Demand) {
        guard demand > .none, subscriber != nil else { return }
        
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] timer in
            guard let self = self, let subscriber = self.subscriber else {
                timer.invalidate()
                return
            }
            
            _ = subscriber.receive(self.currentValue)
            
            self.currentValue += 1
            if self.currentValue > self.range.upperBound {
                subscriber.receive(completion: .finished)
                self.cancel()
            }
        }
    }
    
    func cancel() {
        timer?.invalidate()
        timer = nil
        subscriber = nil
    }
}

// 使用
let publisher = MyPublisher(range: 1...10, interval: 1.0)
publisher
    .sink(
        receiveCompletion: { _ in print("完成") },
        receiveValue: { print("值: \($0)") }
    )
    .store(in: &cancellables)
```

### 连接型发布者（Connectable Publishers）

连接型发布者允许控制何时开始向订阅者发送值。这对于广播场景或确保所有订阅者同时开始接收值很有用。

```swift
// 创建连接型发布者
let publisher = [1, 2, 3, 4, 5].publisher
    .delay(for: 1, scheduler: DispatchQueue.main)
    .makeConnectable()

// 添加订阅者，但尚未接收值
let subscription1 = publisher.sink { print("订阅者1: \($0)") }
let subscription2 = publisher.sink { print("订阅者2: \($0)") }

// 开始发送值
let connection = publisher.connect()

// 稍后取消连接
DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
    connection.cancel()
}
``` 

## 订阅者（Subscribers）

订阅者是 Combine 数据流的终点，负责接收并处理发布者发出的值。

### 理解订阅流程

当发布者与订阅者连接时，会遵循以下流程：

1. 订阅者调用发布者的 `subscribe(_:)` 方法
2. 发布者创建一个订阅，并通过调用 `receive(subscription:)` 将其发送给订阅者
3. 订阅者通过调用订阅的 `request(_:)` 方法请求值
4. 发布者发送值，订阅者通过 `receive(_:)` 接收值
5. 最终，发布者发送完成事件（成功或失败），订阅者通过 `receive(completion:)` 接收

![订阅流程图](https://example.com/subscription_flow.png)

### 内置订阅者

#### Sink

`sink` 是最通用的订阅者，它使用闭包处理接收到的值和完成事件：

```swift
let cancellable = publisher.sink(
    receiveCompletion: { completion in
        switch completion {
        case .finished:
            print("完成")
        case .failure(let error):
            print("错误: \(error)")
        }
    },
    receiveValue: { value in
        print("接收到值: \(value)")
    }
)
```

#### Assign

`assign` 用于将发布者的输出直接绑定到对象的属性：

```swift
class MyViewModel {
    var counter = 0
}

let viewModel = MyViewModel()
let cancellable = publisher
    .assign(to: \.counter, on: viewModel)
```

注意：`assign` 要求发布者的 `Failure` 类型为 `Never`，因此在使用前可能需要使用 `.assertNoFailure()` 或 `.catch()` 处理错误。

### 自定义订阅者

创建自定义订阅者允许更精细地控制如何处理接收到的值：

```swift
class MySubscriber<Input, Failure: Error>: Subscriber {
    func receive(subscription: Subscription) {
        print("接收到订阅")
        // 请求无限数量的值
        subscription.request(.unlimited)
    }
    
    func receive(_ input: Input) -> Subscribers.Demand {
        print("接收到值: \(input)")
        // 维持当前需求
        return .none
    }
    
    func receive(completion: Subscribers.Completion<Failure>) {
        switch completion {
        case .finished:
            print("发布者正常完成")
        case .failure(let error):
            print("发布者发生错误: \(error)")
        }
    }
}

// 使用
let subscriber = MySubscriber<Int, Never>()
let cancellable = [1, 2, 3].publisher
    .subscribe(subscriber)
```

### Subject

Subject 既是发布者又是订阅者，这使其成为连接命令式代码和声明式 Combine 代码的理想桥梁。

#### PassthroughSubject

`PassthroughSubject` 不存储值，仅将收到的值转发给订阅者：

```swift
let subject = PassthroughSubject<Int, Never>()

// 添加订阅者
let cancellable = subject
    .sink { value in
        print("接收到值: \(value)")
    }

// 发送值
subject.send(1)
subject.send(2)
subject.send(3)

// 发送完成信号
subject.send(completion: .finished)
```

#### CurrentValueSubject

`CurrentValueSubject` 存储一个当前值，新的订阅者会立即收到这个值：

```swift
let subject = CurrentValueSubject<Int, Never>(0)

// 添加订阅者 - 会立即接收当前值 0
let cancellable = subject
    .sink { value in
        print("接收到值: \(value)")
    }

// 发送新值
subject.send(1)
subject.send(2)

// 通过属性访问当前值
print("当前值: \(subject.value)")

// 通过属性设置新值
subject.value = 3

// 发送完成信号
subject.send(completion: .finished)
```

### 内存管理

Combine 使用引用计数来管理订阅的生命周期。当订阅被取消或订阅对象被释放时，相关资源会被清理。

#### 存储和管理取消令牌

常见的模式是使用一个集合来存储所有订阅的取消令牌：

```swift
class MyViewModel {
    // 存储所有订阅
    private var cancellables = Set<AnyCancellable>()
    
    func setupBindings() {
        // 方式1：使用 store(in:)
        publisher1
            .sink { _ in }
            .store(in: &cancellables)
        
        // 方式2：手动添加
        let cancellable = publisher2.sink { _ in }
        cancellables.insert(cancellable)
    }
    
    // 在对象释放时，所有订阅都会被自动取消
    deinit {
        print("所有订阅被取消")
    }
}
```

#### 使用 weak 避免循环引用

在闭包中引用 self 时，要注意避免循环引用：

```swift
publisher
    .sink { [weak self] value in
        guard let self = self else { return }
        self.process(value)
    }
    .store(in: &cancellables)
```

## 操作符（Operators）

Combine 提供了丰富的操作符，用于转换、过滤和组合发布者的输出。

### 转换操作符

#### map

将发布者的每个输出转换为新值：

```swift
[1, 2, 3].publisher
    .map { $0 * 2 }
    // 输出: 2, 4, 6
```

#### tryMap

类似 `map`，但允许转换操作抛出错误：

```swift
[1, 2, 3].publisher
    .tryMap { value -> Int in
        if value == 2 {
            throw MyError.invalidValue
        }
        return value * 2
    }
    // 输出: 2, 然后失败
```

#### flatMap

将发布者的每个输出转换为新的发布者，然后将所有这些发布者的输出平铺成单个流：

```swift
struct User { let id: Int }

[User(id: 1), User(id: 2)].publisher
    .flatMap { user -> AnyPublisher<String, Never> in
        // 为每个用户获取详细信息
        return fetchUserDetails(id: user.id)
    }
    // 输出: 两个用户的详细信息
```

#### scan

对发布者的输出应用累积操作：

```swift
[1, 2, 3, 4].publisher
    .scan(0) { accumulator, value in
        accumulator + value
    }
    // 输出: 1, 3, 6, 10
```

### 过滤操作符

#### filter

只允许符合条件的值通过：

```swift
[1, 2, 3, 4, 5].publisher
    .filter { $0 % 2 == 0 }
    // 输出: 2, 4
```

#### removeDuplicates

删除连续的重复值：

```swift
[1, 1, 2, 2, 3, 3, 3, 4].publisher
    .removeDuplicates()
    // 输出: 1, 2, 3, 4
```

#### compactMap

类似 `map`，但会过滤掉 nil 结果：

```swift
["1", "2", "three", "4"].publisher
    .compactMap { Int($0) }
    // 输出: 1, 2, 4
```

#### first / last

只取第一个或最后一个值：

```swift
[1, 2, 3, 4].publisher
    .first()
    // 输出: 1，然后完成

[1, 2, 3, 4].publisher
    .last()
    // 输出: 4，然后完成
```

#### first(where:) / last(where:)

取第一个或最后一个符合条件的值：

```swift
[1, 2, 3, 4].publisher
    .first(where: { $0 > 2 })
    // 输出: 3，然后完成
```

#### drop / prefix

跳过前几个值或只取前几个值：

```swift
[1, 2, 3, 4, 5].publisher
    .dropFirst(2)
    // 输出: 3, 4, 5

[1, 2, 3, 4, 5].publisher
    .prefix(2)
    // 输出: 1, 2，然后完成
```

### 组合操作符

#### merge

将多个发布者的输出合并成一个流：

```swift
let publisher1 = [1, 2, 3].publisher
let publisher2 = [4, 5, 6].publisher

publisher1
    .merge(with: publisher2)
    // 输出可能是: 1, 4, 2, 5, 3, 6（顺序不确定）
```

#### zip

将多个发布者的输出配对成元组：

```swift
let publisher1 = [1, 2, 3].publisher
let publisher2 = ["A", "B", "C"].publisher

publisher1
    .zip(publisher2)
    // 输出: (1, "A"), (2, "B"), (3, "C")
```

#### combineLatest

将多个发布者的最新值组合成元组：

```swift
let publisher1 = PassthroughSubject<Int, Never>()
let publisher2 = PassthroughSubject<String, Never>()

publisher1
    .combineLatest(publisher2)
    .sink { print("\($0)") }
    .store(in: &cancellables)

publisher1.send(1)  // 没有输出，等待 publisher2
publisher2.send("A")  // 输出: (1, "A")
publisher1.send(2)  // 输出: (2, "A")
publisher2.send("B")  // 输出: (2, "B")
```

### 时间操作符

#### delay

延迟发布者的输出：

```swift
[1, 2, 3].publisher
    .delay(for: .seconds(1), scheduler: DispatchQueue.main)
    // 1秒后开始输出: 1, 2, 3
```

#### timeout

如果发布者在指定时间内没有发出值，则失败：

```swift
publisher
    .timeout(.seconds(5), scheduler: DispatchQueue.main)
    // 如果5秒内没有值，发出错误
```

#### throttle / debounce

控制发布频率：

```swift
// throttle: 每隔1秒最多发出一个值
publisher
    .throttle(for: .seconds(1), scheduler: DispatchQueue.main, latest: true)

// debounce: 只在沉默1秒后发出最后一个值
publisher
    .debounce(for: .seconds(1), scheduler: DispatchQueue.main)
```

### 错误处理操作符

#### catch

当发布者失败时提供替代发布者：

```swift
publisher
    .catch { error -> AnyPublisher<Int, Never> in
        print("捕获到错误: \(error)")
        return Just(0).eraseToAnyPublisher()
    }
```

#### retry

在失败时重试指定次数：

```swift
publisher
    .retry(3)  // 失败时最多重试3次
```

#### assertNoFailure

断言发布者不会失败，如果失败则触发断言错误：

```swift
publisher
    .assertNoFailure()
    .sink { /* 处理值 */ }
```

### 调试操作符

#### print

打印发布者的所有事件：

```swift
[1, 2, 3].publisher
    .print("MyPublisher")
    .sink { _ in }
```

#### handleEvents

在发布者生命周期的各个阶段执行代码：

```swift
publisher
    .handleEvents(
        receiveSubscription: { _ in print("已订阅") },
        receiveOutput: { print("接收值: \($0)") },
        receiveCompletion: { print("完成: \($0)") },
        receiveCancel: { print("已取消") },
        receiveRequest: { print("请求: \($0)") }
    )
```

### 类型擦除

#### eraseToAnyPublisher

隐藏发布者的具体类型，简化 API：

```swift
func createPublisher() -> AnyPublisher<Int, Never> {
    return [1, 2, 3].publisher
        .map { $0 * 2 }
        .eraseToAnyPublisher()
}
```

## 实际应用

Combine 框架可以应用于多种场景，如网络请求、用户输入处理、数据绑定等。以下是一些实际应用示例：

### 网络请求

使用 Combine 框架可以轻松处理网络请求，并将其结果转换为数据流：

```swift
let url = URL(string: "https://api.example.com/data")!
let publisher = URLSession.shared.dataTaskPublisher(for: url)

publisher
    .map { data, response in data }
    .decode(type: MyModel.self, decoder: JSONDecoder())
    .sink(
        receiveCompletion: { completion in
            if case .failure(let error) = completion {
                print("请求失败: \(error)")
            }
        },
        receiveValue: { model in
            print("接收到模型: \(model)")
        }
    )
    .store(in: &cancellables)
```

### 用户输入处理

Combine 框架可以轻松处理用户输入，并将其转换为数据流：

```swift
let publisher = NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)

publisher
    .sink { notification in
        print("应用变为活跃状态")
    }
    .store(in: &cancellables)
```

### 数据绑定

Combine 框架可以轻松处理数据绑定，并将其转换为数据流：

```swift
class MyViewModel {
    var currentValue: Int = 0
}

let viewModel = MyViewModel()
let cancellable = publisher.assign(to: \.currentValue, on: viewModel)
```

## 与其他框架的集成

Combine 框架可以与其他框架无缝集成，如 Foundation、SwiftUI 等。以下是一些集成示例：

### 与 Foundation 框架的集成

Combine 与 Foundation 框架紧密集成，提供了许多便捷的发布者：

##### NotificationCenter 扩展
```swift
// 监听通知
let publisher = NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)

publisher
    .sink { notification in
        print("应用变为活跃状态")
    }
    .store(in: &cancellables)
```

##### URLSession 扩展
```swift
// 网络请求
let url = URL(string: "https://api.example.com/data")!
let publisher = URLSession.shared.dataTaskPublisher(for: url)

publisher
    .map { data, response in data }
    .decode(type: MyModel.self, decoder: JSONDecoder())
    .sink(
        receiveCompletion: { completion in
            if case .failure(let error) = completion {
                print("请求失败: \(error)")
            }
        },
        receiveValue: { model in
            print("接收到模型: \(model)")
        }
    )
    .store(in: &cancellables)
```

##### Timer 扩展
```swift
// 定时器
let publisher = Timer.publish(every: 1.0, on: .main, in: .common)
    .autoconnect()

publisher
    .sink { date in
        print("当前时间: \(date)")
    }
    .store(in: &cancellables)
```

##### KVO 集成
```swift
// 键值观察
class MyObject: NSObject {
    @objc dynamic var value: Int = 0
}

let object = MyObject()
let publisher = object.publisher(for: \.value)

publisher
    .sink { value in
        print("值变为: \(value)")
    }
    .store(in: &cancellables)

// 改变值
object.value = 42
```

### 与 SwiftUI 框架的集成

Combine 框架可以与 SwiftUI 框架无缝集成，如使用 `@StateObject` 和 `@State` 属性包装器：

```swift
import SwiftUI

struct MyView: View {
    @StateObject private var viewModel = MyViewModel()

    var body: some View {
        Text("当前值: \(viewModel.currentValue)")
    }
}

struct MyView_Previews: PreviewProvider {
    static var previews: some View {
        MyView()
    }
}
```

## 调试与错误处理

Combine 框架提供了丰富的调试和错误处理功能，如使用 `print` 操作符打印发布者的所有事件：

```swift
[1, 2, 3].publisher
    .print("MyPublisher")
    .sink { _ in }
```

## 性能优化

Combine 框架在设计时考虑了性能优化，如使用引用计数来管理订阅的生命周期，避免不必要的内存分配和释放。

## 最佳实践

以下是一些 Combine 框架的最佳实践：

1. 使用 Combine 框架时，尽量使用声明式代码，避免命令式代码。
2. 使用 Combine 框架时，尽量使用内置发布者和订阅者，避免自定义发布者和订阅者。
3. 使用 Combine 框架时，尽量使用内置操作符，避免自定义操作符。
4. 使用 Combine 框架时，尽量使用内置错误处理机制，避免自定义错误处理机制。

## 常见问题与解决方案

以下是一些常见问题及其解决方案：

1. 如何处理发布者的错误？

解决方案：使用 `catch` 操作符处理发布者的错误。

```swift
publisher
    .catch { error -> AnyPublisher<Int, Never> in
        print("捕获到错误: \(error)")
        return Just(0).eraseToAnyPublisher()
    }
```

2. 如何处理订阅者的错误？

解决方案：使用 `assertNoFailure` 断言发布者不会失败，如果失败则触发断言错误。

```swift
publisher
    .assertNoFailure()
    .sink { /* 处理值 */ }
```

3. 如何处理发布者的完成事件？

解决方案：使用 `receive(completion:)` 接收发布者的完成事件。

```swift
let cancellable = publisher.sink(
    receiveCompletion: { completion in
        switch completion {
        case .finished:
            print("完成")
        case .failure(let error):
            print("错误: \(error)")
        }
    },
    receiveValue: { value in
        print("接收到值: \(value)")
    }
)
```

4. 如何处理发布者的值？

解决方案：使用 `receive(value:)` 接收发布者的值。

```swift
let cancellable = publisher.sink(
    receiveCompletion: { completion in
        switch completion {
        case .finished:
            print("完成")
        case .failure(let error):
            print("错误: \(error)")
        }
    },
    receiveValue: { value in
        print("接收到值: \(value)")
    }
)
```

5. 如何处理发布者的订阅？

解决方案：使用 `receive(subscription:)` 接收发布者的订阅。

```swift
let cancellable = publisher.sink(
    receiveCompletion: { completion in
        switch completion {
        case .finished:
            print("完成")
        case .failure(let error):
            print("错误: \(error)")
        }
    },
    receiveValue: { value in
        print("接收到值: \(value)")
    }
)
```

6. 如何处理发布者的取消？

解决方案：使用 `receive(completion:)` 接收发布者的取消事件。

```swift
let cancellable = publisher.sink(
    receiveCompletion: { completion in
        switch completion {
        case .finished:
            print("完成")
        case .failure(let error):
            print("错误: \(error)")
        }
    },
    receiveValue: { value in
        print("接收到值: \(value)")
    }
)
``` 