# 设计模式 - iOS 常用设计模式

设计模式是在软件设计中常见问题的通用可重用解决方案。它们代表了开发者社区多年经验的结晶，为开发者提供了处理各种复杂问题的经过验证的方法。本文将详细介绍 iOS 开发中常用的设计模式，并结合 Swift 语言提供实用的代码示例。

## 目录

- [创建型模式](#创建型模式)
  - [单例模式 (Singleton)](#单例模式-singleton)
  - [工厂方法模式 (Factory Method)](#工厂方法模式-factory-method)
  - [抽象工厂模式 (Abstract Factory)](#抽象工厂模式-abstract-factory)
  - [建造者模式 (Builder)](#建造者模式-builder)
  - [原型模式 (Prototype)](#原型模式-prototype)
- [结构型模式](#结构型模式)
  - [适配器模式 (Adapter)](#适配器模式-adapter)
  - [桥接模式 (Bridge)](#桥接模式-bridge)
  - [组合模式 (Composite)](#组合模式-composite)
  - [装饰模式 (Decorator)](#装饰模式-decorator)
  - [外观模式 (Facade)](#外观模式-facade)
  - [享元模式 (Flyweight)](#享元模式-flyweight)
  - [代理模式 (Proxy)](#代理模式-proxy)
- [行为型模式](#行为型模式)
  - [责任链模式 (Chain of Responsibility)](#责任链模式-chain-of-responsibility)
  - [命令模式 (Command)](#命令模式-command)
  - [解释器模式 (Interpreter)](#解释器模式-interpreter)
  - [迭代器模式 (Iterator)](#迭代器模式-iterator)
  - [中介者模式 (Mediator)](#中介者模式-mediator)
  - [备忘录模式 (Memento)](#备忘录模式-memento)
  - [观察者模式 (Observer)](#观察者模式-observer)
  - [状态模式 (State)](#状态模式-state)
  - [策略模式 (Strategy)](#策略模式-strategy)
  - [模板方法模式 (Template Method)](#模板方法模式-template-method)
  - [访问者模式 (Visitor)](#访问者模式-visitor)
- [iOS 特有的架构模式](#ios-特有的架构模式)
  - [MVC (Model-View-Controller)](#mvc-model-view-controller)
  - [MVVM (Model-View-ViewModel)](#mvvm-model-view-viewmodel)
  - [VIPER (View-Interactor-Presenter-Entity-Router)](#viper-view-interactor-presenter-entity-router)
  - [协调器模式 (Coordinator)](#协调器模式-coordinator)
  - [Clean Architecture](#clean-architecture)
- [Swift 特有的设计模式](#swift-特有的设计模式)
  - [委托模式 (Delegation)](#委托模式-delegation)
  - [扩展 (Extensions)](#扩展-extensions)
  - [类型擦除 (Type Erasure)](#类型擦除-type-erasure)
  - [属性观察者 (Property Observers)](#属性观察者-property-observers)
  - [函数式编程模式](#函数式编程模式)
- [SwiftUI 中的设计模式](#swiftui-中的设计模式)
  - [数据流模式](#数据流模式)
  - [环境与依赖注入](#环境与依赖注入)
  - [视图组合](#视图组合)
- [设计模式的选择与应用](#设计模式的选择与应用)
  - [如何选择合适的设计模式](#如何选择合适的设计模式)
  - [避免过度设计](#避免过度设计)
  - [模式组合的艺术](#模式组合的艺术)
- [总结](#总结)
- [参考资源](#参考资源)

## 创建型模式

创建型模式关注对象的创建机制，帮助创建对象的同时隐藏创建逻辑，使系统独立于对象的创建、组合和表示方式。

### 单例模式 (Singleton)

单例模式确保一个类只有一个实例，并提供一个全局访问点。这种模式在需要严格控制全局状态的情况下非常有用。

**Swift 实现：**

```swift
class NetworkManager {
    // 共享实例（单例）
    static let shared = NetworkManager()
    
    // 私有初始化方法防止外部创建实例
    private init() {
        // 初始化代码
    }
    
    func fetchData(from url: URL, completion: @escaping (Data?, Error?) -> Void) {
        // 网络请求实现
        let task = URLSession.shared.dataTask(with: url) { data, response, error in
            completion(data, error)
        }
        task.resume()
    }
}

// 使用单例
let manager = NetworkManager.shared
manager.fetchData(from: URL(string: "https://api.example.com/data")!) { data, error in
    // 处理响应
}
```

**使用场景：**

- 管理共享资源，如网络管理器、数据库连接
- 管理全局状态，如用户会话、应用配置
- 协调系统范围的操作，如日志记录

**优点：**

- 保证一个类只有一个实例，减少内存占用
- 提供对该实例的全局访问点
- 实例可以被延迟创建（使用时才初始化）

**缺点：**

- 违反单一职责原则，处理自身职责和实例管理
- 在多线程环境中可能引发问题（需额外同步措施）
- 隐藏类依赖，可能导致代码难以测试

**注意事项：**

```swift
// 线程安全的单例实现
class ThreadSafeSingleton {
    static let shared = ThreadSafeSingleton()
    private init() {}
    
    // 访问共享资源时使用锁或并发队列
    private let concurrentQueue = DispatchQueue(label: "com.example.singleton.queue", attributes: .concurrent)
    private var _data: [String: Any] = [:]
    
    func setData(_ value: Any, forKey key: String) {
        concurrentQueue.async(flags: .barrier) { [weak self] in
            self?._data[key] = value
        }
    }
    
    func getData(forKey key: String) -> Any? {
        var result: Any?
        concurrentQueue.sync {
            result = _data[key]
        }
        return result
    }
}
```

### 工厂方法模式 (Factory Method)

工厂方法模式定义了一个创建对象的接口，但由子类决定实例化的类。这种模式将对象的实例化逻辑委托给子类。

**Swift 实现：**

```swift
// 产品协议
protocol Message {
    var content: String { get }
    func send()
}

// 具体产品
class TextMessage: Message {
    var content: String
    
    init(content: String) {
        self.content = content
    }
    
    func send() {
        print("发送文本消息: \(content)")
    }
}

class ImageMessage: Message {
    var content: String
    var imageData: Data
    
    init(content: String, imageData: Data) {
        self.content = content
        self.imageData = imageData
    }
    
    func send() {
        print("发送图片消息: \(content)，图片大小: \(imageData.count) 字节")
    }
}

// 创建者抽象类
protocol MessageCreator {
    func createMessage() -> Message
}

// 具体创建者
class TextMessageCreator: MessageCreator {
    private let content: String
    
    init(content: String) {
        self.content = content
    }
    
    func createMessage() -> Message {
        return TextMessage(content: content)
    }
}

class ImageMessageCreator: MessageCreator {
    private let content: String
    private let imageData: Data
    
    init(content: String, imageData: Data) {
        self.content = content
        self.imageData = imageData
    }
    
    func createMessage() -> Message {
        return ImageMessage(content: content, imageData: imageData)
    }
}

// 客户端代码
func sendMessage(creator: MessageCreator) {
    let message = creator.createMessage()
    message.send()
}

// 使用工厂方法
let textCreator = TextMessageCreator(content: "你好！")
sendMessage(creator: textCreator)

let imageData = Data(repeating: 0, count: 1024)
let imageCreator = ImageMessageCreator(content: "看这张图片", imageData: imageData)
sendMessage(creator: imageCreator)
```

**使用场景：**

- 当对象的创建逻辑复杂，或依赖于环境、配置或用户输入时
- 当系统需要独立于它所创建的对象时
- 当类将责任委托给多个子类之一时

**优点：**

- 避免创建者和具体产品之间的紧密耦合
- 遵循单一职责原则，将产品创建代码移到程序的一个地方
- 遵循开闭原则，无需修改现有代码即可引入新产品

**缺点：**

- 可能导致代码复杂度增加，因为需要引入许多新的子类

**简化版本（使用枚举）：**

```swift
enum MessageType {
    case text
    case image
}

class MessageFactory {
    static func createMessage(type: MessageType, content: String, imageData: Data? = nil) -> Message {
        switch type {
        case .text:
            return TextMessage(content: content)
        case .image:
            guard let imageData = imageData else {
                fatalError("Image messages require image data")
            }
            return ImageMessage(content: content, imageData: imageData)
        }
    }
}

// 使用简化版工厂
let textMessage = MessageFactory.createMessage(type: .text, content: "你好！")
textMessage.send()

let imageData = Data(repeating: 0, count: 1024)
let imageMessage = MessageFactory.createMessage(type: .image, content: "看这张图片", imageData: imageData)
imageMessage.send()
```

### 抽象工厂模式 (Abstract Factory)

抽象工厂模式提供一个接口来创建一系列相关或相互依赖的对象，而无需指定其具体类。与工厂方法不同，抽象工厂关注的是创建一系列相关的产品。

**Swift 实现：**

```swift
// 抽象产品 - 按钮
protocol Button {
    func render()
    func onClick()
}

// 抽象产品 - 复选框
protocol Checkbox {
    func render()
    func toggle()
}

// 具体产品 - iOS 按钮
class iOSButton: Button {
    func render() {
        print("渲染 iOS 风格的按钮")
    }
    
    func onClick() {
        print("iOS 按钮被点击")
    }
}

// 具体产品 - iOS 复选框
class iOSCheckbox: Checkbox {
    private var isChecked = false
    
    func render() {
        print("渲染 iOS 风格的复选框")
    }
    
    func toggle() {
        isChecked = !isChecked
        print("iOS 复选框状态: \(isChecked ? "选中" : "未选中")")
    }
}

// 具体产品 - macOS 按钮
class macOSButton: Button {
    func render() {
        print("渲染 macOS 风格的按钮")
    }
    
    func onClick() {
        print("macOS 按钮被点击")
    }
}

// 具体产品 - macOS 复选框
class macOSCheckbox: Checkbox {
    private var isChecked = false
    
    func render() {
        print("渲染 macOS 风格的复选框")
    }
    
    func toggle() {
        isChecked = !isChecked
        print("macOS 复选框状态: \(isChecked ? "选中" : "未选中")")
    }
}

// 抽象工厂
protocol UIFactory {
    func createButton() -> Button
    func createCheckbox() -> Checkbox
}

// 具体工厂 - iOS UI 工厂
class iOSUIFactory: UIFactory {
    func createButton() -> Button {
        return iOSButton()
    }
    
    func createCheckbox() -> Checkbox {
        return iOSCheckbox()
    }
}

// 具体工厂 - macOS UI 工厂
class macOSUIFactory: UIFactory {
    func createButton() -> Button {
        return macOSButton()
    }
    
    func createCheckbox() -> Checkbox {
        return macOSCheckbox()
    }
}

// 客户端代码
class Application {
    private var button: Button
    private var checkbox: Checkbox
    
    init(factory: UIFactory) {
        button = factory.createButton()
        checkbox = factory.createCheckbox()
    }
    
    func createUI() {
        button.render()
        checkbox.render()
    }
    
    func buttonClicked() {
        button.onClick()
    }
    
    func checkboxToggled() {
        checkbox.toggle()
    }
}

// 根据当前平台选择工厂
#if os(iOS)
let factory: UIFactory = iOSUIFactory()
#else
let factory: UIFactory = macOSUIFactory()
#endif

// 使用抽象工厂
let app = Application(factory: factory)
app.createUI()
app.buttonClicked()
app.checkboxToggled()
```

**使用场景：**

- 当系统需要独立于其产品的创建、组合和表示时
- 当系统需要配置多个系列的产品时
- 当需要强调一系列相关产品的设计，以便一起使用时

**优点：**

- 确保同一工厂创建的产品相互兼容
- 避免客户端代码与具体产品类的耦合
- 遵循单一职责原则，将产品创建代码提取到一个地方
- 遵循开闭原则，可以引入新的产品变体而不破坏现有代码

**缺点：**

- 代码可能变得比原来更复杂，因为需要引入许多新的接口和类
- 添加新种类的产品需要修改接口，这可能涉及到修改所有工厂

**适用于 iOS 的例子：**

```swift
// 抽象产品 - 网络请求
protocol NetworkRequest {
    func execute(completion: @escaping (Data?, Error?) -> Void)
}

// 抽象产品 - 数据解析器
protocol DataParser {
    func parse(data: Data) -> Any?
}

// 具体产品 - REST 网络请求
class RESTNetworkRequest: NetworkRequest {
    let url: URL
    
    init(url: URL) {
        self.url = url
    }
    
    func execute(completion: @escaping (Data?, Error?) -> Void) {
        let task = URLSession.shared.dataTask(with: url) { data, _, error in
            completion(data, error)
        }
        task.resume()
    }
}

// 具体产品 - JSON 数据解析器
class JSONDataParser: DataParser {
    func parse(data: Data) -> Any? {
        try? JSONSerialization.jsonObject(with: data, options: [])
    }
}

// 具体产品 - GraphQL 网络请求
class GraphQLNetworkRequest: NetworkRequest {
    let url: URL
    let query: String
    
    init(url: URL, query: String) {
        self.url = url
        self.query = query
    }
    
    func execute(completion: @escaping (Data?, Error?) -> Void) {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["query": query])
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let task = URLSession.shared.dataTask(with: request) { data, _, error in
            completion(data, error)
        }
        task.resume()
    }
}

// 具体产品 - GraphQL 响应解析器
class GraphQLDataParser: DataParser {
    func parse(data: Data) -> Any? {
        guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
              let data = json["data"] as? [String: Any] else {
            return nil
        }
        return data
    }
}

// 抽象工厂
protocol APIFactory {
    func createNetworkRequest(url: URL) -> NetworkRequest
    func createDataParser() -> DataParser
}

// 具体工厂 - REST API 工厂
class RESTAPIFactory: APIFactory {
    func createNetworkRequest(url: URL) -> NetworkRequest {
        return RESTNetworkRequest(url: url)
    }
    
    func createDataParser() -> DataParser {
        return JSONDataParser()
    }
}

// 具体工厂 - GraphQL API 工厂
class GraphQLAPIFactory: APIFactory {
    private let query: String
    
    init(query: String) {
        self.query = query
    }
    
    func createNetworkRequest(url: URL) -> NetworkRequest {
        return GraphQLNetworkRequest(url: url, query: query)
    }
    
    func createDataParser() -> DataParser {
        return GraphQLDataParser()
    }
}

// 客户端代码
class APIClient {
    private let factory: APIFactory
    private let baseURL: URL
    
    init(factory: APIFactory, baseURL: URL) {
        self.factory = factory
        self.baseURL = baseURL
    }
    
    func fetchData(completion: @escaping (Any?, Error?) -> Void) {
        let request = factory.createNetworkRequest(url: baseURL)
        let parser = factory.createDataParser()
        
        request.execute { data, error in
            if let error = error {
                completion(nil, error)
                return
            }
            
            guard let data = data else {
                completion(nil, NSError(domain: "APIClient", code: 0, userInfo: [NSLocalizedDescriptionKey: "No data received"]))
                return
            }
            
            let parsedData = parser.parse(data: data)
            completion(parsedData, nil)
        }
    }
}

// 使用 REST API
let restFactory = RESTAPIFactory()
let restClient = APIClient(factory: restFactory, baseURL: URL(string: "https://api.example.com/users")!)

restClient.fetchData { data, error in
    if let error = error {
        print("Error: \(error.localizedDescription)")
        return
    }
    
    if let users = data as? [[String: Any]] {
        for user in users {
            print("User: \(user["name"] ?? "Unknown")")
        }
    }
}

// 使用 GraphQL API
let graphQLFactory = GraphQLAPIFactory(query: """
{
  users {
    id
    name
    email
  }
}
""")
let graphQLClient = APIClient(factory: graphQLFactory, baseURL: URL(string: "https://api.example.com/graphql")!)

graphQLClient.fetchData { data, error in
    if let error = error {
        print("Error: \(error.localizedDescription)")
        return
    }
    
    if let userData = data as? [String: Any],
       let users = userData["users"] as? [[String: Any]] {
        for user in users {
            print("User: \(user["name"] ?? "Unknown")")
        }
    }
}
```

### 建造者模式 (Builder)

建造者模式将一个复杂对象的构建过程与其表示分离，使得同样的构建过程可以创建不同的表示。这种模式适用于构建具有多个可配置选项的复杂对象。

**Swift 实现：**

```swift
// 产品
class HTTPRequest {
    var method: String = "GET"
    var url: URL
    var headers: [String: String] = [:]
    var body: Data?
    var timeoutInterval: TimeInterval = 30.0
    var cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy
    
    init(url: URL) {
        self.url = url
    }
    
    func execute(completion: @escaping (Data?, URLResponse?, Error?) -> Void) {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.allHTTPHeaderFields = headers
        request.httpBody = body
        request.timeoutInterval = timeoutInterval
        request.cachePolicy = cachePolicy
        
        let task = URLSession.shared.dataTask(with: request, completionHandler: completion)
        task.resume()
    }
}

// 建造者
class HTTPRequestBuilder {
    private var request: HTTPRequest
    
    init(url: URL) {
        self.request = HTTPRequest(url: url)
    }
    
    func setMethod(_ method: String) -> HTTPRequestBuilder {
        request.method = method
        return self
    }
    
    func addHeader(name: String, value: String) -> HTTPRequestBuilder {
        request.headers[name] = value
        return self
    }
    
    func setBody(_ body: Data) -> HTTPRequestBuilder {
        request.body = body
        return self
    }
    
    func setJSON<T: Encodable>(_ json: T) -> HTTPRequestBuilder {
        request.headers["Content-Type"] = "application/json"
        request.body = try? JSONEncoder().encode(json)
        return self
    }
    
    func setTimeout(_ timeout: TimeInterval) -> HTTPRequestBuilder {
        request.timeoutInterval = timeout
        return self
    }
    
    func setCachePolicy(_ policy: URLRequest.CachePolicy) -> HTTPRequestBuilder {
        request.cachePolicy = policy
        return self
    }
    
    func build() -> HTTPRequest {
        return request
    }
}

// 导演（可选）
class HTTPRequestDirector {
    private let builder: HTTPRequestBuilder
    
    init(builder: HTTPRequestBuilder) {
        self.builder = builder
    }
    
    func buildGETRequest() -> HTTPRequest {
        return builder
            .setMethod("GET")
            .addHeader(name: "Accept", value: "application/json")
            .setTimeout(10.0)
            .build()
    }
    
    func buildPOSTJSONRequest<T: Encodable>(body: T) -> HTTPRequest {
        return builder
            .setMethod("POST")
            .addHeader(name: "Accept", value: "application/json")
            .setJSON(body)
            .setTimeout(30.0)
            .build()
    }
}

// 使用建造者模式
let url = URL(string: "https://api.example.com/users")!
let requestBuilder = HTTPRequestBuilder(url: url)

// 方法 1：使用建造者直接构建
let getRequest = requestBuilder
    .setMethod("GET")
    .addHeader(name: "Accept", value: "application/json")
    .addHeader(name: "Authorization", value: "Bearer token123")
    .setTimeout(15.0)
    .build()

getRequest.execute { data, response, error in
    // 处理响应
}

// 方法 2：使用导演构建预定义的请求
let director = HTTPRequestDirector(builder: HTTPRequestBuilder(url: url))

struct User: Codable {
    let name: String
    let email: String
}

let postRequest = director.buildPOSTJSONRequest(body: User(name: "张三", email: "zhangsan@example.com"))

postRequest.execute { data, response, error in
    // 处理响应
}
```

**使用场景：**

- 当需要创建具有多个配置选项的复杂对象时
- 当对象需要分步骤构建时
- 当对象的构建过程需要延迟某些步骤时
- 当不同的构建过程需要创建不同的表示时

**优点：**

- 分步创建复杂对象，易于扩展和控制
- 遵循单一职责原则，将构建代码从业务逻辑中分离
- 可以创建不同的表示使用相同的构建过程
- 支持流式接口 (Fluent Interface)，提高代码可读性

**缺点：**

- 代码量增加，引入额外的构建器类
- 与其他创建型模式相比，客户端需要了解更多细节

**Swift 中的链式初始化：**

Swift 中可以使用更轻量级的方法来实现类似建造者模式的链式初始化：

```swift
// 产品类支持链式初始化
class HTTPRequest {
    var method: String = "GET"
    var url: URL
    var headers: [String: String] = [:]
    var body: Data?
    var timeoutInterval: TimeInterval = 30.0
    var cachePolicy: URLRequest.CachePolicy = .useProtocolCachePolicy
    
    init(url: URL) {
        self.url = url
    }
    
    // 链式方法
    @discardableResult
    func setMethod(_ method: String) -> Self {
        self.method = method
        return self
    }
    
    @discardableResult
    func addHeader(name: String, value: String) -> Self {
        self.headers[name] = value
        return self
    }
    
    @discardableResult
    func setBody(_ body: Data) -> Self {
        self.body = body
        return self
    }
    
    @discardableResult
    func setJSON<T: Encodable>(_ json: T) -> Self {
        self.headers["Content-Type"] = "application/json"
        self.body = try? JSONEncoder().encode(json)
        return self
    }
    
    @discardableResult
    func setTimeout(_ timeout: TimeInterval) -> Self {
        self.timeoutInterval = timeout
        return self
    }
    
    @discardableResult
    func setCachePolicy(_ policy: URLRequest.CachePolicy) -> Self {
        self.cachePolicy = policy
        return self
    }
    
    // 执行请求
    func execute(completion: @escaping (Data?, URLResponse?, Error?) -> Void) {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.allHTTPHeaderFields = headers
        request.httpBody = body
        request.timeoutInterval = timeoutInterval
        request.cachePolicy = cachePolicy
        
        let task = URLSession.shared.dataTask(with: request, completionHandler: completion)
        task.resume()
    }
}

// 使用链式初始化
let request = HTTPRequest(url: URL(string: "https://api.example.com/users")!)
    .setMethod("POST")
    .addHeader(name: "Accept", value: "application/json")
    .addHeader(name: "Authorization", value: "Bearer token123")
    .setJSON(User(name: "张三", email: "zhangsan@example.com"))
    .setTimeout(15.0)

request.execute { data, response, error in
    // 处理响应
}
```

这种简化版本适合于不需要将构建逻辑完全分离的情况。

### 原型模式 (Prototype)

原型模式是通过复制（克隆）现有对象来创建新对象的设计模式，而不是通过实例化类。这种模式用于当创建一个对象的成本很高，或者初始化过程很复杂时。

**Swift 实现：**

```swift
// 原型协议
protocol Prototype {
    func clone() -> Self
}

// 具体原型
class ComplexObject: Prototype {
    var id: Int
    var name: String
    var data: [String: Any]
    var date: Date
    
    init(id: Int, name: String, data: [String: Any], date: Date = Date()) {
        self.id = id
        self.name = name
        self.data = data
        self.date = date
        
        // 假设这里有复杂的初始化过程
        print("执行复杂的初始化过程...")
    }
    
    // 实现克隆方法
    func clone() -> Self {
        // 由于 Swift 的类型系统限制，我们需要使用一个小技巧
        return ComplexObject(id: self.id, name: self.name, data: self.data, date: self.date) as! Self
    }
    
    // 自定义描述
    var description: String {
        return "ComplexObject(id: \(id), name: \(name), data: \(data), date: \(date))"
    }
}

// 使用原型模式
let prototype = ComplexObject(id: 1, name: "原型对象", data: ["key": "value"])
print("创建原型: \(prototype.description)")

// 通过克隆创建新对象
let clone1 = prototype.clone()
clone1.id = 2
clone1.name = "克隆对象 1"
print("创建克隆 1: \(clone1.description)")

let clone2 = prototype.clone()
clone2.id = 3
clone2.name = "克隆对象 2"
clone2.data["key"] = "新值"
print("创建克隆 2: \(clone2.description)")
```

**使用场景：**

- 当创建对象的代价很高，需要消耗大量资源时
- 当对象的初始化过程很复杂时
- 当系统应该独立于产品的创建、组合和表示时
- 当需要创建对象的类是在运行时指定的

**优点：**

- 减少子类数量，克隆比创建更高效
- 能在运行时添加或删除对象
- 可以用原型实例指定要创建的对象，无需知道具体类型
- 避免重复的初始化代码

**缺点：**

- 克隆包含循环引用的复杂对象可能很困难
- 深拷贝和浅拷贝的实现可能不直观

**Swift 中实现深拷贝：**

```swift
// 支持深拷贝的原型
class DeepCopyableObject: NSObject, NSCopying {
    var id: Int
    var name: String
    var subObjects: [DeepCopyableObject]
    
    init(id: Int, name: String, subObjects: [DeepCopyableObject] = []) {
        self.id = id
        self.name = name
        self.subObjects = subObjects
    }
    
    // NSCopying 协议实现
    func copy(with zone: NSZone? = nil) -> Any {
        let copy = DeepCopyableObject(id: self.id, name: self.name)
        
        // 深度复制子对象
        copy.subObjects = self.subObjects.map { $0.copy(with: zone) as! DeepCopyableObject }
        
        return copy
    }
    
    // 便利方法
    func clone() -> DeepCopyableObject {
        return self.copy() as! DeepCopyableObject
    }
    
    // 自定义描述
    override var description: String {
        return "DeepCopyableObject(id: \(id), name: \(name), subObjects: \(subObjects.count)个)"
    }
}

// 使用支持深拷贝的原型
let child1 = DeepCopyableObject(id: 11, name: "子对象 1")
let child2 = DeepCopyableObject(id: 12, name: "子对象 2")

let parent = DeepCopyableObject(id: 1, name: "父对象", subObjects: [child1, child2])
print("原型: \(parent.description)")

// 克隆（深拷贝）
let clonedParent = parent.clone()
clonedParent.id = 2
clonedParent.name = "克隆的父对象"
clonedParent.subObjects[0].name = "克隆的子对象 1"

print("原型: \(parent.description)")
print("克隆: \(clonedParent.description)")
print("原型子对象名: \(parent.subObjects[0].name)") // 仍然是 "子对象 1"
print("克隆子对象名: \(clonedParent.subObjects[0].name)") // 是 "克隆的子对象 1"
```

**使用 Codable 实现克隆：**

对于遵循 `Codable` 协议的类型，可以通过编码和解码实现深拷贝：

```swift
// 使用 Codable 实现克隆
class CodableObject: Codable {
    var id: Int
    var name: String
    var subObjects: [CodableObject]
    
    init(id: Int, name: String, subObjects: [CodableObject] = []) {
        self.id = id
        self.name = name
        self.subObjects = subObjects
    }
    
    // 使用 Codable 实现克隆
    func clone() -> CodableObject? {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(self) else { return nil }
        
        let decoder = JSONDecoder()
        return try? decoder.decode(CodableObject.self, from: data)
    }
}

// 使用
let codableParent = CodableObject(id: 1, name: "父对象", 
                                subObjects: [
                                    CodableObject(id: 11, name: "子对象 1"),
                                    CodableObject(id: 12, name: "子对象 2")
                                ])

if let clonedCodableParent = codableParent.clone() {
    clonedCodableParent.id = 2
    clonedCodableParent.name = "克隆的父对象"
    clonedCodableParent.subObjects[0].name = "克隆的子对象 1"
    
    // 验证深拷贝成功
    print(codableParent.subObjects[0].name) // 仍然是 "子对象 1"
    print(clonedCodableParent.subObjects[0].name) // 是 "克隆的子对象 1"
}
```

## 结构型模式

结构型模式关注如何组合类和对象以形成更大的结构，同时保持这些结构的灵活性和高效性。

### 适配器模式 (Adapter)

适配器模式允许不兼容的接口一起工作。这种模式涉及一个单独的类，称为适配器，它将一个类的接口转换成客户端期望的另一个接口。

**Swift 实现：**

```swift
// 目标接口
protocol TargetAuthentication {
    func login(email: String, password: String, completion: @escaping (Bool, Error?) -> Void)
    func logout() -> Bool
    var userName: String { get }
}

// 已有服务（不兼容的接口）
class LegacyAuthService {
    func signIn(username: String, pass: String, onSuccess: @escaping (String) -> Void, onFailure: @escaping (String) -> Void) {
        // 模拟网络请求
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            if username == "admin" && pass == "password" {
                onSuccess("admin_token")
            } else {
                onFailure("Invalid credentials")
            }
        }
    }
    
    func signOut(completion: (Bool) -> Void) {
        // 模拟登出操作
        completion(true)
    }
    
    func getUserName(fromToken token: String) -> String {
        // 从令牌获取用户名
        return token.split(separator: "_").first.map(String.init) ?? ""
    }
}

// 适配器
class AuthServiceAdapter: TargetAuthentication {
    private let legacyService: LegacyAuthService
    private var authToken: String?
    
    init(legacyService: LegacyAuthService) {
        self.legacyService = legacyService
    }
    
    func login(email: String, password: String, completion: @escaping (Bool, Error?) -> Void) {
        legacyService.signIn(
            username: email,
            pass: password,
            onSuccess: { [weak self] token in
                self?.authToken = token
                completion(true, nil)
            },
            onFailure: { errorMessage in
                completion(false, NSError(domain: "AuthError", code: 0, userInfo: [NSLocalizedDescriptionKey: errorMessage]))
            }
        )
    }
    
    func logout() -> Bool {
        var result = false
        legacyService.signOut { success in
            result = success
        }
        authToken = nil
        return result
    }
    
    var userName: String {
        guard let token = authToken else { return "" }
        return legacyService.getUserName(fromToken: token)
    }
}

// 客户端代码
class UserProfileViewController {
    private let authService: TargetAuthentication
    
    init(authService: TargetAuthentication) {
        self.authService = authService
    }
    
    func login(email: String, password: String) {
        authService.login(email: email, password: password) { [weak self] success, error in
            if success {
                print("欢迎回来，\(self?.authService.userName ?? "")")
            } else {
                print("登录失败：\(error?.localizedDescription ?? "未知错误")")
            }
        }
    }
    
    func logout() {
        if authService.logout() {
            print("已成功登出")
        } else {
            print("登出失败")
        }
    }
}

// 使用适配器
let legacyService = LegacyAuthService()
let adapter = AuthServiceAdapter(legacyService: legacyService)
let viewController = UserProfileViewController(authService: adapter)

viewController.login(email: "admin", password: "password")
// 输出: 欢迎回来，admin

viewController.logout()
// 输出: 已成功登出
```

**使用场景：**

- 当需要使用现有类，但其接口与需求不匹配时
- 当需要创建可复用的类，以便与不相关或不可预见的类一起工作
- 当需要使用一些已有子类，但不可能对每一个都进行子类化扩展接口时

**优点：**

- 支持开闭原则，可以引入新类型的适配器而不破坏现有代码
- 支持单一职责原则，将接口转换逻辑与主要业务逻辑分离
- 可以使不相关的类协同工作

**缺点：**

- 增加代码复杂性，引入额外的类和接口
- 有时直接更改服务类可能更简单

**iOS/Swift 常见应用：**

1. **第三方库适配**：

```swift
// 第三方分析库接口
protocol ThirdPartyAnalyticsService {
    func trackEvent(_ name: String, parameters: [String: Any])
    func setUserProperty(_ value: String, forKey key: String)
}

// Firebase 实现
class FirebaseAnalytics: ThirdPartyAnalyticsService {
    func trackEvent(_ name: String, parameters: [String: Any]) {
        // 调用 Firebase 方法
        print("Firebase: 记录事件 \(name) 参数: \(parameters)")
    }
    
    func setUserProperty(_ value: String, forKey key: String) {
        // 调用 Firebase 方法
        print("Firebase: 设置用户属性 \(key)=\(value)")
    }
}

// Mixpanel 实现
class MixpanelAnalytics: ThirdPartyAnalyticsService {
    func trackEvent(_ name: String, parameters: [String: Any]) {
        // 调用 Mixpanel 方法
        print("Mixpanel: 记录事件 \(name) 参数: \(parameters)")
    }
    
    func setUserProperty(_ value: String, forKey key: String) {
        // 调用 Mixpanel 方法
        print("Mixpanel: 设置用户属性 \(key)=\(value)")
    }
}

// 统一的分析工具类
class AnalyticsManager {
    private let services: [ThirdPartyAnalyticsService]
    
    init(services: [ThirdPartyAnalyticsService]) {
        self.services = services
    }
    
    func trackEvent(_ name: String, parameters: [String: Any] = [:]) {
        services.forEach { $0.trackEvent(name, parameters: parameters) }
    }
    
    func setUserProperty(_ value: String, forKey key: String) {
        services.forEach { $0.setUserProperty(value, forKey: key) }
    }
}

// 使用
let analyticsManager = AnalyticsManager(services: [
    FirebaseAnalytics(),
    MixpanelAnalytics()
])

analyticsManager.trackEvent("button_tap", parameters: ["screen": "home"])
analyticsManager.setUserProperty("premium", forKey: "subscription_type")
```

2. **新旧 API 兼容**：

```swift
// 新的网络请求接口
protocol NetworkRequestProtocol {
    func request<T: Decodable>(_ endpoint: String, completion: @escaping (Result<T, Error>) -> Void)
}

// 旧的网络服务
class LegacyNetworkService {
    func performRequest(path: String, parameters: [String: Any], success: @escaping (Data) -> Void, failure: @escaping (Error) -> Void) {
        // 旧的网络请求实现
        guard let url = URL(string: "https://api.example.com/" + path) else {
            failure(NSError(domain: "InvalidURL", code: 0, userInfo: nil))
            return
        }
        
        // 模拟网络请求
        URLSession.shared.dataTask(with: url) { data, response, error in
            if let error = error {
                failure(error)
                return
            }
            
            guard let data = data else {
                failure(NSError(domain: "NoData", code: 0, userInfo: nil))
                return
            }
            
            success(data)
        }.resume()
    }
}

// 适配器
class NetworkServiceAdapter: NetworkRequestProtocol {
    private let legacyService: LegacyNetworkService
    
    init(legacyService: LegacyNetworkService) {
        self.legacyService = legacyService
    }
    
    func request<T: Decodable>(_ endpoint: String, completion: @escaping (Result<T, Error>) -> Void) {
        legacyService.performRequest(
            path: endpoint,
            parameters: [:],
            success: { data in
                do {
                    let decoder = JSONDecoder()
                    let decodedObject = try decoder.decode(T.self, from: data)
                    completion(.success(decodedObject))
                } catch {
                    completion(.failure(error))
                }
            },
            failure: { error in
                completion(.failure(error))
            }
        )
    }
}
```

### 桥接模式 (Bridge)

桥接模式将抽象部分与其实现部分分离，使它们可以独立变化。这种模式涉及创建一个桥接接口，使抽象和实现可以各自演化，而不会相互影响。

**Swift 实现：**

```swift
// 实现部分接口
protocol DeviceAPI {
    func turnOn()
    func turnOff()
    func setVolume(_ percent: Int)
    func setChannel(_ channel: Int)
    var isEnabled: Bool { get }
}

// 具体实现
class SonyTV: DeviceAPI {
    private var on = false
    private var volume = 0
    private var channel = 1
    
    var isEnabled: Bool {
        return on
    }
    
    func turnOn() {
        on = true
        print("Sony TV: 打开")
    }
    
    func turnOff() {
        on = false
        print("Sony TV: 关闭")
    }
    
    func setVolume(_ percent: Int) {
        volume = max(0, min(100, percent))
        print("Sony TV: 设置音量为 \(volume)%")
    }
    
    func setChannel(_ channel: Int) {
        self.channel = channel
        print("Sony TV: 切换到频道 \(channel)")
    }
}

class SamsungTV: DeviceAPI {
    private var on = false
    private var volume = 0
    private var channel = 1
    
    var isEnabled: Bool {
        return on
    }
    
    func turnOn() {
        on = true
        print("Samsung TV: 打开")
    }
    
    func turnOff() {
        on = false
        print("Samsung TV: 关闭")
    }
    
    func setVolume(_ percent: Int) {
        volume = max(0, min(100, percent))
        print("Samsung TV: 设置音量为 \(volume)%")
    }
    
    func setChannel(_ channel: Int) {
        self.channel = channel
        print("Samsung TV: 切换到频道 \(channel)")
    }
}

// 抽象部分
class RemoteControl {
    protected var device: DeviceAPI
    
    init(device: DeviceAPI) {
        self.device = device
    }
    
    func togglePower() {
        if device.isEnabled {
            device.turnOff()
        } else {
            device.turnOn()
        }
    }
    
    func volumeUp() {
        // 假设当前音量是 50%
        device.setVolume(60)
    }
    
    func volumeDown() {
        // 假设当前音量是 50%
        device.setVolume(40)
    }
    
    func channelUp() {
        // 假设当前频道是 1
        device.setChannel(2)
    }
    
    func channelDown() {
        // 假设当前频道是 2
        device.setChannel(1)
    }
}

// 扩展的抽象部分
class AdvancedRemoteControl: RemoteControl {
    func mute() {
        device.setVolume(0)
    }
    
    func goToChannel(_ channel: Int) {
        device.setChannel(channel)
    }
}

// 客户端代码
let sonyTV = SonyTV()
let samsungTV = SamsungTV()

let basicRemote = RemoteControl(device: sonyTV)
basicRemote.togglePower()
basicRemote.channelUp()
basicRemote.volumeUp()

let advancedRemote = AdvancedRemoteControl(device: samsungTV)
advancedRemote.togglePower()
advancedRemote.mute()
advancedRemote.goToChannel(5)
```

**使用场景：**

- 当希望避免抽象和实现之间的永久绑定时
- 当抽象和实现都应该通过子类扩展时
- 当一个类有多个变体时，使用继承会导致类爆炸
- 当需要在运行时更改实现时

**优点：**

- 分离接口和实现，提高可扩展性
- 隐藏实现细节，提高抽象性
- 支持开闭原则，可以独立地扩展抽象和实现
- 支持单一职责原则，将不同关注点分开

**缺点：**

- 增加设计复杂性
- 对高内聚的类使用桥接模式可能会过度设计

**iOS/Swift 中的应用：**

1. **主题化 UI 组件**：

```swift
// 实现部分 - 主题
protocol Theme {
    var backgroundColor: UIColor { get }
    var textColor: UIColor { get }
    var accentColor: UIColor { get }
    var font: UIFont { get }
}

class LightTheme: Theme {
    var backgroundColor: UIColor { .white }
    var textColor: UIColor { .black }
    var accentColor: UIColor { .blue }
    var font: UIFont { .systemFont(ofSize: 14) }
}

class DarkTheme: Theme {
    var backgroundColor: UIColor { .black }
    var textColor: UIColor { .white }
    var accentColor: UIColor { .orange }
    var font: UIFont { .systemFont(ofSize: 14) }
}

// 抽象部分 - UI 组件
class ThemedView {
    var theme: Theme
    
    init(theme: Theme) {
        self.theme = theme
    }
    
    func applyTheme() {
        // 由子类实现
    }
}

class ThemedButton: ThemedView {
    let button = UIButton()
    
    override func applyTheme() {
        button.backgroundColor = theme.accentColor
        button.setTitleColor(theme.textColor, for: .normal)
        button.titleLabel?.font = theme.font
    }
}

class ThemedLabel: ThemedView {
    let label = UILabel()
    
    override func applyTheme() {
        label.backgroundColor = theme.backgroundColor
        label.textColor = theme.textColor
        label.font = theme.font
    }
}

// 使用
let lightTheme = LightTheme()
let darkTheme = DarkTheme()

let button = ThemedButton(theme: lightTheme)
button.applyTheme()

let label = ThemedLabel(theme: darkTheme)
label.applyTheme()

// 动态切换主题
button.theme = darkTheme
button.applyTheme()
```

2. **跨平台渲染引擎**：

```swift
// 实现部分 - 渲染 API
protocol RenderingAPI {
    func drawCircle(center: CGPoint, radius: CGFloat, color: UIColor)
    func drawRectangle(rect: CGRect, color: UIColor)
    func drawText(text: String, position: CGPoint, font: UIFont, color: UIColor)
}

class OpenGLRenderer: RenderingAPI {
    func drawCircle(center: CGPoint, radius: CGFloat, color: UIColor) {
        print("OpenGL: 绘制圆形，中心点 \(center)，半径 \(radius)，颜色 \(color)")
    }
    
    func drawRectangle(rect: CGRect, color: UIColor) {
        print("OpenGL: 绘制矩形，区域 \(rect)，颜色 \(color)")
    }
    
    func drawText(text: String, position: CGPoint, font: UIFont, color: UIColor) {
        print("OpenGL: 绘制文本 '\(text)'，位置 \(position)，字体 \(font.fontName)，颜色 \(color)")
    }
}

class MetalRenderer: RenderingAPI {
    func drawCircle(center: CGPoint, radius: CGFloat, color: UIColor) {
        print("Metal: 绘制圆形，中心点 \(center)，半径 \(radius)，颜色 \(color)")
    }
    
    func drawRectangle(rect: CGRect, color: UIColor) {
        print("Metal: 绘制矩形，区域 \(rect)，颜色 \(color)")
    }
    
    func drawText(text: String, position: CGPoint, font: UIFont, color: UIColor) {
        print("Metal: 绘制文本 '\(text)'，位置 \(position)，字体 \(font.fontName)，颜色 \(color)")
    }
}

// 抽象部分 - 图形
class Shape {
    var renderer: RenderingAPI
    
    init(renderer: RenderingAPI) {
        self.renderer = renderer
    }
    
    func draw() {
        // 由子类实现
    }
}

class Circle: Shape {
    var center: CGPoint
    var radius: CGFloat
    var color: UIColor
    
    init(renderer: RenderingAPI, center: CGPoint, radius: CGFloat, color: UIColor) {
        self.center = center
        self.radius = radius
        self.color = color
        super.init(renderer: renderer)
    }
    
    override func draw() {
        renderer.drawCircle(center: center, radius: radius, color: color)
    }
}

class Rectangle: Shape {
    var rect: CGRect
    var color: UIColor
    
    init(renderer: RenderingAPI, rect: CGRect, color: UIColor) {
        self.rect = rect
        self.color = color
        super.init(renderer: renderer)
    }
    
    override func draw() {
        renderer.drawRectangle(rect: rect, color: color)
    }
}

// 使用
let openGLRenderer = OpenGLRenderer()
let metalRenderer = MetalRenderer()

let circle = Circle(
    renderer: openGLRenderer,
    center: CGPoint(x: 100, y: 100),
    radius: 50,
    color: .red
)
circle.draw()

let rectangle = Rectangle(
    renderer: metalRenderer,
    rect: CGRect(x: 10, y: 10, width: 100, height: 80),
    color: .blue
)
rectangle.draw()

// 切换渲染引擎
circle.renderer = metalRenderer
circle.draw()
```

## 行为型模式

行为型模式关注对象之间的责任分配和交互。它们可以帮助我们更好地组织和扩展系统。

### 责任链模式 (Chain of Responsibility)

责任链模式为请求创建了一个接收者对象的链。这种模式将请求的发送者和接收者解耦，使多个对象都有机会处理请求。

**Swift 实现：**

```swift
// 处理者协议
protocol Handler {
    func handle(request: String)
}

// 具体处理者
class ConcreteHandlerA: Handler {
    func handle(request: String) {
        if request == "A" {
            print("ConcreteHandlerA 处理请求")
        } else {
            print("ConcreteHandlerA 无法处理请求")
        }
    }
}

class ConcreteHandlerB: Handler {
    func handle(request: String) {
        if request == "B" {
            print("ConcreteHandlerB 处理请求")
        } else {
            print("ConcreteHandlerB 无法处理请求")
        }
    }
}

class ConcreteHandlerC: Handler {
    func handle(request: String) {
        if request == "C" {
            print("ConcreteHandlerC 处理请求")
        } else {
            print("ConcreteHandlerC 无法处理请求")
        }
    }
}

// 客户端代码
let handlerA = ConcreteHandlerA()
let handlerB = ConcreteHandlerB()
let handlerC = ConcreteHandlerC()

handlerA.handle(request: "A")
handlerA.handle(request: "B")
handlerA.handle(request: "C")
```

**使用场景：**

- 当多个对象可以处理一个请求，且在运行时确定哪个对象处理请求时
- 当需要将请求的发送者和接收者解耦时

**优点：**

- 降低耦合度
- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 命令模式 (Command)

命令模式将请求封装成对象，从而使您可以用不同的请求、队列或日志来参数化其他对象。命令模式也支持可撤销的操作。

**Swift 实现：**

```swift
// 命令协议
protocol Command {
    func execute()
}

// 具体命令
class ConcreteCommand: Command {
    func execute() {
        print("ConcreteCommand 的执行")
    }
}

// 接收者
class Receiver {
    func action() {
        print("Receiver 的 action")
    }
}

// 命令调用者
class Invoker {
    private let command: Command
    
    init(command: Command) {
        self.command = command
    }
    
    func executeCommand() {
        command.execute()
    }
}

// 客户端代码
let command = ConcreteCommand()
let invoker = Invoker(command: command)
invoker.executeCommand()
```

**使用场景：**

- 当需要将请求封装成对象时
- 当需要参数化其他对象时
- 当需要支持可撤销的操作时

**优点：**

- 降低耦合度
- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 解释器模式 (Interpreter)

解释器模式给定一个语言，定义它的文法的一种表示，并定义一个解释器，这个解释器使用该表示来解释语言中的句子。

**Swift 实现：**

```swift
// 表达式协议
protocol Expression {
    func interpret(context: Context) -> Bool
}

// 具体表达式
class TerminalExpression: Expression {
    func interpret(context: Context) -> Bool {
        // 实现逻辑
        false
    }
}

class NonTerminalExpression: Expression {
    func interpret(context: Context) -> Bool {
        // 实现逻辑
        false
    }
}

// 上下文
class Context {
    private let expressions: [Expression]
    
    init(expressions: [Expression]) {
        self.expressions = expressions
    }
    
    func interpret(input: String) -> Bool {
        // 实现逻辑
        false
    }
}

// 客户端代码
let context = Context(expressions: [TerminalExpression(), NonTerminalExpression()])
let result = context.interpret(input: "input")
```

**使用场景：**

- 当需要解释语言中的句子时
- 当需要解释和执行特定类型的句子时

**优点：**

- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 迭代器模式 (Iterator)

迭代器模式提供一种方法来顺序访问一个聚合对象中的各个元素，而无需暴露其内部表示。

**Swift 实现：**

```swift
// 迭代器协议
protocol Iterator {
    func next() -> Any?
    func hasNext() -> Bool
}

// 具体迭代器
class ConcreteIterator: Iterator {
    private let items: [Any]
    private var index = 0
    
    init(items: [Any]) {
        self.items = items
    }
    
    func next() -> Any? {
        guard index < items.count else { return nil }
        let item = items[index]
        index += 1
        return item
    }
    
    func hasNext() -> Bool {
        index < items.count
    }
}

// 聚合协议
protocol Aggregate {
    func createIterator() -> Iterator
}

// 具体聚合
class ConcreteAggregate: Aggregate {
    private let items: [Any]
    
    init(items: [Any]) {
        self.items = items
    }
    
    func createIterator() -> Iterator {
        ConcreteIterator(items: items)
    }
}

// 客户端代码
let aggregate = ConcreteAggregate(items: [1, 2, 3, 4, 5])
let iterator = aggregate.createIterator()

while iterator.hasNext() {
    if let item = iterator.next() {
        print(item)
    }
}
```

**使用场景：**

- 当需要遍历聚合对象时
- 当需要隐藏聚合对象的表示时

**优点：**

- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 中介者模式 (Mediator)

中介者模式用一个中介对象来封装一系列的对象交互。它使各对象不需要显示地相互引用，从而使其耦合松散，而且可以独立地改变它们之间的交互。

**Swift 实现：**

```swift
// 中介者协议
protocol Mediator {
    func notify(sender: Colleague, event: String)
}

// 具体中介者
class ConcreteMediator: Mediator {
    private var colleagues: [Colleague] = []
    
    func add(colleague: Colleague) {
        colleagues.append(colleague)
    }
    
    func notify(sender: Colleague, event: String) {
        for colleague in colleagues {
            if colleague !== sender {
                colleague.receive(event: event)
            }
        }
    }
}

// 同事协议
protocol Colleague {
    func send(event: String)
    func receive(event: String)
}

// 具体同事
class ConcreteColleagueA: Colleague {
    private let mediator: Mediator
    
    init(mediator: Mediator) {
        self.mediator = mediator
    }
    
    func send(event: String) {
        mediator.notify(sender: self, event: event)
    }
    
    func receive(event: String) {
        print("ConcreteColleagueA 收到事件: \(event)")
    }
}

class ConcreteColleagueB: Colleague {
    private let mediator: Mediator
    
    init(mediator: Mediator) {
        self.mediator = mediator
    }
    
    func send(event: String) {
        mediator.notify(sender: self, event: event)
    }
    
    func receive(event: String) {
        print("ConcreteColleagueB 收到事件: \(event)")
    }
}

// 客户端代码
let mediator = ConcreteMediator()
let colleagueA = ConcreteColleagueA(mediator: mediator)
let colleagueB = ConcreteColleagueB(mediator: mediator)

mediator.add(colleague: colleagueA)
mediator.add(colleague: colleagueB)

colleagueA.send(event: "事件A")
colleagueB.send(event: "事件B")
```

**使用场景：**

- 当对象之间的交互复杂时
- 当需要避免对象之间的紧密耦合时

**优点：**

- 降低耦合度
- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 备忘录模式 (Memento)

备忘录模式在不破坏封装性的前提下，捕获一个对象的内部状态，并在该对象之外保存这个状态。这样以后就可以将该对象恢复到原先保存的状态。

**Swift 实现：**

```swift
// 备忘录协议
protocol Memento {
    func getState() -> String
    func setState(_ state: String)
}

// 具体备忘录
class ConcreteMemento: Memento {
    private var state: String
    
    init(state: String) {
        self.state = state
    }
    
    func getState() -> String {
        state
    }
    
    func setState(_ state: String) {
        self.state = state
    }
}

// 发起人协议
protocol Originator {
    func save() -> Memento
    func restore(memento: Memento)
}

// 具体发起人
class ConcreteOriginator: Originator {
    private var state: String
    
    init(state: String) {
        self.state = state
    }
    
    func save() -> Memento {
        ConcreteMemento(state: state)
    }
    
    func restore(memento: Memento) {
        state = memento.getState()
    }
}

// 客户端代码
let originator = ConcreteOriginator(state: "状态A")
let memento = originator.save()
originator.restore(memento: memento)
```

**使用场景：**

- 当需要保存和恢复对象的状态时
- 当需要封装对象的内部状态时

**优点：**

- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 观察者模式 (Observer)

观察者模式定义了对象之间的一对多依赖关系，使得当一个对象改变状态时，所有依赖于它的对象都会得到通知并自动更新。

**Swift 实现：**

```swift
// 观察者协议
protocol Observer: AnyObject {
    func update(message: String)
}

// 主题协议
protocol Subject {
    func attach(_ observer: Observer)
    func detach(_ observer: Observer)
    func notify(message: String)
}

// 具体主题
class MessagePublisher: Subject {
    private var observers = [Observer]()
    
    func attach(_ observer: Observer) {
        if !observers.contains(where: { $0 === observer }) {
            observers.append(observer)
        }
    }
    
    func detach(_ observer: Observer) {
        observers.removeAll { $0 === observer }
    }
    
    func notify(message: String) {
        observers.forEach { $0.update(message: message) }
    }
    
    func createMessage(_ message: String) {
        print("消息发布者: 创建新消息 - \(message)")
        notify(message: message)
    }
}

// 具体观察者
class MessageSubscriber: Observer {
    let name: String
    
    init(name: String) {
        self.name = name
    }
    
    func update(message: String) {
        print("\(name) 收到消息: \(message)")
    }
}

// 使用观察者模式
let publisher = MessagePublisher()

let subscriber1 = MessageSubscriber(name: "订阅者 1")
let subscriber2 = MessageSubscriber(name: "订阅者 2")
let subscriber3 = MessageSubscriber(name: "订阅者 3")

publisher.attach(subscriber1)
publisher.attach(subscriber2)
publisher.attach(subscriber3)

publisher.createMessage("Hello World!")
// 输出:
// 消息发布者: 创建新消息 - Hello World!
// 订阅者 1 收到消息: Hello World!
// 订阅者 2 收到消息: Hello World!
// 订阅者 3 收到消息: Hello World!

publisher.detach(subscriber2)
publisher.createMessage("第二条消息!")
// 输出:
// 消息发布者: 创建新消息 - 第二条消息!
// 订阅者 1 收到消息: 第二条消息!
// 订阅者 3 收到消息: 第二条消息!
```

**使用场景：**

- 当一个对象的改变需要同时改变其他对象时
- 当应用中的某些对象必须观察其他对象时
- 当一个对象通知未知数量的其他对象时

**优点：**

- 支持开闭原则，可以引入新的订阅者而无需修改发布者的代码
- 建立了对象之间的动态关系，提高了灵活性
- 发布者和订阅者之间松散耦合，可以独立地改变

**缺点：**

- 订阅者被通知的顺序是随机的
- 可能引发内存泄漏（如果观察者忘记从主题中分离）
- 可能导致很难跟踪的更新级联

**iOS/Swift 中的实现方式：**

1. **NotificationCenter**:

```swift
// 发布者代码
class DataManager {
    static let dataChangedNotification = NSNotification.Name("DataManagerDataChanged")
    
    func updateData() {
        // ... 更新数据的逻辑
        
        // 发送通知
        NotificationCenter.default.post(
            name: DataManager.dataChangedNotification,
            object: self,
            userInfo: ["timestamp": Date()]
        )
    }
}

// 订阅者代码
class ViewController: UIViewController {
    private var token: NSObjectProtocol?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 订阅通知
        token = NotificationCenter.default.addObserver(
            forName: DataManager.dataChangedNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let self = self else { return }
            
            if let timestamp = notification.userInfo?["timestamp"] as? Date {
                print("数据在 \(timestamp) 更新了")
            }
            
            self.refreshUI()
        }
    }
    
    func refreshUI() {
        // 更新 UI
    }
    
    deinit {
        // 移除观察者
        if let token = token {
            NotificationCenter.default.removeObserver(token)
        }
    }
}
```

2. **Key-Value Observing (KVO)**:

```swift
class UserModel: NSObject {
    @objc dynamic var name: String
    @objc dynamic var age: Int
    
    init(name: String, age: Int) {
        self.name = name
        self.age = age
        super.init()
    }
}

class UserViewController: UIViewController {
    private var user: UserModel!
    private var observation: NSKeyValueObservation?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        user = UserModel(name: "张三", age: 25)
        
        // 观察 name 属性的变化
        observation = user.observe(\.name, options: [.old, .new]) { (user, change) in
            print("姓名从 \(change.oldValue ?? "") 变为 \(change.newValue ?? "")")
        }
        
        // 修改属性，触发观察者更新
        user.name = "李四"
    }
    
    deinit {
        // 在 Swift 中，NSKeyValueObservation 会在析构时自动失效
        // 不需要显式调用 invalidate()
    }
}
```

3. **Combine 框架**:

```swift
import Combine

class WeatherModel {
    let temperaturePublisher = PassthroughSubject<Double, Never>()
    let humidityPublisher = PassthroughSubject<Double, Never>()
    
    private var currentTemperature: Double = 0 {
        didSet {
            temperaturePublisher.send(currentTemperature)
        }
    }
    
    private var currentHumidity: Double = 0 {
        didSet {
            humidityPublisher.send(currentHumidity)
        }
    }
    
    func updateWeather(temperature: Double, humidity: Double) {
        currentTemperature = temperature
        currentHumidity = humidity
    }
}

class WeatherViewController: UIViewController {
    private var weatherModel = WeatherModel()
    private var cancellables = Set<AnyCancellable>()
    
    private let temperatureLabel = UILabel()
    private let humidityLabel = UILabel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 订阅温度变化
        weatherModel.temperaturePublisher
            .sink { [weak self] temperature in
                self?.temperatureLabel.text = String(format: "%.1f°C", temperature)
            }
            .store(in: &cancellables)
        
        // 订阅湿度变化
        weatherModel.humidityPublisher
            .sink { [weak self] humidity in
                self?.humidityLabel.text = String(format: "湿度: %.1f%%", humidity)
            }
            .store(in: &cancellables)
        
        // 模拟天气更新
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            self.weatherModel.updateWeather(temperature: 23.5, humidity: 65.0)
        }
    }
}
```

4. **SwiftUI 的 ObservableObject**:

```swift
import SwiftUI
import Combine

class UserViewModel: ObservableObject {
    @Published var name: String
    @Published var age: Int
    
    init(name: String, age: Int) {
        self.name = name
        self.age = age
    }
    
    func incrementAge() {
        age += 1
    }
}

struct UserView: View {
    @ObservedObject var viewModel: UserViewModel
    
    var body: some View {
        VStack {
            Text("姓名: \(viewModel.name)")
            Text("年龄: \(viewModel.age)")
            
            Button("增加年龄") {
                viewModel.incrementAge()
            }
            .padding()
        }
    }
}

struct ContentView: View {
    @StateObject private var userViewModel = UserViewModel(name: "张三", age: 25)
    
    var body: some View {
        UserView(viewModel: userViewModel)
    }
}
```

### 状态模式 (State)

状态模式允许对象在内部状态改变时改变它的行为。它看起来像是改变了对象所属的类。

**Swift 实现：**

```swift
// 状态协议
protocol State {
    func handle(context: Context)
}

// 具体状态
class ConcreteStateA: State {
    func handle(context: Context) {
        print("ConcreteStateA 处理请求")
    }
}

class ConcreteStateB: State {
    func handle(context: Context) {
        print("ConcreteStateB 处理请求")
    }
}

// 上下文
class Context {
    private var state: State
    
    init(state: State) {
        self.state = state
    }
    
    func request() {
        state.handle(context: self)
    }
    
    func changeState(to state: State) {
        self.state = state
    }
}

// 客户端代码
let context = Context(state: ConcreteStateA())
context.request()
context.changeState(to: ConcreteStateB())
context.request()
```

**使用场景：**

- 当对象的行为取决于它的状态，并且它必须在运行时根据状态改变行为时
- 当一个操作中含有庞大的多分支的条件语句时

**优点：**

- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 策略模式 (Strategy)

策略模式定义了一系列算法，并将每个算法封装起来，使它们可以互换使用。策略模式让算法独立于使用它的客户端。

**Swift 实现：**

```swift
// 策略接口
protocol SortingStrategy {
    func sort<T: Comparable>(_ array: [T]) -> [T]
}

// 具体策略
class BubbleSortStrategy: SortingStrategy {
    func sort<T: Comparable>(_ array: [T]) -> [T] {
        print("使用冒泡排序")
        var result = array
        let count = result.count
        
        for i in 0..<count {
            for j in 1..<(count - i) {
                if result[j] < result[j-1] {
                    result.swapAt(j, j-1)
                }
            }
        }
        
        return result
    }
}

class QuickSortStrategy: SortingStrategy {
    func sort<T: Comparable>(_ array: [T]) -> [T] {
        print("使用快速排序")
        
        // 简化的快速排序实现
        guard array.count > 1 else { return array }
        
        let pivot = array[array.count / 2]
        let less = array.filter { $0 < pivot }
        let equal = array.filter { $0 == pivot }
        let greater = array.filter { $0 > pivot }
        
        return sort(less) + equal + sort(greater)
    }
}

class MergeSortStrategy: SortingStrategy {
    func sort<T: Comparable>(_ array: [T]) -> [T] {
        print("使用归并排序")
        
        // 简化的归并排序实现
        guard array.count > 1 else { return array }
        
        let middle = array.count / 2
        let left = sort(Array(array[0..<middle]))
        let right = sort(Array(array[middle..<array.count]))
        
        return merge(left, right)
    }
    
    private func merge<T: Comparable>(_ left: [T], _ right: [T]) -> [T] {
        var leftIndex = 0
        var rightIndex = 0
        var result: [T] = []
        
        while leftIndex < left.count && rightIndex < right.count {
            if left[leftIndex] < right[rightIndex] {
                result.append(left[leftIndex])
                leftIndex += 1
            } else {
                result.append(right[rightIndex])
                rightIndex += 1
            }
        }
        
        result.append(contentsOf: left[leftIndex..<left.count])
        result.append(contentsOf: right[rightIndex..<right.count])
        
        return result
    }
}

// 上下文
class SortContext {
    private var strategy: SortingStrategy
    
    init(strategy: SortingStrategy) {
        self.strategy = strategy
    }
    
    func setStrategy(_ strategy: SortingStrategy) {
        self.strategy = strategy
    }
    
    func sort<T: Comparable>(_ array: [T]) -> [T] {
        return strategy.sort(array)
    }
}

// 使用策略模式
let numbers = [5, 2, 8, 1, 9, 3, 7, 4, 6]

// 使用冒泡排序
let context = SortContext(strategy: BubbleSortStrategy())
let sortedWithBubble = context.sort(numbers)
print(sortedWithBubble)

// 切换到快速排序
context.setStrategy(QuickSortStrategy())
let sortedWithQuick = context.sort(numbers)
print(sortedWithQuick)

// 切换到归并排序
context.setStrategy(MergeSortStrategy())
let sortedWithMerge = context.sort(numbers)
print(sortedWithMerge)
```

**使用场景：**

- 当需要使用不同的算法变体，并希望能够在运行时切换算法时
- 当有许多相似的类，只在它们的行为上有所不同时
- 当算法的数据不应该暴露给客户端时
- 当一个类定义了多种行为，并且这些行为在多个条件语句中以多个形式出现时

**优点：**

- 可以在运行时切换算法
- 隔离了算法的实现细节
- 避免了使用多重条件语句
- 更好的代码组织和可维护性

**缺点：**

- 如果只有几个算法且它们很少改变，可能不值得增加这种复杂性
- 客户端必须知道不同的策略

**iOS/Swift 中的应用：**

1. **不同的动画策略**:

```swift
protocol AnimationStrategy {
    func animate(view: UIView, completion: @escaping () -> Void)
}

class FadeAnimation: AnimationStrategy {
    func animate(view: UIView, completion: @escaping () -> Void) {
        view.alpha = 0
        
        UIView.animate(withDuration: 0.5, animations: {
            view.alpha = 1
        }, completion: { _ in
            completion()
        })
    }
}

class SlideAnimation: AnimationStrategy {
    func animate(view: UIView, completion: @escaping () -> Void) {
        let originalCenter = view.center
        view.center.x -= view.bounds.width
        
        UIView.animate(withDuration: 0.5, animations: {
            view.center = originalCenter
        }, completion: { _ in
            completion()
        })
    }
}

class ScaleAnimation: AnimationStrategy {
    func animate(view: UIView, completion: @escaping () -> Void) {
        view.transform = CGAffineTransform(scaleX: 0.01, y: 0.01)
        
        UIView.animate(withDuration: 0.5, animations: {
            view.transform = .identity
        }, completion: { _ in
            completion()
        })
    }
}

class AnimationContext {
    private var strategy: AnimationStrategy
    
    init(strategy: AnimationStrategy) {
        self.strategy = strategy
    }
    
    func setStrategy(_ strategy: AnimationStrategy) {
        self.strategy = strategy
    }
    
    func animate(view: UIView, completion: @escaping () -> Void) {
        strategy.animate(view: view, completion: completion)
    }
}

// 使用
class ViewController: UIViewController {
    let animationContext = AnimationContext(strategy: FadeAnimation())
    let targetView = UIView()
    
    func showView() {
        // 使用淡入动画
        animationContext.animate(view: targetView) {
            print("淡入动画完成")
        }
        
        // 或者使用滑入动画
        animationContext.setStrategy(SlideAnimation())
        animationContext.animate(view: targetView) {
            print("滑入动画完成")
        }
    }
}
```

2. **不同的缓存策略**:

```swift
protocol CacheStrategy {
    func setValue(_ value: Any, forKey key: String)
    func getValue(forKey key: String) -> Any?
    func removeValue(forKey key: String)
    func clear()
}

class MemoryCache: CacheStrategy {
    private var cache: [String: Any] = [:]
    
    func setValue(_ value: Any, forKey key: String) {
        cache[key] = value
    }
    
    func getValue(forKey key: String) -> Any? {
        return cache[key]
    }
    
    func removeValue(forKey key: String) {
        cache.removeValue(forKey: key)
    }
    
    func clear() {
        cache.removeAll()
    }
}

class DiskCache: CacheStrategy {
    private let fileManager = FileManager.default
    private let cacheDirectory: URL
    
    init() {
        let url = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first!
        cacheDirectory = url.appendingPathComponent("DiskCache")
        
        try? fileManager.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
    }
    
    func setValue(_ value: Any, forKey key: String) {
        guard let data = try? NSKeyedArchiver.archivedData(withRootObject: value, requiringSecureCoding: false) else {
            return
        }
        
        let fileURL = cacheDirectory.appendingPathComponent(key)
        try? data.write(to: fileURL)
    }
    
    func getValue(forKey key: String) -> Any? {
        let fileURL = cacheDirectory.appendingPathComponent(key)
        guard let data = try? Data(contentsOf: fileURL),
              let value = try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(data) else {
            return nil
        }
        
        return value
    }
    
    func removeValue(forKey key: String) {
        let fileURL = cacheDirectory.appendingPathComponent(key)
        try? fileManager.removeItem(at: fileURL)
    }
    
    func clear() {
        try? fileManager.removeItem(at: cacheDirectory)
        try? fileManager.createDirectory(at: cacheDirectory, withIntermediateDirectories: true)
    }
}

class UserDefaultsCache: CacheStrategy {
    private let userDefaults = UserDefaults.standard
    
    func setValue(_ value: Any, forKey key: String) {
        userDefaults.set(value, forKey: key)
    }
    
    func getValue(forKey key: String) -> Any? {
        return userDefaults.object(forKey: key)
    }
    
    func removeValue(forKey key: String) {
        userDefaults.removeObject(forKey: key)
    }
    
    func clear() {
        userDefaults.dictionaryRepresentation().keys.forEach { key in
            userDefaults.removeObject(forKey: key)
        }
    }
}

// 缓存管理器
class CacheManager {
    private var strategy: CacheStrategy
    
    init(strategy: CacheStrategy) {
        self.strategy = strategy
    }
    
    func setStrategy(_ strategy: CacheStrategy) {
        self.strategy = strategy
    }
    
    func setValue(_ value: Any, forKey key: String) {
        strategy.setValue(value, forKey: key)
    }
    
    func getValue(forKey key: String) -> Any? {
        return strategy.getValue(forKey: key)
    }
    
    func removeValue(forKey key: String) {
        strategy.removeValue(forKey: key)
    }
    
    func clear() {
        strategy.clear()
    }
}

// 使用
class DataStore {
    private let cacheManager: CacheManager
    
    init() {
        // 默认使用内存缓存
        cacheManager = CacheManager(strategy: MemoryCache())
    }
    
    func saveSmallData(_ data: Data, forKey key: String) {
        // 小数据使用内存缓存
        cacheManager.setStrategy(MemoryCache())
        cacheManager.setValue(data, forKey: key)
    }
    
    func saveLargeData(_ data: Data, forKey key: String) {
        // 大数据使用磁盘缓存
        cacheManager.setStrategy(DiskCache())
        cacheManager.setValue(data, forKey: key)
    }
    
    func saveUserPreference(_ value: Any, forKey key: String) {
        // 用户偏好使用 UserDefaults
        cacheManager.setStrategy(UserDefaultsCache())
        cacheManager.setValue(value, forKey: key)
    }
}
```

### 模板方法模式 (Template Method)

模板方法模式在一个方法中定义一个算法的骨架，而将一些步骤延迟到子类中。模板方法使得子类可以不改变一个算法的结构即可重定义该算法的某些特定步骤。

**Swift 实现：**

```swift
// 抽象类
class AbstractClass {
    func templateMethod() {
        step1()
        step2()
        step3()
    }
    
    func step1() {
        // 默认实现
    }
    
    func step2() {
        // 默认实现
    }
    
    func step3() {
        // 默认实现
    }
}

// 具体子类
class ConcreteClass: AbstractClass {
    override func step1() {
        print("ConcreteClass 的 step1")
    }
    
    override func step2() {
        print("ConcreteClass 的 step2")
    }
    
    override func step3() {
        print("ConcreteClass 的 step3")
    }
}

// 客户端代码
let abstractClass = AbstractClass()
abstractClass.templateMethod()

let concreteClass = ConcreteClass()
concreteClass.templateMethod()
```

**使用场景：**

- 当多个子类有共同的操作，且操作中包含相同或相似的步骤时
- 当需要在子类中重新定义算法的某些步骤时

**优点：**

- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

### 访问者模式 (Visitor)

访问者模式表示一个作用于某对象结构中的各元素的操作。它使你可以在不改变各元素的类的前提下定义作用于这些元素的新操作。

**Swift 实现：**

```swift
// 元素协议
protocol Element {
    func accept(visitor: Visitor)
}

// 具体元素
class ConcreteElementA: Element {
    func accept(visitor: Visitor) {
        visitor.visit(self)
    }
}

class ConcreteElementB: Element {
    func accept(visitor: Visitor) {
        visitor.visit(self)
    }
}

// 访问者协议
protocol Visitor {
    func visit(_ element: ConcreteElementA)
    func visit(_ element: ConcreteElementB)
}

// 具体访问者
class ConcreteVisitor: Visitor {
    func visit(_ element: ConcreteElementA) {
        print("ConcreteVisitor 访问 ConcreteElementA")
    }
    
    func visit(_ element: ConcreteElementB) {
        print("ConcreteVisitor 访问 ConcreteElementB")
    }
}

// 对象结构
class ObjectStructure {
    private var elements: [Element] = []
    
    func attach(element: Element) {
        elements.append(element)
    }
    
    func detach(element: Element) {
        elements.removeAll { $0 === element }
    }
    
    func accept(visitor: Visitor) {
        for element in elements {
            element.accept(visitor: visitor)
        }
    }
}

// 客户端代码
let objectStructure = ObjectStructure()
objectStructure.attach(element: ConcreteElementA())
objectStructure.attach(element: ConcreteElementB())

let visitor = ConcreteVisitor()
objectStructure.accept(visitor: visitor)
```

**使用场景：**

- 当需要对一个对象结构中的对象进行一些额外操作，且这些操作需要在类中定义时
- 当需要对一个对象结构中的对象进行一些不相关的操作，且这些操作需要封装在对象结构之外时

**优点：**

- 提高系统的灵活性

**缺点：**

- 可能导致系统复杂度增加

## iOS 特有的架构模式

### MVC (Model-View-Controller)

MVC 模式将应用程序分为三个主要部分：模型、视图和控制器。它有助于将应用程序的逻辑分离为不同的组件，从而提高代码的可维护性和可扩展性。

### MVVM (Model-View-ViewModel)

MVVM 模式将应用程序分为三个主要部分：模型、视图和视图模型。它有助于将应用程序的逻辑分离为不同的组件，从而提高代码的可维护性和可扩展性。

### VIPER (View-Interactor-Presenter-Entity-Router)

VIPER 模式将应用程序分为五个主要部分：视图、交互器、表示器、实体和路由器。它有助于将应用程序的逻辑分离为不同的组件，从而提高代码的可维护性和可扩展性。

### 协调器模式 (Coordinator)

协调器模式用于管理应用程序中的导航和状态。它有助于将应用程序的逻辑分离为不同的组件，从而提高代码的可维护性和可扩展性。

### Clean Architecture

Clean Architecture 是一种软件架构风格，它将应用程序分为三个主要部分：领域逻辑、应用逻辑和基础设施。它有助于将应用程序的逻辑分离为不同的组件，从而提高代码的可维护性和可扩展性。

## Swift 特有的设计模式

Swift 语言的特性使其拥有一些特定的设计模式实现方法。这些模式充分利用了 Swift 的类型系统、协议和泛型等特性。

### 委托模式 (Delegation)

委托模式是 iOS 开发中最常用的模式之一，允许一个对象将某些责任委托给另一个对象。

**Swift 实现：**

```swift
// 委托协议
protocol TaskDelegate: AnyObject {
    func taskDidStart(_ task: Task)
    func task(_ task: Task, didCompleteWithSuccess success: Bool)
    func task(_ task: Task, didUpdateProgress progress: Float)
}

// 提供默认实现（可选）
extension TaskDelegate {
    func taskDidStart(_ task: Task) {
        print("任务已开始: \(task.name)")
    }
    
    func task(_ task: Task, didUpdateProgress progress: Float) {
        print("任务进度更新: \(progress * 100)%")
    }
}

// 使用委托的类
class Task {
    let name: String
    weak var delegate: TaskDelegate?
    
    init(name: String) {
        self.name = name
    }
    
    func start() {
        delegate?.taskDidStart(self)
        
        // 模拟进度更新
        DispatchQueue.global().async {
            for i in 1...10 {
                Thread.sleep(forTimeInterval: 0.5)
                let progress = Float(i) / 10.0
                
                DispatchQueue.main.async {
                    self.delegate?.task(self, didUpdateProgress: progress)
                }
            }
            
            DispatchQueue.main.async {
                self.delegate?.task(self, didCompleteWithSuccess: true)
            }
        }
    }
}

// 实现委托的类
class TaskManager: TaskDelegate {
    func task(_ task: Task, didCompleteWithSuccess success: Bool) {
        if success {
            print("任务成功完成: \(task.name)")
        } else {
            print("任务失败: \(task.name)")
        }
    }
}

// 使用
let task = Task(name: "数据下载")
let manager = TaskManager()

task.delegate = manager
task.start()
```

**使用场景：**

- 当一个对象需要通知另一个对象某些事件，但不想直接依赖于该对象时
- 当需要将行为从一个类解耦出来，使其可以被外部定制时
- 当实现回调机制，但希望比闭包更结构化时

**优点：**

- 松散耦合，委托者不需要知道具体委托的实现
- 可以在运行时动态更改行为
- 通过协议可以提供默认实现，减少重复代码

**缺点：**

- 如果管理不当，可能导致循环引用（需要使用 weak 引用）
- 当委托方法过多时，协议会变得臃肿

### 扩展 (Extensions)

Swift 的扩展允许向现有类型添加新功能，而无需修改原始代码或继承自该类型。这是一种特殊的装饰模式变体。

**Swift 实现：**

```swift
// 扩展 String 类型
extension String {
    // 添加新的计算属性
    var isValidEmail: Bool {
        let emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
        let emailPredicate = NSPredicate(format: "SELF MATCHES %@", emailRegex)
        return emailPredicate.evaluate(with: self)
    }
    
    // 添加新的方法
    func truncated(toLength length: Int, withTrailing trailing: String = "...") -> String {
        if self.count <= length {
            return self
        }
        return String(self.prefix(length)) + trailing
    }
}

// 使用扩展
let email = "user@example.com"
print("是否有效邮箱: \(email.isValidEmail)") // 输出: 是否有效邮箱: true

let longText = "这是一段很长的文本，需要被截断以适应显示区域"
print(longText.truncated(toLength: 10)) // 输出: 这是一段很长的...
```

**协议扩展：**

```swift
// 定义协议
protocol Drawable {
    func draw()
}

// 为协议提供默认实现
extension Drawable {
    func draw() {
        print("绘制默认图形")
    }
    
    func prepare() {
        print("准备绘制")
    }
}

// 实现协议的类型
class Circle: Drawable {
    // 可以选择是否覆盖默认实现
    func draw() {
        print("绘制圆形")
    }
}

class Rectangle: Drawable {
    // 使用默认实现
}

// 使用
let circle = Circle()
circle.prepare() // 输出: 准备绘制
circle.draw()    // 输出: 绘制圆形

let rectangle = Rectangle()
rectangle.prepare() // 输出: 准备绘制
rectangle.draw()    // 输出: 绘制默认图形
```

**使用场景：**

- 当需要向现有类型添加功能，但不能或不想修改原始代码时
- 当想要将特定功能组织到一起时
- 当希望提供协议的默认实现时

**优点：**

- 可以添加功能而不修改原始代码
- 保持代码的模块化和清晰
- 可以为协议提供默认实现，减少代码重复

**缺点：**

- 不能添加存储属性
- 不能覆盖现有方法（只能添加新方法）
- 扩展过多可能导致类型功能过于分散

### 类型擦除 (Type Erasure)

类型擦除是一种隐藏具体类型的技术，使代码能够处理不同的具体类型，同时保持类型安全。

**Swift 实现：**

```swift
// 定义协议
protocol Drawing {
    func draw()
}

// 具体类型
struct CircleDrawing: Drawing {
    func draw() {
        print("绘制圆形")
    }
}

struct RectangleDrawing: Drawing {
    func draw() {
        print("绘制矩形")
    }
}

// 类型擦除包装器
struct AnyDrawing: Drawing {
    private let _draw: () -> Void
    
    init<D: Drawing>(_ drawing: D) {
        _draw = drawing.draw
    }
    
    func draw() {
        _draw()
    }
}

// 使用类型擦除
func drawShapes(shapes: [AnyDrawing]) {
    for shape in shapes {
        shape.draw()
    }
}

let circle = CircleDrawing()
let rectangle = RectangleDrawing()

// 创建类型擦除的集合
let shapes: [AnyDrawing] = [
    AnyDrawing(circle),
    AnyDrawing(rectangle)
]

drawShapes(shapes: shapes)
```

**更复杂的例子 - 类型擦除容器：**

```swift
// 协议定义了关联类型
protocol DataProvider {
    associatedtype DataType
    func getData() -> DataType
}

// 具体实现
struct StringProvider: DataProvider {
    typealias DataType = String
    
    func getData() -> String {
        return "Hello, World!"
    }
}

struct IntArrayProvider: DataProvider {
    typealias DataType = [Int]
    
    func getData() -> [Int] {
        return [1, 2, 3, 4, 5]
    }
}

// 类型擦除容器
class AnyDataProvider<T> {
    private let _getData: () -> T
    
    init<P: DataProvider>(_ provider: P) where P.DataType == T {
        _getData = provider.getData
    }
    
    func getData() -> T {
        return _getData()
    }
}

// 使用
let stringProvider = AnyDataProvider(StringProvider())
let intArrayProvider = AnyDataProvider(IntArrayProvider())

print(stringProvider.getData())         // 输出: Hello, World!
print(intArrayProvider.getData().count) // 输出: 5
```

**使用场景：**

- 当需要存储实现相同协议但具有不同关联类型的对象集合时
- 当需要隐藏具体类型的实现细节时
- 当需要将依赖于特定类型的代码与通用代码分离时

**优点：**

- 提供类型安全的抽象
- 允许使用具有关联类型的协议作为泛型约束
- 简化复杂的泛型代码

**缺点：**

- 实现可能复杂
- 可能引入运行时开销
- 可能导致代码更难理解

### 属性观察者 (Property Observers)

Swift 的属性观察者允许监控和响应属性值的变化，是实现观察者模式的一种内置方法。

**Swift 实现：**

```swift
class User {
    var name: String {
        willSet {
            print("名称将从 \(name) 变为 \(newValue)")
        }
        didSet {
            print("名称已从 \(oldValue) 变为 \(name)")
            // 可以在这里触发 UI 更新或其他操作
        }
    }
    
    var age: Int = 0 {
        didSet {
            if age < 0 {
                print("年龄不能为负数，重置为 0")
                age = 0
            }
        }
    }
    
    init(name: String, age: Int) {
        self.name = name
        self.age = age
    }
}

// 使用
let user = User(name: "张三", age: 25)
user.name = "李四"
// 输出:
// 名称将从 张三 变为 李四
// 名称已从 张三 变为 李四

user.age = -5
// 输出:
// 年龄不能为负数，重置为 0
print(user.age) // 输出: 0
```

**结合其他模式：**

```swift
class ViewModel {
    var isLoading: Bool = false {
        didSet {
            // 当加载状态改变时，通知观察者
            loadingStateChanged?(isLoading)
        }
    }
    
    // 闭包作为回调
    var loadingStateChanged: ((Bool) -> Void)?
    
    func fetchData() {
        isLoading = true
        
        // 模拟网络请求
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            self?.isLoading = false
        }
    }
}

// 使用
let viewModel = ViewModel()

viewModel.loadingStateChanged = { isLoading in
    if isLoading {
        print("开始加载，显示加载指示器")
    } else {
        print("加载完成，隐藏加载指示器")
    }
}

viewModel.fetchData()
// 输出:
// 开始加载，显示加载指示器
// (2秒后)
// 加载完成，隐藏加载指示器
```

**使用场景：**

- 当需要监控属性值的变化时
- 当需要在属性值变化前后执行特定操作时
- 当需要验证或修正新的属性值时

**优点：**

- 语法简洁，易于使用
- 与 Swift 语言深度集成
- 不需要额外的设计模式实现

**缺点：**

- 只能用于监控单个对象的属性
- 需要直接访问属性才能触发，不能远程监控

### 函数式编程模式

Swift 的函数式编程特性允许更简洁、更声明式的代码风格，并避免副作用。

**Swift 实现：**

```swift
// 高阶函数示例
let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// 函数式方法 - 过滤、映射和归约
let result = numbers
    .filter { $0 % 2 == 0 }              // 过滤出偶数
    .map { $0 * $0 }                     // 对每个数字求平方
    .reduce(0, { $0 + $1 })              // 求和

print(result) // 输出: 220 (2² + 4² + 6² + 8² + 10²)

// 函数组合
typealias StringTransform = (String) -> String

func lowercase(_ s: String) -> String {
    return s.lowercased()
}

func trim(_ s: String) -> String {
    return s.trimmingCharacters(in: .whitespacesAndNewlines)
}

func removeSpecialChars(_ s: String) -> String {
    return s.components(separatedBy: CharacterSet.alphanumerics.inverted).joined()
}

// 组合函数
func compose<T>(_ f: @escaping (T) -> T, _ g: @escaping (T) -> T) -> (T) -> T {
    return { f(g($0)) }
}

let normalizeString = compose(lowercase, compose(trim, removeSpecialChars))
let result2 = normalizeString("  Hello, World!  ")
print(result2) // 输出: helloworld
```

**使用场景：**

- 当处理数据转换和处理时
- 当需要编写没有副作用的纯函数时
- 当需要组合多个操作时

**优点：**

- 代码更简洁、更易读
- 减少可变状态，降低出错可能性
- 易于测试和维护

**缺点：**

- 学习曲线可能较陡
- 过度使用可能导致代码难以理解
- 可能有性能开销（如果不小心使用）

## SwiftUI 中的设计模式

SwiftUI 引入了新的声明式编程范式和新的设计模式。

### 数据流模式

SwiftUI 的数据流模式主要包括：

1. **单向数据流**：

```swift
import SwiftUI

// 模型
struct Todo: Identifiable {
    let id = UUID()
    var title: String
    var isCompleted: Bool
}

// 视图模型
class TodoListViewModel: ObservableObject {
    @Published var todos: [Todo] = []
    
    func addTodo(title: String) {
        let newTodo = Todo(title: title, isCompleted: false)
        todos.append(newTodo)
    }
    
    func toggleCompletion(for todo: Todo) {
        if let index = todos.firstIndex(where: { $0.id == todo.id }) {
            todos[index].isCompleted.toggle()
        }
    }
}

// 视图
struct TodoListView: View {
    @ObservedObject var viewModel: TodoListViewModel
    @State private var newTodoTitle = ""
    
    var body: some View {
        VStack {
            HStack {
                TextField("新任务", text: $newTodoTitle)
                Button("添加") {
                    if !newTodoTitle.isEmpty {
                        viewModel.addTodo(title: newTodoTitle)
                        newTodoTitle = ""
                    }
                }
            }
            .padding()
            
            List {
                ForEach(viewModel.todos) { todo in
                    HStack {
                        Text(todo.title)
                        Spacer()
                        if todo.isCompleted {
                            Image(systemName: "checkmark")
                                .foregroundColor(.green)
                        }
                    }
                    .onTapGesture {
                        viewModel.toggleCompletion(for: todo)
                    }
                }
            }
        }
    }
}

// 预览
struct TodoListView_Previews: PreviewProvider {
    static var previews: some View {
        let viewModel = TodoListViewModel()
        viewModel.todos = [
            Todo(title: "学习 SwiftUI", isCompleted: true),
            Todo(title: "写代码", isCompleted: false),
            Todo(title: "构建应用", isCompleted: false)
        ]
        
        return TodoListView(viewModel: viewModel)
    }
}
```

2. **State 和绑定**：

```swift
struct CounterView: View {
    @State private var count = 0
    
    var body: some View {
        VStack {
            Text("计数: \(count)")
                .font(.largeTitle)
            
            HStack {
                Button("-") {
                    count -= 1
                }
                .font(.title)
                .padding()
                
                Button("+") {
                    count += 1
                }
                .font(.title)
                .padding()
            }
            
            // 使用绑定传递 State
            CounterControlsView(count: $count)
        }
    }
}

struct CounterControlsView: View {
    @Binding var count: Int
    
    var body: some View {
        HStack {
            Button("重置") {
                count = 0
            }
            .padding()
            
            Button("乘以 2") {
                count *= 2
            }
            .padding()
        }
    }
}
```

### 环境与依赖注入

SwiftUI 通过环境对象和首选项提供了一种依赖注入机制：

```swift
// 环境对象
class AppSettings: ObservableObject {
    @Published var isDarkMode = false
    @Published var fontSize: CGFloat = 14
    @Published var accentColor: Color = .blue
}

struct SettingsView: View {
    @EnvironmentObject var settings: AppSettings
    
    var body: some View {
        Form {
            Toggle("深色模式", isOn: $settings.isDarkMode)
            
            HStack {
                Text("字体大小")
                Slider(value: $settings.fontSize, in: 12...24, step: 1)
                Text("\(Int(settings.fontSize))")
            }
            
            Picker("强调色", selection: $settings.accentColor) {
                Text("蓝色").tag(Color.blue)
                Text("红色").tag(Color.red)
                Text("绿色").tag(Color.green)
            }
        }
        .padding()
    }
}

struct ContentView: View {
    @StateObject private var settings = AppSettings()
    
    var body: some View {
        TabView {
            Text("主页")
                .tabItem { Label("主页", systemImage: "house") }
            
            SettingsView()
                .tabItem { Label("设置", systemImage: "gear") }
        }
        .environmentObject(settings)
        .preferredColorScheme(settings.isDarkMode ? .dark : .light)
        .accentColor(settings.accentColor)
        .font(.system(size: settings.fontSize))
    }
}
```

### 视图组合

SwiftUI 鼓励通过组合小型、可重用的视图来构建复杂 UI：

```swift
// 基础组件
struct PrimaryButton: View {
    let title: String
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.headline)
                .padding()
                .frame(maxWidth: .infinity)
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(10)
        }
    }
}

struct InfoCard: View {
    let title: String
    let description: String
    let iconName: String
    
    var body: some View {
        HStack {
            Image(systemName: iconName)
                .font(.largeTitle)
                .padding()
                .foregroundColor(.blue)
            
            VStack(alignment: .leading) {
                Text(title)
                    .font(.headline)
                Text(description)
                    .font(.subheadline)
                    .foregroundColor(.gray)
            }
            
            Spacer()
        }
        .padding()
        .background(Color.white)
        .cornerRadius(10)
        .shadow(radius: 2)
    }
}

// 组合使用
struct UserProfileView: View {
    @State private var showingSettings = false
    
    var body: some View {
        VStack(spacing: 20) {
            InfoCard(
                title: "张三",
                description: "iOS 开发者",
                iconName: "person.circle"
            )
            
            InfoCard(
                title: "电子邮箱",
                description: "zhangsan@example.com",
                iconName: "envelope"
            )
            
            InfoCard(
                title: "地址",
                description: "北京市海淀区",
                iconName: "location"
            )
            
            Spacer()
            
            PrimaryButton(title: "编辑资料") {
                showingSettings = true
            }
        }
        .padding()
        .sheet(isPresented: $showingSettings) {
            Text("设置页面")
        }
    }
}
```

## 设计模式的选择与应用

### 如何选择合适的设计模式

1. **明确问题**：首先，明确你要解决的问题是什么。
2. **考虑上下文**：考虑应用的架构、性能要求和扩展性需求。
3. **权衡利弊**：评估各种模式的优缺点，选择最合适的。
4. **保持简单**：避免过度设计，从简单开始，必要时再引入更复杂的模式。
5. **考虑惯例**：遵循 iOS/Swift 开发中的常见实践和惯例。

### 避免过度设计

设计模式是工具，而不是目标。过度应用设计模式可能导致：

1. **不必要的复杂性**：使代码难以理解和维护。
2. **性能开销**：某些模式可能引入额外的间接层，影响性能。
3. **学习曲线陡峭**：团队成员可能需要更长时间来理解代码。

简单的解决方案通常是最好的。只有当简单的解决方案不足以应对复杂性或未来的变化时，才应考虑使用设计模式。

### 模式组合的艺术

在实际应用中，设计模式往往不是孤立使用的，而是相互结合的：

1. **MVC + 单例**：控制器使用单例服务来获取数据。
2. **MVVM + 观察者**：视图模型使用观察者模式通知视图更新。
3. **工厂 + 策略**：使用工厂创建不同的策略对象。
4. **适配器 + 装饰器**：先适配接口，再添加功能。

成功的设计依赖于恰当地组合这些模式，以构建灵活、可维护的代码。

## 总结

设计模式是软件开发中解决常见问题的有效工具。在 iOS 开发中，理解并应用这些模式可以帮助我们创建更加健壮、灵活和可维护的应用程序。

Swift 的现代特性和 iOS 平台的独特性质为设计模式的应用提供了新的视角和方法。通过学习这些模式，我们可以：

1. **更快地解决问题**：利用经过验证的解决方案。
2. **提高代码质量**：创建更加结构化、可测试的代码。
3. **促进团队合作**：使用共同的词汇和概念进行沟通。
4. **设计更灵活的系统**：构建能够适应变化的应用程序。

然而，重要的是要记住，设计模式是工具而非规则。最好的实践是根据具体情况选择适当的模式，并在需要时将其调整以适应特定的需求。

## 参考资源

1. **书籍**
   - 《设计模式：可复用面向对象软件的基础》(Gang of Four)
   - 《Swift 设计模式》(Jon Hoffman)
   - 《Pro Design Patterns in Swift》(Adam Freeman)

2. **在线资源**
   - [Swift.org 官方文档](https://swift.org/documentation/)
   - [Apple 开发者文档](https://developer.apple.com/documentation/)
   - [Hacking with Swift](https://www.hackingwithswift.com/)
   - [Ray Wenderlich 教程](https://www.raywenderlich.com/)

3. **开源项目**
   - [RxSwift](https://github.com/ReactiveX/RxSwift)
   - [Alamofire](https://github.com/Alamofire/Alamofire)
   - [Moya](https://github.com/Moya/Moya)
   - [Kingfisher](https://github.com/onevcat/Kingfisher) 