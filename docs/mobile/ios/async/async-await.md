# 异步/等待 - 现代并发编程

Swift 5.5 引入的异步/等待（async/await）特性为异步编程提供了一种更简洁、更直观的方式。本文档将全面介绍 async/await 的基本概念、使用方法和最佳实践，帮助你掌握这一现代并发编程技术。

## 目录

- [基本概念](#基本概念)
- [异步函数](#异步函数)
- [结构化并发](#结构化并发)
- [任务管理](#任务管理)
- [异步序列](#异步序列)
- [Actor 模型](#actor-模型)
- [与传统方法对比](#与传统方法对比)
- [实际应用](#实际应用)
- [性能考量](#性能考量)
- [调试技巧](#调试技巧)
- [最佳实践](#最佳实践)
- [常见问题与解决方案](#常见问题与解决方案)

## 基本概念

异步/等待（async/await）提供了一种编写异步代码的方式，使其看起来像同步代码，同时保持非阻塞特性。这种方式让开发者可以更直观地表达异步操作的意图，减少回调嵌套（回调地狱），并提供更好的错误处理机制。

### 核心概念

- **异步函数**：使用 `async` 关键字标记的函数，可以在执行过程中暂停并稍后恢复，而不会阻塞线程
- **等待表达式**：使用 `await` 关键字调用异步函数，标记函数执行过程中可能暂停的点
- **结构化并发**：使用 `Task` 和 `TaskGroup` 管理并发执行的任务，确保子任务在父任务完成前完成
- **非阻塞操作**：异步函数暂停时不会阻塞底层线程，允许其他工作继续进行
- **异步上下文**：一个代码区域，在其中可以使用 `await` 关键字

### 异步执行流程

当程序执行到 `await` 表达式时，当前函数会暂停执行，控制权返回给系统。系统可以决定在同一线程上执行其他任务，或者在不同的线程上恢复函数执行。这样可以提高资源利用率，避免线程被长时间阻塞。

![异步执行流程](https://example.com/async_flow.png)

### 为什么需要 async/await

1. **提高代码可读性**：扁平化代码结构，避免回调嵌套
2. **简化错误处理**：使用熟悉的 try/catch 机制处理异步错误
3. **改进类型安全**：编译时检查异步操作
4. **提升性能**：比传统的基于回调的方法更高效
5. **易于推理**：代码结构更接近问题的逻辑结构

## 异步函数

异步函数是 Swift 异步编程的基础。它们可以在执行过程中暂停并在稍后恢复，而不会阻塞线程。

### 定义异步函数

使用 `async` 关键字定义异步函数：

```swift
// 基本异步函数
func fetchUserData() async throws -> User {
    let url = URL(string: "https://api.example.com/users/1")!
    let (data, _) = try await URLSession.shared.data(from: url)
    return try JSONDecoder().decode(User.self, from: data)
}

// 带参数的异步函数
func fetchUser(id: Int) async throws -> User {
    let url = URL(string: "https://api.example.com/users/\(id)")!
    let (data, response) = try await URLSession.shared.data(from: url)
    
    guard let httpResponse = response as? HTTPURLResponse,
          (200...299).contains(httpResponse.statusCode) else {
        throw APIError.invalidResponse
    }
    
    return try JSONDecoder().decode(User.self, from: data)
}

// 带泛型的异步函数
func fetchData<T: Decodable>(from endpoint: String) async throws -> T {
    let url = URL(string: "https://api.example.com/\(endpoint)")!
    let (data, response) = try await URLSession.shared.data(from: url)
    
    guard let httpResponse = response as? HTTPURLResponse,
          (200...299).contains(httpResponse.statusCode) else {
        throw APIError.invalidResponse
    }
    
    return try JSONDecoder().decode(T.self, from: data)
}

// 不抛出错误的异步函数
func calculateStatistics() async -> Statistics {
    // 执行耗时计算
    let result = await performHeavyCalculation()
    return Statistics(result: result)
}
```

### 调用异步函数

异步函数只能在异步上下文中调用，使用 `await` 关键字标记调用点：

```swift
// 在异步上下文中调用
func loadUserProfile() async {
    do {
        let user = try await fetchUserData()
        updateUI(with: user)
    } catch {
        handleError(error)
    }
}

// 并行调用多个异步函数
func loadDashboardData() async throws -> DashboardData {
    async let user = fetchUser(id: 1)
    async let posts = fetchPosts(userId: 1)
    async let followers = fetchFollowers(userId: 1)
    
    return DashboardData(
        user: try await user,
        posts: try await posts,
        followers: try await followers
    )
}

// 在非异步上下文中调用
func buttonTapped() {
    // 创建任务来调用异步函数
    Task {
        do {
            let user = try await fetchUserData()
            // 在主线程更新 UI
            await MainActor.run {
                updateUI(with: user)
            }
        } catch {
            await MainActor.run {
                handleError(error)
            }
        }
    }
}
```

### 异步属性和异步初始化器

```swift
// 异步计算属性（仅适用于 actor 类型）
actor UserManager {
    var currentUser: User {
        get async throws {
            try await fetchUserData()
        }
    }
    
    // 异步读写属性
    private var _cachedData: Data?
    var cachedData: Data {
        get async throws {
            if let data = _cachedData {
                return data
            }
            let newData = try await fetchData()
            _cachedData = newData
            return newData
        }
    }
}

// 异步初始化器
class ImageLoader {
    let image: UIImage
    
    init(url: URL) async throws {
        let (data, _) = try await URLSession.shared.data(from: url)
        guard let image = UIImage(data: data) else {
            throw ImageError.invalidData
        }
        self.image = image
    }
}

// 创建异步初始化的对象
func loadImage() async throws -> UIImage {
    let loader = try await ImageLoader(url: imageURL)
    return loader.image
}
```

### 异步闭包

```swift
// 函数接受异步闭包参数
func processItems<T>(_ items: [T], using processor: (T) async throws -> T) async rethrows -> [T] {
    var results = [T]()
    for item in items {
        let processed = try await processor(item)
        results.append(processed)
    }
    return results
}

// 使用异步闭包
let processedItems = await processItems([1, 2, 3]) { number in
    // 复杂的异步处理
    try await complexProcess(number)
}
```

### 将基于回调的 API 转换为异步函数

使用 `withCheckedThrowingContinuation` 或 `withCheckedContinuation` 将基于回调的 API 转换为异步函数：

```swift
// 将基于回调的 API 转换为异步函数
func fetchData(from url: URL) async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
        let task = URLSession.shared.dataTask(with: url) { data, response, error in
            if let error = error {
                continuation.resume(throwing: error)
                return
            }
            
            guard let data = data else {
                continuation.resume(throwing: URLError(.badServerResponse))
                return
            }
            
            continuation.resume(returning: data)
        }
        
        task.resume()
    }
}

// 转换不抛出错误的 API
func requestLocationPermission() async -> Bool {
    await withCheckedContinuation { continuation in
        locationManager.requestWhenInUseAuthorization { granted in
            continuation.resume(returning: granted)
        }
    }
}
```

## 结构化并发

结构化并发是一种并发编程模型，它确保所有并发任务在其父任务完成之前完成。这提供了更好的资源管理和错误处理。

### async let 绑定

`async let` 允许你并行启动多个异步操作，并在需要结果时等待它们完成：

```swift
func loadDashboard() async throws -> Dashboard {
    // 并行执行多个异步操作
    async let user = fetchUser()
    async let posts = fetchPosts()
    async let notifications = fetchNotifications()
    
    // 执行其他本地工作
    let preferences = loadLocalPreferences()
    
    // 等待所有异步操作完成
    return try Dashboard(
        user: await user,
        posts: await posts,
        notifications: await notifications,
        preferences: preferences
    )
}
```

`async let` 和串行执行的性能对比：

```swift
// 使用 async let 并行执行
func loadDataParallel() async throws -> (User, [Post], [Notification]) {
    async let user = fetchUser()  // 立即开始，耗时 1 秒
    async let posts = fetchPosts()  // 立即开始，耗时 1 秒
    async let notifications = fetchNotifications()  // 立即开始，耗时 1 秒
    
    // 总耗时约 1 秒
    return try (await user, await posts, await notifications)
}

// 串行执行相同的操作
func loadDataSerial() async throws -> (User, [Post], [Notification]) {
    let user = try await fetchUser()  // 耗时 1 秒
    let posts = try await fetchPosts()  // 耗时 1 秒
    let notifications = try await fetchNotifications()  // 耗时 1 秒
    
    // 总耗时约 3 秒
    return (user, posts, notifications)
}
```

### TaskGroup

`TaskGroup` 允许你动态创建和管理一组任务，并收集它们的结果：

```swift
func loadImages(urls: [URL]) async throws -> [UIImage] {
    try await withThrowingTaskGroup(of: (Int, UIImage).self) { group in
        var images = [UIImage?](repeating: nil, count: urls.count)
        
        // 添加子任务
        for (index, url) in urls.enumerated() {
            group.addTask {
                let (data, _) = try await URLSession.shared.data(from: url)
                guard let image = UIImage(data: data) else {
                    throw ImageError.invalidData
                }
                return (index, image)
            }
        }
        
        // 收集结果
        for try await (index, image) in group {
            images[index] = image
        }
        
        // 过滤掉可能的 nil 值
        return images.compactMap { $0 }
    }
}

// 不抛出错误的 TaskGroup
func combineResults<T>(operations: [() async -> T]) async -> [T] {
    await withTaskGroup(of: T.self) { group in
        for operation in operations {
            group.addTask {
                await operation()
            }
        }
        
        var results = [T]()
        for await result in group {
            results.append(result)
        }
        
        return results
    }
}
```

### 任务取消

任务可以被取消，而且取消会自动传播到子任务：

```swift
func processImages(urls: [URL]) async throws -> [ProcessedImage] {
    try await withThrowingTaskGroup(of: ProcessedImage.self) { group in
        for url in urls {
            group.addTask {
                let image = try await downloadImage(from: url)
                
                // 检查取消状态
                try Task.checkCancellation()
                
                return try await processImage(image)
            }
        }
        
        var results = [ProcessedImage]()
        for try await image in group {
            results.append(image)
        }
        
        return results
    }
}

// 使用并处理取消
let task = Task {
    do {
        let images = try await processImages(urls: imageURLs)
        await updateGallery(with: images)
    } catch is CancellationError {
        print("图片处理被取消")
    } catch {
        print("处理图片时出错: \(error)")
    }
}

// 稍后取消任务
task.cancel()
```

### 任务本地值

任务本地值允许你在任务内部存储值，并在子任务中继承这些值：

```swift
// 定义任务本地值
private enum TraceIDKey: TaskLocalValueKey {
    static let defaultValue = UUID().uuidString
}

extension TaskLocal {
    static var traceID: String {
        get { self[TraceIDKey.self] }
        set { self[TraceIDKey.self] = newValue }
    }
}

// 使用任务本地值
func performOperation() async {
    await TaskLocal.$traceID.withValue("OPERATION-1") {
        print("当前 Trace ID: \(TaskLocal.traceID)")
        
        // 创建子任务，继承父任务的本地值
        let task = Task {
            print("子任务 Trace ID: \(TaskLocal.traceID)")  // 输出: "OPERATION-1"
        }
        
        // 使用不同的值创建子任务
        let customTask = await TaskLocal.$traceID.withValue("CUSTOM-ID") {
            print("自定义 Trace ID: \(TaskLocal.traceID)")  // 输出: "CUSTOM-ID"
            return Task {
                print("自定义子任务 Trace ID: \(TaskLocal.traceID)")  // 输出: "CUSTOM-ID"
            }
        }
    }
}
```

## 与传统方法对比

Swift 提供了多种处理异步编程的方式，包括回调、Combine 框架和 async/await。了解它们之间的差异可以帮助你选择最适合的方法。

### 回调风格 vs. async/await

```swift
// 传统回调风格
func fetchData(completion: @escaping (Result<Data, Error>) -> Void) {
    URLSession.shared.dataTask(with: url) { data, response, error in
        if let error = error {
            completion(.failure(error))
            return
        }
        
        guard let data = data else {
            completion(.failure(APIError.noData))
            return
        }
        
        completion(.success(data))
    }.resume()
}

// 调用回调方法
fetchData { result in
    switch result {
    case .success(let data):
        // 处理数据
        self.processData(data) { processedResult in
            // 嵌套回调
            self.updateUI(with: processedResult) {
                // 更多嵌套...
                self.saveData(processedResult) { success in
                    // 回调地狱
                    if success {
                        self.showSuccessMessage()
                    } else {
                        self.showErrorMessage()
                    }
                }
            }
        }
    case .failure(let error):
        // 处理错误
        self.handleError(error)
    }
}

// 使用 async/await
func fetchData() async throws -> Data {
    let (data, _) = try await URLSession.shared.data(from: url)
    return data
}

// 调用异步方法
Task {
    do {
        let data = try await fetchData()
        let processedResult = try await processData(data)
        await updateUI(with: processedResult)
        
        if success {
            await showSuccessMessage()
        } else {
            await showErrorMessage()
        }
        // 代码扁平化，没有嵌套
    } catch {
        // 集中处理错误
        await handleError(error)
    }
}
```

#### 主要区别

1. **代码结构**：
   - 回调风格：嵌套层级深，导致"回调地狱"
   - async/await：扁平结构，顺序执行，更接近同步代码的逻辑流程

2. **错误处理**：
   - 回调风格：通过 Result 类型或多个参数传递错误，每个回调都需要单独处理错误
   - async/await：使用 Swift 的 try/catch 机制，可以集中处理错误

3. **并发控制**：
   - 回调风格：难以协调多个异步操作，需要复杂的状态管理
   - async/await：使用 async let 和 TaskGroup 简化并发控制

4. **可读性和可维护性**：
   - 回调风格：随着复杂性增加，代码可读性迅速下降
   - async/await：无论多复杂，代码结构保持清晰

### 与 GCD 和 Operation 对比

```swift
// 使用 GCD
func processImagesGCD(urls: [URL], completion: @escaping ([UIImage]?, Error?) -> Void) {
    let group = DispatchGroup()
    var images = [UIImage?](repeating: nil, count: urls.count)
    var finalError: Error?
    
    for (index, url) in urls.enumerated() {
        group.enter()
        
        URLSession.shared.dataTask(with: url) { data, response, error in
            defer { group.leave() }
            
            if let error = error {
                finalError = error
                return
            }
            
            guard let data = data, let image = UIImage(data: data) else {
                finalError = ImageError.invalidData
                return
            }
            
            images[index] = image
        }.resume()
    }
    
    group.notify(queue: .main) {
        if let error = finalError {
            completion(nil, error)
        } else {
            completion(images.compactMap { $0 }, nil)
        }
    }
}

// 使用 Operation
func processImagesOperation(urls: [URL], completion: @escaping ([UIImage]?, Error?) -> Void) {
    let operationQueue = OperationQueue()
    let completionOperation = BlockOperation {
        completion(images.compactMap { $0 }, finalError)
    }
    
    var images = [UIImage?](repeating: nil, count: urls.count)
    var finalError: Error?
    
    for (index, url) in urls.enumerated() {
        let operation = BlockOperation {
            do {
                let data = try Data(contentsOf: url)
                guard let image = UIImage(data: data) else {
                    throw ImageError.invalidData
                }
                images[index] = image
            } catch {
                finalError = error
            }
        }
        
        completionOperation.addDependency(operation)
        operationQueue.addOperation(operation)
    }
    
    OperationQueue.main.addOperation(completionOperation)
}

// 使用 async/await
func processImages(urls: [URL]) async throws -> [UIImage] {
    return try await withThrowingTaskGroup(of: (Int, UIImage).self) { group in
        var images = [UIImage?](repeating: nil, count: urls.count)
        
        for (index, url) in urls.enumerated() {
            group.addTask {
                let (data, _) = try await URLSession.shared.data(from: url)
                guard let image = UIImage(data: data) else {
                    throw ImageError.invalidData
                }
                return (index, image)
            }
        }
        
        for try await (index, image) in group {
            images[index] = image
        }
        
        return images.compactMap { $0 }
    }
}

// 调用
// GCD
processImagesGCD(urls: imageURLs) { images, error in
    if let error = error {
        handleError(error)
        return
    }
    
    if let images = images {
        updateGallery(with: images)
    }
}

// async/await
Task {
    do {
        let images = try await processImages(urls: imageURLs)
        await MainActor.run {
            updateGallery(with: images)
        }
    } catch {
        await MainActor.run {
            handleError(error)
        }
    }
}
```

#### 主要区别

1. **代码复杂性**：
   - GCD/Operation：需要手动管理线程、队列、锁、组和完成处理
   - async/await：系统自动管理线程和任务调度

2. **错误传播**：
   - GCD/Operation：错误处理复杂，需要额外的变量存储错误状态
   - async/await：自然的错误传播机制

3. **取消操作**：
   - GCD：难以实现干净的取消
   - Operation：支持取消但配置复杂
   - async/await：简单的取消机制，取消自动传播

4. **代码组织**：
   - GCD/Operation：回调分散，难以跟踪执行流程
   - async/await：顺序执行，易于理解和调试

### 与 Combine 对比

```swift
// Combine 方式
var cancellables = Set<AnyCancellable>()

URLSession.shared.dataTaskPublisher(for: url)
    .map(\.data)
    .decode(type: User.self, decoder: JSONDecoder())
    .receive(on: DispatchQueue.main)
    .sink(
        receiveCompletion: { completion in
            if case .failure(let error) = completion {
                self.handleError(error)
            }
        },
        receiveValue: { user in
            self.updateUI(with: user)
        }
    )
    .store(in: &cancellables)

// 复杂的 Combine 链
URLSession.shared.dataTaskPublisher(for: userURL)
    .map(\.data)
    .decode(type: User.self, decoder: JSONDecoder())
    .flatMap { user in
        URLSession.shared.dataTaskPublisher(for: URL(string: "https://api.example.com/users/\(user.id)/posts")!)
            .map(\.data)
            .decode(type: [Post].self, decoder: JSONDecoder())
            .map { (user, $0) }
    }
    .receive(on: DispatchQueue.main)
    .sink(
        receiveCompletion: { completion in
            if case .failure(let error) = completion {
                self.handleError(error)
            }
        },
        receiveValue: { user, posts in
            self.updateUI(with: user, posts: posts)
        }
    )
    .store(in: &cancellables)

// Async/await 方式
Task {
    do {
        let (userData, _) = try await URLSession.shared.data(from: userURL)
        let user = try JSONDecoder().decode(User.self, from: userData)
        
        let postsURL = URL(string: "https://api.example.com/users/\(user.id)/posts")!
        let (postsData, _) = try await URLSession.shared.data(from: postsURL)
        let posts = try JSONDecoder().decode([Post].self, from: postsData)
        
        await MainActor.run {
            self.updateUI(with: user, posts: posts)
        }
    } catch {
        await MainActor.run {
            self.handleError(error)
        }
    }
}
```

#### 主要区别

1. **编程范式**：
   - Combine：响应式和声明式，基于发布者-订阅者模式
   - async/await：命令式，更接近传统的同步编程模型

2. **学习曲线**：
   - Combine：操作符众多，有较陡的学习曲线
   - async/await：概念少，易于学习和使用

3. **使用场景**：
   - Combine：适合处理数据流、UI 事件和状态变化
   - async/await：适合单次异步操作和一系列有序的异步任务

4. **取消**：
   - Combine：需要管理 cancellable 对象
   - async/await：通过 Task 对象简单取消

5. **内存管理**：
   - Combine：需要小心管理订阅的生命周期
   - async/await：由 Swift 运行时自动管理

### 实际应用选择指南

- **使用 async/await 的场景**：
  - 一次性异步操作（如网络请求）
  - 顺序执行的异步任务
  - 需要结构化并发的场景
  - 处理异步数据流

- **使用 Combine 的场景**：
  - 响应式 UI 更新
  - 复杂的事件处理和转换
  - 需要组合多个事件源
  - SwiftUI 项目（与 SwiftUI 有很好的集成）

- **使用 GCD/Operation 的场景**：
  - 需要细粒度控制线程和队列
  - 兼容旧版 iOS 系统（iOS 15 之前）
  - 特定的并发模式

## 实际应用

本节将展示在实际 iOS 开发中如何应用 async/await 来解决常见问题。

### 网络请求

使用 async/await 实现网络层：

```swift
// 定义错误类型
enum NetworkError: Error {
    case invalidURL
    case requestFailed(statusCode: Int)
    case decodingFailed
    case unknown(Error)
    
    var localizedDescription: String {
        switch self {
        case .invalidURL:
            return "无效的 URL"
        case .requestFailed(let statusCode):
            return "请求失败，状态码: \(statusCode)"
        case .decodingFailed:
            return "数据解码失败"
        case .unknown(let error):
            return "未知错误: \(error.localizedDescription)"
        }
    }
}

// 网络服务 actor
actor NetworkService {
    // 基础 GET 请求
    func fetch(from urlString: String) async throws -> Data {
        guard let url = URL(string: urlString) else {
            throw NetworkError.invalidURL
        }
        
        let (data, response) = try await URLSession.shared.data(from: url)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NetworkError.unknown(URLError(.badServerResponse))
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            throw NetworkError.requestFailed(statusCode: httpResponse.statusCode)
        }
        
        return data
    }
    
    // 解码 JSON 数据
    func fetch<T: Decodable>(from urlString: String) async throws -> T {
        let data = try await fetch(from: urlString)
        
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw NetworkError.decodingFailed
        }
    }
    
    // 带有身份验证的请求
    func authenticatedFetch<T: Decodable>(from urlString: String, token: String) async throws -> T {
        guard let url = URL(string: urlString) else {
            throw NetworkError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NetworkError.unknown(URLError(.badServerResponse))
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            throw NetworkError.requestFailed(statusCode: httpResponse.statusCode)
        }
        
        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw NetworkError.decodingFailed
        }
    }
    
    // 上传数据
    func upload(data: Data, to urlString: String) async throws -> Data {
        guard let url = URL(string: urlString) else {
            throw NetworkError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let (responseData, response) = try await URLSession.shared.upload(for: request, from: data)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NetworkError.unknown(URLError(.badServerResponse))
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            throw NetworkError.requestFailed(statusCode: httpResponse.statusCode)
        }
        
        return responseData
    }
}

// 使用网络服务
class UserService {
    private let networkService = NetworkService()
    private let baseURL = "https://api.example.com"
    
    func fetchCurrentUser() async throws -> User {
        return try await networkService.fetch(from: "\(baseURL)/users/me")
    }
    
    func fetchUsers() async throws -> [User] {
        return try await networkService.fetch(from: "\(baseURL)/users")
    }
    
    func updateProfile(user: User) async throws -> User {
        let encoder = JSONEncoder()
        let userData = try encoder.encode(user)
        
        let responseData = try await networkService.upload(data: userData, to: "\(baseURL)/users/\(user.id)")
        return try JSONDecoder().decode(User.self, from: responseData)
    }
    
    // 带有重试逻辑的请求
    func fetchUserWithRetry(id: String, maxRetries: Int = 3) async throws -> User {
        var retries = 0
        var lastError: Error?
        
        while retries < maxRetries {
            do {
                return try await networkService.fetch(from: "\(baseURL)/users/\(id)")
            } catch {
                lastError = error
                retries += 1
                
                if retries < maxRetries {
                    // 指数退避
                    try await Task.sleep(nanoseconds: UInt64(pow(2.0, Double(retries)) * 1_000_000_000))
                    continue
                }
            }
        }
        
        throw lastError!
    }
}
```

### 图片加载和缓存

使用 async/await 实现高效的图片加载系统：

```swift
// 图片加载错误
enum ImageLoadingError: Error {
    case invalidURL
    case downloadFailed
    case invalidImageData
}

// 图片缓存 actor
actor ImageCache {
    // 内存缓存
    private var cache = NSCache<NSURL, UIImage>()
    
    // 从缓存获取图片
    func image(for url: URL) -> UIImage? {
        return cache.object(forKey: url as NSURL)
    }
    
    // 存储图片到缓存
    func setImage(_ image: UIImage, for url: URL) {
        cache.setObject(image, forKey: url as NSURL)
    }
    
    // 清除缓存
    func clearCache() {
        cache.removeAllObjects()
    }
    
    // 清除特定图片
    func removeImage(for url: URL) {
        cache.removeObject(forKey: url as NSURL)
    }
}

// 图片加载服务
actor ImageLoader {
    private let cache = ImageCache()
    
    // 加载图片，带缓存
    func loadImage(from urlString: String) async throws -> UIImage {
        guard let url = URL(string: urlString) else {
            throw ImageLoadingError.invalidURL
        }
        
        // 检查缓存
        if let cachedImage = await cache.image(for: url) {
            return cachedImage
        }
        
        // 下载图片
        let (data, response) = try await URLSession.shared.data(from: url)
        
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw ImageLoadingError.downloadFailed
        }
        
        guard let image = UIImage(data: data) else {
            throw ImageLoadingError.invalidImageData
        }
        
        // 存入缓存
        await cache.setImage(image, for: url)
        return image
    }
    
    // 并行加载多张图片
    func loadImages(from urlStrings: [String]) async throws -> [UIImage] {
        try await withThrowingTaskGroup(of: (Int, UIImage).self) { group in
            var images = [UIImage?](repeating: nil, count: urlStrings.count)
            
            // 添加所有下载任务
            for (index, urlString) in urlStrings.enumerated() {
                group.addTask {
                    let image = try await self.loadImage(from: urlString)
                    return (index, image)
                }
            }
            
            // 收集结果
            for try await (index, image) in group {
                images[index] = image
            }
            
            return images.compactMap { $0 }
        }
    }
    
    // 加载缩略图
    func loadThumbnail(from urlString: String, size: CGSize) async throws -> UIImage {
        let image = try await loadImage(from: urlString)
        
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let renderer = UIGraphicsImageRenderer(size: size)
                let thumbnail = renderer.image { _ in
                    image.draw(in: CGRect(origin: .zero, size: size))
                }
                continuation.resume(returning: thumbnail)
            }
        }
    }
}

// 在 SwiftUI 中使用
struct AsyncImageView: View {
    let url: String
    @State private var image: UIImage?
    @State private var isLoading = true
    @State private var error: Error?
    
    private let imageLoader = ImageLoader()
    
    var body: some View {
        Group {
            if let image = image {
                Image(uiImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fit)
            } else if isLoading {
                ProgressView()
                    .progressViewStyle(CircularProgressViewStyle())
            } else if error != nil {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundColor(.red)
                    .overlay(
                        Text("加载失败")
                            .font(.caption)
                            .foregroundColor(.red)
                            .offset(y: 30)
                    )
            }
        }
        .task {
            do {
                isLoading = true
                image = try await imageLoader.loadImage(from: url)
                isLoading = false
            } catch {
                self.error = error
                isLoading = false
            }
        }
    }
}
```

### 本地数据库操作

结合 CoreData 和 async/await 进行数据库操作：

```swift
// 数据库错误
enum DatabaseError: Error {
    case fetchFailed
    case saveFailed
    case deleteFailed
    case entityNotFound
}

// 数据库服务
actor DatabaseService {
    private let container: NSPersistentContainer
    private let backgroundContext: NSManagedObjectContext
    
    init(modelName: String) {
        container = NSPersistentContainer(name: modelName)
        
        container.loadPersistentStores { _, error in
            if let error = error {
                fatalError("加载 Core Data 存储失败: \(error)")
            }
        }
        
        // 创建后台上下文
        backgroundContext = container.newBackgroundContext()
        backgroundContext.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
    }
    
    // 获取主上下文
    func viewContext() -> NSManagedObjectContext {
        return container.viewContext
    }
    
    // 获取所有实体
    func fetchEntities<T: NSManagedObject>(_ entityType: T.Type, predicate: NSPredicate? = nil, sortDescriptors: [NSSortDescriptor]? = nil) async throws -> [T] {
        return try await withCheckedThrowingContinuation { continuation in
            backgroundContext.perform {
                let fetchRequest = NSFetchRequest<T>(entityName: String(describing: entityType))
                fetchRequest.predicate = predicate
                fetchRequest.sortDescriptors = sortDescriptors
                
                do {
                    let results = try self.backgroundContext.fetch(fetchRequest)
                    continuation.resume(returning: results)
                } catch {
                    continuation.resume(throwing: DatabaseError.fetchFailed)
                }
            }
        }
    }
    
    // 获取单个实体
    func fetchEntity<T: NSManagedObject>(_ entityType: T.Type, id: NSManagedObjectID) async throws -> T {
        return try await withCheckedThrowingContinuation { continuation in
            backgroundContext.perform {
                do {
                    guard let entity = try self.backgroundContext.existingObject(with: id) as? T else {
                        continuation.resume(throwing: DatabaseError.entityNotFound)
                        return
                    }
                    
                    continuation.resume(returning: entity)
                } catch {
                    continuation.resume(throwing: DatabaseError.fetchFailed)
                }
            }
        }
    }
    
    // 保存实体
    func saveContext() async throws {
        return try await withCheckedThrowingContinuation { continuation in
            backgroundContext.perform {
                do {
                    if self.backgroundContext.hasChanges {
                        try self.backgroundContext.save()
                    }
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: DatabaseError.saveFailed)
                }
            }
        }
    }
    
    // 创建实体
    func createEntity<T: NSManagedObject>(_ entityType: T.Type) async throws -> T {
        return await withCheckedContinuation { continuation in
            backgroundContext.perform {
                let entity = NSEntityDescription.insertNewObject(forEntityName: String(describing: entityType), into: self.backgroundContext) as! T
                continuation.resume(returning: entity)
            }
        }
    }
    
    // 删除实体
    func deleteEntity<T: NSManagedObject>(_ entity: T) async throws {
        return try await withCheckedThrowingContinuation { continuation in
            backgroundContext.perform {
                self.backgroundContext.delete(entity)
                
                do {
                    try self.backgroundContext.save()
                    continuation.resume()
                } catch {
                    continuation.resume(throwing: DatabaseError.deleteFailed)
                }
            }
        }
    }
    
    // 执行批量更新
    func batchUpdate(entityName: String, predicate: NSPredicate?, propertiesToUpdate: [String: Any]) async throws -> Int {
        return try await withCheckedThrowingContinuation { continuation in
            backgroundContext.perform {
                let batchUpdateRequest = NSBatchUpdateRequest(entityName: entityName)
                batchUpdateRequest.predicate = predicate
                batchUpdateRequest.propertiesToUpdate = propertiesToUpdate
                batchUpdateRequest.resultType = .updatedObjectIDsResultType
                
                do {
                    let result = try self.backgroundContext.execute(batchUpdateRequest) as! NSBatchUpdateResult
                    let objectIDs = result.result as! [NSManagedObjectID]
                    
                    // 通知主上下文更新
                    let changes = [NSUpdatedObjectsKey: objectIDs]
                    NSManagedObjectContext.mergeChanges(fromRemoteContextSave: changes, into: [self.container.viewContext])
                    
                    continuation.resume(returning: objectIDs.count)
                } catch {
                    continuation.resume(throwing: DatabaseError.saveFailed)
                }
            }
        }
    }
}

// 用户服务
class UserDatabaseService {
    private let dbService: DatabaseService
    
    init() {
        dbService = DatabaseService(modelName: "MyAppModel")
    }
    
    // 获取所有用户
    func fetchAllUsers() async throws -> [UserEntity] {
        let sortDescriptor = NSSortDescriptor(key: "name", ascending: true)
        return try await dbService.fetchEntities(UserEntity.self, sortDescriptors: [sortDescriptor])
    }
    
    // 根据 ID 获取用户
    func fetchUser(with id: String) async throws -> UserEntity? {
        let predicate = NSPredicate(format: "id == %@", id)
        let users = try await dbService.fetchEntities(UserEntity.self, predicate: predicate)
        return users.first
    }
    
    // 创建新用户
    func createUser(id: String, name: String, email: String) async throws -> UserEntity {
        let user = try await dbService.createEntity(UserEntity.self)
        user.id = id
        user.name = name
        user.email = email
        try await dbService.saveContext()
        return user
    }
    
    // 更新用户
    func updateUser(id: String, name: String?, email: String?) async throws {
        guard let user = try await fetchUser(with: id) else {
            throw DatabaseError.entityNotFound
        }
        
        if let name = name {
            user.name = name
        }
        
        if let email = email {
            user.email = email
        }
        
        try await dbService.saveContext()
    }
    
    // 删除用户
    func deleteUser(with id: String) async throws {
        guard let user = try await fetchUser(with: id) else {
            throw DatabaseError.entityNotFound
        }
        
        try await dbService.deleteEntity(user)
    }
    
    // 批量更新用户状态
    func updateAllUsersStatus(isActive: Bool) async throws -> Int {
        let propertiesToUpdate = ["isActive": isActive]
        return try await dbService.batchUpdate(entityName: "UserEntity", predicate: nil, propertiesToUpdate: propertiesToUpdate)
    }
}
```

### 异步 API 集成案例

使用 async/await 实现一个完整的数据同步系统：

```swift
// 同步服务
actor SyncService {
    private let networkService = NetworkService()
    private let databaseService: DatabaseService
    private let baseURL = "https://api.example.com"
    
    private var isSyncing = false
    private var lastSyncDate: Date?
    
    init(databaseService: DatabaseService) {
        self.databaseService = databaseService
    }
    
    // 检查是否需要同步
    func shouldSync(forcedSync: Bool = false) -> Bool {
        guard !isSyncing else { return false }
        
        if forcedSync { return true }
        
        // 检查上次同步时间，默认每小时同步一次
        if let lastSync = lastSyncDate, Date().timeIntervalSince(lastSync) < 3600 {
            return false
        }
        
        return true
    }
    
    // 开始同步
    func startSync(forcedSync: Bool = false) async throws -> SyncResult {
        guard shouldSync(forcedSync: forcedSync) else {
            return SyncResult(success: true, message: "不需要同步", itemsSynced: 0)
        }
        
        isSyncing = true
        
        do {
            let result = try await performSync()
            lastSyncDate = Date()
            isSyncing = false
            return result
        } catch {
            isSyncing = false
            throw error
        }
    }
    
    // 执行同步
    private func performSync() async throws -> SyncResult {
        // 1. 获取上次同步时间
        let timestamp = lastSyncDate?.timeIntervalSince1970 ?? 0
        
        // 2. 从服务器获取更新
        let updates: [RemoteItem] = try await networkService.fetch(from: "\(baseURL)/updates?since=\(timestamp)")
        
        guard !updates.isEmpty else {
            return SyncResult(success: true, message: "没有需要同步的数据", itemsSynced: 0)
        }
        
        // 3. 本地处理
        var syncedCount = 0
        
        try await withThrowingTaskGroup(of: Bool.self) { group in
            for update in updates {
                group.addTask {
                    try await self.processUpdate(update)
                    return true
                }
            }
            
            for try await success in group {
                if success {
                    syncedCount += 1
                }
            }
        }
        
        // 4. 发送本地更改到服务器
        let localChanges = try await fetchLocalChanges()
        
        if !localChanges.isEmpty {
            try await uploadLocalChanges(localChanges)
        }
        
        return SyncResult(
            success: true,
            message: "同步完成，同步了 \(syncedCount) 项，上传了 \(localChanges.count) 项本地更改",
            itemsSynced: syncedCount + localChanges.count
        )
    }
    
    // 处理单个更新
    private func processUpdate(_ update: RemoteItem) async throws -> Bool {
        switch update.action {
        case .create, .update:
            try await createOrUpdateLocalItem(update)
        case .delete:
            try await deleteLocalItem(update.id)
        }
        
        return true
    }
    
    // 本地数据库操作
    private func createOrUpdateLocalItem(_ item: RemoteItem) async throws {
        // 实现数据库创建或更新逻辑
    }
    
    private func deleteLocalItem(_ id: String) async throws {
        // 实现数据库删除逻辑
    }
    
    private func fetchLocalChanges() async throws -> [LocalChange] {
        // 获取本地未同步的更改
        return []
    }
    
    private func uploadLocalChanges(_ changes: [LocalChange]) async throws {
        // 上传本地更改到服务器
    }
}

// 同步结果模型
struct SyncResult {
    let success: Bool
    let message: String
    let itemsSynced: Int
    let timestamp = Date()
}

// 在视图控制器中使用
class SyncViewController: UIViewController {
    private let syncService: SyncService
    private var syncTask: Task<Void, Never>?
    
    @IBOutlet weak var syncButton: UIButton!
    @IBOutlet weak var statusLabel: UILabel!
    @IBOutlet weak var progressView: UIProgressView!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    @IBAction func syncButtonTapped(_ sender: Any) {
        startSync(forced: true)
    }
    
    private func startSync(forced: Bool = false) {
        // 取消之前的同步任务
        syncTask?.cancel()
        
        // 创建新的同步任务
        syncTask = Task {
            do {
                updateUI(status: "正在同步...", isLoading: true)
                
                let result = try await syncService.startSync(forcedSync: forced)
                
                await MainActor.run {
                    updateUI(status: result.message, isLoading: false)
                    showToast(message: "同步成功")
                }
            } catch {
                await MainActor.run {
                    updateUI(status: "同步失败: \(error.localizedDescription)", isLoading: false)
                    showToast(message: "同步失败")
                }
            }
        }
    }
    
    private func updateUI(status: String, isLoading: Bool) {
        statusLabel.text = status
        syncButton.isEnabled = !isLoading
        progressView.isHidden = !isLoading
    }
    
    private func showToast(message: String) {
        // 显示提示消息
    }
    
    deinit {
        syncTask?.cancel()
    }
}
``` 
``` 