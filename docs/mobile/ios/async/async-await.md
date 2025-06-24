# 异步/等待

Swift 5.5 引入的异步/等待（async/await）特性为异步编程提供了一种更简洁、更直观的方式。本文档将介绍 async/await 的基本概念、使用方法和最佳实践。

## 目录

- [基本概念](#基本概念)
- [异步函数](#异步函数)
- [结构化并发](#结构化并发)
- [任务管理](#任务管理)
- [异步序列](#异步序列)
- [与传统方法对比](#与传统方法对比)
- [实际应用](#实际应用)
- [最佳实践](#最佳实践)

## 基本概念

异步/等待提供了一种编写异步代码的方式，使其看起来像同步代码，同时保持非阻塞特性。主要概念包括：

- **异步函数**：使用 `async` 关键字标记的函数，可以在执行过程中暂停
- **等待表达式**：使用 `await` 关键字调用异步函数，标记可能暂停的点
- **结构化并发**：使用 `Task` 和 `TaskGroup` 管理并发执行的任务
- **非阻塞操作**：异步函数暂停时不会阻塞线程，允许其他工作继续进行

## 异步函数

### 定义异步函数

```swift
// 基本异步函数
func fetchUserData() async throws -> User {
    let url = URL(string: "https://api.example.com/users/1")!
    let (data, _) = try await URLSession.shared.data(from: url)
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
```

### 调用异步函数

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

// 在非异步上下文中调用
func buttonTapped() {
    Task {
        do {
            let user = try await fetchUserData()
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
```

## 结构化并发

结构化并发允许同时运行多个异步操作，并确保它们都在返回之前完成。

### async let 绑定

```swift
func loadDashboard() async throws -> Dashboard {
    // 并行执行多个异步操作
    async let user = fetchUser()
    async let posts = fetchPosts()
    async let notifications = fetchNotifications()
    
    // 等待所有操作完成
    return try Dashboard(
        user: await user,
        posts: await posts,
        notifications: await notifications
    )
}
```

### TaskGroup

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
```

## 任务管理

### 创建和取消任务

```swift
// 创建后台任务
let task = Task.detached {
    return try await fetchLargeData()
}

// 检查任务是否取消
func processData() async throws -> Data {
    for i in 1...100 {
        // 检查是否请求取消
        try Task.checkCancellation()
        
        // 或使用 isCancelled 属性
        if Task.isCancelled {
            throw CancellationError()
        }
        
        // 处理数据
        try await processChunk(i)
    }
    
    return finalData
}

// 取消任务
task.cancel()

// 等待任务完成并获取结果
do {
    let result = try await task.value
    print("任务完成: \(result)")
} catch is CancellationError {
    print("任务已取消")
} catch {
    print("任务失败: \(error)")
}
```

### 任务优先级

```swift
// 使用不同优先级创建任务
let highPriorityTask = Task(priority: .high) {
    try await fetchCriticalData()
}

let backgroundTask = Task(priority: .background) {
    try await preprocessLargeDataset()
}

// 继承当前任务的优先级
let inheritedPriorityTask = Task {
    // 这个任务继承调用者的优先级
    try await fetchData()
}
```

## 异步序列

异步序列允许迭代一系列异步产生的值。

### 基本用法

```swift
// 定义异步序列
struct NumberGenerator: AsyncSequence {
    typealias Element = Int
    
    let max: Int
    
    struct AsyncIterator: AsyncIteratorProtocol {
        var current = 0
        let max: Int
        
        mutating func next() async throws -> Int? {
            guard current < max else {
                return nil
            }
            
            // 模拟异步工作
            try await Task.sleep(nanoseconds: 1_000_000_000)
            
            current += 1
            return current
        }
    }
    
    func makeAsyncIterator() -> AsyncIterator {
        return AsyncIterator(max: max)
    }
}

// 使用异步序列
func processNumbers() async throws {
    let numbers = NumberGenerator(max: 5)
    
    for try await number in numbers {
        print("处理数字: \(number)")
    }
    
    print("所有数字处理完成")
}
```

### 使用 AsyncStream

```swift
// 创建 AsyncStream
func streamEvents() -> AsyncStream<Event> {
    return AsyncStream { continuation in
        let eventSource = EventSource()
        
        // 设置回调
        eventSource.onEvent = { event in
            continuation.yield(event)
        }
        
        eventSource.onComplete = {
            continuation.finish()
        }
        
        // 开始接收事件
        eventSource.start()
        
        // 设置取消操作
        continuation.onTermination = { @Sendable _ in
            eventSource.stop()
        }
    }
}

// 使用 AsyncStream
func monitorEvents() async {
    let eventStream = streamEvents()
    
    for await event in eventStream {
        processEvent(event)
    }
    
    print("事件流结束")
}
```

## 与传统方法对比

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
            }
        }
    case .failure(let error):
        // 处理错误
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
        // 代码扁平化，没有嵌套
    } catch {
        // 集中处理错误
    }
}
```

### 与 Combine 对比

```swift
// Combine 方式
let cancellable = URLSession.shared.dataTaskPublisher(for: url)
    .map(\.data)
    .decode(type: User.self, decoder: JSONDecoder())
    .receive(on: RunLoop.main)
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

// Async/await 方式
Task {
    do {
        let (data, _) = try await URLSession.shared.data(from: url)
        let user = try JSONDecoder().decode(User.self, from: data)
        await MainActor.run {
            self.updateUI(with: user)
        }
    } catch {
        await MainActor.run {
            self.handleError(error)
        }
    }
}
```

## 实际应用

### 网络请求

```swift
// 网络请求包装器
actor NetworkService {
    func fetch<T: Decodable>(from endpoint: String) async throws -> T {
        guard let url = URL(string: "https://api.example.com/\(endpoint)") else {
            throw URLError(.badURL)
        }
        
        let (data, response) = try await URLSession.shared.data(from: url)
        
        guard let httpResponse = response as? HTTPURLResponse,
              (200...299).contains(httpResponse.statusCode) else {
            throw APIError.invalidResponse
        }
        
        return try JSONDecoder().decode(T.self, from: data)
    }
}

// 使用
let network = NetworkService()

Task {
    do {
        let user: User = try await network.fetch(from: "users/1")
        let posts: [Post] = try await network.fetch(from: "users/1/posts")
        
        await MainActor.run {
            updateUI(user: user, posts: posts)
        }
    } catch {
        print("Error: \(error)")
    }
}
```

### 图片加载

```swift
actor ImageLoader {
    private var cache = [URL: UIImage]()
    
    func loadImage(from url: URL) async throws -> UIImage {
        // 检查缓存
        if let cachedImage = cache[url] {
            return cachedImage
        }
        
        // 下载图片
        let (data, _) = try await URLSession.shared.data(from: url)
        
        guard let image = UIImage(data: data) else {
            throw ImageError.invalidData
        }
        
        // 存入缓存
        cache[url] = image
        return image
    }
}

// 在 SwiftUI 中使用
struct RemoteImage: View {
    let url: URL
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
            } else if error != nil {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundColor(.red)
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

### 数据库操作

```swift
actor DatabaseManager {
    private let dbQueue: DatabaseQueue
    
    init() throws {
        dbQueue = try DatabaseQueue(path: "path/to/database.sqlite")
    }
    
    func fetchUsers() async throws -> [User] {
        try await withCheckedThrowingContinuation { continuation in
            do {
                let users = try dbQueue.read { db in
                    try User.fetchAll(db)
                }
                continuation.resume(returning: users)
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
    
    func saveUser(_ user: User) async throws {
        try await withCheckedThrowingContinuation { continuation in
            do {
                try dbQueue.write { db in
                    try user.save(db)
                }
                continuation.resume()
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}
```

## 最佳实践

### 使用 MainActor

```swift
// 在类上使用 MainActor
@MainActor
class ViewModel {
    // 所有方法默认在主线程上运行
    func updateUI() {
        // 安全地更新 UI
    }
    
    // 显式标记后台任务
    nonisolated func processData() async throws -> Data {
        // 在后台执行
        return try await fetchData()
    }
}

// 在单个方法上使用 MainActor
class DataManager {
    func fetchData() async throws -> Data {
        // 在任何线程上执行
        return try await networkRequest()
    }
    
    @MainActor
    func updateUI(with data: Data) {
        // 确保在主线程上执行
    }
}
```

### 错误处理

```swift
// 定义具体错误类型
enum NetworkError: Error {
    case invalidURL
    case serverError(statusCode: Int)
    case decodingError
    case connectionError
    
    var localizedDescription: String {
        switch self {
        case .invalidURL:
            return "无效的 URL"
        case .serverError(let statusCode):
            return "服务器错误，状态码: \(statusCode)"
        case .decodingError:
            return "数据解码失败"
        case .connectionError:
            return "网络连接错误"
        }
    }
}

// 集中处理错误
func fetchAndProcessData() async {
    do {
        let data = try await fetchData()
        let processedData = try await processData(data)
        await MainActor.run {
            updateUI(with: processedData)
        }
    } catch let error as NetworkError {
        await handleNetworkError(error)
    } catch let error as DecodingError {
        await handleDecodingError(error)
    } catch {
        await handleUnknownError(error)
    }
}
```

### 超时处理

```swift
// 为异步操作添加超时
func withTimeout<T>(seconds: Double, operation: @escaping () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        // 添加主操作
        group.addTask {
            try await operation()
        }
        
        // 添加超时任务
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw TimeoutError()
        }
        
        // 返回首先完成的任务结果
        let result = try await group.next()!
        
        // 取消其他任务
        group.cancelAll()
        
        return result
    }
}

// 使用超时
do {
    let result = try await withTimeout(seconds: 5.0) {
        try await longRunningOperation()
    }
    processResult(result)
} catch is TimeoutError {
    handleTimeout()
} catch {
    handleError(error)
}
```

### 管理并发任务

```swift
// 限制并发数量
func downloadImages(urls: [URL], maxConcurrent: Int) async throws -> [UIImage] {
    return try await withThrowingTaskGroup(of: (Int, UIImage).self) { group in
        var images = [UIImage?](repeating: nil, count: urls.count)
        var added = 0
        var completed = 0
        
        // 初始添加任务，不超过最大并发数
        while added < urls.count && added < maxConcurrent {
            let index = added
            group.addTask {
                let image = try await downloadImage(from: urls[index])
                return (index, image)
            }
            added += 1
        }
        
        // 处理结果并动态添加新任务
        while let result = try await group.next() {
            let (index, image) = result
            images[index] = image
            completed += 1
            
            // 如果还有未处理的 URL，添加新任务
            if added < urls.count {
                let index = added
                group.addTask {
                    let image = try await downloadImage(from: urls[index])
                    return (index, image)
                }
                added += 1
            }
            
            // 如果所有任务都完成，退出循环
            if completed == urls.count {
                break
            }
        }
        
        return images.compactMap { $0 }
    }
}
``` 