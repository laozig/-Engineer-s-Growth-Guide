# URLSession

URLSession 是 iOS 中进行网络请求的核心 API，它提供了一套完整的工具来执行 HTTP 请求、上传和下载文件。本文档将介绍 URLSession 的基本用法和常见场景。

## 目录

- [基本概念](#基本概念)
- [会话类型](#会话类型)
- [基本请求](#基本请求)
- [数据任务](#数据任务)
- [下载任务](#下载任务)
- [上传任务](#上传任务)
- [背景传输](#背景传输)
- [取消和恢复](#取消和恢复)
- [URLSession 配置](#urlsession-配置)
- [最佳实践](#最佳实践)

## 基本概念

URLSession 架构包括几个关键组件：

- **URLSession**：表示与服务器的会话，管理一组相关的网络任务
- **URLSessionConfiguration**：配置会话的行为，如超时、缓存策略等
- **URLSessionTask**：代表单个网络任务，如数据请求、文件下载或上传
- **URLSessionDelegate**：处理会话级别的事件，如认证挑战
- **URLSessionTaskDelegate**：处理任务级别的事件，如进度监控

## 会话类型

URLSession 有三种主要类型，通过不同的 URLSessionConfiguration 创建：

```swift
// 1. 默认会话：使用全局缓存、Cookie 和凭证存储
let defaultSession = URLSession(configuration: .default)

// 2. 临时会话：不使用持久化存储，适合私有浏览
let ephemeralSession = URLSession(configuration: .ephemeral)

// 3. 后台会话：允许在应用挂起时继续传输
let backgroundSession = URLSession(configuration: .background(withIdentifier: "com.example.app.background"))
```

## 基本请求

### 创建和发送基本请求

```swift
// 创建 URL
guard let url = URL(string: "https://api.example.com/data") else {
    print("无效的 URL")
    return
}

// 创建请求
var request = URLRequest(url: url)
request.httpMethod = "GET" // 默认是 GET
request.timeoutInterval = 30 // 30 秒超时

// 添加请求头
request.addValue("application/json", forHTTPHeaderField: "Content-Type")
request.addValue("Bearer token123", forHTTPHeaderField: "Authorization")

// 创建任务并发送请求
let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
    // 检查错误
    if let error = error {
        print("请求失败: \(error)")
        return
    }
    
    // 检查 HTTP 响应状态码
    guard let httpResponse = response as? HTTPURLResponse,
          (200...299).contains(httpResponse.statusCode) else {
        print("服务器错误")
        return
    }
    
    // 处理响应数据
    if let data = data {
        // 将数据转换为字符串（示例）
        if let responseString = String(data: data, encoding: .utf8) {
            print("收到响应: \(responseString)")
        }
        
        // 或解析 JSON
        do {
            let json = try JSONSerialization.jsonObject(with: data)
            print("JSON 数据: \(json)")
        } catch {
            print("JSON 解析失败: \(error)")
        }
    }
}

// 启动任务
task.resume()
```

### 简化版 GET 请求

```swift
URLSession.shared.dataTask(with: URL(string: "https://api.example.com/data")!) { (data, response, error) in
    // 处理响应
    if let data = data {
        print("收到 \(data.count) 字节的数据")
    }
}.resume()
```

## 数据任务

数据任务用于发送和接收 NSData 对象形式的数据，适合小到中等规模的请求和响应。

### POST 请求示例

```swift
guard let url = URL(string: "https://api.example.com/submit") else { return }

var request = URLRequest(url: url)
request.httpMethod = "POST"
request.addValue("application/json", forHTTPHeaderField: "Content-Type")

// 请求体
let parameters: [String: Any] = [
    "name": "张三",
    "email": "zhangsan@example.com",
    "age": 30
]

do {
    // 将字典转换为 JSON 数据
    request.httpBody = try JSONSerialization.data(withJSONObject: parameters)
    
    // 创建任务
    let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
        if let error = error {
            print("请求失败: \(error)")
            return
        }
        
        if let data = data, let httpResponse = response as? HTTPURLResponse {
            print("状态码: \(httpResponse.statusCode)")
            
            // 处理响应
            if let responseString = String(data: data, encoding: .utf8) {
                print("响应: \(responseString)")
            }
        }
    }
    
    task.resume()
} catch {
    print("创建请求体失败: \(error)")
}
```

### 使用 Codable 进行 JSON 处理

```swift
// 定义符合 Codable 的模型
struct User: Codable {
    let id: Int
    let name: String
    let email: String
}

// 请求数据
func fetchUser(id: Int, completion: @escaping (Result<User, Error>) -> Void) {
    let url = URL(string: "https://api.example.com/users/\(id)")!
    
    URLSession.shared.dataTask(with: url) { (data, response, error) in
        // 检查错误
        if let error = error {
            completion(.failure(error))
            return
        }
        
        // 检查数据
        guard let data = data else {
            completion(.failure(NSError(domain: "NoDataError", code: -1, userInfo: nil)))
            return
        }
        
        // 解码 JSON
        do {
            let decoder = JSONDecoder()
            let user = try decoder.decode(User.self, from: data)
            completion(.success(user))
        } catch {
            completion(.failure(error))
        }
    }.resume()
}

// 使用
fetchUser(id: 1) { result in
    switch result {
    case .success(let user):
        print("获取用户成功: \(user.name)")
    case .failure(let error):
        print("获取用户失败: \(error)")
    }
}
```

## 下载任务

下载任务用于获取文件，并支持后台下载和恢复。

### 基本下载

```swift
// 文件 URL
let url = URL(string: "https://example.com/largefile.zip")!

// 目标路径
let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
let destinationUrl = documentsPath.appendingPathComponent("downloaded-file.zip")

// 创建下载任务
let downloadTask = URLSession.shared.downloadTask(with: url) { (tempFileURL, response, error) in
    guard let tempFileURL = tempFileURL, error == nil else {
        print("下载失败: \(error?.localizedDescription ?? "未知错误")")
        return
    }
    
    do {
        // 检查目标位置是否已有文件
        if FileManager.default.fileExists(atPath: destinationUrl.path) {
            try FileManager.default.removeItem(at: destinationUrl)
        }
        
        // 将临时文件移动到目标位置
        try FileManager.default.moveItem(at: tempFileURL, to: destinationUrl)
        
        print("文件下载完成，保存到: \(destinationUrl.path)")
    } catch {
        print("文件移动失败: \(error)")
    }
}

// 开始下载
downloadTask.resume()
```

### 带进度的下载

```swift
class DownloadManager: NSObject, URLSessionDownloadDelegate {
    var downloadTask: URLSessionDownloadTask?
    var session: URLSession!
    var progressHandler: ((Float) -> Void)?
    var completionHandler: ((URL?, Error?) -> Void)?
    
    override init() {
        super.init()
        session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
    }
    
    func download(from url: URL, progress: @escaping (Float) -> Void, completion: @escaping (URL?, Error?) -> Void) {
        progressHandler = progress
        completionHandler = completion
        
        downloadTask = session.downloadTask(with: url)
        downloadTask?.resume()
    }
    
    // 进度更新
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
        let progress = Float(totalBytesWritten) / Float(totalBytesExpectedToWrite)
        DispatchQueue.main.async {
            self.progressHandler?(progress)
        }
    }
    
    // 下载完成
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileName = downloadTask.originalRequest?.url?.lastPathComponent ?? "downloaded_file"
        let destinationUrl = documentsPath.appendingPathComponent(fileName)
        
        do {
            if FileManager.default.fileExists(atPath: destinationUrl.path) {
                try FileManager.default.removeItem(at: destinationUrl)
            }
            try FileManager.default.moveItem(at: location, to: destinationUrl)
            
            DispatchQueue.main.async {
                self.completionHandler?(destinationUrl, nil)
            }
        } catch {
            DispatchQueue.main.async {
                self.completionHandler?(nil, error)
            }
        }
    }
    
    // 任务完成（成功或失败）
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if let error = error {
            DispatchQueue.main.async {
                self.completionHandler?(nil, error)
            }
        }
    }
}

// 使用
let downloader = DownloadManager()
let url = URL(string: "https://example.com/largefile.zip")!

downloader.download(from: url, progress: { progress in
    print("下载进度: \(progress * 100)%")
}) { (fileURL, error) in
    if let error = error {
        print("下载失败: \(error)")
    } else if let fileURL = fileURL {
        print("下载完成，保存到: \(fileURL.path)")
    }
}
```

## 上传任务

上传任务用于将数据或文件发送到服务器。

### 上传数据

```swift
guard let url = URL(string: "https://api.example.com/upload") else { return }

var request = URLRequest(url: url)
request.httpMethod = "POST"
request.addValue("application/json", forHTTPHeaderField: "Content-Type")

// 要上传的数据
let parameters: [String: Any] = ["name": "文件名", "description": "文件描述"]
let jsonData = try? JSONSerialization.data(withJSONObject: parameters)

// 创建上传任务
let uploadTask = URLSession.shared.uploadTask(with: request, from: jsonData!) { (data, response, error) in
    if let error = error {
        print("上传失败: \(error)")
        return
    }
    
    if let data = data, let responseString = String(data: data, encoding: .utf8) {
        print("上传成功，服务器响应: \(responseString)")
    }
}

uploadTask.resume()
```

### 上传文件

```swift
guard let url = URL(string: "https://api.example.com/upload") else { return }

var request = URLRequest(url: url)
request.httpMethod = "POST"

// 设置 multipart/form-data 边界
let boundary = "Boundary-\(UUID().uuidString)"
request.addValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")

// 要上传的文件 URL
let fileURL = documentsPath.appendingPathComponent("image.jpg")

// 创建 multipart/form-data 体
var body = Data()

// 添加表单字段
let fields = ["name": "我的图片", "description": "这是一张美丽的图片"]
for (key, value) in fields {
    body.append("--\(boundary)\r\n".data(using: .utf8)!)
    body.append("Content-Disposition: form-data; name=\"\(key)\"\r\n\r\n".data(using: .utf8)!)
    body.append("\(value)\r\n".data(using: .utf8)!)
}

// 添加文件数据
if let fileData = try? Data(contentsOf: fileURL) {
    let fileName = fileURL.lastPathComponent
    let mimeType = "image/jpeg" // 根据文件类型设置正确的 MIME 类型
    
    body.append("--\(boundary)\r\n".data(using: .utf8)!)
    body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n".data(using: .utf8)!)
    body.append("Content-Type: \(mimeType)\r\n\r\n".data(using: .utf8)!)
    body.append(fileData)
    body.append("\r\n".data(using: .utf8)!)
}

// 添加结束边界
body.append("--\(boundary)--\r\n".data(using: .utf8)!)

// 创建上传任务
let uploadTask = URLSession.shared.uploadTask(with: request, from: body) { (data, response, error) in
    if let error = error {
        print("上传失败: \(error)")
        return
    }
    
    guard let httpResponse = response as? HTTPURLResponse else {
        print("无效的响应")
        return
    }
    
    print("上传状态码: \(httpResponse.statusCode)")
    
    if let data = data, let responseString = String(data: data, encoding: .utf8) {
        print("服务器响应: \(responseString)")
    }
}

uploadTask.resume()
```

### 直接从文件上传

```swift
guard let url = URL(string: "https://api.example.com/upload") else { return }

var request = URLRequest(url: url)
request.httpMethod = "POST"
request.addValue("application/octet-stream", forHTTPHeaderField: "Content-Type")

// 要上传的文件 URL
let fileURL = documentsPath.appendingPathComponent("document.pdf")

// 从文件创建上传任务
let uploadTask = URLSession.shared.uploadTask(with: request, fromFile: fileURL) { (data, response, error) in
    if let error = error {
        print("上传失败: \(error)")
        return
    }
    
    if let httpResponse = response as? HTTPURLResponse {
        print("上传状态码: \(httpResponse.statusCode)")
    }
}

uploadTask.resume()
```

## 背景传输

背景传输允许在应用挂起或终止时继续进行网络操作。

### 配置背景会话

```swift
class BackgroundDownloadManager: NSObject, URLSessionDownloadDelegate {
    static let shared = BackgroundDownloadManager()
    var backgroundCompletionHandler: (() -> Void)?
    
    lazy var session: URLSession = {
        let config = URLSessionConfiguration.background(withIdentifier: "com.example.app.backgroundSession")
        config.isDiscretionary = true // 系统决定最佳传输时机
        config.sessionSendsLaunchEvents = true // 下载完成时启动应用
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()
    
    // 开始后台下载
    func startDownload(from url: URL) {
        let task = session.downloadTask(with: url)
        task.earliestBeginDate = Date(timeIntervalSinceNow: 60) // 1分钟后开始
        task.countOfBytesClientExpectsToSend = 1024 // 预期发送的字节数
        task.countOfBytesClientExpectsToReceive = 1024 * 1024 // 预期接收的字节数
        task.resume()
    }
    
    // 下载完成
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        // 保存下载的文件
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let fileName = downloadTask.originalRequest?.url?.lastPathComponent ?? "background_download"
        let destinationUrl = documentsPath.appendingPathComponent(fileName)
        
        do {
            if FileManager.default.fileExists(atPath: destinationUrl.path) {
                try FileManager.default.removeItem(at: destinationUrl)
            }
            try FileManager.default.moveItem(at: location, to: destinationUrl)
            print("后台下载完成，保存到: \(destinationUrl.path)")
        } catch {
            print("保存后台下载文件失败: \(error)")
        }
    }
    
    // 所有任务完成回调
    func urlSessionDidFinishEvents(forBackgroundURLSession session: URLSession) {
        DispatchQueue.main.async {
            self.backgroundCompletionHandler?()
            self.backgroundCompletionHandler = nil
        }
    }
}

// 在 AppDelegate 中配置
func application(_ application: UIApplication, handleEventsForBackgroundURLSession identifier: String, completionHandler: @escaping () -> Void) {
    if identifier == "com.example.app.backgroundSession" {
        BackgroundDownloadManager.shared.backgroundCompletionHandler = completionHandler
    }
}

// 使用
let url = URL(string: "https://example.com/largefile.zip")!
BackgroundDownloadManager.shared.startDownload(from: url)
```

## 取消和恢复

### 取消任务

```swift
// 取消单个任务
downloadTask.cancel()

// 取消带恢复数据的下载任务
downloadTask.cancel { resumeData in
    if let resumeData = resumeData {
        // 保存恢复数据以供稍后使用
        self.resumeData = resumeData
    }
}

// 取消所有任务
session.invalidateAndCancel()
```

### 恢复下载

```swift
// 使用恢复数据创建新的下载任务
if let resumeData = self.resumeData {
    let task = session.downloadTask(withResumeData: resumeData)
    task.resume()
    self.resumeData = nil
}
```

## URLSession 配置

URLSession 的行为可以通过 URLSessionConfiguration 定制：

```swift
let config = URLSessionConfiguration.default

// 超时设置
config.timeoutIntervalForRequest = 30 // 请求超时（秒）
config.timeoutIntervalForResource = 60 // 资源超时（秒）

// 缓存策略
config.requestCachePolicy = .useProtocolCachePolicy

// 连接设置
config.waitsForConnectivity = true // iOS 11+，等待连接恢复
config.allowsCellularAccess = true // 允许使用蜂窝网络

// HTTP 设置
config.httpMaximumConnectionsPerHost = 5
config.httpShouldUsePipelining = true // HTTP 管道，提高性能

// 安全设置
config.tlsMinimumSupportedProtocolVersion = .TLSv12
config.tlsMaximumSupportedProtocolVersion = .TLSv13

// 创建会话
let session = URLSession(configuration: config)
```

## 最佳实践

### 网络管理器封装

创建一个 API 管理器类，封装常见的网络操作：

```swift
enum NetworkError: Error {
    case invalidURL
    case noData
    case decodingFailed
    case serverError(statusCode: Int)
    case unknown(Error)
}

class APIManager {
    static let shared = APIManager()
    
    private let session: URLSession
    
    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.waitsForConnectivity = true
        self.session = URLSession(configuration: config)
    }
    
    // MARK: - GET 请求
    func get<T: Decodable>(url: String, type: T.Type, completion: @escaping (Result<T, NetworkError>) -> Void) {
        guard let url = URL(string: url) else {
            completion(.failure(.invalidURL))
            return
        }
        
        let task = session.dataTask(with: url) { (data, response, error) in
            if let error = error {
                completion(.failure(.unknown(error)))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(.unknown(NSError(domain: "Invalid response", code: -1, userInfo: nil))))
                return
            }
            
            guard (200...299).contains(httpResponse.statusCode) else {
                completion(.failure(.serverError(statusCode: httpResponse.statusCode)))
                return
            }
            
            guard let data = data else {
                completion(.failure(.noData))
                return
            }
            
            do {
                let decoder = JSONDecoder()
                decoder.keyDecodingStrategy = .convertFromSnakeCase
                let result = try decoder.decode(T.self, from: data)
                completion(.success(result))
            } catch {
                completion(.failure(.decodingFailed))
            }
        }
        
        task.resume()
    }
    
    // MARK: - POST 请求
    func post<T: Decodable, U: Encodable>(url: String, body: U, type: T.Type, completion: @escaping (Result<T, NetworkError>) -> Void) {
        guard let url = URL(string: url) else {
            completion(.failure(.invalidURL))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            let encoder = JSONEncoder()
            encoder.keyEncodingStrategy = .convertToSnakeCase
            request.httpBody = try encoder.encode(body)
        } catch {
            completion(.failure(.unknown(error)))
            return
        }
        
        let task = session.dataTask(with: request) { (data, response, error) in
            if let error = error {
                completion(.failure(.unknown(error)))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(.unknown(NSError(domain: "Invalid response", code: -1, userInfo: nil))))
                return
            }
            
            guard (200...299).contains(httpResponse.statusCode) else {
                completion(.failure(.serverError(statusCode: httpResponse.statusCode)))
                return
            }
            
            guard let data = data else {
                completion(.failure(.noData))
                return
            }
            
            do {
                let decoder = JSONDecoder()
                decoder.keyDecodingStrategy = .convertFromSnakeCase
                let result = try decoder.decode(T.self, from: data)
                completion(.success(result))
            } catch {
                completion(.failure(.decodingFailed))
            }
        }
        
        task.resume()
    }
    
    // MARK: - 下载文件
    func download(url: String, progress: @escaping (Float) -> Void, completion: @escaping (Result<URL, NetworkError>) -> Void) {
        guard let url = URL(string: url) else {
            completion(.failure(.invalidURL))
            return
        }
        
        let downloadManager = DownloadManager()
        downloadManager.download(from: url, progress: progress) { (fileURL, error) in
            if let error = error {
                completion(.failure(.unknown(error)))
            } else if let fileURL = fileURL {
                completion(.success(fileURL))
            } else {
                completion(.failure(.unknown(NSError(domain: "Unknown download error", code: -1, userInfo: nil))))
            }
        }
    }
}

// 使用
struct User: Codable {
    let id: Int
    let name: String
    let email: String
}

// GET 请求
APIManager.shared.get(url: "https://api.example.com/users/1", type: User.self) { result in
    switch result {
    case .success(let user):
        print("获取用户成功: \(user.name)")
    case .failure(let error):
        print("获取用户失败: \(error)")
    }
}

// POST 请求
struct LoginRequest: Codable {
    let email: String
    let password: String
}

struct LoginResponse: Codable {
    let token: String
    let user: User
}

let loginRequest = LoginRequest(email: "user@example.com", password: "password123")

APIManager.shared.post(url: "https://api.example.com/login", body: loginRequest, type: LoginResponse.self) { result in
    switch result {
    case .success(let response):
        print("登录成功，token: \(response.token)")
    case .failure(let error):
        print("登录失败: \(error)")
    }
}

// 下载文件
APIManager.shared.download(url: "https://example.com/largefile.zip", progress: { progress in
    print("下载进度: \(progress * 100)%")
}) { result in
    switch result {
    case .success(let fileURL):
        print("下载完成，文件保存在: \(fileURL.path)")
    case .failure(let error):
        print("下载失败: \(error)")
    }
}
```

### 重试机制

```swift
func performRequestWithRetry<T: Decodable>(url: URL, type: T.Type, retries: Int = 3, completion: @escaping (Result<T, Error>) -> Void) {
    var retriesLeft = retries
    
    func executeRequest() {
        let task = URLSession.shared.dataTask(with: url) { (data, response, error) in
            // 检查是否需要重试
            if let error = error, retriesLeft > 0 {
                // 网络错误，重试
                retriesLeft -= 1
                
                // 指数退避算法
                let delay = pow(2.0, Double(retries - retriesLeft)) * 1.0
                
                DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
                    print("重试请求，剩余尝试次数: \(retriesLeft)")
                    executeRequest()
                }
                return
            }
            
            // 处理最终结果
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                completion(.failure(NSError(domain: "HTTPError", code: (response as? HTTPURLResponse)?.statusCode ?? -1, userInfo: nil)))
                return
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "NoDataError", code: -1, userInfo: nil)))
                return
            }
            
            do {
                let result = try JSONDecoder().decode(T.self, from: data)
                completion(.success(result))
            } catch {
                completion(.failure(error))
            }
        }
        
        task.resume()
    }
    
    executeRequest()
}
```

### 并发请求

```swift
func performConcurrentRequests(urls: [URL], completion: @escaping ([Data?], [Error?]) -> Void) {
    let dispatchGroup = DispatchGroup()
    var results = Array<Data?>(repeating: nil, count: urls.count)
    var errors = Array<Error?>(repeating: nil, count: urls.count)
    
    for (index, url) in urls.enumerated() {
        dispatchGroup.enter()
        
        URLSession.shared.dataTask(with: url) { (data, response, error) in
            // 存储结果
            results[index] = data
            errors[index] = error
            
            dispatchGroup.leave()
        }.resume()
    }
    
    // 所有请求完成后调用
    dispatchGroup.notify(queue: .main) {
        completion(results, errors)
    }
}

// 使用
let urls = [
    URL(string: "https://api.example.com/users")!,
    URL(string: "https://api.example.com/products")!,
    URL(string: "https://api.example.com/orders")!
]

performConcurrentRequests(urls: urls) { (results, errors) in
    for i in 0..<urls.count {
        if let data = results[i] {
            print("请求 \(i+1) 成功，收到 \(data.count) 字节")
        } else if let error = errors[i] {
            print("请求 \(i+1) 失败: \(error)")
        }
    }
}
```

### 中断点测试

在开发中测试不同的网络状况：

```swift
// 在 Xcode 中，可以使用网络链接调节器模拟不同的网络条件
// Debug -> Simulate Location -> Network Link Conditioner

// 或者在代码中设置模拟延迟
func simulateNetworkDelay(completion: @escaping () -> Void) {
    #if DEBUG
    let delay = Int.random(in: 1...3)
    print("模拟网络延迟 \(delay) 秒")
    DispatchQueue.global().asyncAfter(deadline: .now() + .seconds(delay)) {
        completion()
    }
    #else
    completion()
    #endif
}

// 使用
simulateNetworkDelay {
    // 执行网络请求
    URLSession.shared.dataTask(with: url) { ... }.resume()
}
``` 