# Alamofire 网络请求框架

Alamofire 是一个用 Swift 编写的 HTTP 网络请求库，为 iOS 和 macOS 应用提供了简洁、优雅的接口来进行网络通信。作为 AFNetworking 的 Swift 版本继任者，Alamofire 已成为 iOS 开发中最流行的第三方网络框架。

## 目录

- [简介](#简介)
- [安装与配置](#安装与配置)
- [基本用法](#基本用法)
- [请求与响应](#请求与响应)
- [参数编码](#参数编码)
- [响应处理](#响应处理)
- [高级特性](#高级特性)
- [与 Codable 结合使用](#与-codable-结合使用)
- [身份验证](#身份验证)
- [上传与下载](#上传与下载)
- [缓存控制](#缓存控制)
- [网络层架构](#网络层架构)
- [测试与模拟](#测试与模拟)
- [最佳实践](#最佳实践)
- [常见问题](#常见问题)
- [与 Combine 集成](#与-combine-集成)
- [与 async/await 集成](#与-asyncawait-集成)
- [性能优化](#性能优化)
- [迁移指南](#迁移指南)

## 简介

### 什么是 Alamofire？

Alamofire 是一个建立在 Apple 的 Foundation 网络堆栈之上的 Swift 网络库，为常见的网络任务提供了优雅的接口。它支持以下功能：

- 链式请求/响应方法
- URL / JSON / plist 参数编码
- 文件 / 数据 / 流 / 多表单数据上传
- 请求和响应的序列化
- 身份验证
- HTTP 响应验证
- 上传和下载进度跟踪
- cURL 命令输出
- 动态自适应的请求重试
- TLS 证书和公钥固定
- 网络可达性监控

### 为什么选择 Alamofire？

相比原生的 URLSession，Alamofire 提供了：

1. **简洁的 API**：用更少的代码完成相同的网络任务
2. **链式调用**：使代码更易读和维护
3. **强大的扩展性**：丰富的插件生态系统
4. **完善的错误处理**：更明确的错误类型和信息
5. **活跃的社区支持**：问题解决和更新维护
6. **丰富的功能集**：内置多种常用网络功能

### Alamofire 与 URLSession 的关系

Alamofire 并不是对 URLSession 的替代，而是构建在其上的抽象层：

```
应用层代码
    ↓
Alamofire
    ↓
URLSession
    ↓
底层网络协议栈
```

Alamofire 使用 URLSession 作为其底层网络引擎，为开发者提供了更高级的 API 接口。当你使用 Alamofire 时，实际上是在间接使用 URLSession。

## 安装与配置

### 系统要求

- iOS 10.0+ / macOS 10.12+ / tvOS 10.0+ / watchOS 3.0+
- Xcode 11+
- Swift 5.1+

### 使用 Swift Package Manager 安装

1. 在 Xcode 中，选择 File > Swift Packages > Add Package Dependency
2. 输入 Alamofire 的仓库 URL: `https://github.com/Alamofire/Alamofire.git`
3. 选择版本规则（建议使用最新稳定版）
4. 点击"Next"并完成安装

### 使用 CocoaPods 安装

1. 创建或编辑 Podfile:

```ruby
platform :ios, '10.0'
use_frameworks!

target 'YourAppName' do
  pod 'Alamofire', '~> 5.6'
end
```

2. 安装依赖:

```bash
pod install
```

### 使用 Carthage 安装

1. 创建或编辑 Cartfile:

```
github "Alamofire/Alamofire" ~> 5.6
```

2. 安装依赖:

```bash
carthage update --platform iOS
```

### 导入 Alamofire

安装后，在需要使用 Alamofire 的文件顶部导入:

```swift
import Alamofire
```

### 基本配置

创建一个共享的 Session 实例（可选但推荐）:

```swift
// 在 AppDelegate 或专门的网络管理类中
let session = Session.default

// 或自定义配置
let configuration = URLSessionConfiguration.default
configuration.timeoutIntervalForRequest = 30 // 30秒超时
configuration.httpAdditionalHeaders = HTTPHeaders.default.dictionary
let session = Session(configuration: configuration)
```

## 基本用法

### 发起简单请求

```swift
// 最简单的 GET 请求
AF.request("https://api.example.com/data").response { response in
    debugPrint(response)
}

// 带参数的 GET 请求
AF.request("https://api.example.com/search", 
           parameters: ["q": "swift", "page": 1],
           encoder: URLEncodedFormParameterEncoder.default).response { response in
    debugPrint(response)
}

// POST 请求
AF.request("https://api.example.com/create",
           method: .post,
           parameters: ["name": "New Item", "type": "Example"],
           encoder: JSONParameterEncoder.default).response { response in
    debugPrint(response)
}
```

### 指定 HTTP 方法

```swift
AF.request("https://api.example.com/resource", method: .get)  // GET
AF.request("https://api.example.com/resource", method: .post) // POST
AF.request("https://api.example.com/resource", method: .put)  // PUT
AF.request("https://api.example.com/resource", method: .delete) // DELETE
```

### 添加 HTTP 头

```swift
// 创建头部
let headers: HTTPHeaders = [
    "Authorization": "Bearer YOUR_TOKEN_HERE",
    "Accept": "application/json"
]

// 发起请求
AF.request("https://api.example.com/profile", headers: headers).response { response in
    debugPrint(response)
}

// 添加单个头部
AF.request("https://api.example.com/profile")
    .authenticate(username: "user", password: "pass")
    .responseDecodable(of: Profile.self) { response in
        debugPrint(response)
    }
```

### 链式请求

Alamofire 的一大特点是支持链式调用:

```swift
AF.request("https://api.example.com/data")
    .validate()  // 验证响应状态码
    .responseDecodable(of: [Item].self) { response in
        switch response.result {
        case .success(let items):
            print("获取到 \(items.count) 个项目")
        case .failure(let error):
            print("请求失败: \(error)")
        }
    }
```

## 请求与响应

### 请求配置

Alamofire 提供了多种方式来配置请求:

```swift
// 基本请求
let request = AF.request("https://api.example.com/data")

// 完整请求配置
let request = AF.request(
    "https://api.example.com/users",
    method: .post,
    parameters: ["name": "John", "email": "john@example.com"],
    encoder: JSONParameterEncoder.default,
    headers: ["Authorization": "Bearer token"],
    interceptor: RequestInterceptor()
)
```

### 请求的属性和方法

```swift
// 请求状态
let state = request.state  // 可能是 .initialized, .resumed, .suspended, .cancelled, .finished

// 请求细节
let task = request.task    // 底层的 URLSessionTask
let request = request.request  // 底层的 URLRequest
let response = request.response  // 响应 (如果有)

// 请求控制
request.resume()   // 开始/恢复请求
request.suspend()  // 暂停请求
request.cancel()   // 取消请求
```

### 获取响应数据

Alamofire 提供了多种处理响应的方法:

```swift
// 基本响应 - 获取原始数据
AF.request("https://api.example.com/data").response { response in
    debugPrint("状态码:", response.response?.statusCode ?? 0)
    debugPrint("数据:", response.data ?? Data())
    debugPrint("错误:", response.error ?? "无错误")
}

// 获取字符串响应
AF.request("https://api.example.com/data").responseString { response in
    if let string = response.value {
        print("返回的字符串: \(string)")
    }
}

// 获取 JSON 响应
AF.request("https://api.example.com/data").responseJSON { response in
    if let json = response.value {
        print("JSON: \(json)")
    }
}

// 获取 Data 响应
AF.request("https://api.example.com/data").responseData { response in
    if let data = response.value {
        print("获取到 \(data.count) 字节的数据")
    }
}

// 解码为 Decodable 对象
struct User: Codable {
    let id: Int
    let name: String
    let email: String
}

AF.request("https://api.example.com/user/1").responseDecodable(of: User.self) { response in
    if let user = response.value {
        print("用户: \(user.name), 邮箱: \(user.email)")
    }
}
```

### 响应验证

验证响应状态码和 MIME 类型:

```swift
// 验证状态码在 200..<300 范围内
AF.request("https://api.example.com/data")
    .validate()
    .responseJSON { response in
        switch response.result {
        case .success(let value):
            print("请求成功: \(value)")
        case .failure(let error):
            print("请求失败: \(error)")
        }
    }

// 自定义验证
AF.request("https://api.example.com/data")
    .validate(statusCode: 200..<300)  // 验证状态码
    .validate(contentType: ["application/json"])  // 验证内容类型
    .responseDecodable(of: [Item].self) { response in
        // 处理响应
    }

// 自定义验证逻辑
AF.request("https://api.example.com/data")
    .validate { request, response, data in
        // 返回 .success(()) 表示验证通过，或 .failure(错误) 表示验证失败
        guard let data = data, let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return .failure(AFError.responseValidationFailed(reason: .dataFileNil))
        }
        
        // 检查是否有错误字段
        if let error = json["error"] as? String {
            let customError = NSError(domain: "APIError", code: 0, userInfo: [NSLocalizedDescriptionKey: error])
            return .failure(AFError.responseValidationFailed(reason: .customValidationFailed(error: customError)))
        }
        
        return .success(())
    }
    .responseJSON { response in
        // 处理响应
    }
```

### 响应队列

默认情况下，Alamofire 在主队列上调用响应处理程序，但你可以自定义:

```swift
// 在后台队列处理响应
let queue = DispatchQueue(label: "com.example.networkQueue")

AF.request("https://api.example.com/data")
    .responseJSON(queue: queue) { response in
        // 这个闭包在后台队列中执行
        // 处理数据...
        
        // 如果需要更新 UI，必须切换到主队列
        DispatchQueue.main.async {
            // 更新 UI
        }
    }
```

## 参数编码

Alamofire 支持多种参数编码方式，可以根据不同的 API 需求选择合适的编码器。

### URL 编码

适用于 GET 请求的查询参数或 POST 表单数据:

```swift
// GET 请求使用 URLEncoding
AF.request("https://api.example.com/search",
           parameters: ["q": "swift", "page": 1],
           encoder: URLEncodedFormParameterEncoder.default)
// 结果: https://api.example.com/search?q=swift&page=1

// 也可以这样写（向后兼容方式）
AF.request("https://api.example.com/search",
           method: .get,
           parameters: ["q": "swift", "page": 1],
           encoding: URLEncoding.default)

// 自定义 URLEncoding
let encoder = URLEncodedFormParameterEncoder(
    destination: .methodDependent,  // .queryString, .httpBody 或 .methodDependent
    arrayEncoding: .brackets,       // .brackets ([key]=value) 或 .noBrackets (key=value)
    boolEncoding: .literal          // .literal (true/false) 或 .numeric (1/0)
)

AF.request("https://api.example.com/search", parameters: ["tags": ["swift", "ios"]], encoder: encoder)
// 结果: https://api.example.com/search?tags[]=swift&tags[]=ios
```

### JSON 编码

适用于现代 REST API 的 JSON 请求体:

```swift
// 基本 JSON 编码
AF.request("https://api.example.com/users",
           method: .post,
           parameters: ["name": "John", "email": "john@example.com"],
           encoder: JSONParameterEncoder.default)

// 自定义 JSON 编码选项
let encoder = JSONParameterEncoder(encoder: JSONEncoder())
encoder.encoder.keyEncodingStrategy = .convertToSnakeCase
encoder.encoder.dateEncodingStrategy = .iso8601

AF.request("https://api.example.com/users",
           method: .post,
           parameters: User(name: "John", createdAt: Date()),
           encoder: encoder)
```

### 自定义参数编码

你可以创建自定义编码器来处理特殊需求:

```swift
// 实现自定义参数编码器
struct CustomParameterEncoder: ParameterEncoder {
    func encode<Parameters: Encodable>(_ parameters: Parameters?, into request: URLRequest) throws -> URLRequest {
        var request = request
        
        // 实现自定义编码逻辑
        guard let parameters = parameters else { return request }
        
        // 示例：将参数转换为 XML
        let xmlData = try convertToXML(parameters)
        request.httpBody = xmlData
        request.setValue("application/xml", forHTTPHeaderField: "Content-Type")
        
        return request
    }
    
    private func convertToXML<T: Encodable>(_ parameters: T) throws -> Data {
        // 实现 XML 转换逻辑
        // 这里仅作示例，需要实际的 XML 编码实现
        return Data()
    }
}

// 使用自定义编码器
AF.request("https://api.example.com/xmlEndpoint",
           method: .post,
           parameters: ["root": ["name": "value"]],
           encoder: CustomParameterEncoder())
```

### 编码复杂数据结构

处理嵌套数据结构和数组:

```swift
// 嵌套结构
let parameters: [String: Any] = [
    "user": [
        "name": "John",
        "address": [
            "street": "123 Main St",
            "city": "San Francisco"
        ]
    ],
    "preferences": ["dark_mode": true, "notifications": false]
]

// JSON 编码处理嵌套结构自然而然
AF.request("https://api.example.com/users",
           method: .post,
           parameters: parameters,
           encoding: JSONEncoding.default)

// 使用 Encodable 类型更安全
struct Address: Codable {
    let street: String
    let city: String
}

struct UserData: Codable {
    let name: String
    let address: Address
    let preferences: [String: Bool]
}

let userData = UserData(
    name: "John",
    address: Address(street: "123 Main St", city: "San Francisco"),
    preferences: ["darkMode": true, "notifications": false]
)

AF.request("https://api.example.com/users",
           method: .post,
           parameters: userData,
           encoder: JSONParameterEncoder.default)
``` 

## 响应处理

Alamofire 提供了多种处理服务器响应的方式，可以根据不同的需求选择最合适的方法。

### 处理响应结果

使用 Alamofire 的 `Response` 对象获取详细信息:

```swift
AF.request("https://api.example.com/data").responseJSON { response in
    // 获取响应的各个部分
    let request = response.request        // 原始请求
    let response = response.response      // HTTP URL 响应
    let data = response.data              // 服务器返回的数据
    let result = response.result          // 结果枚举 (.success 或 .failure)
    let metrics = response.metrics        // 网络请求的性能指标
    
    // 使用 Result 类型处理响应
    switch response.result {
    case .success(let value):
        print("请求成功，值为: \(value)")
        
    case .failure(let error):
        print("请求失败，错误为: \(error)")
        
        // 获取详细错误信息
        if let underlyingError = error.underlyingError {
            print("底层错误: \(underlyingError)")
        }
        
        // 错误的响应代码
        if let statusCode = response.response?.statusCode {
            print("HTTP 状态码: \(statusCode)")
        }
    }
}
```

### 使用 Decodable 处理 JSON

结合 Swift 的 `Codable` 协议处理 JSON 数据:

```swift
// 定义模型
struct User: Codable {
    let id: Int
    let name: String
    let email: String
    let isActive: Bool
    
    // 使用 CodingKeys 处理 JSON 字段名映射
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case email
        case isActive = "is_active"  // 映射蛇形命名字段
    }
}

// 获取单个对象
AF.request("https://api.example.com/users/1")
    .responseDecodable(of: User.self) { response in
        switch response.result {
        case .success(let user):
            print("用户名: \(user.name)")
        case .failure(let error):
            print("解码失败: \(error)")
        }
    }

// 获取对象数组
AF.request("https://api.example.com/users")
    .responseDecodable(of: [User].self) { response in
        switch response.result {
        case .success(let users):
            print("获取到 \(users.count) 个用户")
            users.forEach { print($0.name) }
        case .failure(let error):
            print("解码失败: \(error)")
        }
    }
```

### 自定义 JSON 解码

使用自定义 `JSONDecoder` 进行更复杂的解码:

```swift
// 创建自定义 JSONDecoder
let decoder = JSONDecoder()
decoder.keyDecodingStrategy = .convertFromSnakeCase  // 自动转换蛇形命名
decoder.dateDecodingStrategy = .iso8601              // 解析 ISO8601 日期

// 使用自定义解码器
AF.request("https://api.example.com/users")
    .responseDecodable(of: [User].self, decoder: decoder) { response in
        if let users = response.value {
            print("获取到 \(users.count) 个用户")
        }
    }
```

### 错误处理

处理网络请求中的各种错误:

```swift
AF.request("https://api.example.com/data")
    .validate()
    .responseJSON { response in
        switch response.result {
        case .success(let value):
            print("成功: \(value)")
            
        case .failure(let error):
            // 类型转换为 AFError 以获取详细信息
            let afError = error as AFError
            
            // 根据错误类型进行处理
            switch afError {
            case .invalidURL(let url):
                print("无效的 URL: \(url)")
                
            case .parameterEncodingFailed(let reason):
                print("参数编码失败: \(reason)")
                
            case .multipartEncodingFailed(let reason):
                print("多部分编码失败: \(reason)")
                
            case .responseValidationFailed(let reason):
                print("响应验证失败: \(reason)")
                
                switch reason {
                case .unacceptableStatusCode(let code):
                    print("状态码不可接受: \(code)")
                    // 例如，可以处理特定状态码
                    if code == 401 {
                        // 处理未授权错误
                        refreshToken()
                    } else if code >= 500 {
                        // 处理服务器错误
                        showServerErrorMessage()
                    }
                case .dataFileNil, .dataFileReadFailed:
                    print("读取数据失败")
                default:
                    print("其他验证失败原因: \(reason)")
                }
                
            case .responseSerializationFailed(let reason):
                print("响应序列化失败: \(reason)")
                
            case .serverTrustEvaluationFailed(let reason):
                print("服务器信任评估失败: \(reason)")
                
            case .sessionTaskFailed(let error):
                print("会话任务失败: \(error)")
                
                // 检查网络连接错误
                if let urlError = error as? URLError {
                    switch urlError.code {
                    case .notConnectedToInternet:
                        print("无网络连接")
                        showNoConnectionAlert()
                    case .timedOut:
                        print("请求超时")
                        showTimeoutAlert()
                    default:
                        print("其他 URL 错误: \(urlError)")
                    }
                }
                
            default:
                print("其他错误: \(afError)")
            }
            
            // 获取响应数据，可能包含错误信息
            if let data = response.data, let errorJson = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                print("错误响应数据: \(errorJson)")
                
                // 显示服务器返回的错误消息
                if let message = errorJson["message"] as? String {
                    showErrorMessage(message)
                }
            }
        }
    }

// 辅助函数
func refreshToken() {
    print("刷新令牌...")
}

func showServerErrorMessage() {
    print("显示服务器错误消息")
}

func showNoConnectionAlert() {
    print("显示无网络连接提示")
}

func showTimeoutAlert() {
    print("显示请求超时提示")
}

func showErrorMessage(_ message: String) {
    print("显示错误消息: \(message)")
}
```

### 序列化响应

自定义响应序列化处理:

```swift
// 自定义响应序列化处理器
struct CustomResponseSerializer<Value>: ResponseSerializer {
    private let serializeResponse: (URLRequest?, HTTPURLResponse?, Data?, Error?) throws -> Value
    
    init(serializeResponse: @escaping (URLRequest?, HTTPURLResponse?, Data?, Error?) throws -> Value) {
        self.serializeResponse = serializeResponse
    }
    
    func serialize(request: URLRequest?, response: HTTPURLResponse?, data: Data?, error: Error?) throws -> Value {
        return try serializeResponse(request, response, data, error)
    }
}

// 使用自定义序列化处理器
let serializer = CustomResponseSerializer<(data: Data, timestamp: Date)> { request, response, data, error in
    guard error == nil else { throw error! }
    guard let data = data else { throw AFError.responseSerializationFailed(reason: .inputDataNilOrZeroLength) }
    
    // 返回自定义值: 数据和时间戳
    return (data: data, timestamp: Date())
}

AF.request("https://api.example.com/data")
    .response(responseSerializer: serializer) { response in
        if let value = response.value {
            print("获取到 \(value.data.count) 字节的数据，时间戳: \(value.timestamp)")
        }
    }

// 创建响应处理扩展
extension DataRequest {
    func responseCustomValue<T: Decodable>(
        of type: T.Type = T.self,
        queue: DispatchQueue = .main,
        dataPreprocessor: DataPreprocessor = DecodableResponseSerializer<T>.defaultDataPreprocessor,
        decoder: DataDecoder = JSONDecoder(),
        emptyResponseCodes: Set<Int> = DecodableResponseSerializer<T>.defaultEmptyResponseCodes,
        emptyRequestMethods: Set<HTTPMethod> = DecodableResponseSerializer<T>.defaultEmptyRequestMethods,
        completionHandler: @escaping (AFDataResponse<(value: T, headers: HTTPHeaders)>) -> Void
    ) -> Self {
        let serializer = CustomResponseSerializer<(value: T, headers: HTTPHeaders)> { request, response, data, error in
            guard error == nil else { throw error! }
            guard let data = data, !data.isEmpty else {
                guard emptyResponseAllowed(forRequest: request, response: response) else {
                    throw AFError.responseSerializationFailed(reason: .inputDataNilOrZeroLength)
                }
                
                // 处理空响应
                throw AFError.responseSerializationFailed(reason: .inputDataNilOrZeroLength)
            }
            
            let headers = response?.headers ?? HTTPHeaders()
            let value = try decoder.decode(T.self, from: data)
            
            return (value: value, headers: headers)
        }
        
        return response(queue: queue, responseSerializer: serializer, completionHandler: completionHandler)
    }
    
    private func emptyResponseAllowed(forRequest request: URLRequest?, response: HTTPURLResponse?) -> Bool {
        return true // 简化示例，实际应检查请求方法和状态码
    }
}

// 使用自定义响应处理扩展
AF.request("https://api.example.com/users/1")
    .responseCustomValue(of: User.self) { response in
        if let result = response.value {
            print("用户: \(result.value.name)")
            print("响应头: \(result.headers)")
        }
    }
``` 

## 高级特性

Alamofire 提供了许多高级功能，用于处理复杂的网络场景和需求。

### 请求拦截器

拦截器允许你检查和修改请求，以及重试失败的请求:

```swift
// 自定义适配器：修改请求
class CustomRequestAdapter: RequestAdapter {
    let token: String
    
    init(token: String) {
        self.token = token
    }
    
    func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        var urlRequest = urlRequest
        
        // 添加认证头
        urlRequest.headers.add(.authorization(bearerToken: token))
        
        // 添加其他通用头
        urlRequest.headers.add(name: "App-Version", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0")
        urlRequest.headers.add(name: "Device-ID", value: UIDevice.current.identifierForVendor?.uuidString ?? "")
        
        completion(.success(urlRequest))
    }
}

// 自定义重试器：重试失败的请求
class CustomRequestRetrier: RequestRetrier {
    let retryLimit: Int
    private var retriedRequests: [String: Int] = [:]
    
    init(retryLimit: Int = 3) {
        self.retryLimit = retryLimit
    }
    
    func retry(_ request: Request, for session: Session, dueTo error: Error, completion: @escaping (RetryResult) -> Void) {
        let requestID = request.id.uuidString
        
        // 检查是否需要重试
        if let retryCount = retriedRequests[requestID] {
            // 已经重试过
            if retryCount >= retryLimit {
                // 达到最大重试次数
                completion(.doNotRetry)
                retriedRequests[requestID] = nil
                return
            }
            
            retriedRequests[requestID] = retryCount + 1
        } else {
            // 第一次重试
            retriedRequests[requestID] = 1
        }
        
        // 检查错误类型
        if let statusCode = request.response?.statusCode {
            switch statusCode {
            case 401:
                // 身份验证错误，尝试刷新令牌
                refreshToken { success in
                    if success {
                        // 令牌刷新成功，延迟重试
                        completion(.retryWithDelay(1.0)) // 1秒后重试
                    } else {
                        // 令牌刷新失败，不再重试
                        completion(.doNotRetry)
                    }
                }
                return
                
            case 500...599:
                // 服务器错误，等待更长时间后重试
                let retryCount = retriedRequests[requestID] ?? 1
                let delay = Double(retryCount) * 2.0 // 指数回退
                completion(.retryWithDelay(delay))
                return
            }
        }
        
        // 检查网络错误
        if let urlError = error as? URLError, urlError.code == .notConnectedToInternet {
            // 网络连接错误，延迟重试
            completion(.retryWithDelay(3.0))
            return
        }
        
        // 默认重试
        completion(.retry)
    }
    
    private func refreshToken(completion: @escaping (Bool) -> Void) {
        // 实现令牌刷新逻辑
        print("刷新令牌...")
        
        // 模拟令牌刷新
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.0) {
            let success = true // 假设成功
            completion(success)
        }
    }
}

// 结合适配器和重试器
class AuthenticationInterceptor: RequestInterceptor {
    private let adapter: CustomRequestAdapter
    private let retrier: CustomRequestRetrier
    
    init(token: String, retryLimit: Int = 3) {
        self.adapter = CustomRequestAdapter(token: token)
        self.retrier = CustomRequestRetrier(retryLimit: retryLimit)
    }
    
    func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
        adapter.adapt(urlRequest, for: session, completion: completion)
    }
    
    func retry(_ request: Request, for session: Session, dueTo error: Error, completion: @escaping (RetryResult) -> Void) {
        retrier.retry(request, for: session, dueTo: error, completion: completion)
    }
}

// 使用拦截器
let interceptor = AuthenticationInterceptor(token: "YOUR_TOKEN")

// 创建会话
let session = Session(interceptor: interceptor)

// 发送请求
session.request("https://api.example.com/protected").responseJSON { response in
    print(response)
}

// 也可以为单个请求设置拦截器
AF.request("https://api.example.com/protected", interceptor: interceptor)
```

### 事件监听器

监听请求生命周期的各个事件:

```swift
// 自定义事件监听器
class NetworkLogger: EventMonitor {
    let queue = DispatchQueue(label: "network.logger")
    
    // 请求开始
    func requestDidResume(_ request: Request) {
        print("⬆️ 请求开始: \(request)")
    }
    
    // 请求结束
    func requestDidFinish(_ request: Request) {
        print("✅ 请求结束: \(request)")
    }
    
    // 响应序列化完成
    func request<Value>(_ request: DataRequest, didParseResponse response: DataResponse<Value, AFError>) {
        print("🔄 响应解析: \(response)")
    }
    
    // 请求失败
    func request(_ request: Request, didFailToCreateURLRequestWithError error: AFError) {
        print("❌ 请求创建失败: \(error)")
    }
    
    // 服务器信任评估失败
    func request(_ request: Request, didFailToValidateRequestWithError error: AFError) {
        print("⚠️ 请求验证失败: \(error)")
    }
}

// 创建会话时添加事件监听器
let logger = NetworkLogger()
let session = Session(eventMonitors: [logger])

// 发送请求
session.request("https://api.example.com/data").responseJSON { response in
    print(response)
}
```

### 重定向处理

自定义 HTTP 重定向行为:

```swift
// 重定向处理
let redirectHandler = Redirector(behavior: .follow)  // 默认行为：跟随重定向

// 自定义重定向行为
let customRedirector = Redirector(behavior: .modify { task, request, response in
    var request = request
    
    // 例如，保留原始请求的所有头部
    let headers = task.originalRequest?.allHTTPHeaderFields ?? [:]
    headers.forEach { request.setValue($0.value, forHTTPHeaderField: $0.key) }
    
    // 修改重定向 URL
    if request.url?.host == "oldapi.example.com" {
        let urlString = request.url?.absoluteString.replacingOccurrences(of: "oldapi", with: "newapi")
        request.url = URL(string: urlString ?? "")
    }
    
    return request
})

// 禁止重定向
let noRedirector = Redirector(behavior: .doNotFollow)

// 使用重定向处理器
AF.request("https://example.com/resource", redirectHandler: customRedirector)
```

### 缓存控制

自定义缓存行为:

```swift
// 配置缓存策略
let configuration = URLSessionConfiguration.default
configuration.requestCachePolicy = .returnCacheDataElseLoad

// 创建带有自定义缓存策略的会话
let session = Session(configuration: configuration)

// 使用 ETag 和条件请求
var headers: HTTPHeaders = [:]
if let etag = UserDefaults.standard.string(forKey: "lastETag") {
    headers.add(name: "If-None-Match", value: etag)
}

AF.request("https://api.example.com/data", headers: headers)
    .validate()
    .responseData { response in
        // 检查 304 Not Modified
        if response.response?.statusCode == 304 {
            // 使用本地缓存数据
            if let cachedData = UserDefaults.standard.data(forKey: "cachedData") {
                // 处理缓存数据
                print("使用缓存数据")
            }
            return
        }
        
        // 保存新的 ETag
        if let etag = response.response?.headers["ETag"] {
            UserDefaults.standard.set(etag, forKey: "lastETag")
        }
        
        // 保存响应数据
        if let data = response.data {
            UserDefaults.standard.set(data, forKey: "cachedData")
            print("保存新数据")
        }
    }
```

### 多部分表单数据上传

上传包含文本和文件的表单数据:

```swift
// 创建多部分表单数据
AF.upload(multipartFormData: { multipartFormData in
    // 添加文本字段
    if let data = "John".data(using: .utf8) {
        multipartFormData.append(data, withName: "name")
    }
    
    if let data = "john@example.com".data(using: .utf8) {
        multipartFormData.append(data, withName: "email")
    }
    
    // 添加文件
    if let fileURL = Bundle.main.url(forResource: "profile", withExtension: "jpg") {
        multipartFormData.append(fileURL, withName: "profile_image", fileName: "profile.jpg", mimeType: "image/jpeg")
    }
    
    // 添加内存中的数据作为文件
    if let imageData = UIImage(named: "avatar")?.jpegData(compressionQuality: 0.7) {
        multipartFormData.append(imageData, withName: "avatar", fileName: "avatar.jpg", mimeType: "image/jpeg")
    }
    
    // 添加自定义文件名和 MIME 类型
    if let fileURL = Bundle.main.url(forResource: "document", withExtension: "pdf") {
        multipartFormData.append(fileURL, withName: "document", fileName: "user_doc.pdf", mimeType: "application/pdf")
    }
    
}, to: "https://api.example.com/upload")
.uploadProgress { progress in
    // 跟踪上传进度
    print("上传进度: \(progress.fractionCompleted * 100)%")
}
.responseDecodable(of: UploadResponse.self) { response in
    switch response.result {
    case .success(let uploadResponse):
        print("上传成功: \(uploadResponse)")
    case .failure(let error):
        print("上传失败: \(error)")
    }
}
```

### 证书验证和 SSL 固定

增强网络安全性:

```swift
// 定义服务器信任评估器
class CustomServerTrustManager: ServerTrustManager {
    override func serverTrustEvaluator(for host: String) throws -> ServerTrustEvaluating? {
        // 为特定主机使用自定义评估
        switch host {
        case "api.example.com":
            // 只信任特定证书
            return PinnedCertificatesTrustEvaluator()
            
        case "test.example.com":
            // 开发环境，禁用验证
            return DisabledTrustEvaluator()
            
        default:
            // 默认使用标准评估
            return DefaultTrustEvaluator()
        }
    }
}

// 配置证书固定
let certificates = [
    try! Data(contentsOf: Bundle.main.url(forResource: "example", withExtension: "cer")!)
]

// 创建固定证书评估器
let evaluator = PinnedCertificatesTrustEvaluator(certificates: certificates)

// 或使用公钥固定
let evaluator2 = PublicKeysTrustEvaluator()

// 配置服务器信任策略
let serverTrustPolicies: [String: ServerTrustEvaluating] = [
    "api.example.com": evaluator,
    "test.example.com": DisabledTrustEvaluator()
]

// 创建服务器信任管理器
let serverTrustManager = ServerTrustManager(evaluators: serverTrustPolicies)

// 创建会话
let session = Session(serverTrustManager: serverTrustManager)

// 发送请求
session.request("https://api.example.com/secure-data").responseJSON { response in
    print(response)
}
```

### 网络可达性监控

监控网络连接状态:

```swift
// 创建网络可达性管理器
let reachabilityManager = NetworkReachabilityManager(host: "www.apple.com")

// 开始监听网络状态变化
reachabilityManager?.startListening { status in
    switch status {
    case .notReachable:
        print("网络不可用")
        // 更新 UI 或显示提示
        
    case .reachable(let connectionType):
        switch connectionType {
        case .ethernetOrWiFi:
            print("通过 WiFi 或以太网连接")
        case .cellular:
            print("通过蜂窝网络连接")
        }
        
        // 恢复任何因网络中断而暂停的操作
        
    case .unknown:
        print("网络状态未知")
    }
}

// 检查当前是否可达
if reachabilityManager?.isReachable ?? false {
    print("网络当前可达")
}

// 停止监听
reachabilityManager?.stopListening()
```

### 使用 URLCredential 进行认证

处理需要认证的请求:

```swift
// 基本认证
let credential = URLCredential(user: "username", password: "password", persistence: .forSession)

AF.request("https://api.example.com/protected-resource")
    .authenticate(with: credential)
    .responseJSON { response in
        print(response)
    }

// 自动处理认证挑战
let session = Session()
session.request("https://api.example.com/protected-resource")
    .authenticate(username: "username", password: "password")
    .responseJSON { response in
        print(response)
    }

// 自定义认证处理
class CustomAuthenticationHandler: AuthenticationCredential {
    let username: String
    let password: String
    
    init(username: String, password: String) {
        self.username = username
        self.password = password
    }
    
    func apply(_ urlRequest: inout URLRequest) {
        // 添加自定义认证头
        let authString = "\(username):\(password)"
        if let authData = authString.data(using: .utf8) {
            let base64String = authData.base64EncodedString()
            urlRequest.headers.add(.authorization(basic: base64String))
        }
    }
    
    func refresh(_ credential: CustomAuthenticationHandler, for session: Session, completion: @escaping (Result<CustomAuthenticationHandler, Error>) -> Void) {
        // 刷新认证信息（如需要）
        completion(.success(self))
    }
    
    func didRequest(_ urlRequest: URLRequest, with response: HTTPURLResponse, failDueToAuthenticationError error: Error) -> Bool {
        // 确定是否因认证失败而需要重试
        return response.statusCode == 401
    }
    
    func isRequest(_ urlRequest: URLRequest, authenticatedWith credential: CustomAuthenticationHandler) -> Bool {
        // 检查请求是否已经包含此认证信息
        return urlRequest.headers["Authorization"] != nil
    }
}

// 使用自定义认证处理器
let authCredential = CustomAuthenticationHandler(username: "user", password: "pass")
AF.request("https://api.example.com/protected-resource", interceptor: authCredential)
    .responseJSON { response in
        print(response)
    }
``` 

## 上传与下载

Alamofire 提供了强大的文件上传和下载功能，支持进度跟踪和后台传输。

### 文件上传

```swift
// 上传文件
let fileURL = Bundle.main.url(forResource: "document", withExtension: "pdf")!

AF.upload(fileURL, to: "https://api.example.com/upload")
    .uploadProgress { progress in
        // 更新上传进度
        print("上传进度: \(progress.fractionCompleted * 100)%")
        
        // 更新 UI
        DispatchQueue.main.async {
            progressView.progress = Float(progress.fractionCompleted)
            progressLabel.text = String(format: "%.1f%%", progress.fractionCompleted * 100)
        }
    }
    .responseDecodable(of: UploadResponse.self) { response in
        switch response.result {
        case .success(let value):
            print("上传成功: \(value)")
        case .failure(let error):
            print("上传失败: \(error)")
        }
    }

// 上传数据
let data = "Hello, World!".data(using: .utf8)!

AF.upload(data, to: "https://api.example.com/upload")
    .responseJSON { response in
        print(response)
    }

// 上传带有进度和自定义头的文件
let headers: HTTPHeaders = [
    "Authorization": "Bearer YOUR_TOKEN",
    "Content-Disposition": "attachment; filename=\"custom_name.pdf\""
]

AF.upload(fileURL, to: "https://api.example.com/upload", method: .post, headers: headers)
    .uploadProgress { progress in
        print("上传进度: \(progress.fractionCompleted * 100)%")
    }
    .validate(statusCode: 200..<300)
    .responseJSON { response in
        print(response)
    }
```

### 大文件上传

处理大文件上传需要考虑内存使用和错误恢复:

```swift
// 处理大文件上传
class LargeFileUploader {
    var uploadRequest: UploadRequest?
    var resumeData: Data?
    
    func uploadLargeFile(fileURL: URL, to url: String) {
        // 创建上传请求
        uploadRequest = AF.upload(fileURL, to: url)
            .uploadProgress { [weak self] progress in
                print("上传进度: \(progress.fractionCompleted * 100)%")
                
                // 保存恢复数据（如果支持）
                if let resumeData = self?.uploadRequest?.resumeData {
                    self?.resumeData = resumeData
                }
            }
            .validate()
            .responseJSON { [weak self] response in
                switch response.result {
                case .success:
                    print("大文件上传成功")
                    self?.resumeData = nil
                    
                case .failure(let error):
                    print("上传失败: \(error)")
                    
                    // 保存恢复数据
                    if let resumeData = self?.uploadRequest?.resumeData {
                        self?.resumeData = resumeData
                        print("保存恢复数据，可以稍后继续")
                    }
                }
            }
    }
    
    func pauseUpload() {
        uploadRequest?.suspend()
        print("上传暂停")
    }
    
    func resumeUpload() {
        if let resumeData = resumeData {
            // 使用恢复数据继续上传
            print("使用恢复数据继续上传")
            uploadRequest = AF.upload(resumeData, to: "https://api.example.com/upload")
                .uploadProgress { progress in
                    print("上传进度: \(progress.fractionComplated * 100)%")
                }
                .responseJSON { response in
                    print("恢复上传响应: \(response)")
                }
        } else {
            // 直接恢复当前请求
            uploadRequest?.resume()
            print("继续上传")
        }
    }
    
    func cancelUpload() {
        uploadRequest?.cancel()
        resumeData = nil
        print("上传取消")
    }
}

// 使用示例
let uploader = LargeFileUploader()
uploader.uploadLargeFile(fileURL: largeFileURL, to: "https://api.example.com/upload")

// 用户操作示例
uploadPauseButton.addTarget(self, action: #selector(pauseUpload), for: .touchUpInside)
uploadResumeButton.addTarget(self, action: #selector(resumeUpload), for: .touchUpInside)
uploadCancelButton.addTarget(self, action: #selector(cancelUpload), for: .touchUpInside)

@objc func pauseUpload() {
    uploader.pauseUpload()
}

@objc func resumeUpload() {
    uploader.resumeUpload()
}

@objc func cancelUpload() {
    uploader.cancelUpload()
}
```

### 文件下载

下载文件并跟踪进度:

```swift
// 基本文件下载
let destination: DownloadRequest.Destination = { _, _ in
    let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    let fileURL = documentsURL.appendingPathComponent("downloaded-file.pdf")
    
    // 返回目标文件 URL 和选项
    return (fileURL, [.removePreviousFile, .createIntermediateDirectories])
}

AF.download("https://example.com/file.pdf", to: destination)
    .downloadProgress { progress in
        print("下载进度: \(progress.fractionCompleted * 100)%")
    }
    .response { response in
        if let error = response.error {
            print("下载失败: \(error)")
        } else {
            print("文件下载成功，保存在: \(response.fileURL?.path ?? "未知路径")")
        }
    }

// 下载和验证
AF.download("https://example.com/file.pdf")
    .validate()
    .downloadProgress { progress in
        print("下载进度: \(progress.fractionCompleted * 100)%")
    }
    .responseData { response in
        switch response.result {
        case .success(let data):
            print("下载成功，数据大小: \(data.count) 字节")
            
            // 保存文件
            let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            let fileURL = documentsURL.appendingPathComponent("downloaded-file.pdf")
            
            do {
                try data.write(to: fileURL)
                print("文件保存在: \(fileURL.path)")
            } catch {
                print("文件保存失败: \(error)")
            }
            
        case .failure(let error):
            print("下载失败: \(error)")
        }
    }
```

### 后台下载和恢复

支持后台下载和中断恢复:

```swift
class BackgroundDownloader {
    var downloadRequest: DownloadRequest?
    var resumeData: Data?
    
    func downloadFile(from url: URL, fileName: String) {
        let destination: DownloadRequest.Destination = { _, _ in
            let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            let fileURL = documentsURL.appendingPathComponent(fileName)
            return (fileURL, [.removePreviousFile, .createIntermediateDirectories])
        }
        
        // 创建配置
        let configuration = URLSessionConfiguration.background(withIdentifier: "com.example.app.backgroundDownload")
        configuration.isDiscretionary = true
        configuration.sessionSendsLaunchEvents = true
        
        // 创建会话
        let session = Session(configuration: configuration)
        
        // 开始下载
        downloadRequest = session.download(url, to: destination)
            .downloadProgress { progress in
                print("下载进度: \(progress.fractionCompleted * 100)%")
            }
            .response { [weak self] response in
                if let error = response.error {
                    print("下载失败: \(error)")
                    
                    // 保存恢复数据
                    if let resumeData = response.resumeData {
                        self?.resumeData = resumeData
                        print("保存恢复数据，可以稍后继续")
                    }
                } else {
                    print("文件下载成功，保存在: \(response.fileURL?.path ?? "未知路径")")
                    self?.resumeData = nil
                }
            }
    }
    
    func pauseDownload() {
        downloadRequest?.cancel(producingResumeData: true) { resumeData in
            if let resumeData = resumeData {
                self.resumeData = resumeData
                print("下载暂停，保存恢复数据")
            }
        }
    }
    
    func resumeDownload() {
        guard let resumeData = resumeData else {
            print("没有恢复数据")
            return
        }
        
        let destination: DownloadRequest.Destination = { _, _ in
            let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            let fileURL = documentsURL.appendingPathComponent("resumed-file.pdf")
            return (fileURL, [.removePreviousFile, .createIntermediateDirectories])
        }
        
        // 使用恢复数据继续下载
        downloadRequest = AF.download(resumingWith: resumeData, to: destination)
            .downloadProgress { progress in
                print("恢复下载进度: \(progress.fractionCompleted * 100)%")
            }
            .response { [weak self] response in
                if let error = response.error {
                    print("恢复下载失败: \(error)")
                    
                    // 再次保存恢复数据
                    if let resumeData = response.resumeData {
                        self?.resumeData = resumeData
                    }
                } else {
                    print("恢复下载成功，文件保存在: \(response.fileURL?.path ?? "未知路径")")
                    self?.resumeData = nil
                }
            }
    }
}

// 使用示例
let downloader = BackgroundDownloader()
downloader.downloadFile(from: URL(string: "https://example.com/large-file.zip")!, fileName: "large-file.zip")

// App 进入后台时
func applicationDidEnterBackground(_ application: UIApplication) {
    // 保存状态
    if let resumeData = downloader.resumeData {
        UserDefaults.standard.set(resumeData, forKey: "downloadResumeData")
    }
}

// App 恢复前台时
func applicationWillEnterForeground(_ application: UIApplication) {
    // 恢复状态
    if let resumeData = UserDefaults.standard.data(forKey: "downloadResumeData") {
        downloader.resumeData = resumeData
        downloader.resumeDownload()
    }
}
```

## 与 Codable 结合使用

Alamofire 与 Swift 的 Codable 协议配合使用非常强大，可以简化 JSON 数据处理。

### 基本用法

```swift
// 定义模型
struct User: Codable {
    let id: Int
    let name: String
    let email: String
    let createdAt: Date
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case email
        case createdAt = "created_at"
    }
}

// 获取单个对象
AF.request("https://api.example.com/users/1")
    .responseDecodable(of: User.self) { response in
        switch response.result {
        case .success(let user):
            print("用户: \(user.name), 邮箱: \(user.email)")
        case .failure(let error):
            print("解码失败: \(error)")
        }
    }

// 获取对象数组
AF.request("https://api.example.com/users")
    .responseDecodable(of: [User].self) { response in
        switch response.result {
        case .success(let users):
            print("获取到 \(users.count) 个用户")
            users.forEach { print($0.name) }
        case .failure(let error):
            print("解码失败: \(error)")
        }
    }
```

### 自定义解码选项

```swift
// 创建自定义 JSONDecoder
let decoder = JSONDecoder()
decoder.keyDecodingStrategy = .convertFromSnakeCase // 自动转换蛇形命名
decoder.dateDecodingStrategy = .iso8601 // 解析 ISO8601 日期

// 使用自定义解码器
AF.request("https://api.example.com/users")
    .responseDecodable(of: [User].self, decoder: decoder) { response in
        if let users = response.value {
            print("获取到 \(users.count) 个用户")
        }
    }

// 处理复杂的日期格式
let dateFormatter = DateFormatter()
dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
dateFormatter.locale = Locale(identifier: "en_US_POSIX")
dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)

let customDecoder = JSONDecoder()
customDecoder.dateDecodingStrategy = .formatted(dateFormatter)

AF.request("https://api.example.com/events")
    .responseDecodable(of: [Event].self, decoder: customDecoder) { response in
        // 处理响应
    }
```

### 嵌套 JSON 结构

处理复杂的嵌套 JSON 响应:

```swift
// 嵌套结构
struct ApiResponse<T: Codable>: Codable {
    let status: String
    let code: Int
    let message: String
    let data: T?
    let errors: [String]?
}

struct UserProfile: Codable {
    let user: User
    let preferences: Preferences
    
    struct Preferences: Codable {
        let theme: String
        let notifications: Bool
        let language: String
    }
}

// 解码嵌套结构
AF.request("https://api.example.com/profile")
    .responseDecodable(of: ApiResponse<UserProfile>.self) { response in
        switch response.result {
        case .success(let apiResponse):
            if apiResponse.code == 200, let profile = apiResponse.data {
                print("用户: \(profile.user.name)")
                print("主题: \(profile.preferences.theme)")
            } else {
                print("API 错误: \(apiResponse.message ?? "未知错误")")
                if let errors = apiResponse.errors {
                    print("详细错误: \(errors.joined(separator: ", "))")
                }
            }
        case .failure(let error):
            print("解码失败: \(error)")
        }
    }
```

### 处理部分解码失败

使用自定义解码器处理可能的解码错误:

```swift
// 定义支持部分解码失败的数组容器
struct PartiallyDecodableArray<T: Decodable>: Decodable {
    let elements: [T]
    
    init(from decoder: Decoder) throws {
        var container = try decoder.unkeyedContainer()
        var elements: [T] = []
        
        while !container.isAtEnd {
            do {
                let element = try container.decode(T.self)
                elements.append(element)
            } catch {
                // 跳过解码失败的元素，但记录错误
                print("跳过解码失败的元素: \(error)")
                _ = try? container.decode(AnyCodable.self) // 消耗当前元素
            }
        }
        
        self.elements = elements
    }
}

// 辅助类型
struct AnyCodable: Codable {}

// 使用部分解码数组
AF.request("https://api.example.com/users")
    .responseDecodable(of: PartiallyDecodableArray<User>.self) { response in
        switch response.result {
        case .success(let result):
            print("成功解码 \(result.elements.count) 个用户")
            result.elements.forEach { print($0.name) }
        case .failure(let error):
            print("整体解码失败: \(error)")
        }
    }
```

### 与请求结合使用

结合编码和解码:

```swift
// 编码请求参数
struct LoginRequest: Encodable {
    let email: String
    let password: String
    let deviceId: String
    
    enum CodingKeys: String, CodingKey {
        case email
        case password
        case deviceId = "device_id"
    }
}

// 解码响应
struct LoginResponse: Decodable {
    let token: String
    let refreshToken: String
    let expiresIn: Int
    let user: User
    
    enum CodingKeys: String, CodingKey {
        case token
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case user
    }
}

// 发送登录请求
let loginRequest = LoginRequest(
    email: "user@example.com",
    password: "password123",
    deviceId: UIDevice.current.identifierForVendor?.uuidString ?? ""
)

// 创建自定义编码器
let encoder = JSONEncoder()
encoder.keyEncodingStrategy = .convertToSnakeCase

// 创建自定义解码器
let decoder = JSONDecoder()
decoder.keyDecodingStrategy = .convertFromSnakeCase

AF.request("https://api.example.com/login",
           method: .post,
           parameters: loginRequest,
           encoder: JSONParameterEncoder(encoder: encoder))
    .validate()
    .responseDecodable(of: LoginResponse.self, decoder: decoder) { response in
        switch response.result {
        case .success(let loginResponse):
            print("登录成功，令牌: \(loginResponse.token)")
            
            // 保存令牌
            UserDefaults.standard.set(loginResponse.token, forKey: "authToken")
            UserDefaults.standard.set(loginResponse.refreshToken, forKey: "refreshToken")
            
            // 处理用户信息
            let user = loginResponse.user
            print("欢迎回来, \(user.name)!")
            
        case .failure(let error):
            print("登录失败: \(error)")
            
            // 显示错误消息
            if let data = response.data,
               let errorResponse = try? decoder.decode(ApiResponse<String>.self, from: data) {
                print("错误信息: \(errorResponse.message ?? "未知错误")")
            }
        }
    }
``` 

## 网络层架构

使用 Alamofire 构建一个良好的网络层架构是构建可维护、可扩展应用的关键。本节介绍如何设计一个强大的网络层。

### 基本网络层结构

```swift
// 1. API 基础 URL 和路径定义
enum APIConstants {
    static let baseURL = "https://api.example.com"
    
    enum Path {
        static let login = "/auth/login"
        static let users = "/users"
        static let posts = "/posts"
        
        static func user(id: Int) -> String {
            return "/users/\(id)"
        }
        
        static func userPosts(userId: Int) -> String {
            return "/users/\(userId)/posts"
        }
    }
}

// 2. API 错误定义
enum APIError: Error {
    case invalidResponse
    case noData
    case decodingError
    case serverError(message: String, code: Int)
    case networkError(Error)
    case unauthorized
    case unknown
    
    var localizedDescription: String {
        switch self {
        case .invalidResponse:
            return "无效的服务器响应"
        case .noData:
            return "服务器没有返回数据"
        case .decodingError:
            return "无法解析服务器响应"
        case .serverError(let message, let code):
            return "服务器错误: \(message) (代码: \(code))"
        case .networkError(let error):
            return "网络错误: \(error.localizedDescription)"
        case .unauthorized:
            return "未授权访问，请重新登录"
        case .unknown:
            return "发生未知错误"
        }
    }
}

// 3. API 响应结构
struct APIResponse<T: Decodable>: Decodable {
    let success: Bool
    let data: T?
    let message: String?
    let error: String?
    let code: Int?
}

// 4. API 服务接口
protocol APIServiceProtocol {
    func request<T: Decodable>(
        path: String,
        method: HTTPMethod,
        parameters: Parameters?,
        encoding: ParameterEncoding,
        headers: HTTPHeaders?,
        completion: @escaping (Result<T, APIError>) -> Void
    )
}

// 5. API 服务实现
class APIService: APIServiceProtocol {
    // 单例模式
    static let shared = APIService()
    
    // Alamofire 会话
    private let session: Session
    
    // 初始化
    private init() {
        // 创建自定义配置
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30
        configuration.httpAdditionalHeaders = HTTPHeaders.default.dictionary
        
        // 创建自定义会话
        self.session = Session(configuration: configuration)
    }
    
    // 请求方法
    func request<T: Decodable>(
        path: String,
        method: HTTPMethod = .get,
        parameters: Parameters? = nil,
        encoding: ParameterEncoding = URLEncoding.default,
        headers: HTTPHeaders? = nil,
        completion: @escaping (Result<T, APIError>) -> Void
    ) {
        // 构建完整 URL
        let url = APIConstants.baseURL + path
        
        // 创建请求
        session.request(
            url,
            method: method,
            parameters: parameters,
            encoding: encoding,
            headers: headers
        )
        .validate()
        .responseDecodable(of: APIResponse<T>.self) { response in
            switch response.result {
            case .success(let apiResponse):
                // 检查 API 响应状态
                if apiResponse.success, let data = apiResponse.data {
                    completion(.success(data))
                } else {
                    // 处理业务逻辑错误
                    let message = apiResponse.error ?? apiResponse.message ?? "未知错误"
                    let code = apiResponse.code ?? 0
                    completion(.failure(.serverError(message: message, code: code)))
                    
                    // 检查授权错误
                    if code == 401 {
                        // 处理授权错误，例如触发令牌刷新或登出流程
                        NotificationCenter.default.post(name: .unauthorized, object: nil)
                    }
                }
                
            case .failure(let error):
                // 处理网络或解码错误
                if let afError = error as? AFError {
                    switch afError {
                    case .responseSerializationFailed:
                        completion(.failure(.decodingError))
                    case .responseValidationFailed(let reason):
                        if case .unacceptableStatusCode(let code) = reason, code == 401 {
                            completion(.failure(.unauthorized))
                            // 触发未授权通知
                            NotificationCenter.default.post(name: .unauthorized, object: nil)
                        } else {
                            completion(.failure(.invalidResponse))
                        }
                    default:
                        completion(.failure(.networkError(afError)))
                    }
                } else {
                    completion(.failure(.unknown))
                }
            }
        }
    }
}

// 扩展通知名称
extension Notification.Name {
    static let unauthorized = Notification.Name("com.example.app.unauthorized")
}
```

### 模块化 API 客户端

将 API 服务划分为不同模块:

```swift
// 用户相关 API
class UserAPIClient {
    private let apiService: APIServiceProtocol
    
    init(apiService: APIServiceProtocol = APIService.shared) {
        self.apiService = apiService
    }
    
    // 获取用户列表
    func getUsers(page: Int, completion: @escaping (Result<[User], APIError>) -> Void) {
        let parameters: [String: Any] = ["page": page, "limit": 20]
        
        apiService.request(
            path: APIConstants.Path.users,
            method: .get,
            parameters: parameters,
            encoding: URLEncoding.default,
            headers: nil,
            completion: completion
        )
    }
    
    // 获取单个用户
    func getUser(id: Int, completion: @escaping (Result<User, APIError>) -> Void) {
        apiService.request(
            path: APIConstants.Path.user(id: id),
            method: .get,
            parameters: nil,
            encoding: URLEncoding.default,
            headers: nil,
            completion: completion
        )
    }
    
    // 创建用户
    func createUser(user: CreateUserRequest, completion: @escaping (Result<User, APIError>) -> Void) {
        // 使用 JSONEncoding 发送 JSON 数据
        apiService.request(
            path: APIConstants.Path.users,
            method: .post,
            parameters: user.dictionary,
            encoding: JSONEncoding.default,
            headers: nil,
            completion: completion
        )
    }
    
    // 更新用户
    func updateUser(id: Int, user: UpdateUserRequest, completion: @escaping (Result<User, APIError>) -> Void) {
        apiService.request(
            path: APIConstants.Path.user(id: id),
            method: .put,
            parameters: user.dictionary,
            encoding: JSONEncoding.default,
            headers: nil,
            completion: completion
        )
    }
    
    // 删除用户
    func deleteUser(id: Int, completion: @escaping (Result<EmptyResponse, APIError>) -> Void) {
        apiService.request(
            path: APIConstants.Path.user(id: id),
            method: .delete,
            parameters: nil,
            encoding: URLEncoding.default,
            headers: nil,
            completion: completion
        )
    }
}

// 认证相关 API
class AuthAPIClient {
    private let apiService: APIServiceProtocol
    
    init(apiService: APIServiceProtocol = APIService.shared) {
        self.apiService = apiService
    }
    
    // 登录
    func login(email: String, password: String, completion: @escaping (Result<AuthResponse, APIError>) -> Void) {
        let parameters: [String: Any] = [
            "email": email,
            "password": password
        ]
        
        apiService.request(
            path: APIConstants.Path.login,
            method: .post,
            parameters: parameters,
            encoding: JSONEncoding.default,
            headers: nil,
            completion: completion
        )
    }
    
    // 刷新令牌
    func refreshToken(refreshToken: String, completion: @escaping (Result<AuthResponse, APIError>) -> Void) {
        let parameters: [String: Any] = [
            "refresh_token": refreshToken
        ]
        
        apiService.request(
            path: "/auth/refresh",
            method: .post,
            parameters: parameters,
            encoding: JSONEncoding.default,
            headers: nil,
            completion: completion
        )
    }
}

// 帖子相关 API
class PostAPIClient {
    private let apiService: APIServiceProtocol
    
    init(apiService: APIServiceProtocol = APIService.shared) {
        self.apiService = apiService
    }
    
    // 获取所有帖子
    func getPosts(page: Int, completion: @escaping (Result<[Post], APIError>) -> Void) {
        let parameters: [String: Any] = ["page": page, "limit": 20]
        
        apiService.request(
            path: APIConstants.Path.posts,
            method: .get,
            parameters: parameters,
            encoding: URLEncoding.default,
            headers: nil,
            completion: completion
        )
    }
    
    // 获取用户的帖子
    func getUserPosts(userId: Int, completion: @escaping (Result<[Post], APIError>) -> Void) {
        apiService.request(
            path: APIConstants.Path.userPosts(userId: userId),
            method: .get,
            parameters: nil,
            encoding: URLEncoding.default,
            headers: nil,
            completion: completion
        )
    }
}

// 辅助类型
struct EmptyResponse: Decodable {}

// 模型扩展
extension Encodable {
    var dictionary: [String: Any]? {
        guard let data = try? JSONEncoder().encode(self) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data, options: .allowFragments)) as? [String: Any]
    }
}

// 请求模型
struct CreateUserRequest: Encodable {
    let name: String
    let email: String
    let password: String
}

struct UpdateUserRequest: Encodable {
    let name: String?
    let email: String?
}

// 响应模型
struct AuthResponse: Decodable {
    let token: String
    let refreshToken: String
    let expiresIn: Int
    let user: User
}

struct User: Decodable {
    let id: Int
    let name: String
    let email: String
    let createdAt: Date
}

struct Post: Decodable {
    let id: Int
    let userId: Int
    let title: String
    let body: String
    let createdAt: Date
}
```

### 网络层使用示例

在视图控制器或视图模型中使用网络层:

```swift
// 在视图控制器中使用
class UsersViewController: UIViewController {
    private let userAPIClient = UserAPIClient()
    private var users: [User] = []
    
    private lazy var tableView: UITableView = {
        let tableView = UITableView()
        tableView.dataSource = self
        tableView.delegate = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "UserCell")
        return tableView
    }()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.addSubview(tableView)
        // 设置约束...
        
        // 加载数据
        loadUsers()
    }
    
    private func loadUsers() {
        // 显示加载指示器
        let activityIndicator = UIActivityIndicatorView(style: .medium)
        activityIndicator.startAnimating()
        navigationItem.rightBarButtonItem = UIBarButtonItem(customView: activityIndicator)
        
        // 调用 API
        userAPIClient.getUsers(page: 1) { [weak self] result in
            guard let self = self else { return }
            
            // 隐藏加载指示器
            self.navigationItem.rightBarButtonItem = UIBarButtonItem(
                barButtonSystemItem: .refresh,
                target: self,
                action: #selector(self.refreshUsers)
            )
            
            // 处理结果
            switch result {
            case .success(let users):
                self.users = users
                self.tableView.reloadData()
                
            case .failure(let error):
                self.showError(error.localizedDescription)
            }
        }
    }
    
    @objc private func refreshUsers() {
        loadUsers()
    }
    
    private func showError(_ message: String) {
        let alert = UIAlertController(title: "错误", message: message, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: "确定", style: .default))
        present(alert, animated: true)
    }
}

extension UsersViewController: UITableViewDataSource, UITableViewDelegate {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return users.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "UserCell", for: indexPath)
        let user = users[indexPath.row]
        
        cell.textLabel?.text = user.name
        cell.detailTextLabel?.text = user.email
        
        return cell
    }
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        
        let userId = users[indexPath.row].id
        let userDetailVC = UserDetailViewController(userId: userId)
        navigationController?.pushViewController(userDetailVC, animated: true)
    }
}

// 在视图模型中使用 (MVVM 架构)
class UserListViewModel {
    private let userAPIClient = UserAPIClient()
    
    // 可观察属性 (可以使用 Combine 或其他响应式框架)
    var users: [User] = [] {
        didSet {
            onUsersUpdated?(users)
        }
    }
    
    var isLoading = false {
        didSet {
            onLoadingStateChanged?(isLoading)
        }
    }
    
    var error: String? {
        didSet {
            onErrorChanged?(error)
        }
    }
    
    // 回调
    var onUsersUpdated: (([User]) -> Void)?
    var onLoadingStateChanged: ((Bool) -> Void)?
    var onErrorChanged: ((String?) -> Void)?
    
    // 加载用户
    func loadUsers(page: Int = 1) {
        isLoading = true
        error = nil
        
        userAPIClient.getUsers(page: page) { [weak self] result in
            guard let self = self else { return }
            
            self.isLoading = false
            
            switch result {
            case .success(let users):
                self.users = users
                
            case .failure(let apiError):
                self.error = apiError.localizedDescription
            }
        }
    }
    
    // 创建用户
    func createUser(name: String, email: String, password: String) {
        isLoading = true
        error = nil
        
        let request = CreateUserRequest(name: name, email: email, password: password)
        
        userAPIClient.createUser(user: request) { [weak self] result in
            guard let self = self else { return }
            
            self.isLoading = false
            
            switch result {
            case .success(let user):
                // 添加新用户到列表
                var updatedUsers = self.users
                updatedUsers.append(user)
                self.users = updatedUsers
                
            case .failure(let apiError):
                self.error = apiError.localizedDescription
            }
        }
    }
}
```

### 使用依赖注入提高可测试性

通过依赖注入使网络层更易于测试:

```swift
// 使用协议和依赖注入
protocol UserAPIClientProtocol {
    func getUsers(page: Int, completion: @escaping (Result<[User], APIError>) -> Void)
    func getUser(id: Int, completion: @escaping (Result<User, APIError>) -> Void)
    func createUser(user: CreateUserRequest, completion: @escaping (Result<User, APIError>) -> Void)
    func updateUser(id: Int, user: UpdateUserRequest, completion: @escaping (Result<User, APIError>) -> Void)
    func deleteUser(id: Int, completion: @escaping (Result<EmptyResponse, APIError>) -> Void)
}

// 实现实际的客户端
class UserAPIClient: UserAPIClientProtocol {
    private let apiService: APIServiceProtocol
    
    init(apiService: APIServiceProtocol = APIService.shared) {
        self.apiService = apiService
    }
    
    // 实现方法...
}

// 视图模型使用协议而非具体实现
class UserListViewModel {
    private let userAPIClient: UserAPIClientProtocol
    
    init(userAPIClient: UserAPIClientProtocol = UserAPIClient()) {
        self.userAPIClient = userAPIClient
    }
    
    // 实现方法...
}

// 创建模拟客户端用于测试
class MockUserAPIClient: UserAPIClientProtocol {
    var mockUsers: [User] = [
        User(id: 1, name: "测试用户1", email: "test1@example.com", createdAt: Date()),
        User(id: 2, name: "测试用户2", email: "test2@example.com", createdAt: Date())
    ]
    
    var shouldFailGetUsers = false
    var shouldFailGetUser = false
    
    func getUsers(page: Int, completion: @escaping (Result<[User], APIError>) -> Void) {
        if shouldFailGetUsers {
            completion(.failure(.networkError(NSError(domain: "Test", code: -1, userInfo: nil))))
        } else {
            completion(.success(mockUsers))
        }
    }
    
    func getUser(id: Int, completion: @escaping (Result<User, APIError>) -> Void) {
        if shouldFailGetUser {
            completion(.failure(.networkError(NSError(domain: "Test", code: -1, userInfo: nil))))
        } else if let user = mockUsers.first(where: { $0.id == id }) {
            completion(.success(user))
        } else {
            completion(.failure(.serverError(message: "User not found", code: 404)))
        }
    }
    
    func createUser(user: CreateUserRequest, completion: @escaping (Result<User, APIError>) -> Void) {
        let newUser = User(id: mockUsers.count + 1, name: user.name, email: user.email, createdAt: Date())
        mockUsers.append(newUser)
        completion(.success(newUser))
    }
    
    func updateUser(id: Int, user: UpdateUserRequest, completion: @escaping (Result<User, APIError>) -> Void) {
        if let index = mockUsers.firstIndex(where: { $0.id == id }) {
            var updatedUser = mockUsers[index]
            if let name = user.name {
                // 在实际情况下，这里应该创建一个新的 User 实例，而不是修改现有实例
                // 这里简化处理
                updatedUser = User(id: id, name: name, email: updatedUser.email, createdAt: updatedUser.createdAt)
            }
            mockUsers[index] = updatedUser
            completion(.success(updatedUser))
        } else {
            completion(.failure(.serverError(message: "User not found", code: 404)))
        }
    }
    
    func deleteUser(id: Int, completion: @escaping (Result<EmptyResponse, APIError>) -> Void) {
        if let index = mockUsers.firstIndex(where: { $0.id == id }) {
            mockUsers.remove(at: index)
            completion(.success(EmptyResponse()))
        } else {
            completion(.failure(.serverError(message: "User not found", code: 404)))
        }
    }
}
``` 

## 最佳实践

以下是使用 Alamofire 的一些最佳实践，帮助你构建更健壮、高效的网络层。

### 性能优化

```swift
// 1. 使用共享会话实例而非每次创建新实例
let session = Session.default

// 2. 使用请求缓存
let configuration = URLSessionConfiguration.default
configuration.requestCachePolicy = .returnCacheDataElseLoad
let cachedSession = Session(configuration: configuration)

// 3. 使用后台会话处理大文件
let backgroundConfiguration = URLSessionConfiguration.background(withIdentifier: "com.example.background")
let backgroundSession = Session(configuration: backgroundConfiguration)

// 4. 批量请求处理
func performBatchRequests() {
    let requestGroup = DispatchGroup()
    var results: [String: Any] = [:]
    
    // 请求1
    requestGroup.enter()
    AF.request("https://api.example.com/users").responseDecodable(of: [User].self) { response in
        if let users = response.value {
            results["users"] = users
        }
        requestGroup.leave()
    }
    
    // 请求2
    requestGroup.enter()
    AF.request("https://api.example.com/posts").responseDecodable(of: [Post].self) { response in
        if let posts = response.value {
            results["posts"] = posts
        }
        requestGroup.leave()
    }
    
    // 所有请求完成后处理结果
    requestGroup.notify(queue: .main) {
        print("所有请求已完成: \(results)")
    }
}
```

### 错误处理

```swift
// 1. 一致的错误处理
enum NetworkError: Error {
    case invalidURL
    case requestFailed(Error)
    case invalidResponse
    case decodingFailed
    case serverError(statusCode: Int, message: String)
    case unauthorized
    case connectionError
    
    var errorMessage: String {
        switch self {
        case .invalidURL:
            return "无效的URL"
        case .requestFailed(let error):
            return "请求失败: \(error.localizedDescription)"
        case .invalidResponse:
            return "无效的服务器响应"
        case .decodingFailed:
            return "响应解析失败"
        case .serverError(let statusCode, let message):
            return "服务器错误 \(statusCode): \(message)"
        case .unauthorized:
            return "未授权，请重新登录"
        case .connectionError:
            return "网络连接错误，请检查网络设置"
        }
    }
}

// 2. 将 AFError 转换为自定义错误
func handleAFError(_ error: AFError) -> NetworkError {
    switch error {
    case .invalidURL:
        return .invalidURL
    case .responseValidationFailed(let reason):
        if case .unacceptableStatusCode(let code) = reason {
            if code == 401 {
                return .unauthorized
            } else {
                return .serverError(statusCode: code, message: "请求验证失败")
            }
        }
        return .invalidResponse
    case .responseSerializationFailed:
        return .decodingFailed
    case .sessionTaskFailed(let error):
        if let urlError = error as? URLError {
            if urlError.code == .notConnectedToInternet || urlError.code == .networkConnectionLost {
                return .connectionError
            }
        }
        return .requestFailed(error)
    default:
        return .requestFailed(error)
    }
}

// 3. 集中处理错误显示
func showErrorAlert(for error: NetworkError, on viewController: UIViewController) {
    let alert = UIAlertController(
        title: "错误",
        message: error.errorMessage,
        preferredStyle: .alert
    )
    alert.addAction(UIAlertAction(title: "确定", style: .default))
    
    // 对特定错误执行额外操作
    if case .unauthorized = error {
        // 登出用户
        UserSession.shared.logout()
        
        // 添加登录选项
        alert.addAction(UIAlertAction(title: "登录", style: .default) { _ in
            let loginVC = LoginViewController()
            viewController.present(loginVC, animated: true)
        })
    }
    
    viewController.present(alert, animated: true)
}
```

### 安全最佳实践

```swift
// 1. 配置证书固定增强安全性
let certificates = [
    SecCertificateCreateWithData(nil, NSData(contentsOf: Bundle.main.url(forResource: "certificate", withExtension: "der")!)!)!
]

let trustManager = ServerTrustManager(evaluators: [
    "api.example.com": PinnedCertificatesTrustEvaluator(certificates: certificates)
])

let secureSession = Session(serverTrustManager: trustManager)

// 2. 安全存储敏感信息
import KeychainAccess

class TokenManager {
    private let keychain = Keychain(service: "com.example.app")
    
    func saveToken(_ token: String) {
        do {
            try keychain.set(token, key: "auth_token")
        } catch {
            print("保存令牌失败: \(error)")
        }
    }
    
    func getToken() -> String? {
        do {
            return try keychain.get("auth_token")
        } catch {
            print("获取令牌失败: \(error)")
            return nil
        }
    }
    
    func deleteToken() {
        do {
            try keychain.remove("auth_token")
        } catch {
            print("删除令牌失败: \(error)")
        }
    }
}

// 3. 安全地添加认证头
func addAuthorizationHeader(_ request: inout URLRequest) {
    if let token = TokenManager().getToken() {
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    }
}
```

### 测试策略

```swift
// 1. 使用依赖注入实现可测试性
protocol NetworkServiceProtocol {
    func fetch<T: Decodable>(url: URL, completion: @escaping (Result<T, NetworkError>) -> Void)
}

class NetworkService: NetworkServiceProtocol {
    func fetch<T: Decodable>(url: URL, completion: @escaping (Result<T, NetworkError>) -> Void) {
        AF.request(url).responseDecodable(of: T.self) { response in
            switch response.result {
            case .success(let value):
                completion(.success(value))
            case .failure(let error):
                completion(.failure(handleAFError(error)))
            }
        }
    }
}

// 2. 创建模拟网络服务进行测试
class MockNetworkService: NetworkServiceProtocol {
    var mockResult: Result<Any, NetworkError>?
    
    func fetch<T: Decodable>(url: URL, completion: @escaping (Result<T, NetworkError>) -> Void) {
        guard let mockResult = mockResult else {
            completion(.failure(.invalidResponse))
            return
        }
        
        switch mockResult {
        case .success(let value):
            if let value = value as? T {
                completion(.success(value))
            } else {
                completion(.failure(.decodingFailed))
            }
        case .failure(let error):
            completion(.failure(error))
        }
    }
}

// 3. 单元测试示例
/*
func testUserFetch() {
    // 设置
    let expectation = XCTestExpectation(description: "Fetch users")
    let mockService = MockNetworkService()
    let mockUsers = [User(id: 1, name: "Test")]
    mockService.mockResult = .success(mockUsers)
    
    let userRepository = UserRepository(networkService: mockService)
    
    // 执行
    userRepository.getUsers { result in
        // 验证
        switch result {
        case .success(let users):
            XCTAssertEqual(users.count, 1)
            XCTAssertEqual(users[0].name, "Test")
        case .failure:
            XCTFail("应该返回成功结果")
        }
        expectation.fulfill()
    }
    
    wait(for: [expectation], timeout: 1.0)
}
*/
```

### 代码组织

```swift
// 1. 使用扩展将相关功能分组
extension NetworkService {
    // 用户相关请求
    func getUsers(completion: @escaping (Result<[User], NetworkError>) -> Void) {
        // 实现...
    }
    
    func getUser(id: Int, completion: @escaping (Result<User, NetworkError>) -> Void) {
        // 实现...
    }
}

extension NetworkService {
    // 帖子相关请求
    func getPosts(completion: @escaping (Result<[Post], NetworkError>) -> Void) {
        // 实现...
    }
    
    func createPost(post: Post, completion: @escaping (Result<Post, NetworkError>) -> Void) {
        // 实现...
    }
}

// 2. 使用类型别名简化代码
typealias NetworkCompletion<T> = (Result<T, NetworkError>) -> Void
typealias JSON = [String: Any]
typealias Parameters = [String: Any]

// 3. 将常量集中管理
enum API {
    static let baseURL = "https://api.example.com"
    
    enum Endpoints {
        static let users = "/users"
        static let posts = "/posts"
        static let login = "/auth/login"
        
        static func user(id: Int) -> String { return "\(users)/\(id)" }
        static func userPosts(userId: Int) -> String { return "\(user(id: userId))/posts" }
    }
    
    enum Headers {
        static let contentType = "Content-Type"
        static let authorization = "Authorization"
        static let accept = "Accept"
    }
    
    enum ContentType {
        static let json = "application/json"
        static let formUrlEncoded = "application/x-www-form-urlencoded"
        static let multipartFormData = "multipart/form-data"
    }
}
```

### 通用提示

1. **设置合理的超时时间**：为不同类型的请求设置适当的超时时间。

2. **实现网络可达性监控**：在网络状态变化时更新 UI 或暂停/恢复操作。

3. **使用 URLRequestConvertible 协议**：创建强类型请求构建器。

4. **添加请求重试机制**：尤其是对于关键请求，配置重试策略。

5. **日志记录与调试**：在开发环境中记录请求和响应详情。

6. **避免硬编码**：使用配置文件或环境变量来管理 API 地址等关键参数。

7. **处理并发**：当多个请求需要协调或合并结果时，使用 DispatchGroup。

8. **考虑使用 Alamofire 插件**：如 AlamofireNetworkActivityIndicator、AlamofireImage 等。

9. **设置全局默认值**：为常用参数和头部设置合理的默认值。

10. **通过抽象隔离 Alamofire**：不要在整个代码库中直接使用 Alamofire，而是通过自己的抽象层来使用它，这样可以更容易地替换或升级网络层。
```

## 与 Combine 集成

Alamofire 可以与 Swift 的 Combine 框架集成，提供响应式编程体验。

```swift
import Combine
import Alamofire

extension DataRequest {
    func publishDecodable<T: Decodable>(type: T.Type = T.self, decoder: JSONDecoder = JSONDecoder()) -> AnyPublisher<T, AFError> {
        return responseDecodable(of: type, decoder: decoder)
            .publishDecodable()
    }
    
    func publishDecodable<T: Decodable>(type: T.Type = T.self, queue: DispatchQueue = .main, decoder: JSONDecoder = JSONDecoder()) -> AnyPublisher<T, AFError> {
        return Publishers.DataResponsePublisher(request: self, responseSerializer: DecodableResponseSerializer(decoder: decoder))
            .receive(on: queue)
            .map(\.value)
            .eraseToAnyPublisher()
    }
}

// 使用 Combine 发起请求
class UserService {
    private var cancellables = Set<AnyCancellable>()
    
    func fetchUsers() -> AnyPublisher<[User], AFError> {
        return AF.request("https://api.example.com/users")
            .publishDecodable(type: [User].self)
            .eraseToAnyPublisher()
    }
    
    func fetchUser(id: Int) -> AnyPublisher<User, AFError> {
        return AF.request("https://api.example.com/users/\(id)")
            .publishDecodable(type: User.self)
            .eraseToAnyPublisher()
    }
    
    // 使用示例
    func loadUsers() {
        fetchUsers()
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    print("请求完成")
                case .failure(let error):
                    print("请求失败: \(error)")
                }
            }, receiveValue: { users in
                print("获取到 \(users.count) 个用户")
            })
            .store(in: &cancellables)
    }
    
    // 组合多个请求
    func loadUserAndPosts(userId: Int) {
        // 先获取用户信息
        let userPublisher = fetchUser(id: userId)
        
        // 然后获取用户的帖子
        let postsPublisher = userPublisher
            .flatMap { user -> AnyPublisher<[Post], AFError> in
                print("获取用户 \(user.name) 的帖子")
                return AF.request("https://api.example.com/users/\(user.id)/posts")
                    .publishDecodable(type: [Post].self)
                    .eraseToAnyPublisher()
            }
        
        // 组合结果
        Publishers.Zip(userPublisher, postsPublisher)
            .sink(receiveCompletion: { completion in
                switch completion {
                case .finished:
                    print("所有请求完成")
                case .failure(let error):
                    print("请求失败: \(error)")
                }
            }, receiveValue: { (user, posts) in
                print("用户: \(user.name), 帖子数: \(posts.count)")
            })
            .store(in: &cancellables)
    }
}
```

## 与 async/await 集成

iOS 15 及更高版本支持使用 async/await 进行异步编程，可以与 Alamofire 结合使用。

```swift
// 扩展 Alamofire 以支持 async/await
extension DataRequest {
    func serializingDecodable<T: Decodable>(_ type: T.Type = T.self, decoder: JSONDecoder = JSONDecoder()) async throws -> T {
        return try await withCheckedThrowingContinuation { continuation in
            responseDecodable(of: type, decoder: decoder) { response in
                switch response.result {
                case .success(let value):
                    continuation.resume(returning: value)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}

// 使用 async/await 的网络服务
@available(iOS 15.0, *)
class AsyncNetworkService {
    // 获取用户列表
    func getUsers() async throws -> [User] {
        return try await AF.request("https://api.example.com/users")
            .serializingDecodable([User].self)
    }
    
    // 获取用户详情
    func getUser(id: Int) async throws -> User {
        return try await AF.request("https://api.example.com/users/\(id)")
            .serializingDecodable(User.self)
    }
    
    // 创建用户
    func createUser(name: String, email: String) async throws -> User {
        let parameters: [String: String] = [
            "name": name,
            "email": email
        ]
        
        return try await AF.request("https://api.example.com/users",
                            method: .post,
                            parameters: parameters,
                            encoder: JSONParameterEncoder.default)
            .serializingDecodable(User.self)
    }
    
    // 并发获取多个资源
    func getUserWithPosts(userId: Int) async throws -> (user: User, posts: [Post]) {
        // 使用 async let 并发执行多个请求
        async let user = getUser(id: userId)
        async let posts = getPosts(userId: userId)
        
        // 等待所有请求完成并返回结果
        return try await (user: user, posts: posts)
    }
    
    // 获取用户帖子
    func getPosts(userId: Int) async throws -> [Post] {
        return try await AF.request("https://api.example.com/users/\(userId)/posts")
            .serializingDecodable([Post].self)
    }
}

// 在 SwiftUI 视图中使用
@available(iOS 15.0, *)
struct UserListView: View {
    @State private var users: [User] = []
    @State private var isLoading = false
    @State private var errorMessage: String?
    
    private let networkService = AsyncNetworkService()
    
    var body: some View {
        NavigationView {
            Group {
                if isLoading {
                    ProgressView("加载中...")
                } else if let errorMessage = errorMessage {
                    Text("错误: \(errorMessage)")
                        .foregroundColor(.red)
                } else {
                    List(users) { user in
                        NavigationLink(destination: UserDetailView(userId: user.id)) {
                            Text(user.name)
                        }
                    }
                }
            }
            .navigationTitle("用户列表")
            .task {
                await loadUsers()
            }
            .refreshable {
                await loadUsers()
            }
        }
    }
    
    private func loadUsers() async {
        isLoading = true
        errorMessage = nil
        
        do {
            users = try await networkService.getUsers()
        } catch {
            errorMessage = error.localizedDescription
        }
        
        isLoading = false
    }
}

// 处理多个并发请求
@available(iOS 15.0, *)
struct DashboardView: View {
    @State private var users: [User] = []
    @State private var posts: [Post] = []
    @State private var comments: [Comment] = []
    @State private var isLoading = false
    @State private var errorMessage: String?
    
    private let networkService = AsyncNetworkService()
    
    var body: some View {
        VStack {
            // 视图内容...
        }
        .task {
            await loadDashboard()
        }
    }
    
    private func loadDashboard() async {
        isLoading = true
        errorMessage = nil
        
        do {
            // 并发执行多个请求
            async let usersTask = networkService.getUsers()
            async let postsTask = AF.request("https://api.example.com/posts").serializingDecodable([Post].self)
            async let commentsTask = AF.request("https://api.example.com/comments").serializingDecodable([Comment].self)
            
            // 等待所有请求完成
            let (fetchedUsers, fetchedPosts, fetchedComments) = try await (usersTask, postsTask, commentsTask)
            
            // 更新状态
            self.users = fetchedUsers
            self.posts = fetchedPosts
            self.comments = fetchedComments
        } catch {
            errorMessage = "加载数据失败: \(error.localizedDescription)"
        }
        
        isLoading = false
    }
}
```

## 迁移指南

从较旧版本的 Alamofire 迁移到最新版本的建议。

### 从 Alamofire 4.x 迁移到 5.x

Alamofire 5 引入了许多重大变化：

1. **请求创建**：
   ```swift
   // Alamofire 4
   Alamofire.request("https://api.example.com", method: .get, parameters: ["foo": "bar"], encoding: URLEncoding.default, headers: ["Authorization": "Bearer token"])
   
   // Alamofire 5
   AF.request("https://api.example.com", method: .get, parameters: ["foo": "bar"], encoder: URLEncodedFormParameterEncoder.default, headers: ["Authorization": "Bearer token"])
   ```

2. **响应处理**：
   ```swift
   // Alamofire 4
   Alamofire.request("https://api.example.com").responseJSON { response in
       if let json = response.result.value {
           print(json)
       }
   }
   
   // Alamofire 5
   AF.request("https://api.example.com").responseJSON { response in
       if let json = response.value {
           print(json)
       }
   }
   ```

3. **结果处理**：
   ```swift
   // Alamofire 4
   if case .success(let value) = response.result {
       print(value)
   }
   
   // Alamofire 5
   switch response.result {
   case .success(let value):
       print(value)
   case .failure(let error):
       print(error)
   }
   ```

4. **验证**：
   ```swift
   // Alamofire 4
   Alamofire.request("https://api.example.com").validate().responseJSON { response in
       // 处理响应
   }
   
   // Alamofire 5 (基本相同)
   AF.request("https://api.example.com").validate().responseJSON { response in
       // 处理响应
   }
   ```

5. **参数编码**：
   ```swift
   // Alamofire 4
   Alamofire.request("https://api.example.com", parameters: params, encoding: JSONEncoding.default)
   
   // Alamofire 5
   AF.request("https://api.example.com", parameters: params, encoder: JSONParameterEncoder.default)
   ```

6. **认证**：
   ```swift
   // Alamofire 4
   let credential = URLCredential(user: username, password: password, persistence: .forSession)
   Alamofire.request("https://api.example.com").authenticate(usingCredential: credential)
   
   // Alamofire 5
   let credential = URLCredential(user: username, password: password, persistence: .forSession)
   AF.request("https://api.example.com").authenticate(with: credential)
   ```

7. **会话管理**：
   ```swift
   // Alamofire 4
   let manager = SessionManager.default
   
   // Alamofire 5
   let session = Session.default
   ```

8. **请求适配器**：
   ```swift
   // Alamofire 4
   class RequestAdapter: RequestAdapter {
       func adapt(_ urlRequest: URLRequest) throws -> URLRequest {
           var urlRequest = urlRequest
           urlRequest.setValue("value", forHTTPHeaderField: "field")
           return urlRequest
       }
   }
   
   // Alamofire 5
   class RequestAdapter: RequestAdapter {
       func adapt(_ urlRequest: URLRequest, for session: Session, completion: @escaping (Result<URLRequest, Error>) -> Void) {
           var urlRequest = urlRequest
           urlRequest.setValue("value", forHTTPHeaderField: "field")
           completion(.success(urlRequest))
       }
   }
   ```

### 一般迁移建议

1. **逐步迁移**：对于大型项目，考虑逐步迁移而不是一次性重写所有网络代码。

2. **使用抽象层**：通过封装 Alamofire 调用，可以使迁移对应用程序代码的影响最小化。

3. **更新依赖项**：确保所有依赖于 Alamofire 的库都与新版本兼容。

4. **全面测试**：迁移后进行彻底的测试，确保所有网络功能正常工作。

5. **利用新特性**：迁移时考虑利用新版本的改进功能，如 Combine 集成和 async/await 支持。