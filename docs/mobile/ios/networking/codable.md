# Codable

Codable 是 Swift 中用于数据编码和解码的协议，它极大地简化了 JSON 处理和对象序列化。本文档将介绍 Codable 的基本用法和常见场景。

## 目录

- [基本概念](#基本概念)
- [基本用法](#基本用法)
- [自定义编码与解码](#自定义编码与解码)
- [处理复杂 JSON](#处理复杂-json)
- [实用技巧](#实用技巧)
- [常见问题](#常见问题)

## 基本概念

Codable 是 `Encodable` 和 `Decodable` 协议的组合：

- **Encodable**: 可以将类型实例编码为外部表示形式（如 JSON）
- **Decodable**: 可以从外部表示形式（如 JSON）创建类型实例
- **Codable**: 同时符合 Encodable 和 Decodable

Swift 的许多基本类型都已符合 Codable 协议，包括：
- String, Int, Double, Bool
- Date, Data, URL
- Array, Dictionary, Optional（当其元素类型符合 Codable 时）

## 基本用法

### 定义 Codable 模型

```swift
// 简单的 Codable 结构体
struct User: Codable {
    let id: Int
    let name: String
    let email: String
    let isActive: Bool
    let createdAt: Date
}
```

### JSON 解码

```swift
// JSON 数据
let jsonString = """
{
    "id": 1,
    "name": "张三",
    "email": "zhangsan@example.com",
    "isActive": true,
    "createdAt": "2023-06-15T10:30:00Z"
}
"""
let jsonData = jsonString.data(using: .utf8)!

// 创建解码器
let decoder = JSONDecoder()

// 配置日期解码策略
decoder.dateDecodingStrategy = .iso8601

do {
    // 解码 JSON 数据
    let user = try decoder.decode(User.self, from: jsonData)
    print("解码成功: \(user.name), ID: \(user.id)")
} catch {
    print("解码失败: \(error)")
}
```

### JSON 编码

```swift
// 创建对象
let user = User(
    id: 2,
    name: "李四",
    email: "lisi@example.com",
    isActive: true,
    createdAt: Date()
)

// 创建编码器
let encoder = JSONEncoder()

// 配置日期编码策略
encoder.dateEncodingStrategy = .iso8601

// 配置输出格式
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

do {
    // 编码为 JSON 数据
    let jsonData = try encoder.encode(user)
    
    // 转换为字符串
    if let jsonString = String(data: jsonData, encoding: .utf8) {
        print("编码成功:\n\(jsonString)")
    }
} catch {
    print("编码失败: \(error)")
}
```

## 自定义编码与解码

### 自定义键名映射

当 JSON 键名与 Swift 属性名不匹配时：

```swift
struct Employee: Codable {
    let id: Int
    let fullName: String
    let emailAddress: String
    
    // 定义 CodingKeys 枚举来映射属性名与 JSON 键名
    enum CodingKeys: String, CodingKey {
        case id
        case fullName = "full_name"
        case emailAddress = "email"
    }
}

// 解码示例
let jsonString = """
{
    "id": 101,
    "full_name": "王五",
    "email": "wangwu@example.com"
}
"""
let jsonData = jsonString.data(using: .utf8)!

do {
    let employee = try JSONDecoder().decode(Employee.self, from: jsonData)
    print("解码成功: \(employee.fullName), 邮箱: \(employee.emailAddress)")
} catch {
    print("解码失败: \(error)")
}
```

### 自定义编码实现

当需要更复杂的编码/解码逻辑时：

```swift
struct Product: Codable {
    let id: Int
    let name: String
    let price: Double
    let tags: [String]
    let releaseDate: Date
    
    // 自定义解码
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        // 基本解码
        id = try container.decode(Int.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        
        // 价格可能是字符串或数字
        if let priceString = try? container.decode(String.self, forKey: .price) {
            price = Double(priceString) ?? 0.0
        } else {
            price = try container.decode(Double.self, forKey: .price)
        }
        
        // 标签可能是单个字符串或数组
        if let singleTag = try? container.decode(String.self, forKey: .tags) {
            tags = [singleTag]
        } else {
            tags = try container.decode([String].self, forKey: .tags)
        }
        
        // 日期解码
        let dateString = try container.decode(String.self, forKey: .releaseDate)
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        
        if let date = formatter.date(from: dateString) {
            releaseDate = date
        } else {
            throw DecodingError.dataCorruptedError(
                forKey: .releaseDate,
                in: container,
                debugDescription: "Date format incorrect"
            )
        }
    }
    
    // 自定义编码
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(price, forKey: .price)
        try container.encode(tags, forKey: .tags)
        
        // 日期编码
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        let dateString = formatter.string(from: releaseDate)
        try container.encode(dateString, forKey: .releaseDate)
    }
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case price
        case tags
        case releaseDate = "release_date"
    }
}
```

## 处理复杂 JSON

### 嵌套对象

```swift
// 嵌套结构
struct Company: Codable {
    let name: String
    let address: Address
    let employees: [Employee]
    
    struct Address: Codable {
        let street: String
        let city: String
        let zipCode: String
        
        enum CodingKeys: String, CodingKey {
            case street
            case city
            case zipCode = "zip_code"
        }
    }
    
    struct Employee: Codable {
        let id: Int
        let name: String
        let role: String
    }
}

// 使用示例
let jsonString = """
{
    "name": "科技有限公司",
    "address": {
        "street": "科技路123号",
        "city": "北京",
        "zip_code": "100000"
    },
    "employees": [
        {
            "id": 1,
            "name": "张三",
            "role": "开发者"
        },
        {
            "id": 2,
            "name": "李四",
            "role": "设计师"
        }
    ]
}
"""
let jsonData = jsonString.data(using: .utf8)!

do {
    let company = try JSONDecoder().decode(Company.self, from: jsonData)
    print("公司: \(company.name)")
    print("地址: \(company.address.city)")
    print("员工数量: \(company.employees.count)")
} catch {
    print("解码失败: \(error)")
}
```

### 动态键

处理键名不固定的 JSON：

```swift
struct DynamicResponse: Codable {
    let success: Bool
    let timestamp: Date
    let data: [String: AnyValue]
    
    // 泛型值容器
    struct AnyValue: Codable {
        let value: Any
        
        init(_ value: Any) {
            self.value = value
        }
        
        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            
            if let value = try? container.decode(String.self) {
                self.value = value
            } else if let value = try? container.decode(Int.self) {
                self.value = value
            } else if let value = try? container.decode(Double.self) {
                self.value = value
            } else if let value = try? container.decode(Bool.self) {
                self.value = value
            } else if let value = try? container.decode([String].self) {
                self.value = value
            } else if let value = try? container.decode([String: String].self) {
                self.value = value
            } else if container.decodeNil() {
                self.value = NSNull()
            } else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Cannot decode value"
                )
            }
        }
        
        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            
            switch value {
            case let value as String:
                try container.encode(value)
            case let value as Int:
                try container.encode(value)
            case let value as Double:
                try container.encode(value)
            case let value as Bool:
                try container.encode(value)
            case let value as [String]:
                try container.encode(value)
            case let value as [String: String]:
                try container.encode(value)
            case is NSNull:
                try container.encodeNil()
            default:
                throw EncodingError.invalidValue(
                    value,
                    EncodingError.Context(
                        codingPath: container.codingPath,
                        debugDescription: "Cannot encode value"
                    )
                )
            }
        }
    }
}

// 使用示例
let jsonString = """
{
    "success": true,
    "timestamp": "2023-06-15T10:30:00Z",
    "data": {
        "user_count": 125,
        "is_premium": true,
        "app_name": "我的应用",
        "recent_users": ["张三", "李四", "王五"],
        "settings": {
            "theme": "dark",
            "language": "zh-CN"
        }
    }
}
"""
let jsonData = jsonString.data(using: .utf8)!

let decoder = JSONDecoder()
decoder.dateDecodingStrategy = .iso8601

do {
    let response = try decoder.decode(DynamicResponse.self, from: jsonData)
    
    // 访问动态值
    if let userCount = response.data["user_count"]?.value as? Int {
        print("用户数量: \(userCount)")
    }
    
    if let isPremium = response.data["is_premium"]?.value as? Bool {
        print("是否高级版: \(isPremium)")
    }
    
    if let recentUsers = response.data["recent_users"]?.value as? [String] {
        print("最近用户: \(recentUsers.joined(separator: ", "))")
    }
} catch {
    print("解码失败: \(error)")
}
```

### 多态类型

处理可能有不同类型的字段：

```swift
// 使用枚举处理多态类型
enum MediaItem: Codable {
    case image(url: URL, width: Int, height: Int)
    case video(url: URL, duration: Double)
    case audio(url: URL, duration: Double, artist: String)
    
    // 类型标识符
    enum MediaType: String, Codable {
        case image
        case video
        case audio
    }
    
    // 编码/解码键
    enum CodingKeys: String, CodingKey {
        case type
        case url
        case width
        case height
        case duration
        case artist
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(MediaType.self, forKey: .type)
        let url = try container.decode(URL.self, forKey: .url)
        
        switch type {
        case .image:
            let width = try container.decode(Int.self, forKey: .width)
            let height = try container.decode(Int.self, forKey: .height)
            self = .image(url: url, width: width, height: height)
            
        case .video:
            let duration = try container.decode(Double.self, forKey: .duration)
            self = .video(url: url, duration: duration)
            
        case .audio:
            let duration = try container.decode(Double.self, forKey: .duration)
            let artist = try container.decode(String.self, forKey: .artist)
            self = .audio(url: url, duration: duration, artist: artist)
        }
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        switch self {
        case .image(let url, let width, let height):
            try container.encode(MediaType.image, forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encode(width, forKey: .width)
            try container.encode(height, forKey: .height)
            
        case .video(let url, let duration):
            try container.encode(MediaType.video, forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encode(duration, forKey: .duration)
            
        case .audio(let url, let duration, let artist):
            try container.encode(MediaType.audio, forKey: .type)
            try container.encode(url, forKey: .url)
            try container.encode(duration, forKey: .duration)
            try container.encode(artist, forKey: .artist)
        }
    }
}

// 使用示例
let jsonArray = """
[
    {
        "type": "image",
        "url": "https://example.com/image1.jpg",
        "width": 800,
        "height": 600
    },
    {
        "type": "video",
        "url": "https://example.com/video1.mp4",
        "duration": 120.5
    },
    {
        "type": "audio",
        "url": "https://example.com/song.mp3",
        "duration": 240.8,
        "artist": "某艺术家"
    }
]
"""
let jsonData = jsonArray.data(using: .utf8)!

do {
    let mediaItems = try JSONDecoder().decode([MediaItem].self, from: jsonData)
    
    for (index, item) in mediaItems.enumerated() {
        switch item {
        case .image(let url, let width, let height):
            print("图片 \(index): \(url), 尺寸: \(width)x\(height)")
            
        case .video(let url, let duration):
            print("视频 \(index): \(url), 时长: \(duration)秒")
            
        case .audio(let url, let duration, let artist):
            print("音频 \(index): \(url), 时长: \(duration)秒, 艺术家: \(artist)")
        }
    }
} catch {
    print("解码失败: \(error)")
}
```

## 实用技巧

### 键名策略

处理不同的 JSON 命名风格：

```swift
struct Product: Codable {
    let productId: Int
    let productName: String
    let productDescription: String
    let unitPrice: Double
    let isAvailable: Bool
}

// JSON 使用蛇形命名法 (snake_case)
let jsonString = """
{
    "product_id": 123,
    "product_name": "智能手表",
    "product_description": "先进的智能手表，支持多种运动模式",
    "unit_price": 1299.99,
    "is_available": true
}
"""
let jsonData = jsonString.data(using: .utf8)!

let decoder = JSONDecoder()
// 设置键名解码策略
decoder.keyDecodingStrategy = .convertFromSnakeCase

do {
    let product = try decoder.decode(Product.self, from: jsonData)
    print("产品: \(product.productName), 价格: \(product.unitPrice)")
} catch {
    print("解码失败: \(error)")
}

// 编码为蛇形命名法
let encoder = JSONEncoder()
encoder.keyEncodingStrategy = .convertToSnakeCase

do {
    let product = Product(
        productId: 456,
        productName: "无线耳机",
        productDescription: "高品质无线耳机，降噪效果好",
        unitPrice: 899.99,
        isAvailable: true
    )
    
    let encodedData = try encoder.encode(product)
    if let encodedString = String(data: encodedData, encoding: .utf8) {
        print("编码后的 JSON:\n\(encodedString)")
    }
} catch {
    print("编码失败: \(error)")
}
```

### 忽略属性

```swift
struct User: Codable {
    let id: Int
    let username: String
    let email: String
    
    // 不参与编码/解码的属性
    var lastLoginDate: Date?
    var sessionToken: String?
    
    // 使用 CodingKeys 明确指定要编码/解码的属性
    enum CodingKeys: String, CodingKey {
        case id
        case username
        case email
        // 不包含 lastLoginDate 和 sessionToken
    }
}
```

### 默认值

为可选属性提供默认值：

```swift
struct AppSettings: Codable {
    let version: String
    let theme: String
    let notificationsEnabled: Bool
    let refreshInterval: Int
    
    // 使用 init(from:) 提供默认值
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        version = try container.decode(String.self, forKey: .version)
        theme = try container.decodeIfPresent(String.self, forKey: .theme) ?? "default"
        notificationsEnabled = try container.decodeIfPresent(Bool.self, forKey: .notificationsEnabled) ?? true
        refreshInterval = try container.decodeIfPresent(Int.self, forKey: .refreshInterval) ?? 60
    }
}

// 测试默认值
let jsonString = """
{
    "version": "1.2.3"
}
"""
let jsonData = jsonString.data(using: .utf8)!

do {
    let settings = try JSONDecoder().decode(AppSettings.self, from: jsonData)
    print("版本: \(settings.version)")
    print("主题: \(settings.theme)") // 输出 "default"
    print("通知: \(settings.notificationsEnabled)") // 输出 true
    print("刷新间隔: \(settings.refreshInterval)秒") // 输出 60
} catch {
    print("解码失败: \(error)")
}
```

### 数据转换

处理特殊格式的数据：

```swift
// 自定义日期格式
let decoder = JSONDecoder()

// ISO8601 日期格式
decoder.dateDecodingStrategy = .iso8601

// 使用 UNIX 时间戳
decoder.dateDecodingStrategy = .secondsSince1970

// 自定义日期格式
let dateFormatter = DateFormatter()
dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
dateFormatter.timeZone = TimeZone(secondsFromGMT: 0)
decoder.dateDecodingStrategy = .formatted(dateFormatter)

// 完全自定义转换
decoder.dateDecodingStrategy = .custom { decoder in
    let container = try decoder.singleValueContainer()
    let string = try container.decode(String.self)
    
    // 处理多种日期格式
    let formatters = [
        "yyyy-MM-dd",
        "yyyy/MM/dd",
        "dd-MM-yyyy",
        "MM/dd/yyyy"
    ].map { format -> DateFormatter in
        let formatter = DateFormatter()
        formatter.dateFormat = format
        return formatter
    }
    
    for formatter in formatters {
        if let date = formatter.date(from: string) {
            return date
        }
    }
    
    throw DecodingError.dataCorruptedError(
        in: container,
        debugDescription: "Cannot decode date from \(string)"
    )
}
```

## 常见问题

### 错误处理

解析 Codable 错误消息：

```swift
func handleDecodingError(_ error: Error) {
    switch error {
    case let DecodingError.dataCorrupted(context):
        print("数据损坏: \(context.debugDescription)")
        
    case let DecodingError.keyNotFound(key, context):
        print("找不到键 '\(key.stringValue)': \(context.debugDescription)")
        print("编码路径: \(context.codingPath)")
        
    case let DecodingError.valueNotFound(type, context):
        print("找不到 \(type) 类型的值: \(context.debugDescription)")
        print("编码路径: \(context.codingPath)")
        
    case let DecodingError.typeMismatch(type, context):
        print("类型不匹配 \(type): \(context.debugDescription)")
        print("编码路径: \(context.codingPath)")
        
    default:
        print("其他错误: \(error)")
    }
}

// 使用
do {
    let user = try JSONDecoder().decode(User.self, from: jsonData)
    // ...
} catch {
    handleDecodingError(error)
}
```

### 性能优化

1. **重用编码器/解码器实例**:

```swift
// 全局单例
class CodableManager {
    static let shared = CodableManager()
    
    let jsonEncoder: JSONEncoder
    let jsonDecoder: JSONDecoder
    
    private init() {
        jsonEncoder = JSONEncoder()
        jsonEncoder.outputFormatting = .prettyPrinted
        jsonEncoder.dateEncodingStrategy = .iso8601
        
        jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .iso8601
    }
}

// 使用
let decoder = CodableManager.shared.jsonDecoder
let encoder = CodableManager.shared.jsonEncoder
```

2. **避免不必要的编码/解码**:

```swift
// 缓存已解码的结果
var cachedUsers: [User]?

func getUsers() -> [User] {
    if let cached = cachedUsers {
        return cached
    }
    
    // 从磁盘加载并解码
    if let data = loadDataFromDisk(), 
       let users = try? JSONDecoder().decode([User].self, from: data) {
        cachedUsers = users
        return users
    }
    
    return []
}
```

### 版本兼容性

处理 API 变更：

```swift
struct UserV2: Codable {
    let id: Int
    let name: String
    let email: String
    // 新增字段
    let phoneNumber: String?
    let profileImageURL: URL?
    
    // 从旧版模型迁移
    init(from v1: UserV1) {
        self.id = v1.id
        self.name = v1.name
        self.email = v1.email
        self.phoneNumber = nil
        self.profileImageURL = nil
    }
    
    enum CodingKeys: String, CodingKey {
        case id
        case name
        case email
        case phoneNumber = "phone"
        case profileImageURL = "avatar_url"
    }
}

// 尝试使用新版本，失败则回退到旧版本
func decodeUserData(_ data: Data) -> Any? {
    // 尝试解码为 V2
    if let userV2 = try? JSONDecoder().decode(UserV2.self, from: data) {
        return userV2
    }
    
    // 回退到 V1
    if let userV1 = try? JSONDecoder().decode(UserV1.self, from: data) {
        // 可以选择迁移到 V2
        return UserV2(from: userV1)
    }
    
    return nil
}
``` 