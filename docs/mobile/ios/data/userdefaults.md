# UserDefaults

UserDefaults 是 iOS 中用于存储少量键值对数据的轻量级持久化解决方案。本文将介绍 UserDefaults 的基本用法和最佳实践。

## 目录

- [基本概念](#基本概念)
- [基本操作](#基本操作)
- [存储自定义对象](#存储自定义对象)
- [监听数据变化](#监听数据变化)
- [高级用法](#高级用法)
- [性能考量](#性能考量)
- [与其他存储方式对比](#与其他存储方式对比)
- [最佳实践](#最佳实践)

## 基本概念

UserDefaults 提供了一种简单的方式来存储用户偏好设置、应用配置和其他小型数据。它将数据存储在 plist 文件中，位于应用沙盒的 Library/Preferences 目录下。

### 适用场景

- 用户偏好设置（如主题、字体大小）
- 应用配置（如是否首次启动）
- 简单的状态持久化
- 小型键值对数据

不适用于：
- 大型数据
- 敏感信息（如密码）
- 复杂对象存储
- 频繁变化的数据

### 工作原理

UserDefaults 在内存中保持一个缓存，并且会在适当的时机（通常是应用进入后台或关闭时）将更改同步到磁盘。这使得读写操作非常快速，但也意味着在某些情况下（如应用崩溃）可能会丢失最近的更改。

```swift
// 手动同步到磁盘
UserDefaults.standard.synchronize()
```

> 注意：从 iOS 12 开始，`synchronize()` 方法已被弃用，系统会自动处理同步操作。只有在旧版本 iOS 或特殊情况下才需要手动调用此方法。

## 基本操作

### 写入数据

```swift
// 获取标准 UserDefaults 实例
let defaults = UserDefaults.standard

// 写入各种类型的数据
defaults.set("张三", forKey: "username")
defaults.set(25, forKey: "age")
defaults.set(true, forKey: "isLoggedIn")
defaults.set(Date(), forKey: "lastLoginDate")
defaults.set(["苹果", "香蕉", "橙子"], forKey: "favoriteItems")
defaults.set(["name": "张三", "age": 25], forKey: "userInfo")
```

### 读取数据

```swift
// 读取数据
let username = defaults.string(forKey: "username") ?? "游客"
let age = defaults.integer(forKey: "age") // 不存在时返回0
let isLoggedIn = defaults.bool(forKey: "isLoggedIn") // 不存在时返回false
let lastLoginDate = defaults.object(forKey: "lastLoginDate") as? Date
let favoriteItems = defaults.stringArray(forKey: "favoriteItems") ?? []
let userInfo = defaults.dictionary(forKey: "userInfo") as? [String: Any] ?? [:]

// 使用 object(forKey:) 读取任意类型
let anyObject = defaults.object(forKey: "someKey")
```

### 读取时使用默认值

```swift
// 针对不同类型使用默认值
let name = defaults.string(forKey: "username") ?? "游客"
let count = defaults.integer(forKey: "count") // 默认为 0
let flag = defaults.bool(forKey: "flag") // 默认为 false
let items = defaults.array(forKey: "items") as? [String] ?? []

// 检查键是否存在
if defaults.object(forKey: "username") != nil {
    print("用户名已设置")
}
```

### 删除数据

```swift
// 删除特定键
defaults.removeObject(forKey: "lastLoginDate")

// 删除所有数据（谨慎使用）
if let bundleID = Bundle.main.bundleIdentifier {
    defaults.removePersistentDomain(forName: bundleID)
}
```

## 存储自定义对象

### 使用 Codable

```swift
// 定义符合 Codable 的结构体
struct User: Codable {
    var name: String
    var age: Int
    var preferences: [String: Bool]
}

// 存储
let user = User(name: "张三", age: 30, preferences: ["darkMode": true, "notifications": false])
if let userData = try? JSONEncoder().encode(user) {
    UserDefaults.standard.set(userData, forKey: "currentUser")
}

// 读取
if let userData = UserDefaults.standard.data(forKey: "currentUser"),
   let user = try? JSONDecoder().decode(User.self, from: userData) {
    print("用户: \(user.name), 年龄: \(user.age)")
    print("偏好设置: \(user.preferences)")
}
```

### 使用 NSCoding（兼容 Objective-C）

```swift
// 定义符合 NSCoding 的类
class LegacyUser: NSObject, NSCoding {
    var name: String
    var age: Int
    
    init(name: String, age: Int) {
        self.name = name
        self.age = age
    }
    
    func encode(with coder: NSCoder) {
        coder.encode(name, forKey: "name")
        coder.encode(age, forKey: "age")
    }
    
    required init?(coder: NSCoder) {
        name = coder.decodeObject(forKey: "name") as? String ?? ""
        age = coder.decodeInteger(forKey: "age")
    }
}

// 存储
let legacyUser = LegacyUser(name: "李四", age: 25)
let userData = try? NSKeyedArchiver.archivedData(withRootObject: legacyUser, requiringSecureCoding: false)
UserDefaults.standard.set(userData, forKey: "legacyUser")

// 读取
if let userData = UserDefaults.standard.data(forKey: "legacyUser"),
   let legacyUser = try? NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(userData) as? LegacyUser {
    print("名称: \(legacyUser.name), 年龄: \(legacyUser.age)")
}
```

### 自定义对象的扩展方法

为了简化存取操作，可以为 UserDefaults 添加扩展：

```swift
extension UserDefaults {
    func save<T: Encodable>(_ object: T, forKey key: String) {
        if let data = try? JSONEncoder().encode(object) {
            set(data, forKey: key)
        }
    }
    
    func fetch<T: Decodable>(_ type: T.Type, forKey key: String) -> T? {
        if let data = data(forKey: key),
           let object = try? JSONDecoder().decode(type, from: data) {
            return object
        }
        return nil
    }
}

// 使用扩展简化操作
let user = User(name: "王五", age: 28, preferences: [:])
UserDefaults.standard.save(user, forKey: "user")
if let savedUser = UserDefaults.standard.fetch(User.self, forKey: "user") {
    print("保存的用户: \(savedUser.name)")
}
```

## 监听数据变化

### 使用 NotificationCenter

UserDefaults 会在值发生变化时发送 `didChangeNotification` 通知：

```swift
class SettingsManager {
    init() {
        // 注册通知
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(defaultsChanged),
            name: UserDefaults.didChangeNotification,
            object: nil
        )
    }
    
    @objc func defaultsChanged() {
        // 处理数据变化
        print("UserDefaults 数据已更改")
        
        // 读取更新后的值
        let username = UserDefaults.standard.string(forKey: "username")
        print("当前用户名: \(username ?? "未设置")")
    }
    
    deinit {
        // 移除观察者
        NotificationCenter.default.removeObserver(self)
    }
}
```

### 使用属性观察器

```swift
class Settings {
    static let shared = Settings()
    
    var username: String {
        didSet {
            UserDefaults.standard.set(username, forKey: "username")
            // 可以在这里添加其他逻辑
            print("用户名已更改: \(username)")
        }
    }
    
    init() {
        username = UserDefaults.standard.string(forKey: "username") ?? "游客"
    }
}
```

### 使用 Combine 框架

在 iOS 13 及以上版本，可以使用 Combine 框架监听变化：

```swift
import Combine

class ModernSettings {
    static let shared = ModernSettings()
    private let defaults = UserDefaults.standard
    private var cancellables = Set<AnyCancellable>()
    
    @Published var username: String
    
    init() {
        username = defaults.string(forKey: "username") ?? "游客"
        
        // 当 username 发生变化时保存到 UserDefaults
        $username
            .dropFirst() // 跳过初始值
            .sink { [weak self] newValue in
                self?.defaults.set(newValue, forKey: "username")
            }
            .store(in: &cancellables)
    }
}

// 使用
let settings = ModernSettings.shared
settings.username = "新用户名" // 自动保存到 UserDefaults
```

## 高级用法

### 使用不同的 UserDefaults 域

除了标准域，你还可以创建和使用自定义域：

```swift
// 创建自定义域
let suiteName = "group.com.yourcompany.app"
if let groupDefaults = UserDefaults(suiteName: suiteName) {
    groupDefaults.set("共享数据", forKey: "sharedKey")
    
    // 读取
    let sharedValue = groupDefaults.string(forKey: "sharedKey")
}
```

> 注意：使用自定义域需要在项目的 Capabilities 中启用 App Groups 并配置相应的组标识符。

### 访问注册表域

你可以访问系统默认值，但通常只读：

```swift
// 获取所有域的列表
let domains = UserDefaults.standard.persistentDomainNames

// 获取特定域的所有键值对
if let domain = UserDefaults.standard.persistentDomain(forName: Bundle.main.bundleIdentifier!) {
    for (key, value) in domain {
        print("\(key): \(value)")
    }
}

// 获取特定键的搜索列表
let searchList = UserDefaults.standard.searchList
```

### 使用初始默认值

在应用启动时设置初始默认值：

```swift
// 在 AppDelegate 的 didFinishLaunchingWithOptions 方法中：
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    // 设置默认值（只有在用户未设置时才会使用）
    let defaultSettings: [String: Any] = [
        "username": "新用户",
        "fontSize": 14,
        "isDarkMode": false,
        "refreshInterval": 60
    ]
    UserDefaults.standard.register(defaults: defaultSettings)
    
    return true
}
```

注意：`register(defaults:)` 方法只会在内存中设置默认值，不会写入到磁盘。只有当用户未设置某个键时，才会返回这些默认值。

### 使用属性列表文件注册默认值

```swift
if let defaultsPath = Bundle.main.path(forResource: "DefaultSettings", ofType: "plist"),
   let defaultsDict = NSDictionary(contentsOfFile: defaultsPath) as? [String: Any] {
    UserDefaults.standard.register(defaults: defaultsDict)
}
```

## 性能考量

### 读写优化

UserDefaults 在内存中缓存数据，所以单个值的读写通常非常快。但有一些注意事项：

1. **批量操作**：连续写入多个值时，UserDefaults 可能会多次同步磁盘，降低性能。

```swift
// 不推荐：多次单独写入
defaults.set("值1", forKey: "键1")
defaults.set("值2", forKey: "键2")
defaults.set("值3", forKey: "键3")

// 推荐：使用字典批量写入
let batch: [String: Any] = [
    "键1": "值1",
    "键2": "值2",
    "键3": "值3"
]
for (key, value) in batch {
    defaults.set(value, forKey: key)
}
```

2. **大型数据**：存储大量数据或大型对象会影响性能，特别是应用启动时。

```swift
// 不推荐：存储大量数据
let largeArray = Array(repeating: "数据", count: 10000)
defaults.set(largeArray, forKey: "largeData") // 性能差

// 推荐：存储到文件系统
func saveLargeData(_ data: [String]) {
    guard let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else {
        return
    }
    
    let fileURL = documentsDirectory.appendingPathComponent("largeData.json")
    
    do {
        let jsonData = try JSONEncoder().encode(data)
        try jsonData.write(to: fileURL)
    } catch {
        print("保存失败: \(error)")
    }
}
```

### 内存占用

虽然 UserDefaults 通常效率很高，但如果存储了大量数据，可能会增加应用的内存占用。

## 与其他存储方式对比

| 存储方式       | 适用场景                     | 优势                       | 劣势                         |
|--------------|----------------------------|----------------------------|------------------------------|
| UserDefaults | 小型键值数据、用户偏好设置      | 简单易用、读写速度快          | 不适合大数据、不安全、不支持复杂查询 |
| Keychain     | 敏感数据（密码、令牌）         | 安全加密、应用删除后仍可保留    | API 复杂、容量有限              |
| Core Data    | 复杂结构化数据、关系型数据      | 强大的查询能力、数据关系管理    | 学习曲线陡峭、配置复杂           |
| Realm        | 大型数据库、高性能需求         | 速度快、易用性好、跨平台        | 第三方依赖、某些限制              |
| FileSystem   | 大型文件、媒体内容            | 完全控制、适合大文件           | 需要手动管理文件生命周期          |
| SQLite       | 原始 SQL 操作、完全控制        | 灵活性高、广泛支持             | 需要手写 SQL、无对象映射         |

### 何时选择 UserDefaults

1. **适合场景**：
   - 存储用户偏好（主题、字体大小等）
   - 应用配置参数
   - 简单标志（如首次启动标记）
   - 需要快速读写的小型数据

2. **不适合场景**：
   - 敏感信息（使用 Keychain）
   - 大型数据集（使用 Core Data 或文件系统）
   - 需要复杂查询的数据（使用 Core Data 或 Realm）

## 最佳实践

### 使用封装类

创建专用的设置管理类，提供类型安全的API：

```swift
class UserSettings {
    static let shared = UserSettings()
    private let defaults = UserDefaults.standard
    
    // 存储属性和键名
    private enum Keys {
        static let username = "username"
        static let isLoggedIn = "isLoggedIn"
        static let appTheme = "appTheme"
        static let lastOpenDate = "lastOpenDate"
    }
    
    var username: String {
        get { defaults.string(forKey: Keys.username) ?? "游客" }
        set { defaults.set(newValue, forKey: Keys.username) }
    }
    
    var isLoggedIn: Bool {
        get { defaults.bool(forKey: Keys.isLoggedIn) }
        set { defaults.set(newValue, forKey: Keys.isLoggedIn) }
    }
    
    var appTheme: String {
        get { defaults.string(forKey: Keys.appTheme) ?? "system" }
        set { defaults.set(newValue, forKey: Keys.appTheme) }
    }
    
    var lastOpenDate: Date? {
        get { defaults.object(forKey: Keys.lastOpenDate) as? Date }
        set { defaults.set(newValue, forKey: Keys.lastOpenDate) }
    }
    
    // 更新最后打开日期
    func updateLastOpenDate() {
        lastOpenDate = Date()
    }
    
    // 重置所有设置
    func reset() {
        let keys = [Keys.username, Keys.isLoggedIn, Keys.appTheme, Keys.lastOpenDate]
        keys.forEach { defaults.removeObject(forKey: $0) }
    }
}

// 使用
let settings = UserSettings.shared
print(settings.username)
settings.isLoggedIn = true
settings.updateLastOpenDate()
```

### 使用枚举类型定义键

使用枚举避免字符串键名错误：

```swift
enum UserDefaultsKeys: String {
    case username
    case counter
    case lastOpenDate
    case appTheme
}

extension UserDefaults {
    func set(_ value: Any?, forKey key: UserDefaultsKeys) {
        set(value, forKey: key.rawValue)
    }
    
    func string(forKey key: UserDefaultsKeys) -> String? {
        return string(forKey: key.rawValue)
    }
    
    func integer(forKey key: UserDefaultsKeys) -> Int {
        return integer(forKey: key.rawValue)
    }
    
    func bool(forKey key: UserDefaultsKeys) -> Bool {
        return bool(forKey: key.rawValue)
    }
    
    func object(forKey key: UserDefaultsKeys) -> Any? {
        return object(forKey: key.rawValue)
    }
    
    func removeObject(forKey key: UserDefaultsKeys) {
        removeObject(forKey: key.rawValue)
    }
}

// 使用
UserDefaults.standard.set("李四", forKey: .username)
let name = UserDefaults.standard.string(forKey: .username)
```

### 使用 SwiftUI 的 @AppStorage

SwiftUI 提供了 `@AppStorage` 属性包装器，可以直接绑定视图和 UserDefaults：

```swift
struct SettingsView: View {
    @AppStorage("username") private var username: String = "游客"
    @AppStorage("isDarkMode") private var isDarkMode: Bool = false
    @AppStorage("fontSize") private var fontSize: Double = 14.0
    @AppStorage("refreshInterval") private var refreshInterval: Int = 60
    
    var body: some View {
        Form {
            Section(header: Text("个人设置")) {
                TextField("用户名", text: $username)
                Toggle("深色模式", isOn: $isDarkMode)
            }
            
            Section(header: Text("显示设置")) {
                VStack {
                    Text("字体大小: \(Int(fontSize))")
                    Slider(value: $fontSize, in: 10...20, step: 1)
                }
                
                Picker("刷新间隔", selection: $refreshInterval) {
                    Text("30 秒").tag(30)
                    Text("1 分钟").tag(60)
                    Text("5 分钟").tag(300)
                }
            }
            
            Button("重置所有设置") {
                username = "游客"
                isDarkMode = false
                fontSize = 14.0
                refreshInterval = 60
            }
        }
    }
}
```

### 使用自定义 AppStorage 属性包装器

对于复杂对象，可以创建自定义的属性包装器：

```swift
@propertyWrapper
struct CodableAppStorage<T: Codable> {
    private let key: String
    private let defaultValue: T
    private let defaults: UserDefaults
    
    init(wrappedValue defaultValue: T, _ key: String, store: UserDefaults = .standard) {
        self.defaultValue = defaultValue
        self.key = key
        self.defaults = store
    }
    
    var wrappedValue: T {
        get {
            guard let data = defaults.data(forKey: key) else {
                return defaultValue
            }
            return (try? JSONDecoder().decode(T.self, from: data)) ?? defaultValue
        }
        set {
            guard let data = try? JSONEncoder().encode(newValue) else {
                defaults.removeObject(forKey: key)
                return
            }
            defaults.set(data, forKey: key)
        }
    }
}

// 使用
struct AdvancedSettingsView: View {
    @CodableAppStorage("userPreferences") private var preferences = UserPreferences(
        theme: "light",
        fontSize: 14,
        notificationsEnabled: true
    )
    
    var body: some View {
        Form {
            Picker("主题", selection: $preferences.theme) {
                Text("浅色").tag("light")
                Text("深色").tag("dark")
                Text("系统").tag("system")
            }
            
            Stepper("字体大小: \(preferences.fontSize)", value: $preferences.fontSize, in: 10...20)
            
            Toggle("启用通知", isOn: $preferences.notificationsEnabled)
        }
    }
}

struct UserPreferences: Codable {
    var theme: String
    var fontSize: Int
    var notificationsEnabled: Bool
}
```

### 注意安全性

UserDefaults 不适合存储敏感信息，因为数据未加密。对于敏感数据，应使用 Keychain：

```swift
import Security

class KeychainManager {
    static func save(password: String, for username: String) -> Bool {
        let passwordData = password.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: username,
            kSecValueData as String: passwordData
        ]
        
        // 先删除旧记录
        SecItemDelete(query as CFDictionary)
        
        // 添加新记录
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    static func getPassword(for username: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: username,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess, let data = dataTypeRef as? Data,
           let password = String(data: data, encoding: .utf8) {
            return password
        }
        
        return nil
    }
}

// 使用
KeychainManager.save(password: "安全密码", for: "user@example.com")
if let password = KeychainManager.getPassword(for: "user@example.com") {
    print("检索到密码: \(password)")
}
```

### 调试 UserDefaults

添加调试辅助方法：

```swift
extension UserDefaults {
    // 打印所有存储的键值对
    static func printAll() {
        let defaults = UserDefaults.standard
        if let domain = defaults.persistentDomain(forName: Bundle.main.bundleIdentifier!) {
            print("--- UserDefaults 内容 ---")
            for (key, value) in domain.sorted(by: { $0.key < $1.key }) {
                print("  \(key): \(value)")
            }
            print("-----------------------")
        }
    }
}

// 使用
UserDefaults.printAll()
```

### 迁移旧版本数据

当应用更新时，可能需要迁移旧版本的数据格式：

```swift
class SettingsMigration {
    static func performMigrationIfNeeded() {
        let defaults = UserDefaults.standard
        let currentVersion = 2
        let lastMigrationVersion = defaults.integer(forKey: "settingsVersion")
        
        guard lastMigrationVersion < currentVersion else { return }
        
        // 执行数据迁移
        if lastMigrationVersion < 1 {
            migrateFromVersion0To1()
        }
        
        if lastMigrationVersion < 2 {
            migrateFromVersion1To2()
        }
        
        // 更新版本号
        defaults.set(currentVersion, forKey: "settingsVersion")
    }
    
    private static func migrateFromVersion0To1() {
        let defaults = UserDefaults.standard
        
        // 例如：将旧键重命名
        if let oldValue = defaults.string(forKey: "user_name") {
            defaults.set(oldValue, forKey: "username")
            defaults.removeObject(forKey: "user_name")
        }
    }
    
    private static func migrateFromVersion1To2() {
        let defaults = UserDefaults.standard
        
        // 例如：将单个设置拆分为多个
        if let oldTheme = defaults.string(forKey: "theme") {
            if oldTheme == "dark" {
                defaults.set(true, forKey: "isDarkMode")
                defaults.set(false, forKey: "useSystemTheme")
            } else if oldTheme == "system" {
                defaults.set(false, forKey: "isDarkMode")
                defaults.set(true, forKey: "useSystemTheme")
            } else {
                defaults.set(false, forKey: "isDarkMode")
                defaults.set(false, forKey: "useSystemTheme")
            }
            defaults.removeObject(forKey: "theme")
        }
    }
}

// 在应用启动时调用
SettingsMigration.performMigrationIfNeeded()
``` 