# iOS 数据持久化

iOS 应用开发中，数据持久化是一个关键概念，它允许应用在重启后仍能保留数据。本文将全面介绍 iOS 数据持久化的方案、选择标准和最佳实践。

## 目录

- [数据持久化概述](#数据持久化概述)
- [持久化方案对比](#持久化方案对比)
- [UserDefaults](#userdefaults)
- [FileManager](#filemanager)
- [Core Data](#core-data)
- [Realm](#realm)
- [SQLite](#sqlite)
- [Keychain](#keychain)
- [iCloud](#icloud)
- [SwiftData](#swiftdata)
- [混合存储策略](#混合存储策略)
- [最佳实践](#最佳实践)

## 数据持久化概述

### 什么是数据持久化？

数据持久化是将程序数据从临时存储（如内存）转移到持久性存储介质（如磁盘）的过程，确保应用程序重启或设备关机后数据不会丢失。

### 为什么需要数据持久化？

- **状态保存**：保存用户设置和应用状态
- **离线访问**：允许应用在无网络连接时运行
- **减少网络请求**：缓存数据减少对后端服务的依赖
- **提升用户体验**：保存用户进度和偏好

### 持久化需考虑的因素

- **数据大小**：需要存储的数据量
- **数据结构**：简单键值对还是复杂关系型数据
- **安全性**：数据敏感程度和加密需求
- **性能要求**：读写速度和效率
- **云同步需求**：是否需要跨设备同步
- **查询复杂度**：是否需要复杂查询
- **开发复杂度**：实现难度和维护成本

## 持久化方案对比

| 方案 | 适用场景 | 优点 | 缺点 | 复杂度 |
|------|----------|------|------|--------|
| UserDefaults | 小型键值数据、用户设置 | 简单易用、读写快速 | 不适合大数据、不安全 | 低 |
| FileManager | 文件、媒体内容、大型数据 | 完全控制、适合大文件 | 需手动管理、无结构化查询 | 中 |
| Core Data | 复杂对象图、关系型数据 | 强大的查询能力、关系管理 | 学习曲线陡峭、配置复杂 | 高 |
| Realm | 跨平台需求、性能敏感场景 | 易用性好、性能优、实时同步 | 第三方依赖、迁移复杂 | 中 |
| SQLite | 原始 SQL 需求、完全控制 | 灵活性高、广泛支持 | 需要手写 SQL、无对象映射 | 高 |
| Keychain | 敏感数据、认证凭证 | 安全加密、应用删除后保留 | API 复杂、容量有限 | 中 |
| iCloud | 跨设备同步、用户数据备份 | 无缝同步、Apple 生态集成 | 依赖 Apple ID、同步延迟 | 中-高 |
| SwiftData | Swift UI 集成、声明式需求 | 与 SwiftUI 深度集成、简化代码 | 仅 iOS 17+、功能相对有限 | 中 |

## UserDefaults

[请参考专门的 UserDefaults 文档](userdefaults.md)

## FileManager

[请参考专门的 FileManager 文档](filemanager.md)

## Core Data

[请参考 Core Data 基础文档](coredata-basics.md)和[Core Data 高级文档](coredata-advanced.md)

## Realm

[请参考专门的 Realm 数据库文档](realm.md)

## SQLite

[请参考专门的 SQLite 与 FMDB 文档](sqlite.md)

## Keychain

Keychain 是 iOS 的安全存储机制，专为存储敏感数据设计。

### 基本用法

```swift
import Security

class KeychainManager {
    // 保存密码
    static func savePassword(_ password: String, for account: String) -> Bool {
        let passwordData = password.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: passwordData
        ]
        
        // 删除可能存在的旧记录
        SecItemDelete(query as CFDictionary)
        
        // 添加新记录
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // 获取密码
    static func getPassword(for account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, let data = result as? Data,
           let password = String(data: data, encoding: .utf8) {
            return password
        }
        return nil
    }
    
    // 删除密码
    static func deletePassword(for account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
}

// 使用
KeychainManager.savePassword("安全密码123", for: "user@example.com")
if let password = KeychainManager.getPassword(for: "user@example.com") {
    print("检索到密码: \(password)")
}
```

### Keychain 适用场景

- 存储认证凭证（用户名、密码）
- API 密钥和令牌
- 加密密钥
- 生物识别数据相关信息
- 需要在应用删除后仍保留的数据

## iCloud

iCloud 允许应用程序将用户数据存储在云中，实现跨设备同步。

### iCloud Key-Value 存储

适用于小型键值数据：

```swift
// 启用 iCloud 能力并配置 entitlements

// 设置观察者
NotificationCenter.default.addObserver(
    self, 
    selector: #selector(iCloudDidChangeRemotely),
    name: NSUbiquitousKeyValueStore.didChangeExternallyNotification, 
    object: NSUbiquitousKeyValueStore.default
)

// 同步变更
NSUbiquitousKeyValueStore.default.synchronize()

// 存储数据
NSUbiquitousKeyValueStore.default.set("张三", forKey: "username")
NSUbiquitousKeyValueStore.default.set(true, forKey: "isPremiumUser")

// 读取数据
let username = NSUbiquitousKeyValueStore.default.string(forKey: "username")
let isPremium = NSUbiquitousKeyValueStore.default.bool(forKey: "isPremiumUser")

// 处理远程变更
@objc func iCloudDidChangeRemotely(notification: Notification) {
    if let userInfo = notification.userInfo,
       let reasonForChange = userInfo[NSUbiquitousKeyValueStoreChangeReasonKey] as? Int {
        // 处理变更
        let username = NSUbiquitousKeyValueStore.default.string(forKey: "username")
        print("iCloud 用户名已更新: \(username ?? "未设置")")
    }
}
```

### iCloud Documents

适用于文档和大型数据：

```swift
// 获取 iCloud 容器 URL
func getiCloudDocumentURL() -> URL? {
    if let iCloudURL = FileManager.default.url(forUbiquityContainerIdentifier: nil) {
        return iCloudURL.appendingPathComponent("Documents")
    }
    return nil
}

// 保存文档到 iCloud
func saveToCould(text: String, filename: String) {
    guard let cloudURL = getiCloudDocumentURL()?.appendingPathComponent(filename) else {
        return
    }
    
    do {
        try text.write(to: cloudURL, atomically: true, encoding: .utf8)
        print("文档保存到 iCloud 成功")
    } catch {
        print("保存到 iCloud 失败: \(error)")
    }
}

// 从 iCloud 读取文档
func readFromCloud(filename: String) -> String? {
    guard let cloudURL = getiCloudDocumentURL()?.appendingPathComponent(filename) else {
        return nil
    }
    
    do {
        let text = try String(contentsOf: cloudURL, encoding: .utf8)
        return text
    } catch {
        print("从 iCloud 读取失败: \(error)")
        return nil
    }
}
```

### iCloud 适用场景

- 需要跨设备同步的用户数据
- 用户生成的文档和内容
- 应用设置和状态同步
- 需要备份到用户 iCloud 账户的数据

## SwiftData

SwiftData 是 iOS 17 引入的现代化数据持久化框架，与 SwiftUI 深度集成。

### 基本设置

```swift
// 确保导入 SwiftData
import SwiftData

// 定义模型
@Model
class Person {
    var name: String
    var age: Int
    var friends: [Person]?
    
    init(name: String, age: Int, friends: [Person]? = nil) {
        self.name = name
        self.age = age
        self.friends = friends
    }
}

// 在 SwiftUI App 中配置
@main
struct MyApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .modelContainer(for: Person.self)
    }
}
```

### 在 SwiftUI 中使用

```swift
struct ContentView: View {
    // 使用查询宏获取数据
    @Query var people: [Person]
    @Environment(\.modelContext) private var modelContext
    
    var body: some View {
        NavigationView {
            List {
                ForEach(people) { person in
                    Text("\(person.name), \(person.age)岁")
                }
                .onDelete(perform: deletePeople)
            }
            .toolbar {
                Button("添加示例") {
                    addSamplePerson()
                }
            }
        }
    }
    
    func addSamplePerson() {
        let person = Person(name: "张三", age: 30)
        modelContext.insert(person)
    }
    
    func deletePeople(offsets: IndexSet) {
        for index in offsets {
            modelContext.delete(people[index])
        }
    }
}

// 使用谓词过滤
struct FilteredView: View {
    @Query(filter: #Predicate<Person> { person in
        person.age > 30
    }, sort: \Person.name) var olderPeople: [Person]
    
    var body: some View {
        List(olderPeople) { person in
            Text(person.name)
        }
    }
}
```

### SwiftData 适用场景

- SwiftUI 应用（iOS 17+）
- 需要简化数据模型代码的场景
- 声明式数据管理需求
- 与 SwiftUI 视图紧密集成的数据

## 混合存储策略

在实际应用中，通常需要组合多种存储方式以满足不同需求：

### 分层存储策略

1. **用户设置**：UserDefaults
2. **认证凭证**：Keychain
3. **应用数据**：Core Data 或 Realm
4. **用户文件**：FileManager
5. **跨设备数据**：iCloud

### 缓存策略

```swift
class DataManager {
    // 内存缓存
    private var memoryCache = NSCache<NSString, AnyObject>()
    
    // 磁盘存储
    private let fileManager = FileManager.default
    private let cacheDirectory: URL
    
    // 数据库
    private let dbManager: DatabaseManager
    
    init() {
        cacheDirectory = fileManager.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        dbManager = DatabaseManager()
    }
    
    // 获取数据，优先从内存缓存获取
    func fetchData(withID id: String, completion: @escaping (Data?) -> Void) {
        // 1. 检查内存缓存
        if let cachedData = memoryCache.object(forKey: id as NSString) as? Data {
            completion(cachedData)
            return
        }
        
        // 2. 检查磁盘缓存
        let cacheFilePath = cacheDirectory.appendingPathComponent(id)
        if fileManager.fileExists(atPath: cacheFilePath.path),
           let diskData = try? Data(contentsOf: cacheFilePath) {
            // 找到磁盘缓存，存入内存缓存
            memoryCache.setObject(diskData as AnyObject, forKey: id as NSString)
            completion(diskData)
            return
        }
        
        // 3. 从数据库获取
        dbManager.fetchData(withID: id) { data in
            if let data = data {
                // 保存到缓存
                self.memoryCache.setObject(data as AnyObject, forKey: id as NSString)
                try? data.write(to: cacheFilePath)
            }
            completion(data)
        }
    }
}
```

## 最佳实践

### 选择正确的存储方案

- **简单键值数据**：UserDefaults（非敏感）或 Keychain（敏感）
- **结构化数据**：Core Data、Realm 或 SwiftData
- **文件存储**：FileManager
- **跨设备同步**：iCloud 或自定义云解决方案

### 封装数据访问层

创建统一的数据访问接口，隐藏具体实现细节：

```swift
protocol DataRepository {
    func fetchItems(completion: @escaping ([Item]) -> Void)
    func save(item: Item, completion: @escaping (Bool) -> Void)
    func delete(item: Item, completion: @escaping (Bool) -> Void)
}

class CoreDataRepository: DataRepository {
    // Core Data 实现
}

class RealmRepository: DataRepository {
    // Realm 实现
}

// 使用工厂模式创建存储库
class RepositoryFactory {
    static func createRepository() -> DataRepository {
        #if DEBUG
        return MockRepository() // 测试环境使用 Mock
        #else
        return CoreDataRepository() // 生产环境使用 Core Data
        #endif
    }
}
```

### 异步操作

将存储操作放在后台线程执行：

```swift
class DataManager {
    private let backgroundQueue = DispatchQueue(label: "com.app.datamanager", qos: .background)
    
    func saveData(_ data: Data, withID id: String, completion: @escaping (Bool) -> Void) {
        backgroundQueue.async {
            // 执行耗时的存储操作
            let success = self.performSave(data, id: id)
            
            // 在主线程返回结果
            DispatchQueue.main.async {
                completion(success)
            }
        }
    }
}
```

### 版本迁移

处理数据模型变更：

```swift
// Core Data 迁移示例
let container = NSPersistentContainer(name: "MyModel")
let description = container.persistentStoreDescriptions.first
description?.shouldMigrateStoreAutomatically = true
description?.shouldInferMappingModelAutomatically = true

// SwiftData 迁移示例
let schema = Schema([Person.self])
let modelConfiguration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false, migrations: [
    // 定义迁移
])
let modelContainer = try ModelContainer(for: schema, configurations: [modelConfiguration])
```

### 数据安全

敏感数据的处理：

```swift
// 使用 Keychain 存储敏感数据
KeychainManager.savePassword(secureToken, for: "api_token")

// 文件加密
func encryptAndSaveData(_ data: Data, to url: URL, with key: Data) throws {
    let algorithm = SecKeyAlgorithm.rsaEncryptionOAEPSHA256
    // 实现加密逻辑...
}

// 数据库加密 (Realm 示例)
var config = Realm.Configuration(encryptionKey: encryptionKey)
let realm = try! Realm(configuration: config)
```

### 缓存管理

实现智能缓存策略：

```swift
class CacheManager {
    private let cache = NSCache<NSString, AnyObject>()
    private let fileManager = FileManager.default
    private let cacheDirectory: URL
    
    init() {
        cacheDirectory = fileManager.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        
        // 设置缓存限制
        cache.countLimit = 100 // 最多缓存100个对象
        cache.totalCostLimit = 50 * 1024 * 1024 // 50MB 限制
        
        // 注册内存警告通知
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(clearMemoryCache),
            name: UIApplication.didReceiveMemoryWarningNotification,
            object: nil
        )
    }
    
    @objc func clearMemoryCache() {
        cache.removeAllObjects()
    }
    
    // 清理过期缓存文件
    func clearExpiredDiskCache() {
        let expirationDate = Date().addingTimeInterval(-7 * 24 * 60 * 60) // 7天前
        
        do {
            let cacheFiles = try fileManager.contentsOfDirectory(
                at: cacheDirectory,
                includingPropertiesForKeys: [.contentModificationDateKey]
            )
            
            for fileURL in cacheFiles {
                if let attributes = try? fileManager.attributesOfItem(atPath: fileURL.path),
                   let modificationDate = attributes[.modificationDate] as? Date,
                   modificationDate < expirationDate {
                    try fileManager.removeItem(at: fileURL)
                }
            }
        } catch {
            print("清理缓存失败: \(error)")
        }
    }
}
```

### 离线优先策略

实现离线优先的数据访问策略：

```swift
class OfflineFirstDataManager {
    private let localRepository: DataRepository
    private let remoteRepository: APIService
    private let syncManager: SyncManager
    
    init(localRepository: DataRepository, remoteRepository: APIService) {
        self.localRepository = localRepository
        self.remoteRepository = remoteRepository
        self.syncManager = SyncManager(localRepository: localRepository, remoteRepository: remoteRepository)
    }
    
    // 获取数据，始终从本地获取，然后尝试更新
    func fetchData(completion: @escaping ([Item]) -> Void) {
        // 先从本地获取
        localRepository.fetchItems { localItems in
            // 返回本地数据
            completion(localItems)
            
            // 尝试从服务器获取最新数据
            self.remoteRepository.fetchItems { result in
                switch result {
                case .success(let remoteItems):
                    // 更新本地存储
                    self.syncManager.updateLocalData(with: remoteItems)
                case .failure:
                    // 标记需要同步
                    self.syncManager.markForSync()
                }
            }
        }
    }
    
    // 处理用户操作，先本地保存，然后尝试同步
    func saveItem(_ item: Item, completion: @escaping (Bool) -> Void) {
        // 先保存到本地
        localRepository.save(item: item) { success in
            completion(success)
            
            if success {
                // 标记需要同步到服务器
                self.syncManager.markItemForSync(item)
                // 尝试同步
                self.syncManager.synchronize()
            }
        }
    }
}
```

通过结合上述策略，可以构建健壮、高效、安全的 iOS 数据持久化解决方案，满足各种应用场景的需求。 