# Realm 数据库

Realm 是一款现代化、跨平台的移动数据库，为 iOS 和 Android 开发者提供了简单、高效的数据持久化解决方案。本文将介绍 Realm 的基本概念和在 iOS 中的使用方法。

## 目录

- [Realm 简介](#realm-简介)
- [安装与配置](#安装与配置)
- [数据模型](#数据模型)
- [基本操作](#基本操作)
- [查询](#查询)
- [关系](#关系)
- [事务](#事务)
- [通知](#通知)
- [高级功能](#高级功能)
- [最佳实践](#最佳实践)
- [与其他持久化方案对比](#与其他持久化方案对比)

## Realm 简介

### Realm 的特点

- **快速**：比 SQLite 和 Core Data 更快的读写性能
- **简单**：易于学习和使用的 API
- **跨平台**：iOS 和 Android 使用相同的数据模型
- **实时**：数据变化时自动更新
- **多线程**：简化了线程间数据共享
- **加密**：支持数据库加密

### Realm 的架构

Realm 不是建立在 SQLite 之上的 ORM，而是一个完全独立的数据库引擎，使用自己的数据格式和查询引擎。它主要由以下部分组成：

- **Realm 核心**：C++ 编写的跨平台数据库引擎
- **Realm 对象**：用于定义数据模型的类
- **Realm 实例**：管理数据访问的对象
- **通知系统**：提供数据变化的实时通知

## 安装与配置

### 使用 CocoaPods 安装

```ruby
# Podfile
pod 'RealmSwift'
```

### 使用 Swift Package Manager 安装

```swift
dependencies: [
    .package(url: "https://github.com/realm/realm-swift.git", from: "10.33.0")
]
```

### 初始化 Realm

```swift
import RealmSwift

// 基本初始化
let realm = try! Realm()

// 自定义配置
let config = Realm.Configuration(
    schemaVersion: 1,
    migrationBlock: { migration, oldSchemaVersion in
        // 迁移代码
    }
)

// 使用自定义配置
let realm = try! Realm(configuration: config)
```

## 数据模型

### 定义 Realm 对象

```swift
import RealmSwift

// 基本对象
class Person: Object {
    @Persisted var name: String = ""
    @Persisted var age: Int = 0
    @Persisted var birthday: Date?
    @Persisted var address: Address?               // 一对一关系
    @Persisted var friends = List<Person>()        // 一对多关系
    @Persisted var scores = Map<String, Int>()     // 键值对
    @Persisted var tags = List<String>()           // 基础类型列表
}

// 嵌套对象
class Address: EmbeddedObject {
    @Persisted var street: String = ""
    @Persisted var city: String = ""
    @Persisted var postalCode: String = ""
}
```

### 主键与索引

```swift
class User: Object {
    // 主键
    @Persisted(primaryKey: true) var id = UUID().uuidString
    
    // 索引属性
    @Persisted(indexed: true) var email: String = ""
    
    @Persisted var username: String = ""
    @Persisted var lastLogin: Date?
}
```

### 忽略属性

```swift
class Task: Object {
    @Persisted var title: String = ""
    @Persisted var completed: Bool = false
    
    // 使用 Persisted(originalName:) 指定属性映射
    @Persisted(originalName: "desc") var description: String = ""
    
    // 不存储在 Realm 中的计算属性
    var isOverdue: Bool {
        guard let dueDate = dueDate else { return false }
        return !completed && dueDate < Date()
    }
    
    @Persisted var dueDate: Date?
}
```

## 基本操作

### 创建与保存对象

```swift
// 创建对象
let person = Person()
person.name = "张三"
person.age = 30
person.birthday = Date(timeIntervalSince1970: 600000000)

let address = Address()
address.street = "中关村大街1号"
address.city = "北京"
address.postalCode = "100080"
person.address = address

// 保存对象
try! realm.write {
    realm.add(person)
}

// 创建并保存
try! realm.write {
    let person = realm.create(Person.self, value: [
        "name": "李四",
        "age": 25,
        "address": [
            "street": "人民路123号",
            "city": "上海"
        ]
    ])
}
```

### 更新对象

```swift
// 直接修改对象
try! realm.write {
    person.age = 31
    person.address?.city = "广州"
}

// 使用主键更新对象
try! realm.write {
    realm.create(User.self, value: ["id": existingUserID, "username": "新用户名"], update: .modified)
}
```

### 删除对象

```swift
// 删除单个对象
try! realm.write {
    realm.delete(person)
}

// 删除多个对象
try! realm.write {
    let youngPeople = realm.objects(Person.self).filter("age < 20")
    realm.delete(youngPeople)
}

// 删除所有对象
try! realm.write {
    realm.deleteAll()
}
```

## 查询

### 基本查询

```swift
// 获取所有对象
let allPersons = realm.objects(Person.self)

// 按条件筛选
let adults = realm.objects(Person.self).filter("age >= 18")

// 组合条件
let filteredPersons = realm.objects(Person.self)
    .filter("age >= 20 AND age < 30 AND name BEGINSWITH 'Z'")

// 排序
let sortedPersons = realm.objects(Person.self).sorted(byKeyPath: "age", ascending: true)

// 多重排序
let multiSortedPersons = realm.objects(Person.self)
    .sorted(by: [
        SortDescriptor(keyPath: "age", ascending: true),
        SortDescriptor(keyPath: "name", ascending: false)
    ])
```

### 链式查询

```swift
// 链式查询
let result = realm.objects(Person.self)
    .filter("age > 20")
    .filter("name CONTAINS '张'")
    .sorted(byKeyPath: "age")
    .prefix(10)  // 限制结果数量

// 聚合操作
let averageAge = realm.objects(Person.self).average(ofProperty: "age")
let maxAge = realm.objects(Person.self).max(ofProperty: "age")
let minAge = realm.objects(Person.self).min(ofProperty: "age")
let sum = realm.objects(Person.self).sum(ofProperty: "age")
```

### 高级查询操作符

```swift
// 基本比较
let equals = realm.objects(Person.self).filter("name == '张三'")
let notEquals = realm.objects(Person.self).filter("name != '张三'")
let greaterThan = realm.objects(Person.self).filter("age > 25")
let lessThanOrEqual = realm.objects(Person.self).filter("age <= 30")

// 字符串操作
let beginsWith = realm.objects(Person.self).filter("name BEGINSWITH '张'")
let endsWith = realm.objects(Person.self).filter("name ENDSWITH '三'")
let contains = realm.objects(Person.self).filter("name CONTAINS '三'")
let like = realm.objects(Person.self).filter("name LIKE '张?'") // ? 匹配单个字符
let regex = realm.objects(Person.self).filter("name MATCHES '张.*'")

// 集合操作
let hasElements = realm.objects(Person.self).filter("tags.@count > 0")
let anyMatch = realm.objects(Person.self).filter("ANY friends.age > 25")
let allMatch = realm.objects(Person.self).filter("ALL friends.age > 20")
```

### 使用 NSPredicate

```swift
// 使用 NSPredicate
let predicate = NSPredicate(format: "age BETWEEN {18, 30} AND name CONTAINS[c] %@", "张")
let results = realm.objects(Person.self).filter(predicate)
```

## 关系

### 一对一关系

```swift
// 定义一对一关系
class Person: Object {
    @Persisted var name: String = ""
    @Persisted var address: Address?  // 一对一关系
}

// 访问关系
let person = realm.objects(Person.self).first!
print(person.address?.city ?? "无地址")

// 更新关系
try! realm.write {
    person.address = newAddress
}
```

### 一对多关系

```swift
// 定义一对多关系
class Team: Object {
    @Persisted(primaryKey: true) var id = UUID().uuidString
    @Persisted var name: String = ""
    @Persisted var members = List<Person>()  // 一对多关系
}

// 使用关系
let team = realm.objects(Team.self).first!

// 添加成员
try! realm.write {
    team.members.append(newPerson)
}

// 查询关系
let teamMembers = team.members
let olderMembers = team.members.filter("age > 30")

// 删除关系中的对象
try! realm.write {
    team.members.remove(at: 0)
    // 或者
    team.members.removeAll()
}
```

### 多对多关系

```swift
// 定义多对多关系
class Student: Object {
    @Persisted(primaryKey: true) var id = UUID().uuidString
    @Persisted var name: String = ""
    @Persisted var courses = List<Course>()
}

class Course: Object {
    @Persisted(primaryKey: true) var id = UUID().uuidString
    @Persisted var name: String = ""
    @Persisted var students = LinkingObjects(fromType: Student.self, property: "courses")
}

// 使用多对多关系
let student = realm.objects(Student.self).first!
let course = realm.objects(Course.self).first!

// 为学生添加课程
try! realm.write {
    student.courses.append(course)
}

// 查询选某课程的所有学生
let studentsInCourse = course.students
```

### 级联删除

```swift
// 定义级联删除关系
class Department: Object {
    @Persisted(primaryKey: true) var id = UUID().uuidString
    @Persisted var name: String = ""
    @Persisted var employees = RealmSwift.List<Employee>()
}

class Employee: Object {
    @Persisted(primaryKey: true) var id = UUID().uuidString
    @Persisted var name: String = ""
    @Persisted var department: LinkingObjects<Department> = LinkingObjects(fromType: Department.self, property: "employees")
}

// 执行级联删除
try! realm.write {
    // 删除部门及其所有员工
    let departmentToDelete = realm.object(ofType: Department.self, forPrimaryKey: departmentID)!
    let employeesToDelete = departmentToDelete.employees
    realm.delete(employeesToDelete)
    realm.delete(departmentToDelete)
}
```

## 事务

### 基本事务

```swift
// 写入事务
try! realm.write {
    // 所有更改必须在写入块内
    let person = Person()
    person.name = "王五"
    realm.add(person)
}

// 嵌套事务
try! realm.write {
    let person1 = Person()
    person1.name = "张三"
    realm.add(person1)
    
    try! realm.write {
        let person2 = Person()
        person2.name = "李四"
        realm.add(person2)
    }
}
```

### 事务控制

```swift
// 手动管理事务
let realm = try! Realm()
realm.beginWrite()

// 执行更改
let person = Person()
person.name = "赵六"
realm.add(person)

// 提交或回滚
if shouldCommit {
    try! realm.commitWrite()
} else {
    realm.cancelWrite()
}

// 使用 try-catch 处理错误
do {
    let realm = try Realm()
    try realm.write {
        // 数据操作
    }
} catch let error as NSError {
    // 处理错误
    print("Realm 错误: \(error)")
}
```

## 通知

### 对象通知

```swift
// 观察单个对象的变化
let person = realm.objects(Person.self).first!
let token = person.observe { change in
    switch change {
    case .change(let properties):
        for property in properties {
            print("属性 '\(property.name)' 从 \(property.oldValue!) 变为 \(property.newValue!)")
        }
    case .deleted:
        print("对象被删除")
    case .error(let error):
        print("观察错误: \(error)")
    }
}

// 取消观察
token.invalidate()
```

### 结果集通知

```swift
// 观察查询结果变化
let results = realm.objects(Person.self).filter("age > 25")
let token = results.observe { changes in
    switch changes {
    case .initial(let people):
        print("初始结果: \(people.count)人")
    case .update(let people, let deletions, let insertions, let modifications):
        print("更新: \(people.count)人")
        print("删除索引: \(deletions)")
        print("插入索引: \(insertions)")
        print("修改索引: \(modifications)")
    case .error(let error):
        print("观察错误: \(error)")
    }
}

// 取消观察
token.invalidate()
```

### Realm 实例通知

```swift
// 观察 Realm 数据库变化
let token = realm.observe { notification, realm in
    print("Realm 数据库发生变化")
    // 重新加载UI等
}

// 取消观察
token.invalidate()
```

### 结合 Combine 框架

```swift
import Combine
import RealmSwift

class ViewModel {
    private var tokens = Set<NotificationToken>()
    private var cancellables = Set<AnyCancellable>()
    
    @Published var people: Results<Person>?
    
    init() {
        let realm = try! Realm()
        people = realm.objects(Person.self)
        
        // 观察结果变化并发布
        tokens.insert(people!.observe { [weak self] _ in
            self?.objectWillChange.send()
        })
    }
    
    deinit {
        tokens.forEach { $0.invalidate() }
    }
}
```

## 高级功能

### 迁移

```swift
// 设置迁移
let config = Realm.Configuration(
    schemaVersion: 2,
    migrationBlock: { migration, oldSchemaVersion in
        if oldSchemaVersion < 1 {
            // v0 到 v1 的迁移
            migration.enumerateObjects(ofType: Person.className()) { oldObject, newObject in
                // 假设我们添加了 fullName 属性并想从 name 派生
                let name = oldObject!["name"] as! String
                newObject!["fullName"] = name
            }
        }
        
        if oldSchemaVersion < 2 {
            // v1 到 v2 的迁移
            migration.enumerateObjects(ofType: Person.className()) { oldObject, newObject in
                // 重命名属性: age -> yearOfBirth
                if let age = oldObject!["age"] as? Int {
                    let currentYear = Calendar.current.component(.year, from: Date())
                    newObject!["yearOfBirth"] = currentYear - age
                }
            }
        }
    }
)

// 设置默认配置
Realm.Configuration.defaultConfiguration = config

// 打开将自动迁移
let realm = try! Realm()
```

### 加密

```swift
// 生成加密密钥
func generateEncryptionKey() -> Data {
    var key = Data(count: 64)
    key.withUnsafeMutableBytes { pointer in
        _ = SecRandomCopyBytes(kSecRandomDefault, 64, pointer.baseAddress!)
    }
    return key
}

// 使用钥匙串存储密钥
func storeEncryptionKey(_ key: Data) {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "realm_encryption_key",
        kSecValueData as String: key
    ]
    
    SecItemDelete(query as CFDictionary)
    SecItemAdd(query as CFDictionary, nil)
}

// 获取加密密钥
func getEncryptionKey() -> Data? {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "realm_encryption_key",
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne
    ]
    
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    if status == errSecSuccess {
        return result as? Data
    } else {
        return nil
    }
}

// 使用加密打开 Realm
func openEncryptedRealm() {
    // 获取或生成密钥
    var encryptionKey = getEncryptionKey()
    if encryptionKey == nil {
        encryptionKey = generateEncryptionKey()
        storeEncryptionKey(encryptionKey!)
    }
    
    // 创建加密配置
    let config = Realm.Configuration(
        encryptionKey: encryptionKey
    )
    
    do {
        let realm = try Realm(configuration: config)
        // 使用加密的 Realm
    } catch let error as NSError {
        print("打开加密 Realm 失败: \(error)")
    }
}
```

### 压缩与优化

```swift
// 压缩数据库文件
try! realm.writeCopy(toFile: compactedRealmURL, encryptionKey: realm.configuration.encryptionKey)

// 在内存压力通知时压缩
NotificationCenter.default.addObserver(forName: UIApplication.didReceiveMemoryWarningNotification, object: nil, queue: nil) { _ in
    autoreleasepool {
        let realm = try! Realm()
        try! realm.writeCopy(toFile: Realm.Configuration.defaultConfiguration.fileURL!, encryptionKey: nil)
    }
}
```

### 后台同步

```swift
// 在后台处理大型导入任务
DispatchQueue.global(qos: .background).async {
    autoreleasepool {
        // 打开后台 Realm 实例
        let backgroundRealm = try! Realm()
        
        // 开始写入事务
        try! backgroundRealm.write {
            // 大批量导入
            for i in 0..<10000 {
                let person = Person()
                person.name = "用户 \(i)"
                person.age = Int.random(in: 18...80)
                backgroundRealm.add(person)
            }
        }
        
        // 完成后通知主线程
        DispatchQueue.main.async {
            print("导入完成")
            // 更新 UI
        }
    }
}
```

## 最佳实践

### 数据访问层

创建数据访问层封装 Realm 操作：

```swift
class DataManager {
    static let shared = DataManager()
    
    private var realm: Realm
    
    private init() {
        do {
            realm = try Realm()
        } catch {
            fatalError("无法初始化 Realm: \(error)")
        }
    }
    
    // MARK: - 用户操作
    
    func saveUser(_ user: User) {
        do {
            try realm.write {
                realm.add(user, update: .modified)
            }
        } catch {
            print("保存用户失败: \(error)")
        }
    }
    
    func deleteUser(_ user: User) {
        do {
            try realm.write {
                realm.delete(user)
            }
        } catch {
            print("删除用户失败: \(error)")
        }
    }
    
    func getUser(withID id: String) -> User? {
        return realm.object(ofType: User.self, forPrimaryKey: id)
    }
    
    func getAllUsers() -> Results<User> {
        return realm.objects(User.self)
    }
    
    func observeUsers(completion: @escaping (Results<User>) -> Void) -> NotificationToken {
        let users = realm.objects(User.self)
        let token = users.observe { _ in
            completion(users)
        }
        return token
    }
    
    // MARK: - 事务辅助方法
    
    func performWrite(_ block: () -> Void) {
        do {
            try realm.write {
                block()
            }
        } catch {
            print("Realm 写入失败: \(error)")
        }
    }
    
    // MARK: - 清理
    
    func deleteAllData() {
        do {
            try realm.write {
                realm.deleteAll()
            }
        } catch {
            print("删除所有数据失败: \(error)")
        }
    }
}
```

### 结合 SwiftUI

```swift
// 定义 Realm 对象
class Task: Object, ObjectKeyIdentifiable {
    @Persisted(primaryKey: true) var id = UUID().uuidString
    @Persisted var title = ""
    @Persisted var completed = false
    @Persisted var createdAt = Date()
}

// 视图模型
class TaskViewModel: ObservableObject {
    @Published var tasks: Results<Task>?
    private var token: NotificationToken?
    
    init() {
        let realm = try! Realm()
        tasks = realm.objects(Task.self).sorted(byKeyPath: "createdAt", ascending: false)
        
        // 观察变化
        token = tasks?.observe { [weak self] _ in
            self?.objectWillChange.send()
        }
    }
    
    deinit {
        token?.invalidate()
    }
    
    func addTask(title: String) {
        let task = Task()
        task.title = title
        
        let realm = try! Realm()
        try! realm.write {
            realm.add(task)
        }
    }
    
    func toggleCompleted(task: Task) {
        let realm = try! Realm()
        try! realm.write {
            task.completed.toggle()
        }
    }
    
    func deleteTask(task: Task) {
        let realm = try! Realm()
        try! realm.write {
            realm.delete(task)
        }
    }
}

// SwiftUI 视图
struct TaskListView: View {
    @StateObject var viewModel = TaskViewModel()
    @State private var newTaskTitle = ""
    
    var body: some View {
        VStack {
            HStack {
                TextField("新任务", text: $newTaskTitle)
                Button("添加") {
                    viewModel.addTask(title: newTaskTitle)
                    newTaskTitle = ""
                }
                .disabled(newTaskTitle.isEmpty)
            }
            .padding()
            
            List {
                ForEach(viewModel.tasks ?? []) { task in
                    HStack {
                        Button(action: {
                            viewModel.toggleCompleted(task: task)
                        }) {
                            Image(systemName: task.completed ? "checkmark.circle.fill" : "circle")
                                .foregroundColor(task.completed ? .green : .gray)
                        }
                        .buttonStyle(PlainButtonStyle())
                        
                        Text(task.title)
                            .strikethrough(task.completed)
                    }
                }
                .onDelete { indexSet in
                    for index in indexSet {
                        if let task = viewModel.tasks?[index] {
                            viewModel.deleteTask(task: task)
                        }
                    }
                }
            }
        }
    }
}
```

### 性能优化

```swift
// 批量操作
try! realm.write {
    // 批量添加
    realm.add(largeArrayOfObjects)
    
    // 或者添加一个事务中添加多个对象
    for i in 0..<1000 {
        let person = Person()
        person.name = "用户 \(i)"
        realm.add(person)
    }
}

// 非UI线程处理大型操作
DispatchQueue.global(qos: .background).async {
    autoreleasepool {
        // 每个线程使用自己的 Realm 实例
        let backgroundRealm = try! Realm()
        
        // 开始写入事务
        try! backgroundRealm.write {
            // 大批量导入
            for item in largeDataArray {
                backgroundRealm.create(DataItem.self, value: item)
            }
        }
    }
}

// 懒加载关系
class Book: Object {
    @Persisted(primaryKey: true) var id = UUID().uuidString
    @Persisted var title = ""
    
    // 使用懒加载减少内存使用
    private var _author: Author?
    var author: Author {
        if let cachedAuthor = _author {
            return cachedAuthor
        }
        
        guard let realm = realm,
              let authorID = authorID,
              let loadedAuthor = realm.object(ofType: Author.self, forPrimaryKey: authorID) else {
            fatalError("无法加载作者")
        }
        
        _author = loadedAuthor
        return loadedAuthor
    }
    
    @Persisted var authorID: String?
}
```

## 与其他持久化方案对比

### Realm vs Core Data

| 特性 | Realm | Core Data |
|------|-------|-----------|
| 易用性 | 简单直观的 API | 相对复杂的设置 |
| 性能 | 优化的读写性能 | 需要手动优化 |
| 跨平台 | iOS 和 Android 共享模型 | 仅限 Apple 平台 |
| 多线程 | 简化的线程处理 | 需要手动管理上下文 |
| 迁移 | 简单的迁移模型 | 更复杂的迁移机制 |
| 生态系统 | 第三方库 | 苹果官方支持 |

### Realm vs SQLite

| 特性 | Realm | SQLite |
|------|-------|--------|
| 数据模型 | 对象导向 | 关系型表格 |
| API | 面向对象的 API | SQL 或包装 API (FMDB) |
| 性能 | 通常更快 | 基本性能良好 |
| 特性集 | 实时更新、加密等 | 轻量级、稳定 |
| 设置难度 | 简单 | 需要更多配置 |

### 何时选择 Realm

- 需要跨平台开发（iOS 和 Android）
- 需要实时更新和响应式 UI
- 处理复杂的对象关系
- 重视开发速度和简单性

### 何时选择其他方案

- Core Data：深度集成 Apple 生态系统
- SQLite：需要完全控制数据库结构和查询
- UserDefaults：仅存储简单键值对
- FileSystem：处理大型文件或二进制数据

Realm 提供了简单易用的 API 和强大的功能，特别适合需要高性能和简化开发体验的现代 iOS 应用。它的跨平台特性和实时更新机制使其成为许多开发者的首选数据库解决方案。 