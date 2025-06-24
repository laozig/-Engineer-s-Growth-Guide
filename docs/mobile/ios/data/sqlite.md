# SQLite 与 FMDB

SQLite 是一个轻量级的关系型数据库，在 iOS 开发中被广泛使用。FMDB 是一个流行的 Objective-C 封装库，简化了 SQLite 在 iOS 中的使用。本文将介绍如何在 iOS 应用中使用 SQLite 和 FMDB。

## 目录

- [SQLite 基础](#sqlite-基础)
- [原生 SQLite API](#原生-sqlite-api)
- [FMDB 简介](#fmdb-简介)
- [基本操作](#基本操作)
- [高级功能](#高级功能)
- [事务与批处理](#事务与批处理)
- [线程安全](#线程安全)
- [性能优化](#性能优化)
- [最佳实践](#最佳实践)

## SQLite 基础

SQLite 是一个自包含、无服务器、零配置的关系型数据库引擎。其特点包括：

- 轻量级：整个数据库就是一个文件
- 零配置：无需安装或管理服务器
- 跨平台：可在多种操作系统上运行
- 可靠性高：广泛的测试和部署
- 开源免费：公共领域许可证

### SQLite 数据类型

SQLite 支持以下基本数据类型：

- NULL：空值
- INTEGER：整数
- REAL：浮点数
- TEXT：字符串
- BLOB：二进制大对象

SQLite 使用"动态类型系统"，这意味着一个列可以存储任何类型的数据，而不仅仅是声明的类型。

## 原生 SQLite API

iOS 内置了 SQLite 库，可以直接使用 C API 进行操作。

### 设置项目

1. 添加 `libsqlite3.tbd` 库到项目
2. 引入 SQLite 头文件

```swift
import SQLite3
```

### 基本操作示例

```swift
func basicSQLiteExample() {
    var db: OpaquePointer?
    let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    let databasePath = documentsDirectory.appendingPathComponent("database.sqlite").path
    
    // 打开数据库
    if sqlite3_open(databasePath, &db) == SQLITE_OK {
        print("成功打开数据库")
        
        // 创建表
        let createTableSQL = """
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER,
                email TEXT
            );
        """
        
        if executeSQL(db: db, sql: createTableSQL) {
            print("表创建成功")
            
            // 插入数据
            let insertSQL = "INSERT INTO Users (name, age, email) VALUES ('张三', 30, 'zhangsan@example.com');"
            if executeSQL(db: db, sql: insertSQL) {
                print("数据插入成功")
            }
            
            // 查询数据
            queryUsers(db: db)
        }
        
        // 关闭数据库
        sqlite3_close(db)
    } else {
        print("打开数据库失败: \(String(cString: sqlite3_errmsg(db)))")
    }
}

func executeSQL(db: OpaquePointer?, sql: String) -> Bool {
    var errMsg: UnsafeMutablePointer<Int8>?
    
    if sqlite3_exec(db, sql, nil, nil, &errMsg) != SQLITE_OK {
        let errorMessage = String(cString: errMsg!)
        print("SQL执行失败: \(errorMessage)")
        sqlite3_free(errMsg)
        return false
    }
    
    return true
}

func queryUsers(db: OpaquePointer?) {
    let querySQL = "SELECT * FROM Users;"
    var statement: OpaquePointer?
    
    if sqlite3_prepare_v2(db, querySQL, -1, &statement, nil) == SQLITE_OK {
        while sqlite3_step(statement) == SQLITE_ROW {
            let id = sqlite3_column_int(statement, 0)
            let name = String(cString: sqlite3_column_text(statement, 1))
            let age = sqlite3_column_int(statement, 2)
            let email = String(cString: sqlite3_column_text(statement, 3))
            
            print("用户: ID=\(id), 姓名=\(name), 年龄=\(age), 邮箱=\(email)")
        }
    } else {
        print("准备查询失败: \(String(cString: sqlite3_errmsg(db)))")
    }
    
    sqlite3_finalize(statement)
}
```

### 参数绑定

使用参数绑定可以防止 SQL 注入攻击：

```swift
func insertUserWithParameters(db: OpaquePointer?, name: String, age: Int, email: String) -> Bool {
    let insertSQL = "INSERT INTO Users (name, age, email) VALUES (?, ?, ?);"
    var statement: OpaquePointer?
    
    if sqlite3_prepare_v2(db, insertSQL, -1, &statement, nil) == SQLITE_OK {
        // 绑定参数
        sqlite3_bind_text(statement, 1, (name as NSString).utf8String, -1, nil)
        sqlite3_bind_int(statement, 2, Int32(age))
        sqlite3_bind_text(statement, 3, (email as NSString).utf8String, -1, nil)
        
        // 执行
        if sqlite3_step(statement) == SQLITE_DONE {
            print("用户插入成功")
            sqlite3_finalize(statement)
            return true
        } else {
            print("插入失败: \(String(cString: sqlite3_errmsg(db)))")
        }
    } else {
        print("准备语句失败: \(String(cString: sqlite3_errmsg(db)))")
    }
    
    sqlite3_finalize(statement)
    return false
}
```

原生 SQLite API 提供了完整的功能，但使用起来较为繁琐，需要处理许多底层细节。因此，大多数开发者会选择使用封装库如 FMDB。

## FMDB 简介

FMDB 是一个基于 SQLite 的 Objective-C 封装库，提供了更简洁、更面向对象的 API。

### 添加 FMDB

使用 CocoaPods 添加 FMDB：

```ruby
pod 'FMDB'
```

或者使用 Swift Package Manager：

```swift
dependencies: [
    .package(url: "https://github.com/ccgus/fmdb", from: "2.7.0")
]
```

### 引入 FMDB

```swift
import FMDB
```

## 基本操作

### 创建/打开数据库

```swift
let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
let databasePath = documentsDirectory.appendingPathComponent("database.sqlite").path
let database = FMDatabase(path: databasePath)

if !database.open() {
    print("无法打开数据库")
    return
}
```

### 创建表

```swift
let createTableSQL = """
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        age INTEGER,
        email TEXT
    );
"""

if !database.executeStatements(createTableSQL) {
    print("创建表失败: \(database.lastErrorMessage())")
}
```

### 插入数据

```swift
let insertSQL = "INSERT INTO Users (name, age, email) VALUES (?, ?, ?)"
if !database.executeUpdate(insertSQL, withArgumentsIn: ["张三", 30, "zhangsan@example.com"]) {
    print("插入数据失败: \(database.lastErrorMessage())")
}
```

### 查询数据

```swift
let querySQL = "SELECT * FROM Users"
if let resultSet = database.executeQuery(querySQL, withArgumentsIn: []) {
    while resultSet.next() {
        let id = Int(resultSet.int(forColumn: "id"))
        let name = resultSet.string(forColumn: "name") ?? ""
        let age = Int(resultSet.int(forColumn: "age"))
        let email = resultSet.string(forColumn: "email") ?? ""
        
        print("用户: ID=\(id), 姓名=\(name), 年龄=\(age), 邮箱=\(email)")
    }
    resultSet.close()
}
```

### 更新数据

```swift
let updateSQL = "UPDATE Users SET age = ? WHERE name = ?"
if !database.executeUpdate(updateSQL, withArgumentsIn: [31, "张三"]) {
    print("更新数据失败: \(database.lastErrorMessage())")
}
```

### 删除数据

```swift
let deleteSQL = "DELETE FROM Users WHERE name = ?"
if !database.executeUpdate(deleteSQL, withArgumentsIn: ["张三"]) {
    print("删除数据失败: \(database.lastErrorMessage())")
}
```

### 关闭数据库

```swift
database.close()
```

## 高级功能

### BLOB 数据处理

FMDB 可以轻松处理二进制数据，如图片：

```swift
// 保存图片
func saveImage(_ image: UIImage, forUserID userID: Int) -> Bool {
    guard let imageData = image.jpegData(compressionQuality: 0.8) else {
        return false
    }
    
    let updateSQL = "UPDATE Users SET avatar = ? WHERE id = ?"
    return database.executeUpdate(updateSQL, withArgumentsIn: [imageData, userID])
}

// 读取图片
func getImageForUser(userID: Int) -> UIImage? {
    let querySQL = "SELECT avatar FROM Users WHERE id = ?"
    
    if let resultSet = database.executeQuery(querySQL, withArgumentsIn: [userID]),
       resultSet.next(),
       let imageData = resultSet.data(forColumn: "avatar") {
        resultSet.close()
        return UIImage(data: imageData)
    }
    
    return nil
}
```

### 复杂查询

FMDB 支持各种复杂的 SQL 查询：

```swift
// 连接查询
let joinSQL = """
    SELECT Users.name, Orders.product, Orders.price
    FROM Users
    INNER JOIN Orders ON Users.id = Orders.user_id
    WHERE Orders.price > ?
    ORDER BY Orders.price DESC
"""

if let resultSet = database.executeQuery(joinSQL, withArgumentsIn: [100]) {
    while resultSet.next() {
        let name = resultSet.string(forColumn: "name") ?? ""
        let product = resultSet.string(forColumn: "product") ?? ""
        let price = resultSet.double(forColumn: "price")
        
        print("\(name) 购买了 \(product)，价格：\(price)")
    }
    resultSet.close()
}

// 聚合查询
let aggregateSQL = """
    SELECT Users.name, COUNT(Orders.id) as order_count, SUM(Orders.price) as total_spent
    FROM Users
    LEFT JOIN Orders ON Users.id = Orders.user_id
    GROUP BY Users.id
    HAVING total_spent > ?
"""

if let resultSet = database.executeQuery(aggregateSQL, withArgumentsIn: [1000]) {
    while resultSet.next() {
        let name = resultSet.string(forColumn: "name") ?? ""
        let orderCount = Int(resultSet.int(forColumn: "order_count"))
        let totalSpent = resultSet.double(forColumn: "total_spent")
        
        print("\(name) 共下了 \(orderCount) 单，总消费：\(totalSpent)")
    }
    resultSet.close()
}
```

## 事务与批处理

### 使用事务

事务可以提高大量操作的性能，并保证操作的原子性：

```swift
func importUsers(_ users: [[String: Any]]) -> Bool {
    database.beginTransaction()
    
    let insertSQL = "INSERT INTO Users (name, age, email) VALUES (?, ?, ?)"
    
    for user in users {
        guard let name = user["name"] as? String,
              let age = user["age"] as? Int,
              let email = user["email"] as? String else {
            continue
        }
        
        if !database.executeUpdate(insertSQL, withArgumentsIn: [name, age, email]) {
            print("导入用户失败: \(database.lastErrorMessage())")
            database.rollback()
            return false
        }
    }
    
    return database.commit()
}
```

### 批量操作

```swift
func batchUpdateAges(ageMapping: [String: Int]) -> Bool {
    database.beginTransaction()
    
    let updateSQL = "UPDATE Users SET age = ? WHERE name = ?"
    
    for (name, age) in ageMapping {
        if !database.executeUpdate(updateSQL, withArgumentsIn: [age, name]) {
            print("更新年龄失败: \(database.lastErrorMessage())")
            database.rollback()
            return false
        }
    }
    
    return database.commit()
}
```

## 线程安全

FMDB 提供了线程安全的数据库队列：

```swift
let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
let databasePath = documentsDirectory.appendingPathComponent("database.sqlite").path
let databaseQueue = FMDatabaseQueue(path: databasePath)

// 在队列中执行操作
databaseQueue.inDatabase { db in
    // 使用 db 执行数据库操作
    let createTableSQL = "CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY, name TEXT);"
    db.executeStatements(createTableSQL)
    
    db.executeUpdate("INSERT INTO Users (name) VALUES (?)", withArgumentsIn: ["李四"])
}

// 在事务中执行多个操作
databaseQueue.inTransaction { db, rollback in
    do {
        try db.executeUpdate("INSERT INTO Users (name) VALUES (?)", values: ["王五"])
        try db.executeUpdate("UPDATE Users SET name = ? WHERE id = ?", values: ["李五", 2])
        
        // 如果需要回滚
        if someCondition {
            rollback.pointee = true
            return
        }
    } catch {
        print("事务失败: \(error)")
        rollback.pointee = true
    }
}
```

## 性能优化

### 索引优化

```swift
// 创建索引提高查询性能
let createIndexSQL = "CREATE INDEX IF NOT EXISTS idx_users_name ON Users (name);"
database.executeStatements(createIndexSQL)
```

### 预编译语句

```swift
// 多次使用的语句可以预编译
if let statement = database.prepareStatement("INSERT INTO Users (name, age) VALUES (?, ?)") {
    for i in 1...1000 {
        statement.reset()
        statement.bindString("用户\(i)", forIndex: 1)
        statement.bindInt32(Int32(20 + (i % 50)), forIndex: 2)
        
        if !statement.executeUpdate() {
            print("执行预编译语句失败")
            break
        }
    }
    statement.close()
}
```

### 批量插入优化

```swift
func optimizedBatchInsert(_ items: [[String: Any]]) {
    // 使用单个事务和拼接的 SQL 语句
    database.beginTransaction()
    
    var insertSQL = "INSERT INTO Users (name, age, email) VALUES "
    var arguments: [Any] = []
    var placeholders: [String] = []
    
    for item in items {
        placeholders.append("(?, ?, ?)")
        arguments.append(item["name"] as? String ?? "")
        arguments.append(item["age"] as? Int ?? 0)
        arguments.append(item["email"] as? String ?? "")
    }
    
    insertSQL += placeholders.joined(separator: ", ")
    
    if !database.executeUpdate(insertSQL, withArgumentsIn: arguments) {
        print("批量插入失败: \(database.lastErrorMessage())")
        database.rollback()
    } else {
        database.commit()
    }
}
```

## 最佳实践

### 数据库管理器

创建一个数据库管理器类封装数据库操作：

```swift
class DatabaseManager {
    static let shared = DatabaseManager()
    
    private let databaseQueue: FMDatabaseQueue
    private let databasePath: String
    
    private init() {
        let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        databasePath = documentsDirectory.appendingPathComponent("app-database.sqlite").path
        
        // 创建数据库队列
        databaseQueue = FMDatabaseQueue(path: databasePath)
        
        // 初始化数据库
        createTables()
    }
    
    private func createTables() {
        databaseQueue.inDatabase { db in
            // 创建用户表
            let createUsersTableSQL = """
                CREATE TABLE IF NOT EXISTS Users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    age INTEGER,
                    email TEXT,
                    avatar BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """
            
            // 创建订单表
            let createOrdersTableSQL = """
                CREATE TABLE IF NOT EXISTS Orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    product TEXT NOT NULL,
                    price REAL,
                    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES Users(id)
                );
            """
            
            db.executeStatements(createUsersTableSQL)
            db.executeStatements(createOrdersTableSQL)
            
            // 创建索引
            db.executeStatements("CREATE INDEX IF NOT EXISTS idx_users_email ON Users (email);")
            db.executeStatements("CREATE INDEX IF NOT EXISTS idx_orders_user_id ON Orders (user_id);")
        }
    }
    
    // MARK: - 用户操作
    
    func createUser(name: String, age: Int, email: String, completion: @escaping (Int64?) -> Void) {
        databaseQueue.inDatabase { db in
            let insertSQL = "INSERT INTO Users (name, age, email) VALUES (?, ?, ?)"
            
            if db.executeUpdate(insertSQL, withArgumentsIn: [name, age, email]) {
                completion(db.lastInsertRowId)
            } else {
                print("创建用户失败: \(db.lastErrorMessage())")
                completion(nil)
            }
        }
    }
    
    func getUser(byID id: Int, completion: @escaping ([String: Any]?) -> Void) {
        databaseQueue.inDatabase { db in
            let querySQL = "SELECT * FROM Users WHERE id = ?"
            
            if let resultSet = db.executeQuery(querySQL, withArgumentsIn: [id]),
               resultSet.next() {
                var userData: [String: Any] = [:]
                
                userData["id"] = Int(resultSet.int(forColumn: "id"))
                userData["name"] = resultSet.string(forColumn: "name")
                userData["age"] = Int(resultSet.int(forColumn: "age"))
                userData["email"] = resultSet.string(forColumn: "email")
                userData["created_at"] = resultSet.date(forColumn: "created_at")
                
                if let avatarData = resultSet.data(forColumn: "avatar") {
                    userData["avatar"] = avatarData
                }
                
                resultSet.close()
                completion(userData)
            } else {
                completion(nil)
            }
        }
    }
    
    func getAllUsers(completion: @escaping ([[String: Any]]) -> Void) {
        databaseQueue.inDatabase { db in
            let querySQL = "SELECT * FROM Users ORDER BY name"
            var users: [[String: Any]] = []
            
            if let resultSet = db.executeQuery(querySQL, withArgumentsIn: []) {
                while resultSet.next() {
                    var userData: [String: Any] = [:]
                    
                    userData["id"] = Int(resultSet.int(forColumn: "id"))
                    userData["name"] = resultSet.string(forColumn: "name")
                    userData["age"] = Int(resultSet.int(forColumn: "age"))
                    userData["email"] = resultSet.string(forColumn: "email")
                    
                    users.append(userData)
                }
                resultSet.close()
            }
            
            completion(users)
        }
    }
    
    func updateUser(id: Int, name: String?, age: Int?, email: String?, completion: @escaping (Bool) -> Void) {
        databaseQueue.inDatabase { db in
            var updateParts: [String] = []
            var arguments: [Any] = []
            
            if let name = name {
                updateParts.append("name = ?")
                arguments.append(name)
            }
            
            if let age = age {
                updateParts.append("age = ?")
                arguments.append(age)
            }
            
            if let email = email {
                updateParts.append("email = ?")
                arguments.append(email)
            }
            
            guard !updateParts.isEmpty else {
                completion(false)
                return
            }
            
            let updateSQL = "UPDATE Users SET \(updateParts.joined(separator: ", ")) WHERE id = ?"
            arguments.append(id)
            
            let success = db.executeUpdate(updateSQL, withArgumentsIn: arguments)
            completion(success)
        }
    }
    
    func deleteUser(id: Int, completion: @escaping (Bool) -> Void) {
        databaseQueue.inTransaction { db, rollback in
            // 先删除用户的订单
            let deleteOrdersSQL = "DELETE FROM Orders WHERE user_id = ?"
            if !db.executeUpdate(deleteOrdersSQL, withArgumentsIn: [id]) {
                print("删除用户订单失败: \(db.lastErrorMessage())")
                rollback.pointee = true
                completion(false)
                return
            }
            
            // 然后删除用户
            let deleteUserSQL = "DELETE FROM Users WHERE id = ?"
            if !db.executeUpdate(deleteUserSQL, withArgumentsIn: [id]) {
                print("删除用户失败: \(db.lastErrorMessage())")
                rollback.pointee = true
                completion(false)
                return
            }
            
            completion(true)
        }
    }
    
    // MARK: - 订单操作
    
    func createOrder(userID: Int, product: String, price: Double, completion: @escaping (Int64?) -> Void) {
        databaseQueue.inDatabase { db in
            let insertSQL = "INSERT INTO Orders (user_id, product, price) VALUES (?, ?, ?)"
            
            if db.executeUpdate(insertSQL, withArgumentsIn: [userID, product, price]) {
                completion(db.lastInsertRowId)
            } else {
                print("创建订单失败: \(db.lastErrorMessage())")
                completion(nil)
            }
        }
    }
    
    // 其他订单相关方法...
    
    // MARK: - 数据库维护
    
    func vacuumDatabase() {
        databaseQueue.inDatabase { db in
            db.executeStatements("VACUUM;")
        }
    }
    
    func getDatabaseSize() -> Int {
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: databasePath)
            if let size = attributes[.size] as? Int {
                return size
            }
        } catch {
            print("获取数据库大小失败: \(error)")
        }
        return 0
    }
}
```

### 面向对象的封装

创建模型类与数据库交互：

```swift
struct User {
    var id: Int64?
    var name: String
    var age: Int
    var email: String
    var avatar: Data?
    var createdAt: Date?
    
    init(name: String, age: Int, email: String, avatar: Data? = nil, id: Int64? = nil, createdAt: Date? = nil) {
        self.name = name
        self.age = age
        self.email = email
        self.avatar = avatar
        self.id = id
        self.createdAt = createdAt
    }
    
    // 从数据库字典创建
    init?(dictionary: [String: Any]) {
        guard let name = dictionary["name"] as? String,
              let age = dictionary["age"] as? Int,
              let email = dictionary["email"] as? String else {
            return nil
        }
        
        self.name = name
        self.age = age
        self.email = email
        self.id = dictionary["id"] as? Int64
        self.avatar = dictionary["avatar"] as? Data
        self.createdAt = dictionary["created_at"] as? Date
    }
    
    // 保存到数据库
    func save(completion: @escaping (Bool) -> Void) {
        if let id = id {
            // 更新现有用户
            DatabaseManager.shared.updateUser(id: Int(id), name: name, age: age, email: email) { success in
                completion(success)
            }
        } else {
            // 创建新用户
            DatabaseManager.shared.createUser(name: name, age: age, email: email) { newID in
                completion(newID != nil)
            }
        }
    }
    
    // 删除用户
    static func delete(id: Int64, completion: @escaping (Bool) -> Void) {
        DatabaseManager.shared.deleteUser(id: Int(id), completion: completion)
    }
    
    // 获取用户
    static func get(byID id: Int64, completion: @escaping (User?) -> Void) {
        DatabaseManager.shared.getUser(byID: Int(id)) { userData in
            guard let userData = userData else {
                completion(nil)
                return
            }
            
            let user = User(dictionary: userData)
            completion(user)
        }
    }
    
    // 获取所有用户
    static func getAll(completion: @escaping ([User]) -> Void) {
        DatabaseManager.shared.getAllUsers { usersData in
            let users = usersData.compactMap { User(dictionary: $0) }
            completion(users)
        }
    }
}
```

通过以上封装，应用代码可以更加面向对象地与数据库交互：

```swift
// 创建用户
let newUser = User(name: "赵六", age: 28, email: "zhaoliu@example.com")
newUser.save { success in
    if success {
        print("用户保存成功")
    }
}

// 获取所有用户
User.getAll { users in
    for user in users {
        print("用户: \(user.name), 年龄: \(user.age)")
    }
}

// 查找并更新用户
User.get(byID: 1) { user in
    if var user = user {
        user.age = 29
        user.save { success in
            print("用户更新\(success ? "成功" : "失败")")
        }
    }
}
```

SQLite 是一个功能强大的轻量级数据库，适合大多数移动应用场景。FMDB 提供了简洁的 API，极大地简化了在 iOS 中使用 SQLite 的难度。通过合理设计数据结构和优化查询，SQLite 可以高效地处理大量数据，为应用提供可靠的持久化存储解决方案。 