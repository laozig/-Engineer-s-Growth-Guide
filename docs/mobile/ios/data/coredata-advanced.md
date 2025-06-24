# Core Data 进阶

本文档将深入探讨 Core Data 的高级功能和技术，包括关系管理、数据迁移、性能优化和多线程处理。

## 目录

- [关系管理](#关系管理)
- [数据迁移](#数据迁移)
- [性能优化](#性能优化)
- [多线程处理](#多线程处理)
- [NSFetchedResultsController](#nsfetchedresultscontroller)
- [与 SwiftUI 集成](#与-swiftui-集成)
- [最佳实践](#最佳实践)

## 关系管理

Core Data 支持实体之间的一对一、一对多和多对多关系。良好的关系设计对应用性能和数据完整性至关重要。

### 配置关系

在 Core Data 模型编辑器中，可以通过以下步骤配置关系：

1. 选择源实体
2. 添加关系（Add Relationship）
3. 设置目标实体（Destination）
4. 配置关系类型和基数（To-One 或 To-Many）
5. 设置反向关系（Inverse）
6. 配置删除规则（Delete Rule）

下面是在代码中操作关系的示例：

```swift
// 一对多关系：部门和员工
// 假设已经有了 Department 和 Employee 实体类

// 创建部门
let department = Department(context: context)
department.name = "研发部"

// 创建员工
let employee1 = Employee(context: context)
employee1.name = "张三"
employee1.position = "iOS 开发"

let employee2 = Employee(context: context)
employee2.name = "李四"
employee2.position = "Android 开发"

// 建立关系 - 方法1：设置单个对象的关系
employee1.department = department
employee2.department = department

// 建立关系 - 方法2：处理集合关系（一对多）
// 确保 Department 实体有一个 employees 关系，类型为 NSSet
department.addToEmployees(employee1)
department.addToEmployees(employee2)

// 或者一次添加多个
department.addToEmployees(NSSet(array: [employee1, employee2]))

// 保存上下文
try? context.save()

// 查询关系
let departmentEmployees = department.employees?.allObjects as? [Employee] ?? []
print("部门 \(department.name!) 有 \(departmentEmployees.count) 名员工")

// 通过关系查询
let employeeDepartment = employee1.department
print("\(employee1.name!) 属于 \(employeeDepartment?.name ?? "无部门")")
```

### 关系删除规则

Core Data 提供了四种关系删除规则，用于处理关联对象的删除行为：

- **Nullify**：（默认规则）删除源对象时，将目标对象的关系设为 `nil`。例如，删除部门时，该部门的员工将不再关联到任何部门。
  
- **Cascade**：删除源对象时，级联删除所有相关的目标对象。例如，删除部门时，同时删除该部门的所有员工。
  
- **Deny**：如果存在相关对象，则阻止删除源对象。例如，如果部门中还有员工，则不允许删除该部门。
  
- **No Action**：不执行任何操作。这通常用于特殊情况，大多数情况下不推荐使用。

使用示例：

```swift
// 实现级联删除
// 在 Core Data 模型中将部门对员工的关系删除规则设置为 Cascade

// 删除部门，所有关联的员工也会被删除
context.delete(department)
try? context.save()

// 实现 Deny 删除规则的逻辑检查
func canDeleteDepartment(_ department: Department) -> Bool {
    // 假设关系删除规则设置为 Deny
    if let employees = department.employees, employees.count > 0 {
        return false // 有员工，不能删除
    }
    return true // 没有员工，可以删除
}

// 使用关系删除规则
if canDeleteDepartment(department) {
    context.delete(department)
    try? context.save()
} else {
    print("无法删除部门：还有员工关联到该部门")
}
```

### 关系验证与约束

Core Data 允许为关系添加验证规则和约束，确保数据完整性：

```swift
// 在 NSManagedObject 子类中实现验证方法
class Department: NSManagedObject {
    // ...属性定义...
    
    // 验证关系
    override func validateEmployees(_ value: AutoreleasingUnsafeMutablePointer<NSSet?>) throws {
        guard let employees = value.pointee else { return }
        
        // 验证部门员工数量不超过限制
        if employees.count > 50 {
            throw NSError(domain: "DepartmentError", code: 1001, userInfo: [
                NSLocalizedDescriptionKey: "部门员工不能超过50人"
            ])
        }
        
        // 其他验证逻辑...
    }
}
```

### 多对多关系管理

多对多关系在 Core Data 中通常通过两个一对多关系实现：

```swift
// 多对多关系：学生和课程
// 假设已经有了 Student 和 Course 实体类

// 创建学生
let student1 = Student(context: context)
student1.name = "王五"

let student2 = Student(context: context)
student2.name = "赵六"

// 创建课程
let course1 = Course(context: context)
course1.name = "iOS 开发"

let course2 = Course(context: context)
course2.name = "Swift 编程"

// 建立多对多关系
student1.addToCourses(course1)
student1.addToCourses(course2)
student2.addToCourses(course1)

// 或者从课程方向建立关系
course1.addToStudents(student1)
course1.addToStudents(student2)

// 保存上下文
try? context.save()

// 查询多对多关系
let studentCourses = student1.courses?.allObjects as? [Course] ?? []
print("\(student1.name!) 选修了 \(studentCourses.count) 门课程")

let courseStudents = course1.students?.allObjects as? [Student] ?? []
print("\(course1.name!) 课程有 \(courseStudents.count) 名学生")
```

### 关系预取与懒加载

对于复杂关系，可以使用预取提高性能，或者实现懒加载策略：

```swift
// 使用关系预取提高查询性能
let fetchRequest: NSFetchRequest<Department> = Department.fetchRequest()

// 预取员工关系，减少后续查询
fetchRequest.relationshipKeyPathsForPrefetching = ["employees"]

let departments = try? context.fetch(fetchRequest)

// 实现关系懒加载
class CustomDepartment: NSManagedObject {
    // 关系懒加载属性
    private var _cachedEmployees: [Employee]?
    
    var cachedEmployees: [Employee] {
        if _cachedEmployees == nil {
            // 只在首次访问时加载员工
            _cachedEmployees = employees?.allObjects as? [Employee] ?? []
        }
        return _cachedEmployees!
    }
    
    // 重置缓存
    func resetCache() {
        _cachedEmployees = nil
    }
}
```

## 数据迁移

随着应用程序的演变，数据模型需要进行迁移以适应新的需求。Core Data 提供了多种迁移机制，从简单的轻量级迁移到复杂的自定义迁移。

### 轻量级迁移

轻量级迁移是最简单的迁移方式，适用于简单的模型变更，如添加属性、重命名属性或修改可选性。

```swift
// 配置轻量级迁移
let container = NSPersistentContainer(name: "MyDataModel")

// 获取第一个存储描述符
let description = container.persistentStoreDescriptions.first

// 启用自动轻量级迁移
description?.shouldMigrateStoreAutomatically = true
description?.shouldInferMappingModelAutomatically = true

container.loadPersistentStores { (storeDescription, error) in
    if let error = error as NSError? {
        print("无法加载持久化存储: \(error), \(error.userInfo)")
    }
}
```

轻量级迁移支持的变更类型：
- 添加新实体或属性
- 使可选属性变为非可选（如果有默认值）
- 使非可选属性变为可选
- 删除实体或属性
- 简单的重命名（通过 Renaming ID）

### 使用 Mapping Model 进行迁移

对于轻量级迁移无法处理的复杂变更，可以创建映射模型（Mapping Model）：

1. 在 Xcode 中创建映射模型文件（File > New > File > Mapping Model）
2. 选择源模型和目标模型
3. 配置实体映射和属性映射

```swift
// 使用自定义映射模型进行迁移
func migrateStore(at storeURL: URL) {
    
    guard let sourceModel = NSManagedObjectModel.modelVersions(forModelNamed: "MyDataModel").first else {
        print("无法找到源模型")
        return
    }
    
    guard let destinationModel = NSManagedObjectModel(contentsOf: Bundle.main.url(forResource: "MyDataModel_v2", withExtension: "momd")!) else {
        print("无法找到目标模型")
        return
    }
    
    // 获取映射模型
    guard let mappingModel = NSMappingModel(from: nil, forSourceModel: sourceModel, destinationModel: destinationModel) else {
        print("无法创建映射模型")
        return
    }
    
    // 创建迁移管理器
    let manager = NSMigrationManager(sourceModel: sourceModel, destinationModel: destinationModel)
    
    // 目标存储URL
    let destinationURL = storeURL.deletingLastPathComponent().appendingPathComponent("MyDataModel_v2.sqlite")
    
    do {
        // 执行迁移
        try manager.migrateStore(
            from: storeURL,
            sourceType: NSSQLiteStoreType,
            options: nil,
            with: mappingModel,
            toDestinationURL: destinationURL,
            destinationType: NSSQLiteStoreType,
            destinationOptions: nil
        )
        
        // 迁移成功，替换旧存储
        try FileManager.default.removeItem(at: storeURL)
        try FileManager.default.moveItem(at: destinationURL, to: storeURL)
        
        print("数据迁移成功")
    } catch {
        print("迁移失败: \(error)")
    }
}
```

### 自定义实体迁移策略

对于复杂的迁移逻辑，可以创建自定义的 `NSEntityMigrationPolicy` 子类：

```swift
// 自定义实体迁移策略
class CustomEmployeeMigrationPolicy: NSEntityMigrationPolicy {
    
    // 在实体映射过程中自定义迁移逻辑
    override func createDestinationInstances(forSource sInstance: NSManagedObject, in mapping: NSEntityMapping, manager: NSMigrationManager) throws {
        // 调用父类方法创建目标实例
        try super.createDestinationInstances(forSource: sInstance, in: mapping, manager: manager)
        
        // 获取迁移过程中创建的目标实例
        guard let destinationEmployee = manager.destinationInstances(forEntityMappingName: mapping.name, sourceInstances: [sInstance]).first else {
            return
        }
        
        // 自定义迁移逻辑
        if let sourceFullName = sInstance.value(forKey: "fullName") as? String {
            // 假设我们正在将单一的 fullName 拆分为 firstName 和 lastName
            let nameComponents = sourceFullName.components(separatedBy: " ")
            
            if nameComponents.count > 0 {
                destinationEmployee.setValue(nameComponents[0], forKey: "firstName")
            }
            
            if nameComponents.count > 1 {
                destinationEmployee.setValue(nameComponents[1], forKey: "lastName")
            }
        }
        
        // 添加其他自定义迁移逻辑...
    }
}
```

在映射模型中，将此自定义策略类指定为相应实体映射的自定义策略类。

### 渐进式迁移

对于多个版本的迁移，可以实现渐进式迁移策略：

```swift
// 渐进式迁移 - 处理多个版本间的迁移
func progressiveMigration(for storeURL: URL) {
    
    // 获取存储的元数据
    let metadata = try? NSPersistentStoreCoordinator.metadataForPersistentStore(
        ofType: NSSQLiteStoreType,
        at: storeURL,
        options: nil
    )
    
    guard let metadata = metadata else {
        print("无法获取存储元数据")
        return
    }
    
    // 按版本顺序排列的所有模型
    let modelVersions = ["MyDataModel_v1", "MyDataModel_v2", "MyDataModel_v3"]
    var currentModel: NSManagedObjectModel?
    var destinationModel: NSManagedObjectModel?
    
    // 找到当前模型版本
    for version in modelVersions {
        if let model = NSManagedObjectModel(contentsOf: Bundle.main.url(forResource: version, withExtension: "momd")!),
           model.isConfiguration(withName: nil, compatibleWithStoreMetadata: metadata) {
            currentModel = model
            break
        }
    }
    
    guard let sourceModel = currentModel else {
        print("无法确定当前模型版本")
        return
    }
    
    // 获取目标模型（最新版本）
    if let model = NSManagedObjectModel(contentsOf: Bundle.main.url(forResource: modelVersions.last!, withExtension: "momd")!) {
        destinationModel = model
    }
    
    guard let targetModel = destinationModel else {
        print("无法获取目标模型")
        return
    }
    
    // 如果当前模型已经是最新版本，则无需迁移
    if sourceModel == targetModel {
        print("当前模型已是最新版本，无需迁移")
        return
    }
    
    // 查找当前模型的索引
    guard let currentIndex = modelVersions.firstIndex(where: { $0 == sourceModel.entityVersionHashesByName.description }) else {
        print("无法确定当前模型版本索引")
        return
    }
    
    // 逐步迁移到最新版本
    var currentURL = storeURL
    
    for i in currentIndex..<(modelVersions.count - 1) {
        let sourceVersion = modelVersions[i]
        let destinationVersion = modelVersions[i + 1]
        
        guard let sourceModel = NSManagedObjectModel(contentsOf: Bundle.main.url(forResource: sourceVersion, withExtension: "momd")!),
              let destinationModel = NSManagedObjectModel(contentsOf: Bundle.main.url(forResource: destinationVersion, withExtension: "momd")!) else {
            continue
        }
        
        // 获取映射模型
        guard let mappingModel = NSMappingModel(from: [Bundle.main], forSourceModel: sourceModel, destinationModel: destinationModel) else {
            print("无法创建 \(sourceVersion) 到 \(destinationVersion) 的映射模型")
            continue
        }
        
        let manager = NSMigrationManager(sourceModel: sourceModel, destinationModel: destinationModel)
        
        // 临时目标URL
        let tempDestinationURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        
        do {
            try manager.migrateStore(
                from: currentURL,
                sourceType: NSSQLiteStoreType,
                options: nil,
                with: mappingModel,
                toDestinationURL: tempDestinationURL,
                destinationType: NSSQLiteStoreType,
                destinationOptions: nil
            )
            
            // 如果不是最终迁移，更新当前URL为临时URL
            if i < modelVersions.count - 2 {
                currentURL = tempDestinationURL
            } else {
                // 最终迁移，替换原始存储
                try FileManager.default.removeItem(at: storeURL)
                try FileManager.default.moveItem(at: tempDestinationURL, to: storeURL)
            }
            
            print("\(sourceVersion) 到 \(destinationVersion) 迁移成功")
        } catch {
            print("\(sourceVersion) 到 \(destinationVersion) 迁移失败: \(error)")
            return
        }
    }
    
    print("渐进式迁移完成")
}
```

### 迁移的最佳实践

1. **始终在发布新版本前测试迁移**：确保在各种场景下的迁移都能顺利进行。

2. **保留所有历史模型版本**：不要删除旧的模型版本，以支持从任何版本迁移。

3. **版本命名策略**：使用清晰的版本命名，如 `MyModel_v1`、`MyModel_v2` 等。

4. **增量设计**：避免一次性进行大量模型变更，尽量采用增量方式。

5. **备份策略**：在迁移前备份用户数据，以防迁移失败。

6. **错误处理**：实现健壮的错误处理和恢复机制。

```swift
// 迁移前备份数据存储
func backupStoreBeforeMigration(storeURL: URL) -> Bool {
    let backupURL = storeURL.deletingLastPathComponent().appendingPathComponent("backup_\(Date().timeIntervalSince1970).sqlite")
    
    do {
        if FileManager.default.fileExists(atPath: storeURL.path) {
            try FileManager.default.copyItem(at: storeURL, to: backupURL)
            print("数据存储已备份到: \(backupURL.path)")
            return true
        }
        return false
    } catch {
        print("备份失败: \(error)")
        return false
    }
}

// 迁移失败时恢复备份
func restoreBackup(backupURL: URL, storeURL: URL) -> Bool {
    do {
        if FileManager.default.fileExists(atPath: storeURL.path) {
            try FileManager.default.removeItem(at: storeURL)
        }
        try FileManager.default.copyItem(at: backupURL, to: storeURL)
        print("从备份恢复成功")
        return true
    } catch {
        print("恢复备份失败: \(error)")
        return false
    }
}
```

## 性能优化

Core Data 在处理大量数据时可能会遇到性能瓶颈。以下是一些提高 Core Data 应用程序性能的关键技术和最佳实践。

### 批量操作

对于需要创建、更新或删除大量对象的操作，使用批量请求可以显著提升性能：

```swift
// 批量插入
let context = persistentContainer.viewContext
let batchSize = 1000

for i in 0..<10000 {
    // 创建实体
    let person = Person(context: context)
    person.name = "用户\(i)"
    person.age = Int16(18 + (i % 50))
    
    // 每处理 batchSize 个对象保存一次
    if i % batchSize == 0 && i > 0 {
        do {
            try context.save()
            print("已保存 \(i) 条记录")
            
            // 重置上下文，释放内存
            context.reset()
        } catch {
            print("批量保存失败: \(error)")
        }
    }
}

// 批量更新
let batchUpdateRequest = NSBatchUpdateRequest(entityName: "Person")
batchUpdateRequest.propertiesToUpdate = ["active": true]
batchUpdateRequest.predicate = NSPredicate(format: "age < %d", 30)
batchUpdateRequest.resultType = .updatedObjectIDsResultType

do {
    let batchResult = try context.execute(batchUpdateRequest) as? NSBatchUpdateResult
    
    if let objectIDs = batchResult?.result as? [NSManagedObjectID] {
        // 合并变更到上下文
        let changes = [NSUpdatedObjectsKey: objectIDs]
        NSManagedObjectContext.mergeChanges(fromRemoteContextSave: changes, into: [context])
        
        print("批量更新了 \(objectIDs.count) 条记录")
    }
} catch {
    print("批量更新失败: \(error)")
}

// 批量删除
let batchDeleteRequest = NSBatchDeleteRequest(fetchRequest: Person.fetchRequest())
batchDeleteRequest.resultType = .resultTypeObjectIDs

do {
    let batchResult = try context.execute(batchDeleteRequest) as? NSBatchDeleteResult
    
    if let objectIDs = batchResult?.result as? [NSManagedObjectID] {
        // 合并删除操作到上下文
        let changes = [NSDeletedObjectsKey: objectIDs]
        NSManagedObjectContext.mergeChanges(fromRemoteContextSave: changes, into: [context])
        
        print("批量删除了 \(objectIDs.count) 条记录")
    }
} catch {
    print("批量删除失败: \(error)")
}
```

### 索引和预取

合理使用索引和预取可以大幅提升查询性能：

```swift
// 在数据模型中为经常查询的属性添加索引
// 1. 选择实体
// 2. 选择属性
// 3. 在属性检查器中勾选 "Indexed"

// 在代码中使用预取减少后续查询
let fetchRequest: NSFetchRequest<Department> = Department.fetchRequest()

// 预取关系
fetchRequest.relationshipKeyPathsForPrefetching = ["employees", "employees.address"]

// 设置批量大小
fetchRequest.fetchBatchSize = 20

// 执行查询
let departments = try? context.fetch(fetchRequest)

// 使用预取的关系
for department in departments ?? [] {
    // 访问预取的关系不会触发额外查询
    let employees = department.employees?.allObjects as? [Employee] ?? []
    for employee in employees {
        print("\(employee.name!) - \(employee.address?.city ?? "无地址")")
    }
}
```

### 使用合适的获取策略

Core Data 提供多种获取策略以适应不同场景：

```swift
let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()

// 1. NSManagedObjectResultType (默认)：返回完整的实体对象
fetchRequest.resultType = .managedObjectResultType

// 2. NSCountResultType：只返回计数
fetchRequest.resultType = .countResultType
let count = try? context.count(for: fetchRequest)
print("总人数: \(count ?? 0)")

// 3. NSDictionaryResultType：返回字典，适合只需要部分属性的场景
fetchRequest.resultType = .dictionaryResultType
fetchRequest.propertiesToFetch = ["name", "age"]
let results = try? context.fetch(fetchRequest) as? [[String: Any]]
print("结果: \(results ?? [])")
```

### 优化查询

编写高效的查询可以显著提升性能：

```swift
let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()

// 1. 使用精确的谓词
fetchRequest.predicate = NSPredicate(format: "age > %d AND department.name = %@", 25, "研发部")

// 2. 只获取需要的属性
fetchRequest.propertiesToFetch = ["name", "age"]

// 3. 限制结果数量
fetchRequest.fetchLimit = 100
fetchRequest.fetchOffset = 0 // 分页

// 4. 高效排序
fetchRequest.sortDescriptors = [
    NSSortDescriptor(key: "age", ascending: false),
    NSSortDescriptor(key: "name", ascending: true)
]

// 5. 使用缓存
fetchRequest.returnsObjectsAsFaults = false // 完全加载对象，适合重复访问的场景

// 执行优化的查询
let people = try? context.fetch(fetchRequest)
```

### 内存管理

适当管理内存对于大型 Core Data 应用至关重要：

```swift
// 1. 定期重置上下文释放内存
context.reset()

// 2. 使用自动重置上下文
let autoResetContext = NSManagedObjectContext(concurrencyType: .mainQueueConcurrencyType)
autoResetContext.automaticallyMergesChangesFromParent = true
autoResetContext.parent = persistentContainer.viewContext

// 3. 刷新对象以更新数据
context.refresh(someObject, mergeChanges: true)

// 4. 控制对象生命周期
var temporaryObjectID: NSManagedObjectID?

// 只获取 ID
if let object = context.fetch(fetchRequest).first {
    temporaryObjectID = object.objectID
    
    // 从上下文移除对象
    context.refresh(object, mergeChanges: false)
}

// 稍后通过 ID 获取对象
if let objectID = temporaryObjectID {
    let reloadedObject = context.object(with: objectID)
    // 使用重新加载的对象
}
```

### 使用 SQLite 优化

Core Data 底层通常使用 SQLite，可以针对 SQLite 进行优化：

```swift
// 配置 SQLite 存储选项
let persistentStoreDescription = NSPersistentStoreDescription()
persistentStoreDescription.type = NSSQLiteStoreType

// 优化 SQLite 存储
persistentStoreDescription.setOption(true as NSNumber, forKey: NSPersistentStoreRemoteChangeNotificationPostOptionKey)
persistentStoreDescription.setOption(true as NSNumber, forKey: NSSQLitePragmasOption)
persistentStoreDescription.setOption(["journal_mode": "WAL"], forKey: NSSQLitePragmasOption) // 使用 WAL 模式

// 应用存储描述
container.persistentStoreDescriptions = [persistentStoreDescription]
```

## 多线程处理

Core Data 是线程安全的，但要求每个线程使用自己的 `NSManagedObjectContext` 实例。正确的多线程设计对于构建响应式 Core Data 应用至关重要。

### 上下文类型

Core Data 提供三种并发类型的上下文：

```swift
// 1. 主队列上下文：用于 UI 更新
let mainContext = NSManagedObjectContext(concurrencyType: .mainQueueConcurrencyType)

// 2. 私有队列上下文：用于后台处理
let privateContext = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)

// 3. 私有并发上下文：用于多线程处理
let privateConcurrentContext = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
```

### 线程安全操作

在正确的队列上执行操作是确保线程安全的关键：

```swift
// 主队列上下文
let mainContext = persistentContainer.viewContext

// 创建私有队列上下文
let privateContext = persistentContainer.newBackgroundContext()

// 在私有队列执行长时间运行的操作
privateContext.perform {
    // 创建和修改对象
    let newPerson = Person(context: privateContext)
    newPerson.name = "后台创建的用户"
    newPerson.age = 35
    
    // 保存私有上下文
    do {
        try privateContext.save()
        print("私有上下文保存成功")
        
        // 在主队列更新 UI
        DispatchQueue.main.async {
            print("UI 已更新")
        }
    } catch {
        print("私有上下文保存失败: \(error)")
    }
}

// 使用 performAndWait 进行同步操作
privateContext.performAndWait {
    // 执行必须立即完成的操作
    // 注意：这会阻塞当前线程
    let count = try? privateContext.count(for: Person.fetchRequest())
    print("同步获取的记录数: \(count ?? 0)")
}
```

### 父子上下文

父子上下文是一种强大的多线程模式，允许在后台进行操作，然后将更改传播到主上下文：

```swift
// 设置父子上下文
// 主上下文（父）
let mainContext = persistentContainer.viewContext

// 子上下文（私有队列）
let childContext = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
childContext.parent = mainContext

// 在子上下文进行操作
childContext.perform {
    // 创建对象
    let newPerson = Person(context: childContext)
    newPerson.name = "子上下文用户"
    newPerson.age = 28
    
    // 保存子上下文 - 这会将更改推送到父上下文，但不会持久化到磁盘
    do {
        try childContext.save()
        print("子上下文保存成功")
        
        // 在主队列保存父上下文，将更改持久化到磁盘
        DispatchQueue.main.async {
            do {
                try mainContext.save()
                print("主上下文保存成功，更改已持久化")
            } catch {
                print("主上下文保存失败: \(error)")
            }
        }
    } catch {
        print("子上下文保存失败: \(error)")
    }
}
```

### 多层上下文设计

对于复杂应用，多层上下文架构提供了更好的灵活性和性能：

```swift
class CoreDataStack {
    let persistentContainer: NSPersistentContainer
    
    // 持久化上下文：直接连接到持久化存储协调器
    lazy var persistingContext: NSManagedObjectContext = {
        let context = persistentContainer.newBackgroundContext()
        context.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
        return context
    }()
    
    // 主上下文：用于 UI，父级是持久化上下文
    lazy var mainContext: NSManagedObjectContext = {
        let context = NSManagedObjectContext(concurrencyType: .mainQueueConcurrencyType)
        context.parent = persistingContext
        context.automaticallyMergesChangesFromParent = true
        context.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
        return context
    }()
    
    // 工作上下文：用于后台操作，父级是主上下文
    func newWorkingContext() -> NSManagedObjectContext {
        let context = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
        context.parent = mainContext
        context.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
        return context
    }
    
    init() {
        persistentContainer = NSPersistentContainer(name: "MyModel")
        persistentContainer.loadPersistentStores { _, error in
            if let error = error {
                fatalError("加载持久化存储失败: \(error)")
            }
        }
    }
    
    // 保存所有上下文更改
    func saveAllContexts(completion: @escaping (Error?) -> Void) {
        mainContext.perform {
            do {
                if self.mainContext.hasChanges {
                    try self.mainContext.save()
                }
                
                self.persistingContext.perform {
                    do {
                        if self.persistingContext.hasChanges {
                            try self.persistingContext.save()
                        }
                        completion(nil)
                    } catch {
                        completion(error)
                    }
                }
            } catch {
                completion(error)
            }
        }
    }
}

// 使用多层上下文
let coreDataStack = CoreDataStack()

// 获取工作上下文
let workingContext = coreDataStack.newWorkingContext()

// 在工作上下文执行操作
workingContext.perform {
    // 创建对象
    let newPerson = Person(context: workingContext)
    newPerson.name = "多层上下文用户"
    
    do {
        // 保存工作上下文
        try workingContext.save()
        print("工作上下文保存成功")
        
        // 保存所有上下文
        coreDataStack.saveAllContexts { error in
            if let error = error {
                print("保存所有上下文失败: \(error)")
            } else {
                print("所有上下文保存成功")
            }
        }
    } catch {
        print("工作上下文保存失败: \(error)")
    }
}
```

### 线程间对象传递

在线程间安全地传递 Core Data 对象至关重要：

```swift
// 1. 使用对象 ID 在上下文间传递对象
let mainContext = persistentContainer.viewContext
let backgroundContext = persistentContainer.newBackgroundContext()

// 在主上下文获取对象
if let person = try? mainContext.fetch(Person.fetchRequest()).first {
    // 获取永久 ID
    let objectID = person.objectID
    
    // 在后台上下文使用该对象
    backgroundContext.perform {
        let backgroundPerson = backgroundContext.object(with: objectID) as? Person
        backgroundPerson?.age += 1
        
        try? backgroundContext.save()
    }
}

// 2. 跨上下文通知
// 注册变更通知
NotificationCenter.default.addObserver(
    self,
    selector: #selector(handleContextDidSave(_:)),
    name: .NSManagedObjectContextDidSave,
    object: backgroundContext
)

@objc func handleContextDidSave(_ notification: Notification) {
    // 确保在主线程处理 UI 更新
    DispatchQueue.main.async {
        // 将后台上下文的变更合并到主上下文
        self.persistentContainer.viewContext.mergeChanges(fromContextDidSave: notification)
        print("背景变更已合并到主上下文")
    }
}
```

### 竞态条件和冲突解决

管理多线程环境中的并发访问和冲突：

```swift
// 设置冲突解决策略
let context = persistentContainer.viewContext

// 1. 使用合并策略
// 属性级冲突解决：当属性值冲突时，保留此上下文的值
context.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy

// 或者保留存储的值
// context.mergePolicy = NSMergeByPropertyStoreTrumpMergePolicy

// 2. 自定义冲突解决
class CustomMergePolicy: NSMergePolicy {
    override func resolve(optimisticLockingConflicts list: [NSMergeConflict]) throws {
        for conflict in list {
            // 获取冲突对象
            let object = conflict.sourceObject
            
            // 获取冲突值
            let sourceSnapshot = conflict.sourceSnapshot
            let destinationSnapshot = conflict.destinationSnapshot
            
            // 实现自定义冲突解决逻辑
            if let sourceObject = object as? Person,
               let sourceName = sourceSnapshot["name"] as? String,
               let destinationName = destinationSnapshot["name"] as? String {
                
                // 例如：合并名称
                sourceObject.setValue("\(sourceName) + \(destinationName)", forKey: "name")
            }
        }
        
        // 调用父类方法处理其他冲突
        try super.resolve(optimisticLockingConflicts: list)
    }
}

// 使用自定义合并策略
context.mergePolicy = CustomMergePolicy(merge: .mergeByPropertyObjectTrumpMergePolicyType)

// 3. 乐观锁和版本控制
// 在数据模型中为实体添加版本属性，标记为"External Storage"
```

### 后台导入性能优化

对于大量数据的导入，可以使用专门优化的技术：

```swift
// 高性能导入
func importLargeDataSet(_ dataSet: [[String: Any]]) {
    // 创建专用的导入上下文
    let importContext = NSManagedObjectContext(concurrencyType: .privateQueueConcurrencyType)
    importContext.persistentStoreCoordinator = persistentContainer.persistentStoreCoordinator
    
    // 禁用撤销管理以提高性能
    importContext.undoManager = nil
    
    // 分批导入
    let batchSize = 1000
    var currentBatch = 0
    
    importContext.perform {
        for i in 0..<dataSet.count {
            let data = dataSet[i]
            
            // 创建对象
            let person = Person(context: importContext)
            person.name = data["name"] as? String ?? ""
            person.age = Int16(data["age"] as? Int ?? 0)
            
            // 每批次保存
            currentBatch += 1
            if currentBatch % batchSize == 0 || i == dataSet.count - 1 {
                do {
                    try importContext.save()
                    print("已导入 \(i + 1)/\(dataSet.count) 条记录")
                    
                    // 重置上下文以释放内存
                    importContext.reset()
                    
                    // 通知进度更新
                    let progress = Float(i + 1) / Float(dataSet.count)
                    DispatchQueue.main.async {
                        NotificationCenter.default.post(
                            name: Notification.Name("ImportProgressUpdated"),
                            object: nil,
                            userInfo: ["progress": progress]
                        )
                    }
                } catch {
                    print("批量导入失败: \(error)")
                }
            }
        }
        
        // 导入完成通知
        DispatchQueue.main.async {
            NotificationCenter.default.post(
                name: Notification.Name("ImportCompleted"),
                object: nil
            )
        }
    }
}
```

## NSFetchedResultsController

NSFetchedResultsController 是一个强大的控制器，专为高效管理表视图中的 Core Data 结果而设计。它可以自动追踪数据变化并更新 UI，同时优化内存使用和性能。

### 基本设置

```swift
class PersonsViewController: UITableViewController, NSFetchedResultsControllerDelegate {
    
    private var fetchedResultsController: NSFetchedResultsController<Person>!
    private let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 配置 FetchedResultsController
        let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()
        fetchRequest.sortDescriptors = [NSSortDescriptor(key: "name", ascending: true)]
        
        // 可选：按年龄分组
        fetchRequest.sortDescriptors = [
            NSSortDescriptor(key: "age", ascending: true),
            NSSortDescriptor(key: "name", ascending: true)
        ]
        
        fetchedResultsController = NSFetchedResultsController(
            fetchRequest: fetchRequest,
            managedObjectContext: context,
            sectionNameKeyPath: "age", // 可选：使用 age 属性分组
            cacheName: "PersonCache"   // 可选：使用缓存提高性能
        )
        
        // 设置代理
        fetchedResultsController.delegate = self
        
        // 执行获取
        do {
            try fetchedResultsController.performFetch()
        } catch {
            print("获取数据失败: \(error)")
        }
    }
    
    // MARK: - UITableViewDataSource
    
    override func numberOfSections(in tableView: UITableView) -> Int {
        return fetchedResultsController.sections?.count ?? 0
    }
    
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return fetchedResultsController.sections?[section].numberOfObjects ?? 0
    }
    
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "PersonCell", for: indexPath)
        
        // 获取数据
        let person = fetchedResultsController.object(at: indexPath)
        
        // 配置单元格
        cell.textLabel?.text = person.name
        cell.detailTextLabel?.text = "年龄: \(person.age)"
        
        return cell
    }
    
    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return fetchedResultsController.sections?[section].name
    }
    
    // MARK: - NSFetchedResultsControllerDelegate
    
    func controllerWillChangeContent(_ controller: NSFetchedResultsController<NSFetchRequestResult>) {
        tableView.beginUpdates()
    }
    
    func controller(_ controller: NSFetchedResultsController<NSFetchRequestResult>,
                   didChange sectionInfo: NSFetchedResultsSectionInfo,
                   atSectionIndex sectionIndex: Int,
                   for type: NSFetchedResultsChangeType) {
        switch type {
        case .insert:
            tableView.insertSections(IndexSet(integer: sectionIndex), with: .fade)
        case .delete:
            tableView.deleteSections(IndexSet(integer: sectionIndex), with: .fade)
        default:
            break
        }
    }
    
    func controller(_ controller: NSFetchedResultsController<NSFetchRequestResult>,
                   didChange anObject: Any,
                   at indexPath: IndexPath?,
                   for type: NSFetchedResultsChangeType,
                   newIndexPath: IndexPath?) {
        switch type {
        case .insert:
            if let newIndexPath = newIndexPath {
                tableView.insertRows(at: [newIndexPath], with: .fade)
            }
        case .delete:
            if let indexPath = indexPath {
                tableView.deleteRows(at: [indexPath], with: .fade)
            }
        case .update:
            if let indexPath = indexPath {
                tableView.reloadRows(at: [indexPath], with: .fade)
            }
        case .move:
            if let indexPath = indexPath, let newIndexPath = newIndexPath {
                tableView.moveRow(at: indexPath, to: newIndexPath)
            }
        @unknown default:
            break
        }
    }
    
    func controllerDidChangeContent(_ controller: NSFetchedResultsController<NSFetchRequestResult>) {
        tableView.endUpdates()
    }
}
```

### 高级用法

```swift
// 使用谓词过滤结果
func updateSearchResults(searchText: String) {
    // 清除缓存
    NSFetchedResultsController<NSFetchRequestResult>.deleteCache(withName: "PersonCache")
    
    // 创建新的请求和控制器
    let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()
    
    // 添加搜索过滤
    if !searchText.isEmpty {
        fetchRequest.predicate = NSPredicate(format: "name CONTAINS[cd] %@", searchText)
    }
    
    fetchRequest.sortDescriptors = [NSSortDescriptor(key: "name", ascending: true)]
    
    fetchedResultsController = NSFetchedResultsController(
        fetchRequest: fetchRequest,
        managedObjectContext: context,
        sectionNameKeyPath: nil,
        cacheName: "PersonCache"
    )
    
    fetchedResultsController.delegate = self
    
    do {
        try fetchedResultsController.performFetch()
        tableView.reloadData()
    } catch {
        print("更新搜索结果失败: \(error)")
    }
}

// 自定义分组逻辑
class CustomGroupingFetchedResultsController: NSFetchedResultsController<Person> {
    
    override func sectionIndexTitle(forSectionName sectionName: String) -> String? {
        // 自定义分组标题
        if let age = Int(sectionName) {
            if age < 18 {
                return "未成年"
            } else if age < 30 {
                return "青年"
            } else if age < 50 {
                return "中年"
            } else {
                return "老年"
            }
        }
        return sectionName
    }
}

// 创建自定义分组控制器
let customController = CustomGroupingFetchedResultsController(
    fetchRequest: fetchRequest,
    managedObjectContext: context,
    sectionNameKeyPath: "age",
    cacheName: nil
)
```

### 性能优化

```swift
// 优化 NSFetchedResultsController 性能
// 1. 设置批量大小
fetchRequest.fetchBatchSize = 20

// 2. 只获取必要的属性
fetchRequest.propertiesToFetch = ["name", "age"]

// 3. 禁用状态跟踪（适用于只读场景）
context.stalenessInterval = 0 // 禁用自动刷新

// 4. 控制缓存使用
// 使用缓存
let controller = NSFetchedResultsController(
    fetchRequest: fetchRequest,
    managedObjectContext: context,
    sectionNameKeyPath: nil,
    cacheName: "MyCache"
)

// 清除缓存
NSFetchedResultsController<NSFetchRequestResult>.deleteCache(withName: "MyCache")

// 5. 减少不必要的更新
var updatesDisabled = false

func disableUpdates() {
    updatesDisabled = true
}

func enableUpdates() {
    updatesDisabled = false
    tableView.reloadData()
}

// 在代理方法中使用
func controllerWillChangeContent(_ controller: NSFetchedResultsController<NSFetchRequestResult>) {
    if !updatesDisabled {
        tableView.beginUpdates()
    }
}

func controllerDidChangeContent(_ controller: NSFetchedResultsController<NSFetchRequestResult>) {
    if !updatesDisabled {
        tableView.endUpdates()
    }
}
```

## 与 SwiftUI 集成

Core Data 与 SwiftUI 的集成为构建数据驱动的现代化应用提供了强大支持。

### 基本集成

```swift
// SwiftUI 中使用 Core Data
import SwiftUI
import CoreData

struct PersonListView: View {
    // 注入管理的对象上下文
    @Environment(\.managedObjectContext) private var viewContext
    
    // 获取数据
    @FetchRequest(
        sortDescriptors: [NSSortDescriptor(key: "name", ascending: true)],
        animation: .default
    )
    private var persons: FetchedResults<Person>
    
    var body: some View {
        NavigationView {
            List {
                ForEach(persons) { person in
                    HStack {
                        Text(person.name ?? "无名")
                        Spacer()
                        Text("年龄: \(person.age)")
                            .foregroundColor(.secondary)
                    }
                }
                .onDelete(perform: deletePerson)
            }
            .navigationTitle("人员列表")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: addPerson) {
                        Label("添加", systemImage: "plus")
                    }
                }
            }
        }
    }
    
    private func addPerson() {
        withAnimation {
            let newPerson = Person(context: viewContext)
            newPerson.name = "新用户\(Int.random(in: 1...100))"
            newPerson.age = Int16.random(in: 18...60)
            
            do {
                try viewContext.save()
            } catch {
                let nsError = error as NSError
                print("添加失败: \(nsError), \(nsError.userInfo)")
            }
        }
    }
    
    private func deletePerson(offsets: IndexSet) {
        withAnimation {
            offsets.map { persons[$0] }.forEach(viewContext.delete)
            
            do {
                try viewContext.save()
            } catch {
                let nsError = error as NSError
                print("删除失败: \(nsError), \(nsError.userInfo)")
            }
        }
    }
}

// 设置持久化容器
@main
struct MyApp: App {
    let persistenceController = PersistenceController.shared
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.managedObjectContext, persistenceController.container.viewContext)
        }
    }
}

// 持久化控制器
struct PersistenceController {
    static let shared = PersistenceController()
    
    let container: NSPersistentContainer
    
    init(inMemory: Bool = false) {
        container = NSPersistentContainer(name: "MyModel")
        
        if inMemory {
            container.persistentStoreDescriptions.first!.url = URL(fileURLWithPath: "/dev/null")
        }
        
        container.loadPersistentStores { description, error in
            if let error = error {
                fatalError("加载存储失败: \(error.localizedDescription)")
            }
        }
        
        // 自动合并更改
        container.viewContext.automaticallyMergesChangesFromParent = true
        container.viewContext.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy
    }
}
```

### 自定义 FetchRequest

```swift
// 自定义 FetchRequest 包装器
struct FilteredPersonList: View {
    @Environment(\.managedObjectContext) private var viewContext
    @FetchRequest private var persons: FetchedResults<Person>
    
    init(ageThreshold: Int) {
        // 创建自定义获取请求
        let request: NSFetchRequest<Person> = Person.fetchRequest()
        request.sortDescriptors = [NSSortDescriptor(key: "name", ascending: true)]
        request.predicate = NSPredicate(format: "age > %d", ageThreshold)
        
        // 使用自定义请求初始化 FetchRequest
        _persons = FetchRequest(fetchRequest: request, animation: .default)
    }
    
    var body: some View {
        List(persons) { person in
            Text("\(person.name ?? "无名") - \(person.age)岁")
        }
    }
}

// 使用
struct ContentView: View {
    var body: some View {
        TabView {
            PersonListView()
                .tabItem {
                    Label("所有人员", systemImage: "person.3")
                }
            
            FilteredPersonList(ageThreshold: 30)
                .tabItem {
                    Label("30岁以上", systemImage: "person.badge.plus")
                }
        }
    }
}
```

### 动态更新查询

```swift
// 动态更新查询条件
struct SearchablePersonList: View {
    @Environment(\.managedObjectContext) private var viewContext
    @State private var searchText = ""
    
    // 创建基本查询
    @FetchRequest(
        sortDescriptors: [NSSortDescriptor(key: "name", ascending: true)],
        animation: .default
    )
    private var persons: FetchedResults<Person>
    
    var body: some View {
        VStack {
            // 搜索框
            TextField("搜索", text: $searchText)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()
                .onChange(of: searchText) { _ in
                    updateSearch()
                }
            
            List {
                ForEach(filteredPersons) { person in
                    Text("\(person.name ?? "无名") - \(person.age)岁")
                }
            }
        }
    }
    
    // 筛选结果
    private var filteredPersons: [Person] {
        if searchText.isEmpty {
            return Array(persons)
        } else {
            return persons.filter { person in
                person.name?.contains(searchText) ?? false
            }
        }
    }
    
    // 或者使用谓词更新查询
    private func updateSearch() {
        persons.nsPredicate = searchText.isEmpty ? nil : NSPredicate(format: "name CONTAINS[cd] %@", searchText)
    }
}
```

### 关系处理

```swift
// 处理 Core Data 关系
struct DepartmentDetailView: View {
    @ObservedObject var department: Department
    @Environment(\.managedObjectContext) private var viewContext
    @State private var newEmployeeName = ""
    
    var body: some View {
        VStack {
            Text(department.name ?? "未命名部门")
                .font(.largeTitle)
            
            HStack {
                TextField("新员工姓名", text: $newEmployeeName)
                Button("添加") {
                    addEmployee()
                }
                .disabled(newEmployeeName.isEmpty)
            }
            .padding()
            
            List {
                ForEach(department.employeesArray) { employee in
                    HStack {
                        Text(employee.name ?? "")
                        Spacer()
                        Text(employee.position ?? "")
                            .foregroundColor(.secondary)
                    }
                }
                .onDelete(perform: deleteEmployees)
            }
        }
        .padding()
    }
    
    private func addEmployee() {
        withAnimation {
            let employee = Employee(context: viewContext)
            employee.name = newEmployeeName
            employee.position = "新职位"
            employee.department = department
            
            do {
                try viewContext.save()
                newEmployeeName = ""
            } catch {
                print("添加员工失败: \(error)")
            }
        }
    }
    
    private func deleteEmployees(at offsets: IndexSet) {
        withAnimation {
            offsets.map { department.employeesArray[$0] }.forEach(viewContext.delete)
            
            do {
                try viewContext.save()
            } catch {
                print("删除员工失败: \(error)")
            }
        }
    }
}

// 扩展 Department 使其更好地与 SwiftUI 集成
extension Department {
    var employeesArray: [Employee] {
        let set = employees as? Set<Employee> ?? []
        return set.sorted { $0.name ?? "" < $1.name ?? "" }
    }
}
```

### 结合 Combine 框架

```swift
// 将 Core Data 与 Combine 集成
import Combine
import CoreData
import SwiftUI

class PersonViewModel: ObservableObject {
    private let context: NSManagedObjectContext
    private var cancellables = Set<AnyCancellable>()
    
    @Published var name = ""
    @Published var age = ""
    @Published var searchText = ""
    
    @Published var persons: [Person] = []
    
    init(context: NSManagedObjectContext) {
        self.context = context
        
        // 监听搜索文本变化
        $searchText
            .debounce(for: .milliseconds(300), scheduler: DispatchQueue.main)
            .removeDuplicates()
            .sink { [weak self] searchText in
                self?.fetchPersons(matching: searchText)
            }
            .store(in: &cancellables)
        
        // 初始加载
        fetchPersons(matching: "")
    }
    
    func fetchPersons(matching searchText: String) {
        let request: NSFetchRequest<Person> = Person.fetchRequest()
        request.sortDescriptors = [NSSortDescriptor(key: "name", ascending: true)]
        
        if !searchText.isEmpty {
            request.predicate = NSPredicate(format: "name CONTAINS[cd] %@", searchText)
        }
        
        do {
            persons = try context.fetch(request)
        } catch {
            print("获取失败: \(error)")
        }
    }
    
    func addPerson() {
        guard !name.isEmpty, let ageValue = Int16(age) else { return }
        
        let person = Person(context: context)
        person.name = name
        person.age = ageValue
        
        do {
            try context.save()
            // 重置输入
            name = ""
            age = ""
            // 刷新列表
            fetchPersons(matching: searchText)
        } catch {
            print("保存失败: \(error)")
        }
    }
    
    func deletePerson(_ person: Person) {
        context.delete(person)
        
        do {
            try context.save()
            // 刷新列表
            fetchPersons(matching: searchText)
        } catch {
            print("删除失败: \(error)")
        }
    }
}

// 使用视图模型
struct PersonManagementView: View {
    @StateObject private var viewModel: PersonViewModel
    
    init(context: NSManagedObjectContext) {
        _viewModel = StateObject(wrappedValue: PersonViewModel(context: context))
    }
    
    var body: some View {
        VStack {
            HStack {
                TextField("姓名", text: $viewModel.name)
                TextField("年龄", text: $viewModel.age)
                    .keyboardType(.numberPad)
                Button("添加") {
                    viewModel.addPerson()
                }
                .disabled(viewModel.name.isEmpty || viewModel.age.isEmpty)
            }
            .padding()
            
            TextField("搜索", text: $viewModel.searchText)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding(.horizontal)
            
            List {
                ForEach(viewModel.persons) { person in
                    HStack {
                        Text(person.name ?? "")
                        Spacer()
                        Text("\(person.age)岁")
                    }
                }
                .onDelete { indexSet in
                    indexSet.forEach { index in
                        viewModel.deletePerson(viewModel.persons[index])
                    }
                }
            }
        }
    }
}
```

## 最佳实践

### 核心原则

1. **合理设计模型**：良好的数据模型设计是 Core Data 性能和可维护性的基础。

2. **合适的上下文配置**：根据应用需求设置合适的上下文配置和关系。

3. **批量操作与事务**：使用批量操作和事务处理大量数据操作。

4. **正确的线程管理**：确保在正确的线程上执行 Core Data 操作。

### 数据模型设计最佳实践

```swift
// 1. 使用模块化实体设计
// 将大型实体拆分为多个关联实体
// 例如：将 User 拆分为 User, UserProfile, UserSettings

// 2. 使用适当的数据类型
// 例如：使用 Binary Data 存储大型数据而不是字符串
// 使用 Transformable 属性存储自定义类型

// 3. 使用版本控制和迁移策略
class VersionManager {
    static func checkAndMigrateIfNeeded() {
        let currentModelVersion = "MyModel_v2"
        let userDefaults = UserDefaults.standard
        let lastModelVersion = userDefaults.string(forKey: "lastModelVersion") ?? "MyModel_v1"
        
        if lastModelVersion != currentModelVersion {
            // 执行迁移
            print("需要从 \(lastModelVersion) 迁移到 \(currentModelVersion)")
            
            // 迁移代码...
            
            // 更新已保存的版本
            userDefaults.set(currentModelVersion, forKey: "lastModelVersion")
        }
    }
}
```

### 性能优化最佳实践

```swift
// 1. 使用索引优化查询
// 在数据模型中为经常查询的属性添加索引

// 2. 使用批处理操作
func efficientBatchOperation() {
    let context = persistentContainer.newBackgroundContext()
    context.perform {
        // 批量操作
        try? context.execute(NSBatchDeleteRequest(fetchRequest: Person.fetchRequest()))
        
        // 或者使用批量更新
        let batchUpdate = NSBatchUpdateRequest(entityName: "Person")
        batchUpdate.propertiesToUpdate = ["active": false]
        batchUpdate.predicate = NSPredicate(format: "lastLoginDate < %@", Date().addingTimeInterval(-30*24*60*60) as NSDate)
        batchUpdate.resultType = .updatedObjectIDsResultType
        
        try? context.execute(batchUpdate)
    }
}

// 3. 避免不必要的获取
func efficientDataAccess() {
    // 只获取需要的属性
    let request: NSFetchRequest<NSDictionary> = NSFetchRequest<NSDictionary>(entityName: "Person")
    request.resultType = .dictionaryResultType
    request.propertiesToFetch = ["name", "age"]
    
    // 使用计数而非获取所有对象
    let countRequest = Person.fetchRequest()
    let count = try? context.count(for: countRequest)
}
```

### 错误处理最佳实践

```swift
// 全面的错误处理
func robustSaveOperation() {
    do {
        try context.save()
    } catch let error as NSError {
        // 区分错误类型
        switch error.code {
        case NSValidationErrorMinimum...NSValidationErrorMaximum:
            // 处理验证错误
            if let details = error.userInfo["NSValidationErrorKey"] {
                print("验证错误: \(details)")
            }
        case NSManagedObjectConstraintMergeError:
            // 处理约束错误
            print("约束冲突: \(error.userInfo)")
        case NSPersistentStoreError:
            // 处理存储错误
            print("持久化存储错误: \(error.localizedDescription)")
        default:
            // 其他错误
            print("未知错误: \(error), \(error.userInfo)")
        }
        
        // 恢复策略
        context.rollback()
    }
}

// 错误恢复与重试
func saveWithRetry(maxAttempts: Int = 3) {
    var attempts = 0
    var savedSuccessfully = false
    
    while !savedSuccessfully && attempts < maxAttempts {
        attempts += 1
        
        do {
            try context.save()
            savedSuccessfully = true
        } catch {
            print("保存失败，尝试 \(attempts)/\(maxAttempts): \(error)")
            
            // 短暂延迟后重试
            if attempts < maxAttempts {
                Thread.sleep(forTimeInterval: 0.5)
                context.rollback() // 回滚后重试
            }
        }
    }
    
    if !savedSuccessfully {
        print("保存失败，已达到最大重试次数")
    }
}
```

### 测试最佳实践

```swift
// 为测试创建内存中存储
func setUpTestingStack() -> NSPersistentContainer {
    let container = NSPersistentContainer(name: "MyModel")
    
    // 使用内存中存储
    let description = NSPersistentStoreDescription()
    description.type = NSInMemoryStoreType
    container.persistentStoreDescriptions = [description]
    
    container.loadPersistentStores { description, error in
        if let error = error {
            fatalError("创建内存存储失败: \(error)")
        }
    }
    
    return container
}

// 测试代码示例
func testPersonEntity() {
    // 设置测试环境
    let container = setUpTestingStack()
    let context = container.viewContext
    
    // 创建测试数据
    let person = Person(context: context)
    person.name = "测试用户"
    person.age = 25
    
    // 保存上下文
    XCTAssertNoThrow(try context.save(), "保存应该成功")
    
    // 验证保存结果
    let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()
    fetchRequest.predicate = NSPredicate(format: "name == %@", "测试用户")
    
    do {
        let results = try context.fetch(fetchRequest)
        XCTAssertEqual(results.count, 1, "应该找到一条记录")
        XCTAssertEqual(results.first?.age, 25, "年龄应该是25")
    } catch {
        XCTFail("获取失败: \(error)")
    }
    
    // 清理
    context.delete(person)
    XCTAssertNoThrow(try context.save(), "删除应该成功")
}
```

通过掌握这些高级概念和最佳实践，开发者可以更有效地利用 Core Data 的强大功能，构建高性能、可扩展的数据驱动应用。 