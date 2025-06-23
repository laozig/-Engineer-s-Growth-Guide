# Core Data 基础

Core Data 是 Apple 提供的强大数据管理框架，用于在 iOS、macOS、watchOS 和 tvOS 应用程序中管理对象图和对象生命周期。本教程将介绍 Core Data 的基础知识和常见使用场景。

## 目录

- [Core Data 简介](#core-data-简介)
- [核心组件](#核心组件)
- [设置 Core Data](#设置-core-data)
- [数据模型设计](#数据模型设计)
- [基本操作](#基本操作)
- [上下文管理](#上下文管理)
- [关系](#关系)
- [获取数据](#获取数据)
- [性能考虑](#性能考虑)
- [常见问题与解决方案](#常见问题与解决方案)
- [与 SwiftUI 集成](#与-swiftui-集成)
- [小结](#小结)

## Core Data 简介

### 什么是 Core Data？

Core Data 是 Apple 的对象图和持久化框架，它不仅是一个数据库，更是一个完整的数据管理解决方案。Core Data 提供以下功能：

- 对象生命周期和图管理
- 对象间关系维护
- 更改跟踪和撤销/重做
- 数据持久化到 SQLite、XML 或二进制文件
- 数据验证
- 懒加载机制
- 数据迁移

### Core Data 不是什么

- Core Data 不是一个关系型数据库（虽然它可以使用 SQLite 作为存储介质）
- Core Data 不是一个简单的键值存储系统
- Core Data 不是 ORM（对象关系映射）工具
- Core Data 不适合处理大量非结构化数据

## 核心组件

Core Data 架构由以下核心组件组成：

### 持久化存储协调器 (Persistent Store Coordinator)

作为 Core Data 架构的核心，持久化存储协调器负责协调管理对象上下文和持久化存储之间的交互。它确保多个上下文可以访问同一组数据存储。

### 管理对象上下文 (Managed Object Context)

管理对象上下文是一个临时的"暂存区"，用于跟踪对对象的更改。它提供以下功能：

- 跟踪被修改的对象
- 提供撤销和重做功能
- 执行数据验证
- 处理对象间的关系

### 管理对象模型 (Managed Object Model)

管理对象模型定义了应用程序的数据结构，包括实体、属性和关系。它类似于传统数据库中的表结构定义。

### 持久化存储 (Persistent Store)

持久化存储是实际存储数据的地方。Core Data 支持多种存储类型：

- SQLite 数据库（最常用）
- 二进制文件
- 内存存储
- XML（仅在 macOS 上可用）

### 管理对象 (Managed Object)

管理对象是 Core Data 实体的实例，代表应用程序中的数据记录。每个管理对象都与一个管理对象上下文相关联。

## 设置 Core Data

### 在新项目中设置 Core Data

1. 创建新项目时，勾选 "Use Core Data" 选项
2. Xcode 会自动生成 Core Data 堆栈代码和一个 `.xcdatamodeld` 文件

### 在现有项目中添加 Core Data

1. 添加新的 `.xcdatamodeld` 文件：File > New > File > Data Model
2. 实现 Core Data 堆栈：

```swift
import CoreData

class CoreDataStack {
    static let shared = CoreDataStack()
    
    lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "YourModelName")
        container.loadPersistentStores { description, error in
            if let error = error {
                fatalError("无法加载 Core Data 堆栈: \(error)")
            }
        }
        return container
    }()
    
    var context: NSManagedObjectContext {
        return persistentContainer.viewContext
    }
    
    func saveContext() {
        if context.hasChanges {
            do {
                try context.save()
            } catch {
                let nserror = error as NSError
                fatalError("保存上下文失败: \(nserror), \(nserror.userInfo)")
            }
        }
    }
}
```

## 数据模型设计

### 创建实体

1. 打开 `.xcdatamodeld` 文件
2. 点击 "Add Entity" 添加一个新实体
3. 为实体命名（通常使用单数形式，如 "Person" 而不是 "People"）

### 添加属性

1. 选择实体，点击 "Add Attribute" 添加属性
2. 设置属性名称和类型（如 String、Date、Integer 等）
3. 配置属性选项（如 optional、default value 等）

### 配置实体

在实体的 Data Model Inspector 中，您可以配置：

- 实体名称和类名
- 父实体（用于实体继承）
- 抽象实体设置
- 约束和索引

### 生成 NSManagedObject 子类

1. 选择实体，然后选择 Editor > Create NSManagedObject Subclass...
2. 选择目标实体和保存位置
3. 选择语言（Swift 或 Objective-C）

生成的类示例：

```swift
import Foundation
import CoreData

@objc(Person)
public class Person: NSManagedObject {
    // 默认生成的空类
}

extension Person {
    @nonobjc public class func fetchRequest() -> NSFetchRequest<Person> {
        return NSFetchRequest<Person>(entityName: "Person")
    }
    
    @NSManaged public var name: String?
    @NSManaged public var age: Int16
    @NSManaged public var email: String?
    @NSManaged public var birthDate: Date?
}
```

## 基本操作

### 创建对象

```swift
// 获取上下文
let context = CoreDataStack.shared.context

// 创建新对象
let person = Person(context: context)
person.name = "张三"
person.age = 30
person.email = "zhangsan@example.com"
person.birthDate = Date()

// 保存上下文
do {
    try context.save()
    print("保存成功")
} catch {
    print("保存失败: \(error)")
}
```

### 更新对象

```swift
// 假设我们已经有了一个 person 对象
person.age = 31
person.email = "zhangsan_new@example.com"

// 保存更改
do {
    try context.save()
    print("更新成功")
} catch {
    print("更新失败: \(error)")
}
```

### 删除对象

```swift
// 假设我们已经有了一个 person 对象
context.delete(person)

// 保存更改
do {
    try context.save()
    print("删除成功")
} catch {
    print("删除失败: \(error)")
}
```

## 上下文管理

### 主队列上下文

主队列上下文通常用于 UI 相关操作：

```swift
let mainContext = CoreDataStack.shared.context
// mainContext 在主队列上运行，可以直接更新 UI
```

### 私有队列上下文

私有队列上下文适用于后台操作：

```swift
let privateContext = CoreDataStack.shared.persistentContainer.newBackgroundContext()

// 在后台执行数据操作
privateContext.perform {
    let person = Person(context: privateContext)
    person.name = "李四"
    person.age = 25
    
    do {
        try privateContext.save()
    } catch {
        print("后台保存失败: \(error)")
    }
}
```

### 子上下文

子上下文可以创建层次结构，适用于临时操作：

```swift
// 创建一个子上下文
let childContext = NSManagedObjectContext(concurrencyType: .mainQueueConcurrencyType)
childContext.parent = CoreDataStack.shared.context

// 在子上下文中执行操作
let tempPerson = Person(context: childContext)
tempPerson.name = "临时用户"

// 保存子上下文会将更改推送到父上下文
do {
    try childContext.save()
    // 还需要保存父上下文以将更改写入存储
    try CoreDataStack.shared.context.save()
} catch {
    print("保存子上下文失败: \(error)")
}
```

## 关系

Core Data 支持以下类型的关系：

### 一对一关系

```swift
// 在数据模型中设置一对一关系
// Person <--> IDCard

// 创建并关联对象
let person = Person(context: context)
person.name = "张三"

let idCard = IDCard(context: context)
idCard.number = "123456789"

// 设置关系
person.idCard = idCard
idCard.owner = person

// 保存上下文
try? context.save()
```

### 一对多关系

```swift
// 在数据模型中设置一对多关系
// Department <->> Employee

// 创建部门
let department = Department(context: context)
department.name = "研发部"

// 创建员工
let employee1 = Employee(context: context)
employee1.name = "张三"

let employee2 = Employee(context: context)
employee2.name = "李四"

// 设置关系
department.addToEmployees(employee1)
department.addToEmployees(employee2)
// 或者
employee1.department = department
employee2.department = department

// 保存上下文
try? context.save()
```

### 多对多关系

```swift
// 在数据模型中设置多对多关系
// Student <<->> Course

// 创建学生
let student1 = Student(context: context)
student1.name = "张三"

let student2 = Student(context: context)
student2.name = "李四"

// 创建课程
let course1 = Course(context: context)
course1.name = "数学"

let course2 = Course(context: context)
course2.name = "物理"

// 设置关系
student1.addToCourses(course1)
student1.addToCourses(course2)
student2.addToCourses(course1)

// 保存上下文
try? context.save()
```

### 级联删除规则

Core Data 支持以下删除规则：

- **Nullify** - 断开关系，但不删除相关对象
- **Cascade** - 删除主对象时，也删除所有相关对象
- **Deny** - 如果存在相关对象，则阻止删除主对象
- **No Action** - 不执行任何操作，可能导致数据不一致

在数据模型编辑器中，可以为每个关系设置删除规则。

## 获取数据

### 基本获取请求

```swift
// 创建获取请求
let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()

// 执行请求
do {
    let people = try context.fetch(fetchRequest)
    for person in people {
        print("姓名: \(person.name ?? "无名"), 年龄: \(person.age)")
    }
} catch {
    print("获取失败: \(error)")
}
```

### 使用谓词

```swift
// 创建获取请求
let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()

// 添加谓词
fetchRequest.predicate = NSPredicate(format: "age > %d AND name CONTAINS %@", 25, "张")

// 执行请求
do {
    let people = try context.fetch(fetchRequest)
    print("找到 \(people.count) 个符合条件的人")
} catch {
    print("获取失败: \(error)")
}
```

### 排序

```swift
// 创建获取请求
let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()

// 添加排序描述符
let sortByAge = NSSortDescriptor(key: "age", ascending: true)
let sortByName = NSSortDescriptor(key: "name", ascending: true)
fetchRequest.sortDescriptors = [sortByAge, sortByName]

// 执行请求
do {
    let people = try context.fetch(fetchRequest)
    // 结果已按年龄和姓名排序
} catch {
    print("获取失败: \(error)")
}
```

### 限制结果数量

```swift
// 创建获取请求
let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()

// 设置限制和偏移量（用于分页）
fetchRequest.fetchLimit = 10  // 最多返回 10 条结果
fetchRequest.fetchOffset = 20 // 跳过前 20 条结果

// 执行请求
do {
    let people = try context.fetch(fetchRequest)
    print("获取到 \(people.count) 条结果")
} catch {
    print("获取失败: \(error)")
}
```

### 获取单个对象

```swift
// 创建获取请求
let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()
fetchRequest.predicate = NSPredicate(format: "email == %@", "zhangsan@example.com")
fetchRequest.fetchLimit = 1

// 执行请求
do {
    let people = try context.fetch(fetchRequest)
    if let person = people.first {
        print("找到用户: \(person.name ?? "无名")")
    } else {
        print("未找到用户")
    }
} catch {
    print("获取失败: \(error)")
}
```

### 使用 NSFetchedResultsController

`NSFetchedResultsController` 是在 UITableView 或 UICollectionView 中展示 Core Data 数据的理想选择：

```swift
import UIKit
import CoreData

class PeopleViewController: UITableViewController, NSFetchedResultsControllerDelegate {
    
    var fetchedResultsController: NSFetchedResultsController<Person>!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 配置获取请求
        let fetchRequest: NSFetchRequest<Person> = Person.fetchRequest()
        fetchRequest.sortDescriptors = [NSSortDescriptor(key: "name", ascending: true)]
        
        // 初始化 NSFetchedResultsController
        fetchedResultsController = NSFetchedResultsController(
            fetchRequest: fetchRequest,
            managedObjectContext: CoreDataStack.shared.context,
            sectionNameKeyPath: nil,
            cacheName: "PeopleCache"
        )
        
        // 设置代理
        fetchedResultsController.delegate = self
        
        // 执行获取
        do {
            try fetchedResultsController.performFetch()
        } catch {
            print("获取失败: \(error)")
        }
    }
    
    // MARK: - Table view data source
    
    override func numberOfSections(in tableView: UITableView) -> Int {
        return fetchedResultsController.sections?.count ?? 0
    }
    
    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        let sectionInfo = fetchedResultsController.sections![section]
        return sectionInfo.numberOfObjects
    }
    
    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "PersonCell", for: indexPath)
        
        // 配置单元格
        let person = fetchedResultsController.object(at: indexPath)
        cell.textLabel?.text = person.name
        cell.detailTextLabel?.text = "年龄: \(person.age)"
        
        return cell
    }
    
    // MARK: - NSFetchedResultsController delegate
    
    func controllerWillChangeContent(_ controller: NSFetchedResultsController<NSFetchRequestResult>) {
        tableView.beginUpdates()
    }
    
    func controller(_ controller: NSFetchedResultsController<NSFetchRequestResult>, didChange anObject: Any, at indexPath: IndexPath?, for type: NSFetchedResultsChangeType, newIndexPath: IndexPath?) {
        switch type {
        case .insert:
            tableView.insertRows(at: [newIndexPath!], with: .fade)
        case .delete:
            tableView.deleteRows(at: [indexPath!], with: .fade)
        case .update:
            tableView.reloadRows(at: [indexPath!], with: .fade)
        case .move:
            tableView.deleteRows(at: [indexPath!], with: .fade)
            tableView.insertRows(at: [newIndexPath!], with: .fade)
        @unknown default:
            break
        }
    }
    
    func controllerDidChangeContent(_ controller: NSFetchedResultsController<NSFetchRequestResult>) {
        tableView.endUpdates()
    }
}
```

## 性能考虑

### 批处理操作

对于大量数据操作，使用批处理：

```swift
// 批量更新
let batchUpdate = NSBatchUpdateRequest(entityName: "Person")
batchUpdate.propertiesToUpdate = ["age": 18]
batchUpdate.predicate = NSPredicate(format: "age < %d", 18)

do {
    try context.execute(batchUpdate)
} catch {
    print("批量更新失败: \(error)")
}

// 批量删除
let batchDelete = NSBatchDeleteRequest(fetchRequest: NSFetchRequest<NSFetchRequestResult>(entityName: "Person"))
batchDelete.predicate = NSPredicate(format: "age > %d", 60)

do {
    try context.execute(batchDelete)
} catch {
    print("批量删除失败: \(error)")
}
```

### 使用 Fetched Properties

Fetched Properties 类似于数据库视图，可以优化复杂查询：

1. 在数据模型编辑器中，添加 Fetched Property
2. 配置获取请求和谓词
3. 在代码中使用该属性

### 优化关系

- 对于大型关系，考虑使用 Fetched Property 而不是真实关系
- 为一对多和多对多关系设置适当的 Delete Rule
- 使用 Fault 机制延迟加载相关对象

## 常见问题与解决方案

### 合并冲突

当多个上下文尝试修改同一对象时，可能会发生合并冲突：

```swift
// 设置合并策略
CoreDataStack.shared.persistentContainer.viewContext.mergePolicy = NSMergeByPropertyObjectTrumpMergePolicy

// 监听外部更改通知
NotificationCenter.default.addObserver(
    self,
    selector: #selector(managedObjectContextDidSave),
    name: .NSManagedObjectContextDidSave,
    object: nil
)

@objc func managedObjectContextDidSave(notification: Notification) {
    let context = CoreDataStack.shared.context
    
    // 仅处理来自其他上下文的通知
    if notification.object as? NSManagedObjectContext != context {
        context.perform {
            context.mergeChanges(fromContextDidSave: notification)
        }
    }
}
```

### 迁移错误

在更新数据模型时，必须处理迁移：

```swift
lazy var persistentContainer: NSPersistentContainer = {
    let container = NSPersistentContainer(name: "YourModelName")
    
    // 配置迁移选项
    let options = [
        NSMigratePersistentStoresAutomaticallyOption: true,
        NSInferMappingModelAutomaticallyOption: true
    ]
    
    container.loadPersistentStores(completionHandler: { (storeDescription, error) in
        if let error = error as NSError? {
            fatalError("无法加载持久化存储: \(error), \(error.userInfo)")
        }
    })
    
    return container
}()
```

### 性能问题

- 避免在主线程上执行繁重的 Core Data 操作
- 使用子上下文处理临时操作
- 为大型查询设置合适的 fetchBatchSize
- 避免一次性加载太多对象

## 与 SwiftUI 集成

SwiftUI 提供了与 Core Data 集成的原生支持：

### 使用 @FetchRequest

```swift
import SwiftUI
import CoreData

struct PersonListView: View {
    @Environment(\.managedObjectContext) private var viewContext
    
    @FetchRequest(
        sortDescriptors: [NSSortDescriptor(keyPath: \Person.name, ascending: true)],
        animation: .default)
    private var people: FetchedResults<Person>
    
    var body: some View {
        List {
            ForEach(people, id: \.self) { person in
                Text("\(person.name ?? "无名") - \(person.age)")
            }
            .onDelete(perform: deletePeople)
        }
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: addPerson) {
                    Label("添加", systemImage: "plus")
                }
            }
        }
    }
    
    private func addPerson() {
        withAnimation {
            let newPerson = Person(context: viewContext)
            newPerson.name = "新用户"
            newPerson.age = 25
            
            do {
                try viewContext.save()
            } catch {
                print("添加用户失败: \(error)")
            }
        }
    }
    
    private func deletePeople(offsets: IndexSet) {
        withAnimation {
            offsets.map { people[$0] }.forEach(viewContext.delete)
            
            do {
                try viewContext.save()
            } catch {
                print("删除用户失败: \(error)")
            }
        }
    }
}
```

### 使用 @ObservedObject

```swift
class PersonViewModel: ObservableObject {
    private var person: Person
    private var context: NSManagedObjectContext
    
    @Published var name: String
    @Published var age: Int
    
    init(person: Person, context: NSManagedObjectContext) {
        self.person = person
        self.context = context
        self.name = person.name ?? ""
        self.age = Int(person.age)
    }
    
    func save() {
        person.name = name
        person.age = Int16(age)
        
        do {
            try context.save()
        } catch {
            print("保存失败: \(error)")
        }
    }
}

struct PersonEditView: View {
    @ObservedObject var viewModel: PersonViewModel
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        Form {
            TextField("姓名", text: $viewModel.name)
            Stepper("年龄: \(viewModel.age)", value: $viewModel.age, in: 1...120)
            
            Button("保存") {
                viewModel.save()
                presentationMode.wrappedValue.dismiss()
            }
        }
        .navigationTitle("编辑用户")
    }
}
```

## 小结

Core Data 是一个功能强大的框架，适用于管理 iOS 和 macOS 应用程序中的结构化数据。本教程介绍了 Core Data 的基础知识，包括：

- Core Data 架构和组件
- 设置和配置 Core Data 堆栈
- 创建和管理数据模型
- 执行基本的 CRUD 操作
- 使用关系
- 获取和过滤数据
- 性能优化
- 与 SwiftUI 集成

通过掌握这些基础知识，您将能够在应用程序中高效地管理数据。在[Core Data 进阶](coredata-advanced.md)教程中，我们将探讨更高级的主题，如数据迁移、自定义 NSManagedObject 子类、多线程处理等。 