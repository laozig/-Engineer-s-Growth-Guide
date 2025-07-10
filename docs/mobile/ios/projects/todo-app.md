# iOS待办事项应用开发教程

## 目录

- [概述](#概述)
- [需求分析](#需求分析)
  - [功能需求](#功能需求)
  - [用户流程](#用户流程)
  - [技术需求](#技术需求)
- [环境设置](#环境设置)
  - [所需工具](#所需工具)
  - [项目创建](#项目创建)
  - [Git版本控制设置](#git版本控制设置)
- [应用架构设计](#应用架构设计)
  - [MVC架构](#mvc架构)
  - [MVVM架构](#mvvm架构)
  - [文件结构组织](#文件结构组织)
- [数据模型设计](#数据模型设计)
  - [Task模型](#task模型)
  - [Category模型](#category模型)
  - [数据关系](#数据关系)
- [数据持久化](#数据持久化)
  - [UserDefaults实现](#userdefaults实现)
  - [Core Data实现](#core-data实现)
  - [数据迁移策略](#数据迁移策略)
- [UI设计与实现](#ui设计与实现)
  - [任务列表界面](#任务列表界面)
  - [任务详情界面](#任务详情界面)
  - [任务创建/编辑界面](#任务创建编辑界面)
  - [设置界面](#设置界面)
- [功能实现](#功能实现)
  - [任务CRUD操作](#任务crud操作)
  - [任务分类与筛选](#任务分类与筛选)
  - [任务提醒与通知](#任务提醒与通知)
  - [数据同步](#数据同步)
- [高级功能](#高级功能)
  - [拖拽排序](#拖拽排序)
  - [搜索功能](#搜索功能)
  - [统计分析](#统计分析)
  - [主题切换](#主题切换)
- [测试](#测试)
  - [单元测试](#单元测试)
  - [UI测试](#ui测试)
  - [性能测试](#性能测试)
- [调试与优化](#调试与优化)
  - [常见问题排查](#常见问题排查)
  - [性能优化](#性能优化)
  - [内存管理](#内存管理)
- [应用发布](#应用发布)
  - [App Icon与启动页面](#app-icon与启动页面)
  - [应用截图准备](#应用截图准备)
  - [TestFlight测试](#testflight测试)
  - [App Store提交](#app-store提交)
- [扩展与改进](#扩展与改进)
  - [iPad适配](#ipad适配)
  - [添加Widget](#添加widget)
  - [iCloud同步](#icloud同步)
  - [Siri集成](#siri集成)
- [参考资源](#参考资源)

## 概述

待办事项应用是iOS平台上最常见且实用的应用类型之一，不仅可以帮助用户管理日常任务，也是iOS开发者学习的理想项目。本教程将带领读者从零开始，构建一个功能完整、界面精美的待办事项应用，涵盖从需求分析、设计、开发到测试和发布的全过程。

在这个教程中，我们将使用Swift语言和UIKit框架构建应用的主体，同时也会探讨如何使用SwiftUI实现部分现代化的界面。我们会采用符合苹果人机界面指南(HIG)的设计理念，确保应用既美观又易用。同时，我们还会介绍如何实现本地数据存储、任务提醒、拖拽排序等实用功能。

通过完成这个项目，你将掌握：
- iOS应用开发的完整流程
- Swift语言的实际应用
- 数据持久化的多种方案
- iOS用户界面设计与实现
- 本地通知的处理
- 性能优化与调试技巧
- 应用上架的完整流程

无论你是初学者还是有一定经验的开发者，这个教程都将提供有价值的实践经验和技术深度，帮助你提升iOS开发技能。

## 需求分析

在开始开发之前，我们需要清晰地定义应用的需求，包括功能需求、用户流程和技术需求。这一步骤对于项目的成功至关重要，可以帮助我们避免在开发过程中出现方向性错误。

### 功能需求

我们的待办事项应用应该具备以下核心功能：

1. **任务管理**
   - 创建新任务
   - 查看任务列表
   - 编辑现有任务
   - 删除任务
   - 标记任务为已完成/未完成

2. **任务属性**
   - 标题(必填)
   - 描述(可选)
   - 截止日期(可选)
   - 优先级(高/中/低)
   - 分类/标签
   - 完成状态

3. **任务组织**
   - 按日期查看(今天、明天、未来七天、全部)
   - 按分类查看
   - 按优先级查看
   - 按完成状态查看

4. **提醒功能**
   - 为任务设置提醒时间
   - 接收本地通知提醒

5. **数据持久化**
   - 在设备上保存所有任务数据
   - 应用重启后恢复数据

6. **用户界面**
   - 简洁直观的任务列表
   - 任务详情查看界面
   - 任务创建/编辑界面
   - 设置界面

7. **设置选项**
   - 默认视图选择(按日期/分类/优先级)
   - 深色/浅色主题切换
   - 应用内通知设置

### 用户流程

为了确保良好的用户体验，我们需要设计清晰的用户流程：

1. **首次启动流程**
   - 欢迎页面简介
   - 权限请求(通知权限)
   - 引导创建第一个任务

2. **任务创建流程**
   - 点击"+"按钮
   - 填写任务信息
   - 设置可选属性(截止日期、优先级、分类等)
   - 保存任务

3. **任务查看与编辑流程**
   - 从列表选择任务
   - 查看任务详情
   - 点击编辑按钮进入编辑模式
   - 修改任务信息
   - 保存更改

4. **任务完成流程**
   - 在列表中滑动或点击勾选任务
   - 任务显示为已完成状态
   - 可选择查看已完成任务或隐藏

5. **任务搜索流程**
   - 点击搜索栏
   - 输入搜索关键词
   - 实时显示匹配结果
   - 点击结果查看详情

### 技术需求

为了实现上述功能和用户流程，我们需要以下技术：

1. **开发环境**
   - Xcode 15或更高版本
   - Swift 5.9或更高版本
   - iOS 16.0+作为部署目标

2. **UI框架**
   - UIKit为主要框架
   - 可选择性使用SwiftUI实现部分界面
   - AutoLayout确保多设备适配

3. **数据存储**
   - 初始方案：UserDefaults(简单数据)
   - 进阶方案：Core Data(复杂关系和查询)
   - 可选扩展：CloudKit(跨设备同步)

4. **本地通知**
   - UserNotifications框架
   - 后台通知调度

5. **架构模式**
   - MVC架构(基础实现)
   - MVVM架构(进阶实现)

6. **第三方依赖**
   - 尽量减少第三方库的使用
   - 考虑使用SwiftPM进行依赖管理

7. **测试策略**
   - XCTest单元测试
   - UI测试
   - TestFlight beta测试

## 环境设置

在开始开发之前，我们需要准备好开发环境，创建项目并设置版本控制。

### 所需工具

以下是开发iOS待办事项应用所需的工具和软件：

1. **硬件需求**
   - Mac电脑(推荐macOS Ventura或更高版本)
   - 足够的存储空间(至少20GB空闲空间)
   - 8GB或以上RAM(推荐16GB)

2. **软件需求**
   - Xcode 15(或最新版本)：Apple官方IDE
   - Git：版本控制工具
   - Simulator：iOS模拟器(包含在Xcode中)
   - Apple Developer账号(可选，用于TestFlight和发布)

3. **可选工具**
   - Sketch/Figma：UI设计工具
   - Postman：API测试工具(如果计划添加云同步功能)
   - SourceTree/GitKraken：Git图形界面工具
   - Charles：网络请求调试工具

### 项目创建

以下是创建新项目的步骤：

1. **启动Xcode并创建新项目**
   - 打开Xcode
   - 选择"File" > "New" > "Project"
   - 选择"App"模板
   - 点击"Next"

2. **配置项目基本信息**
   - 产品名称：TaskMaster(或你喜欢的名称)
   - 团队：选择你的开发者账号
   - 组织标识符：com.yourname.taskmaster(使用反向域名格式)
   - Bundle Identifier会自动生成
   - 语言：Swift
   - 用户界面：Storyboard(我们将同时学习基于代码和Storyboard的方式)
   - 生命周期：UIKit App Delegate
   - 确保勾选"Use Core Data"选项
   - 点击"Next"

3. **选择项目保存位置**
   - 选择一个便于访问的位置保存项目
   - 可选择勾选"Create Git repository on my Mac"
   - 点击"Create"

### Git版本控制设置

版本控制是专业开发流程中的重要环节，以下是设置Git版本控制的步骤：

1. **初始化Git仓库**
   - 如果在创建项目时没有选择创建Git仓库，可以在终端中导航到项目目录执行：
   ```bash
   git init
   ```

2. **创建.gitignore文件**
   - 在项目根目录创建.gitignore文件
   - 添加以下内容：
   ```
   # Xcode
   #
   # gitignore contributors: remember to update Global/Xcode.gitignore, Objective-C.gitignore & Swift.gitignore

   ## User settings
   xcuserdata/

   ## compatibility with Xcode 8 and earlier (ignoring not required starting Xcode 9)
   *.xcscmblueprint
   *.xccheckout

   ## compatibility with Xcode 3 and earlier (ignoring not required starting Xcode 4)
   build/
   DerivedData/
   *.moved-aside
   *.pbxuser
   !default.pbxuser
   *.mode1v3
   !default.mode1v3
   *.mode2v3
   !default.mode2v3
   *.perspectivev3
   !default.perspectivev3

   ## Obj-C/Swift specific
   *.hmap

   ## App packaging
   *.ipa
   *.dSYM.zip
   *.dSYM

   ## Playgrounds
   timeline.xctimeline
   playground.xcworkspace

   # Swift Package Manager
   #
   # Add this line if you want to avoid checking in source code from Swift Package Manager dependencies.
   # Packages/
   # Package.pins
   # Package.resolved
   # *.xcodeproj
   #
   # Xcode automatically generates this directory with a .xcworkspacedata file and xcuserdata
   # hence it is not needed unless you have added a package configuration file to your project
   # .swiftpm

   .build/

   # CocoaPods
   #
   # We recommend against adding the Pods directory to your .gitignore. However
   # you should judge for yourself, the pros and cons are mentioned at:
   # https://guides.cocoapods.org/using/using-cocoapods.html#should-i-check-the-pods-directory-into-source-control
   #
   # Pods/
   #
   # Add this line if you want to avoid checking in source code from the Xcode workspace
   # *.xcworkspace

   # Carthage
   #
   # Add this line if you want to avoid checking in source code from Carthage dependencies.
   # Carthage/Checkouts

   Carthage/Build/

   # Accio dependency management
   Dependencies/
   .accio/

   # fastlane
   #
   # It is recommended to not store the screenshots in the git repo.
   # Instead, use fastlane to re-generate the screenshots whenever they are needed.
   # For more information about the recommended setup visit:
   # https://docs.fastlane.tools/best-practices/source-control/#source-control

   fastlane/report.xml
   fastlane/Preview.html
   fastlane/screenshots/**/*.png
   fastlane/test_output

   # Code Injection
   #
   # After new code Injection tools there's a generated folder /iOSInjectionProject
   # https://github.com/johnno1962/injectionforxcode

   iOSInjectionProject/

   # macOS
   .DS_Store
   ```

3. **创建初始提交**
   ```bash
   git add .
   git commit -m "初始项目设置"
   ```

4. **创建远程仓库(可选)**
   - 在GitHub/GitLab/Bitbucket上创建新仓库
   - 按照平台提示添加远程仓库并推送：
   ```bash
   git remote add origin https://github.com/yourusername/taskmaster.git
   git branch -M main
   git push -u origin main
   ```

5. **分支策略(可选)**
   - 创建开发分支：
   ```bash
   git checkout -b develop
   ```
   - 为每个功能创建单独分支：
   ```bash
   git checkout -b feature/task-list
   ```

现在我们已经完成了环境设置和项目创建，接下来将开始应用架构设计。

## 应用架构设计

合理的架构设计对于应用的可维护性、可测试性和可扩展性至关重要。在本项目中，我们将介绍两种主流架构模式：MVC和MVVM，并讨论它们在待办事项应用中的实际应用。

### MVC架构

Model-View-Controller (MVC) 是iOS开发中最传统的架构模式，也是Apple官方推荐的架构。

1. **MVC架构组成**

   - **Model(模型)**：表示应用的数据和业务逻辑
     - Task模型：表示一个待办任务
     - Category模型：表示任务分类
     - TaskManager：管理任务数据的CRUD操作

   - **View(视图)**：负责展示数据和接收用户输入
     - TaskListView：显示任务列表
     - TaskDetailView：显示任务详情
     - TaskFormView：创建/编辑任务的表单

   - **Controller(控制器)**：连接模型和视图，处理用户交互和业务逻辑
     - TaskListViewController：管理任务列表视图
     - TaskDetailViewController：管理任务详情视图
     - TaskFormViewController：管理任务创建/编辑视图

2. **MVC架构的优势**

   - 结构清晰，易于理解
   - 与iOS原生框架完美匹配
   - 开发速度快，适合中小型应用

3. **MVC架构的挑战**

   - 控制器容易变得臃肿("Massive View Controller")
   - 视图和控制器耦合度高，不易测试
   - 随着功能增加，维护难度增大

4. **MVC架构在待办应用中的实现示例**

```swift
// Model
struct Task {
    var id: UUID
    var title: String
    var description: String?
    var dueDate: Date?
    var priority: Priority
    var isCompleted: Bool
    var categoryId: UUID?
    
    enum Priority: Int {
        case low = 0
        case medium = 1
        case high = 2
    }
}

// Controller
class TaskListViewController: UIViewController {
    @IBOutlet weak var tableView: UITableView!
    var tasks: [Task] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupTableView()
        loadTasks()
    }
    
    func loadTasks() {
        // 从数据源加载任务
        TaskManager.shared.getTasks { [weak self] tasks in
            self?.tasks = tasks
            self?.tableView.reloadData()
        }
    }
    
    @IBAction func addTaskButtonTapped(_ sender: UIButton) {
        // 打开任务创建界面
        performSegue(withIdentifier: "ShowTaskForm", sender: nil)
    }
    
    // 其他方法...
}
```

### MVVM架构

Model-View-ViewModel (MVVM) 是近年来在iOS开发中日益流行的架构模式，它通过引入ViewModel层解决了MVC中的一些问题。

1. **MVVM架构组成**

   - **Model(模型)**：与MVC中的模型相同，表示数据和业务逻辑
   - **View(视图)**：与MVC类似，但只负责显示，不包含业务逻辑
     - 包括ViewController，在MVVM中视图控制器被视为视图的一部分
   - **ViewModel(视图模型)**：连接模型和视图，处理视图逻辑
     - 提供视图所需的所有数据
     - 处理用户交互
     - 执行业务逻辑操作

2. **MVVM架构的优势**

   - 视图控制器变得轻量化
   - 提高了代码的可测试性
   - 实现了关注点分离，便于维护
   - 支持数据绑定(使用组合框架、RxSwift或自定义观察者模式)

3. **MVVM架构的挑战**

   - 学习曲线较陡
   - 对于简单功能可能显得过度设计
   - 需要额外的绑定机制

4. **MVVM架构在待办应用中的实现示例**

```swift
// ViewModel
class TaskListViewModel {
    // 数据源
    private(set) var tasks: [Task] = []
    
    // 观察者回调
    var onTasksChanged: (([Task]) -> Void)?
    
    // 加载任务
    func loadTasks() {
        TaskManager.shared.getTasks { [weak self] tasks in
            self?.tasks = tasks
            self?.onTasksChanged?(tasks)
        }
    }
    
    // 添加任务
    func addTask(_ task: Task) {
        TaskManager.shared.saveTask(task) { [weak self] success in
            if success {
                self?.loadTasks()
            }
        }
    }
    
    // 完成任务
    func toggleTaskCompletion(_ task: Task) {
        var updatedTask = task
        updatedTask.isCompleted = !task.isCompleted
        
        TaskManager.shared.updateTask(updatedTask) { [weak self] success in
            if success {
                self?.loadTasks()
            }
        }
    }
    
    // 删除任务
    func deleteTask(_ task: Task) {
        TaskManager.shared.deleteTask(task.id) { [weak self] success in
            if success {
                self?.loadTasks()
            }
        }
    }
    
    // 获取任务数量
    func numberOfTasks() -> Int {
        return tasks.count
    }
    
    // 获取指定索引的任务
    func task(at index: Int) -> Task {
        return tasks[index]
    }
}

// View
class TaskListViewController: UIViewController {
    @IBOutlet weak var tableView: UITableView!
    
    let viewModel = TaskListViewModel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupTableView()
        bindViewModel()
        viewModel.loadTasks()
    }
    
    private func bindViewModel() {
        viewModel.onTasksChanged = { [weak self] _ in
            DispatchQueue.main.async {
                self?.tableView.reloadData()
            }
        }
    }
    
    @IBAction func addTaskButtonTapped(_ sender: UIButton) {
        // 打开任务创建界面
        performSegue(withIdentifier: "ShowTaskForm", sender: nil)
    }
    
    // 其他方法...
}

// 表格数据源实现
extension TaskListViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return viewModel.numberOfTasks()
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "TaskCell", for: indexPath) as! TaskCell
        let task = viewModel.task(at: indexPath.row)
        cell.configure(with: task)
        return cell
    }
}
```

### 文件结构组织

一个良好组织的文件结构可以提高代码的可读性和可维护性。以下是我们待办事项应用的推荐文件结构：

```
TaskMaster/
├── AppDelegate.swift
├── SceneDelegate.swift
├── Models/
│   ├── Task.swift
│   ├── Category.swift
│   └── CoreDataModels/
│       ├── TaskEntity+CoreDataClass.swift
│       └── CategoryEntity+CoreDataClass.swift
├── Views/
│   ├── Cells/
│   │   ├── TaskCell.swift
│   │   └── CategoryCell.swift
│   ├── CustomViews/
│   │   ├── PriorityView.swift
│   │   └── DatePickerView.swift
│   └── Storyboards/
│       ├── Main.storyboard
│       └── LaunchScreen.storyboard
├── Controllers/
│   ├── TaskList/
│   │   ├── TaskListViewController.swift
│   │   └── TaskListViewModel.swift (MVVM)
│   ├── TaskDetail/
│   │   ├── TaskDetailViewController.swift
│   │   └── TaskDetailViewModel.swift (MVVM)
│   ├── TaskForm/
│   │   ├── TaskFormViewController.swift
│   │   └── TaskFormViewModel.swift (MVVM)
│   └── Settings/
│       ├── SettingsViewController.swift
│       └── SettingsViewModel.swift (MVVM)
├── Services/
│   ├── DataManager.swift
│   ├── NotificationManager.swift
│   └── SettingsManager.swift
├── Utilities/
│   ├── Extensions/
│   │   ├── Date+Extensions.swift
│   │   ├── UIColor+Extensions.swift
│   │   └── String+Extensions.swift
│   ├── Constants.swift
│   └── Helpers/
│       ├── AlertHelper.swift
│       └── ThemeManager.swift
├── Resources/
│   ├── Assets.xcassets/
│   └── Fonts/
└── SupportingFiles/
    ├── Info.plist
    └── TaskMaster.xcdatamodeld
```

这种结构遵循以下原则：
- 按功能组织文件，而不是按类型
- 相关文件放在同一个目录中
- 通用组件和服务放在独立的目录中
- 清晰的命名约定，便于理解每个文件的用途

## 数据模型设计

数据模型是应用的核心，它定义了应用需要处理的数据结构和关系。对于待办事项应用，我们需要设计任务(Task)和分类(Category)两个主要模型。

### Task模型

Task(任务)是我们应用的核心数据模型，表示用户需要完成的单个任务项。

1. **基本属性**

```swift
struct Task {
    var id: UUID               // 任务唯一标识符
    var title: String          // 任务标题
    var description: String?   // 任务描述(可选)
    var dueDate: Date?         // 截止日期(可选)
    var creationDate: Date     // 创建日期
    var modificationDate: Date // 最后修改日期
    var priority: Priority     // 优先级(高/中/低)
    var isCompleted: Bool      // 完成状态
    var categoryId: UUID?      // 所属分类ID(可选)
    var reminderDate: Date?    // 提醒日期(可选)
    
    enum Priority: Int, CaseIterable, Codable {
        case low = 0
        case medium = 1
        case high = 2
        
        var title: String {
            switch self {
            case .low: return "低"
            case .medium: return "中"
            case .high: return "高"
            }
        }
        
        var color: UIColor {
            switch self {
            case .low: return .systemBlue
            case .medium: return .systemOrange
            case .high: return .systemRed
            }
        }
    }
}
```

2. **序列化支持**

为了支持数据持久化，我们需要让Task模型支持编码和解码：

```swift
extension Task: Codable {
    enum CodingKeys: String, CodingKey {
        case id, title, description, dueDate, creationDate
        case modificationDate, priority, isCompleted, categoryId, reminderDate
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        dueDate = try container.decodeIfPresent(Date.self, forKey: .dueDate)
        creationDate = try container.decode(Date.self, forKey: .creationDate)
        modificationDate = try container.decode(Date.self, forKey: .modificationDate)
        let priorityRaw = try container.decode(Int.self, forKey: .priority)
        priority = Priority(rawValue: priorityRaw) ?? .medium
        isCompleted = try container.decode(Bool.self, forKey: .isCompleted)
        categoryId = try container.decodeIfPresent(UUID.self, forKey: .categoryId)
        reminderDate = try container.decodeIfPresent(Date.self, forKey: .reminderDate)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        try container.encodeIfPresent(description, forKey: .description)
        try container.encodeIfPresent(dueDate, forKey: .dueDate)
        try container.encode(creationDate, forKey: .creationDate)
        try container.encode(modificationDate, forKey: .modificationDate)
        try container.encode(priority.rawValue, forKey: .priority)
        try container.encode(isCompleted, forKey: .isCompleted)
        try container.encodeIfPresent(categoryId, forKey: .categoryId)
        try container.encodeIfPresent(reminderDate, forKey: .reminderDate)
    }
}
```

3. **便利方法**

```swift
extension Task {
    // 创建新任务的便利初始化方法
    init(title: String, description: String? = nil, dueDate: Date? = nil, 
         priority: Priority = .medium, categoryId: UUID? = nil, reminderDate: Date? = nil) {
        self.id = UUID()
        self.title = title
        self.description = description
        self.dueDate = dueDate
        self.creationDate = Date()
        self.modificationDate = Date()
        self.priority = priority
        self.isCompleted = false
        self.categoryId = categoryId
        self.reminderDate = reminderDate
    }
    
    // 判断任务是否已逾期
    var isOverdue: Bool {
        guard let dueDate = dueDate else { return false }
        return !isCompleted && dueDate < Date()
    }
    
    // 判断任务是否为今天的任务
    var isToday: Bool {
        guard let dueDate = dueDate else { return false }
        return Calendar.current.isDateInToday(dueDate)
    }
    
    // 判断任务是否为明天的任务
    var isTomorrow: Bool {
        guard let dueDate = dueDate else { return false }
        return Calendar.current.isDateInTomorrow(dueDate)
    }
    
    // 获取格式化的截止日期字符串
    func formattedDueDate() -> String? {
        guard let dueDate = dueDate else { return nil }
        
        let dateFormatter = DateFormatter()
        
        if isToday {
            return "今天 " + dateFormatter.timeOnly(from: dueDate)
        } else if isTomorrow {
            return "明天 " + dateFormatter.timeOnly(from: dueDate)
        } else {
            return dateFormatter.fullFormat(from: dueDate)
        }
    }
    
    // 创建任务的副本
    func copy() -> Task {
        return Task(
            id: self.id,
            title: self.title,
            description: self.description,
            dueDate: self.dueDate,
            creationDate: self.creationDate,
            modificationDate: Date(),
            priority: self.priority,
            isCompleted: self.isCompleted,
            categoryId: self.categoryId,
            reminderDate: self.reminderDate
        )
    }
}
```

### Category模型

Category(分类)模型用于对任务进行分组和分类，帮助用户更好地组织任务。

1. **基本属性**

```swift
struct Category {
    var id: UUID               // 分类唯一标识符
    var name: String           // 分类名称
    var color: CategoryColor   // 分类颜色
    var creationDate: Date     // 创建日期
    
    enum CategoryColor: Int, CaseIterable, Codable {
        case red = 0
        case orange = 1
        case yellow = 2
        case green = 3
        case blue = 4
        case purple = 5
        case pink = 6
        
        var uiColor: UIColor {
            switch self {
            case .red: return .systemRed
            case .orange: return .systemOrange
            case .yellow: return .systemYellow
            case .green: return .systemGreen
            case .blue: return .systemBlue
            case .purple: return .systemPurple
            case .pink: return .systemPink
            }
        }
        
        var name: String {
            switch self {
            case .red: return "红色"
            case .orange: return "橙色"
            case .yellow: return "黄色"
            case .green: return "绿色"
            case .blue: return "蓝色"
            case .purple: return "紫色"
            case .pink: return "粉色"
            }
        }
    }
}
```

2. **序列化支持**

```swift
extension Category: Codable {
    enum CodingKeys: String, CodingKey {
        case id, name, color, creationDate
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        let colorRaw = try container.decode(Int.self, forKey: .color)
        color = CategoryColor(rawValue: colorRaw) ?? .blue
        creationDate = try container.decode(Date.self, forKey: .creationDate)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        try container.encode(color.rawValue, forKey: .color)
        try container.encode(creationDate, forKey: .creationDate)
    }
}
```

3. **便利方法**

```swift
extension Category {
    // 创建新分类的便利初始化方法
    init(name: String, color: CategoryColor = .blue) {
        self.id = UUID()
        self.name = name
        self.color = color
        self.creationDate = Date()
    }
    
    // 预定义的默认分类
    static let defaultCategories: [Category] = [
        Category(name: "工作", color: .blue),
        Category(name: "个人", color: .green),
        Category(name: "购物", color: .orange),
        Category(name: "健康", color: .red),
        Category(name: "学习", color: .purple)
    ]
}
```

### 数据关系

在我们的应用中，Task和Category之间存在一对多的关系：一个Category可以包含多个Task，而一个Task只能属于一个Category(或者不属于任何Category)。

为了方便数据管理，我们可以定义以下关系辅助方法：

```swift
class DataRelationship {
    // 获取指定分类的所有任务
    static func tasks(for category: Category, in allTasks: [Task]) -> [Task] {
        return allTasks.filter { $0.categoryId == category.id }
    }
    
    // 获取任务所属的分类
    static func category(for task: Task, in allCategories: [Category]) -> Category? {
        guard let categoryId = task.categoryId else { return nil }
        return allCategories.first { $0.id == categoryId }
    }
    
    // 获取未分类的任务
    static func uncategorizedTasks(in allTasks: [Task]) -> [Task] {
        return allTasks.filter { $0.categoryId == nil }
    }
    
    // 按分类分组任务
    static func tasksByCategory(tasks: [Task], categories: [Category]) -> [Category?: [Task]] {
        var result: [Category?: [Task]] = [nil: []]
        
        // 初始化结果字典，确保每个分类都有一个条目
        for category in categories {
            result[category] = []
        }
        
        // 将任务分配到对应的分类
        for task in tasks {
            if let categoryId = task.categoryId, let category = categories.first(where: { $0.id == categoryId }) {
                result[category]?.append(task)
            } else {
                result[nil]?.append(task)
            }
        }
        
        return result
    }
}
```

这些辅助方法将帮助我们在应用中方便地管理和展示按分类组织的任务。在下一节中，我们将探讨如何实现数据持久化，确保用户的任务和分类数据能够被安全地存储和加载。

## 数据持久化

数据持久化是应用开发中的重要环节，它确保了应用的数据能够在设备上被安全地存储和加载。在本项目中，我们将介绍两种主要的持久化方案：UserDefaults和Core Data。

### UserDefaults实现

UserDefaults是iOS平台上的一种轻量级的数据存储方案，适合存储简单的数据。对于我们的待办事项应用，我们可以使用UserDefaults来存储任务和分类数据，特别是在应用的初始阶段或者对于数据量较小的情况。

1. **创建UserDefaults管理器**

首先，我们创建一个专门的类来管理所有与UserDefaults相关的操作，这有助于保持代码的组织性和可维护性：

```swift
class UserDefaultsManager {
    static let shared = UserDefaultsManager()
    
    private let defaults = UserDefaults.standard
    private let tasksKey = "storedTasks"
    private let categoriesKey = "storedCategories"
    
    private init() {}
    
    // MARK: - 任务相关操作
    
    // 保存所有任务
    func saveTasks(_ tasks: [Task]) {
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let tasksData = try encoder.encode(tasks)
            defaults.set(tasksData, forKey: tasksKey)
        } catch {
            print("保存任务时出错: \(error.localizedDescription)")
        }
    }
    
    // 加载所有任务
    func loadTasks() -> [Task] {
        guard let tasksData = defaults.data(forKey: tasksKey) else { return [] }
        
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let tasks = try decoder.decode([Task].self, from: tasksData)
            return tasks
        } catch {
            print("加载任务时出错: \(error.localizedDescription)")
            return []
        }
    }
    
    // 保存单个任务
    func saveTask(_ task: Task) {
        var tasks = loadTasks()
        
        // 检查是否已存在该任务
        if let index = tasks.firstIndex(where: { $0.id == task.id }) {
            tasks[index] = task
        } else {
            tasks.append(task)
        }
        
        saveTasks(tasks)
    }
    
    // 删除任务
    func deleteTask(withId id: UUID) {
        var tasks = loadTasks()
        tasks.removeAll { $0.id == id }
        saveTasks(tasks)
    }
    
    // MARK: - 分类相关操作
    
    // 保存所有分类
    func saveCategories(_ categories: [Category]) {
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            let categoriesData = try encoder.encode(categories)
            defaults.set(categoriesData, forKey: categoriesKey)
        } catch {
            print("保存分类时出错: \(error.localizedDescription)")
        }
    }
    
    // 加载所有分类
    func loadCategories() -> [Category] {
        guard let categoriesData = defaults.data(forKey: categoriesKey) else { 
            // 如果没有保存的分类，返回默认分类
            return Category.defaultCategories 
        }
        
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            let categories = try decoder.decode([Category].self, from: categoriesData)
            return categories
        } catch {
            print("加载分类时出错: \(error.localizedDescription)")
            return Category.defaultCategories
        }
    }
    
    // 保存单个分类
    func saveCategory(_ category: Category) {
        var categories = loadCategories()
        
        // 检查是否已存在该分类
        if let index = categories.firstIndex(where: { $0.id == category.id }) {
            categories[index] = category
        } else {
            categories.append(category)
        }
        
        saveCategories(categories)
    }
    
    // 删除分类
    func deleteCategory(withId id: UUID) {
        var categories = loadCategories()
        categories.removeAll { $0.id == id }
        saveCategories(categories)
        
        // 同时处理关联到此分类的任务
        var tasks = loadTasks()
        for (index, task) in tasks.enumerated() where task.categoryId == id {
            var updatedTask = task
            updatedTask.categoryId = nil
            tasks[index] = updatedTask
        }
        saveTasks(tasks)
    }
    
    // MARK: - 应用设置
    
    // 保存默认视图设置
    func saveDefaultViewOption(_ option: Int) {
        defaults.set(option, forKey: "defaultViewOption")
    }
    
    // 获取默认视图设置
    func getDefaultViewOption() -> Int {
        return defaults.integer(forKey: "defaultViewOption")
    }
    
    // 保存主题设置
    func saveThemeOption(_ option: Int) {
        defaults.set(option, forKey: "themeOption")
    }
    
    // 获取主题设置
    func getThemeOption() -> Int {
        return defaults.integer(forKey: "themeOption")
    }
    
    // 保存通知设置
    func saveNotificationEnabled(_ enabled: Bool) {
        defaults.set(enabled, forKey: "notificationEnabled")
    }
    
    // 获取通知设置
    func getNotificationEnabled() -> Bool {
        return defaults.bool(forKey: "notificationEnabled")
    }
    
    // MARK: - 辅助方法
    
    // 清除所有数据（用于测试或重置功能）
    func clearAllData() {
        defaults.removeObject(forKey: tasksKey)
        defaults.removeObject(forKey: categoriesKey)
        defaults.removeObject(forKey: "defaultViewOption")
        defaults.removeObject(forKey: "themeOption")
        defaults.removeObject(forKey: "notificationEnabled")
    }
}
```

2. **在应用中使用UserDefaults存储器**

接下来，我们可以在应用中的各个地方使用这个管理器类来处理数据的存储和读取。以下是一些示例：

```swift
class TaskListViewController: UIViewController {
    var tasks: [Task] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        loadTasks()
    }
    
    func loadTasks() {
        // 从UserDefaults加载任务
        tasks = UserDefaultsManager.shared.loadTasks()
        tableView.reloadData()
    }
    
    @IBAction func addTaskButtonTapped(_ sender: UIButton) {
        // 创建新任务示例
        let newTask = Task(title: "新任务", description: "任务描述")
        UserDefaultsManager.shared.saveTask(newTask)
        loadTasks() // 重新加载任务列表
    }
    
    func completeTask(at index: Int) {
        var task = tasks[index]
        task.isCompleted = !task.isCompleted
        task.modificationDate = Date()
        
        UserDefaultsManager.shared.saveTask(task)
        loadTasks()
    }
    
    func deleteTask(at index: Int) {
        let task = tasks[index]
        UserDefaultsManager.shared.deleteTask(withId: task.id)
        loadTasks()
    }
}
```

3. **处理日期格式化的扩展方法**

为了支持前面提到的日期格式化方法，我们需要添加一些DateFormatter的扩展：

```swift
extension DateFormatter {
    // 只返回时间部分的格式化字符串
    func timeOnly(from date: Date) -> String {
        self.dateFormat = "HH:mm"
        return self.string(from: date)
    }
    
    // 返回完整日期时间的格式化字符串
    func fullFormat(from date: Date) -> String {
        self.dateFormat = "yyyy年MM月dd日 HH:mm"
        return self.string(from: date)
    }
    
    // 返回仅日期的格式化字符串
    func dateOnly(from date: Date) -> String {
        self.dateFormat = "yyyy年MM月dd日"
        return self.string(from: date)
    }
}
```

4. **实现任务排序与筛选**

使用UserDefaults存储的数据进行排序和筛选操作：

```swift
extension TaskListViewController {
    // 按截止日期排序任务
    func sortTasksByDueDate() {
        tasks.sort { 
            // 没有截止日期的任务排在最后
            guard let date1 = $0.dueDate else { return false }
            guard let date2 = $1.dueDate else { return true }
            return date1 < date2
        }
        tableView.reloadData()
    }
    
    // 按优先级排序任务
    func sortTasksByPriority() {
        tasks.sort {
            $0.priority.rawValue > $1.priority.rawValue
        }
        tableView.reloadData()
    }
    
    // 筛选今天的任务
    func filterTodayTasks() {
        let allTasks = UserDefaultsManager.shared.loadTasks()
        tasks = allTasks.filter { $0.isToday }
        tableView.reloadData()
    }
    
    // 筛选已完成的任务
    func filterCompletedTasks() {
        let allTasks = UserDefaultsManager.shared.loadTasks()
        tasks = allTasks.filter { $0.isCompleted }
        tableView.reloadData()
    }
    
    // 筛选未完成的任务
    func filterIncompleteTasks() {
        let allTasks = UserDefaultsManager.shared.loadTasks()
        tasks = allTasks.filter { !$0.isCompleted }
        tableView.reloadData()
    }
    
    // 按分类筛选任务
    func filterTasks(byCategory categoryId: UUID?) {
        let allTasks = UserDefaultsManager.shared.loadTasks()
        tasks = allTasks.filter { $0.categoryId == categoryId }
        tableView.reloadData()
    }
}
```

5. **任务数据完整性与一致性**

为了确保数据的完整性和一致性，我们还可以添加一些数据验证和处理方法：

```swift
extension Task {
    // 验证任务数据
    func isValid() -> Bool {
        return !title.isEmpty // 至少需要有标题
    }
    
    // 计算任务的剩余时间
    var remainingTime: TimeInterval? {
        guard let dueDate = dueDate else { return nil }
        return dueDate.timeIntervalSince(Date())
    }
    
    // 获取任务状态描述
    var statusDescription: String {
        if isCompleted {
            return "已完成"
        } else if isOverdue {
            return "已逾期"
        } else if isToday {
            return "今天到期"
        } else if isTomorrow {
            return "明天到期"
        } else if let dueDate = dueDate {
            let formatter = DateFormatter()
            formatter.dateFormat = "yyyy年MM月dd日"
            return "\(formatter.string(from: dueDate))到期"
        } else {
            return "无截止日期"
        }
    }
}
```

### Core Data实现

Core Data是iOS平台上功能更强大的数据持久化框架，适合存储复杂的数据关系和执行高级查询。随着应用功能的增长和数据量的增加，从UserDefaults迁移到Core Data是自然的选择。

1. **设置Core Data模型**

首先，我们需要创建Core Data模型文件(.xcdatamodeld)并定义实体。在Xcode中：

- 选择"File" > "New" > "File..."
- 选择"Data Model"模板
- 命名为"TaskMaster.xcdatamodeld"

然后创建两个实体：TaskEntity和CategoryEntity

**TaskEntity**:
- attributes:
  - id: UUID
  - title: String
  - taskDescription: String (使用description会与NSManagedObject冲突)
  - dueDate: Date
  - creationDate: Date
  - modificationDate: Date
  - priorityValue: Integer 16 (枚举值)
  - isCompleted: Boolean
  - reminderDate: Date

**CategoryEntity**:
- attributes:
  - id: UUID
  - name: String
  - colorValue: Integer 16 (枚举值)
  - creationDate: Date

**关系**:
- TaskEntity 添加 relationship "category" -> CategoryEntity (类型：To One)
- CategoryEntity 添加 relationship "tasks" -> TaskEntity (类型：To Many)
- 设置互为inverse关系

2. **创建Core Data管理器**

接下来，创建一个Core Data管理器类来处理所有与Core Data相关的操作：

```swift
import CoreData
import UIKit

class CoreDataManager {
    static let shared = CoreDataManager()
    
    private init() {}
    
    // 获取视图上下文
    lazy var context: NSManagedObjectContext = {
        return persistentContainer.viewContext
    }()
    
    // 设置持久化容器
    lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "TaskMaster")
        container.loadPersistentStores { (storeDescription, error) in
            if let error = error as NSError? {
                fatalError("无法加载Core Data存储: \(error), \(error.userInfo)")
            }
        }
        return container
    }()
    
    // MARK: - 数据保存方法
    
    func saveContext() {
        if context.hasChanges {
            do {
                try context.save()
            } catch {
                let nserror = error as NSError
                print("无法保存Core Data上下文: \(nserror), \(nserror.userInfo)")
            }
        }
    }
    
    // MARK: - 任务相关方法
    
    // 创建新任务
    func createTask(title: String, description: String? = nil, dueDate: Date? = nil, 
                   priority: Task.Priority = .medium, category: CategoryEntity? = nil, 
                   reminderDate: Date? = nil) -> TaskEntity {
        
        let task = TaskEntity(context: context)
        task.id = UUID()
        task.title = title
        task.taskDescription = description
        task.dueDate = dueDate
        task.creationDate = Date()
        task.modificationDate = Date()
        task.priorityValue = Int16(priority.rawValue)
        task.isCompleted = false
        task.category = category
        task.reminderDate = reminderDate
        
        saveContext()
        return task
    }
    
    // 更新任务
    func updateTask(_ entity: TaskEntity, with task: Task) {
        entity.title = task.title
        entity.taskDescription = task.description
        entity.dueDate = task.dueDate
        entity.modificationDate = Date()
        entity.priorityValue = Int16(task.priority.rawValue)
        entity.isCompleted = task.isCompleted
        entity.reminderDate = task.reminderDate
        
        // 处理分类关系
        if let categoryId = task.categoryId {
            entity.category = fetchCategory(withId: categoryId)
        } else {
            entity.category = nil
        }
        
        saveContext()
    }
    
    // 删除任务
    func deleteTask(_ task: TaskEntity) {
        context.delete(task)
        saveContext()
    }
    
    // 获取所有任务
    func fetchAllTasks() -> [TaskEntity] {
        let request: NSFetchRequest<TaskEntity> = TaskEntity.fetchRequest()
        
        // 默认按创建日期排序
        let sortDescriptor = NSSortDescriptor(key: "creationDate", ascending: false)
        request.sortDescriptors = [sortDescriptor]
        
        do {
            return try context.fetch(request)
        } catch {
            print("获取任务失败: \(error)")
            return []
        }
    }
    
    // 按ID获取任务
    func fetchTask(withId id: UUID) -> TaskEntity? {
        let request: NSFetchRequest<TaskEntity> = TaskEntity.fetchRequest()
        request.predicate = NSPredicate(format: "id == %@", id as CVarArg)
        
        do {
            let results = try context.fetch(request)
            return results.first
        } catch {
            print("按ID获取任务失败: \(error)")
            return nil
        }
    }
    
    // 获取今天的任务
    func fetchTodayTasks() -> [TaskEntity] {
        let request: NSFetchRequest<TaskEntity> = TaskEntity.fetchRequest()
        
        // 创建今天开始和结束的日期
        let calendar = Calendar.current
        let today = calendar.startOfDay(for: Date())
        let tomorrow = calendar.date(byAdding: .day, value: 1, to: today)!
        
        // 设置谓词条件：dueDate在今天范围内或者已经过期但未完成
        let todayPredicate = NSPredicate(format: "dueDate >= %@ AND dueDate < %@", today as NSDate, tomorrow as NSDate)
        let overduePredicate = NSPredicate(format: "dueDate < %@ AND isCompleted == %@", today as NSDate, NSNumber(value: false))
        request.predicate = NSCompoundPredicate(orPredicateWithSubpredicates: [todayPredicate, overduePredicate])
        
        do {
            return try context.fetch(request)
        } catch {
            print("获取今天任务失败: \(error)")
            return []
        }
    }
    
    // 获取已完成的任务
    func fetchCompletedTasks() -> [TaskEntity] {
        let request: NSFetchRequest<TaskEntity> = TaskEntity.fetchRequest()
        request.predicate = NSPredicate(format: "isCompleted == %@", NSNumber(value: true))
        
        do {
            return try context.fetch(request)
        } catch {
            print("获取已完成任务失败: \(error)")
            return []
        }
    }
    
    // 按分类获取任务
    func fetchTasks(forCategory category: CategoryEntity) -> [TaskEntity] {
        // 直接使用关系获取
        return (category.tasks?.allObjects as? [TaskEntity]) ?? []
    }
    
    // MARK: - 分类相关方法
    
    // 创建新分类
    func createCategory(name: String, color: Category.CategoryColor = .blue) -> CategoryEntity {
        let category = CategoryEntity(context: context)
        category.id = UUID()
        category.name = name
        category.colorValue = Int16(color.rawValue)
        category.creationDate = Date()
        
        saveContext()
        return category
    }
    
    // 更新分类
    func updateCategory(_ entity: CategoryEntity, with category: Category) {
        entity.name = category.name
        entity.colorValue = Int16(category.color.rawValue)
        
        saveContext()
    }
    
    // 删除分类
    func deleteCategory(_ category: CategoryEntity) {
        // 获取关联的任务
        if let tasks = category.tasks as? Set<TaskEntity> {
            // 解除任务与分类的关联
            for task in tasks {
                task.category = nil
            }
        }
        
        context.delete(category)
        saveContext()
    }
    
    // 获取所有分类
    func fetchAllCategories() -> [CategoryEntity] {
        let request: NSFetchRequest<CategoryEntity> = CategoryEntity.fetchRequest()
        
        // 按名称排序
        let sortDescriptor = NSSortDescriptor(key: "name", ascending: true)
        request.sortDescriptors = [sortDescriptor]
        
        do {
            return try context.fetch(request)
        } catch {
            print("获取分类失败: \(error)")
            return []
        }
    }
    
    // 按ID获取分类
    func fetchCategory(withId id: UUID) -> CategoryEntity? {
        let request: NSFetchRequest<CategoryEntity> = CategoryEntity.fetchRequest()
        request.predicate = NSPredicate(format: "id == %@", id as CVarArg)
        
        do {
            let results = try context.fetch(request)
            return results.first
        } catch {
            print("按ID获取分类失败: \(error)")
            return nil
        }
    }
    
    // MARK: - 模型转换方法
    
    // 将TaskEntity转换为Task模型
    func convertToTask(_ entity: TaskEntity) -> Task {
        let categoryId = entity.category?.id
        
        return Task(
            id: entity.id ?? UUID(),
            title: entity.title ?? "",
            description: entity.taskDescription,
            dueDate: entity.dueDate,
            creationDate: entity.creationDate ?? Date(),
            modificationDate: entity.modificationDate ?? Date(),
            priority: Task.Priority(rawValue: Int(entity.priorityValue)) ?? .medium,
            isCompleted: entity.isCompleted,
            categoryId: categoryId,
            reminderDate: entity.reminderDate
        )
    }
    
    // 将CategoryEntity转换为Category模型
    func convertToCategory(_ entity: CategoryEntity) -> Category {
        return Category(
            id: entity.id ?? UUID(),
            name: entity.name ?? "",
            color: Category.CategoryColor(rawValue: Int(entity.colorValue)) ?? .blue,
            creationDate: entity.creationDate ?? Date()
        )
    }
    
    // MARK: - 批量操作方法
    
    // 批量删除所有任务
    func deleteAllTasks() {
        let fetchRequest: NSFetchRequest<NSFetchRequestResult> = TaskEntity.fetchRequest()
        let deleteRequest = NSBatchDeleteRequest(fetchRequest: fetchRequest)
        
        do {
            try context.execute(deleteRequest)
            saveContext()
        } catch {
            print("批量删除任务失败: \(error)")
        }
    }
    
    // 批量删除所有分类
    func deleteAllCategories() {
        let fetchRequest: NSFetchRequest<NSFetchRequestResult> = CategoryEntity.fetchRequest()
        let deleteRequest = NSBatchDeleteRequest(fetchRequest: fetchRequest)
        
        do {
            try context.execute(deleteRequest)
            saveContext()
        } catch {
            print("批量删除分类失败: \(error)")
        }
    }
    
    // 重置所有数据
    func resetAllData() {
        deleteAllTasks()
        deleteAllCategories()
    }
}
```

3. **创建NSManagedObject子类**

为了更方便地使用Core Data实体，我们可以为TaskEntity和CategoryEntity创建NSManagedObject子类：

```swift
// TaskEntity+CoreDataClass.swift
import Foundation
import CoreData

@objc(TaskEntity)
public class TaskEntity: NSManagedObject {
    // 判断任务是否已逾期
    var isOverdue: Bool {
        guard let dueDate = dueDate else { return false }
        return !isCompleted && dueDate < Date()
    }
    
    // 判断任务是否为今天的任务
    var isToday: Bool {
        guard let dueDate = dueDate else { return false }
        return Calendar.current.isDateInToday(dueDate)
    }
    
    // 判断任务是否为明天的任务
    var isTomorrow: Bool {
        guard let dueDate = dueDate else { return false }
        return Calendar.current.isDateInTomorrow(dueDate)
    }
    
    // 获取任务优先级
    var priority: Task.Priority {
        get {
            return Task.Priority(rawValue: Int(priorityValue)) ?? .medium
        }
        set {
            priorityValue = Int16(newValue.rawValue)
        }
    }
}

// TaskEntity+CoreDataProperties.swift
import Foundation
import CoreData

extension TaskEntity {
    @nonobjc public class func fetchRequest() -> NSFetchRequest<TaskEntity> {
        return NSFetchRequest<TaskEntity>(entityName: "TaskEntity")
    }

    @NSManaged public var id: UUID?
    @NSManaged public var title: String?
    @NSManaged public var taskDescription: String?
    @NSManaged public var dueDate: Date?
    @NSManaged public var creationDate: Date?
    @NSManaged public var modificationDate: Date?
    @NSManaged public var priorityValue: Int16
    @NSManaged public var isCompleted: Bool
    @NSManaged public var reminderDate: Date?
    @NSManaged public var category: CategoryEntity?
}

// CategoryEntity+CoreDataClass.swift
import Foundation
import CoreData

@objc(CategoryEntity)
public class CategoryEntity: NSManagedObject {
    // 获取分类颜色
    var color: Category.CategoryColor {
        get {
            return Category.CategoryColor(rawValue: Int(colorValue)) ?? .blue
        }
        set {
            colorValue = Int16(newValue.rawValue)
        }
    }
}

// CategoryEntity+CoreDataProperties.swift
import Foundation
import CoreData

extension CategoryEntity {
    @nonobjc public class func fetchRequest() -> NSFetchRequest<CategoryEntity> {
        return NSFetchRequest<CategoryEntity>(entityName: "CategoryEntity")
    }

    @NSManaged public var id: UUID?
    @NSManaged public var name: String?
    @NSManaged public var colorValue: Int16
    @NSManaged public var creationDate: Date?
    @NSManaged public var tasks: NSSet?
}

// MARK: Generated accessors for tasks
extension CategoryEntity {
    @objc(addTasksObject:)
    @NSManaged public func addToTasks(_ value: TaskEntity)

    @objc(removeTasksObject:)
    @NSManaged public func removeFromTasks(_ value: TaskEntity)

    @objc(addTasks:)
    @NSManaged public func addToTasks(_ values: NSSet)

    @objc(removeTasks:)
    @NSManaged public func removeFromTasks(_ values: NSSet)
}
```

4. **在视图控制器中使用Core Data**

下面是一个使用Core Data来管理任务的TaskListViewController示例：

```swift
class TaskListViewController: UIViewController {
    @IBOutlet weak var tableView: UITableView!
    
    var taskEntities: [TaskEntity] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupTableView()
        loadTasks()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // 每次界面将要显示时刷新数据
        loadTasks()
    }
    
    func loadTasks() {
        // 从Core Data加载任务
        taskEntities = CoreDataManager.shared.fetchAllTasks()
        tableView.reloadData()
    }
    
    @IBAction func addTaskButtonTapped(_ sender: UIButton) {
        showAddTaskAlert()
    }
    
    func showAddTaskAlert() {
        let alert = UIAlertController(title: "添加新任务", message: nil, preferredStyle: .alert)
        
        alert.addTextField { textField in
            textField.placeholder = "任务标题"
        }
        
        let cancelAction = UIAlertAction(title: "取消", style: .cancel)
        let addAction = UIAlertAction(title: "添加", style: .default) { [weak self] _ in
            guard let title = alert.textFields?.first?.text, !title.isEmpty else { return }
            
            // 创建新任务
            let _ = CoreDataManager.shared.createTask(title: title)
            self?.loadTasks()
        }
        
        alert.addAction(cancelAction)
        alert.addAction(addAction)
        
        present(alert, animated: true)
    }
    
    func completeTask(at indexPath: IndexPath) {
        let task = taskEntities[indexPath.row]
        task.isCompleted = !task.isCompleted
        task.modificationDate = Date()
        
        CoreDataManager.shared.saveContext()
        loadTasks()
    }
    
    func deleteTask(at indexPath: IndexPath) {
        let task = taskEntities[indexPath.row]
        CoreDataManager.shared.deleteTask(task)
        loadTasks()
    }
}

// MARK: - UITableViewDataSource
extension TaskListViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return taskEntities.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "TaskCell", for: indexPath)
        
        let task = taskEntities[indexPath.row]
        
        // 配置单元格
        cell.textLabel?.text = task.title
        
        // 设置附加信息
        var detailText = ""
        if let dueDate = task.dueDate {
            let formatter = DateFormatter()
            if task.isToday {
                detailText += "今天 "
                formatter.dateFormat = "HH:mm"
            } else if task.isTomorrow {
                detailText += "明天 "
                formatter.dateFormat = "HH:mm"
            } else {
                formatter.dateFormat = "yyyy年MM月dd日 HH:mm"
            }
            detailText += formatter.string(from: dueDate)
        }
        
        // 添加分类信息
        if let category = task.category {
            if !detailText.isEmpty {
                detailText += " - "
            }
            detailText += category.name ?? ""
        }
        
        cell.detailTextLabel?.text = detailText
        
        // 设置完成状态
        if task.isCompleted {
            cell.textLabel?.attributedText = task.title?.strikethrough()
            cell.accessoryType = .checkmark
        } else {
            cell.textLabel?.attributedText = nil
            cell.textLabel?.text = task.title
            cell.accessoryType = .none
        }
        
        // 设置过期样式
        if task.isOverdue && !task.isCompleted {
            cell.textLabel?.textColor = .systemRed
        } else {
            cell.textLabel?.textColor = .label
        }
        
        return cell
    }
}

// MARK: - UITableViewDelegate
extension TaskListViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        
        // 跳转到任务详情页
        let task = taskEntities[indexPath.row]
        performSegue(withIdentifier: "ShowTaskDetail", sender: task)
    }
    
    func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        // 删除操作
        let deleteAction = UIContextualAction(style: .destructive, title: "删除") { [weak self] (_, _, completion) in
            self?.deleteTask(at: indexPath)
            completion(true)
        }
        deleteAction.backgroundColor = .systemRed
        
        // 完成/取消完成操作
        let task = taskEntities[indexPath.row]
        let completeTitle = task.isCompleted ? "取消完成" : "完成"
        let completeAction = UIContextualAction(style: .normal, title: completeTitle) { [weak self] (_, _, completion) in
            self?.completeTask(at: indexPath)
            completion(true)
        }
        completeAction.backgroundColor = task.isCompleted ? .systemOrange : .systemGreen
        
        let configuration = UISwipeActionsConfiguration(actions: [deleteAction, completeAction])
        return configuration
    }
}

// MARK: - 导航
extension TaskListViewController {
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if segue.identifier == "ShowTaskDetail", let task = sender as? TaskEntity, let detailVC = segue.destination as? TaskDetailViewController {
            detailVC.taskEntity = task
        }
    }
}

// 为String添加删除线样式的扩展
extension String {
    func strikethrough() -> NSAttributedString {
        let attributeString = NSMutableAttributedString(string: self)
        attributeString.addAttribute(NSAttributedString.Key.strikethroughStyle, value: NSUnderlineStyle.single.rawValue, range: NSRange(location: 0, length: attributeString.length))
        return attributeString
    }
}
```

5. **数据迁移**

如果需要从UserDefaults迁移到Core Data，可以实现以下迁移函数：

```swift
func migrateFromUserDefaultsToCorData() {
    // 检查是否已经迁移过
    let defaults = UserDefaults.standard
    if defaults.bool(forKey: "hasMigratedToCorData") {
        return
    }
    
    // 获取UserDefaults中的数据
    let userDefaultsManager = UserDefaultsManager.shared
    let tasks = userDefaultsManager.loadTasks()
    let categories = userDefaultsManager.loadCategories()
    
    // 获取Core Data管理器
    let coreDataManager = CoreDataManager.shared
    
    // 先迁移分类数据
    var categoryMappings: [UUID: CategoryEntity] = [:]
    for category in categories {
        let categoryEntity = coreDataManager.createCategory(name: category.name, color: category.color)
        categoryMappings[category.id] = categoryEntity
    }
    
    // 迁移任务数据
    for task in tasks {
        let categoryEntity = task.categoryId.flatMap { categoryMappings[$0] }
        let _ = coreDataManager.createTask(
            title: task.title,
            description: task.description,
            dueDate: task.dueDate,
            priority: task.priority,
            category: categoryEntity,
            reminderDate: task.reminderDate
        )
    }
    
    // 标记已迁移
    defaults.set(true, forKey: "hasMigratedToCorData")
    
    print("从UserDefaults成功迁移到Core Data!")
}
```

使用Core Data可以实现更复杂的数据操作，比如复杂查询、关系管理和数据迁移。随着应用的增长，Core Data能够提供更好的性能和功能支持。
```

### 数据迁移策略

数据迁移是应用开发中的重要环节，它确保了应用的数据能够在不同版本之间被安全地迁移和加载。在本项目中，我们将介绍如何实现数据迁移。

1. **基本用法**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let task = Task(context: context)
task.title = "新任务"
task.description = "这是一个新任务的描述"
task.dueDate = Date()
task.priority = .medium
task.isCompleted = false
task.creationDate = Date()
task.modificationDate = Date()
task.categoryId = UUID()
task.reminderDate = Date()

try? context.save()
```

2. **序列化支持**

为了支持数据迁移，我们需要让Task模型支持编码和解码：

```swift
extension Task: Codable {
    enum CodingKeys: String, CodingKey {
        case id, title, description, dueDate, creationDate
        case modificationDate, priority, isCompleted, categoryId, reminderDate
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        description = try container.decodeIfPresent(String.self, forKey: .description)
        dueDate = try container.decodeIfPresent(Date.self, forKey: .dueDate)
        creationDate = try container.decode(Date.self, forKey: .creationDate)
        modificationDate = try container.decode(Date.self, forKey: .modificationDate)
        let priorityRaw = try container.decode(Int.self, forKey: .priority)
        priority = Priority(rawValue: priorityRaw) ?? .medium
        isCompleted = try container.decode(Bool.self, forKey: .isCompleted)
        categoryId = try container.decodeIfPresent(UUID.self, forKey: .categoryId)
        reminderDate = try container.decodeIfPresent(Date.self, forKey: .reminderDate)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        try container.encodeIfPresent(description, forKey: .description)
        try container.encodeIfPresent(dueDate, forKey: .dueDate)
        try container.encode(creationDate, forKey: .creationDate)
        try container.encode(modificationDate, forKey: .modificationDate)
        try container.encode(priority.rawValue, forKey: .priority)
        try container.encode(isCompleted, forKey: .isCompleted)
        try container.encodeIfPresent(categoryId, forKey: .categoryId)
        try container.encodeIfPresent(reminderDate, forKey: .reminderDate)
    }
}
```

3. **便利方法**

```swift
extension Task {
    // 创建新任务的便利初始化方法
    init(title: String, description: String? = nil, dueDate: Date? = nil, 
         priority: Priority = .medium, categoryId: UUID? = nil, reminderDate: Date? = nil) {
        self.id = UUID()
        self.title = title
        self.description = description
        self.dueDate = dueDate
        self.creationDate = Date()
        self.modificationDate = Date()
        self.priority = priority
        self.isCompleted = false
        self.categoryId = categoryId
        self.reminderDate = reminderDate
    }
    
    // 判断任务是否已逾期
    var isOverdue: Bool {
        guard let dueDate = dueDate else { return false }
        return !isCompleted && dueDate < Date()
    }
    
    // 判断任务是否为今天的任务
    var isToday: Bool {
        guard let dueDate = dueDate else { return false }
        return Calendar.current.isDateInToday(dueDate)
    }
    
    // 判断任务是否为明天的任务
    var isTomorrow: Bool {
        guard let dueDate = dueDate else { return false }
        return Calendar.current.isDateInTomorrow(dueDate)
    }
    
    // 获取格式化的截止日期字符串
    func formattedDueDate() -> String? {
        guard let dueDate = dueDate else { return nil }
        
        let dateFormatter = DateFormatter()
        
        if isToday {
            return "今天 " + dateFormatter.timeOnly(from: dueDate)
        } else if isTomorrow {
            return "明天 " + dateFormatter.timeOnly(from: dueDate)
        } else {
            return dateFormatter.fullFormat(from: dueDate)
        }
    }
    
    // 创建任务的副本
    func copy() -> Task {
        return Task(
            id: self.id,
            title: self.title,
            description: self.description,
            dueDate: self.dueDate,
            creationDate: self.creationDate,
            modificationDate: Date(),
            priority: self.priority,
            isCompleted: self.isCompleted,
            categoryId: self.categoryId,
            reminderDate: self.reminderDate
        )
    }
}
```

## UI设计与实现

UI设计与实现是应用开发中的重要环节，它确保了应用的用户界面既美观又易用。在本项目中，我们将介绍如何实现任务列表界面、任务详情界面、任务创建/编辑界面和设置界面。

### 任务列表界面

任务列表界面是应用的入口界面，它展示了所有任务的列表。这个界面需要设计得简洁直观，让用户能够快速查看和管理自己的任务。

1. **界面设计与布局**

首先，我们需要创建一个任务列表界面的布局：

```swift
import UIKit

class TaskListViewController: UIViewController {
    
    // MARK: - UI组件
    
    // 表格视图
    private lazy var tableView: UITableView = {
        let tableView = UITableView(frame: .zero, style: .insetGrouped)
        tableView.register(TaskCell.self, forCellReuseIdentifier: "TaskCell")
        tableView.delegate = self
        tableView.dataSource = self
        tableView.backgroundColor = .systemGroupedBackground
        tableView.separatorStyle = .singleLine
        tableView.rowHeight = UITableView.automaticDimension
        tableView.estimatedRowHeight = 70
        tableView.translatesAutoresizingMaskIntoConstraints = false
        return tableView
    }()
    
    // 空状态视图
    private lazy var emptyStateView: UIView = {
        let view = UIView()
        view.isHidden = true
        view.translatesAutoresizingMaskIntoConstraints = false
        
        let imageView = UIImageView(image: UIImage(systemName: "checkmark.circle"))
        imageView.tintColor = .systemGray3
        imageView.contentMode = .scaleAspectFit
        imageView.translatesAutoresizingMaskIntoConstraints = false
        
        let label = UILabel()
        label.text = "没有任务\n点击 + 添加新任务"
        label.textAlignment = .center
        label.textColor = .systemGray
        label.font = UIFont.systemFont(ofSize: 17, weight: .medium)
        label.numberOfLines = 0
        label.translatesAutoresizingMaskIntoConstraints = false
        
        view.addSubview(imageView)
        view.addSubview(label)
        
        NSLayoutConstraint.activate([
            imageView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            imageView.topAnchor.constraint(equalTo: view.topAnchor, constant: 20),
            imageView.widthAnchor.constraint(equalToConstant: 60),
            imageView.heightAnchor.constraint(equalToConstant: 60),
            
            label.topAnchor.constraint(equalTo: imageView.bottomAnchor, constant: 16),
            label.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            label.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 20),
            label.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -20),
            label.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -20)
        ])
        
        return view
    }()
    
    // 添加任务按钮
    private lazy var addButton: UIButton = {
        let button = UIButton(type: .system)
        button.setImage(UIImage(systemName: "plus.circle.fill"), for: .normal)
        button.tintColor = .systemBlue
        button.contentVerticalAlignment = .fill
        button.contentHorizontalAlignment = .fill
        button.addTarget(self, action: #selector(addTaskButtonTapped), for: .touchUpInside)
        button.translatesAutoresizingMaskIntoConstraints = false
        return button
    }()
    
    // 分段控制器（用于筛选任务）
    private lazy var segmentedControl: UISegmentedControl = {
        let items = ["全部", "今天", "未完成", "已完成"]
        let segmentedControl = UISegmentedControl(items: items)
        segmentedControl.selectedSegmentIndex = 0
        segmentedControl.addTarget(self, action: #selector(segmentChanged(_:)), for: .valueChanged)
        segmentedControl.translatesAutoresizingMaskIntoConstraints = false
        return segmentedControl
    }()
    
    // MARK: - 属性
    
    private var tasks: [Task] = []
    private var filteredTasks: [Task] = []
    private var currentFilter: TaskFilter = .all
    
    private enum TaskFilter {
        case all
        case today
        case incomplete
        case completed
    }
    
    // MARK: - 生命周期方法
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        loadTasks()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        loadTasks() // 每次视图将要显示时重新加载任务
    }
    
    // MARK: - UI设置
    
    private func setupUI() {
        view.backgroundColor = .systemBackground
        title = "待办任务"
        
        // 添加导航栏按钮
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: "筛选", style: .plain, target: self, action: #selector(filterButtonTapped))
        
        // 添加子视图
        view.addSubview(segmentedControl)
        view.addSubview(tableView)
        view.addSubview(emptyStateView)
        view.addSubview(addButton)
        
        // 设置约束
        NSLayoutConstraint.activate([
            segmentedControl.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            segmentedControl.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            segmentedControl.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            
            tableView.topAnchor.constraint(equalTo: segmentedControl.bottomAnchor, constant: 8),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            
            emptyStateView.centerXAnchor.constraint(equalTo: tableView.centerXAnchor),
            emptyStateView.centerYAnchor.constraint(equalTo: tableView.centerYAnchor),
            emptyStateView.widthAnchor.constraint(equalTo: tableView.widthAnchor),
            emptyStateView.heightAnchor.constraint(greaterThanOrEqualToConstant: 200),
            
            addButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            addButton.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20),
            addButton.widthAnchor.constraint(equalToConstant: 56),
            addButton.heightAnchor.constraint(equalToConstant: 56)
        ])
    }
    
    // MARK: - 数据管理
    
    private func loadTasks() {
        // 从数据源加载任务
        tasks = UserDefaultsManager.shared.loadTasks()
        applyFilter()
    }
    
    private func applyFilter() {
        switch currentFilter {
        case .all:
            filteredTasks = tasks
        case .today:
            filteredTasks = tasks.filter { $0.isToday }
        case .incomplete:
            filteredTasks = tasks.filter { !$0.isCompleted }
        case .completed:
            filteredTasks = tasks.filter { $0.isCompleted }
        }
        
        updateEmptyState()
        tableView.reloadData()
    }
    
    private func updateEmptyState() {
        emptyStateView.isHidden = !filteredTasks.isEmpty
        tableView.isHidden = filteredTasks.isEmpty
    }
    
    // MARK: - 事件处理
    
    @objc private func addTaskButtonTapped() {
        let taskFormVC = TaskFormViewController()
        taskFormVC.delegate = self
        let navController = UINavigationController(rootViewController: taskFormVC)
        present(navController, animated: true)
    }
    
    @objc private func segmentChanged(_ sender: UISegmentedControl) {
        switch sender.selectedSegmentIndex {
        case 0:
            currentFilter = .all
        case 1:
            currentFilter = .today
        case 2:
            currentFilter = .incomplete
        case 3:
            currentFilter = .completed
        default:
            currentFilter = .all
        }
        
        applyFilter()
    }
    
    @objc private func filterButtonTapped() {
        // 弹出筛选菜单
        let actionSheet = UIAlertController(title: "筛选任务", message: nil, preferredStyle: .actionSheet)
        
        // 添加按日期排序
        let sortByDateAction = UIAlertAction(title: "按日期排序", style: .default) { [weak self] _ in
            self?.sortTasksByDate()
        }
        
        // 添加按优先级排序
        let sortByPriorityAction = UIAlertAction(title: "按优先级排序", style: .default) { [weak self] _ in
            self?.sortTasksByPriority()
        }
        
        // 添加显示所有分类选项
        let showAllCategoriesAction = UIAlertAction(title: "所有分类", style: .default) { [weak self] _ in
            self?.filterByCategory(nil)
        }
        
        // 添加分类筛选选项
        let categories = UserDefaultsManager.shared.loadCategories()
        for category in categories {
            let categoryAction = UIAlertAction(title: "分类: \(category.name)", style: .default) { [weak self] _ in
                self?.filterByCategory(category.id)
            }
            actionSheet.addAction(categoryAction)
        }
        
        let cancelAction = UIAlertAction(title: "取消", style: .cancel)
        
        actionSheet.addAction(sortByDateAction)
        actionSheet.addAction(sortByPriorityAction)
        actionSheet.addAction(showAllCategoriesAction)
        actionSheet.addAction(cancelAction)
        
        present(actionSheet, animated: true)
    }
    
    private func sortTasksByDate() {
        tasks.sort {
            guard let date1 = $0.dueDate else { return false }
            guard let date2 = $1.dueDate else { return true }
            return date1 < date2
        }
        applyFilter()
    }
    
    private func sortTasksByPriority() {
        tasks.sort { $0.priority.rawValue > $1.priority.rawValue }
        applyFilter()
    }
    
    private func filterByCategory(_ categoryId: UUID?) {
        currentFilter = .all
        segmentedControl.selectedSegmentIndex = 0
        
        if let categoryId = categoryId {
            filteredTasks = tasks.filter { $0.categoryId == categoryId }
        } else {
            filteredTasks = tasks
        }
        
        updateEmptyState()
        tableView.reloadData()
    }
}

// MARK: - UITableViewDataSource
extension TaskListViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return filteredTasks.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "TaskCell", for: indexPath) as! TaskCell
        let task = filteredTasks[indexPath.row]
        cell.configure(with: task)
        return cell
    }
}

// MARK: - UITableViewDelegate
extension TaskListViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        
        let task = filteredTasks[indexPath.row]
        let detailVC = TaskDetailViewController(task: task)
        navigationController?.pushViewController(detailVC, animated: true)
    }
    
    func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let task = filteredTasks[indexPath.row]
        
        // 删除操作
        let deleteAction = UIContextualAction(style: .destructive, title: "删除") { [weak self] _, _, completion in
            guard let self = self else { return }
            
            // 显示确认对话框
            let alert = UIAlertController(title: "确认删除", message: "确定要删除任务"\(task.title)"吗？", preferredStyle: .alert)
            
            let cancelAction = UIAlertAction(title: "取消", style: .cancel) { _ in
                completion(false)
            }
            
            let confirmAction = UIAlertAction(title: "删除", style: .destructive) { _ in
                UserDefaultsManager.shared.deleteTask(withId: task.id)
                self.loadTasks()
                completion(true)
            }
            
            alert.addAction(cancelAction)
            alert.addAction(confirmAction)
            
            self.present(alert, animated: true)
        }
        
        // 完成/取消完成操作
        let completionTitle = task.isCompleted ? "取消完成" : "完成"
        let completionAction = UIContextualAction(style: .normal, title: completionTitle) { [weak self] _, _, completion in
            guard let self = self else { return }
            
            var updatedTask = task
            updatedTask.isCompleted = !task.isCompleted
            updatedTask.modificationDate = Date()
            
            UserDefaultsManager.shared.saveTask(updatedTask)
            self.loadTasks()
            completion(true)
        }
        completionAction.backgroundColor = task.isCompleted ? .systemOrange : .systemGreen
        
        // 编辑操作
        let editAction = UIContextualAction(style: .normal, title: "编辑") { [weak self] _, _, completion in
            guard let self = self else { return }
            
            let taskFormVC = TaskFormViewController(task: task)
            taskFormVC.delegate = self
            let navController = UINavigationController(rootViewController: taskFormVC)
            self.present(navController, animated: true)
            completion(true)
        }
        editAction.backgroundColor = .systemBlue
        
        return UISwipeActionsConfiguration(actions: [deleteAction, completionAction, editAction])
    }
}

// MARK: - TaskFormViewControllerDelegate
extension TaskListViewController: TaskFormViewControllerDelegate {
    func taskFormViewController(_ controller: TaskFormViewController, didSaveTask task: Task) {
        UserDefaultsManager.shared.saveTask(task)
        loadTasks()
        dismiss(animated: true)
    }
    
    func taskFormViewControllerDidCancel(_ controller: TaskFormViewController) {
        dismiss(animated: true)
    }
}

// MARK: - 任务单元格
class TaskCell: UITableViewCell {
    
    // MARK: - UI组件
    
    private let titleLabel: UILabel = {
        let label = UILabel()
        label.font = UIFont.systemFont(ofSize: 17, weight: .medium)
        label.numberOfLines = 1
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let detailLabel: UILabel = {
        let label = UILabel()
        label.font = UIFont.systemFont(ofSize: 14)
        label.textColor = .secondaryLabel
        label.numberOfLines = 2
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let dueDateLabel: UILabel = {
        let label = UILabel()
        label.font = UIFont.systemFont(ofSize: 12)
        label.textColor = .tertiaryLabel
        label.textAlignment = .right
        label.translatesAutoresizingMaskIntoConstraints = false
        return label
    }()
    
    private let priorityIndicator: UIView = {
        let view = UIView()
        view.layer.cornerRadius = 4
        view.translatesAutoresizingMaskIntoConstraints = false
        return view
    }()
    
    private let checkmarkImageView: UIImageView = {
        let imageView = UIImageView()
        imageView.contentMode = .scaleAspectFit
        imageView.tintColor = .systemGreen
        imageView.translatesAutoresizingMaskIntoConstraints = false
        return imageView
    }()
    
    // MARK: - 初始化
    
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupUI()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    // MARK: - UI设置
    
    private func setupUI() {
        accessoryType = .disclosureIndicator
        
        contentView.addSubview(priorityIndicator)
        contentView.addSubview(titleLabel)
        contentView.addSubview(detailLabel)
        contentView.addSubview(dueDateLabel)
        contentView.addSubview(checkmarkImageView)
        
        NSLayoutConstraint.activate([
            priorityIndicator.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            priorityIndicator.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            priorityIndicator.widthAnchor.constraint(equalToConstant: 8),
            priorityIndicator.heightAnchor.constraint(equalToConstant: 36),
            
            titleLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            titleLabel.leadingAnchor.constraint(equalTo: priorityIndicator.trailingAnchor, constant: 12),
            titleLabel.trailingAnchor.constraint(equalTo: checkmarkImageView.leadingAnchor, constant: -12),
            
            detailLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            detailLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            detailLabel.trailingAnchor.constraint(equalTo: dueDateLabel.leadingAnchor, constant: -8),
            detailLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12),
            
            dueDateLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12),
            dueDateLabel.trailingAnchor.constraint(equalTo: checkmarkImageView.leadingAnchor, constant: -12),
            dueDateLabel.widthAnchor.constraint(lessThanOrEqualToConstant: 120),
            
            checkmarkImageView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            checkmarkImageView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -32),
            checkmarkImageView.widthAnchor.constraint(equalToConstant: 24),
            checkmarkImageView.heightAnchor.constraint(equalToConstant: 24)
        ])
    }
    
    // MARK: - 配置
    
    func configure(with task: Task) {
        // 设置标题
        if task.isCompleted {
            let attributedString = NSAttributedString(
                string: task.title,
                attributes: [.strikethroughStyle: NSUnderlineStyle.single.rawValue]
            )
            titleLabel.attributedText = attributedString
            titleLabel.textColor = .secondaryLabel
        } else {
            titleLabel.attributedText = nil
            titleLabel.text = task.title
            titleLabel.textColor = .label
        }
        
        // 设置详情
        detailLabel.text = task.description
        
        // 设置优先级指示器颜色
        priorityIndicator.backgroundColor = task.priority.color
        
        // 设置截止日期
        if let formattedDate = task.formattedDueDate() {
            dueDateLabel.text = formattedDate
            
            // 设置过期任务的样式
            if task.isOverdue && !task.isCompleted {
                dueDateLabel.textColor = .systemRed
            } else {
                dueDateLabel.textColor = .tertiaryLabel
            }
        } else {
            dueDateLabel.text = nil
        }
        
        // 设置完成状态图标
        checkmarkImageView.image = task.isCompleted ? 
            UIImage(systemName: "checkmark.circle.fill") : 
            UIImage(systemName: "circle")
    }
    
    override func prepareForReuse() {
        super.prepareForReuse()
        titleLabel.attributedText = nil
        titleLabel.text = nil
        detailLabel.text = nil
        dueDateLabel.text = nil
        checkmarkImageView.image = nil
    }
}
```

### 任务详情界面

任务详情界面展示了单个任务的详细信息。

1. **基本用法**

```swift
let detailView = UIView()
let titleLabel = UILabel()
let descriptionLabel = UILabel()
let dueDateLabel = UILabel()
let priorityLabel = UILabel()
let isCompletedLabel = UILabel()

detailView.addSubview(titleLabel)
detailView.addSubview(descriptionLabel)
detailView.addSubview(dueDateLabel)
detailView.addSubview(priorityLabel)
detailView.addSubview(isCompletedLabel)

titleLabel.translatesAutoresizingMaskIntoConstraints = false
descriptionLabel.translatesAutoresizingMaskIntoConstraints = false
dueDateLabel.translatesAutoresizingMaskIntoConstraints = false
priorityLabel.translatesAutoresizingMaskIntoConstraints = false
isCompletedLabel.translatesAutoresizingMaskIntoConstraints = false

NSLayoutConstraint.activate([
    titleLabel.topAnchor.constraint(equalTo: detailView.topAnchor, constant: 16),
    titleLabel.leadingAnchor.constraint(equalTo: detailView.leadingAnchor, constant: 16),
    titleLabel.trailingAnchor.constraint(equalTo: detailView.trailingAnchor, constant: -16),

    descriptionLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
    descriptionLabel.leadingAnchor.constraint(equalTo: detailView.leadingAnchor, constant: 16),
    descriptionLabel.trailingAnchor.constraint(equalTo: detailView.trailingAnchor, constant: -16),

    dueDateLabel.topAnchor.constraint(equalTo: descriptionLabel.bottomAnchor, constant: 8),
    dueDateLabel.leadingAnchor.constraint(equalTo: detailView.leadingAnchor, constant: 16),
    dueDateLabel.trailingAnchor.constraint(equalTo: detailView.trailingAnchor, constant: -16),

    priorityLabel.topAnchor.constraint(equalTo: dueDateLabel.bottomAnchor, constant: 8),
    priorityLabel.leadingAnchor.constraint(equalTo: detailView.leadingAnchor, constant: 16),
    priorityLabel.trailingAnchor.constraint(equalTo: detailView.trailingAnchor, constant: -16),

    isCompletedLabel.topAnchor.constraint(equalTo: priorityLabel.bottomAnchor, constant: 8),
    isCompletedLabel.leadingAnchor.constraint(equalTo: detailView.leadingAnchor, constant: 16),
    isCompletedLabel.trailingAnchor.constraint(equalTo: detailView.trailingAnchor, constant: -16),
    isCompletedLabel.bottomAnchor.constraint(equalTo: detailView.bottomAnchor, constant: -16)
])
```

2. **数据源实现**

```swift
extension TaskDetailViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return 1 // 假设只有一个任务详情行
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "TaskDetailCell", for: indexPath)
        cell.textLabel?.text = task.title
        cell.detailTextLabel?.text = task.description
        return cell
    }
}
```

### 任务创建/编辑界面

任务创建/编辑界面允许用户创建或编辑一个任务。

1. **基本用法**

```swift
let formView = UIView()
let titleTextField = UITextField()
let descriptionTextField = UITextField()
let dueDatePicker = UIDatePicker()
let priorityPicker = UIPickerView()
let categoryPicker = UIPickerView()
let saveButton = UIButton()

formView.addSubview(titleTextField)
formView.addSubview(descriptionTextField)
formView.addSubview(dueDatePicker)
formView.addSubview(priorityPicker)
formView.addSubview(categoryPicker)
formView.addSubview(saveButton)

titleTextField.translatesAutoresizingMaskIntoConstraints = false
descriptionTextField.translatesAutoresizingMaskIntoConstraints = false
dueDatePicker.translatesAutoresizingMaskIntoConstraints = false
priorityPicker.translatesAutoresizingMaskIntoConstraints = false
categoryPicker.translatesAutoresizingMaskIntoConstraints = false
saveButton.translatesAutoresizingMaskIntoConstraints = false

NSLayoutConstraint.activate([
    titleTextField.topAnchor.constraint(equalTo: formView.topAnchor, constant: 16),
    titleTextField.leadingAnchor.constraint(equalTo: formView.leadingAnchor, constant: 16),
    titleTextField.trailingAnchor.constraint(equalTo: formView.trailingAnchor, constant: -16),

    descriptionTextField.topAnchor.constraint(equalTo: titleTextField.bottomAnchor, constant: 8),
    descriptionTextField.leadingAnchor.constraint(equalTo: formView.leadingAnchor, constant: 16),
    descriptionTextField.trailingAnchor.constraint(equalTo: formView.trailingAnchor, constant: -16),

    dueDatePicker.topAnchor.constraint(equalTo: descriptionTextField.bottomAnchor, constant: 8),
    dueDatePicker.leadingAnchor.constraint(equalTo: formView.leadingAnchor, constant: 16),
    dueDatePicker.trailingAnchor.constraint(equalTo: formView.trailingAnchor, constant: -16),

    priorityPicker.topAnchor.constraint(equalTo: dueDatePicker.bottomAnchor, constant: 8),
    priorityPicker.leadingAnchor.constraint(equalTo: formView.leadingAnchor, constant: 16),
    priorityPicker.trailingAnchor.constraint(equalTo: formView.trailingAnchor, constant: -16),

    categoryPicker.topAnchor.constraint(equalTo: priorityPicker.bottomAnchor, constant: 8),
    categoryPicker.leadingAnchor.constraint(equalTo: formView.leadingAnchor, constant: 16),
    categoryPicker.trailingAnchor.constraint(equalTo: formView.trailingAnchor, constant: -16),

    saveButton.topAnchor.constraint(equalTo: categoryPicker.bottomAnchor, constant: 16),
    saveButton.leadingAnchor.constraint(equalTo: formView.leadingAnchor, constant: 16),
    saveButton.trailingAnchor.constraint(equalTo: formView.trailingAnchor, constant: -16),
    saveButton.bottomAnchor.constraint(equalTo: formView.bottomAnchor, constant: -16)
])
```

2. **数据源实现**

```swift
extension TaskFormViewController: UIPickerViewDataSource {
    func numberOfComponents(in pickerView: UIPickerView) -> Int {
        return 1 // 假设只有一个组件
    }
    
    func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
        if pickerView == priorityPicker {
            return Priority.allCases.count
        } else if pickerView == categoryPicker {
            return categories.count
        }
        return 0
    }
}

extension TaskFormViewController: UIPickerViewDelegate {
    func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
        if pickerView == priorityPicker {
            return Priority.allCases[row].title
        } else if pickerView == categoryPicker {
            return categories[row].name
        }
        return nil
    }
    
    func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
        if pickerView == priorityPicker {
            task.priority = Priority.allCases[row]
        } else if pickerView == categoryPicker {
            task.categoryId = categories[row].id
        }
    }
}
```

### 设置界面

设置界面允许用户配置应用的设置选项。

1. **基本用法**

```swift
let settingsView = UIView()
let defaultViewSegmentedControl = UISegmentedControl()
let themeSegmentedControl = UISegmentedControl()
let notificationSwitch = UISwitch()

settingsView.addSubview(defaultViewSegmentedControl)
settingsView.addSubview(themeSegmentedControl)
settingsView.addSubview(notificationSwitch)

defaultViewSegmentedControl.translatesAutoresizingMaskIntoConstraints = false
themeSegmentedControl.translatesAutoresizingMaskIntoConstraints = false
notificationSwitch.translatesAutoresizingMaskIntoConstraints = false

NSLayoutConstraint.activate([
    defaultViewSegmentedControl.topAnchor.constraint(equalTo: settingsView.topAnchor, constant: 16),
    defaultViewSegmentedControl.leadingAnchor.constraint(equalTo: settingsView.leadingAnchor, constant: 16),
    defaultViewSegmentedControl.trailingAnchor.constraint(equalTo: settingsView.trailingAnchor, constant: -16),

    themeSegmentedControl.topAnchor.constraint(equalTo: defaultViewSegmentedControl.bottomAnchor, constant: 8),
    themeSegmentedControl.leadingAnchor.constraint(equalTo: settingsView.leadingAnchor, constant: 16),
    themeSegmentedControl.trailingAnchor.constraint(equalTo: settingsView.trailingAnchor, constant: -16),

    notificationSwitch.topAnchor.constraint(equalTo: themeSegmentedControl.bottomAnchor, constant: 8),
    notificationSwitch.leadingAnchor.constraint(equalTo: settingsView.leadingAnchor, constant: 16),
    notificationSwitch.trailingAnchor.constraint(equalTo: settingsView.trailingAnchor, constant: -16),
    notificationSwitch.bottomAnchor.constraint(equalTo: settingsView.bottomAnchor, constant: -16)
])
```

2. **数据源实现**

```swift
extension SettingsViewController: UIPickerViewDataSource {
    func numberOfComponents(in pickerView: UIPickerView) -> Int {
        return 1 // 假设只有一个组件
    }
    
    func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
        if pickerView == defaultViewSegmentedControl {
            return defaultViewOptions.count
        } else if pickerView == themeSegmentedControl {
            return themeOptions.count
        }
        return 0
    }
}

extension SettingsViewController: UIPickerViewDelegate {
    func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
        if pickerView == defaultViewSegmentedControl {
            return defaultViewOptions[row]
        } else if pickerView == themeSegmentedControl {
            return themeOptions[row]
        }
        return nil
    }
    
    func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
        if pickerView == defaultViewSegmentedControl {
            selectedDefaultView = DefaultViewOptions(rawValue: row)
        } else if pickerView == themeSegmentedControl {
            selectedTheme = themeOptions[row]
        }
    }
}
```

## 功能实现

功能实现是应用开发中的重要环节，它确保了应用的核心功能能够被正确地实现。在本项目中，我们将介绍如何实现任务CRUD操作、任务分类与筛选、任务提醒与通知和数据同步。

### 任务CRUD操作

任务CRUD操作是指创建、读取、更新和删除任务的操作。

1. **创建任务**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let task = Task(context: context)
task.title = "新任务"
task.description = "这是一个新任务的描述"
task.dueDate = Date()
task.priority = .medium
task.isCompleted = false
task.creationDate = Date()
task.modificationDate = Date()
task.categoryId = UUID()
task.reminderDate = Date()

try? context.save()
```

2. **读取任务**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let fetchRequest: NSFetchRequest<Task> = Task.fetchRequest()

do {
    let tasks = try context.fetch(fetchRequest)
    self.tasks = tasks
} catch {
    print("无法加载任务: \(error)")
}
```

3. **更新任务**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let task = tasks[indexPath.row]
task.title = "更新后的任务标题"
task.description = "更新后的任务描述"
task.dueDate = Date()
task.priority = .high
task.isCompleted = true
task.modificationDate = Date()

try? context.save()
```

4. **删除任务**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let task = tasks[indexPath.row]
context.delete(task)

try? context.save()
```

### 任务分类与筛选

任务分类与筛选是指根据任务的分类或属性对任务进行分类和筛选的操作。

1. **分类任务**

```swift
let categorizedTasks = DataRelationship.tasksByCategory(tasks: tasks, categories: categories)
```

2. **筛选任务**

```swift
let filteredTasks = tasks.filter { $0.isCompleted }
```

### 任务提醒与通知

任务提醒与通知是指在任务的截止日期或提醒日期向用户发送通知的操作。

1. **设置本地通知**

```swift
let content = UNMutableNotificationContent()
content.title = "任务提醒"
content.body = "你有一个任务即将到期"
content.sound = UNNotificationSound.default

let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 5, repeats: false)

let request = UNNotificationRequest(identifier: "taskReminder", content: content, trigger: trigger)

UNUserNotificationCenter.current().add(request)
```

2. **接收本地通知**

```swift
func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
    // 处理通知响应
    completionHandler()
}
```

### 数据同步

数据同步是指将应用的数据在不同设备之间进行同步的操作。

1. **实现云同步**

```swift
let cloudKitManager = CloudKitManager()

func saveTask(_ task: Task) {
    cloudKitManager.saveTask(task)
}

func loadTasks() {
    cloudKitManager.loadTasks { tasks in
        self.tasks = tasks
        self.tableView.reloadData()
    }
}
```

2. **实现iCloud同步**

```swift
let iCloudManager = iCloudManager()

func saveTask(_ task: Task) {
    iCloudManager.saveTask(task)
}

func loadTasks() {
    iCloudManager.loadTasks { tasks in
        self.tasks = tasks
        self.tableView.reloadData()
    }
}
```

## 高级功能

高级功能是应用开发中的重要环节，它确保了应用的额外功能能够被正确地实现。在本项目中，我们将介绍如何实现拖拽排序、搜索功能、统计分析和主题切换。

### 拖拽排序

拖拽排序是指允许用户通过拖拽任务来改变任务的顺序的操作。

1. **实现拖拽排序**

```swift
let tableView = UITableView()
tableView.dataSource = self
tableView.delegate = self
```

2. **数据源实现**

```swift
extension TaskListViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, canMoveRowAt indexPath: IndexPath) -> Bool {
        return true
    }
    
    func tableView(_ tableView: UITableView, moveRowAt sourceIndexPath: IndexPath, to destinationIndexPath: IndexPath) {
        let movedTask = tasks[sourceIndexPath.row]
        tasks.remove(at: sourceIndexPath.row)
        tasks.insert(movedTask, at: destinationIndexPath.row)
    }
}
```

### 搜索功能

搜索功能是指允许用户通过输入关键词来搜索任务的操作。

1. **实现搜索功能**

```swift
let searchBar = UISearchBar()
searchBar.delegate = self
```

2. **委托实现**

```swift
extension TaskListViewController: UISearchBarDelegate {
    func searchBar(_ searchBar: UISearchBar, textDidChange searchText: String) {
        if searchText.isEmpty {
            tasks = originalTasks
        } else {
            tasks = originalTasks.filter { $0.title.contains(searchText) }
        }
        tableView.reloadData()
    }
}
```

### 统计分析

统计分析是指对应用的数据进行分析和统计的操作。

1. **实现统计分析**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let fetchRequest: NSFetchRequest<Task> = Task.fetchRequest()

do {
    let tasks = try context.fetch(fetchRequest)
    let completedTasks = tasks.filter { $0.isCompleted }
    let totalTasks = tasks.count
    let completionRate = (Double(completedTasks.count) / Double(totalTasks)) * 100
    print("任务完成率: \(completionRate)%")
} catch {
    print("无法加载任务: \(error)")
}
```

### 主题切换

主题切换是指允许用户在应用中切换主题的操作。

1. **实现主题切换**

```swift
let themeManager = ThemeManager()

func switchTheme() {
    themeManager.switchTheme()
    // 重新加载UI
}
```

## 测试

测试是应用开发中的重要环节，它确保了应用的功能能够被正确地测试。在本项目中，我们将介绍如何实现单元测试和UI测试。

### 单元测试

单元测试是指对应用的单个功能进行测试的操作。

1. **实现单元测试**

```swift
import XCTest

class TaskListViewControllerTests: XCTestCase {
    func testLoadTasks() {
        let viewController = TaskListViewController()
        viewController.loadTasks()
        XCTAssertEqual(viewController.tasks.count, 0, "预期加载的任务数量为0")
    }
}
```

2. **运行单元测试**

```bash
xcodebuild test -project TaskMaster.xcodeproj -scheme TaskMasterTests
```

### UI测试

UI测试是指对应用的UI进行测试的操作。

1. **实现UI测试**

```swift
import XCTest

class TaskListViewControllerTests: XCTestCase {
    func testInitialState() {
        let viewController = TaskListViewController()
        XCTAssertEqual(viewController.tasks.count, 0, "预期初始任务数量为0")
    }
}
```

2. **运行UI测试**

```bash
xcodebuild test -project TaskMaster.xcodeproj -scheme TaskMasterUITests
```

## 调试与优化

调试与优化是应用开发中的重要环节，它确保了应用的性能和稳定性。在本项目中，我们将介绍如何实现常见问题排查、性能优化和内存管理。

### 常见问题排查

常见问题排查是指在应用开发过程中遇到的问题进行排查和解决的操作。

1. **实现常见问题排查**

```swift
func handleError(_ error: Error) {
    print("发生错误: \(error)")
}
```

2. **使用调试工具**

```bash
lldb
```

### 性能优化

性能优化是指对应用的性能进行优化和提升的操作。

1. **实现性能优化**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let fetchRequest: NSFetchRequest<Task> = Task.fetchRequest()

do {
    let tasks = try context.fetch(fetchRequest)
    let optimizedTasks = tasks.filter { $0.isCompleted }
    self.tasks = optimizedTasks
} catch {
    print("无法加载任务: \(error)")
}
```

2. **使用性能调试工具**

```bash
instruments -t "Time Profiler"
```

### 内存管理

内存管理是指对应用的内存使用进行管理和优化操作。

1. **实现内存管理**

```swift
let context = (UIApplication.shared.delegate as! AppDelegate).persistentContainer.viewContext
let fetchRequest: NSFetchRequest<Task> = Task.fetchRequest()

do {
    let tasks = try context.fetch(fetchRequest)
    let optimizedTasks = tasks.filter { $0.isCompleted }
    self.tasks = optimizedTasks
} catch {
    print("无法加载任务: \(error)")
}
```

2. **使用内存调试工具**

```bash
instruments -t "Allocations"
```

## 应用发布

应用发布是应用开发中的重要环节，它确保了应用能够被正确地发布和上架。在本项目中，我们将介绍如何实现应用图标和启动页面、应用截图准备、TestFlight测试和App Store提交。

### App Icon与启动页面

App Icon与启动页面是指应用的图标和启动页面。

1. **实现App Icon与启动页面**

```swift
let appIcon = UIImage(named: "AppIcon")
let launchScreen = UIImage(named: "LaunchScreen")
```

2. **使用设计工具**

```bash
sketch
```

### 应用截图准备

应用截图准备是指为应用准备截图的操作。

1. **实现应用截图准备**

```bash
fastlane snapshot
```

2. **使用截图工具**

```bash
screencapture -i -R 100,100,800,1200
```

### TestFlight测试

TestFlight测试是指对应用进行TestFlight测试的操作。

1. **实现TestFlight测试**

```bash
fastlane pilot
```

2. **使用TestFlight工具**

```bash
testflight
```

### App Store提交

App Store提交是指将应用提交到App Store的操作。

1. **实现App Store提交**

```bash
fastlane deliver
```

2. **使用App Store工具**

```bash
appstore
```

## 扩展与改进

扩展与改进是应用开发中的重要环节，它确保了应用能够被正确地扩展和改进。在本项目中，我们将介绍如何实现iPad适配、添加Widget、iCloud同步和Siri集成。

### iPad适配

iPad适配是指对应用进行iPad适配的操作。

1. **实现iPad适配**

```swift
let window = UIWindow(frame: UIScreen.main.bounds)
window.rootViewController = TaskListViewController()
window.makeKeyAndVisible()
```

2. **使用iPad布局**

```bash
sketch
```

### 添加Widget

添加Widget是指为应用添加Widget的操作。

1. **实现添加Widget**

```swift
let widget = Widget()
```

2. **使用Widget工具**

```bash
sketch
```

### iCloud同步

iCloud同步是指将应用的数据同步到iCloud的操作。

1. **实现iCloud同步**

```swift
let iCloudManager = iCloudManager()

func saveTask(_ task: Task) {
    iCloudManager.saveTask(task)
}

func loadTasks() {
    iCloudManager.loadTasks { tasks in
        self.tasks = tasks
        self.tableView.reloadData()
    }
}
```

2. **使用iCloud工具**

```bash
xcodebuild -scheme TaskMaster -archivePath "TaskMaster.xcarchive" -exportArchive -exportOptionsPlist "TaskMasterExportOptions.plist" -exportPath "/Users/yourusername/Desktop"
```

### Siri集成

Siri集成是指将应用集成到Siri的操作。

1. **实现Siri集成**

```swift
let siriManager = SiriManager()

func handleSiriIntent(_ intent: INIntent) {
    siriManager.handleSiriIntent(intent)
}
```

2. **使用Siri工具**

```bash
xcodebuild -scheme TaskMaster -archivePath "TaskMaster.xcarchive" -exportArchive -exportOptionsPlist "TaskMasterExportOptions.plist" -exportPath "/Users/yourusername/Desktop"
```

## 参考资源

参考资源是应用开发中的重要环节，它确保了应用开发过程中能够正确地使用和参考相关资源。在本项目中，我们将介绍如何正确地使用和参考相关资源。

1. **使用官方文档**

```bash
open https://developer.apple.com/documentation/
```

2. **使用第三方库**

```bash
open https://cocoapods.org/
```

3. **使用在线资源**

```bash
open https://stackoverflow.com/
```

4. **使用社区资源**

```bash
open https://developer.apple.com/forums/
```

通过完成这个项目，你将掌握：
- iOS应用开发的完整流程
- Swift语言的实际应用
- 数据持久化的多种方案
- iOS用户界面设计与实现
- 本地通知的处理
- 性能优化与调试技巧
- 应用上架的完整流程

无论你是初学者还是有一定经验的开发者，这个教程都将提供有价值的实践经验和技术深度，帮助你提升iOS开发技能。
