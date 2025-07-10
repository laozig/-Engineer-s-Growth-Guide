# MVVM 架构模式 - 视图模型分离模式

MVVM (Model-View-ViewModel) 是 iOS 应用开发中广泛使用的架构模式，特别适合与 SwiftUI 和现代 iOS 开发实践配合使用。本教程将全面介绍 MVVM 的核心概念、优势，以及在 iOS 项目中的实现方法，帮助开发者构建高质量、易维护的应用程序。

## 目录

- [MVVM 基础概念](#mvvm-基础概念)
  - [MVVM 的定义与起源](#mvvm-的定义与起源)
  - [MVVM 的核心原则](#mvvm-的核心原则)
- [MVVM 组件详解](#mvvm-组件详解)
  - [模型 (Model)](#模型-model)
  - [视图 (View)](#视图-view)
  - [视图模型 (ViewModel)](#视图模型-viewmodel)
  - [组件间的通信](#组件间的通信)
- [MVVM 的优势](#mvvm-的优势)
- [在 UIKit 中实现 MVVM](#在-uikit-中实现-mvvm)
  - [使用闭包实现数据绑定](#使用闭包实现数据绑定)
  - [使用 Combine 框架](#使用-combine-框架)
  - [完整示例：待办事项应用](#完整示例待办事项应用-uikit)
- [在 SwiftUI 中实现 MVVM](#在-swiftui-中实现-mvvm)
  - [使用 ObservableObject 协议](#使用-observableobject-协议)
  - [状态管理与数据流](#状态管理与数据流)
  - [完整示例：天气应用](#完整示例天气应用-swiftui)
- [MVVM 与其他架构的比较](#mvvm-与其他架构的比较)
  - [MVVM vs MVC](#mvvm-vs-mvc)
  - [MVVM vs MVP](#mvvm-vs-mvp)
  - [MVVM vs VIPER](#mvvm-vs-viper)
  - [MVVM vs Clean Architecture](#mvvm-vs-clean-architecture)
- [MVVM 最佳实践](#mvvm-最佳实践)
  - [ViewModel 设计原则](#viewmodel-设计原则)
  - [依赖注入](#依赖注入)
  - [单元测试](#单元测试)
  - [反模式与注意事项](#反模式与注意事项)
- [常见问题与解决方案](#常见问题与解决方案)
- [实战案例分析](#实战案例分析)
- [总结与展望](#总结与展望)
- [参考资源](#参考资源)

## MVVM 基础概念

### MVVM 的定义与起源

MVVM 是一种将应用程序逻辑与用户界面明确分离的软件架构模式。它通过引入 ViewModel 作为 Model 和 View 之间的中介层，实现关注点分离，提高代码的可测试性和可维护性。

MVVM 最初由微软的 WPF (Windows Presentation Foundation) 和 Silverlight 架构师 John Gossman 在 2005 年提出，随后被广泛应用于各种前端和移动应用开发中。在 iOS 开发领域，MVVM 的普及与 Swift 语言的发展、响应式编程框架（如 RxSwift、Combine）和声明式 UI 框架（如 SwiftUI）的兴起紧密相连。

### MVVM 的核心原则

MVVM 建立在以下核心原则基础上：

1. **关注点分离**：将应用程序划分为数据模型、界面展示和业务逻辑三个不同的关注点
2. **数据绑定**：通过数据绑定机制，实现 ViewModel 和 View 之间的自动同步
3. **状态驱动**：View 的状态和行为由 ViewModel 驱动，而不是直接操作 UI 元素
4. **可测试性**：业务逻辑和展示逻辑位于 ViewModel 中，可以独立于 UI 进行测试
5. **可重用性**：同一 ViewModel 可以用于不同的视图，提高代码复用

## MVVM 组件详解

MVVM 架构包含三个核心组件：Model、View 和 ViewModel。下面详细介绍每个组件的职责和实现方式。

### 模型 (Model)

Model 表示应用程序的数据和业务逻辑，它应该：

- 封装应用程序的核心数据结构
- 实现与数据源（如网络 API、数据库）的交互
- 包含业务规则和数据验证逻辑
- 独立于 UI 层，不包含任何表现逻辑
- 不直接与 View 或 ViewModel 通信

#### Model 实现示例

```swift
// 数据模型
struct User: Codable, Identifiable {
    let id: String
    let name: String
    let email: String
    let profileImageURL: URL?
    
    // 业务逻辑方法
    func isValidEmail() -> Bool {
        return email.contains("@") && email.contains(".")
    }
    
    func displayName() -> String {
        return name.isEmpty ? email : name
    }
}

// 数据源接口
protocol UserRepository {
    func fetchUser(id: String) async throws -> User
    func updateUser(_ user: User) async throws -> Bool
    func deleteUser(id: String) async throws -> Bool
}

// 网络数据源实现
class RemoteUserRepository: UserRepository {
    private let apiClient: APIClient
    
    init(apiClient: APIClient = APIClient.shared) {
        self.apiClient = apiClient
    }
    
    func fetchUser(id: String) async throws -> User {
        let endpoint = Endpoint.user(id: id)
        return try await apiClient.request(endpoint)
    }
    
    func updateUser(_ user: User) async throws -> Bool {
        let endpoint = Endpoint.updateUser(user)
        let response: APIResponse = try await apiClient.request(endpoint)
        return response.success
    }
    
    func deleteUser(id: String) async throws -> Bool {
        let endpoint = Endpoint.deleteUser(id: id)
        let response: APIResponse = try await apiClient.request(endpoint)
        return response.success
    }
}

// 本地数据源实现
class LocalUserRepository: UserRepository {
    private let database: Database
    
    init(database: Database = Database.shared) {
        self.database = database
    }
    
    func fetchUser(id: String) async throws -> User {
        return try await database.fetch(User.self, id: id)
    }
    
    func updateUser(_ user: User) async throws -> Bool {
        try await database.save(user)
        return true
    }
    
    func deleteUser(id: String) async throws -> Bool {
        try await database.delete(User.self, id: id)
        return true
    }
}

// 用户服务（整合数据源）
class UserService {
    private let remoteRepository: UserRepository
    private let localRepository: UserRepository
    
    init(
        remoteRepository: UserRepository = RemoteUserRepository(),
        localRepository: UserRepository = LocalUserRepository()
    ) {
        self.remoteRepository = remoteRepository
        self.localRepository = localRepository
    }
    
    func getUser(id: String) async throws -> User {
        // 先尝试从本地获取
        do {
            return try await localRepository.fetchUser(id: id)
        } catch {
            // 本地获取失败，从远程获取并缓存到本地
            let user = try await remoteRepository.fetchUser(id: id)
            try? await localRepository.updateUser(user)
            return user
        }
    }
    
    func updateUser(_ user: User) async throws -> Bool {
        // 先更新远程，成功后更新本地
        let success = try await remoteRepository.updateUser(user)
        if success {
            try? await localRepository.updateUser(user)
        }
        return success
    }
}
```

### 视图 (View)

View 负责 UI 的展示和用户交互，它应该：

- 展示数据给用户
- 捕获用户输入并传递给 ViewModel
- 观察 ViewModel 状态变化并更新 UI
- 不包含业务逻辑和数据处理代码
- 尽可能保持"愚蠢"（dumb），专注于 UI 渲染

#### UIKit 中的 View 实现

在 UIKit 中，View 通常由 UIViewController 及其管理的视图层次结构组成：

```swift
class ProfileViewController: UIViewController {
    // ViewModel 引用
    private let viewModel: ProfileViewModel
    
    // UI 组件
    private let nameLabel = UILabel()
    private let emailLabel = UILabel()
    private let profileImageView = UIImageView()
    private let loadingIndicator = UIActivityIndicatorView()
    private let errorLabel = UILabel()
    private let editButton = UIButton(type: .system)
    
    // 初始化方法
    init(viewModel: ProfileViewModel) {
        self.viewModel = viewModel
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    // 视图生命周期方法
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
        viewModel.fetchUserProfile()
    }
    
    // 设置 UI
    private func setupUI() {
        view.backgroundColor = .white
        title = "个人资料"
        
        // 配置 UI 组件
        profileImageView.contentMode = .scaleAspectFill
        profileImageView.clipsToBounds = true
        profileImageView.layer.cornerRadius = 40
        profileImageView.backgroundColor = .lightGray
        
        nameLabel.font = .systemFont(ofSize: 20, weight: .bold)
        emailLabel.font = .systemFont(ofSize: 16)
        emailLabel.textColor = .darkGray
        
        errorLabel.textColor = .red
        errorLabel.numberOfLines = 0
        errorLabel.textAlignment = .center
        errorLabel.isHidden = true
        
        editButton.setTitle("编辑", for: .normal)
        
        // 布局 UI 组件
        let stackView = UIStackView(arrangedSubviews: [
            profileImageView,
            nameLabel,
            emailLabel,
            errorLabel,
            editButton
        ])
        stackView.axis = .vertical
        stackView.spacing = 12
        stackView.alignment = .center
        stackView.translatesAutoresizingMaskIntoConstraints = false
        
        view.addSubview(stackView)
        view.addSubview(loadingIndicator)
        
        NSLayoutConstraint.activate([
            profileImageView.heightAnchor.constraint(equalToConstant: 80),
            profileImageView.widthAnchor.constraint(equalToConstant: 80),
            
            stackView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stackView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stackView.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 20),
            stackView.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -20),
            
            loadingIndicator.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            loadingIndicator.centerYAnchor.constraint(equalTo: view.centerYAnchor)
        ])
        
        loadingIndicator.translatesAutoresizingMaskIntoConstraints = false
    }
    
    // 绑定 ViewModel
    private func bindViewModel() {
        // 设置状态更新回调
        viewModel.onStateChange = { [weak self] state in
            DispatchQueue.main.async {
                self?.updateUI(with: state)
            }
        }
        
        // 设置按钮动作
        editButton.addTarget(self, action: #selector(editButtonTapped), for: .touchUpInside)
    }
    
    // 根据状态更新 UI
    private func updateUI(with state: ProfileViewModel.State) {
        switch state {
        case .loading:
            loadingIndicator.startAnimating()
            nameLabel.isHidden = true
            emailLabel.isHidden = true
            profileImageView.isHidden = true
            editButton.isHidden = true
            errorLabel.isHidden = true
            
        case .loaded(let user):
            loadingIndicator.stopAnimating()
            nameLabel.isHidden = false
            emailLabel.isHidden = false
            profileImageView.isHidden = false
            editButton.isHidden = false
            errorLabel.isHidden = true
            
            nameLabel.text = user.name
            emailLabel.text = user.email
            
            if let imageURL = user.profileImageURL {
                loadImage(from: imageURL)
            }
            
        case .error(let message):
            loadingIndicator.stopAnimating()
            nameLabel.isHidden = true
            emailLabel.isHidden = true
            profileImageView.isHidden = true
            editButton.isHidden = true
            errorLabel.isHidden = false
            
            errorLabel.text = "错误: \(message)"
        }
    }
    
    // 加载图片
    private func loadImage(from url: URL) {
        URLSession.shared.dataTask(with: url) { [weak self] data, _, error in
            guard let data = data, let image = UIImage(data: data) else {
                return
            }
            
            DispatchQueue.main.async {
                self?.profileImageView.image = image
            }
        }.resume()
    }
    
    // 按钮事件处理
    @objc private func editButtonTapped() {
        viewModel.editProfile()
    }
}
```

#### SwiftUI 中的 View 实现

在 SwiftUI 中，View 是结构体，通过声明式语法定义 UI：

```swift
struct ProfileView: View {
    @ObservedObject var viewModel: ProfileViewModel
    
    var body: some View {
        Group {
            switch viewModel.state {
            case .loading:
                ProgressView("加载中...")
                
            case .loaded(let user):
                VStack(alignment: .center, spacing: 16) {
                    if let imageURL = user.profileImageURL {
                        AsyncImage(url: imageURL) { image in
                            image
                                .resizable()
                                .aspectRatio(contentMode: .fill)
                        } placeholder: {
                            Color.gray
                        }
                        .frame(width: 100, height: 100)
                        .clipShape(Circle())
                    } else {
                        Image(systemName: "person.circle.fill")
                            .resizable()
                            .frame(width: 100, height: 100)
                            .foregroundColor(.gray)
                    }
                    
                    Text(user.name)
                        .font(.title2)
                        .fontWeight(.bold)
                    
                    Text(user.email)
                        .font(.body)
                        .foregroundColor(.secondary)
                    
                    Button("编辑资料") {
                        viewModel.editProfile()
                    }
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(8)
                }
                .padding()
                
            case .error(let message):
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 50))
                        .foregroundColor(.red)
                    
                    Text("出错了")
                        .font(.title)
                    
                    Text(message)
                        .multilineTextAlignment(.center)
                        .padding()
                    
                    Button("重试") {
                        viewModel.fetchUserProfile()
                    }
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(8)
                }
            }
        }
        .onAppear {
            if case .loading = viewModel.state {
                viewModel.fetchUserProfile()
            }
        }
    }
}
```

### 视图模型 (ViewModel)

ViewModel 是 MVVM 架构的核心，它负责：

- 从 Model 获取数据并转换为 View 可以直接使用的格式
- 处理视图的展示逻辑（不是视图本身）
- 响应用户交互，更新模型数据
- 管理视图状态
- 不直接引用或依赖具体的 View 实现

#### ViewModel 实现示例

```swift
class ProfileViewModel: ObservableObject {
    // 视图状态枚举
    enum State {
        case loading
        case loaded(User)
        case error(String)
    }
    
    // 依赖服务
    private let userService: UserService
    private let userId: String
    private let navigator: ProfileNavigator
    
    // 状态管理
    // UIKit 使用闭包通知状态变化
    var onStateChange: ((State) -> Void)?
    
    // SwiftUI 使用 @Published 属性
    @Published var state: State = .loading
    
    // 初始化方法
    init(
        userId: String,
        userService: UserService = UserService(),
        navigator: ProfileNavigator = DefaultProfileNavigator()
    ) {
        self.userId = userId
        self.userService = userService
        self.navigator = navigator
    }
    
    // 公共方法：获取用户资料
    func fetchUserProfile() {
        // 更新状态为加载中
        setState(.loading)
        
        Task {
            do {
                let user = try await userService.getUser(id: userId)
                setState(.loaded(user))
            } catch {
                setState(.error(error.localizedDescription))
            }
        }
    }
    
    // 公共方法：编辑用户资料
    func editProfile() {
        guard case .loaded(let user) = state else { return }
        navigator.navigateToEditProfile(user: user)
    }
    
    // 私有方法：设置状态
    private func setState(_ newState: State) {
        // 对于 UIKit，通过闭包通知状态变化
        onStateChange?(newState)
        
        // 对于 SwiftUI，更新 @Published 属性
        Task { @MainActor in
            state = newState
        }
    }
}

// 导航协议
protocol ProfileNavigator {
    func navigateToEditProfile(user: User)
}

// 默认导航实现
class DefaultProfileNavigator: ProfileNavigator {
    func navigateToEditProfile(user: User) {
        // 实现导航逻辑，例如：
        // 1. 在 UIKit 中使用 UINavigationController 导航
        // 2. 在 SwiftUI 中更新路由状态
        print("导航到编辑资料页面")
    }
}
```

### 组件间的通信

MVVM 架构中，组件间通信遵循特定的模式：

1. **View → ViewModel**: 通过方法调用或绑定传递用户操作
   - 用户点击按钮 → View 调用 ViewModel 的方法
   - 用户输入文本 → View 更新绑定到 ViewModel 的属性

2. **ViewModel → View**: 通过数据绑定或状态更新通知 View
   - ViewModel 属性变化 → View 自动更新（通过绑定机制）
   - ViewModel 状态变化 → View 接收通知并更新 UI

3. **ViewModel ↔ Model**: 直接交互
   - ViewModel 调用 Model 的方法获取或更新数据
   - Model 通过回调或异步返回值通知 ViewModel

4. **View ↔ Model**: 不直接通信
   - View 永远不应该直接访问 Model
   - Model 永远不应该直接通知 View

#### 通信流程图

```
┌─────────┐          ┌───────────┐          ┌─────────┐
│         │ 1. 操作  │           │ 3. 调用  │         │
│  View   ├─────────►│ ViewModel ├─────────►│  Model  │
│         │          │           │          │         │
└─────────┘          └───────────┘          └─────────┘
     ▲                     ▲                     │
     │                     │                     │
     │ 2. 更新             │ 4. 返回数据         │
     └─────────────────────┴─────────────────────┘
```

## MVVM 的优势

MVVM 架构模式提供了多方面的优势：

1. **关注点分离**：
   - 将 UI 逻辑、业务逻辑和数据处理明确分离
   - 使代码结构更清晰，职责更明确

2. **可测试性**：
   - ViewModel 不依赖于具体 UI 实现，可以独立测试
   - 业务逻辑和展示逻辑可以通过单元测试验证
   - 减少对 UI 测试的依赖，提高测试效率

3. **代码重用**：
   - 相同的 ViewModel 可以用于不同的视图（如 UIKit 和 SwiftUI）
   - 业务逻辑和数据处理代码可以在不同场景中复用

4. **可维护性**：
   - 代码结构清晰，责任明确，易于维护和扩展
   - 新功能可以更容易地集成到现有架构中
   - 减少代码耦合，降低修改的风险

5. **适应性**：
   - 特别适合复杂的 UI 和交互需求
   - 能够优雅处理状态管理和数据流
   - 对界面变更有较强的适应能力

6. **与现代框架兼容**：
   - 完美适配 SwiftUI 和 Combine 等响应式框架
   - 符合声明式编程范式
   - 支持现代异步编程模型（如 async/await）

## 在 UIKit 中实现 MVVM

在 UIKit 中实现 MVVM 需要手动建立 ViewModel 和 View 之间的数据绑定。下面介绍几种常用的绑定方式和一个完整示例。

### 使用闭包实现数据绑定

闭包是 UIKit 中实现 MVVM 最简单直接的方式，通过闭包回调通知视图状态变化：

```swift
class TaskListViewModel {
    // 模型数据
    private var tasks: [Task] = []
    
    // 用于视图展示的数据
    private(set) var taskViewModels: [TaskCellViewModel] = []
    
    // 状态更新闭包
    var onTasksUpdated: (() -> Void)?
    var onError: ((String) -> Void)?
    
    // 数据源方法
    func numberOfTasks() -> Int {
        return taskViewModels.count
    }
    
    func taskViewModel(at index: Int) -> TaskCellViewModel {
        return taskViewModels[index]
    }
    
    // 加载数据
    func loadTasks() {
        TaskService.shared.fetchTasks { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success(let tasks):
                self.tasks = tasks
                self.taskViewModels = tasks.map { TaskCellViewModel(task: $0) }
                self.onTasksUpdated?()
                
            case .failure(let error):
                self.onError?(error.localizedDescription)
            }
        }
    }
    
    // 添加任务
    func addTask(title: String, priority: Task.Priority) {
        let newTask = Task(id: UUID().uuidString, title: title, priority: priority, isCompleted: false)
        
        TaskService.shared.createTask(newTask) { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success:
                self.tasks.append(newTask)
                self.taskViewModels.append(TaskCellViewModel(task: newTask))
                self.onTasksUpdated?()
                
            case .failure(let error):
                self.onError?(error.localizedDescription)
            }
        }
    }
    
    // 切换任务完成状态
    func toggleTaskCompletion(at index: Int) {
        guard index < tasks.count else { return }
        
        var task = tasks[index]
        task.isCompleted.toggle()
        
        TaskService.shared.updateTask(task) { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success:
                self.tasks[index] = task
                self.taskViewModels[index] = TaskCellViewModel(task: task)
                self.onTasksUpdated?()
                
            case .failure(let error):
                self.onError?(error.localizedDescription)
            }
        }
    }
}

// 在 ViewController 中使用
class TaskListViewController: UIViewController {
    private let tableView = UITableView()
    private let viewModel = TaskListViewModel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
        viewModel.loadTasks()
    }
    
    private func bindViewModel() {
        viewModel.onTasksUpdated = { [weak self] in
            DispatchQueue.main.async {
                self?.tableView.reloadData()
            }
        }
        
        viewModel.onError = { [weak self] message in
            DispatchQueue.main.async {
                let alert = UIAlertController(title: "错误", message: message, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "确定", style: .default))
                self?.present(alert, animated: true)
            }
        }
    }
}
```

### 使用 Combine 框架

从 iOS 13 开始，可以使用 Combine 框架实现更优雅的响应式数据绑定：

```swift
import Combine

class WeatherViewModel {
    // 可发布属性
    @Published var temperature: String = ""
    @Published var location: String = ""
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    
    private var cancellables = Set<AnyCancellable>()
    
    func fetchWeather(for city: String) {
        guard !city.isEmpty else { return }
        
        isLoading = true
        errorMessage = nil
        
        WeatherService.shared.getWeather(for: city)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] completion in
                self?.isLoading = false
                
                if case .failure(let error) = completion {
                    self?.errorMessage = error.localizedDescription
                }
            } receiveValue: { [weak self] weather in
                self?.temperature = "\(weather.temperature)°C"
                self?.location = weather.cityName
            }
            .store(in: &cancellables)
    }
}

// 在 ViewController 中使用
class WeatherViewController: UIViewController {
    private let viewModel = WeatherViewModel()
    private let temperatureLabel = UILabel()
    private let locationLabel = UILabel()
    private let cityTextField = UITextField()
    private let searchButton = UIButton()
    private let activityIndicator = UIActivityIndicatorView()
    private let errorLabel = UILabel()
    
    private var cancellables = Set<AnyCancellable>()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
    }
    
    private func bindViewModel() {
        // 绑定 temperature 到 label
        viewModel.$temperature
            .receive(on: RunLoop.main)
            .sink { [weak self] temperature in
                self?.temperatureLabel.text = temperature
            }
            .store(in: &cancellables)
        
        // 绑定 location 到 label
        viewModel.$location
            .receive(on: RunLoop.main)
            .sink { [weak self] location in
                self?.locationLabel.text = location
            }
            .store(in: &cancellables)
        
        // 绑定 isLoading 到活动指示器
        viewModel.$isLoading
            .receive(on: RunLoop.main)
            .sink { [weak self] isLoading in
                if isLoading {
                    self?.activityIndicator.startAnimating()
                } else {
                    self?.activityIndicator.stopAnimating()
                }
                self?.searchButton.isEnabled = !isLoading
            }
            .store(in: &cancellables)
        
        // 绑定 errorMessage 到错误标签
        viewModel.$errorMessage
            .receive(on: RunLoop.main)
            .sink { [weak self] errorMessage in
                self?.errorLabel.text = errorMessage
                self?.errorLabel.isHidden = errorMessage == nil
            }
            .store(in: &cancellables)
        
        // 设置按钮事件
        searchButton.addTarget(self, action: #selector(searchTapped), for: .touchUpInside)
    }
    
    @objc private func searchTapped() {
        guard let city = cityTextField.text, !city.isEmpty else { return }
        viewModel.fetchWeather(for: city)
        cityTextField.resignFirstResponder()
    }
}
```

### 完整示例：待办事项应用 (UIKit)

下面是一个使用 MVVM 架构的完整待办事项应用示例，展示如何在 UIKit 中实现 MVVM：

#### 模型层

```swift
// 任务模型
struct Task: Codable, Identifiable {
    enum Priority: String, Codable, CaseIterable {
        case low = "低"
        case medium = "中"
        case high = "高"
        
        var color: UIColor {
            switch self {
            case .low: return .systemGreen
            case .medium: return .systemOrange
            case .high: return .systemRed
            }
        }
    }
    
    var id: String
    var title: String
    var description: String?
    var priority: Priority
    var isCompleted: Bool
    var dueDate: Date?
    var createdAt: Date = Date()
}

// 任务服务
class TaskService {
    static let shared = TaskService()
    
    private var tasks: [Task] = []
    
    private init() {
        loadTasksFromDisk()
    }
    
    func fetchTasks(completion: @escaping (Result<[Task], Error>) -> Void) {
        // 模拟网络延迟
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) {
            completion(.success(self.tasks))
        }
    }
    
    func createTask(_ task: Task, completion: @escaping (Result<Void, Error>) -> Void) {
        tasks.append(task)
        saveTasksToDisk()
        completion(.success(()))
    }
    
    func updateTask(_ task: Task, completion: @escaping (Result<Void, Error>) -> Void) {
        if let index = tasks.firstIndex(where: { $0.id == task.id }) {
            tasks[index] = task
            saveTasksToDisk()
            completion(.success(()))
        } else {
            completion(.failure(NSError(domain: "TaskService", code: 404, userInfo: [
                NSLocalizedDescriptionKey: "找不到任务"
            ])))
        }
    }
    
    func deleteTask(id: String, completion: @escaping (Result<Void, Error>) -> Void) {
        tasks.removeAll { $0.id == id }
        saveTasksToDisk()
        completion(.success(()))
    }
    
    private func saveTasksToDisk() {
        if let encoded = try? JSONEncoder().encode(tasks) {
            UserDefaults.standard.set(encoded, forKey: "tasks")
        }
    }
    
    private func loadTasksFromDisk() {
        if let savedTasks = UserDefaults.standard.data(forKey: "tasks"),
           let decodedTasks = try? JSONDecoder().decode([Task].self, from: savedTasks) {
            tasks = decodedTasks
        }
    }
}
```

#### 视图模型层

```swift
// 单个任务的 Cell ViewModel
struct TaskCellViewModel {
    let id: String
    let title: String
    let priorityText: String
    let priorityColor: UIColor
    let isCompleted: Bool
    let dueDateText: String?
    
    init(task: Task) {
        id = task.id
        title = task.title
        priorityText = task.priority.rawValue
        priorityColor = task.priority.color
        isCompleted = task.isCompleted
        
        if let dueDate = task.dueDate {
            let formatter = DateFormatter()
            formatter.dateStyle = .medium
            formatter.timeStyle = .short
            dueDateText = formatter.string(from: dueDate)
        } else {
            dueDateText = nil
        }
    }
}

// 任务列表 ViewModel
class TaskListViewModel {
    enum TaskFilter {
        case all
        case active
        case completed
    }
    
    // 状态
    private var tasks: [Task] = []
    private(set) var filteredTasks: [Task] = []
    private(set) var taskViewModels: [TaskCellViewModel] = []
    private var currentFilter: TaskFilter = .all
    
    // 回调
    var onTasksUpdated: (() -> Void)?
    var onError: ((String) -> Void)?
    
    // 加载数据
    func loadTasks() {
        TaskService.shared.fetchTasks { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success(let tasks):
                self.tasks = tasks
                self.applyFilter()
                
            case .failure(let error):
                self.onError?(error.localizedDescription)
            }
        }
    }
    
    // 应用过滤器
    func applyFilter(_ filter: TaskFilter = .all) {
        currentFilter = filter
        
        switch filter {
        case .all:
            filteredTasks = tasks
        case .active:
            filteredTasks = tasks.filter { !$0.isCompleted }
        case .completed:
            filteredTasks = tasks.filter { $0.isCompleted }
        }
        
        // 更新 cell view models
        taskViewModels = filteredTasks.map { TaskCellViewModel(task: $0) }
        
        // 通知视图更新
        onTasksUpdated?()
    }
    
    // 添加任务
    func addTask(title: String, priority: Task.Priority, dueDate: Date? = nil) {
        let newTask = Task(
            id: UUID().uuidString,
            title: title,
            priority: priority,
            isCompleted: false,
            dueDate: dueDate
        )
        
        TaskService.shared.createTask(newTask) { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success:
                self.tasks.append(newTask)
                self.applyFilter(self.currentFilter)
                
            case .failure(let error):
                self.onError?(error.localizedDescription)
            }
        }
    }
    
    // 切换任务完成状态
    func toggleTaskCompletion(at index: Int) {
        guard index < filteredTasks.count else { return }
        
        let taskId = filteredTasks[index].id
        guard let originalIndex = tasks.firstIndex(where: { $0.id == taskId }) else { return }
        
        var updatedTask = tasks[originalIndex]
        updatedTask.isCompleted.toggle()
        
        TaskService.shared.updateTask(updatedTask) { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success:
                self.tasks[originalIndex] = updatedTask
                self.applyFilter(self.currentFilter)
                
            case .failure(let error):
                self.onError?(error.localizedDescription)
            }
        }
    }
    
    // 删除任务
    func deleteTask(at index: Int) {
        guard index < filteredTasks.count else { return }
        
        let taskId = filteredTasks[index].id
        
        TaskService.shared.deleteTask(id: taskId) { [weak self] result in
            guard let self = self else { return }
            
            switch result {
            case .success:
                if let originalIndex = self.tasks.firstIndex(where: { $0.id == taskId }) {
                    self.tasks.remove(at: originalIndex)
                }
                self.applyFilter(self.currentFilter)
                
            case .failure(let error):
                self.onError?(error.localizedDescription)
            }
        }
    }
    
    // 数据源方法
    func numberOfTasks() -> Int {
        return taskViewModels.count
    }
    
    func taskViewModel(at index: Int) -> TaskCellViewModel {
        return taskViewModels[index]
    }
}
```

#### 视图层

```swift
// 任务单元格
class TaskCell: UITableViewCell {
    static let reuseIdentifier = "TaskCell"
    
    private let titleLabel = UILabel()
    private let priorityLabel = UILabel()
    private let dueDateLabel = UILabel()
    private let checkmarkButton = UIButton(type: .system)
    
    var onToggleCompletion: (() -> Void)?
    
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupUI()
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    private func setupUI() {
        titleLabel.numberOfLines = 1
        titleLabel.font = .systemFont(ofSize: 16)
        
        priorityLabel.font = .systemFont(ofSize: 12)
        priorityLabel.textAlignment = .center
        priorityLabel.layer.cornerRadius = 4
        priorityLabel.clipsToBounds = true
        priorityLabel.textColor = .white
        
        dueDateLabel.font = .systemFont(ofSize: 12)
        dueDateLabel.textColor = .darkGray
        
        checkmarkButton.setImage(UIImage(systemName: "circle"), for: .normal)
        checkmarkButton.addTarget(self, action: #selector(checkmarkTapped), for: .touchUpInside)
        
        contentView.addSubview(checkmarkButton)
        contentView.addSubview(titleLabel)
        contentView.addSubview(priorityLabel)
        contentView.addSubview(dueDateLabel)
        
        checkmarkButton.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        priorityLabel.translatesAutoresizingMaskIntoConstraints = false
        dueDateLabel.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            checkmarkButton.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            checkmarkButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            checkmarkButton.widthAnchor.constraint(equalToConstant: 24),
            checkmarkButton.heightAnchor.constraint(equalToConstant: 24),
            
            titleLabel.leadingAnchor.constraint(equalTo: checkmarkButton.trailingAnchor, constant: 16),
            titleLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            titleLabel.trailingAnchor.constraint(equalTo: priorityLabel.leadingAnchor, constant: -8),
            
            priorityLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            priorityLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            priorityLabel.widthAnchor.constraint(equalToConstant: 40),
            
            dueDateLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            dueDateLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            dueDateLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            dueDateLabel.bottomAnchor.constraint(lessThanOrEqualTo: contentView.bottomAnchor, constant: -12)
        ])
    }
    
    func configure(with viewModel: TaskCellViewModel) {
        titleLabel.text = viewModel.title
        
        if viewModel.isCompleted {
            titleLabel.attributedText = NSAttributedString(
                string: viewModel.title,
                attributes: [.strikethroughStyle: NSUnderlineStyle.single.rawValue]
            )
            checkmarkButton.setImage(UIImage(systemName: "checkmark.circle.fill"), for: .normal)
        } else {
            titleLabel.attributedText = NSAttributedString(string: viewModel.title)
            checkmarkButton.setImage(UIImage(systemName: "circle"), for: .normal)
        }
        
        priorityLabel.text = viewModel.priorityText
        priorityLabel.backgroundColor = viewModel.priorityColor
        
        dueDateLabel.text = viewModel.dueDateText
        dueDateLabel.isHidden = viewModel.dueDateText == nil
    }
    
    @objc private func checkmarkTapped() {
        onToggleCompletion?()
    }
}

// 任务列表控制器
class TaskListViewController: UIViewController {
    private let tableView = UITableView()
    private let addButton = UIBarButtonItem(barButtonSystemItem: .add, target: nil, action: nil)
    private let segmentedControl = UISegmentedControl(items: ["全部", "待办", "已完成"])
    private let viewModel = TaskListViewModel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
        viewModel.loadTasks()
    }
    
    private func setupUI() {
        title = "待办事项"
        view.backgroundColor = .systemBackground
        
        // 配置导航栏
        navigationItem.rightBarButtonItem = addButton
        
        // 配置分段控制器
        segmentedControl.selectedSegmentIndex = 0
        segmentedControl.translatesAutoresizingMaskIntoConstraints = false
        
        // 配置表格视图
        tableView.register(TaskCell.self, forCellReuseIdentifier: TaskCell.reuseIdentifier)
        tableView.delegate = self
        tableView.dataSource = self
        tableView.translatesAutoresizingMaskIntoConstraints = false
        
        // 添加子视图
        view.addSubview(segmentedControl)
        view.addSubview(tableView)
        
        // 设置约束
        NSLayoutConstraint.activate([
            segmentedControl.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 8),
            segmentedControl.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            segmentedControl.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            
            tableView.topAnchor.constraint(equalTo: segmentedControl.bottomAnchor, constant: 8),
            tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
    }
    
    private func bindViewModel() {
        // 绑定表格视图更新
        viewModel.onTasksUpdated = { [weak self] in
            DispatchQueue.main.async {
                self?.tableView.reloadData()
            }
        }
        
        // 绑定错误处理
        viewModel.onError = { [weak self] message in
            DispatchQueue.main.async {
                let alert = UIAlertController(title: "错误", message: message, preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: "确定", style: .default))
                self?.present(alert, animated: true)
            }
        }
        
        // 设置按钮动作
        addButton.target = self
        addButton.action = #selector(addButtonTapped)
        
        // 设置分段控制器动作
        segmentedControl.addTarget(self, action: #selector(filterChanged), for: .valueChanged)
    }
    
    @objc private func addButtonTapped() {
        let alert = UIAlertController(title: "添加任务", message: nil, preferredStyle: .alert)
        
        alert.addTextField { textField in
            textField.placeholder = "任务标题"
        }
        
        alert.addAction(UIAlertAction(title: "取消", style: .cancel))
        alert.addAction(UIAlertAction(title: "添加", style: .default) { [weak self, weak alert] _ in
            guard let title = alert?.textFields?.first?.text, !title.isEmpty else { return }
            self?.viewModel.addTask(title: title, priority: .medium)
        })
        
        present(alert, animated: true)
    }
    
    @objc private func filterChanged() {
        let filter: TaskListViewModel.TaskFilter
        
        switch segmentedControl.selectedSegmentIndex {
        case 0: filter = .all
        case 1: filter = .active
        case 2: filter = .completed
        default: filter = .all
        }
        
        viewModel.applyFilter(filter)
    }
}

// MARK: - UITableViewDataSource
extension TaskListViewController: UITableViewDataSource {
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return viewModel.numberOfTasks()
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        guard let cell = tableView.dequeueReusableCell(withIdentifier: TaskCell.reuseIdentifier, for: indexPath) as? TaskCell else {
            return UITableViewCell()
        }
        
        let taskViewModel = viewModel.taskViewModel(at: indexPath.row)
        cell.configure(with: taskViewModel)
        
        cell.onToggleCompletion = { [weak self] in
            self?.viewModel.toggleTaskCompletion(at: indexPath.row)
        }
        
        return cell
    }
}

// MARK: - UITableViewDelegate
extension TaskListViewController: UITableViewDelegate {
    func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return UITableView.automaticDimension
    }
    
    func tableView(_ tableView: UITableView, estimatedHeightForRowAt indexPath: IndexPath) -> CGFloat {
        return 60
    }
    
    func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let deleteAction = UIContextualAction(style: .destructive, title: "删除") { [weak self] _, _, completion in
            self?.viewModel.deleteTask(at: indexPath.row)
            completion(true)
        }
        
        return UISwipeActionsConfiguration(actions: [deleteAction])
    }
}
```

这个完整示例展示了 MVVM 在 UIKit 中的实现，包括：
- 模型层处理数据和业务逻辑
- 视图模型层处理展示逻辑和状态管理
- 视图层负责 UI 展示和用户交互
- 清晰的数据流和责任分配

## 在 SwiftUI 中实现 MVVM

SwiftUI 天然支持 MVVM 架构模式，通过 `@ObservedObject`、`@StateObject` 和 `@Published` 等属性包装器实现数据绑定。

### 使用 ObservableObject 协议

在 SwiftUI 中，ViewModel 通常实现 `ObservableObject` 协议，并使用 `@Published` 标记需要通知视图更新的属性：

```swift
import SwiftUI
import Combine

class CounterViewModel: ObservableObject {
    @Published var count: Int = 0
    @Published var history: [String] = []
    
    func increment() {
        count += 1
        addToHistory("增加到 \(count)")
    }
    
    func decrement() {
        count -= 1
        addToHistory("减少到 \(count)")
    }
    
    func reset() {
        count = 0
        addToHistory("重置为 0")
    }
    
    private func addToHistory(_ entry: String) {
        let timestamp = DateFormatter.localizedString(
            from: Date(),
            dateStyle: .none,
            timeStyle: .medium
        )
        history.insert("\(timestamp): \(entry)", at: 0)
        
        // 限制历史记录数量
        if history.count > 10 {
            history.removeLast()
        }
    }
}

struct CounterView: View {
    @StateObject private var viewModel = CounterViewModel()
    
    var body: some View {
        VStack(spacing: 20) {
            Text("计数器: \(viewModel.count)")
                .font(.largeTitle)
            
            HStack(spacing: 20) {
                Button("-") {
                    viewModel.decrement()
                }
                .font(.title)
                .padding()
                .background(Color.red)
                .foregroundColor(.white)
                .cornerRadius(10)
                
                Button("重置") {
                    viewModel.reset()
                }
                .font(.title)
                .padding()
                .background(Color.gray)
                .foregroundColor(.white)
                .cornerRadius(10)
                
                Button("+") {
                    viewModel.increment()
                }
                .font(.title)
                .padding()
                .background(Color.green)
                .foregroundColor(.white)
                .cornerRadius(10)
            }
            
            Text("操作历史")
                .font(.headline)
                .padding(.top, 20)
            
            List(viewModel.history, id: \.self) { entry in
                Text(entry)
                    .font(.caption)
            }
            .frame(height: 200)
        }
        .padding()
    }
}
```

### 状态管理与数据流

SwiftUI 中的 MVVM 使用单向数据流，从 ViewModel 到 View 的数据流通过属性绑定实现，从 View 到 ViewModel 的数据流通过方法调用实现：

```swift
class SearchViewModel: ObservableObject {
    // 输入
    @Published var searchQuery: String = ""
    
    // 输出
    @Published var searchResults: [SearchResult] = []
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    
    private var cancellables = Set<AnyCancellable>()
    
    init() {
        setupBindings()
    }
    
    private func setupBindings() {
        // 监听搜索查询变化，自动触发搜索
        $searchQuery
            .debounce(for: .milliseconds(500), scheduler: RunLoop.main) // 防抖动
            .removeDuplicates()
            .filter { !$0.isEmpty }
            .sink { [weak self] query in
                self?.performSearch(query: query)
            }
            .store(in: &cancellables)
    }
    
    func performSearch(query: String) {
        guard !query.isEmpty else {
            searchResults = []
            return
        }
        
        isLoading = true
        errorMessage = nil
        
        // 模拟网络请求
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            DispatchQueue.main.async {
                self.isLoading = false
                
                // 生成模拟结果
                if query.lowercased() == "error" {
                    self.errorMessage = "搜索失败，请重试"
                    self.searchResults = []
                } else {
                    self.searchResults = (1...10).map { index in
                        SearchResult(
                            id: UUID().uuidString,
                            title: "\(query) 结果 #\(index)",
                            description: "关于 \(query) 的详细信息 #\(index)"
                        )
                    }
                }
            }
        }
    }
    
    func clearSearch() {
        searchQuery = ""
        searchResults = []
        errorMessage = nil
    }
}

struct SearchResult: Identifiable {
    let id: String
    let title: String
    let description: String
}

struct SearchView: View {
    @StateObject private var viewModel = SearchViewModel()
    
    var body: some View {
        NavigationView {
            VStack {
                // 搜索框
                TextField("搜索...", text: $viewModel.searchQuery)
                    .padding(8)
                    .background(Color(.systemGray6))
                    .cornerRadius(8)
                    .padding(.horizontal)
                
                if viewModel.isLoading {
                    // 加载中
                    ProgressView("搜索中...")
                        .padding()
                    Spacer()
                } else if let errorMessage = viewModel.errorMessage {
                    // 错误状态
                    VStack {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.largeTitle)
                            .foregroundColor(.red)
                            .padding()
                        
                        Text(errorMessage)
                        
                        Button("重试") {
                            viewModel.performSearch(query: viewModel.searchQuery)
                        }
                        .padding()
                    }
                    .padding()
                    Spacer()
                } else if viewModel.searchResults.isEmpty {
                    // 空结果
                    if !viewModel.searchQuery.isEmpty {
                        Text("未找到结果")
                            .foregroundColor(.secondary)
                            .padding()
                    }
                    Spacer()
                } else {
                    // 搜索结果列表
                    List(viewModel.searchResults) { result in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(result.title)
                                .font(.headline)
                            Text(result.description)
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                        .padding(.vertical, 4)
                    }
                }
            }
            .navigationTitle("搜索")
            .toolbar {
                if !viewModel.searchQuery.isEmpty {
                    Button(action: {
                        viewModel.clearSearch()
                    }) {
                        Image(systemName: "xmark.circle.fill")
                    }
                }
            }
        }
    }
}
```

### 完整示例：天气应用 (SwiftUI)

下面是一个使用 MVVM 架构的完整天气应用示例，展示如何在 SwiftUI 中实现 MVVM：

#### 模型层

```swift
// 天气数据模型
struct WeatherData: Codable, Identifiable {
    var id: String { city.id }
    let city: City
    let current: CurrentWeather
    let forecast: [ForecastDay]
    
    struct City: Codable, Identifiable {
        let id: String
        let name: String
        let country: String
        let coordinates: Coordinates
        
        struct Coordinates: Codable {
            let latitude: Double
            let longitude: Double
        }
    }
    
    struct CurrentWeather: Codable {
        let temperature: Double
        let feelsLike: Double
        let humidity: Int
        let windSpeed: Double
        let condition: Condition
        
        struct Condition: Codable {
            let main: String
            let description: String
            let icon: String
        }
    }
    
    struct ForecastDay: Codable, Identifiable {
        var id: String { date }
        let date: String
        let temperature: Temperature
        let condition: CurrentWeather.Condition
        
        struct Temperature: Codable {
            let min: Double
            let max: Double
        }
    }
}

// 天气服务
class WeatherService {
    static let shared = WeatherService()
    
    func fetchWeather(for cityName: String) -> AnyPublisher<WeatherData, Error> {
        // 模拟网络请求，返回假数据
        return Future<WeatherData, Error> { promise in
            // 延迟1秒模拟网络延迟
            DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
                // 随机决定是否出错（10%概率）
                let shouldFail = Int.random(in: 1...10) == 1
                
                if shouldFail {
                    promise(.failure(NSError(domain: "WeatherService", code: 500, userInfo: [
                        NSLocalizedDescriptionKey: "无法获取天气数据，请重试"
                    ])))
                } else {
                    // 创建假数据
                    let weatherData = WeatherData(
                        city: .init(
                            id: UUID().uuidString,
                            name: cityName,
                            country: "中国",
                            coordinates: .init(latitude: 39.9, longitude: 116.3)
                        ),
                        current: .init(
                            temperature: Double.random(in: 5...30),
                            feelsLike: Double.random(in: 5...30),
                            humidity: Int.random(in: 30...90),
                            windSpeed: Double.random(in: 1...10),
                            condition: .init(
                                main: ["晴朗", "多云", "小雨", "阴天"].randomElement()!,
                                description: "天气描述",
                                icon: "01d"
                            )
                        ),
                        forecast: (1...5).map { day in
                            let date = Calendar.current.date(byAdding: .day, value: day, to: Date())!
                            let dateFormatter = DateFormatter()
                            dateFormatter.dateFormat = "yyyy-MM-dd"
                            
                            return WeatherData.ForecastDay(
                                date: dateFormatter.string(from: date),
                                temperature: .init(
                                    min: Double.random(in: 5...20),
                                    max: Double.random(in: 20...30)
                                ),
                                condition: .init(
                                    main: ["晴朗", "多云", "小雨", "阴天"].randomElement()!,
                                    description: "天气描述",
                                    icon: "01d"
                                )
                            )
                        }
                    )
                    
                    promise(.success(weatherData))
                }
            }
        }
        .eraseToAnyPublisher()
    }
}
```

#### 视图模型层

```swift
class WeatherViewModel: ObservableObject {
    // 输入
    @Published var cityName: String = ""
    
    // 输出
    @Published var state: ViewState = .idle
    
    enum ViewState {
        case idle
        case loading
        case loaded(WeatherData)
        case error(String)
    }
    
    private var cancellables = Set<AnyCancellable>()
    
    func searchWeather() {
        guard !cityName.isEmpty else { return }
        
        state = .loading
        
        WeatherService.shared.fetchWeather(for: cityName)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] completion in
                guard let self = self else { return }
                
                if case .failure(let error) = completion {
                    self.state = .error(error.localizedDescription)
                }
            } receiveValue: { [weak self] weatherData in
                self?.state = .loaded(weatherData)
            }
            .store(in: &cancellables)
    }
    
    func clearSearch() {
        cityName = ""
        state = .idle
    }
}

// 扩展提供便捷访问方法
extension WeatherViewModel {
    var isLoading: Bool {
        if case .loading = state {
            return true
        }
        return false
    }
    
    var errorMessage: String? {
        if case .error(let message) = state {
            return message
        }
        return nil
    }
    
    var weatherData: WeatherData? {
        if case .loaded(let data) = state {
            return data
        }
        return nil
    }
}
```

#### 视图层

```swift
struct WeatherView: View {
    @StateObject private var viewModel = WeatherViewModel()
    @State private var isSearching = false
    
    var body: some View {
        NavigationView {
            Group {
                switch viewModel.state {
                case .idle:
                    // 初始状态
                    welcomeView
                    
                case .loading:
                    // 加载状态
                    ProgressView("获取天气数据中...")
                    
                case .loaded(let weatherData):
                    // 加载完成状态
                    weatherDetailView(data: weatherData)
                    
                case .error(let message):
                    // 错误状态
                    errorView(message: message)
                }
            }
            .navigationTitle("天气预报")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: {
                        isSearching = true
                    }) {
                        Image(systemName: "magnifyingglass")
                    }
                }
                
                if case .loaded = viewModel.state {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button(action: {
                            viewModel.clearSearch()
                        }) {
                            Image(systemName: "house")
                        }
                    }
                }
            }
            .sheet(isPresented: $isSearching) {
                searchView
            }
        }
    }
    
    // 欢迎视图
    private var welcomeView: some View {
        VStack(spacing: 20) {
            Image(systemName: "cloud.sun")
                .font(.system(size: 80))
                .foregroundColor(.blue)
            
            Text("欢迎使用天气应用")
                .font(.title)
            
            Text("请点击右上角搜索按钮查询城市天气")
                .multilineTextAlignment(.center)
                .padding()
            
            Button("搜索城市") {
                isSearching = true
            }
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(10)
        }
        .padding()
    }
    
    // 搜索视图
    private var searchView: some View {
        VStack(spacing: 16) {
            Text("搜索城市")
                .font(.headline)
            
            TextField("输入城市名称", text: $viewModel.cityName)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .autocapitalization(.none)
                .padding(.horizontal)
            
            Button("搜索") {
                viewModel.searchWeather()
                isSearching = false
            }
            .disabled(viewModel.cityName.isEmpty)
            .padding()
            .background(viewModel.cityName.isEmpty ? Color.gray : Color.blue)
            .foregroundColor(.white)
            .cornerRadius(10)
            
            Button("取消") {
                isSearching = false
            }
            .padding()
            
            Spacer()
        }
        .padding()
    }
    
    // 天气详情视图
    private func weatherDetailView(data: WeatherData) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // 城市信息
                HStack {
                    VStack(alignment: .leading) {
                        Text(data.city.name)
                            .font(.largeTitle)
                            .fontWeight(.bold)
                        
                        Text(data.city.country)
                            .font(.title3)
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                    
                    VStack(alignment: .trailing) {
                        Text("\(Int(data.current.temperature))°C")
                            .font(.system(size: 50))
                            .fontWeight(.bold)
                        
                        Text("体感温度: \(Int(data.current.feelsLike))°C")
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }
                .padding()
                .background(Color(.systemBackground))
                .cornerRadius(12)
                .shadow(radius: 2)
                
                // 当前天气详情
                VStack(alignment: .leading, spacing: 12) {
                    Text("当前天气")
                        .font(.headline)
                    
                    HStack {
                        WeatherInfoCard(
                            icon: "humidity",
                            title: "湿度",
                            value: "\(data.current.humidity)%"
                        )
                        
                        Spacer()
                        
                        WeatherInfoCard(
                            icon: "wind",
                            title: "风速",
                            value: "\(String(format: "%.1f", data.current.windSpeed)) m/s"
                        )
                        
                        Spacer()
                        
                        WeatherInfoCard(
                            icon: "thermometer",
                            title: "天气",
                            value: data.current.condition.main
                        )
                    }
                }
                .padding()
                .background(Color(.systemBackground))
                .cornerRadius(12)
                .shadow(radius: 2)
                
                // 预报
                VStack(alignment: .leading, spacing: 12) {
                    Text("未来预报")
                        .font(.headline)
                    
                    ForEach(data.forecast) { day in
                        HStack {
                            Text(formatDate(day.date))
                                .frame(width: 100, alignment: .leading)
                            
                            Spacer()
                            
                            Text(day.condition.main)
                                .frame(width: 80)
                            
                            Spacer()
                            
                            HStack(spacing: 4) {
                                Text("\(Int(day.temperature.min))°")
                                    .foregroundColor(.secondary)
                                Text("-")
                                Text("\(Int(day.temperature.max))°")
                            }
                            .frame(width: 80)
                        }
                        .padding(.vertical, 8)
                        
                        if day.id != data.forecast.last?.id {
                            Divider()
                        }
                    }
                }
                .padding()
                .background(Color(.systemBackground))
                .cornerRadius(12)
                .shadow(radius: 2)
            }
            .padding()
        }
        .background(Color(.systemGroupedBackground).ignoresSafeArea())
    }
    
    // 错误视图
    private func errorView(message: String) -> some View {
        VStack(spacing: 20) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 60))
                .foregroundColor(.red)
            
            Text("出错了")
                .font(.title)
            
            Text(message)
                .multilineTextAlignment(.center)
                .padding()
            
            Button("重试") {
                viewModel.searchWeather()
            }
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(10)
            
            Button("返回主页") {
                viewModel.clearSearch()
            }
            .padding()
        }
        .padding()
    }
    
    // 格式化日期
    private func formatDate(_ dateString: String) -> String {
        let inputFormatter = DateFormatter()
        inputFormatter.dateFormat = "yyyy-MM-dd"
        
        guard let date = inputFormatter.date(from: dateString) else {
            return dateString
        }
        
        let outputFormatter = DateFormatter()
        outputFormatter.dateFormat = "MM月dd日"
        return outputFormatter.string(from: date)
    }
}

// 天气信息卡片组件
struct WeatherInfoCard: View {
    let icon: String
    let title: String
    let value: String
    
    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 24))
                .foregroundColor(.blue)
            
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
            
            Text(value)
                .font(.headline)
        }
        .frame(height: 90)
        .padding(.horizontal, 8)
    }
}
```

这个完整示例展示了 MVVM 在 SwiftUI 中的实现，包括：
- 模型层负责数据结构和业务逻辑
- 视图模型层负责状态管理和展示逻辑
- 视图层负责 UI 展示和用户交互
- 清晰的单向数据流

## MVVM 与其他架构的比较

### MVVM vs MVC

MVC (Model-View-Controller) 是 iOS 开发中最传统的架构模式，而 MVVM 可以看作是 MVC 的演进。以下是两者的主要区别：

| 特性 | MVC | MVVM |
|------|-----|------|
| 职责划分 | 三层：数据、视图、控制器 | 三层：数据、视图、视图模型 |
| 代码分布 | 大量代码集中在 Controller | 业务逻辑迁移到 ViewModel |
| 视图更新 | 控制器手动更新视图 | 通过数据绑定自动更新 |
| 可测试性 | 控制器与 UI 紧耦合，难以测试 | ViewModel 独立于 UI，易于单元测试 |
| 代码复用 | 控制器难以复用 | ViewModel 可在不同视图间复用 |
| 学习曲线 | 简单直观 | 需要理解绑定机制 |
| 适用场景 | 简单小型应用 | 中大型应用或复杂交互 |

**代码对比**：

MVC 中的视图控制器：
```swift
class WeatherViewController: UIViewController {
    // UI 组件
    private let cityTextField = UITextField()
    private let temperatureLabel = UILabel()
    private let locationLabel = UILabel()
    private let searchButton = UIButton()
    private let activityIndicator = UIActivityIndicatorView()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    @objc private func searchButtonTapped() {
        guard let city = cityTextField.text, !city.isEmpty else { return }
        
        // 显示加载指示器
        activityIndicator.startAnimating()
        searchButton.isEnabled = false
        
        // 在控制器中直接处理网络请求
        WeatherService.shared.fetchWeather(for: city) { [weak self] result in
            DispatchQueue.main.async {
                self?.activityIndicator.stopAnimating()
                self?.searchButton.isEnabled = true
                
                switch result {
                case .success(let weather):
                    // 控制器直接更新 UI
                    self?.temperatureLabel.text = "\(weather.temperature)°C"
                    self?.locationLabel.text = city
                    
                case .failure(let error):
                    // 控制器处理错误
                    let alert = UIAlertController(
                        title: "错误",
                        message: error.localizedDescription,
                        preferredStyle: .alert
                    )
                    alert.addAction(UIAlertAction(title: "确定", style: .default))
                    self?.present(alert, animated: true)
                }
            }
        }
    }
}
```

MVVM 中的视图控制器与视图模型：
```swift
// ViewModel
class WeatherViewModel {
    // 输出
    var temperature: Observable<String> = Observable("")
    var location: Observable<String> = Observable("")
    var isLoading: Observable<Bool> = Observable(false)
    var error: Observable<String?> = Observable(nil)
    
    // 输入
    func searchWeather(for city: String) {
        guard !city.isEmpty else { return }
        
        isLoading.value = true
        error.value = nil
        
        WeatherService.shared.fetchWeather(for: city) { [weak self] result in
            guard let self = self else { return }
            
            DispatchQueue.main.async {
                self.isLoading.value = false
                
                switch result {
                case .success(let weather):
                    self.temperature.value = "\(weather.temperature)°C"
                    self.location.value = city
                    
                case .failure(let error):
                    self.error.value = error.localizedDescription
                }
            }
        }
    }
}

// Observable 简单实现
class Observable<T> {
    var value: T {
        didSet {
            listener?(value)
        }
    }
    
    private var listener: ((T) -> Void)?
    
    init(_ value: T) {
        self.value = value
    }
    
    func bind(_ listener: @escaping (T) -> Void) {
        self.listener = listener
        listener(value)
    }
}

// ViewController
class WeatherViewController: UIViewController {
    // UI 组件
    private let cityTextField = UITextField()
    private let temperatureLabel = UILabel()
    private let locationLabel = UILabel()
    private let searchButton = UIButton()
    private let activityIndicator = UIActivityIndicatorView()
    
    // ViewModel
    private let viewModel = WeatherViewModel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
    }
    
    private func bindViewModel() {
        // 数据绑定
        viewModel.temperature.bind { [weak self] temperature in
            self?.temperatureLabel.text = temperature
        }
        
        viewModel.location.bind { [weak self] location in
            self?.locationLabel.text = location
        }
        
        viewModel.isLoading.bind { [weak self] isLoading in
            if isLoading {
                self?.activityIndicator.startAnimating()
            } else {
                self?.activityIndicator.stopAnimating()
            }
            self?.searchButton.isEnabled = !isLoading
        }
        
        viewModel.error.bind { [weak self] errorMessage in
            guard let errorMessage = errorMessage else { return }
            
            let alert = UIAlertController(
                title: "错误",
                message: errorMessage,
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "确定", style: .default))
            self?.present(alert, animated: true)
        }
    }
    
    @objc private func searchTapped() {
        guard let city = cityTextField.text, !city.isEmpty else { return }
        viewModel.searchWeather(for: city)
    }
}
```

### MVVM vs MVP

MVP (Model-View-Presenter) 是另一种常见的架构模式，它与 MVVM 有一些相似之处，但也存在明显差异：

| 特性 | MVVM | MVP |
|------|------|-----|
| 视图更新方式 | 数据绑定（双向或单向） | Presenter 直接调用视图方法 |
| 视图状态 | ViewModel 持有视图状态 | Presenter 不持有状态 |
| 视图接口 | 视图无需实现特定接口 | 视图通常需要实现接口 |
| 测试难度 | ViewModel 易于测试 | Presenter 依赖视图接口，略难测试 |
| 视图引用 | ViewModel 不直接引用视图 | Presenter 持有视图的弱引用 |
| 适用框架 | 适合响应式框架（SwiftUI、RxSwift） | 适合传统命令式编程 |

**代码对比**：

MVP 实现：
```swift
// 视图协议
protocol WeatherView: AnyObject {
    func showLoading(_ isLoading: Bool)
    func showTemperature(_ temperature: String)
    func showLocation(_ location: String)
    func showError(_ message: String)
}

// Presenter
class WeatherPresenter {
    private weak var view: WeatherView?
    private let weatherService: WeatherService
    
    init(view: WeatherView, weatherService: WeatherService = WeatherService.shared) {
        self.view = view
        self.weatherService = weatherService
    }
    
    func searchWeather(for city: String) {
        guard !city.isEmpty else { return }
        
        view?.showLoading(true)
        
        weatherService.fetchWeather(for: city) { [weak self] result in
            DispatchQueue.main.async {
                self?.view?.showLoading(false)
                
                switch result {
                case .success(let weather):
                    self?.view?.showTemperature("\(weather.temperature)°C")
                    self?.view?.showLocation(city)
                    
                case .failure(let error):
                    self?.view?.showError(error.localizedDescription)
                }
            }
        }
    }
}

// ViewController 实现视图协议
class WeatherViewController: UIViewController, WeatherView {
    // UI 组件
    private let cityTextField = UITextField()
    private let temperatureLabel = UILabel()
    private let locationLabel = UILabel()
    private let searchButton = UIButton()
    private let activityIndicator = UIActivityIndicatorView()
    
    // Presenter
    private lazy var presenter = WeatherPresenter(view: self)
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    @objc private func searchTapped() {
        guard let city = cityTextField.text, !city.isEmpty else { return }
        presenter.searchWeather(for: city)
    }
    
    // 实现 WeatherView 协议
    func showLoading(_ isLoading: Bool) {
        if isLoading {
            activityIndicator.startAnimating()
        } else {
            activityIndicator.stopAnimating()
        }
        searchButton.isEnabled = !isLoading
    }
    
    func showTemperature(_ temperature: String) {
        temperatureLabel.text = temperature
    }
    
    func showLocation(_ location: String) {
        locationLabel.text = location
    }
    
    func showError(_ message: String) {
        let alert = UIAlertController(
            title: "错误",
            message: message,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "确定", style: .default))
        present(alert, animated: true)
    }
}
```

MVVM 与 MVP 的主要区别在于，MVP 中 Presenter 直接调用视图方法更新 UI，而 MVVM 中 ViewModel 不直接引用视图，而是通过数据绑定机制通知视图更新。

### MVVM vs VIPER

VIPER (View-Interactor-Presenter-Entity-Router) 是一种更复杂的架构模式，将应用程序分为五个层次：

| 特性 | MVVM | VIPER |
|------|------|-------|
| 复杂度 | 中等 | 高 |
| 组件数量 | 3个核心组件 | 5个核心组件 |
| 职责划分 | 视图模型承担多种职责 | 职责更加细分 |
| 导航管理 | 通常在视图控制器中处理 | 专门的 Router 组件处理 |
| 业务逻辑 | 可能混合在视图模型中 | 由 Interactor 专门处理 |
| 模块边界 | 不明确 | 严格定义 |
| 代码量 | 中等 | 大量样板代码 |
| 学习曲线 | 中等 | 陡峭 |
| 适用场景 | 中小型到大型应用 | 大型团队协作项目 |

VIPER 的核心组件：
- **View**: 负责 UI 展示，与 MVVM 中的 View 类似
- **Interactor**: 包含业务逻辑和数据处理
- **Presenter**: 协调 View 和 Interactor，类似 MVVM 中的 ViewModel
- **Entity**: 数据模型，类似 MVVM 中的 Model
- **Router**: 负责导航和模块间通信

VIPER 的优势在于职责划分更加明确，模块化程度更高，适合大型团队协作开发。但其缺点是架构复杂，需要编写大量样板代码，学习曲线陡峭。

### MVVM vs Clean Architecture

Clean Architecture 是一种架构思想，而非具体实现模式，它强调将业务逻辑与外部依赖（如 UI、数据库等）分离：

| 特性 | MVVM | Clean Architecture |
|------|------|-------------------|
| 核心思想 | 视图和模型分离 | 业务规则独立于外部框架 |
| 层次结构 | 三层结构 | 多层结构（通常至少四层） |
| 依赖规则 | 不严格 | 严格的依赖规则（内层不知道外层） |
| 业务逻辑 | 可能与 UI 逻辑混合 | 完全独立的领域层 |
| 复杂度 | 中等 | 高 |
| 适应性 | 容易适配不同UI框架 | 框架无关，高度适应性 |
| 适用场景 | 一般应用程序 | 长期维护的复杂系统 |

Clean Architecture 通常包含以下层次：
1. **实体层**（Entities）：包含业务对象和规则
2. **用例层**（Use Cases）：包含应用特定的业务规则
3. **接口适配层**（Interface Adapters）：将用例转换为适合外部的格式
4. **框架和驱动层**（Frameworks & Drivers）：包含所有外部依赖

MVVM 可以作为 Clean Architecture 的一部分，通常位于接口适配层，负责协调领域层与 UI 层之间的数据转换。

### 选择合适的架构

选择架构模式时，应考虑以下因素：

1. **项目规模**：
   - 小型项目：MVC 或简单的 MVVM
   - 中型项目：MVVM
   - 大型项目：MVVM + 协调器、VIPER 或 Clean Architecture

2. **团队规模和经验**：
   - 小团队或初学者：MVVM
   - 大团队或有经验开发者：可以考虑更复杂的架构

3. **项目生命周期**：
   - 短期项目：简单架构如 MVC 或 MVVM
   - 长期维护项目：考虑 Clean Architecture

4. **UI 框架**：
   - SwiftUI：天然适合 MVVM
   - UIKit：MVVM、MVP 或 VIPER 都可行

5. **业务复杂度**：
   - 简单业务逻辑：MVVM 足够
   - 复杂业务逻辑：考虑 Clean Architecture

在实际项目中，可以根据需要组合多种架构的优点，例如 MVVM + 协调器模式、MVVM + Clean Architecture 等。最重要的是架构应该服务于项目需求，而不是为了使用特定架构而让项目适应它。

## MVVM 最佳实践

### ViewModel 设计原则

设计高质量的 ViewModel 是实现 MVVM 架构的关键。以下是一些重要的设计原则：

#### 1. 保持 ViewModel 的独立性

ViewModel 不应该依赖于具体的 UI 框架，这样可以提高可测试性和可重用性：

```swift
// 不好的做法：ViewModel 依赖 UIKit
class BadViewModel {
    func updateView(_ view: UIView) {
        // 直接操作视图
    }
    
    func configureCell(_ cell: UITableViewCell, at indexPath: IndexPath) {
        // 直接配置 UIKit 单元格
    }
}

// 好的做法：ViewModel 完全独立于 UI 框架
class GoodViewModel {
    @Published var title: String = ""
    @Published var isLoading: Bool = false
    
    // 提供视图需要的数据，而不是直接操作视图
    func cellViewModel(at index: Int) -> CellViewModel {
        return CellViewModel(title: "Item \(index)")
    }
}
```

#### 2. 明确输入/输出接口

将 ViewModel 设计为明确的输入/输出模式，使其更易于理解和使用：

```swift
class SearchViewModel {
    // 输入（用户操作）
    func search(query: String) {
        performSearch(query)
    }
    
    func loadNextPage() {
        fetchNextPage()
    }
    
    func cancelSearch() {
        resetState()
    }
    
    // 输出（视图状态）
    @Published var results: [SearchResult] = []
    @Published var isLoading: Bool = false
    @Published var error: Error? = nil
    @Published var hasMoreResults: Bool = false
    
    // 私有实现
    private func performSearch(_ query: String) {
        // 实现搜索逻辑
    }
    
    private func fetchNextPage() {
        // 实现分页加载
    }
    
    private func resetState() {
        // 重置状态
    }
}
```

#### 3. 使用合适的状态管理方式

根据 UI 框架选择合适的状态管理方式：

**基于状态枚举的管理**（适用于复杂视图）：
```swift
class ProfileViewModel {
    enum ViewState {
        case loading
        case loaded(User)
        case error(String)
        case empty
    }
    
    @Published var state: ViewState = .loading
    
    func loadProfile() {
        state = .loading
        
        userService.fetchUser { [weak self] result in
            switch result {
            case .success(let user):
                self?.state = .loaded(user)
            case .failure(let error):
                self?.state = .error(error.localizedDescription)
            }
        }
    }
}
```

**基于独立属性的管理**（适用于简单视图）：
```swift
class LoginViewModel {
    @Published var email: String = ""
    @Published var password: String = ""
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    
    var isLoginEnabled: Bool {
        return isValidEmail(email) && password.count >= 6 && !isLoading
    }
    
    func login() {
        isLoading = true
        errorMessage = nil
        
        authService.login(email: email, password: password) { [weak self] result in
            self?.isLoading = false
            
            switch result {
            case .success:
                // 处理登录成功
            case .failure(let error):
                self?.errorMessage = error.localizedDescription
            }
        }
    }
    
    private func isValidEmail(_ email: String) -> Bool {
        // 验证邮箱格式
        return email.contains("@") && email.contains(".")
    }
}
```

#### 4. 适当分解大型 ViewModel

当 ViewModel 变得过于复杂时，应该考虑拆分为多个小型 ViewModel：

```swift
// 主 ViewModel
class ShoppingCartViewModel {
    @Published var cartItems: [CartItemViewModel] = []
    @Published var isLoading: Bool = false
    
    // 结账相关逻辑委托给专门的 ViewModel
    let checkoutViewModel: CheckoutViewModel
    
    init(checkoutService: CheckoutService) {
        self.checkoutViewModel = CheckoutViewModel(checkoutService: checkoutService)
    }
    
    func loadCart() {
        // 加载购物车
    }
}

// 专门处理结账流程的 ViewModel
class CheckoutViewModel {
    enum CheckoutState {
        case idle
        case processing
        case completed
        case failed(String)
    }
    
    @Published var state: CheckoutState = .idle
    @Published var paymentMethods: [PaymentMethod] = []
    
    private let checkoutService: CheckoutService
    
    init(checkoutService: CheckoutService) {
        self.checkoutService = checkoutService
    }
    
    func checkout(with paymentMethod: PaymentMethod) {
        // 处理结账逻辑
    }
}

// 单个购物车项的 ViewModel
struct CartItemViewModel: Identifiable {
    let id: String
    let productName: String
    let price: String
    let quantity: Int
    let imageURL: URL?
    
    var totalPrice: String {
        // 计算总价
        return "$\(Double(price.dropFirst()) ?? 0 * Double(quantity))"
    }
}
```

### 依赖注入

依赖注入是实现松耦合架构的重要技术，有助于提高代码的可测试性和可维护性：

#### 1. 通过构造器注入依赖

```swift
class ProductViewModel {
    private let productService: ProductService
    private let analyticsService: AnalyticsService
    
    init(
        productService: ProductService = ProductService.shared,
        analyticsService: AnalyticsService = AnalyticsService.shared
    ) {
        self.productService = productService
        self.analyticsService = analyticsService
    }
    
    func loadProduct(id: String) {
        productService.fetchProduct(id: id) { /* ... */ }
        analyticsService.trackEvent("product_viewed", parameters: ["id": id])
    }
}

// 使用
let viewModel = ProductViewModel()  // 使用默认依赖
let testViewModel = ProductViewModel(
    productService: MockProductService(),
    analyticsService: MockAnalyticsService()
)  // 用于测试
```

#### 2. 使用协议定义服务依赖

```swift
// 定义服务协议
protocol WeatherService {
    func fetchWeather(for city: String) async throws -> WeatherData
}

// 实现服务
class RealWeatherService: WeatherService {
    func fetchWeather(for city: String) async throws -> WeatherData {
        // 实际的网络请求
        return try await apiClient.request(endpoint: .weather(city: city))
    }
}

// 测试模拟实现
class MockWeatherService: WeatherService {
    var stubbedWeather: WeatherData?
    var error: Error?
    
    func fetchWeather(for city: String) async throws -> WeatherData {
        if let error = error {
            throw error
        }
        
        return stubbedWeather ?? WeatherData(
            temperature: 25,
            humidity: 60,
            windSpeed: 10,
            description: "晴朗"
        )
    }
}

// ViewModel 使用协议而非具体类
class WeatherViewModel {
    private let weatherService: WeatherService
    
    init(weatherService: WeatherService) {
        self.weatherService = weatherService
    }
    
    func fetchWeather(for city: String) async {
        // 使用注入的服务获取数据
        do {
            let weather = try await weatherService.fetchWeather(for: city)
            // 处理结果
        } catch {
            // 处理错误
        }
    }
}
```

#### 3. 使用依赖容器

对于大型应用，可以使用依赖容器管理服务实例：

```swift
class DependencyContainer {
    // 单例实例
    static let shared = DependencyContainer()
    
    // 服务注册表
    private var services: [String: Any] = [:]
    
    // 注册服务
    func register<T>(_ serviceType: T.Type, factory: @escaping () -> T) {
        let key = String(describing: serviceType)
        services[key] = factory
    }
    
    // 获取服务
    func resolve<T>(_ serviceType: T.Type) -> T? {
        let key = String(describing: serviceType)
        if let factory = services[key] as? () -> T {
            return factory()
        }
        return nil
    }
}

// 应用启动时配置
func setupDependencies() {
    let container = DependencyContainer.shared
    
    // 注册服务
    container.register(WeatherService.self) { RealWeatherService() }
    container.register(UserService.self) { RealUserService() }
    container.register(AnalyticsService.self) { RealAnalyticsService() }
}

// 在 ViewModel 中使用
class WeatherViewModel {
    private let weatherService: WeatherService
    
    init(weatherService: WeatherService? = nil) {
        // 使用注入的服务或从容器获取
        self.weatherService = weatherService ?? 
            DependencyContainer.shared.resolve(WeatherService.self)!
    }
}
```

### 单元测试

MVVM 架构的一个主要优势是可测试性。以下是测试 ViewModel 的一些最佳实践：

#### 1. 基本 ViewModel 测试

```swift
import XCTest
@testable import MyApp

class LoginViewModelTests: XCTestCase {
    var viewModel: LoginViewModel!
    var mockAuthService: MockAuthService!
    
    override func setUp() {
        super.setUp()
        mockAuthService = MockAuthService()
        viewModel = LoginViewModel(authService: mockAuthService)
    }
    
    override func tearDown() {
        viewModel = nil
        mockAuthService = nil
        super.tearDown()
    }
    
    func testLoginSuccess() {
        // 准备
        viewModel.email = "test@example.com"
        viewModel.password = "password123"
        mockAuthService.stubbedResult = .success(User(id: "123", name: "Test User"))
        
        // 期望值
        let expectation = self.expectation(description: "Login success")
        
        // 监听状态变化
        var isLoadingValues: [Bool] = []
        var successCalled = false
        
        let cancellable = viewModel.$isLoading.sink { isLoading in
            isLoadingValues.append(isLoading)
        }
        
        viewModel.onLoginSuccess = {
            successCalled = true
            expectation.fulfill()
        }
        
        // 执行
        viewModel.login()
        
        // 验证
        waitForExpectations(timeout: 1)
        XCTAssertTrue(successCalled)
        XCTAssertEqual(isLoadingValues, [false, true, false]) // 初始值、加载中、加载完成
        XCTAssertNil(viewModel.errorMessage)
    }
    
    func testLoginFailure() {
        // 准备
        viewModel.email = "test@example.com"
        viewModel.password = "password123"
        let expectedError = NSError(domain: "auth", code: 401, userInfo: [
            NSLocalizedDescriptionKey: "Invalid credentials"
        ])
        mockAuthService.stubbedResult = .failure(expectedError)
        
        // 期望值
        let expectation = self.expectation(description: "Login failure")
        
        var errorMessageValue: String?
        let errorCancellable = viewModel.$errorMessage.dropFirst().sink { message in
            errorMessageValue = message
            expectation.fulfill()
        }
        
        // 执行
        viewModel.login()
        
        // 验证
        waitForExpectations(timeout: 1)
        XCTAssertEqual(errorMessageValue, "Invalid credentials")
        XCTAssertFalse(viewModel.isLoading)
    }
    
    func testIsLoginEnabledValidation() {
        // 测试空输入
        viewModel.email = ""
        viewModel.password = ""
        XCTAssertFalse(viewModel.isLoginEnabled)
        
        // 测试无效邮箱
        viewModel.email = "notanemail"
        viewModel.password = "password123"
        XCTAssertFalse(viewModel.isLoginEnabled)
        
        // 测试密码太短
        viewModel.email = "test@example.com"
        viewModel.password = "12345"
        XCTAssertFalse(viewModel.isLoginEnabled)
        
        // 测试有效输入
        viewModel.email = "test@example.com"
        viewModel.password = "password123"
        XCTAssertTrue(viewModel.isLoginEnabled)
        
        // 测试加载中
        viewModel.isLoading = true
        XCTAssertFalse(viewModel.isLoginEnabled)
    }
}

// 模拟认证服务
class MockAuthService: AuthService {
    var stubbedResult: Result<User, Error>?
    
    func login(email: String, password: String, completion: @escaping (Result<User, Error>) -> Void) {
        if let result = stubbedResult {
            completion(result)
        }
    }
}
```

#### 2. 测试异步 ViewModel

使用 Swift 的 async/await 测试异步 ViewModel：

```swift
import XCTest
@testable import MyApp

class WeatherViewModelTests: XCTestCase {
    var viewModel: WeatherViewModel!
    var mockWeatherService: MockWeatherService!
    
    override func setUp() {
        super.setUp()
        mockWeatherService = MockWeatherService()
        viewModel = WeatherViewModel(weatherService: mockWeatherService)
    }
    
    func testFetchWeatherSuccess() async {
        // 准备
        let expectedWeather = WeatherData(
            temperature: 25,
            humidity: 60,
            windSpeed: 10,
            description: "晴朗"
        )
        mockWeatherService.stubbedWeather = expectedWeather
        
        // 观察状态变化
        let expectation = XCTestExpectation(description: "State should change to loaded")
        
        let cancellable = viewModel.$state.dropFirst().sink { state in
            if case .loaded(let weather) = state {
                XCTAssertEqual(weather.temperature, expectedWeather.temperature)
                XCTAssertEqual(weather.description, expectedWeather.description)
                expectation.fulfill()
            }
        }
        
        // 执行
        await viewModel.fetchWeather(for: "北京")
        
        // 验证
        await fulfillment(of: [expectation], timeout: 1)
    }
    
    func testFetchWeatherFailure() async {
        // 准备
        let expectedError = NSError(domain: "weather", code: 500, userInfo: [
            NSLocalizedDescriptionKey: "网络错误"
        ])
        mockWeatherService.error = expectedError
        
        // 观察状态变化
        let expectation = XCTestExpectation(description: "State should change to error")
        
        let cancellable = viewModel.$state.dropFirst().sink { state in
            if case .error(let message) = state {
                XCTAssertEqual(message, "网络错误")
                expectation.fulfill()
            }
        }
        
        // 执行
        await viewModel.fetchWeather(for: "北京")
        
        // 验证
        await fulfillment(of: [expectation], timeout: 1)
    }
}
```

### 反模式与注意事项

在使用 MVVM 架构时，应避免以下常见的反模式：

#### 1. 避免在 ViewModel 中保存全局状态

```swift
// 不好的做法：在 ViewModel 中管理全局状态
class UserViewModel {
    static var currentUser: User? // 不应该在这里存储全局状态
    
    func login() {
        // 登录后更新全局状态
        UserViewModel.currentUser = user
    }
}

// 好的做法：使用专门的状态管理器
class AppState {
    static let shared = AppState()
    private(set) var currentUser: User?
    
    func updateUser(_ user: User?) {
        currentUser = user
        NotificationCenter.default.post(name: .userDidChange, object: nil)
    }
}

class UserViewModel {
    func login(completion: @escaping (Result<Void, Error>) -> Void) {
        authService.login { result in
            switch result {
            case .success(let user):
                AppState.shared.updateUser(user)
                completion(.success(()))
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
}
```

#### 2. 避免 ViewModel 直接引用 ViewController

```swift
// 不好的做法：ViewModel 引用 ViewController
class BadViewModel {
    weak var viewController: UIViewController?
    
    func showDetails(for item: Item) {
        let detailVC = DetailViewController(item: item)
        viewController?.navigationController?.pushViewController(detailVC, animated: true)
    }
}

// 好的做法：使用协调器或回调处理导航
protocol NavigationDelegate: AnyObject {
    func navigateToDetail(item: Item)
}

class GoodViewModel {
    weak var navigationDelegate: NavigationDelegate?
    
    func selectItem(_ item: Item) {
        // 处理业务逻辑
        analyticsService.trackItemSelected(item)
        
        // 委托导航
        navigationDelegate?.navigateToDetail(item: item)
    }
}

// 在视图控制器中实现
class ItemListViewController: UIViewController, NavigationDelegate {
    private let viewModel = GoodViewModel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        viewModel.navigationDelegate = self
    }
    
    func navigateToDetail(item: Item) {
        let detailVC = DetailViewController(item: item)
        navigationController?.pushViewController(detailVC, animated: true)
    }
}
```

#### 3. 避免 ViewModel 过于臃肿

当 ViewModel 变得臃肿时，考虑以下解决方案：

- **分解为多个子 ViewModel**：将不同功能区域的逻辑分离到专门的 ViewModel 中
- **使用 UseCase 或 Interactor**：将业务逻辑移至专门的组件
- **使用组合而非继承**：通过组合多个小型组件构建功能
- **适当使用扩展**：使用扩展整理相关功能

```swift
// 过于臃肿的 ViewModel
class HugeViewModel {
    // 数十个属性和方法...
}

// 分解后的 ViewModel
class ProductListViewModel {
    let filterViewModel: FilterViewModel
    let sortViewModel: SortViewModel
    let searchViewModel: SearchViewModel
    
    // 主要负责产品列表的核心功能
}

class FilterViewModel {
    // 专门处理过滤逻辑
}

class SortViewModel {
    // 专门处理排序逻辑
}

class SearchViewModel {
    // 专门处理搜索逻辑
}
```

#### 4. 避免在 ViewModel 中进行视图格式化以外的 UI 决策

```swift
// 不好的做法：ViewModel 作出 UI 决策
class BadViewModel {
    func configureCell(_ cell: UITableViewCell, at indexPath: IndexPath) {
        cell.textLabel?.text = items[indexPath.row].name
        cell.textLabel?.font = .boldSystemFont(ofSize: 16) // UI 决策
        cell.accessoryType = .disclosureIndicator // UI 决策
    }
}

// 好的做法：ViewModel 提供数据，View 决定如何显示
class GoodViewModel {
    func itemViewModel(at index: Int) -> ItemViewModel {
        let item = items[index]
        return ItemViewModel(
            name: item.name,
            isSelected: item.isSelected,
            hasBadge: item.unreadCount > 0
        )
    }
}

// 视图决定如何展示数据
class ItemCell: UITableViewCell {
    func configure(with viewModel: ItemViewModel) {
        textLabel?.text = viewModel.name
        // 视图层决定 UI 样式
        textLabel?.font = viewModel.isSelected ? .boldSystemFont(ofSize: 16) : .systemFont(ofSize: 16)
        accessoryType = viewModel.hasBadge ? .detailDisclosureButton : .none
    }
}
```

## 总结与展望

MVVM 架构已经成为现代 iOS 应用开发的主流架构模式之一，尤其在 SwiftUI 的推动下获得了更广泛的应用。

### 主要优势回顾

1. **关注点分离**：MVVM 将应用程序划分为数据模型、视图和视图模型三个明确的层次，每层具有清晰的职责。

2. **可测试性**：视图模型层不依赖于具体的 UI 实现，可以轻松进行单元测试，提高代码质量和可靠性。

3. **代码复用**：视图模型可以在不同的视图间复用，减少代码重复，提高开发效率。

4. **数据绑定**：通过数据绑定机制，实现视图和视图模型之间的自动同步，简化状态管理。

5. **易于维护**：清晰的职责划分和模块化设计，使得代码更易于理解和维护，特别是在大型团队协作中。

### 何时选择 MVVM

MVVM 架构适合以下场景：

- 中大型应用程序，特别是具有复杂用户界面和交互的应用
- 需要高度可测试性的项目
- 使用响应式编程（如 Combine、RxSwift）的项目
- SwiftUI 应用程序（天然适合 MVVM 模式）
- 需要清晰分离 UI 和业务逻辑的项目

对于非常简单的应用或原型，MVC 可能更加简洁直接；而对于特别复杂的大型企业应用，可能需要考虑 Clean Architecture 或 VIPER 等更严格的架构。

### MVVM 的演进趋势

随着 Swift 和 iOS 开发生态的发展，MVVM 架构也在不断演进：

1. **MVVM + Coordinator**：将导航逻辑抽离到协调器中，进一步优化架构。

2. **MVVM + Clean Architecture**：融合 Clean Architecture 的核心原则，增强业务逻辑的独立性。

3. **Unidirectional Data Flow**：受 Redux 和 Flux 架构影响，在 MVVM 中采用单向数据流模式。

4. **Compositional MVVM**：使用组合而非继承，构建更灵活的 MVVM 实现。

5. **声明式 MVVM**：随着 SwiftUI 的普及，MVVM 与声明式 UI 范式结合得更加紧密。

### 实践建议

在实际项目中应用 MVVM 架构时，可以遵循以下建议：

1. **从简单开始**：不要过度设计，根据项目需求选择合适的复杂度。

2. **持续重构**：随着项目发展，定期重构和优化架构，避免架构腐化。

3. **保持一致性**：在团队中建立明确的架构规范和最佳实践，确保一致性。

4. **关注平衡**：在代码复杂度和功能实现之间寻找平衡点，避免过度工程化。

5. **拥抱变化**：随着 Swift 和 iOS 平台的发展，保持对新技术和范式的开放态度。

MVVM 不是银弹，它是一种工具，而非目标本身。最终，好的架构应该服务于项目需求和团队效率，而不是为了架构而架构。通过深入理解 MVVM 的原则和实践，开发者可以灵活应用这一模式，构建出高质量、易维护的 iOS 应用程序。

## 参考资源

### 官方文档
- [Apple Developer Documentation: SwiftUI](https://developer.apple.com/documentation/swiftui)
- [Apple Developer Documentation: Combine](https://developer.apple.com/documentation/combine)

### 推荐书籍
- 《Swift in Depth》by Tjeerd in 't Veen
- 《App Architecture: iOS Application Design Patterns in Swift》by Chris Eidhof, Matt Gallagher, and Florian Kugler
- 《Advanced iOS App Architecture》by Rene Cacheaux and Josh Berlin

### 在线资源
- [objc.io: MVVM](https://www.objc.io/issues/13-architecture/mvvm/)
- [Ray Wenderlich: MVVM in iOS](https://www.raywenderlich.com/34-design-patterns-by-tutorials-mvvm)
- [Hacking with Swift: MVVM with SwiftUI](https://www.hackingwithswift.com/books/ios-swiftui/introducing-mvvm-into-your-swiftui-project)

### 开源项目
- [Kickstarter iOS App](https://github.com/kickstarter/ios-oss) - 使用 MVVM 和响应式编程
- [GitHawk](https://github.com/GitHawkApp/GitHawk) - GitHub 客户端，使用 MVVM 架构
- [SwiftUI 天气应用](https://github.com/AppPear/SwiftUI-Weather) - 简单的 SwiftUI MVVM 示例

通过这些资源，开发者可以进一步深入学习 MVVM 架构，掌握更多高级技巧和最佳实践。

## 常见问题与解决方案

### 1. ViewModel 过于臃肿

**问题**: 随着功能增加，ViewModel 可能变得过于臃肿，承担过多责任。

**解决方案**:
- 将 ViewModel 分解为多个较小的、专注于特定功能的 ViewModel
- 使用组合模式组织多个 ViewModel
- 将业务逻辑移至专门的服务层或 UseCase
- 使用扩展按功能组织代码

```swift
// 过于臃肿的 ViewModel
class HugeProfileViewModel {
    // 个人信息
    @Published var userName: String = ""
    @Published var userAvatar: UIImage?
    @Published var userEmail: String = ""
    
    // 统计信息
    @Published var postCount: Int = 0
    @Published var followerCount: Int = 0
    @Published var followingCount: Int = 0
    
    // 帖子列表
    @Published var posts: [Post] = []
    @Published var isLoadingPosts: Bool = false
    
    // 各种方法...
    func loadUserProfile() { /* ... */ }
    func loadUserPosts() { /* ... */ }
    func updateProfile() { /* ... */ }
    func followUser() { /* ... */ }
    // 等等...
}

// 重构为多个 ViewModel
class ProfileViewModel {
    let userInfoViewModel: UserInfoViewModel
    let userStatsViewModel: UserStatsViewModel
    let userPostsViewModel: UserPostsViewModel
    
    init(userId: String, userService: UserService) {
        self.userInfoViewModel = UserInfoViewModel(userId: userId, userService: userService)
        self.userStatsViewModel = UserStatsViewModel(userId: userId, userService: userService)
        self.userPostsViewModel = UserPostsViewModel(userId: userId, userService: userService)
    }
    
    func loadAllData() {
        userInfoViewModel.loadUserInfo()
        userStatsViewModel.loadStats()
        userPostsViewModel.loadPosts()
    }
}

class UserInfoViewModel {
    @Published var userName: String = ""
    @Published var userAvatar: UIImage?
    @Published var userEmail: String = ""
    
    // 只关注用户基本信息
}

class UserStatsViewModel {
    @Published var postCount: Int = 0
    @Published var followerCount: Int = 0
    @Published var followingCount: Int = 0
    
    // 只关注统计数据
}

class UserPostsViewModel {
    @Published var posts: [Post] = []
    @Published var isLoadingPosts: Bool = false
    
    // 只关注帖子相关功能
}
```

### 2. 数据绑定性能问题

**问题**: 在复杂 UI 或频繁更新的场景下，数据绑定可能导致性能问题。

**解决方案**:
- 减少发布者数量，合并相关状态
- 使用节流（debounce）或合并（combineLatest）等操作符
- 实现细粒度更新而非整体刷新
- 对于大量数据，考虑分页加载或虚拟化列表

```swift
// 优化前：多个独立发布者
class IneffieientViewModel {
    @Published var items: [Item] = []       // 触发整个列表刷新
    @Published var isLoading: Bool = false
    @Published var selectedItemId: String?
    @Published var searchQuery: String = ""
    
    // 每次搜索都会触发网络请求
    func search(query: String) {
        searchQuery = query
        performSearch()
    }
}

// 优化后：合并状态和使用节流
class OptimizedViewModel {
    // 合并相关状态到一个状态对象
    enum ViewState {
        case loading
        case loaded([Item])
        case error(String)
    }
    
    @Published var state: ViewState = .loaded([])
    @Published var selectedItemId: String?
    
    private var searchCancellable: AnyCancellable?
    private var searchText: CurrentValueSubject<String, Never> = CurrentValueSubject("")
    
    init() {
        // 对搜索查询进行节流，避免频繁请求
        searchCancellable = searchText
            .debounce(for: .milliseconds(300), scheduler: RunLoop.main)
            .removeDuplicates()
            .sink { [weak self] query in
                self?.performSearch(query: query)
            }
    }
    
    func updateSearchQuery(_ query: String) {
        searchText.send(query)
    }
    
    // 列表差异更新
    func updateItems(_ newItems: [Item]) {
        guard case .loaded(let currentItems) = state else {
            state = .loaded(newItems)
            return
        }
        
        // 使用差异算法计算变化
        let changes = calculateChanges(from: currentItems, to: newItems)
        
        // 应用差异更新而非整体刷新
        applyChanges(changes)
    }
}
```

### 3. 依赖注入复杂性

**问题**: 随着应用规模增长，依赖注入变得复杂且难以管理。

**解决方案**:
- 使用依赖注入框架（如 Swinject、Resolver）
- 实现服务定位器模式集中管理依赖
- 使用工厂模式创建 ViewModel 及其依赖
- 对于简单应用，使用属性注入而非构造器注入

```swift
// 使用依赖注入框架
import Swinject

let container = Container()

// 注册服务
container.register(NetworkService.self) { _ in RealNetworkService() }
container.register(UserService.self) { r in
    RealUserService(networkService: r.resolve(NetworkService.self)!)
}
container.register(AuthService.self) { r in
    RealAuthService(networkService: r.resolve(NetworkService.self)!)
}

// 注册 ViewModel
container.register(LoginViewModel.self) { r in
    LoginViewModel(authService: r.resolve(AuthService.self)!)
}
container.register(ProfileViewModel.self) { r in
    ProfileViewModel(userService: r.resolve(UserService.self)!)
}

// 在视图层使用
class LoginViewController: UIViewController {
    private let viewModel = container.resolve(LoginViewModel.self)!
    // ...
}
```

### 4. 导航管理

**问题**: 在 MVVM 中，处理导航和界面转换可能比较棘手，特别是当 ViewModel 不应该直接引用 UI 组件时。

**解决方案**:
- 使用协调器（Coordinator）模式管理导航流程
- 定义导航协议，让视图控制器实现该协议
- 使用闭包回调通知导航事件
- 在 SwiftUI 中使用 NavigationStack 和 NavigationPath

```swift
// 使用协调器模式
protocol Coordinator: AnyObject {
    var childCoordinators: [Coordinator] { get set }
    var navigationController: UINavigationController { get }
    
    func start()
}

class AppCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        showLogin()
    }
    
    func showLogin() {
        let viewModel = LoginViewModel()
        viewModel.onLoginSuccess = { [weak self] user in
            self?.showMainScreen(for: user)
        }
        
        let loginVC = LoginViewController(viewModel: viewModel)
        navigationController.setViewControllers([loginVC], animated: true)
    }
    
    func showMainScreen(for user: User) {
        let mainCoordinator = MainCoordinator(navigationController: navigationController, user: user)
        childCoordinators.append(mainCoordinator)
        mainCoordinator.start()
    }
}

// ViewModel 定义导航回调
class LoginViewModel {
    var onLoginSuccess: ((User) -> Void)?
    
    func login(email: String, password: String) {
        authService.login(email: email, password: password) { [weak self] result in
            if case .success(let user) = result {
                self?.onLoginSuccess?(user)
            }
        }
    }
}
```

### 5. 状态同步

**问题**: 当多个视图或组件需要共享状态时，可能导致状态不同步或重复逻辑。

**解决方案**:
- 使用全局状态管理器（如 Redux 风格的 Store）
- 实现观察者模式让多个组件监听状态变化
- 使用单一数据源原则
- 在 SwiftUI 中使用 EnvironmentObject 或 StateObject

```swift
// 全局状态管理器
class AppState: ObservableObject {
    static let shared = AppState()
    
    @Published var currentUser: User?
    @Published var isLoggedIn: Bool = false
    @Published var appSettings: AppSettings = AppSettings()
    
    func login(_ user: User) {
        currentUser = user
        isLoggedIn = true
    }
    
    func logout() {
        currentUser = nil
        isLoggedIn = false
    }
}

// 在 SwiftUI 中使用
struct ContentView: View {
    @EnvironmentObject var appState: AppState
    
    var body: some View {
        Group {
            if appState.isLoggedIn {
                MainView()
            } else {
                LoginView()
            }
        }
    }
}

// 应用启动时配置
@main
struct MyApp: App {
    @StateObject var appState = AppState.shared
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
        }
    }
}
```

### 6. 内存管理

**问题**: 在 MVVM 中，如果不正确处理引用循环，可能导致内存泄漏。

**解决方案**:
- 使用弱引用（weak）处理闭包和委托
- 注意 ViewModel 和视图之间的引用关系
- 在异步操作中使用 [weak self]
- 使用 ARC 调试工具检测内存泄漏

```swift
class ProfileViewModel {
    private let userService: UserService
    
    // 潜在的内存泄漏
    var onProfileLoaded: ((User) -> Void)?
    
    init(userService: UserService) {
        self.userService = userService
    }
    
    func loadProfile() {
        userService.fetchCurrentUser { [weak self] result in
            // 使用 [weak self] 避免循环引用
            guard let self = self else { return }
            
            if case .success(let user) = result {
                self.onProfileLoaded?(user)
            }
        }
    }
}

class ProfileViewController: UIViewController {
    private let viewModel: ProfileViewModel
    
    init(viewModel: ProfileViewModel) {
        self.viewModel = viewModel
        super.init(nibName: nil, bundle: nil)
        
        // 设置回调时避免循环引用
        viewModel.onProfileLoaded = { [weak self] user in
            self?.updateUI(with: user)
        }
    }
    
    func updateUI(with user: User) {
        // 更新 UI
    }
}
```

### 7. 测试覆盖率

**问题**: 确保 ViewModel 的所有代码路径和边缘情况都得到测试。

**解决方案**:
- 编写单元测试覆盖成功和失败场景
- 使用测试驱动开发（TDD）
- 模拟各种依赖行为
- 使用代码覆盖率工具监控测试覆盖情况

```swift
func testEmptySearchResults() {
    // 准备
    mockSearchService.stubbedResults = []
    
    // 执行
    viewModel.search(query: "nonexistent")
    
    // 验证
    XCTAssertEqual(viewModel.results.count, 0)
    XCTAssertTrue(viewModel.showEmptyState)
    XCTAssertFalse(viewModel.isLoading)
}

func testNetworkError() {
    // 准备
    let expectedError = NSError(domain: "network", code: 500)
    mockSearchService.stubbedError = expectedError
    
    // 执行
    viewModel.search(query: "test")
    
    // 验证
    XCTAssertTrue(viewModel.showError)
    XCTAssertEqual(viewModel.errorMessage, expectedError.localizedDescription)
    XCTAssertFalse(viewModel.isLoading)
}

func testCancelSearch() {
    // 准备
    viewModel.isLoading = true
    viewModel.results = [mockResult]
    
    // 执行
    viewModel.cancelSearch()
    
    // 验证
    XCTAssertFalse(viewModel.isLoading)
    XCTAssertTrue(viewModel.results.isEmpty)
    XCTAssertFalse(viewModel.showError)
    XCTAssertFalse(viewModel.showEmptyState)
}
```

## 实战案例分析

通过一个实际案例，我们来看看如何应用 MVVM 架构解决实际问题。以下是一个社交媒体应用的帖子列表功能实现：

### 案例：社交媒体帖子列表

#### 1. 模型层

```swift
// 数据模型
struct Post: Identifiable, Codable {
    let id: String
    let author: User
    let content: String
    let imageURL: URL?
    let likesCount: Int
    let commentsCount: Int
    let createdAt: Date
    var isLiked: Bool
}

struct User: Identifiable, Codable {
    let id: String
    let name: String
    let avatarURL: URL?
}

// 数据服务
protocol PostService {
    func fetchPosts() async throws -> [Post]
    func likePost(id: String) async throws -> Bool
    func unlikePost(id: String) async throws -> Bool
}

class ApiPostService: PostService {
    private let networkClient: NetworkClient
    
    init(networkClient: NetworkClient = NetworkClient.shared) {
        self.networkClient = networkClient
    }
    
    func fetchPosts() async throws -> [Post] {
        return try await networkClient.request(endpoint: .posts)
    }
    
    func likePost(id: String) async throws -> Bool {
        return try await networkClient.request(endpoint: .likePost(id: id))
    }
    
    func unlikePost(id: String) async throws -> Bool {
        return try await networkClient.request(endpoint: .unlikePost(id: id))
    }
}
```

#### 2. 视图模型层

```swift
// 帖子列表 ViewModel
class PostListViewModel: ObservableObject {
    // 输出状态
    enum ViewState {
        case loading
        case loaded([PostCellViewModel])
        case error(String)
        case empty
    }
    
    @Published var state: ViewState = .loading
    @Published var isRefreshing: Bool = false
    
    // 依赖
    private let postService: PostService
    
    // 内部状态
    private var posts: [Post] = []
    
    init(postService: PostService = ApiPostService()) {
        self.postService = postService
    }
    
    // 输入方法
    func loadPosts() {
        if case .loading = state, !isRefreshing { return }
        
        if isRefreshing {
            // 不改变状态，保持当前列表可见
        } else {
            state = .loading
        }
        
        Task {
            do {
                let fetchedPosts = try await postService.fetchPosts()
                await updatePosts(fetchedPosts)
            } catch {
                await setError(error.localizedDescription)
            }
        }
    }
    
    func refresh() {
        isRefreshing = true
        loadPosts()
    }
    
    func toggleLike(for postId: String) {
        guard let index = posts.firstIndex(where: { $0.id == postId }) else { return }
        
        let post = posts[index]
        let isCurrentlyLiked = post.isLiked
        
        // 乐观更新 UI
        var updatedPost = post
        updatedPost.isLiked = !isCurrentlyLiked
        updatedPost.likesCount += isCurrentlyLiked ? -1 : 1
        posts[index] = updatedPost
        
        updateCellViewModels()
        
        // 执行实际网络请求
        Task {
            do {
                let success: Bool
                if isCurrentlyLiked {
                    success = try await postService.unlikePost(id: postId)
                } else {
                    success = try await postService.likePost(id: postId)
                }
                
                if !success {
                    // 如果失败，回滚 UI 更新
                    posts[index] = post
                    await MainActor.run {
                        updateCellViewModels()
                    }
                }
            } catch {
                // 错误处理：回滚 UI 更新
                posts[index] = post
                await MainActor.run {
                    updateCellViewModels()
                }
            }
        }
    }
    
    // 内部辅助方法
    @MainActor
    private func updatePosts(_ newPosts: [Post]) {
        posts = newPosts
        isRefreshing = false
        
        if posts.isEmpty {
            state = .empty
        } else {
            updateCellViewModels()
        }
    }
    
    @MainActor
    private func setError(_ message: String) {
        isRefreshing = false
        state = .error(message)
    }
    
    private func updateCellViewModels() {
        let cellViewModels = posts.map { post in
            PostCellViewModel(
                id: post.id,
                authorName: post.author.name,
                authorAvatarURL: post.author.avatarURL,
                content: post.content,
                imageURL: post.imageURL,
                likesText: "\(post.likesCount) 赞",
                commentsText: "\(post.commentsCount) 评论",
                timeText: formatDate(post.createdAt),
                isLiked: post.isLiked,
                onLikeToggle: { [weak self] in
                    self?.toggleLike(for: post.id)
                }
            )
        }
        
        state = .loaded(cellViewModels)
    }
    
    private func formatDate(_ date: Date) -> String {
        // 格式化日期显示
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}

// 单个帖子的 Cell ViewModel
struct PostCellViewModel: Identifiable {
    let id: String
    let authorName: String
    let authorAvatarURL: URL?
    let content: String
    let imageURL: URL?
    let likesText: String
    let commentsText: String
    let timeText: String
    let isLiked: Bool
    let onLikeToggle: () -> Void
}
```

#### 3. 视图层 (SwiftUI)

```swift
// 帖子列表视图
struct PostListView: View {
    @StateObject var viewModel = PostListViewModel()
    
    var body: some View {
        NavigationView {
            Group {
                switch viewModel.state {
                case .loading:
                    loadingView
                    
                case .loaded(let postViewModels):
                    loadedView(posts: postViewModels)
                    
                case .error(let message):
                    errorView(message: message)
                    
                case .empty:
                    emptyView
                }
            }
            .navigationTitle("动态")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: {
                        viewModel.refresh()
                    }) {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(viewModel.isRefreshing)
                }
            }
            .onAppear {
                viewModel.loadPosts()
            }
        }
    }
    
    // 加载中视图
    private var loadingView: some View {
        VStack {
            ProgressView()
            Text("加载中...")
                .foregroundColor(.secondary)
        }
    }
    
    // 加载完成视图
    private func loadedView(posts: [PostCellViewModel]) -> some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                ForEach(posts) { post in
                    PostCell(viewModel: post)
                        .padding(.horizontal)
                }
            }
            .padding(.vertical)
        }
        .refreshable {
            await withCheckedContinuation { continuation in
                viewModel.refresh()
                continuation.resume()
            }
        }
    }
    
    // 错误视图
    private func errorView(message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle")
                .font(.largeTitle)
                .foregroundColor(.red)
            
            Text("出错了")
                .font(.headline)
            
            Text(message)
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
            
            Button("重试") {
                viewModel.loadPosts()
            }
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(8)
        }
        .padding()
    }
    
    // 空视图
    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "tray")
                .font(.largeTitle)
                .foregroundColor(.secondary)
            
            Text("暂无动态")
                .font(.headline)
            
            Text("关注更多好友，查看他们的动态")
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
        }
        .padding()
    }
}

// 单个帖子单元格
struct PostCell: View {
    let viewModel: PostCellViewModel
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // 作者信息
            HStack {
                AsyncImage(url: viewModel.authorAvatarURL) { image in
                    image.resizable().scaledToFill()
                } placeholder: {
                    Color.gray
                }
                .frame(width: 40, height: 40)
                .clipShape(Circle())
                
                VStack(alignment: .leading, spacing: 2) {
                    Text(viewModel.authorName)
                        .font(.headline)
                    
                    Text(viewModel.timeText)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                
                Spacer()
            }
            
            // 内容
            Text(viewModel.content)
                .font(.body)
            
            // 图片（如果有）
            if let imageURL = viewModel.imageURL {
                AsyncImage(url: imageURL) { image in
                    image
                        .resizable()
                        .scaledToFit()
                } placeholder: {
                    Rectangle()
                        .fill(Color.gray.opacity(0.3))
                        .aspectRatio(16/9, contentMode: .fit)
                }
                .cornerRadius(8)
            }
            
            // 交互按钮
            HStack {
                Button(action: viewModel.onLikeToggle) {
                    HStack {
                        Image(systemName: viewModel.isLiked ? "heart.fill" : "heart")
                            .foregroundColor(viewModel.isLiked ? .red : .gray)
                        
                        Text(viewModel.likesText)
                            .foregroundColor(.secondary)
                    }
                }
                
                Spacer()
                
                HStack {
                    Image(systemName: "bubble.right")
                        .foregroundColor(.gray)
                    
                    Text(viewModel.commentsText)
                        .foregroundColor(.secondary)
                }
            }
            .padding(.top, 8)
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .shadow(color: Color.black.opacity(0.1), radius: 5, x: 0, y: 2)
    }
}
```

#### 4. 案例分析

这个社交媒体帖子列表实现展示了 MVVM 架构的优势：

1. **关注点分离**：
   - 模型层处理数据结构和网络请求
   - 视图模型层处理状态管理和业务逻辑
   - 视图层专注于 UI 展示

2. **状态管理**：
   - ViewModel 使用状态枚举管理不同视图状态
   - 提供细粒度的 UI 更新（如点赞按钮的即时反馈）

3. **业务逻辑**：
   - ViewModel 处理乐观更新逻辑
   - 错误处理和回滚机制
   - 数据格式化（如日期格式化）

4. **可测试性**：
   - ViewModel 可以独立测试，不依赖 UI
   - 使用协议定义服务，便于模拟

5. **代码组织**：
   - 使用子 ViewModel（PostCellViewModel）提高可维护性
   - 清晰的状态更新流程

这个案例展示了如何在实际项目中应用 MVVM 架构，实现清晰、可维护的代码结构。

## 总结与展望

MVVM 架构已经成为现代 iOS 应用开发的主流架构模式之一，尤其在 SwiftUI 的推动下获得了更广泛的应用。

### 主要优势回顾

1. **关注点分离**：MVVM 将应用程序划分为数据模型、视图和视图模型三个明确的层次，每层具有清晰的职责。

2. **可测试性**：视图模型层不依赖于具体的 UI 实现，可以轻松进行单元测试，提高代码质量和可靠性。

3. **代码复用**：视图模型可以在不同的视图间复用，减少代码重复，提高开发效率。

4. **数据绑定**：通过数据绑定机制，实现视图和视图模型之间的自动同步，简化状态管理。

5. **易于维护**：清晰的职责划分和模块化设计，使得代码更易于理解和维护，特别是在大型团队协作中。

### 何时选择 MVVM

MVVM 架构适合以下场景：

- 中大型应用程序，特别是具有复杂用户界面和交互的应用
- 需要高度可测试性的项目
- 使用响应式编程（如 Combine、RxSwift）的项目
- SwiftUI 应用程序（天然适合 MVVM 模式）
- 需要清晰分离 UI 和业务逻辑的项目

对于非常简单的应用或原型，MVC 可能更加简洁直接；而对于特别复杂的大型企业应用，可能需要考虑 Clean Architecture 或 VIPER 等更严格的架构。

### MVVM 的演进趋势

随着 Swift 和 iOS 开发生态的发展，MVVM 架构也在不断演进：

1. **MVVM + Coordinator**：将导航逻辑抽离到协调器中，进一步优化架构。

2. **MVVM + Clean Architecture**：融合 Clean Architecture 的核心原则，增强业务逻辑的独立性。

3. **Unidirectional Data Flow**：受 Redux 和 Flux 架构影响，在 MVVM 中采用单向数据流模式。

4. **Compositional MVVM**：使用组合而非继承，构建更灵活的 MVVM 实现。

5. **声明式 MVVM**：随着 SwiftUI 的普及，MVVM 与声明式 UI 范式结合得更加紧密。

### 实践建议

在实际项目中应用 MVVM 架构时，可以遵循以下建议：

1. **从简单开始**：不要过度设计，根据项目需求选择合适的复杂度。

2. **持续重构**：随着项目发展，定期重构和优化架构，避免架构腐化。

3. **保持一致性**：在团队中建立明确的架构规范和最佳实践，确保一致性。

4. **关注平衡**：在代码复杂度和功能实现之间寻找平衡点，避免过度工程化。

5. **拥抱变化**：随着 Swift 和 iOS 平台的发展，保持对新技术和范式的开放态度。

MVVM 不是银弹，它是一种工具，而非目标本身。最终，好的架构应该服务于项目需求和团队效率，而不是为了架构而架构。通过深入理解 MVVM 的原则和实践，开发者可以灵活应用这一模式，构建出高质量、易维护的 iOS 应用程序。

## 参考资源

### 官方文档
- [Apple Developer Documentation: SwiftUI](https://developer.apple.com/documentation/swiftui)
- [Apple Developer Documentation: Combine](https://developer.apple.com/documentation/combine)

### 推荐书籍
- 《Swift in Depth》by Tjeerd in 't Veen
- 《App Architecture: iOS Application Design Patterns in Swift》by Chris Eidhof, Matt Gallagher, and Florian Kugler
- 《Advanced iOS App Architecture》by Rene Cacheaux and Josh Berlin

### 在线资源
- [objc.io: MVVM](https://www.objc.io/issues/13-architecture/mvvm/)
- [Ray Wenderlich: MVVM in iOS](https://www.raywenderlich.com/34-design-patterns-by-tutorials-mvvm)
- [Hacking with Swift: MVVM with SwiftUI](https://www.hackingwithswift.com/books/ios-swiftui/introducing-mvvm-into-your-swiftui-project)

### 开源项目
- [Kickstarter iOS App](https://github.com/kickstarter/ios-oss) - 使用 MVVM 和响应式编程
- [GitHawk](https://github.com/GitHawkApp/GitHawk) - GitHub 客户端，使用 MVVM 架构
- [SwiftUI 天气应用](https://github.com/AppPear/SwiftUI-Weather) - 简单的 SwiftUI MVVM 示例

通过这些资源，开发者可以进一步深入学习 MVVM 架构，掌握更多高级技巧和最佳实践。