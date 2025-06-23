# MVVM 架构模式

MVVM (Model-View-ViewModel) 是iOS应用开发中广泛使用的架构模式，特别适合与SwiftUI和现代iOS开发实践配合使用。本教程将介绍MVVM的核心概念、优势，以及在iOS项目中的实现方法。

## 目录

- [MVVM 概述](#mvvm-概述)
- [MVVM 组件](#mvvm-组件)
- [MVVM 的优势](#mvvm-的优势)
- [在UIKit中实现MVVM](#在uikit中实现mvvm)
- [在SwiftUI中实现MVVM](#在swiftui中实现mvvm)
- [MVVM与其他架构的比较](#mvvm与其他架构的比较)
- [最佳实践](#最佳实践)
- [常见问题与解决方案](#常见问题与解决方案)

## MVVM 概述

MVVM是一种将应用逻辑与用户界面明确分离的软件架构模式。它通过引入ViewModel作为Model和View之间的中介层，实现关注点分离，提高代码的可测试性和可维护性。

### MVVM的演进

MVVM源于Microsoft的WPF和Silverlight平台，后来被广泛应用于各种前端和移动应用开发中。在iOS开发中，MVVM的普及与响应式编程框架（如RxSwift、Combine）和声明式UI框架（如SwiftUI）的发展紧密相连。

## MVVM 组件

MVVM架构包含三个核心组件：

### Model（模型）

- 表示应用程序的数据和业务逻辑
- 与数据源（如网络API、数据库）交互
- 独立于UI层，不包含任何表现逻辑

```swift
// 典型的Model示例
struct User: Codable {
    let id: String
    let name: String
    let email: String
    let profileImageURL: URL?
    
    // 业务逻辑方法
    func isValidEmail() -> Bool {
        return email.contains("@") && email.contains(".")
    }
}

// 数据服务示例
class UserService {
    func fetchUser(id: String) async throws -> User {
        let url = URL(string: "https://api.example.com/users/\(id)")!
        let (data, _) = try await URLSession.shared.data(from: url)
        return try JSONDecoder().decode(User.self, from: data)
    }
    
    func updateUser(_ user: User) async throws -> Bool {
        // 实现更新用户的网络请求
        return true
    }
}
```

### View（视图）

- 负责UI的展示和用户交互
- 将用户输入传递给ViewModel
- 观察ViewModel状态变化并更新UI
- 尽可能保持"愚蠢"，不包含业务逻辑

#### UIKit中的View

```swift
class ProfileViewController: UIViewController {
    private let viewModel: ProfileViewModel
    
    private let nameLabel = UILabel()
    private let emailLabel = UILabel()
    private let profileImageView = UIImageView()
    private let loadingIndicator = UIActivityIndicatorView()
    
    init(viewModel: ProfileViewModel) {
        self.viewModel = viewModel
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
        viewModel.fetchUserProfile()
    }
    
    private func setupUI() {
        // 设置UI组件布局和样式
    }
    
    private func bindViewModel() {
        viewModel.onStateChange = { [weak self] state in
            DispatchQueue.main.async {
                self?.updateUI(with: state)
            }
        }
    }
    
    private func updateUI(with state: ProfileViewModel.State) {
        switch state {
        case .loading:
            loadingIndicator.startAnimating()
            nameLabel.isHidden = true
            emailLabel.isHidden = true
            
        case .loaded(let user):
            loadingIndicator.stopAnimating()
            nameLabel.isHidden = false
            emailLabel.isHidden = false
            
            nameLabel.text = user.name
            emailLabel.text = user.email
            
            if let imageURL = user.profileImageURL {
                // 加载图片（这里省略实现细节）
            }
            
        case .error(let message):
            loadingIndicator.stopAnimating()
            // 显示错误信息
        }
    }
}
```

#### SwiftUI中的View

```swift
struct ProfileView: View {
    @ObservedObject var viewModel: ProfileViewModel
    
    var body: some View {
        Group {
            switch viewModel.state {
            case .loading:
                ProgressView("加载中...")
                
            case .loaded(let user):
                VStack(alignment: .leading, spacing: 12) {
                    if let imageURL = user.profileImageURL {
                        AsyncImage(url: imageURL) { image in
                            image.resizable().scaledToFit()
                        } placeholder: {
                            Color.gray
                        }
                        .frame(width: 100, height: 100)
                        .clipShape(Circle())
                    }
                    
                    Text(user.name)
                        .font(.title)
                    
                    Text(user.email)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding()
                
            case .error(let message):
                VStack {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.largeTitle)
                    Text("错误: \(message)")
                }
            }
        }
        .onAppear {
            viewModel.fetchUserProfile()
        }
    }
}
```

### ViewModel（视图模型）

- 负责处理View的展示逻辑
- 从Model获取数据并转换为View可以直接使用的格式
- 处理用户交互并更新Model
- 管理View的状态
- 不直接引用View，保持与特定UI框架的独立性

```swift
class ProfileViewModel: ObservableObject {
    enum State {
        case loading
        case loaded(User)
        case error(String)
    }
    
    private let userService: UserService
    private let userId: String
    
    // UIKit中使用闭包通知状态变化
    var onStateChange: ((State) -> Void)?
    
    // SwiftUI中使用@Published属性
    @Published var state: State = .loading
    
    init(userId: String, userService: UserService = UserService()) {
        self.userId = userId
        self.userService = userService
    }
    
    func fetchUserProfile() {
        // 更新状态为加载中
        setState(.loading)
        
        Task {
            do {
                let user = try await userService.fetchUser(id: userId)
                setState(.loaded(user))
            } catch {
                setState(.error(error.localizedDescription))
            }
        }
    }
    
    private func setState(_ newState: State) {
        // 对于UIKit，通过闭包通知状态变化
        onStateChange?(newState)
        
        // 对于SwiftUI，更新@Published属性
        Task { @MainActor in
            state = newState
        }
    }
}
```

## MVVM 的优势

MVVM架构模式提供了多方面的优势：

1. **关注点分离**：将UI逻辑、业务逻辑和数据处理明确分离
2. **可测试性**：ViewModel不依赖于具体UI实现，可以独立测试
3. **代码重用**：相同的ViewModel可以用于不同的视图
4. **可维护性**：代码结构清晰，责任明确，易于维护和扩展
5. **与现代框架兼容**：特别适合SwiftUI和Combine等响应式框架

## 在UIKit中实现MVVM

在UIKit中实现MVVM时，需要手动建立ViewModel和View之间的数据绑定。常用的绑定方式包括：

### 1. 使用闭包进行绑定

```swift
class WeatherViewModel {
    var temperature: String = ""
    var location: String = ""
    var onUpdate: (() -> Void)?
    
    func fetchWeather(for city: String) {
        // 示例：假设这是获取天气数据的网络请求
        // 实际情况下应该使用异步方式处理
        temperature = "25°C"
        location = city
        onUpdate?()
    }
}

class WeatherViewController: UIViewController {
    private let viewModel = WeatherViewModel()
    private let temperatureLabel = UILabel()
    private let locationLabel = UILabel()
    private let refreshButton = UIButton()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
    }
    
    private func setupUI() {
        // 设置UI组件
    }
    
    private func bindViewModel() {
        viewModel.onUpdate = { [weak self] in
            DispatchQueue.main.async {
                self?.temperatureLabel.text = self?.viewModel.temperature
                self?.locationLabel.text = self?.viewModel.location
            }
        }
        
        refreshButton.addTarget(self, action: #selector(refreshTapped), for: .touchUpInside)
    }
    
    @objc private func refreshTapped() {
        viewModel.fetchWeather(for: "北京")
    }
}
```

### 2. 使用Combine框架

```swift
import Combine

class WeatherViewModel {
    @Published var temperature: String = ""
    @Published var location: String = ""
    
    func fetchWeather(for city: String) {
        // 异步获取天气数据
        temperature = "25°C"
        location = city
    }
}

class WeatherViewController: UIViewController {
    private let viewModel = WeatherViewModel()
    private let temperatureLabel = UILabel()
    private let locationLabel = UILabel()
    private let refreshButton = UIButton()
    
    private var cancellables = Set<AnyCancellable>()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        bindViewModel()
    }
    
    private func bindViewModel() {
        viewModel.$temperature
            .receive(on: RunLoop.main)
            .sink { [weak self] temperature in
                self?.temperatureLabel.text = temperature
            }
            .store(in: &cancellables)
        
        viewModel.$location
            .receive(on: RunLoop.main)
            .sink { [weak self] location in
                self?.locationLabel.text = location
            }
            .store(in: &cancellables)
        
        refreshButton.addTarget(self, action: #selector(refreshTapped), for: .touchUpInside)
    }
    
    @objc private func refreshTapped() {
        viewModel.fetchWeather(for: "北京")
    }
}
```

## 在SwiftUI中实现MVVM

SwiftUI天然支持MVVM模式，通过`@ObservedObject`、`@StateObject`和`@Published`等属性包装器实现数据绑定：

```swift
import SwiftUI
import Combine

class WeatherViewModel: ObservableObject {
    @Published var temperature: String = ""
    @Published var location: String = ""
    @Published var isLoading: Bool = false
    
    func fetchWeather(for city: String) {
        isLoading = true
        
        // 模拟网络请求
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            self.temperature = "25°C"
            self.location = city
            self.isLoading = false
        }
    }
}

struct WeatherView: View {
    @StateObject private var viewModel = WeatherViewModel()
    @State private var cityInput: String = ""
    
    var body: some View {
        VStack(spacing: 20) {
            TextField("输入城市", text: $cityInput)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding(.horizontal)
            
            Button("获取天气") {
                viewModel.fetchWeather(for: cityInput)
            }
            .disabled(cityInput.isEmpty || viewModel.isLoading)
            
            if viewModel.isLoading {
                ProgressView()
            } else if !viewModel.temperature.isEmpty {
                Text(viewModel.location)
                    .font(.title)
                
                Text(viewModel.temperature)
                    .font(.largeTitle)
                    .fontWeight(.bold)
            }
            
            Spacer()
        }
        .padding()
    }
}
```

## MVVM与其他架构的比较

### MVVM vs MVC

传统的MVC（Model-View-Controller）架构在iOS中常导致"臃肿的视图控制器"问题，而MVVM通过引入ViewModel层解决了这个问题：

| 特性 | MVC | MVVM |
|------|-----|------|
| 代码分布 | 大量代码集中在Controller | 逻辑分散到ViewModel |
| 测试难度 | 控制器难以测试 | ViewModel易于单元测试 |
| 视图更新 | 通常需要手动刷新 | 数据绑定实现自动更新 |
| 学习曲线 | 简单直观 | 需要理解绑定概念 |
| 适用场景 | 简单小型应用 | 复杂交互应用 |

### MVVM vs VIPER

VIPER（View-Interactor-Presenter-Entity-Router）是一种更复杂的架构模式：

| 特性 | MVVM | VIPER |
|------|------|-------|
| 复杂度 | 中等 | 高 |
| 模块化 | 适中 | 高度模块化 |
| 组件数量 | 三个主要组件 | 五个主要组件 |
| 学习曲线 | 中等 | 陡峭 |
| 适用场景 | 中小型到大型应用 | 大型团队协作项目 |

## 最佳实践

### 1. 保持ViewModel的独立性

ViewModel不应该依赖于具体的UI框架或视图实现：

```swift
// 不好的做法：ViewModel依赖UIKit
class BadViewModel {
    func updateView(_ view: UIView) {
        // 直接操作视图
    }
}

// 好的做法：ViewModel完全独立
class GoodViewModel {
    @Published var title: String = ""
    // 不引用任何UI组件
}
```

### 2. 使用协议定义服务依赖

ViewModel应该通过协议而非具体类依赖服务，便于测试和替换实现：

```swift
protocol WeatherService {
    func fetchWeather(for city: String) async throws -> WeatherData
}

class WeatherViewModel {
    private let weatherService: WeatherService
    
    init(weatherService: WeatherService) {
        self.weatherService = weatherService
    }
    
    func fetchWeather(for city: String) {
        // 使用注入的服务获取数据
    }
}
```

### 3. 避免在ViewModel中保存状态

ViewModel应该表示视图状态，而不是存储应用状态：

```swift
// 不好的做法：在ViewModel中管理全局状态
class UserViewModel {
    static var currentUser: User? // 不应该在这里存储
}

// 好的做法：使用专门的状态管理器
class AppState {
    static let shared = AppState()
    var currentUser: User?
}

class ProfileViewModel {
    @Published var userName: String = ""
    
    func updateFromCurrentUser() {
        if let user = AppState.shared.currentUser {
            userName = user.name
        }
    }
}
```

### 4. 适当使用输入/输出模式

考虑将ViewModel设计为清晰的输入/输出模式：

```swift
class SearchViewModel {
    // 输入
    func search(query: String) {
        performSearch(query)
    }
    
    func loadMore() {
        fetchNextPage()
    }
    
    // 输出
    @Published var results: [SearchResult] = []
    @Published var isLoading: Bool = false
    @Published var error: Error? = nil
    
    private func performSearch(_ query: String) {
        // 实现搜索逻辑
    }
    
    private func fetchNextPage() {
        // 实现分页加载
    }
}
```

## 常见问题与解决方案

### 1. ViewModel过于臃肿

当ViewModel承担过多责任时，可以：
- 拆分为多个小型ViewModel
- 将业务逻辑移至专门的Service层
- 使用UseCase/Interactor处理特定业务流程

### 2. 数据绑定性能问题

对于复杂UI和频繁更新：
- 减少Combine发布者数量
- 使用节流(debounce)或合并(combineLatest)操作符
- 考虑使用细粒度的状态更新而非整体刷新

### 3. 依赖注入复杂性

对于大型应用：
- 考虑使用依赖注入框架
- 实现服务定位器模式
- 使用工厂方法创建ViewModel

## 结论

MVVM是iOS开发中一种平衡灵活性和复杂性的架构模式，特别适合与SwiftUI和Combine框架配合使用。通过正确实现MVVM，可以显著提高代码质量、测试覆盖率和开发效率。

## 延伸阅读

- [Swift与MVVM实战](../advanced/advanced-mvvm.md)
- [响应式编程与MVVM](../async/combine.md)
- [MVVM与依赖注入](../architecture/dependency-injection.md)
- [SwiftUI与MVVM](../ui/swiftui-advanced.md) 