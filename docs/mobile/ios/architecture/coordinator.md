# 协调器模式 - 流程控制与导航

协调器模式（Coordinator Pattern）是一种在 iOS 应用程序开发中用于管理导航流程和控制器之间协调的架构模式。它通过分离导航逻辑和视图控制器的职责，使应用程序的流程控制更加清晰和可维护。本文将详细介绍协调器模式的核心概念、实现方法以及最佳实践。

## 目录

- [协调器模式基础概念](#协调器模式基础概念)
  - [什么是协调器模式](#什么是协调器模式)
  - [为什么需要协调器模式](#为什么需要协调器模式)
  - [协调器模式的核心原则](#协调器模式的核心原则)
  - [协调器模式的优势与挑战](#协调器模式的优势与挑战)
- [协调器的类型与结构](#协调器的类型与结构)
  - [应用协调器](#应用协调器)
  - [流程协调器](#流程协调器)
  - [协调器层次结构](#协调器层次结构)
  - [协调器之间的通信](#协调器之间的通信)
- [实现协调器模式](#实现协调器模式)
  - [基本协调器协议](#基本协调器协议)
  - [协调器的生命周期管理](#协调器的生命周期管理)
  - [视图控制器与协调器的集成](#视图控制器与协调器的集成)
  - [处理回调和数据传递](#处理回调和数据传递)
  - [深度链接和外部导航处理](#深度链接和外部导航处理)
- [协调器模式实战示例](#协调器模式实战示例)
  - [基础示例：简单登录流程](#基础示例简单登录流程)
  - [中级示例：标签栏应用程序](#中级示例标签栏应用程序)
  - [高级示例：复杂电商应用](#高级示例复杂电商应用)
- [与其他架构模式的集成](#与其他架构模式的集成)
  - [协调器 + MVC](#协调器--mvc)
  - [协调器 + MVVM](#协调器--mvvm)
  - [协调器 + VIPER](#协调器--viper)
  - [协调器 + Redux/单向数据流](#协调器--redux单向数据流)
- [协调器模式最佳实践](#协调器模式最佳实践)
  - [依赖注入与协调器](#依赖注入与协调器)
  - [测试协调器](#测试协调器)
  - [内存管理与循环引用](#内存管理与循环引用)
  - [避免协调器过度使用](#避免协调器过度使用)
- [协调器模式在 SwiftUI 中的应用](#协调器模式在-swiftui-中的应用)
  - [SwiftUI 的导航挑战](#swiftui-的导航挑战)
  - [SwiftUI 与 UIKit 协调器的结合](#swiftui-与-uikit-协调器的结合)
  - [纯 SwiftUI 环境中的协调器模式](#纯-swiftui-环境中的协调器模式)
- [常见问题与解决方案](#常见问题与解决方案)
- [总结与展望](#总结与展望)
- [参考资源](#参考资源)

## 协调器模式基础概念

### 什么是协调器模式

协调器模式（Coordinator Pattern）是一种设计模式，旨在解决 iOS 应用程序中导航和流程控制的问题。该模式由 Soroush Khanlou 在 2015 年的 NSSpain 大会上首次提出，并在 iOS 开发社区中获得了广泛的认可和采用。

协调器的核心思想是将应用程序的导航逻辑从视图控制器中分离出来，交由专门的对象（即协调器）来处理。每个协调器负责特定的导航流程或应用程序的特定部分，协调器之间可以组成层次结构，类似于视图控制器的层次结构。

在传统的 iOS 应用程序中，视图控制器通常负责显示内容、处理用户输入以及管理导航。这导致视图控制器变得臃肿，职责不明确。协调器模式通过将导航责任转移到专门的对象，使视图控制器能够专注于其核心职责：管理视图和处理用户交互。

### 为什么需要协调器模式

在传统的 iOS 开发中，我们面临以下几个常见问题，这些问题促使了协调器模式的产生：

1. **视图控制器耦合度高**：视图控制器之间相互了解，导致它们难以单独使用或测试。当一个视图控制器需要导航到另一个视图控制器时，它需要知道如何创建和配置目标视图控制器。

   ```swift
   // 视图控制器之间的直接耦合
   func buttonTapped() {
       let detailVC = DetailViewController()
       detailVC.item = self.selectedItem
       navigationController?.pushViewController(detailVC, animated: true)
   }
   ```

2. **视图控制器职责过多**：除了管理视图和处理用户交互外，视图控制器还需要处理导航逻辑，违反了单一职责原则。

3. **缺乏中心化的导航控制**：导航逻辑分散在各个视图控制器中，难以全局管理应用程序的流程。

4. **流程重用困难**：当需要在应用程序的不同部分重用相同的导航流程时，传统方法需要复制代码。

5. **深度链接处理复杂**：没有专门的对象来处理深度链接，导致处理外部导航请求的代码散布在整个应用程序中。

协调器模式通过引入专门负责导航的对象，解决了上述问题，使应用程序的结构更加清晰，代码更易于维护和测试。

### 协调器模式的核心原则

协调器模式基于以下核心原则：

1. **分离关注点**：将导航逻辑与视图逻辑分离，使每个组件只关注单一职责。

2. **视图控制器独立性**：视图控制器不应该知道它们在应用程序中的位置或如何导航到其他视图控制器。它们应该是自包含的，只关注自己的视图和用户交互。

3. **集中化导航控制**：所有导航决策都由协调器做出，提供了一个中心点来管理应用程序的流程。

4. **协调器层次结构**：协调器可以组成层次结构，类似于视图控制器的层次结构，使复杂导航变得可管理。

5. **松耦合组件**：通过协调器，视图控制器之间不直接通信，而是通过协调器进行通信，降低了耦合度。

6. **可重用流程**：导航流程可以封装在协调器中，在应用程序的不同部分重用。

7. **深度链接支持**：协调器提供了一个自然的方式来处理深度链接，允许应用程序响应外部导航请求。

### 协调器模式的优势与挑战

**优势：**

1. **提高代码组织**：通过明确分离导航逻辑和视图逻辑，使代码结构更清晰。

2. **降低视图控制器复杂度**：视图控制器不再负责导航，可以专注于视图管理和用户交互。

3. **提高组件的可重用性**：视图控制器不再与特定导航流程绑定，可以在不同上下文中重用。

4. **简化流程管理**：协调器为管理应用程序的导航流程提供了一个中心点。

5. **支持复杂导航场景**：协调器层次结构可以处理复杂的导航场景，如多级导航、模态演示和自定义转场。

6. **简化深度链接处理**：协调器为处理深度链接提供了一个自然的方式。

7. **促进单元测试**：由于组件职责明确分离，可以更容易地对视图控制器和协调器进行单独测试。

**挑战：**

1. **额外的抽象层**：引入协调器会增加应用程序的复杂性，特别是对于简单的应用程序。

2. **学习曲线**：协调器模式需要时间来理解和正确实现。

3. **内存管理**：协调器与其子协调器和视图控制器之间的引用关系需要小心管理，以避免内存泄漏。

4. **可能的过度架构**：对于简单的应用程序，协调器模式可能是不必要的过度架构。

5. **SwiftUI 集成挑战**：将协调器模式与 SwiftUI 的声明式导航集成需要额外的工作。

6. **标准化缺乏**：虽然基本概念是一致的，但协调器模式的实现方式有多种变体，缺乏一个标准化的实现。

## 协调器的类型与结构

协调器模式非常灵活，可以根据应用程序的需求采用不同的结构。以下是常见的协调器类型和结构：

### 应用协调器

应用协调器（App Coordinator）是协调器层次结构的根节点，负责管理整个应用程序的高级流程。它通常在应用程序启动时创建，并存在于整个应用程序的生命周期中。

应用协调器的主要职责包括：

1. 决定应用程序的初始导航流程（例如，显示登录界面或主界面）
2. 管理主要的应用程序流程（如登录、注册、主要功能）
3. 处理应用程序级别的事件（如用户登录状态变化）
4. 创建和管理子协调器

```swift
class AppCoordinator: Coordinator {
    private let window: UIWindow
    private var childCoordinators: [Coordinator] = []
    
    init(window: UIWindow) {
        self.window = window
    }
    
    func start() {
        if UserManager.shared.isLoggedIn {
            showMainFlow()
        } else {
            showAuthFlow()
        }
    }
    
    private func showAuthFlow() {
        let authCoordinator = AuthCoordinator(window: window)
        childCoordinators.append(authCoordinator)
        authCoordinator.delegate = self
        authCoordinator.start()
    }
    
    private func showMainFlow() {
        let mainCoordinator = MainCoordinator(window: window)
        childCoordinators.append(mainCoordinator)
        mainCoordinator.start()
    }
}

extension AppCoordinator: AuthCoordinatorDelegate {
    func authCoordinatorDidFinish(_ coordinator: AuthCoordinator) {
        childCoordinators = childCoordinators.filter { $0 !== coordinator }
        showMainFlow()
    }
}
```

### 流程协调器

流程协调器（Flow Coordinator）负责管理应用程序的特定流程或功能区域。它们通常作为应用协调器的子协调器，专注于特定的用户流程，如登录流程、注册流程或产品购买流程。

流程协调器的主要职责包括：

1. 管理流程中的导航逻辑
2. 创建和配置流程中的视图控制器
3. 处理流程中的用户决策和数据传递
4. 通知父协调器流程的完成或中断

```swift
protocol AuthCoordinatorDelegate: AnyObject {
    func authCoordinatorDidFinish(_ coordinator: AuthCoordinator)
}

class AuthCoordinator: Coordinator {
    private let window: UIWindow
    private let navigationController: UINavigationController
    private var childCoordinators: [Coordinator] = []
    
    weak var delegate: AuthCoordinatorDelegate?
    
    init(window: UIWindow) {
        self.window = window
        self.navigationController = UINavigationController()
    }
    
    func start() {
        let loginVC = LoginViewController()
        loginVC.delegate = self
        navigationController.setViewControllers([loginVC], animated: false)
        window.rootViewController = navigationController
        window.makeKeyAndVisible()
    }
    
    private func showRegistration() {
        let registrationVC = RegistrationViewController()
        registrationVC.delegate = self
        navigationController.pushViewController(registrationVC, animated: true)
    }
    
    private func finishAuth() {
        delegate?.authCoordinatorDidFinish(self)
    }
}

extension AuthCoordinator: LoginViewControllerDelegate {
    func loginViewControllerDidTapLogin(_ viewController: LoginViewController, withCredentials credentials: Credentials) {
        // 处理登录逻辑
        UserManager.shared.login(credentials) { [weak self] success in
            if success {
                self?.finishAuth()
            } else {
                // 显示错误
            }
        }
    }
    
    func loginViewControllerDidTapRegister(_ viewController: LoginViewController) {
        showRegistration()
    }
}

extension AuthCoordinator: RegistrationViewControllerDelegate {
    func registrationViewControllerDidRegister(_ viewController: RegistrationViewController) {
        navigationController.popToRootViewController(animated: true)
    }
}
```

### 协调器层次结构

协调器通常组织成层次结构，类似于视图控制器的层次结构。这种层次结构使我们能够将导航逻辑分解为可管理的部分，并支持复杂的导航场景。

典型的协调器层次结构包括：

1. **应用协调器**：作为根协调器，管理整个应用程序
2. **流程协调器**：管理特定流程，如登录、注册、产品浏览
3. **子流程协调器**：管理更具体的子流程，如结账流程中的支付过程

每个协调器负责创建和管理其子协调器，并通过代理模式或闭包与其父协调器通信。

```swift
class MainCoordinator: Coordinator {
    private let window: UIWindow
    private let tabBarController: UITabBarController
    private var childCoordinators: [Coordinator] = []
    
    init(window: UIWindow) {
        self.window = window
        self.tabBarController = UITabBarController()
    }
    
    func start() {
        let homeCoordinator = HomeCoordinator()
        let homeNavigationController = UINavigationController()
        homeCoordinator.navigationController = homeNavigationController
        homeCoordinator.start()
        
        let profileCoordinator = ProfileCoordinator()
        let profileNavigationController = UINavigationController()
        profileCoordinator.navigationController = profileNavigationController
        profileCoordinator.start()
        
        childCoordinators = [homeCoordinator, profileCoordinator]
        
        tabBarController.viewControllers = [homeNavigationController, profileNavigationController]
        window.rootViewController = tabBarController
        window.makeKeyAndVisible()
    }
}
```

### 协调器之间的通信

协调器之间的通信是协调器模式实现中的关键方面。常见的通信机制包括：

1. **代理模式**：子协调器通过代理与父协调器通信
2. **闭包/回调**：父协调器在创建子协调器时传递闭包
3. **通知中心**：对于不直接相关的协调器，可以使用通知中心进行通信
4. **事件总线**：使用集中式事件处理系统
5. **响应式编程**：使用 RxSwift、Combine 等框架实现响应式通信

以下是使用代理模式的示例：

```swift
protocol ProfileCoordinatorDelegate: AnyObject {
    func profileCoordinatorDidRequestLogout(_ coordinator: ProfileCoordinator)
}

class ProfileCoordinator: Coordinator {
    var navigationController: UINavigationController!
    weak var delegate: ProfileCoordinatorDelegate?
    
    func start() {
        let profileVC = ProfileViewController()
        profileVC.delegate = self
        navigationController.viewControllers = [profileVC]
    }
}

extension ProfileCoordinator: ProfileViewControllerDelegate {
    func profileViewControllerDidTapLogout(_ viewController: ProfileViewController) {
        delegate?.profileCoordinatorDidRequestLogout(self)
    }
}
```

使用闭包的示例：

```swift
class CheckoutCoordinator: Coordinator {
    var navigationController: UINavigationController!
    var onFinish: ((Bool) -> Void)?
    
    func start() {
        let checkoutVC = CheckoutViewController()
        checkoutVC.delegate = self
        navigationController.pushViewController(checkoutVC, animated: true)
    }
}

extension CheckoutCoordinator: CheckoutViewControllerDelegate {
    func checkoutViewControllerDidComplete(_ viewController: CheckoutViewController) {
        navigationController.popViewController(animated: true)
        onFinish?(true)
    }
    
    func checkoutViewControllerDidCancel(_ viewController: CheckoutViewController) {
        navigationController.popViewController(animated: true)
        onFinish?(false)
    }
}

// 使用闭包
let checkoutCoordinator = CheckoutCoordinator()
checkoutCoordinator.navigationController = navigationController
checkoutCoordinator.onFinish = { success in
    if success {
        // 处理成功结账
    } else {
        // 处理取消结账
    }
}
checkoutCoordinator.start()
```

## 实现协调器模式

实现协调器模式需要考虑多个方面，从基本协议定义到生命周期管理和与视图控制器的集成。以下是协调器模式实现的关键部分：

### 基本协调器协议

协调器模式的实现通常从定义一个基本协议开始，该协议声明所有协调器共有的方法和属性。最基本的协调器协议可能如下所示：

```swift
protocol Coordinator: AnyObject {
    func start()
}
```

这个简单的协议只有一个方法 `start()`，它是协调器的入口点，负责启动协调器管理的流程。根据应用程序的需求，协调器协议可以扩展为包含更多功能：

```swift
protocol Coordinator: AnyObject {
    var childCoordinators: [Coordinator] { get set }
    var navigationController: UINavigationController { get set }
    
    func start()
    func addChildCoordinator(_ coordinator: Coordinator)
    func removeChildCoordinator(_ coordinator: Coordinator)
}

extension Coordinator {
    func addChildCoordinator(_ coordinator: Coordinator) {
        childCoordinators.append(coordinator)
    }
    
    func removeChildCoordinator(_ coordinator: Coordinator) {
        childCoordinators = childCoordinators.filter { $0 !== coordinator }
    }
}
```

这个扩展版本的协议添加了管理子协调器的功能，以及对导航控制器的引用。这使得协调器可以组织成层次结构，并通过导航控制器来控制视图的展示。

对于不同类型的协调器，可能需要更具体的协议：

```swift
protocol FlowCoordinator: Coordinator {
    associatedtype Result
    var completion: ((Result) -> Void)? { get set }
}
```

这个协议适用于需要返回结果的流程协调器，例如表单流程或身份验证流程。

### 协调器的生命周期管理

协调器的生命周期管理是实现协调器模式时的关键考虑因素。以下是一些管理协调器生命周期的常见方法：

1. **父子关系**：父协调器负责创建和存储对子协调器的引用，确保子协调器在流程完成前不会被释放。

```swift
class ParentCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        // 启动流程
    }
    
    func startChildFlow() {
        let childCoordinator = ChildCoordinator(navigationController: navigationController)
        childCoordinators.append(childCoordinator)
        childCoordinator.parentCoordinator = self
        childCoordinator.start()
    }
    
    func childDidFinish(_ child: Coordinator) {
        // 移除对子协调器的引用
        for (index, coordinator) in childCoordinators.enumerated() {
            if coordinator === child {
                childCoordinators.remove(at: index)
                break
            }
        }
    }
}

class ChildCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    weak var parentCoordinator: ParentCoordinator?
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        // 启动子流程
    }
    
    func finish() {
        // 通知父协调器流程完成
        parentCoordinator?.childDidFinish(self)
    }
}
```

2. **使用闭包**：流程完成后通过闭包通知父协调器，并让父协调器移除对子协调器的引用。

```swift
class ParentCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        // 启动流程
    }
    
    func startChildFlow() {
        let childCoordinator = ChildCoordinator(navigationController: navigationController)
        childCoordinators.append(childCoordinator)
        
        childCoordinator.onFinish = { [weak self, weak childCoordinator] in
            guard let self = self, let childCoordinator = childCoordinator else { return }
            self.removeChildCoordinator(childCoordinator)
        }
        
        childCoordinator.start()
    }
}

class ChildCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    var onFinish: (() -> Void)?
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        // 启动子流程
    }
    
    func finish() {
        // 通知流程完成
        onFinish?()
    }
}
```

3. **使用代理模式**：定义协调器代理协议，让父协调器实现该协议来接收子协调器的事件。

```swift
protocol ChildCoordinatorDelegate: AnyObject {
    func childCoordinatorDidFinish(_ coordinator: ChildCoordinator)
}

class ParentCoordinator: Coordinator, ChildCoordinatorDelegate {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        // 启动流程
    }
    
    func startChildFlow() {
        let childCoordinator = ChildCoordinator(navigationController: navigationController)
        childCoordinators.append(childCoordinator)
        childCoordinator.delegate = self
        childCoordinator.start()
    }
    
    // ChildCoordinatorDelegate 实现
    func childCoordinatorDidFinish(_ coordinator: ChildCoordinator) {
        removeChildCoordinator(coordinator)
    }
}

class ChildCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    weak var delegate: ChildCoordinatorDelegate?
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        // 启动子流程
    }
    
    func finish() {
        // 通知代理流程完成
        delegate?.childCoordinatorDidFinish(self)
    }
}
```

### 视图控制器与协调器的集成

协调器模式的一个关键方面是视图控制器与协调器之间的通信。视图控制器需要一种方式来通知协调器导航事件，而不直接处理导航逻辑。常见的集成方法包括：

1. **使用代理模式**：定义视图控制器代理协议，让协调器实现该协议。

```swift
protocol LoginViewControllerDelegate: AnyObject {
    func loginViewControllerDidTapLogin(_ viewController: LoginViewController, withCredentials credentials: Credentials)
    func loginViewControllerDidTapForgotPassword(_ viewController: LoginViewController)
    func loginViewControllerDidTapRegister(_ viewController: LoginViewController)
}

class LoginViewController: UIViewController {
    weak var delegate: LoginViewControllerDelegate?
    
    // UI 组件和用户交互逻辑
    
    @objc private func loginButtonTapped() {
        let credentials = Credentials(username: usernameTextField.text ?? "", password: passwordTextField.text ?? "")
        delegate?.loginViewControllerDidTapLogin(self, withCredentials: credentials)
    }
    
    @objc private func forgotPasswordButtonTapped() {
        delegate?.loginViewControllerDidTapForgotPassword(self)
    }
    
    @objc private func registerButtonTapped() {
        delegate?.loginViewControllerDidTapRegister(self)
    }
}

class AuthCoordinator: Coordinator, LoginViewControllerDelegate {
    // 协调器实现
    
    func showLogin() {
        let loginVC = LoginViewController()
        loginVC.delegate = self
        navigationController.pushViewController(loginVC, animated: true)
    }
    
    // LoginViewControllerDelegate 实现
    func loginViewControllerDidTapLogin(_ viewController: LoginViewController, withCredentials credentials: Credentials) {
        // 处理登录逻辑
    }
    
    func loginViewControllerDidTapForgotPassword(_ viewController: LoginViewController) {
        showForgotPassword()
    }
    
    func loginViewControllerDidTapRegister(_ viewController: LoginViewController) {
        showRegistration()
    }
}
```

2. **使用闭包/回调**：视图控制器通过闭包通知事件。

```swift
class LoginViewController: UIViewController {
    var onLoginTapped: ((Credentials) -> Void)?
    var onForgotPasswordTapped: (() -> Void)?
    var onRegisterTapped: (() -> Void)?
    
    // UI 组件和用户交互逻辑
    
    @objc private func loginButtonTapped() {
        let credentials = Credentials(username: usernameTextField.text ?? "", password: passwordTextField.text ?? "")
        onLoginTapped?(credentials)
    }
    
    @objc private func forgotPasswordButtonTapped() {
        onForgotPasswordTapped?()
    }
    
    @objc private func registerButtonTapped() {
        onRegisterTapped?()
    }
}

class AuthCoordinator: Coordinator {
    // 协调器实现
    
    func showLogin() {
        let loginVC = LoginViewController()
        
        loginVC.onLoginTapped = { [weak self] credentials in
            self?.handleLogin(credentials)
        }
        
        loginVC.onForgotPasswordTapped = { [weak self] in
            self?.showForgotPassword()
        }
        
        loginVC.onRegisterTapped = { [weak self] in
            self?.showRegistration()
        }
        
        navigationController.pushViewController(loginVC, animated: true)
    }
}
```

3. **使用通知中心**：对于不直接相关的组件，可以使用通知中心。

```swift
extension Notification.Name {
    static let userDidTapLogin = Notification.Name("userDidTapLogin")
    static let userDidTapForgotPassword = Notification.Name("userDidTapForgotPassword")
    static let userDidTapRegister = Notification.Name("userDidTapRegister")
}

class LoginViewController: UIViewController {
    // UI 组件和用户交互逻辑
    
    @objc private func loginButtonTapped() {
        let credentials = Credentials(username: usernameTextField.text ?? "", password: passwordTextField.text ?? "")
        NotificationCenter.default.post(name: .userDidTapLogin, object: nil, userInfo: ["credentials": credentials])
    }
    
    @objc private func forgotPasswordButtonTapped() {
        NotificationCenter.default.post(name: .userDidTapForgotPassword, object: nil)
    }
    
    @objc private func registerButtonTapped() {
        NotificationCenter.default.post(name: .userDidTapRegister, object: nil)
    }
}

class AuthCoordinator: Coordinator {
    // 协调器实现
    
    func start() {
        // 注册通知
        NotificationCenter.default.addObserver(self, selector: #selector(handleLoginTapped(_:)), name: .userDidTapLogin, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(handleForgotPasswordTapped), name: .userDidTapForgotPassword, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(handleRegisterTapped), name: .userDidTapRegister, object: nil)
        
        showLogin()
    }
    
    @objc private func handleLoginTapped(_ notification: Notification) {
        if let credentials = notification.userInfo?["credentials"] as? Credentials {
            // 处理登录逻辑
        }
    }
    
    @objc private func handleForgotPasswordTapped() {
        showForgotPassword()
    }
    
    @objc private func handleRegisterTapped() {
        showRegistration()
    }
}
```

### 处理回调和数据传递

在协调器模式中，处理回调和数据传递是一个常见的需求。例如，当用户完成登录流程后，需要将登录结果传递回应用协调器。以下是一些常见的方法：

1. **使用代理模式**：

```swift
protocol AuthCoordinatorDelegate: AnyObject {
    func authCoordinatorDidFinishWithSuccess(_ coordinator: AuthCoordinator, user: User)
    func authCoordinatorDidFinishWithCancellation(_ coordinator: AuthCoordinator)
}

class AuthCoordinator: Coordinator {
    weak var delegate: AuthCoordinatorDelegate?
    
    // 流程完成时调用
    func finishWithSuccess(user: User) {
        delegate?.authCoordinatorDidFinishWithSuccess(self, user: user)
    }
    
    func finishWithCancellation() {
        delegate?.authCoordinatorDidFinishWithCancellation(self)
    }
}

class AppCoordinator: Coordinator, AuthCoordinatorDelegate {
    // 实现 AuthCoordinatorDelegate
    
    func authCoordinatorDidFinishWithSuccess(_ coordinator: AuthCoordinator, user: User) {
        // 保存用户信息
        userManager.currentUser = user
        // 移除子协调器
        removeChildCoordinator(coordinator)
        // 显示主界面
        showMainFlow()
    }
    
    func authCoordinatorDidFinishWithCancellation(_ coordinator: AuthCoordinator) {
        removeChildCoordinator(coordinator)
        // 可能显示欢迎界面或执行其他操作
    }
}
```

2. **使用闭包**：

```swift
class AuthCoordinator: Coordinator {
    var onFinishWithSuccess: ((User) -> Void)?
    var onFinishWithCancellation: (() -> Void)?
    
    // 流程完成时调用
    func finishWithSuccess(user: User) {
        onFinishWithSuccess?(user)
    }
    
    func finishWithCancellation() {
        onFinishWithCancellation?()
    }
}

class AppCoordinator: Coordinator {
    func showAuthFlow() {
        let authCoordinator = AuthCoordinator(navigationController: UINavigationController())
        
        authCoordinator.onFinishWithSuccess = { [weak self, weak authCoordinator] user in
            guard let self = self, let authCoordinator = authCoordinator else { return }
            // 保存用户信息
            self.userManager.currentUser = user
            // 移除子协调器
            self.removeChildCoordinator(authCoordinator)
            // 显示主界面
            self.showMainFlow()
        }
        
        authCoordinator.onFinishWithCancellation = { [weak self, weak authCoordinator] in
            guard let self = self, let authCoordinator = authCoordinator else { return }
            self.removeChildCoordinator(authCoordinator)
            // 可能显示欢迎界面或执行其他操作
        }
        
        addChildCoordinator(authCoordinator)
        authCoordinator.start()
        window.rootViewController = authCoordinator.navigationController
    }
}
```

3. **使用响应式编程**：

```swift
import Combine

class AuthCoordinator: Coordinator {
    let finishSubject = PassthroughSubject<AuthResult, Never>()
    
    enum AuthResult {
        case success(User)
        case cancellation
    }
    
    // 流程完成时调用
    func finishWithSuccess(user: User) {
        finishSubject.send(.success(user))
    }
    
    func finishWithCancellation() {
        finishSubject.send(.cancellation)
    }
}

class AppCoordinator: Coordinator {
    private var cancellables = Set<AnyCancellable>()
    
    func showAuthFlow() {
        let authCoordinator = AuthCoordinator(navigationController: UINavigationController())
        
        authCoordinator.finishSubject
            .sink { [weak self, weak authCoordinator] result in
                guard let self = self, let authCoordinator = authCoordinator else { return }
                
                switch result {
                case .success(let user):
                    // 保存用户信息
                    self.userManager.currentUser = user
                    // 显示主界面
                    self.showMainFlow()
                case .cancellation:
                    // 可能显示欢迎界面或执行其他操作
                    break
                }
                
                // 移除子协调器
                self.removeChildCoordinator(authCoordinator)
            }
            .store(in: &cancellables)
        
        addChildCoordinator(authCoordinator)
        authCoordinator.start()
        window.rootViewController = authCoordinator.navigationController
    }
}
```

### 深度链接和外部导航处理

协调器模式为处理深度链接和外部导航请求提供了一个自然的方式。应用协调器可以接收深度链接 URL，然后将导航请求路由到适当的子协调器。

```swift
class AppCoordinator: Coordinator {
    // 应用协调器实现
    
    func handleDeepLink(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else { return }
        
        // 解析路径和参数
        let path = components.path
        let queryItems = components.queryItems ?? []
        
        // 根据路径路由到适当的协调器
        switch path {
        case "/products":
            // 导航到产品列表
            if let categoryItem = queryItems.first(where: { $0.name == "category" }),
               let category = categoryItem.value {
                navigateToProductList(category: category)
            } else {
                navigateToProductList()
            }
            
        case "/products/details":
            // 导航到产品详情
            if let productIdItem = queryItems.first(where: { $0.name == "id" }),
               let productId = productIdItem.value {
                navigateToProductDetails(productId: productId)
            }
            
        case "/cart":
            // 导航到购物车
            navigateToCart()
            
        case "/orders":
            // 导航到订单历史
            navigateToOrderHistory()
            
        default:
            // 未识别的路径
            break
        }
    }
    
    // 导航方法
    private func navigateToProductList(category: String? = nil) {
        // 导航到产品列表，可能需要切换到特定标签，然后推入产品列表视图控制器
    }
    
    private func navigateToProductDetails(productId: String) {
        // 导航到产品详情
    }
    
    private func navigateToCart() {
        // 导航到购物车
    }
    
    private func navigateToOrderHistory() {
        // 导航到订单历史
    }
}

// 在 SceneDelegate 或 AppDelegate 中
func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    guard let url = URLContexts.first?.url else { return }
    appCoordinator.handleDeepLink(url)
}
```

这种方法使深度链接处理集中在应用协调器中，而不是分散在多个视图控制器中。应用协调器可以根据 URL 的路径和参数，决定如何导航到应用程序的适当部分。

## 协调器模式实战示例

为了更好地理解协调器模式的实际应用，让我们通过一些实际示例来探索它的实现。

### 基础示例：简单登录流程

让我们从一个简单的登录流程开始，这是协调器模式的一个常见应用场景。登录流程包括登录页面、注册页面和忘记密码页面。

#### 1. 定义协调器协议

首先，定义基本的协调器协议：

```swift
protocol Coordinator: AnyObject {
    var childCoordinators: [Coordinator] { get set }
    var navigationController: UINavigationController { get set }
    
    func start()
}

extension Coordinator {
    func addChildCoordinator(_ coordinator: Coordinator) {
        childCoordinators.append(coordinator)
    }
    
    func removeChildCoordinator(_ coordinator: Coordinator) {
        childCoordinators = childCoordinators.filter { $0 !== coordinator }
    }
}
```

#### 2. 创建身份验证协调器

接下来，创建管理身份验证流程的协调器：

```swift
protocol AuthCoordinatorDelegate: AnyObject {
    func authCoordinatorDidFinishWithSuccess(_ coordinator: AuthCoordinator)
    func authCoordinatorDidFinishWithCancellation(_ coordinator: AuthCoordinator)
}

class AuthCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    weak var delegate: AuthCoordinatorDelegate?
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        showLogin()
    }
    
    private func showLogin() {
        let loginVC = LoginViewController()
        loginVC.delegate = self
        navigationController.viewControllers = [loginVC]
    }
    
    private func showRegistration() {
        let registrationVC = RegistrationViewController()
        registrationVC.delegate = self
        navigationController.pushViewController(registrationVC, animated: true)
    }
    
    private func showForgotPassword() {
        let forgotPasswordVC = ForgotPasswordViewController()
        forgotPasswordVC.delegate = self
        navigationController.pushViewController(forgotPasswordVC, animated: true)
    }
    
    private func finishWithSuccess() {
        delegate?.authCoordinatorDidFinishWithSuccess(self)
    }
    
    private func finishWithCancellation() {
        delegate?.authCoordinatorDidFinishWithCancellation(self)
    }
}
```

#### 3. 定义视图控制器代理

为每个视图控制器定义代理协议，使它们能够与协调器通信：

```swift
protocol LoginViewControllerDelegate: AnyObject {
    func loginViewControllerDidTapLogin(_ viewController: LoginViewController, withCredentials credentials: Credentials)
    func loginViewControllerDidTapRegister(_ viewController: LoginViewController)
    func loginViewControllerDidTapForgotPassword(_ viewController: LoginViewController)
    func loginViewControllerDidTapCancel(_ viewController: LoginViewController)
}

protocol RegistrationViewControllerDelegate: AnyObject {
    func registrationViewControllerDidTapRegister(_ viewController: RegistrationViewController, withUserInfo userInfo: UserInfo)
    func registrationViewControllerDidTapCancel(_ viewController: RegistrationViewController)
}

protocol ForgotPasswordViewControllerDelegate: AnyObject {
    func forgotPasswordViewControllerDidTapSubmit(_ viewController: ForgotPasswordViewController, withEmail email: String)
    func forgotPasswordViewControllerDidTapCancel(_ viewController: ForgotPasswordViewController)
}
```

#### 4. 实现视图控制器

实现各个视图控制器，让它们通过代理与协调器通信：

```swift
class LoginViewController: UIViewController {
    weak var delegate: LoginViewControllerDelegate?
    
    private let usernameTextField = UITextField()
    private let passwordTextField = UITextField()
    private let loginButton = UIButton()
    private let registerButton = UIButton()
    private let forgotPasswordButton = UIButton()
    private let cancelButton = UIButton()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    private func setupUI() {
        title = "登录"
        view.backgroundColor = .white
        
        // 设置文本字段
        usernameTextField.placeholder = "用户名"
        usernameTextField.borderStyle = .roundedRect
        usernameTextField.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(usernameTextField)
        
        passwordTextField.placeholder = "密码"
        passwordTextField.borderStyle = .roundedRect
        passwordTextField.isSecureTextEntry = true
        passwordTextField.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(passwordTextField)
        
        // 设置按钮
        loginButton.setTitle("登录", for: .normal)
        loginButton.backgroundColor = .systemBlue
        loginButton.setTitleColor(.white, for: .normal)
        loginButton.layer.cornerRadius = 5
        loginButton.addTarget(self, action: #selector(loginButtonTapped), for: .touchUpInside)
        loginButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(loginButton)
        
        registerButton.setTitle("注册新账号", for: .normal)
        registerButton.setTitleColor(.systemBlue, for: .normal)
        registerButton.addTarget(self, action: #selector(registerButtonTapped), for: .touchUpInside)
        registerButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(registerButton)
        
        forgotPasswordButton.setTitle("忘记密码?", for: .normal)
        forgotPasswordButton.setTitleColor(.systemBlue, for: .normal)
        forgotPasswordButton.addTarget(self, action: #selector(forgotPasswordButtonTapped), for: .touchUpInside)
        forgotPasswordButton.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(forgotPasswordButton)
        
        // 如果需要取消按钮
        if navigationController?.viewControllers.first !== self {
            navigationItem.leftBarButtonItem = UIBarButtonItem(title: "取消", style: .plain, target: self, action: #selector(cancelButtonTapped))
        }
        
        // 设置约束
        NSLayoutConstraint.activate([
            usernameTextField.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 100),
            usernameTextField.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            usernameTextField.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            usernameTextField.heightAnchor.constraint(equalToConstant: 44),
            
            passwordTextField.topAnchor.constraint(equalTo: usernameTextField.bottomAnchor, constant: 20),
            passwordTextField.leadingAnchor.constraint(equalTo: usernameTextField.leadingAnchor),
            passwordTextField.trailingAnchor.constraint(equalTo: usernameTextField.trailingAnchor),
            passwordTextField.heightAnchor.constraint(equalToConstant: 44),
            
            loginButton.topAnchor.constraint(equalTo: passwordTextField.bottomAnchor, constant: 30),
            loginButton.leadingAnchor.constraint(equalTo: passwordTextField.leadingAnchor),
            loginButton.trailingAnchor.constraint(equalTo: passwordTextField.trailingAnchor),
            loginButton.heightAnchor.constraint(equalToConstant: 44),
            
            registerButton.topAnchor.constraint(equalTo: loginButton.bottomAnchor, constant: 20),
            registerButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            
            forgotPasswordButton.topAnchor.constraint(equalTo: registerButton.bottomAnchor, constant: 20),
            forgotPasswordButton.centerXAnchor.constraint(equalTo: view.centerXAnchor)
        ])
    }
    
    @objc private func loginButtonTapped() {
        let credentials = Credentials(
            username: usernameTextField.text ?? "",
            password: passwordTextField.text ?? ""
        )
        delegate?.loginViewControllerDidTapLogin(self, withCredentials: credentials)
    }
    
    @objc private func registerButtonTapped() {
        delegate?.loginViewControllerDidTapRegister(self)
    }
    
    @objc private func forgotPasswordButtonTapped() {
        delegate?.loginViewControllerDidTapForgotPassword(self)
    }
    
    @objc private func cancelButtonTapped() {
        delegate?.loginViewControllerDidTapCancel(self)
    }
}

// 实现其他视图控制器（RegistrationViewController 和 ForgotPasswordViewController）类似，略过...
```

#### 5. 实现协调器代理方法

让协调器实现视图控制器的代理方法：

```swift
extension AuthCoordinator: LoginViewControllerDelegate {
    func loginViewControllerDidTapLogin(_ viewController: LoginViewController, withCredentials credentials: Credentials) {
        // 在实际应用中，这里会调用认证服务进行登录
        print("登录尝试: \(credentials.username)")
        
        // 模拟登录成功
        finishWithSuccess()
    }
    
    func loginViewControllerDidTapRegister(_ viewController: LoginViewController) {
        showRegistration()
    }
    
    func loginViewControllerDidTapForgotPassword(_ viewController: LoginViewController) {
        showForgotPassword()
    }
    
    func loginViewControllerDidTapCancel(_ viewController: LoginViewController) {
        finishWithCancellation()
    }
}

extension AuthCoordinator: RegistrationViewControllerDelegate {
    func registrationViewControllerDidTapRegister(_ viewController: RegistrationViewController, withUserInfo userInfo: UserInfo) {
        // 在实际应用中，这里会调用服务进行注册
        print("注册尝试: \(userInfo.username)")
        
        // 注册成功后返回到登录页面
        navigationController.popToRootViewController(animated: true)
    }
    
    func registrationViewControllerDidTapCancel(_ viewController: RegistrationViewController) {
        navigationController.popViewController(animated: true)
    }
}

extension AuthCoordinator: ForgotPasswordViewControllerDelegate {
    func forgotPasswordViewControllerDidTapSubmit(_ viewController: ForgotPasswordViewController, withEmail email: String) {
        // 在实际应用中，这里会调用服务发送重置密码邮件
        print("重置密码尝试: \(email)")
        
        // 提交后返回到登录页面
        navigationController.popViewController(animated: true)
    }
    
    func forgotPasswordViewControllerDidTapCancel(_ viewController: ForgotPasswordViewController) {
        navigationController.popViewController(animated: true)
    }
}
```

#### 6. 创建应用协调器

最后，创建应用协调器，启动身份验证流程：

```swift
class AppCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    var window: UIWindow
    
    init(window: UIWindow) {
        self.window = window
        self.navigationController = UINavigationController()
    }
    
    func start() {
        window.rootViewController = navigationController
        window.makeKeyAndVisible()
        
        if UserDefaults.standard.bool(forKey: "isLoggedIn") {
            showMainFlow()
        } else {
            showAuthFlow()
        }
    }
    
    private func showAuthFlow() {
        let authCoordinator = AuthCoordinator(navigationController: navigationController)
        authCoordinator.delegate = self
        addChildCoordinator(authCoordinator)
        authCoordinator.start()
    }
    
    private func showMainFlow() {
        // 在实际应用中，这里会启动主要流程
        let mainViewController = UIViewController()
        mainViewController.view.backgroundColor = .white
        mainViewController.title = "主页"
        
        let logoutButton = UIButton(type: .system)
        logoutButton.setTitle("退出登录", for: .normal)
        logoutButton.addTarget(self, action: #selector(logoutButtonTapped), for: .touchUpInside)
        logoutButton.translatesAutoresizingMaskIntoConstraints = false
        
        mainViewController.view.addSubview(logoutButton)
        NSLayoutConstraint.activate([
            logoutButton.centerXAnchor.constraint(equalTo: mainViewController.view.centerXAnchor),
            logoutButton.centerYAnchor.constraint(equalTo: mainViewController.view.centerYAnchor)
        ])
        
        navigationController.viewControllers = [mainViewController]
    }
    
    @objc private func logoutButtonTapped() {
        UserDefaults.standard.set(false, forKey: "isLoggedIn")
        showAuthFlow()
    }
}

extension AppCoordinator: AuthCoordinatorDelegate {
    func authCoordinatorDidFinishWithSuccess(_ coordinator: AuthCoordinator) {
        UserDefaults.standard.set(true, forKey: "isLoggedIn")
        removeChildCoordinator(coordinator)
        showMainFlow()
    }
    
    func authCoordinatorDidFinishWithCancellation(_ coordinator: AuthCoordinator) {
        // 在真实场景中，可能会关闭应用程序或显示欢迎页面
        removeChildCoordinator(coordinator)
    }
}
```

#### 7. 在应用程序入口点设置

在 `SceneDelegate` 或 `AppDelegate` 中设置应用协调器：

```swift
class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    var appCoordinator: AppCoordinator?
    
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = scene as? UIWindowScene else { return }
        
        let window = UIWindow(windowScene: windowScene)
        appCoordinator = AppCoordinator(window: window)
        appCoordinator?.start()
        
        self.window = window
    }
}
```

这个基础示例展示了协调器模式的核心概念：

1. 协调器负责导航逻辑和流程控制
2. 视图控制器只关注视图展示和用户交互
3. 视图控制器通过代理与协调器通信
4. 协调器通过层次结构组织，每个协调器负责特定流程
5. 协调器之间通过代理模式通信

通过这种方式，导航逻辑被集中在协调器中，而不是分散在各个视图控制器中。这使得代码更加模块化，更容易维护和测试。

### 中级示例：标签栏应用程序

标签栏应用程序是 iOS 中常见的应用类型，它通常包含多个标签，每个标签代表应用程序的一个主要功能区域。下面是如何使用协调器模式组织标签栏应用程序的示例：

### 高级示例：复杂电商应用

## 与其他架构模式的集成

协调器模式专注于解决导航和流程控制的问题，它可以与其他专注于视图-模型交互的架构模式（如 MVC、MVVM 和 VIPER）结合使用。以下是协调器模式与其他常见架构模式的集成方法：

### 协调器 + MVC

MVC（模型-视图-控制器）是 iOS 开发中最传统的架构模式。MVC 和协调器模式可以很好地结合使用：

- **模型 (Model)**: 数据和业务逻辑
- **视图 (View)**: 用户界面
- **控制器 (Controller)**: 协调模型和视图
- **协调器 (Coordinator)**: 管理导航和流程

在这种组合中，视图控制器负责处理视图和模型之间的交互，而协调器负责处理视图控制器之间的导航。这减轻了视图控制器的职责，使其更专注于其核心任务。

```swift
// MVC + Coordinator 示例

// 模型
struct Product {
    let id: String
    let name: String
    let price: Double
    let description: String
}

// 视图控制器（Controller）
class ProductListViewController: UIViewController {
    private var products: [Product] = []
    weak var delegate: ProductListViewControllerDelegate?
    
    // 视图和用户交互逻辑
    
    func setProducts(_ products: [Product]) {
        self.products = products
        tableView.reloadData()
    }
    
    @objc private func addButtonTapped() {
        delegate?.productListViewControllerDidTapAddProduct(self)
    }
}

protocol ProductListViewControllerDelegate: AnyObject {
    func productListViewController(_ viewController: ProductListViewController, didSelectProduct product: Product)
    func productListViewControllerDidTapAddProduct(_ viewController: ProductListViewController)
}

// 协调器
class ProductCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    private let productService: ProductService
    
    init(navigationController: UINavigationController, productService: ProductService) {
        self.navigationController = navigationController
        self.productService = productService
    }
    
    func start() {
        let productListVC = ProductListViewController()
        productListVC.delegate = self
        
        // 从服务获取产品数据
        productService.fetchProducts { products in
            productListVC.setProducts(products)
        }
        
        navigationController.pushViewController(productListVC, animated: false)
    }
    
    private func showProductDetails(product: Product) {
        let productDetailsVC = ProductDetailsViewController()
        productDetailsVC.delegate = self
        productDetailsVC.product = product
        navigationController.pushViewController(productDetailsVC, animated: true)
    }
    
    private func showAddProduct() {
        let addProductVC = AddProductViewController()
        addProductVC.delegate = self
        navigationController.pushViewController(addProductVC, animated: true)
    }
}

extension ProductCoordinator: ProductListViewControllerDelegate {
    func productListViewController(_ viewController: ProductListViewController, didSelectProduct product: Product) {
        showProductDetails(product: product)
    }
    
    func productListViewControllerDidTapAddProduct(_ viewController: ProductListViewController) {
        showAddProduct()
    }
}
```

### 协调器 + MVVM

MVVM（模型-视图-视图模型）是一种流行的架构模式，它引入了视图模型层来协调视图和模型。MVVM 和协调器模式的结合可以提供清晰的职责分离：

- **模型 (Model)**: 数据和业务逻辑
- **视图 (View)**: 用户界面（包括视图控制器）
- **视图模型 (ViewModel)**: 视图的状态和行为
- **协调器 (Coordinator)**: 管理导航和流程

在这种组合中，视图模型负责将模型数据转换为视图可以直接使用的形式，而协调器负责管理应用程序的导航流程。

```swift
// MVVM + Coordinator 示例

// 模型
struct Product {
    let id: String
    let name: String
    let price: Double
    let description: String
}

// 视图模型
class ProductListViewModel {
    private let productService: ProductService
    private var products: [Product] = []
    
    // 使用 Combine 框架创建可观察属性
    @Published var productViewModels: [ProductViewModel] = []
    @Published var isLoading = false
    @Published var error: Error?
    
    init(productService: ProductService) {
        self.productService = productService
    }
    
    func loadProducts() {
        isLoading = true
        
        productService.fetchProducts { [weak self] result in
            guard let self = self else { return }
            
            self.isLoading = false
            
            switch result {
            case .success(let products):
                self.products = products
                self.productViewModels = products.map { ProductViewModel(product: $0) }
            case .failure(let error):
                self.error = error
            }
        }
    }
    
    func product(at index: Int) -> Product {
        return products[index]
    }
}

struct ProductViewModel {
    let id: String
    let name: String
    let formattedPrice: String
    
    init(product: Product) {
        self.id = product.id
        self.name = product.name
        self.formattedPrice = String(format: "¥%.2f", product.price)
    }
}

// 视图控制器
class ProductListViewController: UIViewController {
    private let viewModel: ProductListViewModel
    private var cancellables = Set<AnyCancellable>()
    
    weak var delegate: ProductListViewControllerDelegate?
    
    init(viewModel: ProductListViewModel) {
        self.viewModel = viewModel
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        setupBindings()
        viewModel.loadProducts()
    }
    
    private func setupBindings() {
        viewModel.$productViewModels
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.tableView.reloadData()
            }
            .store(in: &cancellables)
        
        viewModel.$isLoading
            .receive(on: DispatchQueue.main)
            .sink { [weak self] isLoading in
                if isLoading {
                    self?.activityIndicator.startAnimating()
                } else {
                    self?.activityIndicator.stopAnimating()
                }
            }
            .store(in: &cancellables)
        
        viewModel.$error
            .receive(on: DispatchQueue.main)
            .compactMap { $0 }
            .sink { [weak self] error in
                self?.showError(error)
            }
            .store(in: &cancellables)
    }
    
    // 视图和用户交互逻辑
}

protocol ProductListViewControllerDelegate: AnyObject {
    func productListViewController(_ viewController: ProductListViewController, didSelectProductAt index: Int)
    func productListViewControllerDidTapAddProduct(_ viewController: ProductListViewController)
}

// 协调器
class ProductCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    private let productService: ProductService
    
    init(navigationController: UINavigationController, productService: ProductService) {
        self.navigationController = navigationController
        self.productService = productService
    }
    
    func start() {
        let viewModel = ProductListViewModel(productService: productService)
        let productListVC = ProductListViewController(viewModel: viewModel)
        productListVC.delegate = self
        navigationController.pushViewController(productListVC, animated: false)
    }
    
    private func showProductDetails(product: Product) {
        let viewModel = ProductDetailsViewModel(product: product)
        let productDetailsVC = ProductDetailsViewController(viewModel: viewModel)
        productDetailsVC.delegate = self
        navigationController.pushViewController(productDetailsVC, animated: true)
    }
}

extension ProductCoordinator: ProductListViewControllerDelegate {
    func productListViewController(_ viewController: ProductListViewController, didSelectProductAt index: Int) {
        let product = viewModel.product(at: index)
        showProductDetails(product: product)
    }
    
    func productListViewControllerDidTapAddProduct(_ viewController: ProductListViewController) {
        showAddProduct()
    }
}
```

### 协调器 + VIPER

VIPER（视图-交互器-展示器-实体-路由）是一种基于干净架构的架构模式。VIPER 中的路由器（Router）组件与协调器有一些重叠，但它们可以结合使用：

- **视图 (View)**: 用户界面
- **交互器 (Interactor)**: 业务逻辑
- **展示器 (Presenter)**: 协调视图和交互器
- **实体 (Entity)**: 数据模型
- **路由 (Router)**: 基本导航功能
- **协调器 (Coordinator)**: 高级导航和流程管理

在这种组合中，VIPER 的路由器负责基本的导航操作，而协调器负责更高级的流程管理和协调多个 VIPER 模块。

```swift
// VIPER + Coordinator 示例

// 实体
struct Product {
    let id: String
    let name: String
    let price: Double
    let description: String
}

// VIPER 模块接口
protocol ProductListViewInterface: AnyObject {
    func showProducts(_ products: [ProductViewModel])
    func showLoading()
    func hideLoading()
    func showError(_ message: String)
}

protocol ProductListPresenterInterface: AnyObject {
    func viewDidLoad()
    func didSelectProduct(at index: Int)
    func didTapAddProduct()
}

protocol ProductListInteractorInterface: AnyObject {
    func fetchProducts()
}

protocol ProductListInteractorOutputInterface: AnyObject {
    func didFetchProducts(_ products: [Product])
    func didFailToFetchProducts(with error: Error)
}

protocol ProductListRouterInterface: AnyObject {
    func navigateToProductDetails(product: Product)
    func navigateToAddProduct()
}

protocol ProductListDelegate: AnyObject {
    func productListModuleDidRequestShowDetails(for product: Product)
    func productListModuleDidRequestAddProduct()
}

// VIPER 实现
class ProductListViewController: UIViewController, ProductListViewInterface {
    var presenter: ProductListPresenterInterface!
    
    // 视图和用户交互逻辑
    
    func showProducts(_ products: [ProductViewModel]) {
        // 更新 UI
    }
    
    func showLoading() {
        // 显示加载指示器
    }
    
    func hideLoading() {
        // 隐藏加载指示器
    }
    
    func showError(_ message: String) {
        // 显示错误消息
    }
}

class ProductListPresenter: ProductListPresenterInterface, ProductListInteractorOutputInterface {
    weak var view: ProductListViewInterface?
    var interactor: ProductListInteractorInterface
    var router: ProductListRouterInterface
    
    private var products: [Product] = []
    
    init(view: ProductListViewInterface, interactor: ProductListInteractorInterface, router: ProductListRouterInterface) {
        self.view = view
        self.interactor = interactor
        self.router = router
    }
    
    func viewDidLoad() {
        view?.showLoading()
        interactor.fetchProducts()
    }
    
    func didSelectProduct(at index: Int) {
        guard index < products.count else { return }
        let product = products[index]
        router.navigateToProductDetails(product: product)
    }
    
    func didTapAddProduct() {
        router.navigateToAddProduct()
    }
    
    func didFetchProducts(_ products: [Product]) {
        self.products = products
        view?.hideLoading()
        
        let viewModels = products.map { ProductViewModel(product: $0) }
        view?.showProducts(viewModels)
    }
    
    func didFailToFetchProducts(with error: Error) {
        view?.hideLoading()
        view?.showError(error.localizedDescription)
    }
}

class ProductListInteractor: ProductListInteractorInterface {
    weak var output: ProductListInteractorOutputInterface?
    private let productService: ProductService
    
    init(productService: ProductService) {
        self.productService = productService
    }
    
    func fetchProducts() {
        productService.fetchProducts { [weak self] result in
            switch result {
            case .success(let products):
                self?.output?.didFetchProducts(products)
            case .failure(let error):
                self?.output?.didFailToFetchProducts(with: error)
            }
        }
    }
}

class ProductListRouter: ProductListRouterInterface {
    weak var viewController: UIViewController?
    weak var delegate: ProductListDelegate?
    
    func navigateToProductDetails(product: Product) {
        delegate?.productListModuleDidRequestShowDetails(for: product)
    }
    
    func navigateToAddProduct() {
        delegate?.productListModuleDidRequestAddProduct()
    }
}

// 协调器
class ProductCoordinator: Coordinator, ProductListDelegate {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    private let productService: ProductService
    
    init(navigationController: UINavigationController, productService: ProductService) {
        self.navigationController = navigationController
        self.productService = productService
    }
    
    func start() {
        // 创建 VIPER 模块
        let view = ProductListViewController()
        let interactor = ProductListInteractor(productService: productService)
        let router = ProductListRouter()
        let presenter = ProductListPresenter(view: view, interactor: interactor, router: router)
        
        // 连接组件
        view.presenter = presenter
        interactor.output = presenter
        router.viewController = view
        router.delegate = self
        
        navigationController.pushViewController(view, animated: false)
    }
    
    // ProductListDelegate 实现
    func productListModuleDidRequestShowDetails(for product: Product) {
        showProductDetails(product: product)
    }
    
    func productListModuleDidRequestAddProduct() {
        showAddProduct()
    }
    
    private func showProductDetails(product: Product) {
        // 创建并启动产品详情模块
    }
    
    private func showAddProduct() {
        // 创建并启动添加产品模块
    }
}
```

### 协调器 + Redux/单向数据流

Redux 是一种单向数据流架构，通常用于管理应用程序的状态。Redux 和协调器模式可以很好地结合使用：

- **Redux**: 管理应用程序的状态
- **协调器**: 管理导航和流程

在这种组合中，Redux 负责管理应用程序的状态和业务逻辑，而协调器负责管理导航流程。

```swift
// Redux + Coordinator 示例

// Redux 状态
struct AppState {
    var products: [Product] = []
    var cart: [CartItem] = []
    var isLoading: Bool = false
    var error: Error?
}

// Redux 动作
enum Action {
    case fetchProducts
    case fetchProductsSuccess([Product])
    case fetchProductsFailure(Error)
    case addToCart(Product)
    case removeFromCart(CartItem)
}

// Redux 中间件和 reducer 略过...

// Redux 存储
class Store {
    private(set) var state: AppState
    private let reducer: (inout AppState, Action) -> Void
    private let middlewares: [(Store, Action) -> Void]
    
    init(initialState: AppState, reducer: @escaping (inout AppState, Action) -> Void, middlewares: [(Store, Action) -> Void] = []) {
        self.state = initialState
        self.reducer = reducer
        self.middlewares = middlewares
    }
    
    func dispatch(_ action: Action) {
        // 应用中间件
        middlewares.forEach { middleware in
            middleware(self, action)
        }
        
        // 应用 reducer
        reducer(&state, action)
    }
}

// 视图控制器
class ProductListViewController: UIViewController {
    private let store: Store
    
    init(store: Store) {
        self.store = store
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        
        // 监听状态变化
        // 在实际应用中，这可能使用 Combine 或 RxSwift
        
        // 加载产品
        store.dispatch(.fetchProducts)
    }
    
    // 视图和用户交互逻辑
}

// 协调器
class ProductCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    private let store: Store
    
    init(navigationController: UINavigationController, store: Store) {
        self.navigationController = navigationController
        self.store = store
    }
    
    func start() {
        let productListVC = ProductListViewController(store: store)
        productListVC.delegate = self
        navigationController.pushViewController(productListVC, animated: false)
    }
}

extension ProductCoordinator: ProductListViewControllerDelegate {
    func productListViewController(_ viewController: ProductListViewController, didSelectProduct product: Product) {
        showProductDetails(product: product)
    }
}
```

协调器模式的灵活性使其能够与各种架构模式结合使用。无论选择哪种架构模式，协调器都可以帮助管理导航和流程，使代码更加模块化和可维护。

## 协调器模式最佳实践

### 依赖注入与协调器

随着协调器模式在 iOS 开发中的普及，开发社区已经总结出一些最佳实践。以下是实现协调器模式时应考虑的关键实践：

#### 1. 构造器注入

最直接的方法是通过构造器注入依赖：

```swift
class ProductCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    // 注入依赖
    private let productService: ProductService
    private let analyticsService: AnalyticsService
    
    init(navigationController: UINavigationController, productService: ProductService, analyticsService: AnalyticsService) {
        self.navigationController = navigationController
        self.productService = productService
        self.analyticsService = analyticsService
    }
    
    func start() {
        let viewModel = ProductListViewModel(productService: productService)
        let productListVC = ProductListViewController(viewModel: viewModel)
        productListVC.delegate = self
        navigationController.pushViewController(productListVC, animated: false)
        
        // 记录分析事件
        analyticsService.trackScreenView("ProductList")
    }
}
```

#### 2. 使用依赖容器

对于更复杂的应用程序，可以使用依赖容器来管理依赖：

```swift
class DependencyContainer {
    let productService: ProductService
    let userService: UserService
    let analyticsService: AnalyticsService
    let networkService: NetworkService
    
    init() {
        // 创建所有服务
        networkService = NetworkService()
        productService = ProductService(networkService: networkService)
        userService = UserService(networkService: networkService)
        analyticsService = AnalyticsService()
    }
}

class AppCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    private let container: DependencyContainer
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
        self.container = DependencyContainer()
    }
    
    func start() {
        if container.userService.isUserLoggedIn {
            showMainFlow()
        } else {
            showAuthFlow()
        }
    }
    
    private func showAuthFlow() {
        let authCoordinator = AuthCoordinator(
            navigationController: navigationController,
            userService: container.userService,
            analyticsService: container.analyticsService
        )
        addChildCoordinator(authCoordinator)
        authCoordinator.start()
    }
    
    private func showMainFlow() {
        let mainCoordinator = MainCoordinator(
            navigationController: navigationController,
            productService: container.productService,
            userService: container.userService,
            analyticsService: container.analyticsService
        )
        addChildCoordinator(mainCoordinator)
        mainCoordinator.start()
    }
}
```

#### 3. 工厂模式

对于需要创建多个相似对象的情况，可以使用工厂模式：

```swift
protocol ViewControllerFactory {
    func makeProductListViewController() -> UIViewController
    func makeProductDetailsViewController(product: Product) -> UIViewController
    func makeAddProductViewController() -> UIViewController
}

class DefaultViewControllerFactory: ViewControllerFactory {
    private let productService: ProductService
    private let analyticsService: AnalyticsService
    
    init(productService: ProductService, analyticsService: AnalyticsService) {
        self.productService = productService
        self.analyticsService = analyticsService
    }
    
    func makeProductListViewController() -> UIViewController {
        let viewModel = ProductListViewModel(productService: productService)
        let vc = ProductListViewController(viewModel: viewModel)
        return vc
    }
    
    func makeProductDetailsViewController(product: Product) -> UIViewController {
        let viewModel = ProductDetailsViewModel(product: product, productService: productService)
        let vc = ProductDetailsViewController(viewModel: viewModel)
        return vc
    }
    
    func makeAddProductViewController() -> UIViewController {
        let viewModel = AddProductViewModel(productService: productService)
        let vc = AddProductViewController(viewModel: viewModel)
        return vc
    }
}

class ProductCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    private let factory: ViewControllerFactory
    
    init(navigationController: UINavigationController, factory: ViewControllerFactory) {
        self.navigationController = navigationController
        self.factory = factory
    }
    
    func start() {
        let productListVC = factory.makeProductListViewController()
        if let productListVC = productListVC as? ProductListViewController {
            productListVC.delegate = self
        }
        navigationController.pushViewController(productListVC, animated: false)
    }
    
    private func showProductDetails(product: Product) {
        let productDetailsVC = factory.makeProductDetailsViewController(product: product)
        if let productDetailsVC = productDetailsVC as? ProductDetailsViewController {
            productDetailsVC.delegate = self
        }
        navigationController.pushViewController(productDetailsVC, animated: true)
    }
}
```

通过依赖注入，协调器可以管理应用程序的依赖图，使组件之间保持松散耦合，并提高代码的可测试性。

### 测试协调器

协调器模式的一个主要优势是提高了代码的可测试性。以下是测试协调器的一些方法：

### 测试协调器

### 内存管理与循环引用

### 避免协调器过度使用

## 协调器模式在 SwiftUI 中的应用

### SwiftUI 的导航挑战

SwiftUI 引入了声明式 UI 和新的导航方法，这给协调器模式的应用带来了新的挑战和机会。以下是在 SwiftUI 环境中应用协调器模式的一些方法：

#### 1. 使用 `@State` 和视图工厂

使用 `@State` 变量来控制导航状态，并使用视图工厂来创建目标视图：

```swift
class AppViewFactory {
    func makeProductListView(coordinator: AppCoordinator) -> some View {
        ProductListView(coordinator: coordinator)
    }
    
    func makeProductDetailView(product: Product, coordinator: AppCoordinator) -> some View {
        ProductDetailView(product: product, coordinator: coordinator)
    }
    
    func makeCartView(coordinator: AppCoordinator) -> some View {
        CartView(coordinator: coordinator)
    }
}

class AppCoordinator: ObservableObject {
    private let viewFactory: AppViewFactory
    
    @Published var navigationPath = NavigationPath()
    @Published var selectedProduct: Product?
    @Published var isShowingCart = false
    
    init(viewFactory: AppViewFactory = AppViewFactory()) {
        self.viewFactory = viewFactory
    }
    
    func showProductDetails(product: Product) {
        selectedProduct = product
        navigationPath.append(product)
    }
    
    func showCart() {
        isShowingCart = true
    }
    
    func dismissCart() {
        isShowingCart = false
    }
    
    func popToRoot() {
        navigationPath = NavigationPath()
    }
}

struct RootView: View {
    @StateObject private var coordinator = AppCoordinator()
    
    var body: some View {
        NavigationStack(path: $coordinator.navigationPath) {
            coordinator.viewFactory.makeProductListView(coordinator: coordinator)
                .navigationDestination(for: Product.self) { product in
                    coordinator.viewFactory.makeProductDetailView(product: product, coordinator: coordinator)
                }
                .sheet(isPresented: $coordinator.isShowingCart) {
                    coordinator.viewFactory.makeCartView(coordinator: coordinator)
                }
        }
    }
}

struct ProductListView: View {
    let coordinator: AppCoordinator
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                coordinator.showProductDetails(product: product)
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                coordinator.showCart()
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

#### 2. 使用 `Router` 模式

另一种方法是使用 `Router` 模式，将路由逻辑从视图和协调器中分离出来：

```swift
enum Route: Hashable {
    case productList
    case productDetail(Product)
    case cart
    case checkout
}

class Router: ObservableObject {
    @Published var path = NavigationPath()
    @Published var presentedSheet: Route?
    
    func navigate(to route: Route) {
        path.append(route)
    }
    
    func navigateBack() {
        path.removeLast()
    }
    
    func navigateToRoot() {
        path = NavigationPath()
    }
    
    func present(sheet route: Route) {
        presentedSheet = route
    }
    
    func dismissSheet() {
        presentedSheet = nil
    }
}

struct AppView: View {
    @StateObject private var router = Router()
    
    var body: some View {
        NavigationStack(path: $router.path) {
            routeView(for: .productList)
                .navigationDestination(for: Route.self) { route in
                    routeView(for: route)
                }
                .sheet(item: $router.presentedSheet) { route in
                    routeView(for: route)
                }
        }
        .environmentObject(router)
    }
    
    @ViewBuilder
    func routeView(for route: Route) -> some View {
        switch route {
        case .productList:
            ProductListView()
        case .productDetail(let product):
            ProductDetailView(product: product)
        case .cart:
            CartView()
        case .checkout:
            CheckoutView()
        }
    }
}

struct ProductListView: View {
    @EnvironmentObject private var router: Router
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                router.navigate(to: .productDetail(product))
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                router.present(sheet: .cart)
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

#### 3. 使用 `Coordinator` 协议和依赖注入

将协调器作为环境对象注入到 SwiftUI 视图中：

```swift
protocol Coordinator: ObservableObject {
    associatedtype Route
    var path: NavigationPath { get set }
    var sheet: Route? { get set }
    
    func navigate(to route: Route)
    func present(sheet route: Route)
    func dismiss()
    func popToRoot()
}

enum AppRoute: Hashable {
    case productDetail(Product)
    case cart
    case checkout
}

class AppCoordinator: Coordinator {
    typealias Route = AppRoute
    
    @Published var path = NavigationPath()
    @Published var sheet: AppRoute?
    
    func navigate(to route: Route) {
        path.append(route)
    }
    
    func present(sheet route: Route) {
        self.sheet = route
    }
    
    func dismiss() {
        sheet = nil
    }
    
    func popToRoot() {
        path = NavigationPath()
    }
}

struct AppView: View {
    @StateObject private var coordinator = AppCoordinator()
    
    var body: some View {
        NavigationStack(path: $coordinator.path) {
            ProductListView()
                .navigationDestination(for: AppRoute.self) { route in
                    switch route {
                    case .productDetail(let product):
                        ProductDetailView(product: product)
                    case .cart:
                        CartView()
                    case .checkout:
                        CheckoutView()
                    }
                }
                .sheet(item: $coordinator.sheet) { route in
                    switch route {
                    case .productDetail(let product):
                        ProductDetailView(product: product)
                    case .cart:
                        CartView()
                    case .checkout:
                        CheckoutView()
                    }
                }
        }
        .environmentObject(coordinator)
    }
}

struct ProductListView: View {
    @EnvironmentObject private var coordinator: AppCoordinator
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                coordinator.navigate(to: .productDetail(product))
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                coordinator.present(sheet: .cart)
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

在 SwiftUI 中实现协调器模式仍在探索阶段，没有一种公认的最佳方法。开发者应根据应用程序的需求和复杂性选择合适的方法。随着 SwiftUI 的不断发展，可能会出现更好的模式来处理导航和流程控制。

### SwiftUI 与 UIKit 协调器的结合

一种解决方案是使用 UIKit 协调器来管理 SwiftUI 视图的导航。这可以通过 `UIHostingController` 来实现：

```swift
class ProductCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        let productListView = ProductListView(delegate: self)
        let hostingController = UIHostingController(rootView: productListView)
        navigationController.pushViewController(hostingController, animated: false)
    }
    
    func showProductDetails(product: Product) {
        let productDetailView = ProductDetailView(product: product)
        let hostingController = UIHostingController(rootView: productDetailView)
        navigationController.pushViewController(hostingController, animated: true)
    }
}

// SwiftUI 视图使用代理与协调器通信
struct ProductListView: View {
    let products: [Product] = ProductService.shared.getProducts()
    let delegate: ProductCoordinator
    
    var body: some View {
        List(products) { product in
            Button(action: {
                delegate.showProductDetails(product: product)
            }) {
                Text(product.name)
            }
        }
    }
}
```

这种方法允许重用现有的 UIKit 协调器结构，但需要在 SwiftUI 视图和 UIKit 之间进行转换。

### 纯 SwiftUI 环境中的协调器模式

在纯 SwiftUI 环境中实现协调器模式需要不同的方法。以下是一些可能的实现方式：

#### 1. 使用 `@State` 和视图工厂

使用 `@State` 变量来控制导航状态，并使用视图工厂来创建目标视图：

```swift
class AppViewFactory {
    func makeProductListView(coordinator: AppCoordinator) -> some View {
        ProductListView(coordinator: coordinator)
    }
    
    func makeProductDetailView(product: Product, coordinator: AppCoordinator) -> some View {
        ProductDetailView(product: product, coordinator: coordinator)
    }
    
    func makeCartView(coordinator: AppCoordinator) -> some View {
        CartView(coordinator: coordinator)
    }
}

class AppCoordinator: ObservableObject {
    private let viewFactory: AppViewFactory
    
    @Published var navigationPath = NavigationPath()
    @Published var selectedProduct: Product?
    @Published var isShowingCart = false
    
    init(viewFactory: AppViewFactory = AppViewFactory()) {
        self.viewFactory = viewFactory
    }
    
    func showProductDetails(product: Product) {
        selectedProduct = product
        navigationPath.append(product)
    }
    
    func showCart() {
        isShowingCart = true
    }
    
    func dismissCart() {
        isShowingCart = false
    }
    
    func popToRoot() {
        navigationPath = NavigationPath()
    }
}

struct RootView: View {
    @StateObject private var coordinator = AppCoordinator()
    
    var body: some View {
        NavigationStack(path: $coordinator.navigationPath) {
            coordinator.viewFactory.makeProductListView(coordinator: coordinator)
                .navigationDestination(for: Product.self) { product in
                    coordinator.viewFactory.makeProductDetailView(product: product, coordinator: coordinator)
                }
                .sheet(isPresented: $coordinator.isShowingCart) {
                    coordinator.viewFactory.makeCartView(coordinator: coordinator)
                }
        }
    }
}

struct ProductListView: View {
    let coordinator: AppCoordinator
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                coordinator.showProductDetails(product: product)
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                coordinator.showCart()
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

#### 2. 使用 `Router` 模式

另一种方法是使用 `Router` 模式，将路由逻辑从视图和协调器中分离出来：

```swift
enum Route: Hashable {
    case productList
    case productDetail(Product)
    case cart
    case checkout
}

class Router: ObservableObject {
    @Published var path = NavigationPath()
    @Published var presentedSheet: Route?
    
    func navigate(to route: Route) {
        path.append(route)
    }
    
    func navigateBack() {
        path.removeLast()
    }
    
    func navigateToRoot() {
        path = NavigationPath()
    }
    
    func present(sheet route: Route) {
        presentedSheet = route
    }
    
    func dismissSheet() {
        presentedSheet = nil
    }
}

struct AppView: View {
    @StateObject private var router = Router()
    
    var body: some View {
        NavigationStack(path: $router.path) {
            routeView(for: .productList)
                .navigationDestination(for: Route.self) { route in
                    routeView(for: route)
                }
                .sheet(item: $router.presentedSheet) { route in
                    routeView(for: route)
                }
        }
        .environmentObject(router)
    }
    
    @ViewBuilder
    func routeView(for route: Route) -> some View {
        switch route {
        case .productList:
            ProductListView()
        case .productDetail(let product):
            ProductDetailView(product: product)
        case .cart:
            CartView()
        case .checkout:
            CheckoutView()
        }
    }
}

struct ProductListView: View {
    @EnvironmentObject private var router: Router
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                router.navigate(to: .productDetail(product))
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                router.present(sheet: .cart)
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

#### 3. 使用 `Coordinator` 协议和依赖注入

将协调器作为环境对象注入到 SwiftUI 视图中：

```swift
protocol Coordinator: ObservableObject {
    associatedtype Route
    var path: NavigationPath { get set }
    var sheet: Route? { get set }
    
    func navigate(to route: Route)
    func present(sheet route: Route)
    func dismiss()
    func popToRoot()
}

enum AppRoute: Hashable {
    case productDetail(Product)
    case cart
    case checkout
}

class AppCoordinator: Coordinator {
    typealias Route = AppRoute
    
    @Published var path = NavigationPath()
    @Published var sheet: AppRoute?
    
    func navigate(to route: Route) {
        path.append(route)
    }
    
    func present(sheet route: Route) {
        self.sheet = route
    }
    
    func dismiss() {
        sheet = nil
    }
    
    func popToRoot() {
        path = NavigationPath()
    }
}

struct AppView: View {
    @StateObject private var coordinator = AppCoordinator()
    
    var body: some View {
        NavigationStack(path: $coordinator.path) {
            ProductListView()
                .navigationDestination(for: AppRoute.self) { route in
                    switch route {
                    case .productDetail(let product):
                        ProductDetailView(product: product)
                    case .cart:
                        CartView()
                    case .checkout:
                        CheckoutView()
                    }
                }
                .sheet(item: $coordinator.sheet) { route in
                    switch route {
                    case .productDetail(let product):
                        ProductDetailView(product: product)
                    case .cart:
                        CartView()
                    case .checkout:
                        CheckoutView()
                    }
                }
        }
        .environmentObject(coordinator)
    }
}

struct ProductListView: View {
    @EnvironmentObject private var coordinator: AppCoordinator
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                coordinator.navigate(to: .productDetail(product))
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                coordinator.present(sheet: .cart)
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

在 SwiftUI 中实现协调器模式仍在探索阶段，没有一种公认的最佳方法。开发者应根据应用程序的需求和复杂性选择合适的方法。随着 SwiftUI 的不断发展，可能会出现更好的模式来处理导航和流程控制。

### SwiftUI 与 UIKit 协调器的结合

一种解决方案是使用 UIKit 协调器来管理 SwiftUI 视图的导航。这可以通过 `UIHostingController` 来实现：

```swift
class ProductCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        let productListView = ProductListView(delegate: self)
        let hostingController = UIHostingController(rootView: productListView)
        navigationController.pushViewController(hostingController, animated: false)
    }
    
    func showProductDetails(product: Product) {
        let productDetailView = ProductDetailView(product: product)
        let hostingController = UIHostingController(rootView: productDetailView)
        navigationController.pushViewController(hostingController, animated: true)
    }
}

// SwiftUI 视图使用代理与协调器通信
struct ProductListView: View {
    let products: [Product] = ProductService.shared.getProducts()
    let delegate: ProductCoordinator
    
    var body: some View {
        List(products) { product in
            Button(action: {
                delegate.showProductDetails(product: product)
            }) {
                Text(product.name)
            }
        }
    }
}
```

这种方法允许重用现有的 UIKit 协调器结构，但需要在 SwiftUI 视图和 UIKit 之间进行转换。

### 纯 SwiftUI 环境中的协调器模式

在纯 SwiftUI 环境中实现协调器模式需要不同的方法。以下是一些可能的实现方式：

#### 1. 使用 `@State` 和视图工厂

使用 `@State` 变量来控制导航状态，并使用视图工厂来创建目标视图：

```swift
class AppViewFactory {
    func makeProductListView(coordinator: AppCoordinator) -> some View {
        ProductListView(coordinator: coordinator)
    }
    
    func makeProductDetailView(product: Product, coordinator: AppCoordinator) -> some View {
        ProductDetailView(product: product, coordinator: coordinator)
    }
    
    func makeCartView(coordinator: AppCoordinator) -> some View {
        CartView(coordinator: coordinator)
    }
}

class AppCoordinator: ObservableObject {
    private let viewFactory: AppViewFactory
    
    @Published var navigationPath = NavigationPath()
    @Published var selectedProduct: Product?
    @Published var isShowingCart = false
    
    init(viewFactory: AppViewFactory = AppViewFactory()) {
        self.viewFactory = viewFactory
    }
    
    func showProductDetails(product: Product) {
        selectedProduct = product
        navigationPath.append(product)
    }
    
    func showCart() {
        isShowingCart = true
    }
    
    func dismissCart() {
        isShowingCart = false
    }
    
    func popToRoot() {
        navigationPath = NavigationPath()
    }
}

struct RootView: View {
    @StateObject private var coordinator = AppCoordinator()
    
    var body: some View {
        NavigationStack(path: $coordinator.navigationPath) {
            coordinator.viewFactory.makeProductListView(coordinator: coordinator)
                .navigationDestination(for: Product.self) { product in
                    coordinator.viewFactory.makeProductDetailView(product: product, coordinator: coordinator)
                }
                .sheet(isPresented: $coordinator.isShowingCart) {
                    coordinator.viewFactory.makeCartView(coordinator: coordinator)
                }
        }
    }
}

struct ProductListView: View {
    let coordinator: AppCoordinator
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                coordinator.showProductDetails(product: product)
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                coordinator.showCart()
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

#### 2. 使用 `Router` 模式

另一种方法是使用 `Router` 模式，将路由逻辑从视图和协调器中分离出来：

```swift
enum Route: Hashable {
    case productList
    case productDetail(Product)
    case cart
    case checkout
}

class Router: ObservableObject {
    @Published var path = NavigationPath()
    @Published var presentedSheet: Route?
    
    func navigate(to route: Route) {
        path.append(route)
    }
    
    func navigateBack() {
        path.removeLast()
    }
    
    func navigateToRoot() {
        path = NavigationPath()
    }
    
    func present(sheet route: Route) {
        presentedSheet = route
    }
    
    func dismissSheet() {
        presentedSheet = nil
    }
}

struct AppView: View {
    @StateObject private var router = Router()
    
    var body: some View {
        NavigationStack(path: $router.path) {
            routeView(for: .productList)
                .navigationDestination(for: Route.self) { route in
                    routeView(for: route)
                }
                .sheet(item: $router.presentedSheet) { route in
                    routeView(for: route)
                }
        }
        .environmentObject(router)
    }
    
    @ViewBuilder
    func routeView(for route: Route) -> some View {
        switch route {
        case .productList:
            ProductListView()
        case .productDetail(let product):
            ProductDetailView(product: product)
        case .cart:
            CartView()
        case .checkout:
            CheckoutView()
        }
    }
}

struct ProductListView: View {
    @EnvironmentObject private var router: Router
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                router.navigate(to: .productDetail(product))
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                router.present(sheet: .cart)
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

#### 3. 使用 `Coordinator` 协议和依赖注入

将协调器作为环境对象注入到 SwiftUI 视图中：

```swift
protocol Coordinator: ObservableObject {
    associatedtype Route
    var path: NavigationPath { get set }
    var sheet: Route? { get set }
    
    func navigate(to route: Route)
    func present(sheet route: Route)
    func dismiss()
    func popToRoot()
}

enum AppRoute: Hashable {
    case productDetail(Product)
    case cart
    case checkout
}

class AppCoordinator: Coordinator {
    typealias Route = AppRoute
    
    @Published var path = NavigationPath()
    @Published var sheet: AppRoute?
    
    func navigate(to route: Route) {
        path.append(route)
    }
    
    func present(sheet route: Route) {
        self.sheet = route
    }
    
    func dismiss() {
        sheet = nil
    }
    
    func popToRoot() {
        path = NavigationPath()
    }
}

struct AppView: View {
    @StateObject private var coordinator = AppCoordinator()
    
    var body: some View {
        NavigationStack(path: $coordinator.path) {
            ProductListView()
                .navigationDestination(for: AppRoute.self) { route in
                    switch route {
                    case .productDetail(let product):
                        ProductDetailView(product: product)
                    case .cart:
                        CartView()
                    case .checkout:
                        CheckoutView()
                    }
                }
                .sheet(item: $coordinator.sheet) { route in
                    switch route {
                    case .productDetail(let product):
                        ProductDetailView(product: product)
                    case .cart:
                        CartView()
                    case .checkout:
                        CheckoutView()
                    }
                }
        }
        .environmentObject(coordinator)
    }
}

struct ProductListView: View {
    @EnvironmentObject private var coordinator: AppCoordinator
    let products: [Product] = ProductService.shared.getProducts()
    
    var body: some View {
        List(products) { product in
            Button(action: {
                coordinator.navigate(to: .productDetail(product))
            }) {
                Text(product.name)
            }
        }
        .navigationTitle("产品")
        .toolbar {
            Button(action: {
                coordinator.present(sheet: .cart)
            }) {
                Image(systemName: "cart")
            }
        }
    }
}
```

在 SwiftUI 中实现协调器模式仍在探索阶段，没有一种公认的最佳方法。开发者应根据应用程序的需求和复杂性选择合适的方法。随着 SwiftUI 的不断发展，可能会出现更好的模式来处理导航和流程控制。

## 常见问题与解决方案

在实现协调器模式时，开发者可能会遇到一些常见问题。以下是这些问题及其解决方案：

### 问题 1：协调器过多导致代码复杂性增加

**解决方案**：
- 只为主要流程创建协调器，而不是每个视图控制器
- 基于功能而非视图创建协调器
- 对于简单流程，考虑使用更简单的导航方法

### 问题 2：内存泄漏

**解决方案**：
- 使用弱引用声明代理属性
- 在闭包中使用 `[weak self]`
- 确保在流程完成后移除子协调器
- 使用内存分析工具定期检查

### 问题 3：协调器与 Storyboard 的集成

**解决方案**：
- 使用 Storyboard 引用来分割大型 Storyboard
- 在协调器中使用 `UIStoryboard` 来实例化视图控制器
- 考虑使用工厂模式来封装 Storyboard 实例化逻辑

```swift
class StoryboardFactory {
    static func createViewController<T: UIViewController>(
        storyboardName: String,
        identifier: String? = nil
    ) -> T {
        let storyboard = UIStoryboard(name: storyboardName, bundle: nil)
        
        if let identifier = identifier {
            return storyboard.instantiateViewController(withIdentifier: identifier) as! T
        } else {
            return storyboard.instantiateInitialViewController() as! T
        }
    }
}

class AuthCoordinator: Coordinator {
    func showLogin() {
        let loginVC: LoginViewController = StoryboardFactory.createViewController(
            storyboardName: "Auth",
            identifier: "LoginViewController"
        )
        loginVC.delegate = self
        navigationController.pushViewController(loginVC, animated: true)
    }
}
```

### 问题 4：如何处理标签栏控制器

**解决方案**：
- 创建一个主协调器来管理标签栏控制器
- 为每个标签创建子协调器
- 在主协调器中启动子协调器

```swift
class MainCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        let tabBarController = UITabBarController()
        
        let homeCoordinator = HomeCoordinator(navigationController: UINavigationController())
        let searchCoordinator = SearchCoordinator(navigationController: UINavigationController())
        let profileCoordinator = ProfileCoordinator(navigationController: UINavigationController())
        
        homeCoordinator.start()
        searchCoordinator.start()
        profileCoordinator.start()
        
        childCoordinators = [homeCoordinator, searchCoordinator, profileCoordinator]
        
        tabBarController.viewControllers = [
            homeCoordinator.navigationController,
            searchCoordinator.navigationController,
            profileCoordinator.navigationController
        ]
        
        navigationController.viewControllers = [tabBarController]
        navigationController.isNavigationBarHidden = true
    }
}
```

### 问题 5：如何处理深度链接

**解决方案**：
- 在应用协调器中集中处理深度链接
- 根据 URL 路径和参数决定导航到哪里
- 确保应用处于适当的状态（如用户已登录）

```swift
extension AppCoordinator {
    func handleDeepLink(_ url: URL) {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: true) else { return }
        
        let path = components.path
        let queryItems = components.queryItems ?? []
        
        // 确保用户已登录
        guard userService.isLoggedIn else {
            // 保存深度链接，在登录后处理
            pendingDeepLink = url
            showAuthFlow()
            return
        }
        
        // 根据路径导航
        switch path {
        case "/product":
            if let productId = queryItems.first(where: { $0.name == "id" })?.value {
                showProduct(productId: productId)
            }
        case "/category":
            if let categoryId = queryItems.first(where: { $0.name == "id" })?.value {
                showCategory(categoryId: categoryId)
            }
        case "/cart":
            showCart()
        default:
            break
        }
    }
}
```

### 问题 6：协调器与视图模型的职责分离

**解决方案**：
- 协调器负责导航和流程控制
- 视图模型负责视图的状态和行为
- 通过闭包或代理让视图模型通知协调器导航事件

```swift
class ProductListViewModel {
    var onSelectProduct: ((Product) -> Void)?
    var onAddProduct: (() -> Void)?
    
    func selectProduct(_ product: Product) {
        // 可能进行一些业务逻辑处理
        onSelectProduct?(product)
    }
    
    func addProduct() {
        onAddProduct?()
    }
}

class ProductCoordinator: Coordinator {
    func start() {
        let viewModel = ProductListViewModel()
        
        viewModel.onSelectProduct = { [weak self] product in
            self?.showProductDetails(product: product)
        }
        
        viewModel.onAddProduct = { [weak self] in
            self?.showAddProduct()
        }
        
        let productListVC = ProductListViewController(viewModel: viewModel)
        navigationController.pushViewController(productListVC, animated: false)
    }
}
```

通过解决这些常见问题，可以更有效地实现协调器模式，并充分利用其优势。

## 总结与展望

协调器模式是一种强大的架构模式，它通过分离导航逻辑和视图逻辑，解决了 iOS 应用程序中的许多常见问题。以下是协调器模式的主要优势：

1. **关注点分离**：协调器模式将导航逻辑从视图控制器中分离出来，使每个组件都能专注于其核心职责。
2. **降低耦合度**：视图控制器不再直接依赖于其他视图控制器，使它们更加独立和可重用。
3. **中心化导航控制**：协调器提供了一个中心点来管理应用程序的导航流程，使导航逻辑更清晰、更易于理解。
4. **提高可测试性**：由于组件职责明确分离，可以更容易地对视图控制器和协调器进行单独测试。
5. **支持复杂导航场景**：协调器模式天然支持复杂的导航场景，如深度链接和多步骤流程。

尽管协调器模式有许多优势，但它也有一些挑战：

1. **额外的复杂性**：对于简单的应用程序，协调器模式可能引入不必要的复杂性。
2. **学习曲线**：理解和正确实现协调器模式需要时间和经验。
3. **内存管理**：如果不小心管理引用关系，可能导致内存泄漏。
4. **SwiftUI 集成**：将协调器模式与 SwiftUI 的声明式导航集成仍在探索阶段。

随着 iOS 应用程序变得越来越复杂，协调器模式的价值将继续增长。未来的发展方向可能包括：

1. **与 SwiftUI 的更好集成**：随着 SwiftUI 的不断发展，可能会出现更好的模式来结合协调器模式和声明式导航。
2. **标准化实现**：虽然基本概念是一致的，但协调器模式的实现方式有多种变体。未来可能会出现更标准化的实现方式。
3. **工具和框架支持**：可能会出现更多的工具和框架来简化协调器模式的实现，如代码生成工具或专门的协调器框架。
4. **与其他架构模式的结合**：协调器模式将继续与其他架构模式（如 MVVM、Redux 等）结合使用，形成更全面的架构解决方案。

在选择是否使用协调器模式时，应考虑应用程序的复杂性、团队的经验和项目的需求。对于简单的应用程序，传统的导航方法可能已经足够。但对于复杂的应用程序，特别是那些有复杂导航流程和深度链接要求的应用程序，协调器模式可以提供显著的好处。

无论选择哪种方法，关键是确保导航逻辑清晰、可维护，并且与应用程序的其他部分良好集成。

## 参考资源

以下是一些有关协调器模式的优秀资源，可以帮助深入理解和实现这一模式：

### 文章和博客

1. [Coordinators Redux](http://khanlou.com/2015/10/coordinators-redux/) - Soroush Khanlou 的原始文章，首次介绍协调器模式。
2. [Advanced Coordinators in iOS](https://www.hackingwithswift.com/articles/175/advanced-coordinator-pattern-tutorial-ios) - Paul Hudson 的高级协调器模式教程。
3. [Coordinators and Tab Bars](http://khanlou.com/2017/05/coordinators-and-tab-bars/) - 如何将协调器与标签栏控制器结合使用。
4. [Coordinator Pattern in SwiftUI](https://quickbirdstudios.com/blog/coordinator-pattern-in-swiftui/) - 在 SwiftUI 中实现协调器模式。
5. [Using the Coordinator Pattern with UIKit and SwiftUI](https://www.kodeco.com/books/design-patterns-by-tutorials/v3.0/chapters/23-coordinator-pattern) - 协调器模式与 UIKit 和 SwiftUI 的结合。

### 视频教程

1. [Coordinators in iOS](https://www.youtube.com/watch?v=7HgbcTqxoN4) - Soroush Khanlou 在 NSSpain 的演讲。
2. [The Coordinator Pattern](https://www.youtube.com/watch?v=UR7bjDe1TrE) - SwiftTalk 的协调器模式视频。
3. [iOS Architecture: Coordinators](https://www.youtube.com/watch?v=qJdFm2tD0dQ) - Essential Developer 的协调器架构视频。

### 开源项目

1. [XCoordinator](https://github.com/quickbirdstudios/XCoordinator) - 一个基于协调器模式的导航框架。
2. [Coordinators](https://github.com/radianttap/Coordinators) - Coordinators 的实现示例。
3. [RxFlow](https://github.com/RxSwiftCommunity/RxFlow) - 一个基于 RxSwift 的协调器模式实现。
4. [SwiftUI-Coordinator](https://github.com/AndrewBennet/SwiftUI-Coordinator) - SwiftUI 中协调器模式的示例实现。

### 书籍

1. [iOS App Architecture: MVVM, MVC, Coordinator & VIPER](https://www.raywenderlich.com/books/advanced-ios-app-architecture) - 包含协调器模式的详细章节。
2. [Design Patterns by Tutorials](https://www.raywenderlich.com/books/design-patterns-by-tutorials) - 包含协调器模式的设计模式书籍。

### 生成工具

1. [XcodeGen](https://github.com/yonaskolb/XcodeGen) - 可以生成基于协调器模式的项目结构。
2. [SwiftGen](https://github.com/SwiftGen/SwiftGen) - 可以为协调器生成类型安全的资源访问。

通过这些资源，可以更深入地了解协调器模式，并学习如何在不同场景中有效地实现它。无论是初学者还是有经验的开发者，都可以从这些资源中获取有价值的信息，提高在 iOS 应用程序中使用协调器模式的能力。 