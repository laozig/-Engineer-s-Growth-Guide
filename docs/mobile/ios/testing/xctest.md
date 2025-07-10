# XCTest 框架 - 单元测试基础

XCTest 是 Apple 官方提供的测试框架，用于为 iOS、macOS、watchOS 和 tvOS 应用程序创建和运行单元测试、性能测试和UI测试。通过 XCTest，开发者可以验证代码的正确性，确保应用程序在不同环境中稳定运行，并防止在添加新功能时引入回归问题。

## 目录

- [XCTest 介绍](#xctest-介绍)
- [测试环境设置](#测试环境设置)
- [创建测试目标](#创建测试目标)
- [编写基本单元测试](#编写基本单元测试)
- [XCTAssert 断言函数](#xctassert-断言函数)
- [测试生命周期](#测试生命周期)
- [异步测试](#异步测试)
- [性能测试](#性能测试)
- [代码覆盖率](#代码覆盖率)
- [测试依赖管理](#测试依赖管理)
- [模拟和存根](#模拟和存根)
- [参数化测试](#参数化测试)
- [UI测试基础](#ui测试基础)
- [持续集成](#持续集成)
- [最佳实践](#最佳实践)
- [常见问题解答](#常见问题解答)

## XCTest 介绍

### 什么是 XCTest？

XCTest 是一个全面的测试框架，集成在 Xcode 中，为 Swift 和 Objective-C 项目提供测试功能。它支持：

- **单元测试**：验证独立代码单元的正确性
- **性能测试**：测量代码执行的性能
- **UI测试**：模拟用户与应用的交互
- **集成测试**：验证多个组件如何协同工作

### 为什么需要单元测试？

编写测试有许多好处：

- **验证代码正确性**：确保代码按预期工作
- **防止回归**：避免在修改代码时引入新的错误
- **改进设计**：可测试的代码通常具有更好的设计
- **文档化**：测试展示了代码的预期行为
- **加速开发**：减少手动测试的时间
- **增强重构信心**：安全地重构代码

### XCTest 与其他测试框架的比较

| 特性 | XCTest | Quick & Nimble | OCMock |
|------|--------|----------------|--------|
| 官方支持 | ✅ | ❌ | ❌ |
| Xcode 集成 | 完全集成 | 需配置 | 需配置 |
| 语法风格 | 标准 | BDD 风格 | 模拟对象 |
| 学习曲线 | 适中 | 低 | 高 |
| UI 测试 | ✅ | ❌ | ❌ |
| 性能测试 | ✅ | ❌ | ❌ |

## 测试环境设置

### Xcode 中的测试导航器

Xcode 提供了专门的测试导航器，可通过以下方式访问：

1. 打开 Xcode 项目
2. 点击导航栏中的测试图标（菱形图标）或使用快捷键 `⌘6`
3. 测试导航器显示项目中的所有测试类和方法

### 创建新项目时包含测试

创建新项目时，Xcode 会询问是否包含测试：

1. 创建新项目时，勾选 "Include Tests" 选项
2. Xcode 会自动创建单元测试和 UI 测试目标
3. 生成的测试目标将包含示例测试类

### 为现有项目添加测试

如果项目没有测试目标，可以添加：

1. 选择项目导航器中的项目
2. 点击 "+" 按钮选择 "New Target"
3. 选择 "iOS" > "Test" 类别
4. 选择 "Unit Testing Bundle" 或 "UI Testing Bundle"
5. 点击 "Next"，输入测试目标的名称（通常为 `[项目名]Tests`）
6. 点击 "Finish" 完成创建

## 创建测试目标

### 测试目标结构

测试目标通常包含以下内容：

```
ProjectTests/
  ├── Info.plist
  └── ProjectTests.swift (初始测试类)
```

### 测试类命名约定

测试类和方法应遵循以下命名约定：

- 测试类名应以 "Tests" 结尾（例如：`CalculatorTests`）
- 测试方法名应以 "test" 开头（例如：`testAddition()`）
- 测试方法名应清晰描述被测试的功能（例如：`testLoginWithValidCredentials()`）

### 导入被测模块

在测试类中，需要导入 XCTest 框架和被测模块：

```swift
import XCTest
@testable import MyApp  // 导入被测模块，使用 @testable 关键字可以访问 internal 成员

class MyAppTests: XCTestCase {
    // 测试方法
}
```

## 编写基本单元测试

### 创建测试类

所有测试类必须继承自 `XCTestCase`：

```swift
import XCTest
@testable import MyApp

class CalculatorTests: XCTestCase {
    
    // 测试方法
    func testAddition() {
        // 被测代码
        let calculator = Calculator()
        let result = calculator.add(2, 3)
        
        // 验证结果
        XCTAssertEqual(result, 5, "加法操作应返回正确的和")
    }
}
```

### 测试方法结构

测试方法通常遵循 AAA (Arrange-Act-Assert) 模式：

1. **Arrange**：设置测试所需的对象和值
2. **Act**：执行被测试的代码
3. **Assert**：验证结果是否符合预期

```swift
func testMultiplication() {
    // Arrange - 准备测试环境
    let calculator = Calculator()
    
    // Act - 执行被测试的代码
    let result = calculator.multiply(4, 5)
    
    // Assert - 验证结果
    XCTAssertEqual(result, 20, "乘法操作应返回正确的积")
}
```

### 运行测试

有多种方式运行测试：

- **运行单个测试**：点击测试方法旁边的菱形按钮，或将光标放在测试方法中按 `⌘U`
- **运行测试类**：点击测试类旁边的菱形按钮
- **运行所有测试**：按 `⌘U` 或点击 Product > Test

## XCTAssert 断言函数

XCTest 提供了多种断言函数来验证测试结果：

### 相等性断言

```swift
// 验证两个值相等
XCTAssertEqual(result, 5)

// 验证两个值相等，带自定义错误消息
XCTAssertEqual(result, 5, "结果应该等于5")

// 验证两个值不相等
XCTAssertNotEqual(result, 0)

// 对于浮点数，可以指定精度
XCTAssertEqual(doubleValue, 3.14, accuracy: 0.001)
```

### 布尔断言

```swift
// 验证条件为 true
XCTAssertTrue(flag)

// 验证条件为 false
XCTAssertFalse(flag)
```

### 空值断言

```swift
// 验证值不为 nil
XCTAssertNotNil(optionalValue)

// 验证值为 nil
XCTAssertNil(optionalValue)
```

### 比较断言

```swift
// 验证值大于指定值
XCTAssertGreaterThan(value, 10)

// 验证值小于指定值
XCTAssertLessThan(value, 100)

// 验证值大于等于指定值
XCTAssertGreaterThanOrEqual(value, 10)

// 验证值小于等于指定值
XCTAssertLessThanOrEqual(value, 100)
```

### 异常断言

```swift
// 验证代码是否抛出异常
XCTAssertThrowsError(try riskyOperation()) { error in
    // 可以进一步验证错误类型和属性
    XCTAssertEqual(error as? MyError, MyError.invalidInput)
}

// 验证代码不抛出异常
XCTAssertNoThrow(try safeOperation())
```

### 自定义失败

```swift
// 使测试立即失败
XCTFail("测试失败原因")

// 条件失败
if condition {
    XCTFail("条件不应为真")
}
```

## 测试生命周期

XCTest 提供了多个方法来设置和清理测试环境：

### 测试实例生命周期

每个测试方法运行时，XCTest 会创建一个新的测试类实例。这意味着：

1. 每个测试方法运行在独立的环境中
2. 测试之间不共享实例变量的状态
3. 每个测试方法都有自己的 `setUp` 和 `tearDown` 调用

### 设置和清理方法

```swift
class UserServiceTests: XCTestCase {
    
    var userService: UserService!
    var mockDatabase: MockDatabase!
    
    // 每个测试方法之前调用
    override func setUp() {
        super.setUp()
        mockDatabase = MockDatabase()
        userService = UserService(database: mockDatabase)
    }
    
    // 每个测试方法之后调用
    override func tearDown() {
        userService = nil
        mockDatabase = nil
        super.tearDown()
    }
    
    // 测试方法
    func testUserCreation() {
        // 测试代码
    }
}
```

### 一次性设置和清理

对于昂贵的设置操作，可以使用类级别的设置和清理方法：

```swift
class DatabaseTests: XCTestCase {
    
    static var sharedDatabase: Database!
    var transaction: Transaction!
    
    // 在第一个测试方法之前调用一次
    override class func setUp() {
        super.setUp()
        sharedDatabase = Database(path: "test.db")
        sharedDatabase.prepare()
    }
    
    // 在最后一个测试方法之后调用一次
    override class func tearDown() {
        sharedDatabase.close()
        sharedDatabase = nil
        super.tearDown()
    }
    
    // 每个测试方法之前调用
    override func setUp() {
        super.setUp()
        transaction = Transaction(database: Self.sharedDatabase)
    }
    
    // 每个测试方法之后调用
    override func tearDown() {
        transaction.rollback()
        transaction = nil
        super.tearDown()
    }
}
```

### 测试顺序

默认情况下，测试方法的执行顺序是不确定的。如果需要特定顺序，可以使用以下方法：

```swift
class OrderedTests: XCTestCase {
    
    // 这些测试将按字母顺序执行
    func testA_FirstStep() { ... }
    func testB_SecondStep() { ... }
    func testC_ThirdStep() { ... }
    
    // 或者使用依赖测试（但不推荐）
    func testFirstTask() { ... }
    
    func testSecondTask() {
        // 依赖于 testFirstTask 的结果
        // 不推荐这种做法，应保持测试独立
    }
}
```

## 异步测试

很多iOS应用程序包含异步操作，如网络请求、动画或延迟执行的代码。XCTest提供了测试异步代码的机制。

### 基础异步测试

使用 `XCTestExpectation` 和 `wait(for:timeout:)` 方法测试异步代码：

```swift
func testAsyncNetworkCall() {
    // 创建期望
    let expectation = expectation(description: "Fetch user profile")
    
    // 执行异步操作
    networkService.fetchUserProfile(userID: "123") { result in
        switch result {
        case .success(let profile):
            // 验证结果
            XCTAssertEqual(profile.name, "张三")
            XCTAssertEqual(profile.email, "zhangsan@example.com")
        case .failure(let error):
            XCTFail("获取用户资料失败: \(error)")
        }
        
        // 标记期望已满足
        expectation.fulfill()
    }
    
    // 等待期望满足或超时
    wait(for: [expectation], timeout: 5.0)
}
```

### 使用多个期望

可以等待多个异步操作完成：

```swift
func testMultipleAsyncOperations() {
    // 创建多个期望
    let profileExpectation = expectation(description: "Fetch profile")
    let friendsExpectation = expectation(description: "Fetch friends")
    
    // 执行第一个异步操作
    networkService.fetchUserProfile(userID: "123") { result in
        // 验证结果
        if case .success(let profile) = result {
            XCTAssertEqual(profile.name, "张三")
        }
        
        profileExpectation.fulfill()
    }
    
    // 执行第二个异步操作
    networkService.fetchFriendsList(userID: "123") { result in
        // 验证结果
        if case .success(let friends) = result {
            XCTAssertFalse(friends.isEmpty)
        }
        
        friendsExpectation.fulfill()
    }
    
    // 等待所有期望满足
    wait(for: [profileExpectation, friendsExpectation], timeout: 5.0)
}
```

### 反向期望

有时需要确保某个操作不会在特定时间内发生：

```swift
func testCacheExpiration() {
    // 创建反向期望
    let expectation = expectation(description: "Cache hit")
    expectation.isInverted = true
    
    // 设置已过期的缓存
    cache.set(key: "testKey", value: "testValue", expiresIn: -60)
    
    // 尝试从缓存获取值
    cache.get(key: "testKey") { value in
        if value != nil {
            expectation.fulfill()
        }
    }
    
    // 等待短时间，期望不会被满足
    wait(for: [expectation], timeout: 0.5)
}
```

### 在 Swift 5.5+ 中使用 async/await

在 Swift 5.5 及更高版本中，可以使用现代并发功能测试异步代码：

```swift
// 使用 async 测试方法
func testAsyncFunction() async throws {
    // 直接使用 await 调用异步函数
    let result = try await dataService.fetchData()
    
    // 验证结果
    XCTAssertFalse(result.isEmpty)
    XCTAssertEqual(result.count, 10)
}

// 测试抛出错误的异步函数
func testAsyncFunctionThrows() async {
    // 测试异步函数抛出预期错误
    do {
        _ = try await dataService.fetchDataWithInvalidParameters()
        XCTFail("应该抛出错误")
    } catch DataError.invalidParameters {
        // 预期的错误
    } catch {
        XCTFail("抛出了意外的错误: \(error)")
    }
}
```

### 将回调转换为 async/await

对于使用回调的旧代码，可以创建适配器将其转换为 async/await 形式：

```swift
extension NetworkService {
    // 将基于回调的API转换为 async/await 形式
    func fetchUserProfileAsync(userID: String) async throws -> UserProfile {
        return try await withCheckedThrowingContinuation { continuation in
            fetchUserProfile(userID: userID) { result in
                continuation.resume(with: result)
            }
        }
    }
}

// 在测试中使用转换后的方法
func testFetchUserProfileAsync() async throws {
    let profile = try await networkService.fetchUserProfileAsync(userID: "123")
    
    XCTAssertEqual(profile.name, "张三")
    XCTAssertEqual(profile.email, "zhangsan@example.com")
}
```

## 性能测试

XCTest 提供了测量代码性能的工具，帮助识别性能退化问题。

### 基本性能测试

使用 `measure` 方法测量代码的执行时间：

```swift
func testSortingPerformance() {
    // 准备测试数据
    var numbers = (1...1000).map { _ in Int.random(in: 1...1000) }
    
    // 测量排序性能
    measure {
        // 这段代码的性能将被测量
        numbers.sort()
    }
}
```

执行此测试时，XCTest 将：

1. 运行代码块 10 次
2. 测量每次执行的时间
3. 计算平均执行时间和标准差
4. 与基准比较（如果已设置）

### 设置性能基准

可以设置性能基准，并指定允许的偏差范围：

```swift
func testParsingPerformance() {
    // 准备测试数据
    let jsonData = loadTestJSON()
    
    // 测量解析性能，设置基准和允许的偏差
    measure(metrics: [XCTClockMetric()]) {
        // 执行被测量的代码
        _ = try? JSONDecoder().decode(MyModel.self, from: jsonData)
    }
}
```

在 Xcode 中，可以：

1. 运行测试后，点击结果旁边的灰色菱形图标
2. 将当前结果设置为基准
3. 修改允许的偏差百分比（默认为 10%）

### 自定义性能指标

除了默认的时间测量外，还可以使用自定义性能指标：

```swift
func testMemoryPerformance() {
    // 使用内存指标
    measure(metrics: [XCTMemoryMetric()]) {
        // 执行内存密集型操作
        _ = processLargeDataSet()
    }
}

func testCombinedMetrics() {
    // 同时测量多个指标
    measure(metrics: [
        XCTClockMetric(),       // 测量时间
        XCTMemoryMetric(),      // 测量内存使用
        XCTStorageMetric(),     // 测量存储使用
        XCTCPUMetric()          // 测量CPU使用
    ]) {
        // 执行需要测量的代码
        _ = processComplexTask()
    }
}
```

### 多次迭代的自定义设置

对于需要特殊设置的性能测试，可以使用 `measureMetrics(_:automaticallyStartMeasuring:for:)` 方法：

```swift
func testComplexOperationPerformance() {
    // 定义要测量的指标
    let metrics: [XCTMetric] = [XCTClockMetric()]
    
    // 手动控制测量过程
    measureMetrics(metrics, automaticallyStartMeasuring: false) {
        // 每次迭代前的设置代码（不测量）
        let data = generateLargeTestData()
        
        // 开始测量
        self.startMeasuring()
        
        // 被测量的代码
        _ = processData(data)
        
        // 停止测量
        self.stopMeasuring()
        
        // 清理代码（不测量）
        cleanupTemporaryData()
    }
}
```

## 代码覆盖率

代码覆盖率是衡量测试完整性的重要指标，显示了测试执行了多少源代码。

### 启用代码覆盖率

在 Xcode 中启用代码覆盖率：

1. 选择项目的 scheme
2. 点击 "Edit Scheme..."
3. 选择 "Test" 选项
4. 勾选 "Code Coverage" 选项
5. 可选：勾选 "Gather coverage for all targets"

### 查看覆盖率报告

运行测试后，可以查看覆盖率报告：

1. 打开 Xcode 的 Report Navigator (⌘9)
2. 选择最近的测试运行
3. 点击 "Coverage" 标签
4. 查看按文件、类和函数分类的覆盖率报告

### 解读覆盖率指标

覆盖率报告包含多种指标：

- **行覆盖率**：执行的代码行百分比
- **函数覆盖率**：调用的函数百分比
- **条件覆盖率**：评估的条件百分比

### 增加覆盖率的策略

提高代码覆盖率的常用策略：

1. **识别未测试的路径**：查看报告中标红的代码行
2. **优先测试核心业务逻辑**：关注应用的关键功能
3. **测试边界条件**：包括最小值、最大值和特殊情况
4. **测试错误处理**：确保错误被正确处理
5. **使用参数化测试**：使用不同输入测试相同功能

### 覆盖率目标

设置合理的覆盖率目标：

- **80-90%** 通常被视为优秀的覆盖率
- **关键模块** 应有更高的覆盖率（接近 100%）
- **生成的代码** 或简单的样板代码可以有较低的覆盖率

注意：覆盖率不应成为唯一目标，测试质量比数量更重要。100% 的覆盖率不保证没有缺陷。

### 排除特定代码

某些代码不适合包含在覆盖率报告中：

```swift
// MARK: - 在 Swift 中排除代码覆盖
#if !CODECOV_EXCLUDED
    // 这段代码将被计入覆盖率
    func complexFunction() {
        // 实现...
    }
#endif

// 在 Xcode 设置中，可以配置排除特定文件或目录
```

## 测试依赖管理

大多数类都依赖于其他组件，例如网络服务、数据库或外部API。在测试中，需要隔离和管理这些依赖。

### 依赖注入

依赖注入是一种设计模式，使测试更容易：

```swift
// 没有依赖注入的类
class UserService {
    private let networkClient = NetworkClient()
    
    func fetchUser(id: String, completion: @escaping (User?) -> Void) {
        networkClient.get("/users/\(id)") { data in
            // 处理数据
            let user = self.parseUserData(data)
            completion(user)
        }
    }
}

// 使用依赖注入的可测试类
class UserService {
    private let networkClient: NetworkClientProtocol
    
    // 依赖通过构造函数注入
    init(networkClient: NetworkClientProtocol) {
        self.networkClient = networkClient
    }
    
    func fetchUser(id: String, completion: @escaping (User?) -> Void) {
        networkClient.get("/users/\(id)") { data in
            // 处理数据
            let user = self.parseUserData(data)
            completion(user)
        }
    }
}

// 在测试中使用模拟对象
func testFetchUser() {
    // 创建模拟网络客户端
    let mockNetworkClient = MockNetworkClient()
    mockNetworkClient.getResponseToReturn = sampleUserData
    
    // 使用模拟对象创建被测试的服务
    let userService = UserService(networkClient: mockNetworkClient)
    
    // 测试方法
    let expectation = self.expectation(description: "Fetch user")
    userService.fetchUser(id: "123") { user in
        XCTAssertNotNil(user)
        XCTAssertEqual(user?.name, "张三")
        expectation.fulfill()
    }
    
    waitForExpectations(timeout: 1.0)
}
```

### 使用协议实现松耦合

协议可以帮助实现更松散的耦合，使测试更容易：

```swift
// 定义服务协议
protocol UserServiceProtocol {
    func fetchUser(id: String, completion: @escaping (User?) -> Void)
}

// 实现协议
class UserService: UserServiceProtocol {
    // 实现...
}

// 创建模拟实现用于测试
class MockUserService: UserServiceProtocol {
    var userToReturn: User?
    var errorToThrow: Error?
    
    func fetchUser(id: String, completion: @escaping (User?) -> Void) {
        completion(userToReturn)
    }
}

// 在视图控制器中使用协议
class UserProfileViewController: UIViewController {
    private let userService: UserServiceProtocol
    
    init(userService: UserServiceProtocol) {
        self.userService = userService
        super.init(nibName: nil, bundle: nil)
    }
    
    // ...
}

// 在测试中注入模拟服务
func testUserProfileDisplay() {
    let mockService = MockUserService()
    mockService.userToReturn = User(id: "123", name: "张三", email: "zhangsan@example.com")
    
    let viewController = UserProfileViewController(userService: mockService)
    viewController.loadViewIfNeeded()
    
    // 触发加载用户数据
    viewController.viewDidAppear(false)
    
    // 验证显示的用户数据
    XCTAssertEqual(viewController.nameLabel.text, "张三")
    XCTAssertEqual(viewController.emailLabel.text, "zhangsan@example.com")
}
```

### 工厂模式和测试

使用工厂模式可以更灵活地创建依赖：

```swift
// 服务工厂协议
protocol ServiceFactory {
    func makeNetworkClient() -> NetworkClientProtocol
    func makeUserService() -> UserServiceProtocol
    func makeAuthService() -> AuthServiceProtocol
}

// 生产环境工厂
class AppServiceFactory: ServiceFactory {
    func makeNetworkClient() -> NetworkClientProtocol {
        return NetworkClient(baseURL: "https://api.example.com")
    }
    
    func makeUserService() -> UserServiceProtocol {
        return UserService(networkClient: makeNetworkClient())
    }
    
    func makeAuthService() -> AuthServiceProtocol {
        return AuthService(networkClient: makeNetworkClient())
    }
}

// 测试工厂
class TestServiceFactory: ServiceFactory {
    var mockNetworkClient = MockNetworkClient()
    var mockUserService = MockUserService()
    var mockAuthService = MockAuthService()
    
    func makeNetworkClient() -> NetworkClientProtocol {
        return mockNetworkClient
    }
    
    func makeUserService() -> UserServiceProtocol {
        return mockUserService
    }
    
    func makeAuthService() -> AuthServiceProtocol {
        return mockAuthService
    }
}

// 应用中使用工厂
class AppCoordinator {
    private let serviceFactory: ServiceFactory
    
    init(serviceFactory: ServiceFactory) {
        self.serviceFactory = serviceFactory
    }
    
    func showUserProfile(userID: String) {
        let userService = serviceFactory.makeUserService()
        let viewController = UserProfileViewController(userService: userService)
        // 显示视图控制器
    }
}

// 在测试中使用测试工厂
func testShowUserProfile() {
    let testFactory = TestServiceFactory()
    testFactory.mockUserService.userToReturn = User(id: "123", name: "张三")
    
    let appCoordinator = AppCoordinator(serviceFactory: testFactory)
    appCoordinator.showUserProfile(userID: "123")
    
    // 验证结果
}
```

## 模拟和存根

模拟对象（Mock）和存根（Stub）允许替换真实依赖，以便在隔离环境中测试代码。

### 手动创建模拟对象

最简单的方法是手动创建模拟类：

```swift
// 原始协议
protocol DataService {
    func fetchData(completion: @escaping (Result<[String], Error>) -> Void)
}

// 手动创建的模拟对象
class MockDataService: DataService {
    // 控制返回值
    var dataToReturn: [String]?
    var errorToReturn: Error?
    
    // 跟踪调用
    var fetchDataCalled = false
    var fetchDataCallCount = 0
    
    func fetchData(completion: @escaping (Result<[String], Error>) -> Void) {
        fetchDataCalled = true
        fetchDataCallCount += 1
        
        if let error = errorToReturn {
            completion(.failure(error))
        } else if let data = dataToReturn {
            completion(.success(data))
        }
    }
}

// 在测试中使用模拟对象
func testDataFetching() {
    // 创建模拟对象
    let mockService = MockDataService()
    mockService.dataToReturn = ["Item 1", "Item 2", "Item 3"]
    
    // 创建被测试的对象
    let viewModel = DataViewModel(dataService: mockService)
    
    // 执行操作
    viewModel.loadData()
    
    // 验证模拟对象的交互
    XCTAssertTrue(mockService.fetchDataCalled)
    XCTAssertEqual(mockService.fetchDataCallCount, 1)
    
    // 验证结果
    XCTAssertEqual(viewModel.items.count, 3)
    XCTAssertEqual(viewModel.items[0], "Item 1")
}
```

### 使用存根模拟网络请求

对于网络请求，可以创建返回预定义响应的存根：

```swift
// 创建 URLProtocol 子类来提供模拟响应
class MockURLProtocol: URLProtocol {
    
    // 保存模拟响应数据的字典
    static var mockResponses = [URL?: (Data, HTTPURLResponse)]()
    
    // 重置所有模拟响应
    static func reset() {
        mockResponses = [:]
    }
    
    // 添加模拟响应
    static func mockResponse(for url: URL?, data: Data, statusCode: Int = 200) {
        let response = HTTPURLResponse(url: url ?? URL(string: "https://example.com")!, 
                                    statusCode: statusCode, 
                                    httpVersion: nil, 
                                    headerFields: nil)!
        mockResponses[url] = (data, response)
    }
    
    // 检查是否可以处理此请求
    override class func canInit(with request: URLRequest) -> Bool {
        return mockResponses.keys.contains(request.url)
    }
    
    // 返回相同的请求
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }
    
    // 开始加载请求
    override func startLoading() {
        guard let url = request.url,
              let (data, response) = MockURLProtocol.mockResponses[url] else {
            client?.urlProtocol(self, didFailWithError: NSError(domain: "MockURLProtocol", code: -1, userInfo: nil))
            return
        }
        
        // 发送模拟响应
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }
    
    // 停止加载（不需要任何操作）
    override func stopLoading() {}
}

// 配置 URLSession 使用模拟协议
func configureURLSessionForTesting() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [MockURLProtocol.self]
    return URLSession(configuration: configuration)
}

// 在测试中使用模拟 URLSession
func testFetchUserProfile() {
    // 准备模拟响应数据
    let userJSON = """
    {
        "id": "123",
        "name": "张三",
        "email": "zhangsan@example.com"
    }
    """
    let userData = userJSON.data(using: .utf8)!
    
    // 设置模拟响应
    let url = URL(string: "https://api.example.com/users/123")!
    MockURLProtocol.mockResponse(for: url, data: userData)
    
    // 创建使用模拟会话的网络客户端
    let session = configureURLSessionForTesting()
    let networkClient = NetworkClient(session: session)
    
    // 创建被测试的服务
    let userService = UserService(networkClient: networkClient)
    
    // 执行异步测试
    let expectation = self.expectation(description: "Fetch user profile")
    
    userService.fetchUser(id: "123") { result in
        switch result {
        case .success(let user):
            XCTAssertEqual(user.id, "123")
            XCTAssertEqual(user.name, "张三")
            XCTAssertEqual(user.email, "zhangsan@example.com")
        case .failure(let error):
            XCTFail("获取用户失败: \(error)")
        }
        expectation.fulfill()
    }
    
    waitForExpectations(timeout: 1.0)
}
```

### 模拟用户默认设置

对于需要测试使用 `UserDefaults` 的代码：

```swift
// 用于测试的UserDefaults扩展
extension UserDefaults {
    
    // 创建用于测试的实例
    static func createTestInstance() -> UserDefaults {
        let suiteName = "test_\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        return defaults
    }
}

// 使用依赖注入的设置服务
class SettingsService {
    private let userDefaults: UserDefaults
    
    init(userDefaults: UserDefaults = .standard) {
        self.userDefaults = userDefaults
    }
    
    var username: String {
        get {
            return userDefaults.string(forKey: "username") ?? ""
        }
        set {
            userDefaults.set(newValue, forKey: "username")
        }
    }
    
    // 其他设置...
}

// 测试设置服务
func testSettingsService() {
    // 创建测试专用的UserDefaults实例
    let testDefaults = UserDefaults.createTestInstance()
    
    // 创建使用测试实例的服务
    let settingsService = SettingsService(userDefaults: testDefaults)
    
    // 测试设置和获取值
    settingsService.username = "张三"
    XCTAssertEqual(settingsService.username, "张三")
    
    // 修改值
    settingsService.username = "李四"
    XCTAssertEqual(settingsService.username, "李四")
}
```

### 模拟文件系统操作

对于需要测试文件操作的代码：

```swift
// 文件管理器协议
protocol FileManagerProtocol {
    func fileExists(atPath: String) -> Bool
    func createDirectory(at: URL, withIntermediateDirectories: Bool, attributes: [FileAttributeKey: Any]?) throws
    func createFile(atPath: String, contents: Data?, attributes: [FileAttributeKey: Any]?) -> Bool
    func contentsOfDirectory(at: URL, includingPropertiesForKeys: [URLResourceKey]?, options: FileManager.DirectoryEnumerationOptions) throws -> [URL]
    func removeItem(at: URL) throws
}

// 扩展标准文件管理器以符合协议
extension FileManager: FileManagerProtocol {}

// 模拟文件管理器
class MockFileManager: FileManagerProtocol {
    // 模拟文件系统状态
    var mockFiles: [String: Data] = [:]
    var mockDirectories: Set<String> = []
    
    // 实现协议方法
    func fileExists(atPath path: String) -> Bool {
        return mockFiles.keys.contains(path) || mockDirectories.contains(path)
    }
    
    func createDirectory(at url: URL, withIntermediateDirectories: Bool, attributes: [FileAttributeKey : Any]?) throws {
        mockDirectories.insert(url.path)
    }
    
    func createFile(atPath path: String, contents: Data?, attributes: [FileAttributeKey : Any]?) -> Bool {
        mockFiles[path] = contents
        return true
    }
    
    func contentsOfDirectory(at url: URL, includingPropertiesForKeys: [URLResourceKey]?, options: FileManager.DirectoryEnumerationOptions) throws -> [URL] {
        let basePath = url.path
        // 返回此目录下的所有文件和子目录
        let fileURLs = mockFiles.keys
            .filter { $0.hasPrefix(basePath) && $0 != basePath }
            .map { URL(fileURLWithPath: $0) }
        
        let directoryURLs = mockDirectories
            .filter { $0.hasPrefix(basePath) && $0 != basePath }
            .map { URL(fileURLWithPath: $0) }
        
        return fileURLs + directoryURLs
    }
    
    func removeItem(at url: URL) throws {
        mockFiles.removeValue(forKey: url.path)
        mockDirectories.remove(url.path)
    }
}

// 使用文件管理器的服务
class DocumentService {
    private let fileManager: FileManagerProtocol
    
    init(fileManager: FileManagerProtocol = FileManager.default) {
        self.fileManager = fileManager
    }
    
    // 服务方法...
}

// 测试文档服务
func testDocumentService() {
    // 创建模拟文件管理器
    let mockFileManager = MockFileManager()
    let documentService = DocumentService(fileManager: mockFileManager)
    
    // 测试服务...
}
```

## 参数化测试

参数化测试允许使用不同的输入数据运行相同的测试代码，避免重复测试逻辑。

### 使用数据驱动的测试方法

一种简单的方法是创建一个包含测试数据的数组，并在循环中运行测试：

```swift
func testStringValidation() {
    // 测试用例：(输入字符串, 是否有效)
    let testCases: [(String, Bool)] = [
        ("abc@example.com", true),      // 有效邮箱
        ("invalid.email", false),       // 无效邮箱
        ("another@example.com", true),  // 有效邮箱
        ("@missing.com", false),        // 无效邮箱
        ("spaces not allowed@test.com", false) // 无效邮箱
    ]
    
    // 运行所有测试用例
    for (input, expectedResult) in testCases {
        // 执行验证
        let isValid = validator.isValidEmail(input)
        
        // 验证结果
        XCTAssertEqual(isValid, expectedResult, "验证失败: \(input) 应该\(expectedResult ? "有效" : "无效")")
    }
}
```

### 创建自定义测试辅助方法

为更复杂的测试创建辅助方法：

```swift
// 自定义测试辅助方法
func validateCalculation(a: Int, b: Int, operation: String, expected: Int, file: StaticString = #file, line: UInt = #line) {
    let calculator = Calculator()
    
    var result: Int
    
    switch operation {
    case "+": result = calculator.add(a, b)
    case "-": result = calculator.subtract(a, b)
    case "*": result = calculator.multiply(a, b)
    case "/": result = calculator.divide(a, b)
    default:
        XCTFail("不支持的操作: \(operation)", file: file, line: line)
        return
    }
    
    XCTAssertEqual(result, expected, "\(a) \(operation) \(b) 应该等于 \(expected)，但得到 \(result)", file: file, line: line)
}

// 使用辅助方法运行多个测试
func testCalculations() {
    // 加法测试
    validateCalculation(a: 2, b: 3, operation: "+", expected: 5)
    validateCalculation(a: -1, b: 1, operation: "+", expected: 0)
    
    // 减法测试
    validateCalculation(a: 5, b: 3, operation: "-", expected: 2)
    validateCalculation(a: 1, b: 5, operation: "-", expected: -4)
    
    // 乘法测试
    validateCalculation(a: 2, b: 3, operation: "*", expected: 6)
    validateCalculation(a: -2, b: 4, operation: "*", expected: -8)
    
    // 除法测试
    validateCalculation(a: 6, b: 2, operation: "/", expected: 3)
    validateCalculation(a: 5, b: 2, operation: "/", expected: 2)  // 整数除法
}
```

### 生成随机测试数据

使用随机数据增强测试覆盖范围：

```swift
func testRandomInputs() {
    // 随机测试加法
    for _ in 1...100 {
        let a = Int.random(in: -1000...1000)
        let b = Int.random(in: -1000...1000)
        let expected = a + b
        
        let calculator = Calculator()
        let result = calculator.add(a, b)
        
        XCTAssertEqual(result, expected, "\(a) + \(b) 应该等于 \(expected)")
    }
}

// 使用种子保证可重复性
func testRandomWithSeed() {
    // 使用固定种子创建随机数生成器
    var generator = RandomNumberGenerator(seed: 12345)
    
    for _ in 1...50 {
        // 生成随机数但具有可重复性
        let a = Int.random(in: -100...100, using: &generator)
        let b = Int.random(in: -100...100, using: &generator)
        
        // 测试乘法
        let expected = a * b
        let result = calculator.multiply(a, b)
        
        XCTAssertEqual(result, expected)
    }
}
```

### 使用特殊测试用例

除了普通情况外，还应测试边界和特殊情况：

```swift
func testEdgeCases() {
    let calculator = Calculator()
    
    // 极限值测试
    XCTAssertEqual(calculator.add(Int.max, 0), Int.max)
    XCTAssertEqual(calculator.add(Int.min, 0), Int.min)
    
    // 溢出测试
    XCTAssertThrowsError(try calculator.safeAdd(Int.max, 1))
    XCTAssertThrowsError(try calculator.safeAdd(Int.min, -1))
    
    // 除零测试
    XCTAssertThrowsError(try calculator.safeDivide(10, 0))
    
    // 特殊情况
    XCTAssertEqual(calculator.multiply(0, 5), 0)
    XCTAssertEqual(calculator.multiply(5, 0), 0)
    XCTAssertEqual(calculator.multiply(1, 5), 5)
    XCTAssertEqual(calculator.multiply(5, 1), 5)
}
```

## UI测试基础

XCTest 框架包含 XCUITest，用于自动化UI测试。UI测试模拟用户与应用的交互，验证界面的正确性。

### 创建UI测试

创建UI测试目标：

1. 在 Xcode 中，选择 File > New > Target
2. 选择 iOS > Test > UI Testing Bundle
3. 配置测试目标名称（通常为 `[项目名]UITests`）

### 基本UI测试结构

```swift
import XCTest

class MyAppUITests: XCTestCase {
    
    var app: XCUIApplication!
    
    override func setUp() {
        super.setUp()
        
        // 持续集成设置
        continueAfterFailure = false
        
        // 初始化应用
        app = XCUIApplication()
        
        // 可以设置启动参数，例如启用测试模式
        app.launchArguments = ["-UITesting"]
        
        // 启动应用
        app.launch()
    }
    
    func testLoginScreen() {
        // 查找界面元素
        let usernameField = app.textFields["usernameField"]
        let passwordField = app.secureTextFields["passwordField"]
        let loginButton = app.buttons["loginButton"]
        
        // 验证元素存在
        XCTAssertTrue(usernameField.exists)
        XCTAssertTrue(passwordField.exists)
        XCTAssertTrue(loginButton.exists)
        
        // 与元素交互
        usernameField.tap()
        usernameField.typeText("testuser")
        
        passwordField.tap()
        passwordField.typeText("password123")
        
        loginButton.tap()
        
        // 验证登录成功 - 检查新界面的元素
        let welcomeLabel = app.staticTexts["welcomeLabel"]
        XCTAssertTrue(welcomeLabel.waitForExistence(timeout: 2.0))
        XCTAssertEqual(welcomeLabel.label, "欢迎，testuser")
    }
}
```

### 查找UI元素

XCUITest 提供多种查找UI元素的方法：

```swift
// 通过标识符查找（最推荐）
let button = app.buttons["loginButton"]

// 通过标签查找
let button = app.buttons["登录"]

// 通过类型和索引查找
let firstButton = app.buttons.element(boundBy: 0)

// 通过谓词查找
let predicate = NSPredicate(format: "label CONTAINS %@", "登录")
let loginButton = app.buttons.element(matching: predicate)

// 查找匹配多个条件的元素
let buttonCount = app.buttons.matching(identifier: "actionButton").count

// 使用层次结构查找
let textField = app.tables.cells.element(boundBy: 1).textFields.element

// 等待元素出现
XCTAssertTrue(app.alerts["确认删除"].waitForExistence(timeout: 2.0))
```

### 与元素交互

可以模拟各种用户交互：

```swift
// 点击
button.tap()

// 双击
image.doubleTap()

// 长按
cell.press(forDuration: 1.5)

// 输入文本
textField.typeText("Hello, World!")

// 清除文本
textField.clearAndEnterText("新文本")

// 滑动
slider.adjust(toNormalizedSliderPosition: 0.5)

// 拖拽
element.swipeUp()
element.swipeDown()
element.swipeLeft()
element.swipeRight()

// 精确拖拽
let startCoordinate = cell.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
let endCoordinate = otherCell.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
startCoordinate.press(forDuration: 0.1, thenDragTo: endCoordinate)
```

### 处理键盘

```swift
// 点击键盘上的按钮
app.keyboards.buttons["Return"].tap()

// 关闭键盘
app.keyboards.buttons["Done"].tap()

// 检查键盘是否显示
XCTAssertTrue(app.keyboards.element.exists)

// 等待键盘消失
let keyboardGoneExpectation = expectation(for: NSPredicate(format: "exists == false"), 
                                       evaluatedWith: app.keyboards.element,
                                       handler: nil)
wait(for: [keyboardGoneExpectation], timeout: 2.0)
```

### 处理警告框和弹窗

```swift
// 点击警告框上的按钮
app.alerts["警告"].buttons["确定"].tap()

// 检查警告框是否显示
XCTAssertTrue(app.alerts["警告"].exists)

// 等待警告框出现
let alertExpectation = expectation(for: NSPredicate(format: "exists == true"), 
                                evaluatedWith: app.alerts["警告"],
                                handler: nil)
wait(for: [alertExpectation], timeout: 2.0)

// 处理操作表
app.sheets["选项"].buttons["删除"].tap()
```

### 自定义扩展简化测试

可以创建扩展来简化常见测试操作：

```swift
extension XCUIElement {
    // 清除并输入文本
    func clearAndEnterText(_ text: String) {
        tap()
        let oldText = value as? String ?? ""
        
        // 删除旧文本
        let deleteString = String(repeating: XCUIKeyboardKey.delete.rawValue, count: oldText.count)
        typeText(deleteString)
        
        // 输入新文本
        typeText(text)
    }
    
    // 等待元素可点击
    func waitForEnabled(_ timeout: TimeInterval) -> Bool {
        let predicate = NSPredicate(format: "isEnabled == true")
        let expectation = XCTNSPredicateExpectation(predicate: predicate, object: self)
        
        let result = XCTWaiter.wait(for: [expectation], timeout: timeout)
        return result == .completed
    }
}

// 在测试中使用扩展
func testEditProfile() {
    app.textFields["nameField"].clearAndEnterText("新名称")
    
    let saveButton = app.buttons["saveButton"]
    XCTAssertTrue(saveButton.waitForEnabled(2.0))
    saveButton.tap()
}
```

### 记录UI测试

Xcode 提供了记录UI交互的功能：

1. 打开UI测试文件
2. 将光标放在要添加录制代码的位置
3. 点击底部的红色录制按钮
4. 与应用交互
5. 点击停止按钮
6. Xcode 会自动生成交互代码

### 截图和视觉验证

在测试中可以捕获截图进行验证：

```swift
func testAppearance() {
    // 导航到特定界面
    app.tabBars.buttons["Profile"].tap()
    
    // 截取屏幕截图
    let screenshot = app.screenshot()
    
    // 将截图添加到测试附件
    let attachment = XCTAttachment(screenshot: screenshot)
    attachment.lifetime = .keepAlways
    add(attachment)
    
    // 注意：XCTest 不内置图像比较功能
    // 需要自定义实现或使用第三方库进行截图比较
}
```

## 持续集成

将 XCTest 与持续集成系统集成可以自动运行测试并捕获结果。

### 命令行运行测试

使用 `xcodebuild` 命令行工具运行测试：

```bash
# 运行单元测试
xcodebuild test -project MyApp.xcodeproj -scheme MyApp -destination 'platform=iOS Simulator,name=iPhone 14,OS=16.0'

# 运行UI测试
xcodebuild test -project MyApp.xcodeproj -scheme MyApp -destination 'platform=iOS Simulator,name=iPhone 14,OS=16.0' -testPlan UITests

# 运行特定测试类
xcodebuild test -project MyApp.xcodeproj -scheme MyApp -destination 'platform=iOS Simulator,name=iPhone 14,OS=16.0' -only-testing:MyAppTests/LoginTests
```

### 配置 CI 服务器

以下是在常见 CI 系统中配置 iOS 测试的基本步骤：

#### GitHub Actions 示例

```yaml
name: iOS Tests

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: macos-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set Xcode Version
      run: sudo xcode-select -s /Applications/Xcode_14.0.app
    
    - name: Build and Test
      run: |
        xcodebuild test -project MyApp.xcodeproj -scheme MyApp -destination 'platform=iOS Simulator,name=iPhone 14,OS=16.0' -resultBundlePath TestResults
    
    - name: Upload Test Results
      if: success() || failure()
      uses: actions/upload-artifact@v3
      with:
        name: test-results
        path: TestResults
```

#### Jenkins 配置

1. 安装 Xcode 集成插件
2. 创建 iOS 构建作业
3. 配置源代码管理
4. 添加构建步骤，运行 xcodebuild 命令
5. 配置测试报告发布

### 测试报告

使用第三方工具生成更好的测试报告：

```bash
# 使用 xcpretty 格式化输出
xcodebuild test -project MyApp.xcodeproj -scheme MyApp -destination 'platform=iOS Simulator,name=iPhone 14,OS=16.0' | xcpretty

# 生成 JUnit 格式报告
xcodebuild test -project MyApp.xcodeproj -scheme MyApp -destination 'platform=iOS Simulator,name=iPhone 14,OS=16.0' | xcpretty --report junit --output tests.xml
```

### 测试计划和配置

Xcode 11+ 支持测试计划(Test Plans)：

1. 在 Xcode 中，选择 Product > Scheme > Edit Scheme
2. 选择 Test 选项
3. 点击 "+" 按钮创建新的测试计划
4. 配置要包含的测试目标和选项
5. 可创建多个测试计划，如"单元测试"、"UI 测试"、"完整测试"等

## 最佳实践

### 测试命名与组织

```swift
// 使用描述性命名
func testLoginWithValidCredentialsShouldSucceed() { ... }
func testLoginWithInvalidCredentialsShouldFail() { ... }

// 使用 GIVEN-WHEN-THEN 格式
func testGivenValidUserWhenLoggingInThenNavigatesToHomeScreen() { ... }
```

### 测试大小分类

根据执行速度和复杂性分类测试：

- **小型测试**：快速单元测试，无外部依赖
- **中型测试**：集成测试，可能有外部依赖
- **大型测试**：端到端测试，包括UI测试

### 测试金字塔

遵循测试金字塔原则，从底向上：

1. **单元测试**（底层）：最多，最快
2. **集成测试**（中层）：中等数量
3. **UI 测试**（顶层）：最少，最慢

### 持续测试

建立持续测试习惯：

1. 编写新功能前先编写测试
2. 修复 bug 前编写展示 bug 的测试
3. 在本地和 CI 中频繁运行测试

### 避免测试反模式

避免这些常见的测试陷阱：

- **脆弱的测试**：过度指定实现细节
- **测试实现而非行为**：专注于测试公共 API 和行为
- **测试数据库访问**：使用内存数据库或模拟
- **依赖测试顺序**：测试应该相互独立
- **忽略测试失败**：始终修复失败的测试

### 保持测试快速

快速测试鼓励频繁运行：

- 将大型集成测试与小型单元测试分开
- 使用模拟替代慢速依赖
- 最小化 `setUp` 和 `tearDown` 中的工作
- 考虑使用并行测试执行

### 测试驱动开发 (TDD)

考虑采用 TDD 方法：

1. **红色**：编写一个失败的测试
2. **绿色**：编写最简代码使测试通过
3. **重构**：改进代码，保持测试通过

### 生产代码中的测试辅助

在主代码中添加测试辅助：

```swift
// 在类中添加测试钩子
class UserManager {
    func login(username: String, password: String, completion: @escaping (Result<User, Error>) -> Void) {
        // 实现...
    }
    
    #if DEBUG
    // 仅在调试构建中可用的测试方法
    func simulateSuccessfulLogin(user: User) {
        // 允许测试直接设置登录状态
    }
    #endif
}

// 使用启动参数启用测试模式
if ProcessInfo.processInfo.arguments.contains("-UITesting") {
    // 配置应用用于 UI 测试
    setupTestEnvironment()
}
```

## 常见问题解答

### 如何排除测试失败？

测试失败时的调试步骤：

1. 检查失败消息和期望值
2. 在测试方法中添加断点
3. 逐步执行测试
4. 添加打印语句查看中间值
5. 确保测试环境设置正确

### 如何测试视图控制器？

测试视图控制器的策略：

1. **分离逻辑**：将业务逻辑移至单独的类
2. **测试生命周期**：
   ```swift
   func testViewDidLoad() {
       let viewController = MyViewController()
       viewController.loadViewIfNeeded()
       // 验证初始状态
   }
   ```
3. **测试输出和状态**：
   ```swift
   func testLabelUpdatesWhenModelChanges() {
       let viewController = MyViewController()
       viewController.loadViewIfNeeded()
       
       viewController.model = newValue
       
       XCTAssertEqual(viewController.label.text, expectedText)
   }
   ```

### 如何处理后台线程中的断言？

在后台线程中运行的代码可能需要特殊处理：

```swift
func testAsyncOperation() {
    // 使用期望等待后台操作完成
    let expectation = self.expectation(description: "Background operation")
    
    // 启动异步操作
    viewModel.performBackgroundOperation {
        // 这些断言在后台线程中执行
        XCTAssertEqual(viewModel.result, expectedValue)
        expectation.fulfill()
    }
    
    waitForExpectations(timeout: 1.0)
}
```

### 为什么应该避免测试私有方法？

测试私有方法有几个问题：

1. 测试应关注类的公共 API 和行为
2. 测试私有方法会使测试与实现细节耦合
3. 当内部实现更改时，测试会变得脆弱
4. 如果私有方法需要单独测试，可能应该将其提取到单独的类中

### 如何测试网络请求？

测试网络代码的最佳实践：

1. 使用协议和依赖注入使网络层可测试
2. 使用模拟网络会话返回预定义响应
3. 避免在单元测试中进行实际网络调用
4. 考虑使用真实网络的单独集成测试套件

### 如何提高测试性能？

加速测试套件的技巧：

1. 关注单元测试而非集成测试
2. 使用内存数据存储而非文件或数据库操作
3. 最小化 `setUp` 和 `tearDown` 中的工作
4. 启用并行测试执行：
   - 选择 Edit Scheme > Test > Options
   - 勾选 "Execute in parallel"
5. 标记慢速测试：
   ```swift
   func testExpensiveOperation() throws {
       try XCTSkipIf(ProcessInfo.processInfo.environment["SKIP_SLOW_TESTS"] == "YES")
       // 执行慢速测试...
   }
   ```

### 如何在 CI 中处理 UI 测试失败？

UI 测试在 CI 中更容易失败：

1. 添加重试机制：
   ```swift
   func testUserRegistration() throws {
       for attempt in 1...3 {
           do {
               try performRegistrationSteps()
               return // 成功则返回
           } catch {
               if attempt == 3 { throw error } // 最后一次尝试时抛出
               print("尝试 \(attempt) 失败，重试中...")
               sleep(2) // 在重试前等待
           }
       }
   }
   ```

2. 添加更多日志和截图：
   ```swift
   func captureScreenshotOnFailure(_ name: String) {
       let screenshot = app.screenshot()
       let attachment = XCTAttachment(screenshot: screenshot)
       attachment.name = name
       attachment.lifetime = .keepAlways
       add(attachment)
   }
   ```

3. 使用更长的超时和等待：
   ```swift
   // 增加 CI 环境中的超时时间
   let timeout: TimeInterval = ProcessInfo.processInfo.environment["CI"] != nil ? 10.0 : 2.0
   XCTAssertTrue(element.waitForExistence(timeout: timeout))
   ```

### 如何生成和查看代码覆盖率报告？

生成详细覆盖率报告的步骤：

1. 在 Xcode 中启用代码覆盖率收集
2. 运行测试
3. 在 Xcode 的 Report Navigator 中查看覆盖率
4. 使用命令行生成报告：
   ```bash
   xcrun llvm-cov show -instr-profile=Coverage.profdata MyApp.xctest/Contents/MacOS/MyApp > coverage.txt
   ```
5. 考虑使用第三方工具如 Slather 或 Codecov 集成到 CI 流程中

---

本教程涵盖了使用 XCTest 框架进行 iOS 应用测试的核心概念和最佳实践。通过应用这些技术，您可以创建健壮、可维护的测试套件，提高代码质量，并更有信心地进行应用程序开发。随着测试经验的积累，您会发现测试不仅是一种验证手段，也是一种强大的设计工具，能够引导您创建更清晰、更模块化的代码结构。
