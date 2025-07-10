# iOS UI 测试 - 界面自动化测试指南

## 简介

UI 测试是移动应用质量保证过程中的重要环节，它通过模拟用户与应用界面的交互来验证应用的功能和用户体验。在 iOS 开发中，Apple 提供了强大的 XCUITest 框架，作为 XCTest 框架的一部分，专门用于 UI 自动化测试。本文档将全面介绍如何使用这些工具为 iOS 应用构建稳定、可靠的 UI 测试，以确保应用在各种条件下都能如预期般运行。

UI 测试能够帮助开发者检测界面变更带来的回归问题，确保关键用户流程正常工作，并在持续集成环境中自动验证应用的用户体验。通过本教程，您将学习如何设计、编写和维护高质量的 UI 测试，使其成为应用开发生命周期中的宝贵资产。

## 目录

- [基础概念](#基础概念)
- [搭建测试环境](#搭建测试环境)
- [编写第一个 UI 测试](#编写第一个-ui-测试)
- [查找和交互 UI 元素](#查找和交互-ui-元素)
- [测试常见交互模式](#测试常见交互模式)
- [处理异步操作](#处理异步操作)
- [测试表格和集合视图](#测试表格和集合视图)
- [测试导航和过渡](#测试导航和过渡)
- [模拟用户输入](#模拟用户输入)
- [测试手势和触摸事件](#测试手势和触摸事件)
- [截图和视觉验证](#截图和视觉验证)
- [设置测试状态和数据](#设置测试状态和数据)
- [高级测试技术](#高级测试技术)
- [测试可访问性](#测试可访问性)
- [性能和可靠性](#性能和可靠性)
- [集成到 CI/CD 流程](#集成到-cicd-流程)
- [最佳实践](#最佳实践)
- [故障排除指南](#故障排除指南)
- [常见问题解答](#常见问题解答)

## 基础概念

### UI 测试与单元测试的区别

UI 测试和单元测试在测试范围、执行速度和稳定性方面有明显区别：

| 特性 | UI 测试 | 单元测试 |
|-----|--------|---------|
| 测试范围 | 整个应用的用户界面和交互 | 独立代码单元的功能 |
| 执行速度 | 较慢，需启动应用并执行实际操作 | 快速，直接执行代码 |
| 稳定性 | 较低，受多种外部因素影响 | 高，测试环境可控 |
| 维护成本 | 较高，UI 变更可能导致测试失败 | 较低，仅受 API 变更影响 |
| 测试价值 | 验证端到端用户体验 | 验证逻辑正确性 |

UI 测试补充了单元测试，通过从用户视角验证应用，能发现单元测试无法捕获的问题。

### XCUITest 框架概述

XCUITest 是 Apple 官方的 UI 测试框架，集成在 Xcode 中。它提供了一套全面的工具和 API，用于自动化测试 iOS 应用的用户界面。

主要组件包括：

- **XCUIApplication**：表示被测应用的实例
- **XCUIElement**：表示 UI 元素（按钮、文本框等）
- **XCUIElementQuery**：用于查找 UI 元素的查询系统
- **XCUICoordinate**：表示屏幕上的坐标点，用于精确的触摸操作

XCUITest 的优势：

- 完全集成到 Xcode 和 iOS 生态系统
- 无需额外依赖或第三方库
- 可靠地检测和交互 UI 元素
- 支持模拟各种用户手势和输入
- 通过 Accessibility API 访问应用界面

### UI 测试架构

一个良好的 UI 测试架构通常包含以下层次：

1. **基础设施层**：测试启动和配置，共享的辅助函数
2. **页面对象层**：封装屏幕和组件的交互逻辑
3. **测试用例层**：实际的测试场景和断言

这种分层架构的优势：

- **可维护性**：UI 变更只需在一处更新
- **可读性**：测试代码更加清晰，表达业务流程
- **可重用性**：页面对象可以在多个测试中重用

### 测试策略

制定有效的 UI 测试策略，应考虑：

- **关键用户流程**：优先测试核心功能和常用路径
- **覆盖范围**：平衡测试覆盖与维护成本
- **测试粒度**：决定何时使用短小的单一功能测试或长流程测试
- **测试数据**：规划如何提供和管理测试数据
- **测试环境**：确保测试在不同环境中的一致性

### UI 测试的优势和局限性

**优势**：

- 从用户视角验证应用
- 测试端到端流程和集成
- 捕获视觉和交互问题
- 自动化重复性测试
- 作为活文档展示应用功能

**局限性**：

- 执行时间较长
- 维护成本较高
- 可能受外部因素影响而变得不稳定
- 不适合测试所有边缘情况
- 设置初始状态可能复杂

了解这些局限性有助于合理规划测试范围，将 UI 测试与其他测试类型（如单元测试和集成测试）结合使用，构建全面的测试策略。

### 何时应该使用 UI 测试

UI 测试最适合以下场景：

- **关键用户流程**：登录、注册、购买流程等
- **跨页面功能**：涉及多个屏幕的操作
- **复杂交互**：手势、动画、自定义控件
- **回归测试**：确保新功能不破坏现有功能
- **验收测试**：确认需求实现符合期望

相比之下，以下情况通常不适合使用 UI 测试：

- 业务逻辑和算法测试
- 数据处理和转换
- 网络请求和响应处理
- 边缘情况和错误处理
- 性能测试（除非特别关注 UI 性能）

## 搭建测试环境

良好的测试环境是成功实施 UI 测试的基础。本节将介绍如何为 iOS 应用创建和配置 UI 测试环境。

### 创建 UI 测试目标

在 Xcode 中创建 UI 测试目标有两种方式：

#### 在新项目中创建

1. 创建新 Xcode 项目时，勾选 "Include UI Tests" 选项
2. Xcode 会自动创建 UI 测试目标和示例测试类

#### 为现有项目添加

1. 选择项目导航器中的项目
2. 点击左下角的 "+" 按钮
3. 选择 "iOS" > "Test" > "UI Testing Bundle"
4. 设置测试目标名称（通常为 `[项目名]UITests`）
5. 点击 "Finish" 完成创建

### UI 测试目标结构

新创建的 UI 测试目标通常包含以下文件：

```
ProjectUITests/
  ├── Info.plist
  └── ProjectUITests.swift (示例测试类)
```

示例测试类包含基本的测试骨架：

```swift
import XCTest

class ProjectUITests: XCTestCase {
    
    override func setUpWithError() throws {
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        // 清理代码
    }
    
    func testExample() throws {
        let app = XCUIApplication()
        app.launch()
        
        // 添加测试代码
    }
}
```

### 配置测试设置

#### 基本设置

在测试类的 `setUp` 方法中配置基本设置：

```swift
override func setUp() {
    super.setUp()
    
    // 禁止测试在失败后继续执行
    continueAfterFailure = false
    
    // 初始化应用
    let app = XCUIApplication()
    
    // 设置启动参数和环境变量
    app.launchArguments = ["-UITesting"]
    app.launchEnvironment = ["UITEST_MODE": "1"]
    
    // 启动应用
    app.launch()
}
```

#### 禁用系统弹窗

系统弹窗（如通知权限请求）会干扰 UI 测试。可以使用以下方法禁用：

```swift
// 在 App Delegate 中
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    // 检查是否处于 UI 测试模式
    if ProcessInfo.processInfo.arguments.contains("-UITesting") {
        // 禁用系统弹窗
        UIApplication.shared.registerForRemoteNotifications()
    }
    return true
}
```

#### 在测试中识别测试模式

在应用代码中，可以检测是否处于测试模式：

```swift
// 检查是否处于 UI 测试模式
let isUITesting = ProcessInfo.processInfo.arguments.contains("-UITesting")
let isUITestingMode = ProcessInfo.processInfo.environment["UITEST_MODE"] == "1"

if isUITesting {
    // 配置测试专用的行为
    setupTestEnvironment()
}
```

### 准备被测应用

为使应用更易于测试，应进行以下准备：

#### 添加可访问性标识符

为关键 UI 元素添加可访问性标识符，使其易于在测试中查找：

```swift
// 为按钮添加标识符
loginButton.accessibilityIdentifier = "loginButton"

// 为文本字段添加标识符
usernameTextField.accessibilityIdentifier = "usernameField"
passwordTextField.accessibilityIdentifier = "passwordField"
```

这比依赖文本标签或界面位置更可靠，因为标识符通常不会随着 UI 外观变化而改变。

#### 创建测试专用模式

为应用添加测试专用模式，简化测试环境设置：

```swift
func setupTestEnvironment() {
    // 使用测试数据
    UserDefaults.standard.set("testuser", forKey: "savedUsername")
    
    // 绕过耗时的初始化
    skipAnimations = true
    
    // 使用模拟服务而非真实 API
    NetworkManager.shared.useTestServer = true
}
```

#### 添加 UI 测试辅助方法

在应用中添加辅助方法，专门用于支持 UI 测试：

```swift
// 只在调试和测试构建中包含
#if DEBUG
extension AppDelegate {
    // 允许测试设置特定状态
    @objc func setUITestingState(_ state: String) {
        switch state {
        case "loggedIn":
            setupAuthenticatedState()
        case "onboarding":
            showOnboarding()
        default:
            resetToInitialState()
        }
    }
}
#endif
```

这些辅助方法可以通过 URL 方案或启动参数调用，帮助快速设置测试环境。

### 设置测试数据

可靠的测试需要一致的测试数据。有几种方式可以管理测试数据：

#### 使用预定义的测试账户

```swift
let testUser = "uitest@example.com"
let testPassword = "Test@123"

func testLogin() {
    let app = XCUIApplication()
    app.launch()
    
    let emailField = app.textFields["emailField"]
    emailField.tap()
    emailField.typeText(testUser)
    
    let passwordField = app.secureTextFields["passwordField"]
    passwordField.tap()
    passwordField.typeText(testPassword)
    
    app.buttons["loginButton"].tap()
    
    // 验证登录成功
}
```

#### 使用模拟后端

在测试模式下，配置应用使用模拟后端，返回可预测的响应：

```swift
if ProcessInfo.processInfo.arguments.contains("-UITesting") {
    // 设置模拟网络服务
    NetworkService.shared = MockNetworkService()
}

// 模拟服务实现
class MockNetworkService: NetworkServiceProtocol {
    func fetchUserData(completion: @escaping (User?) -> Void) {
        // 返回预定义的测试用户数据
        let testUser = User(id: "test123", name: "测试用户", email: "test@example.com")
        completion(testUser)
    }
}
```

#### 使用专用测试数据库

为 UI 测试创建独立的本地数据库：

```swift
if ProcessInfo.processInfo.arguments.contains("-UITesting") {
    // 使用测试专用的数据库配置
    DatabaseManager.shared.configureForTesting()
}

// 在数据库管理器中
func configureForTesting() {
    // 使用内存数据库或测试专用的数据库文件
    let testDBPath = NSTemporaryDirectory() + "test_database.sqlite"
    databasePath = testDBPath
    
    // 预填充测试数据
    seedTestData()
}

func seedTestData() {
    // 添加测试用户、产品等数据
}
```

## 编写第一个 UI 测试

现在我们已经设置好了测试环境，让我们编写第一个 UI 测试。我们将从一个简单的登录测试开始。

### 基本测试结构

UI 测试通常遵循以下模式：

1. **设置**：启动应用并准备测试环境
2. **交互**：执行用户操作（点击、输入文本等）
3. **验证**：检查应用状态和 UI 变化

下面是登录功能的基本测试：

```swift
import XCTest

class LoginUITests: XCTestCase {
    
    let app = XCUIApplication()
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        app.launch()
    }
    
    func testSuccessfulLogin() {
        // 找到输入字段
        let emailField = app.textFields["emailField"]
        let passwordField = app.secureTextFields["passwordField"]
        let loginButton = app.buttons["loginButton"]
        
        // 验证元素存在
        XCTAssertTrue(emailField.exists, "邮箱字段不存在")
        XCTAssertTrue(passwordField.exists, "密码字段不存在")
        XCTAssertTrue(loginButton.exists, "登录按钮不存在")
        
        // 执行登录操作
        emailField.tap()
        emailField.typeText("test@example.com")
        
        passwordField.tap()
        passwordField.typeText("password123")
        
        loginButton.tap()
        
        // 验证登录成功
        let welcomeMessage = app.staticTexts["welcomeMessage"]
        XCTAssertTrue(welcomeMessage.waitForExistence(timeout: 2), "欢迎消息未显示，登录可能失败")
        XCTAssertEqual(welcomeMessage.label, "欢迎, 测试用户")
    }
    
    func testFailedLogin() {
        // 找到输入字段
        let emailField = app.textFields["emailField"]
        let passwordField = app.secureTextFields["passwordField"]
        let loginButton = app.buttons["loginButton"]
        
        // 执行登录操作，使用错误的凭据
        emailField.tap()
        emailField.typeText("wrong@example.com")
        
        passwordField.tap()
        passwordField.typeText("wrongpassword")
        
        loginButton.tap()
        
        // 验证错误消息显示
        let errorMessage = app.staticTexts["errorMessage"]
        XCTAssertTrue(errorMessage.waitForExistence(timeout: 2), "错误消息未显示")
        XCTAssertEqual(errorMessage.label, "用户名或密码不正确")
    }
}
```

### 使用 XCTest 录制功能

Xcode 提供了录制功能，可以自动生成 UI 测试代码：

1. 打开 UI 测试文件
2. 将光标放在测试方法中
3. 点击 Xcode 底部的录制按钮（红色圆圈）
4. 与应用交互执行测试步骤
5. 停止录制
6. Xcode 会生成相应的测试代码

录制功能生成的代码通常需要手动优化：

- 替换基于位置或索引的查询为标识符
- 添加有意义的断言
- 整理和组织代码结构

### 运行测试

运行 UI 测试的方法：

1. **运行单个测试**：点击测试方法旁边的菱形按钮
2. **运行测试类**：点击测试类名称旁边的菱形按钮
3. **运行所有 UI 测试**：选择 Product > Test，或使用快捷键 ⌘+U

UI 测试运行时，模拟器会启动应用，并自动执行测试步骤。Xcode 会显示测试结果，包括成功、失败或错误信息。

### 使用 XCTContext 添加测试附件

XCTest 允许向测试报告添加附件，如截图或日志：

```swift
func testWithAttachments() {
    // 执行测试步骤...
    
    // 添加截图附件
    let screenshot = XCUIScreen.main.screenshot()
    let attachment = XCTAttachment(screenshot: screenshot)
    attachment.name = "登录界面截图"
    attachment.lifetime = .keepAlways
    add(attachment)
    
    // 添加日志附件
    let log = """
    测试日志：
    - 时间: \(Date())
    - 用户: test@example.com
    - 结果: 成功
    """
    let logAttachment = XCTAttachment(string: log)
    logAttachment.name = "测试日志"
    logAttachment.lifetime = .keepAlways
    add(logAttachment)
}
```

这些附件将显示在测试报告中，有助于诊断测试失败。

### 处理测试失败

合理处理测试失败可以提高测试的可靠性：

```swift
func testWithErrorHandling() {
    // 尝试执行可能失败的操作
    do {
        try performRiskyOperation()
    } catch {
        XCTFail("操作失败: \(error.localizedDescription)")
    }
    
    // 条件性测试
    if !app.buttons["nextButton"].exists {
        XCTFail("下一步按钮未出现")
        return // 提前退出，避免后续步骤依赖此按钮
    }
    
    // 继续测试...
}
```

### 使用 XCTIssue 提供详细错误信息

在 Xcode 12 及更高版本中，可以使用 `XCTIssue` 提供更详细的错误信息：

```swift
func testWithDetailedErrors() {
    guard app.buttons["loginButton"].exists else {
        let issue = XCTIssue(
            type: .assertionFailure,
            compactDescription: "登录按钮不存在",
            detailedDescription: """
            无法找到登录按钮。可能原因：
            1. 按钮的标识符可能已更改
            2. 应用可能未加载到登录界面
            3. 按钮可能被其他元素遮挡
            """,
            sourceCodeContext: XCTSourceCodeContext(
                location: XCTSourceCodeLocation(
                    filePath: #file,
                    lineNumber: #line
                )
            ),
            associatedError: nil,
            attachments: [XCTAttachment(screenshot: XCUIScreen.main.screenshot())]
        )
        record(issue)
        return
    }
    
    // 继续测试...
}
```

## 查找和交互 UI 元素

XCUITest 框架提供了强大的查询系统，用于查找和交互 UI 元素。本节将介绍如何高效地查询和操作界面元素。

### 元素查询基础

XCUITest 使用查询链来定位 UI 元素。基本查询结构如下：

```swift
app.element_type.element_identifier
```

常见的元素类型包括：

- `buttons`：按钮
- `staticTexts`：标签和文本
- `textFields`：文本输入框
- `secureTextFields`：密码输入框
- `switches`：开关
- `sliders`：滑块
- `pickers`：选择器
- `tables`：表格视图
- `cells`：表格单元格
- `collectionViews`：集合视图
- `images`：图像
- `scrollViews`：滚动视图
- `webViews`：网页视图
- `alerts`：弹窗
- `navigationBars`：导航栏

### 常用的查询方法

#### 通过标识符查询

```swift
// 使用可访问性标识符（最推荐的方法）
let loginButton = app.buttons["loginButton"]
let usernameField = app.textFields["usernameField"]

// 检查元素是否存在
XCTAssertTrue(loginButton.exists)
```

#### 通过标签文本查询

```swift
// 通过显示的文本查找
let loginButton = app.buttons["登录"]
let forgotPasswordLink = app.staticTexts["忘记密码？"]
```

#### 通过谓词查询

```swift
// 使用谓词匹配部分文本
let predicate = NSPredicate(format: "label CONTAINS '登录'")
let loginButton = app.buttons.element(matching: predicate)

// 使用谓词匹配多个条件
let complexPredicate = NSPredicate(format: "label BEGINSWITH '欢迎' AND isEnabled == true")
let welcomeLabel = app.staticTexts.element(matching: complexPredicate)
```

#### 通过索引查询

```swift
// 获取第一个按钮（索引从 0 开始）
let firstButton = app.buttons.element(boundBy: 0)

// 获取第二个文本字段
let secondTextField = app.textFields.element(boundBy: 1)
```

#### 通过层次结构查询

```swift
// 查找特定容器内的元素
let loginForm = app.otherElements["loginForm"]
let submitButton = loginForm.buttons["提交"]

// 查找单元格内的标签
let nameLabel = app.tables.cells.element(boundBy: 0).staticTexts["nameLabel"]
```

### 处理元素集合

当查询返回多个元素时，可以使用以下方法处理：

```swift
// 获取所有按钮
let allButtons = app.buttons

// 遍历所有按钮
for i in 0..<allButtons.count {
    let button = allButtons.element(boundBy: i)
    print("按钮 \(i): \(button.label)")
}

// 获取满足条件的所有元素
let redButtons = app.buttons.matching(NSPredicate(format: "value CONTAINS '红色'"))

// 获取元素数量
let textFieldCount = app.textFields.count
XCTAssertEqual(textFieldCount, 3, "应该有 3 个文本字段")
```

### 元素属性和状态

XCUIElement 提供了许多属性，用于检查元素的状态：

```swift
// 检查元素是否存在
XCTAssertTrue(loginButton.exists)

// 检查元素是否可见
XCTAssertTrue(loginButton.isHittable)

// 检查元素是否启用
XCTAssertTrue(loginButton.isEnabled)

// 获取元素标签（显示文本）
XCTAssertEqual(welcomeLabel.label, "欢迎回来")

// 获取元素值
XCTAssertEqual(usernameField.value as? String, "admin")

// 获取元素占位符文本
let placeholderText = usernameField.placeholderValue as? String
XCTAssertEqual(placeholderText, "请输入用户名")

// 检查开关状态
let rememberMeSwitch = app.switches["rememberMeSwitch"]
XCTAssertEqual(rememberMeSwitch.value as? String, "1") // 开启状态
```

### 基本交互操作

XCUIElement 支持多种交互操作，模拟用户行为：

#### 点击操作

```swift
// 简单点击
loginButton.tap()

// 双击
imageView.doubleTap()

// 双指点击（放大）
mapView.twoFingerTap()
```

#### 文本输入

```swift
// 点击文本字段并输入文本
usernameField.tap()
usernameField.typeText("测试用户")

// 清除并输入新文本
usernameField.tap()
usernameField.clearAndEnterText("新用户名")

// 辅助函数
extension XCUIElement {
    func clearAndEnterText(_ text: String) {
        // 清除现有文本
        guard let stringValue = value as? String else {
            XCTFail("无法获取文本字段的值")
            return
        }
        
        tap()
        
        let deleteString = String(repeating: XCUIKeyboardKey.delete.rawValue, count: stringValue.count)
        typeText(deleteString)
        
        // 输入新文本
        typeText(text)
    }
}
```

#### 滑动和滚动

```swift
// 简单滑动
app.swipeUp()
app.swipeDown()
app.swipeLeft()
app.swipeRight()

// 在特定元素上滑动
tableView.swipeUp()

// 滚动到特定元素
app.tables.cells["底部单元格"].scrollToVisible()

// 自定义滑动
let startCoordinate = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.8))
let endCoordinate = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.2))
startCoordinate.press(forDuration: 0.01, thenDragTo: endCoordinate)
```

#### 拖拽操作

```swift
// 拖拽元素
let sourceElement = app.tables.cells.element(boundBy: 0)
let destinationElement = app.tables.cells.element(boundBy: 5)

sourceElement.press(forDuration: 0.5, thenDragTo: destinationElement)
```

#### 长按操作

```swift
// 长按元素
listItem.press(forDuration: 2.0)

// 长按后执行菜单操作
listItem.press(forDuration: 2.0)
app.menuItems["删除"].tap()
```

### 等待元素出现

UI 测试中常需要等待元素出现或消失：

```swift
// 等待元素出现，带超时
let exists = loadingIndicator.waitForExistence(timeout: 5)
XCTAssertTrue(exists, "加载指示器未出现")

// 等待元素消失
let predicate = NSPredicate(format: "exists == false")
let expectation = XCTNSPredicateExpectation(predicate: predicate, object: loadingIndicator)
let result = XCTWaiter().wait(for: [expectation], timeout: 5.0)
XCTAssertEqual(result, .completed, "加载指示器未消失")

// 等待元素变为可交互
let buttonPredicate = NSPredicate(format: "isEnabled == true")
let buttonExpectation = XCTNSPredicateExpectation(predicate: buttonPredicate, object: submitButton)
let buttonResult = XCTWaiter().wait(for: [buttonExpectation], timeout: 3.0)
XCTAssertEqual(buttonResult, .completed, "提交按钮未启用")
```

### 查询优化技巧

有效的查询策略可以提高测试的可靠性和性能：

#### 使用可访问性标识符

```swift
// 在应用代码中设置
loginButton.accessibilityIdentifier = "loginButton"

// 在测试中使用
app.buttons["loginButton"].tap()
```

#### 缓存查询结果

```swift
// 缓存频繁使用的元素引用
let tabBar = app.tabBars.element
let profileTab = tabBar.buttons["个人资料"]
let settingsTab = tabBar.buttons["设置"]

// 使用缓存的引用
profileTab.tap()
// 执行操作...
settingsTab.tap()
```

#### 使用后代匹配器优化查询

```swift
// 使用后代匹配器直接查找深层元素
let deepElement = app.descendants(matching: .button)["deepButton"]

// 而不是使用长链式查询
// let deepElement = app.scrollViews.element.otherElements.element.buttons["deepButton"]
```

## 测试常见交互模式

本节将介绍如何测试 iOS 应用中常见的用户交互模式。

### 测试导航栏操作

```swift
func testNavigationBarInteractions() {
    // 测试导航栏标题
    let navBar = app.navigationBars.element
    XCTAssertEqual(navBar.identifier, "设置")
    
    // 测试返回按钮
    let backButton = navBar.buttons.element(boundBy: 0)
    backButton.tap()
    
    // 测试导航栏右侧按钮
    let addButton = app.navigationBars.element.buttons["添加"]
    addButton.tap()
    
    // 验证新视图已显示
    XCTAssertTrue(app.navigationBars["新项目"].exists)
}
```

### 测试标签栏切换

```swift
func testTabBarNavigation() {
    // 获取标签栏
    let tabBar = app.tabBars.element
    
    // 切换到"设置"标签
    tabBar.buttons["设置"].tap()
    XCTAssertTrue(app.navigationBars["设置"].exists)
    
    // 切换到"个人资料"标签
    tabBar.buttons["个人资料"].tap()
    XCTAssertTrue(app.navigationBars["个人资料"].exists)
    
    // 切换到"主页"标签
    tabBar.buttons["主页"].tap()
    XCTAssertTrue(app.navigationBars["主页"].exists)
}
```

### 测试表格视图交互

```swift
func testTableViewInteractions() {
    // 获取表格
    let table = app.tables.element
    
    // 测试滚动
    table.swipeUp(velocity: .fast)
    table.swipeDown(velocity: .slow)
    
    // 测试点击单元格
    let firstCell = table.cells.element(boundBy: 0)
    firstCell.tap()
    
    // 验证导航到详情页
    XCTAssertTrue(app.navigationBars["详情"].exists)
    
    // 返回列表
    app.navigationBars["详情"].buttons.element(boundBy: 0).tap()
    
    // 测试侧滑删除
    let thirdCell = table.cells.element(boundBy: 2)
    thirdCell.swipeLeft()
    
    // 点击删除按钮
    app.buttons["删除"].tap()
    
    // 验证单元格已删除
    XCTAssertEqual(table.cells.count, 9) // 原有 10 个单元格
}
```

### 测试集合视图交互

```swift
func testCollectionViewInteractions() {
    // 获取集合视图
    let collection = app.collectionViews.element
    
    // 测试滚动
    collection.swipeLeft()
    collection.swipeRight()
    
    // 测试点击单元格
    let cell = collection.cells.element(boundBy: 2)
    cell.tap()
    
    // 验证详情视图
    XCTAssertTrue(app.navigationBars["商品详情"].exists)
    
    // 测试分页滚动
    for _ in 0..<5 {
        collection.swipeLeft()
    }
    
    // 验证滚动到末尾
    let lastCell = collection.cells.element(boundBy: collection.cells.count - 1)
    XCTAssertTrue(lastCell.isHittable)
}
```

### 测试弹窗和警告框

```swift
func testAlertInteractions() {
    // 触发显示警告框
    app.buttons["显示警告"].tap()
    
    // 获取警告框
    let alert = app.alerts.element
    
    // 验证警告框标题和消息
    XCTAssertEqual(alert.label, "确认操作")
    XCTAssertTrue(alert.staticTexts["您确定要执行此操作吗？"].exists)
    
    // 点击"确定"按钮
    alert.buttons["确定"].tap()
    
    // 验证警告框已关闭
    XCTAssertFalse(alert.exists)
    
    // 测试取消按钮
    app.buttons["显示警告"].tap()
    app.alerts.element.buttons["取消"].tap()
    XCTAssertFalse(app.alerts.element.exists)
}
```

### 测试动作表（Action Sheet）

```swift
func testActionSheetInteractions() {
    // 触发显示动作表
    app.buttons["显示选项"].tap()
    
    // 获取动作表
    let actionSheet = app.sheets.element
    
    // 验证动作表标题
    XCTAssertEqual(actionSheet.label, "可用选项")
    
    // 验证选项存在
    XCTAssertTrue(actionSheet.buttons["编辑"].exists)
    XCTAssertTrue(actionSheet.buttons["分享"].exists)
    XCTAssertTrue(actionSheet.buttons["删除"].exists)
    XCTAssertTrue(actionSheet.buttons["取消"].exists)
    
    // 选择"编辑"选项
    actionSheet.buttons["编辑"].tap()
    
    // 验证编辑界面显示
    XCTAssertTrue(app.navigationBars["编辑"].exists)
}
```

### 测试开关和滑块

```swift
func testSwitchesAndSliders() {
    // 测试开关
    let notificationSwitch = app.switches["notificationSwitch"]
    
    // 获取初始状态
    let initialValue = notificationSwitch.value as? String
    
    // 切换开关
    notificationSwitch.tap()
    
    // 验证状态改变
    let newValue = notificationSwitch.value as? String
    XCTAssertNotEqual(initialValue, newValue)
    
    // 测试滑块
    let volumeSlider = app.sliders["volumeSlider"]
    
    // 将滑块调至最小值
    volumeSlider.adjust(toNormalizedSliderPosition: 0.0)
    XCTAssertEqual(volumeSlider.value as? String, "0%")
    
    // 将滑块调至最大值
    volumeSlider.adjust(toNormalizedSliderPosition: 1.0)
    XCTAssertEqual(volumeSlider.value as? String, "100%")
    
    // 将滑块调至中间值
    volumeSlider.adjust(toNormalizedSliderPosition: 0.5)
    XCTAssertEqual(volumeSlider.value as? String, "50%")
}
```

### 测试分段控件（Segmented Control）

```swift
func testSegmentedControlInteractions() {
    // 获取分段控件
    let segmentedControl = app.segmentedControls.element
    
    // 获取所有分段
    let segments = segmentedControl.buttons
    XCTAssertEqual(segments.count, 3)
    
    // 验证分段标题
    XCTAssertEqual(segments.element(boundBy: 0).label, "日")
    XCTAssertEqual(segments.element(boundBy: 1).label, "周")
    XCTAssertEqual(segments.element(boundBy: 2).label, "月")
    
    // 选择不同分段
    segments.element(boundBy: 1).tap()
    // 验证周视图显示
    XCTAssertTrue(app.staticTexts["周视图"].exists)
    
    segments.element(boundBy: 2).tap()
    // 验证月视图显示
    XCTAssertTrue(app.staticTexts["月视图"].exists)
}
```

### 测试日期选择器

```swift
func testDatePickerInteractions() {
    // 获取日期选择器
    let datePicker = app.datePickers.element
    
    // 检查日期选择器类型（取决于设置的模式）
    
    // 对于轮盘式日期选择器
    if datePicker.pickerWheels.count > 0 {
        // 选择月份
        datePicker.pickerWheels.element(boundBy: 0).adjust(toPickerWheelValue: "6月")
        
        // 选择日期
        datePicker.pickerWheels.element(boundBy: 1).adjust(toPickerWheelValue: "15")
        
        // 选择年份
        datePicker.pickerWheels.element(boundBy: 2).adjust(toPickerWheelValue: "2023")
    } else {
        // 对于日历式日期选择器，通过坐标点击特定日期
        // 注意：这种方法不太可靠，因为坐标依赖于设备和 UI 布局
        
        // 点击"今天"按钮
        app.buttons["今天"].tap()
        
        // 点击下一个月按钮
        app.buttons["下个月"].tap()
        
        // 点击特定日期（这里需要根据实际日历布局调整）
        let dateCell = app.collectionViews.cells.staticTexts["15"]
        dateCell.tap()
    }
    
    // 验证日期选择结果
    app.buttons["完成"].tap()
    XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label CONTAINS '2023'")).element.exists)
}
```

### 测试步进器（Stepper）

```swift
func testStepperInteractions() {
    // 获取步进器
    let stepper = app.steppers["quantityStepper"]
    
    // 获取增加和减少按钮
    let incrementButton = stepper.buttons.element(boundBy: 1)
    let decrementButton = stepper.buttons.element(boundBy: 0)
    
    // 获取当前值显示
    let valueLabel = app.staticTexts["quantityValue"]
    XCTAssertEqual(valueLabel.label, "1") // 默认值
    
    // 增加值
    incrementButton.tap()
    incrementButton.tap()
    XCTAssertEqual(valueLabel.label, "3")
    
    // 减少值
    decrementButton.tap()
    XCTAssertEqual(valueLabel.label, "2")
}
```

### 测试长列表的滚动和加载

```swift
func testLongListScrollingAndLoading() {
    // 获取表格视图
    let table = app.tables.element
    
    // 记录初始可见单元格
    let initialVisibleCellCount = table.cells.matching(NSPredicate(format: "isHittable == true")).count
    
    // 执行多次滚动，直到看到"加载更多"按钮
    var loadMoreButtonFound = false
    for _ in 0..<10 {
        table.swipeUp()
        
        if app.buttons["加载更多"].exists {
            loadMoreButtonFound = true
            break
        }
    }
    
    XCTAssertTrue(loadMoreButtonFound, "未找到'加载更多'按钮")
    
    // 点击加载更多
    app.buttons["加载更多"].tap()
    
    // 等待加载完成
    let loadingIndicator = app.activityIndicators.element
    let disappearExpectation = XCTNSPredicateExpectation(
        predicate: NSPredicate(format: "exists == false"),
        object: loadingIndicator
    )
    XCTWaiter().wait(for: [disappearExpectation], timeout: 5.0)
    
    // 继续滚动查看新加载的内容
    table.swipeUp()
    
    // 验证加载了更多单元格
    let newVisibleCellCount = table.cells.matching(NSPredicate(format: "isHittable == true")).count
    XCTAssertGreaterThan(table.cells.count, initialVisibleCellCount, "加载更多后单元格数量未增加")
}
```

## 处理异步操作

UI 测试中的一个主要挑战是处理异步操作，如网络请求、动画和视图转换。本节将介绍有效测试异步行为的策略。

### 使用 waitForExistence

最简单的等待方法是使用 `waitForExistence` 等待 UI 元素出现：

```swift
// 等待最多 5 秒钟，直到元素出现
let exists = app.buttons["完成"].waitForExistence(timeout: 5.0)
XCTAssertTrue(exists, "完成按钮未在预期时间内出现")

// 如果元素出现，继续测试
if exists {
    app.buttons["完成"].tap()
}
```

### 使用 XCTWaiter 和期望

对于更复杂的等待条件，可以使用 `XCTWaiter` 和 `XCTNSPredicateExpectation`：

```swift
// 创建断言期望
let predicate = NSPredicate(format: "count > 5")
let expectation = XCTNSPredicateExpectation(predicate: predicate, object: app.tables.cells)

// 等待期望满足
let result = XCTWaiter().wait(for: [expectation], timeout: 10.0)

// 检查结果
if result == .completed {
    // 期望满足，继续测试
    app.tables.cells.element(boundBy: 5).tap()
} else {
    XCTFail("表格未在预期时间内加载足够的单元格")
}
```

### 组合多个期望

有时需要等待多个条件同时满足：

```swift
// 创建多个期望
let loadingPredicate = NSPredicate(format: "exists == false")
let loadingExpectation = XCTNSPredicateExpectation(predicate: loadingPredicate, object: app.activityIndicators["loadingIndicator"])

let contentPredicate = NSPredicate(format: "exists == true")
let contentExpectation = XCTNSPredicateExpectation(predicate: contentPredicate, object: app.tables["contentTable"])

// 等待所有期望满足
let result = XCTWaiter().wait(for: [loadingExpectation, contentExpectation], timeout: 10.0)

// 检查结果
XCTAssertEqual(result, .completed, "加载指示器未消失或内容未显示")
```

### 使用 XCTestCase 期望

对于更传统的异步测试模式，可以使用 `XCTestCase` 的期望方法：

```swift
func testAsyncOperation() {
    // 创建期望
    let expectation = expectation(description: "数据加载完成")
    
    // 启动异步操作
    app.buttons["加载数据"].tap()
    
    // 在异步完成时履行期望
    DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
        if app.staticTexts["dataLoaded"].exists {
            expectation.fulfill()
        }
    }
    
    // 等待期望满足，最多等待 5 秒
    waitForExpectations(timeout: 5.0) { error in
        if let error = error {
            XCTFail("等待超时: \(error.localizedDescription)")
        }
    }
    
    // 期望满足后继续测试
    XCTAssertTrue(app.staticTexts["数据已加载"].exists)
}
```

### 轮询检查状态

对于没有明确 UI 指示器的异步操作，可以实现轮询机制：

```swift
func waitForCondition(timeout: TimeInterval, handler: @escaping () -> Bool) -> Bool {
    let startTime = Date()
    
    while Date().timeIntervalSince(startTime) < timeout {
        if handler() {
            return true
        }
        // 短暂睡眠以减少 CPU 使用
        Thread.sleep(forTimeInterval: 0.1)
        // 允许运行循环处理 UI 更新
        RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.01))
    }
    
    return false
}

// 使用轮询等待表格数据加载
let dataLoaded = waitForCondition(timeout: 10.0) {
    return app.tables.cells.count > 0
}
XCTAssertTrue(dataLoaded, "表格数据未加载")
```

### 处理异步加载指示器

测试包含加载指示器的异步操作：

```swift
func testAsyncLoading() {
    // 触发异步加载
    app.buttons["刷新"].tap()
    
    // 验证加载指示器显示
    let loadingIndicator = app.activityIndicators["loadingIndicator"]
    XCTAssertTrue(loadingIndicator.waitForExistence(timeout: 2.0), "加载指示器未显示")
    
    // 等待加载指示器消失
    let disappearPredicate = NSPredicate(format: "exists == false")
    let expectation = XCTNSPredicateExpectation(predicate: disappearPredicate, object: loadingIndicator)
    
    let result = XCTWaiter().wait(for: [expectation], timeout: 10.0)
    XCTAssertEqual(result, .completed, "加载指示器未消失，可能表示加载失败")
    
    // 验证内容已加载
    XCTAssertTrue(app.tables["dataTable"].exists)
    XCTAssertGreaterThan(app.tables["dataTable"].cells.count, 0, "表格无数据")
}
```

### 处理网络请求

UI 测试中的网络请求通常应该被模拟或存根：

```swift
// 在应用委托中检测 UI 测试模式
if ProcessInfo.processInfo.arguments.contains("-UITesting") {
    // 使用模拟网络层
    setupMockNetworking()
}

// 在测试设置中配置模拟响应
app.launchArguments = ["-UITesting", "-mockNetworkResponses"]
app.launchEnvironment = ["MOCK_RESPONSE_DELAY": "1.5"] // 模拟 1.5 秒的网络延迟
```

### 处理定时操作

测试定时触发的 UI 变化：

```swift
func testTimedOperation() {
    // 启动有计时器的操作
    app.buttons["startTimer"].tap()
    
    // 等待自动跳转（假设 5 秒后跳转）
    let nextScreenPredicate = NSPredicate(format: "exists == true")
    let expectation = XCTNSPredicateExpectation(predicate: nextScreenPredicate, object: app.navigationBars["结果"])
    
    let result = XCTWaiter().wait(for: [expectation], timeout: 7.0) // 给予一些缓冲时间
    XCTAssertEqual(result, .completed, "未在预期时间内跳转到结果屏幕")
}
```

### 自定义等待辅助方法

创建通用的等待辅助方法，简化异步测试：

```swift
extension XCTestCase {
    func waitForElementToExist(_ element: XCUIElement, timeout: TimeInterval = 5.0, file: StaticString = #file, line: UInt = #line) -> Bool {
        let exists = element.waitForExistence(timeout: timeout)
        if !exists {
            XCTFail("元素未在 \(timeout) 秒内出现", file: file, line: line)
        }
        return exists
    }
    
    func waitForElementToDisappear(_ element: XCUIElement, timeout: TimeInterval = 5.0, file: StaticString = #file, line: UInt = #line) -> Bool {
        let predicate = NSPredicate(format: "exists == false")
        let expectation = XCTNSPredicateExpectation(predicate: predicate, object: element)
        let result = XCTWaiter().wait(for: [expectation], timeout: timeout)
        
        if result != .completed {
            XCTFail("元素未在 \(timeout) 秒内消失", file: file, line: line)
            return false
        }
        return true
    }
    
    func waitForElementToBeHittable(_ element: XCUIElement, timeout: TimeInterval = 5.0, file: StaticString = #file, line: UInt = #line) -> Bool {
        let predicate = NSPredicate(format: "isHittable == true")
        let expectation = XCTNSPredicateExpectation(predicate: predicate, object: element)
        let result = XCTWaiter().wait(for: [expectation], timeout: timeout)
        
        if result != .completed {
            XCTFail("元素未在 \(timeout) 秒内变为可交互", file: file, line: line)
            return false
        }
        return true
    }
}

// 使用自定义等待方法
func testWithCustomWaits() {
    app.buttons["加载数据"].tap()
    
    // 等待加载指示器消失
    waitForElementToDisappear(app.activityIndicators["loadingIndicator"])
    
    // 等待内容变为可交互
    waitForElementToBeHittable(app.tables["contentTable"].cells.element(boundBy: 0))
    
    // 继续测试
    app.tables["contentTable"].cells.element(boundBy: 0).tap()
}
```

## 测试表格和集合视图

表格视图和集合视图是 iOS 应用中最常用的 UI 组件之一。本节将详细介绍如何测试这些组件。

### 基本表格视图测试

测试表格视图的基本属性和行为：

```swift
func testBasicTableView() {
    // 等待表格加载
    let tableView = app.tables["contactsTable"]
    XCTAssertTrue(tableView.exists, "联系人表格不存在")
    
    // 检查表格单元格数量
    let cellCount = tableView.cells.count
    XCTAssertGreaterThan(cellCount, 0, "表格无数据")
    
    // 验证特定单元格存在
    let specificCell = tableView.cells.staticTexts["张三"]
    XCTAssertTrue(specificCell.exists, "未找到特定联系人")
    
    // 点击单元格
    specificCell.tap()
    
    // 验证导航到详情页
    XCTAssertTrue(app.navigationBars["联系人详情"].exists)
}
```

### 表格视图滚动和搜索

测试表格的滚动和搜索功能：

```swift
func testTableViewScrollingAndSearch() {
    let tableView = app.tables["contactsTable"]
    
    // 测试搜索
    let searchField = app.searchFields["搜索联系人"]
    searchField.tap()
    searchField.typeText("李四")
    
    // 验证搜索结果
    XCTAssertEqual(tableView.cells.count, 1, "搜索结果不符合预期")
    XCTAssertTrue(tableView.cells.staticTexts["李四"].exists)
    
    // 清除搜索
    searchField.buttons["清除文本"].tap()
    
    // 验证表格恢复原状
    XCTAssertGreaterThan(tableView.cells.count, 1)
    
    // 测试滚动到底部
    let lastCell = tableView.cells.element(boundBy: tableView.cells.count - 1)
    lastCell.scrollToVisible()
    XCTAssertTrue(lastCell.isHittable, "无法滚动到最后一个单元格")
}
```

### 测试表格编辑模式

测试表格的编辑功能，如删除和重新排序：

```swift
func testTableViewEditing() {
    let tableView = app.tables["contactsTable"]
    
    // 进入编辑模式
    app.navigationBars["联系人"].buttons["编辑"].tap()
    
    // 测试删除单元格
    let initialCellCount = tableView.cells.count
    
    // 点击第一个单元格的删除按钮
    let firstCell = tableView.cells.element(boundBy: 0)
    firstCell.buttons["删除"].tap()
    
    // 确认删除
    app.buttons["删除"].tap()
    
    // 验证单元格已删除
    XCTAssertEqual(tableView.cells.count, initialCellCount - 1)
    
    // 测试重新排序
    let secondCell = tableView.cells.element(boundBy: 1)
    let reorderControl = secondCell.buttons["重新排序"]
    
    // 拖动单元格到顶部
    let destination = tableView.cells.element(boundBy: 0)
    reorderControl.press(forDuration: 0.5, thenDragTo: destination)
    
    // 退出编辑模式
    app.navigationBars["联系人"].buttons["完成"].tap()
    
    // 验证顺序已改变
    XCTAssertEqual(tableView.cells.element(boundBy: 0).staticTexts.firstMatch.label, secondCell.staticTexts.firstMatch.label)
}
```

### 测试表格下拉刷新

测试表格的下拉刷新功能：

```swift
func testTableViewPullToRefresh() {
    let tableView = app.tables["feedTable"]
    
    // 记录初始状态
    let initialFirstCellText = tableView.cells.element(boundBy: 0).staticTexts.firstMatch.label
    
    // 执行下拉刷新
    let start = tableView.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
    let end = tableView.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.8))
    start.press(forDuration: 0.1, thenDragTo: end)
    
    // 等待刷新完成
    let refreshControl = app.activityIndicators["refreshControl"]
    let predicate = NSPredicate(format: "exists == false")
    let expectation = XCTNSPredicateExpectation(predicate: predicate, object: refreshControl)
    let result = XCTWaiter().wait(for: [expectation], timeout: 5.0)
    XCTAssertEqual(result, .completed, "刷新未在预期时间内完成")
    
    // 验证内容已更新
    let newFirstCellText = tableView.cells.element(boundBy: 0).staticTexts.firstMatch.label
    XCTAssertNotEqual(newFirstCellText, initialFirstCellText, "下拉刷新后内容未更新")
}
```

### 测试表格分页加载

测试表格的分页加载功能：

```swift
func testTableViewPagination() {
    let tableView = app.tables["articlesTable"]
    
    // 记录初始单元格数量
    let initialCellCount = tableView.cells.count
    
    // 滚动到底部
    for _ in 0..<5 {
        tableView.swipeUp()
    }
    
    // 查找并点击"加载更多"按钮
    let loadMoreButton = tableView.buttons["加载更多"]
    XCTAssertTrue(loadMoreButton.exists, "未找到加载更多按钮")
    loadMoreButton.tap()
    
    // 等待加载完成
    let loadingIndicator = app.activityIndicators["loadingMoreIndicator"]
    let predicate = NSPredicate(format: "exists == false")
    let expectation = XCTNSPredicateExpectation(predicate: predicate, object: loadingIndicator)
    let result = XCTWaiter().wait(for: [expectation], timeout: 5.0)
    XCTAssertEqual(result, .completed, "加载更多未在预期时间内完成")
    
    // 验证加载了更多单元格
    XCTAssertGreaterThan(tableView.cells.count, initialCellCount, "分页加载后单元格数量未增加")
}
```

### 测试表格的侧滑操作

测试表格单元格的侧滑操作：

```swift
func testTableViewSwipeActions() {
    let tableView = app.tables["messagesTable"]
    let firstCell = tableView.cells.element(boundBy: 0)
    
    // 左滑显示删除按钮
    firstCell.swipeLeft()
    
    // 验证侧滑操作按钮
    let deleteButton = app.buttons["删除"]
    let archiveButton = app.buttons["归档"]
    
    XCTAssertTrue(deleteButton.exists, "删除按钮未显示")
    XCTAssertTrue(archiveButton.exists, "归档按钮未显示")
    
    // 点击归档按钮
    archiveButton.tap()
    
    // 验证单元格被归档（从列表中移除）
    let archivedCellIdentifier = firstCell.identifier
    XCTAssertFalse(tableView.cells[archivedCellIdentifier].exists, "单元格未被归档")
    
    // 测试右滑操作（如有）
    let secondCell = tableView.cells.element(boundBy: 0)
    secondCell.swipeRight()
    
    // 验证右滑操作按钮
    let markReadButton = app.buttons["标记为已读"]
    XCTAssertTrue(markReadButton.exists, "标记为已读按钮未显示")
    
    // 点击标记为已读按钮
    markReadButton.tap()
    
    // 验证已读状态变化（这取决于应用如何表示已读状态）
    let unreadIndicator = secondCell.otherElements["unreadIndicator"]
    XCTAssertFalse(unreadIndicator.exists, "未读指示器仍然存在")
}
```

### 测试集合视图基本功能

测试集合视图的基本功能：

```swift
func testCollectionViewBasics() {
    let collectionView = app.collectionViews["photoCollection"]
    
    // 检查集合视图存在
    XCTAssertTrue(collectionView.exists, "照片集合视图不存在")
    
    // 检查单元格数量
    let cellCount = collectionView.cells.count
    XCTAssertGreaterThan(cellCount, 0, "集合视图无数据")
    
    // 测试点击单元格
    let firstCell = collectionView.cells.element(boundBy: 0)
    firstCell.tap()
    
    // 验证导航到详情页
    XCTAssertTrue(app.navigationBars["照片详情"].exists, "未导航到照片详情页")
    
    // 返回集合视图
    app.navigationBars["照片详情"].buttons.element(boundBy: 0).tap()
}
```

### 测试集合视图滚动和布局

测试集合视图的滚动和布局变化：

```swift
func testCollectionViewScrollingAndLayout() {
    let collectionView = app.collectionViews["photoCollection"]
    
    // 测试水平滚动
    collectionView.swipeLeft()
    collectionView.swipeRight()
    
    // 测试垂直滚动（如适用）
    collectionView.swipeUp()
    collectionView.swipeDown()
    
    // 测试切换布局
    app.buttons["列表布局"].tap()
    
    // 验证布局已改变（例如，检查单元格高度或宽高比变化）
    let cellAfterLayoutChange = collectionView.cells.element(boundBy: 0)
    // 此处可以检查单元格尺寸或外观的变化
    
    // 切回网格布局
    app.buttons["网格布局"].tap()
}
```

### 测试集合视图选择和多选

测试集合视图的选择和多选功能：

```swift
func testCollectionViewSelection() {
    let collectionView = app.collectionViews["photoCollection"]
    
    // 进入选择模式
    app.navigationBars["照片"].buttons["选择"].tap()
    
    // 选择多个单元格
    collectionView.cells.element(boundBy: 0).tap()
    collectionView.cells.element(boundBy: 2).tap()
    collectionView.cells.element(boundBy: 4).tap()
    
    // 验证选择数量
    let selectionCountText = app.navigationBars["照片"].staticTexts["已选择3项"]
    XCTAssertTrue(selectionCountText.exists, "选择计数未正确显示")
    
    // 执行批量操作
    app.buttons["删除"].tap()
    
    // 确认删除
    app.alerts["删除照片"].buttons["删除"].tap()
    
    // 验证单元格已删除
    XCTAssertEqual(collectionView.cells.count, 2, "删除后单元格数量不正确")
    
    // 退出选择模式
    app.navigationBars["照片"].buttons["取消"].tap()
}
```

### 测试集合视图拖放功能

测试集合视图的拖放功能（iOS 11 及更高版本）：

```swift
func testCollectionViewDragAndDrop() {
    let collectionView = app.collectionViews["arrangeableCollection"]
    
    // 长按第一个单元格开始拖动
    let sourceCell = collectionView.cells.element(boundBy: 0)
    let sourceIdentifier = sourceCell.identifier
    
    // 拖动到第四个单元格位置
    let destinationCell = collectionView.cells.element(boundBy: 3)
    
    sourceCell.press(forDuration: 0.5, thenDragTo: destinationCell)
    
    // 验证顺序已改变
    // 注意：拖放后识别单元格可能变得复杂，因为标识符可能变化
    // 下面的验证方法取决于应用如何实现拖放后的单元格标识
    
    // 方法一：检查第四个单元格是否具有原第一个单元格的内容
    let cellAfterDrop = collectionView.cells.element(boundBy: 3)
    XCTAssertEqual(cellAfterDrop.identifier, sourceIdentifier, "拖放操作未成功改变单元格顺序")
    
    // 方法二：如果单元格有特定内容，可以检查内容位置是否改变
    let specificContent = "特定内容"
    let cellWithContent = collectionView.cells.containing(NSPredicate(format: "label CONTAINS %@", specificContent)).element
    XCTAssertTrue(cellWithContent.exists, "包含特定内容的单元格不存在")
}
```

### 测试集合视图的分段控制器过滤

测试使用分段控制器筛选集合视图内容：

```swift
func testCollectionViewFiltering() {
    // 选择不同的筛选选项
    let segmentedControl = app.segmentedControls["filterControl"]
    
    // 选择"收藏"选项
    segmentedControl.buttons["收藏"].tap()
    
    // 验证集合视图仅显示收藏项目
    let collectionView = app.collectionViews["photoCollection"]
    let favoriteIndicators = collectionView.cells.otherElements["favoriteIndicator"]
    XCTAssertEqual(favoriteIndicators.count, collectionView.cells.count, "筛选后显示了非收藏项目")
    
    // 选择"全部"选项
    segmentedControl.buttons["全部"].tap()
    
    // 验证集合视图显示所有项目
    XCTAssertGreaterThan(collectionView.cells.count, favoriteIndicators.count, "未显示所有项目")
}
```

## 测试导航和过渡

导航是 iOS 应用的核心部分，测试不同视图之间的导航和过渡对于确保应用流程正常工作至关重要。

### 测试导航控制器的推入和弹出

```swift
func testNavigationPushAndPop() {
    // 初始视图
    XCTAssertTrue(app.navigationBars["主页"].exists)
    
    // 点击列表项导航到详情页
    app.tables.cells.element(boundBy: 0).tap()
    
    // 验证已推入详情页
    XCTAssertTrue(app.navigationBars["详情"].exists)
    
    // 测试返回按钮（弹出）
    app.navigationBars["详情"].buttons.element(boundBy: 0).tap()
    
    // 验证已返回主页
    XCTAssertTrue(app.navigationBars["主页"].exists)
    XCTAssertFalse(app.navigationBars["详情"].exists)
}
```

### 测试标签栏控制器

```swift
func testTabBarNavigation() {
    // 初始标签页
    XCTAssertTrue(app.navigationBars["主页"].exists)
    
    // 切换到第二个标签页
    app.tabBars.buttons["收藏"].tap()
    
    // 验证已切换到收藏页面
    XCTAssertTrue(app.navigationBars["收藏"].exists)
    
    // 切换到第三个标签页
    app.tabBars.buttons["设置"].tap()
    
    // 验证已切换到设置页面
    XCTAssertTrue(app.navigationBars["设置"].exists)
    
    // 切换回第一个标签页
    app.tabBars.buttons["主页"].tap()
    
    // 验证已返回主页
    XCTAssertTrue(app.navigationBars["主页"].exists)
}
```

### 测试模态视图的呈现和消除

```swift
func testModalPresentation() {
    // 触发模态视图呈现
    app.buttons["添加"].tap()
    
    // 验证模态视图已呈现
    XCTAssertTrue(app.navigationBars["新建项目"].exists)
    
    // 取消模态视图
    app.buttons["取消"].tap()
    
    // 验证模态视图已消除
    XCTAssertFalse(app.navigationBars["新建项目"].exists)
    XCTAssertTrue(app.navigationBars["主页"].exists)
    
    // 再次呈现模态视图并保存
    app.buttons["添加"].tap()
    
    // 填写表单
    app.textFields["标题"].tap()
    app.textFields["标题"].typeText("测试项目")
    
    // 保存并关闭模态视图
    app.buttons["保存"].tap()
    
    // 验证模态视图已消除且数据已保存
    XCTAssertFalse(app.navigationBars["新建项目"].exists)
    XCTAssertTrue(app.tables.cells.staticTexts["测试项目"].exists)
}
```

### 测试页面控制器

```swift
func testPageController() {
    // 获取页面控制器视图
    let pageView = app.scrollViews["onboardingPages"]
    
    // 滑动到下一页
    pageView.swipeLeft()
    
    // 验证页面指示器状态
    let pageIndicator = app.pageIndicators.element
    XCTAssertEqual(pageIndicator.value as? String, "第 2 页，共 3 页")
    
    // 滑动到最后一页
    pageView.swipeLeft()
    
    // 验证页面指示器状态
    XCTAssertEqual(pageIndicator.value as? String, "第 3 页，共 3 页")
    
    // 滑动回上一页
    pageView.swipeRight()
    
    // 验证页面指示器状态
    XCTAssertEqual(pageIndicator.value as? String, "第 2 页，共 3 页")
    
    // 使用页面控制按钮直接跳转到第三页
    pageIndicator.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
    
    // 验证页面指示器状态
    XCTAssertEqual(pageIndicator.value as? String, "第 3 页，共 3 页")
}
```

### 测试分段控制器导航

```swift
func testSegmentedControlNavigation() {
    // 获取分段控制器
    let segmentedControl = app.segmentedControls["viewSegmentControl"]
    
    // 切换到第二个视图
    segmentedControl.buttons["列表"].tap()
    
    // 验证视图已切换
    XCTAssertTrue(app.tables["listView"].exists)
    XCTAssertFalse(app.collectionViews["gridView"].exists)
    
    // 切换到第三个视图
    segmentedControl.buttons["详情"].tap()
    
    // 验证视图已切换
    XCTAssertTrue(app.scrollViews["detailView"].exists)
    XCTAssertFalse(app.tables["listView"].exists)
    
    // 切换回第一个视图
    segmentedControl.buttons["网格"].tap()
    
    // 验证视图已切换回原始状态
    XCTAssertTrue(app.collectionViews["gridView"].exists)
    XCTAssertFalse(app.scrollViews["detailView"].exists)
}
```

### 测试侧边菜单导航

```swift
func testSideMenuNavigation() {
    // 打开侧边菜单
    app.buttons["menuButton"].tap()
    
    // 验证侧边菜单已显示
    let sideMenu = app.otherElements["sideMenu"]
    XCTAssertTrue(sideMenu.waitForExistence(timeout: 2))
    
    // 选择菜单项
    sideMenu.tables.cells["设置"].tap()
    
    // 验证导航到设置页面
    XCTAssertTrue(app.navigationBars["设置"].exists)
    
    // 返回并再次打开侧边菜单
    app.buttons["menuButton"].tap()
    
    // 选择另一个菜单项
    sideMenu.tables.cells["个人资料"].tap()
    
    // 验证导航到个人资料页面
    XCTAssertTrue(app.navigationBars["个人资料"].exists)
    
    // 测试关闭侧边菜单
    app.buttons["menuButton"].tap()
    XCTAssertTrue(sideMenu.waitForExistence(timeout: 2))
    
    // 点击菜单外部区域关闭菜单
    app.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
    
    // 验证菜单已关闭
    let menuClosed = XCTNSPredicateExpectation(
        predicate: NSPredicate(format: "exists == false"),
        object: sideMenu
    )
    XCTWaiter().wait(for: [menuClosed], timeout: 2)
}
```

### 测试自定义过渡动画

```swift
func testCustomTransition() {
    // 触发自定义过渡
    app.buttons["showDetails"].tap()
    
    // 等待过渡完成并验证目标视图存在
    XCTAssertTrue(app.otherElements["detailView"].waitForExistence(timeout: 3))
    
    // 执行关闭操作
    app.buttons["closeDetails"].tap()
    
    // 验证视图已关闭
    let detailViewClosed = XCTNSPredicateExpectation(
        predicate: NSPredicate(format: "exists == false"),
        object: app.otherElements["detailView"]
    )
    XCTWaiter().wait(for: [detailViewClosed], timeout: 3)
}
```

### 测试深层导航

```swift
func testDeepNavigation() {
    // 导航到设置
    app.tabBars.buttons["设置"].tap()
    
    // 点击"账户"设置
    app.tables.cells["账户"].tap()
    
    // 点击"个人信息"设置
    app.tables.cells["个人信息"].tap()
    
    // 点击"编辑姓名"
    app.tables.cells["编辑姓名"].tap()
    
    // 验证导航到编辑姓名界面
    XCTAssertTrue(app.navigationBars["编辑姓名"].exists)
    
    // 返回到个人信息
    app.navigationBars["编辑姓名"].buttons.element(boundBy: 0).tap()
    
    // 返回到账户
    app.navigationBars["个人信息"].buttons.element(boundBy: 0).tap()
    
    // 返回到设置
    app.navigationBars["账户"].buttons.element(boundBy: 0).tap()
    
    // 验证已返回设置主界面
    XCTAssertTrue(app.navigationBars["设置"].exists)
}
```

### 测试 URL 方案导航

```swift
func testURLSchemeNavigation() {
    // 设置通过 URL 方案启动应用
    let app = XCUIApplication()
    app.launchArguments = ["-UITesting"]
    app.launchEnvironment = ["LAUNCH_URL": "myapp://profile/123"]
    app.launch()
    
    // 验证应用直接导航到了指定页面
    XCTAssertTrue(app.navigationBars["个人资料"].exists)
    XCTAssertTrue(app.staticTexts["用户ID: 123"].exists)
}
```

### 测试通用链接导航

```swift
func testUniversalLinkNavigation() {
    // 设置通过通用链接启动应用
    let app = XCUIApplication()
    app.launchArguments = ["-UITesting"]
    app.launchEnvironment = ["UNIVERSAL_LINK": "https://example.com/products/456"]
    app.launch()
    
    // 验证应用直接导航到了产品详情页
    XCTAssertTrue(app.navigationBars["产品详情"].exists)
    XCTAssertTrue(app.staticTexts["产品ID: 456"].exists)
}
```

## 模拟用户输入

准确模拟用户输入是 UI 测试的重要部分，本节将介绍如何测试各种输入控件。

### 测试文本输入

```swift
func testTextInput() {
    // 找到文本字段
    let usernameField = app.textFields["usernameField"]
    let passwordField = app.secureTextFields["passwordField"]
    
    // 输入用户名
    usernameField.tap()
    usernameField.typeText("测试用户")
    
    // 输入密码
    passwordField.tap()
    passwordField.typeText("Test@123")
    
    // 点击登录按钮
    app.buttons["loginButton"].tap()
    
    // 验证登录成功
    XCTAssertTrue(app.staticTexts["欢迎, 测试用户"].exists)
}
```

### 处理键盘操作

```swift
func testKeyboardOperations() {
    // 找到文本字段
    let messageField = app.textFields["messageField"]
    
    // 点击文本字段显示键盘
    messageField.tap()
    
    // 验证键盘显示
    XCTAssertTrue(app.keyboards.element.exists)
    
    // 输入文本
    messageField.typeText("Hello, World!")
    
    // 点击键盘上的返回键
    app.keyboards.buttons["return"].tap()
    
    // 验证键盘已消失
    XCTAssertFalse(app.keyboards.element.exists)
    
    // 点击文本字段再次显示键盘
    messageField.tap()
    
    // 点击工具栏上的"完成"按钮关闭键盘
    app.toolbars.buttons["完成"].tap()
    
    // 验证键盘已消失
    XCTAssertFalse(app.keyboards.element.exists)
}
```

### 处理自定义键盘输入视图

```swift
func testCustomInputView() {
    // 找到日期字段
    let dateField = app.textFields["dateField"]
    
    // 点击日期字段
    dateField.tap()
    
    // 验证自定义日期选择器显示而不是标准键盘
    XCTAssertTrue(app.datePickers.element.exists)
    XCTAssertFalse(app.keyboards.element.exists)
    
    // 使用日期选择器选择日期
    let datePicker = app.datePickers.element
    
    // 为轮盘式日期选择器
    if datePicker.pickerWheels.count > 0 {
        datePicker.pickerWheels.element(boundBy: 0).adjust(toPickerWheelValue: "5月")
        datePicker.pickerWheels.element(boundBy: 1).adjust(toPickerWheelValue: "15")
        datePicker.pickerWheels.element(boundBy: 2).adjust(toPickerWheelValue: "2023")
    }
    
    // 点击"完成"按钮
    app.toolbars.buttons["完成"].tap()
    
    // 验证日期已设置
    XCTAssertEqual(dateField.value as? String, "2023年5月15日")
}
```

### 测试多行文本输入

```swift
func testMultilineTextInput() {
    // 找到文本视图
    let commentTextView = app.textViews["commentTextView"]
    
    // 点击文本视图
    commentTextView.tap()
    
    // 输入多行文本
    commentTextView.typeText("这是第一行\n")
    commentTextView.typeText("这是第二行\n")
    commentTextView.typeText("这是第三行")
    
    // 点击"提交"按钮
    app.buttons["submitButton"].tap()
    
    // 验证评论已提交
    XCTAssertTrue(app.staticTexts["评论已提交"].exists)
    
    // 验证评论内容
    XCTAssertTrue(app.staticTexts.containing(NSPredicate(format: "label CONTAINS '这是第一行'")).element.exists)
}
```

### 测试自动完成和建议

```swift
func testAutocompleteSuggestions() {
    // 找到搜索字段
    let searchField = app.searchFields["citySearch"]
    
    // 点击搜索字段
    searchField.tap()
    
    // 输入部分文本触发自动完成
    searchField.typeText("北")
    
    // 等待自动完成建议出现
    let suggestion = app.tables["suggestionTable"].cells.staticTexts["北京"]
    XCTAssertTrue(suggestion.waitForExistence(timeout: 2))
    
    // 点击建议
    suggestion.tap()
    
    // 验证搜索字段已填充完整文本
    XCTAssertEqual(searchField.value as? String, "北京")
    
    // 验证键盘已收起
    XCTAssertFalse(app.keyboards.element.exists)
}
```

### 测试自定义输入验证

```swift
func testInputValidation() {
    // 找到电子邮件字段
    let emailField = app.textFields["emailField"]
    
    // 输入无效的电子邮件
    emailField.tap()
    emailField.typeText("invalid-email")
    
    // 点击提交按钮
    app.buttons["submitButton"].tap()
    
    // 验证错误消息显示
    XCTAssertTrue(app.staticTexts["请输入有效的电子邮件地址"].exists)
    
    // 清除字段并输入有效的电子邮件
    emailField.tap()
    emailField.clearAndEnterText("test@example.com")
    
    // 点击提交按钮
    app.buttons["submitButton"].tap()
    
    // 验证表单已提交（错误消息消失）
    XCTAssertFalse(app.staticTexts["请输入有效的电子邮件地址"].exists)
}

// 辅助方法，清除并输入文本
extension XCUIElement {
    func clearAndEnterText(_ text: String) {
        guard let currentValue = value as? String else {
            XCTFail("无法获取文本字段的值")
            return
        }
        
        tap()
        
        // 清除现有文本
        let deleteString = String(repeating: XCUIKeyboardKey.delete.rawValue, count: currentValue.count)
        typeText(deleteString)
        
        // 输入新文本
        typeText(text)
    }
}
```

### 测试富文本编辑

```swift
func testRichTextEditing() {
    // 找到富文本编辑器
    let richTextEditor = app.textViews["richTextEditor"]
    
    // 点击编辑器
    richTextEditor.tap()
    
    // 输入一些文本
    richTextEditor.typeText("这是一些普通文本")
    
    // 使用格式工具栏
    app.buttons["boldButton"].tap()
    richTextEditor.typeText("这是粗体文本")
    app.buttons["boldButton"].tap() // 关闭粗体
    
    app.buttons["italicButton"].tap()
    richTextEditor.typeText("这是斜体文本")
    app.buttons["italicButton"].tap() // 关闭斜体
    
    // 点击保存按钮
    app.buttons["saveButton"].tap()
    
    // 验证富文本已保存
    XCTAssertTrue(app.staticTexts["文档已保存"].exists)
}
```

### 测试数字键盘输入

```swift
func testNumericKeyboardInput() {
    // 找到价格输入字段（配置了数字键盘）
    let priceField = app.textFields["priceField"]
    
    // 点击价格字段
    priceField.tap()
    
    // 验证显示的是数字键盘
    let numberKeyboard = app.keyboards.element
    XCTAssertTrue(numberKeyboard.keys["1"].exists)
    XCTAssertTrue(numberKeyboard.keys["2"].exists)
    XCTAssertFalse(numberKeyboard.keys["q"].exists) // 数字键盘没有字母按键
    
    // 输入数字
    priceField.typeText("42.99")
    
    // 关闭键盘
    app.toolbars.buttons["完成"].tap()
    
    // 验证价格已设置
    XCTAssertEqual(priceField.value as? String, "¥42.99")
}
```

### 测试字符数限制

```swift
func testCharacterLimit() {
    // 找到有字符限制的文本字段（假设限制为 10 个字符）
    let limitedField = app.textFields["limitedField"]
    
    // 点击字段
    limitedField.tap()
    
    // 输入超过限制的文本
    limitedField.typeText("这个文本超过了十个字符的限制")
    
    // 关闭键盘
    app.toolbars.buttons["完成"].tap()
    
    // 验证文本被截断到限制长度
    let fieldValue = limitedField.value as? String
    XCTAssertEqual(fieldValue?.count, 10)
    XCTAssertEqual(fieldValue, "这个文本超过了")
    
    // 验证显示了字符计数指示器
    XCTAssertTrue(app.staticTexts["10/10"].exists)
}
```

### 测试输入焦点和键盘工具栏

```swift
func testInputFocusAndKeyboardToolbar() {
    // 找到多个文本字段
    let nameField = app.textFields["nameField"]
    let emailField = app.textFields["emailField"]
    let phoneField = app.textFields["phoneField"]
    
    // 点击第一个字段
    nameField.tap()
    
    // 确认字段有焦点
    XCTAssertTrue(app.keyboards.element.exists)
    
    // 使用键盘工具栏的"下一个"按钮
    app.toolbars.buttons["下一个"].tap()
    
    // 验证焦点移到了第二个字段
    XCTAssertEqual(app.textFields.element(boundBy: app.textFields.allElementsBoundByIndex.firstIndex(of: emailField)!).value as? String, "")
    
    // 输入电子邮件
    emailField.typeText("test@example.com")
    
    // 使用键盘工具栏的"下一个"按钮
    app.toolbars.buttons["下一个"].tap()
    
    // 验证焦点移到了第三个字段
    XCTAssertEqual(app.textFields.element(boundBy: app.textFields.allElementsBoundByIndex.firstIndex(of: phoneField)!).value as? String, "")
    
    // 输入电话号码
    phoneField.typeText("13800138000")
    
    // 使用键盘工具栏的"完成"按钮
    app.toolbars.buttons["完成"].tap()
    
    // 验证键盘已关闭
    XCTAssertFalse(app.keyboards.element.exists)
}
```

### 测试日期和时间选择

```swift
func testDateAndTimePicker() {
    // 找到日期时间字段
    let dateTimeField = app.textFields["dateTimeField"]
    
    // 点击字段打开日期时间选择器
    dateTimeField.tap()
    
    // 验证日期时间选择器显示
    let datePicker = app.datePickers.element
    XCTAssertTrue(datePicker.exists)
    
    // 切换到时间模式（如果有多个模式）
    app.buttons["时间"].tap()
    
    // 设置时间
    // 对于滚轮式选择器
    if datePicker.pickerWheels.count > 0 {
        datePicker.pickerWheels.element(boundBy: 0).adjust(toPickerWheelValue: "10")
        datePicker.pickerWheels.element(boundBy: 1).adjust(toPickerWheelValue: "30")
        if datePicker.pickerWheels.count > 2 {
            datePicker.pickerWheels.element(boundBy: 2).adjust(toPickerWheelValue: "PM")
        }
    }
    
    // 切换到日期模式
    app.buttons["日期"].tap()
    
    // 设置日期
    // 对于日历式选择器，点击特定日期
    let targetDate = app.datePickers.element.staticTexts["15"]
    if targetDate.exists {
        targetDate.tap()
    } else {
        // 对于滚轮式选择器
        if datePicker.pickerWheels.count > 0 {
            datePicker.pickerWheels.element(boundBy: 0).adjust(toPickerWheelValue: "6月")
            datePicker.pickerWheels.element(boundBy: 1).adjust(toPickerWheelValue: "15")
            datePicker.pickerWheels.element(boundBy: 2).adjust(toPickerWheelValue: "2023")
        }
    }
    
    // 点击"完成"按钮
    app.toolbars.buttons["完成"].tap()
    
    // 验证日期和时间已设置
    let dateTimeValue = dateTimeField.value as? String
    XCTAssertTrue(dateTimeValue?.contains("2023年6月15日") ?? false)
    XCTAssertTrue(dateTimeValue?.contains("10:30") ?? false)
}
```

### 测试单选和多选输入

```swift
func testSingleAndMultipleChoice() {
    // 测试单选按钮组
    let maleRadioButton = app.radioButtons["maleRadio"]
    let femaleRadioButton = app.radioButtons["femaleRadio"]
    
    // 选择"男性"选项
    maleRadioButton.tap()
    
    // 验证选择状态
    XCTAssertEqual(maleRadioButton.value as? String, "1")
    XCTAssertEqual(femaleRadioButton.value as? String, "0")
    
    // 选择"女性"选项
    femaleRadioButton.tap()
    
    // 验证选择状态更新
    XCTAssertEqual(maleRadioButton.value as? String, "0")
    XCTAssertEqual(femaleRadioButton.value as? String, "1")
    
    // 测试复选框
    let notificationsCheckbox = app.checkBoxes["notificationsCheckbox"]
    let newsletterCheckbox = app.checkBoxes["newsletterCheckbox"]
    
    // 初始状态都未选中
    XCTAssertEqual(notificationsCheckbox.value as? String, "0")
    XCTAssertEqual(newsletterCheckbox.value as? String, "0")
    
    // 选中"接收通知"
    notificationsCheckbox.tap()
    
    // 验证状态变化
    XCTAssertEqual(notificationsCheckbox.value as? String, "1")
    XCTAssertEqual(newsletterCheckbox.value as? String, "0")
    
    // 选中"订阅新闻"
    newsletterCheckbox.tap()
    
    // 验证两个都被选中
    XCTAssertEqual(notificationsCheckbox.value as? String, "1")
    XCTAssertEqual(newsletterCheckbox.value as? String, "1")
    
    // 取消选择"接收通知"
    notificationsCheckbox.tap()
    
    // 验证状态变化
    XCTAssertEqual(notificationsCheckbox.value as? String, "0")
    XCTAssertEqual(newsletterCheckbox.value as? String, "1")
}
```

## 测试手势和触摸事件

iOS 应用中的手势交互是用户体验的重要组成部分，本节将介绍如何测试各种手势和触摸事件。

### 测试基本点击和双击

```swift
func testTapAndDoubleTap() {
    // 基本点击
    let button = app.buttons["actionButton"]
    button.tap()
    
    // 验证点击效果
    XCTAssertTrue(app.staticTexts["操作已执行"].exists)
    
    // 测试双击
    let imageView = app.images["zoomableImage"]
    imageView.doubleTap()
    
    // 验证双击效果（例如图片放大）
    let zoomedStatus = app.staticTexts["zoomStatus"]
    XCTAssertEqual(zoomedStatus.label, "已放大")
}
```

### 测试长按手势

```swift
func testLongPress() {
    // 找到目标元素
    let listItem = app.tables.cells.element(boundBy: 1)
    
    // 执行长按
    listItem.press(forDuration: 2.0)
    
    // 验证长按菜单显示
    let contextMenu = app.menus.firstMatch
    XCTAssertTrue(contextMenu.exists)
    
    // 验证菜单项存在
    XCTAssertTrue(contextMenu.menuItems["编辑"].exists)
    XCTAssertTrue(contextMenu.menuItems["删除"].exists)
    XCTAssertTrue(contextMenu.menuItems["分享"].exists)
    
    // 选择菜单项
    contextMenu.menuItems["编辑"].tap()
    
    // 验证导航到编辑页面
    XCTAssertTrue(app.navigationBars["编辑项目"].exists)
}
```

### 测试滑动手势

```swift
func testSwipeGestures() {
    // 基本滑动
    app.swipeUp()
    app.swipeDown()
    app.swipeLeft()
    app.swipeRight()
    
    // 带速度的滑动
    app.swipeUp(velocity: .fast)
    app.swipeDown(velocity: .slow)
    
    // 在特定元素上滑动
    let scrollView = app.scrollViews.element
    scrollView.swipeUp()
    
    // 验证滑动效果（例如内容变化）
    let bottomContent = app.staticTexts["底部内容"]
    XCTAssertTrue(bottomContent.isHittable)
    
    // 测试卡片滑动
    let card = app.otherElements["cardView"]
    card.swipeLeft()
    
    // 验证卡片被移除
    let cardDisappeared = XCTNSPredicateExpectation(
        predicate: NSPredicate(format: "exists == false"),
        object: card
    )
    XCTWaiter().wait(for: [cardDisappeared], timeout: 2)
}
```

### 测试拖拽手势

```swift
func testDragAndDrop() {
    // 拖拽项目改变顺序
    let sourceItem = app.collectionViews["arrangeableItems"].cells.element(boundBy: 0)
    let destinationItem = app.collectionViews["arrangeableItems"].cells.element(boundBy: 3)
    
    // 执行拖拽
    sourceItem.press(forDuration: 0.5, thenDragTo: destinationItem)
    
    // 验证顺序已改变
    // 这里需要根据应用的实现方式来验证顺序变化
    
    // 测试拖拽到其他容器
    let draggableItem = app.collectionViews["sourceCollection"].cells.element(boundBy: 0)
    let targetContainer = app.collectionViews["targetCollection"]
    
    draggableItem.press(forDuration: 0.5, thenDragTo: targetContainer)
    
    // 验证项目已移动到目标容器
    XCTAssertEqual(app.collectionViews["sourceCollection"].cells.count, 3) // 原来有4个
    XCTAssertEqual(app.collectionViews["targetCollection"].cells.count, 1) // 原来有0个
}
```

### 测试捏合手势

```swift
func testPinchGestures() {
    // 找到支持缩放的视图
    let zoomableView = app.images["zoomableImage"]
    
    // 执行捏合放大（两指分开）
    zoomableView.pinch(withScale: 2.0, velocity: 1.0)
    
    // 验证放大效果
    let zoomStatus = app.staticTexts["zoomStatus"]
    XCTAssertEqual(zoomStatus.label, "已放大")
    
    // 执行捏合缩小（两指靠拢）
    zoomableView.pinch(withScale: 0.5, velocity: -1.0)
    
    // 验证缩小效果
    XCTAssertEqual(zoomStatus.label, "已缩小")
}
```

### 测试旋转手势

```swift
func testRotationGestures() {
    // 找到支持旋转的视图
    let rotatableView = app.otherElements["rotatableView"]
    
    // 执行旋转手势
    rotatableView.rotate(CGFloat.pi / 2, withVelocity: 1.0)
    
    // 验证旋转效果
    let rotationStatus = app.staticTexts["rotationStatus"]
    XCTAssertEqual(rotationStatus.label, "已旋转")
}
```

### 测试边缘滑动手势

```swift
func testEdgeSwipes() {
    // 从屏幕左边缘向右滑动（通常用于返回）
    let leftEdge = app.coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0.5))
    let centerPoint = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
    leftEdge.press(forDuration: 0.1, thenDragTo: centerPoint)
    
    // 验证返回效果
    XCTAssertTrue(app.navigationBars["上一页"].exists)
    
    // 从屏幕顶部边缘向下滑动（通知中心）
    // 注意：这通常会离开应用，所以在 UI 测试中很少使用
    
    // 从屏幕底部边缘向上滑动（控制中心）
    // 注意：这通常会离开应用，所以在 UI 测试中很少使用
}
```

### 测试自定义手势识别器

```swift
func testCustomGestureRecognizer() {
    // 找到支持自定义手势的视图
    let customGestureView = app.otherElements["customGestureView"]
    
    // 执行特定的触摸序列
    let startPoint = customGestureView.coordinate(withNormalizedOffset: CGVector(dx: 0.2, dy: 0.2))
    let midPoint1 = customGestureView.coordinate(withNormalizedOffset: CGVector(dx: 0.4, dy: 0.4))
    let midPoint2 = customGestureView.coordinate(withNormalizedOffset: CGVector(dx: 0.6, dy: 0.2))
    let endPoint = customGestureView.coordinate(withNormalizedOffset: CGVector(dx: 0.8, dy: 0.4))
    
    // 执行连续拖动以形成"Z"形手势
    startPoint.press(forDuration: 0.1, thenDragTo: midPoint1)
    midPoint1.press(forDuration: 0.1, thenDragTo: midPoint2)
    midPoint2.press(forDuration: 0.1, thenDragTo: endPoint)
    
    // 验证手势被识别
    XCTAssertTrue(app.staticTexts["已识别Z手势"].waitForExistence(timeout: 2))
}
```

### 测试手势交互冲突

```swift
func testGestureConflicts() {
    // 测试具有多个手势识别器的视图
    let complexView = app.otherElements["complexGestureView"]
    
    // 测试单击（可能会触发单击手势识别器）
    complexView.tap()
    XCTAssertTrue(app.staticTexts["单击已识别"].exists)
    
    // 测试双击（可能会触发双击手势识别器，并可能与单击冲突）
    complexView.doubleTap()
    XCTAssertTrue(app.staticTexts["双击已识别"].exists)
    XCTAssertFalse(app.staticTexts["单击已识别"].exists) // 确认单击事件被取消
    
    // 测试长按（与单击和双击并存）
    complexView.press(forDuration: 2.0)
    XCTAssertTrue(app.staticTexts["长按已识别"].exists)
}
```

### 测试触摸序列

```swift
func testTouchSequence() {
    // 测试需要特定触摸序列的功能（如绘图应用）
    let canvas = app.otherElements["drawingCanvas"]
    
    // 定义触摸点
    let startPoint = canvas.coordinate(withNormalizedOffset: CGVector(dx: 0.3, dy: 0.3))
    let midPoint = canvas.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5))
    let endPoint = canvas.coordinate(withNormalizedOffset: CGVector(dx: 0.7, dy: 0.3))
    
    // 执行触摸序列模拟绘制
    startPoint.press(forDuration: 0.01, thenDragTo: midPoint)
    midPoint.press(forDuration: 0.01, thenDragTo: endPoint)
    
    // 验证绘制效果
    XCTAssertTrue(app.staticTexts["已绘制图形"].exists)
    
    // 截图并添加到测试报告
    let screenshot = canvas.screenshot()
    let attachment = XCTAttachment(screenshot: screenshot)
    attachment.name = "绘制结果"
    attachment.lifetime = .keepAlways
    add(attachment)
}
```

### 测试加速度计和陀螺仪交互

```swift
func testMotionBasedInteractions() {
    // 注意：XCUITest 不直接支持模拟设备运动
    // 需要在应用中添加测试钩子来模拟这些事件
    
    // 示例：通过 UI 触发模拟的运动事件
    app.buttons["模拟摇动"].tap()
    
    // 验证摇动效果
    XCTAssertTrue(app.alerts["摇动检测到"].exists)
    app.alerts["摇动检测到"].buttons["确定"].tap()
    
    // 示例：通过 UI 触发模拟的倾斜事件
    app.buttons["模拟向左倾斜"].tap()
    
    // 验证倾斜效果
    XCTAssertTrue(app.staticTexts["向左倾斜已检测"].exists)
}
```

### 测试 3D Touch / 触感触控

```swift
func testForceTouchInteractions() {
    // 注意：XCUITest 不直接支持模拟力度触摸
    // 需要在应用中添加测试钩子来模拟这些事件
    
    // 示例：通过 UI 触发模拟的力度触摸
    app.buttons["模拟力度触摸"].tap()
    
    // 验证力度触摸效果
    XCTAssertTrue(app.popovers.element.exists)
    
    // 与弹出内容交互
    app.popovers.element.buttons["预览操作"].tap()
    
    // 验证操作效果
    XCTAssertTrue(app.navigationBars["预览详情"].exists)
}
```

### 自定义手势测试辅助方法

```swift
extension XCTestCase {
    // 辅助方法：执行轻扫手势
    func performSwipe(on element: XCUIElement, from start: CGVector, to end: CGVector, duration: TimeInterval = 0.5) {
        let startCoordinate = element.coordinate(withNormalizedOffset: start)
        let endCoordinate = element.coordinate(withNormalizedOffset: end)
        startCoordinate.press(forDuration: duration, thenDragTo: endCoordinate)
    }
    
    // 辅助方法：执行画圆手势
    func drawCircle(on element: XCUIElement, center: CGVector, radius: CGFloat, duration: TimeInterval = 1.0) {
        let centerCoordinate = element.coordinate(withNormalizedOffset: center)
        let startPoint = element.coordinate(withNormalizedOffset: CGVector(dx: center.dx, dy: center.dy - radius))
        
        // 按下起点
        startPoint.press(forDuration: 0.01)
        
        // 画圆的步骤数
        let steps = 20
        let angleIncrement = 2.0 * Double.pi / Double(steps)
        
        // 当前坐标
        var currentCoordinate = startPoint
        
        // 画圆
        for i in 1...steps {
            let angle = Double(i) * angleIncrement
            let x = center.dx + CGFloat(sin(angle)) * radius
            let y = center.dy - CGFloat(cos(angle)) * radius
            
            let nextCoordinate = element.coordinate(withNormalizedOffset: CGVector(dx: x, dy: y))
            currentCoordinate.press(forDuration: duration / TimeInterval(steps), thenDragTo: nextCoordinate)
            currentCoordinate = nextCoordinate
        }
        
        // 松开
        currentCoordinate.press(forDuration: 0.01)
    }
}

// 使用自定义手势辅助方法
func testAdvancedGestures() {
    let gestureView = app.otherElements["gestureView"]
    
    // 执行从左到右的轻扫
    performSwipe(
        on: gestureView,
        from: CGVector(dx: 0.2, dy: 0.5),
        to: CGVector(dx: 0.8, dy: 0.5)
    )
    
    // 验证轻扫效果
    XCTAssertTrue(app.staticTexts["向右轻扫"].exists)
    
    // 执行画圆手势
    drawCircle(
        on: gestureView,
        center: CGVector(dx: 0.5, dy: 0.5),
        radius: 0.2
    )
    
    // 验证画圆效果
    XCTAssertTrue(app.staticTexts["检测到圆形手势"].waitForExistence(timeout: 2))
}
```

## 截图和视觉验证

截图和视觉验证可以帮助发现 UI 布局问题和视觉回归。本节将介绍如何在 UI 测试中使用截图和进行视觉比较。

### 基本截图捕获

```swift
func testScreenshotCapture() {
    // 导航到要截图的界面
    app.tabBars.buttons["设置"].tap()
    
    // 捕获整个屏幕的截图
    let fullScreenshot = XCUIScreen.main.screenshot()
    
    // 创建截图附件并添加到测试报告
    let attachment = XCTAttachment(screenshot: fullScreenshot)
    attachment.name = "设置界面截图"
    attachment.lifetime = .keepAlways
    add(attachment)
    
    // 捕获特定元素的截图
    let profileSection = app.tables.cells["个人资料"]
    let profileScreenshot = profileSection.screenshot()
    
    let profileAttachment = XCTAttachment(screenshot: profileScreenshot)
    profileAttachment.name = "个人资料部分截图"
    profileAttachment.lifetime = .keepAlways
    add(profileAttachment)
}
```

### 在失败时自动截图

```swift
// 在测试类中添加辅助方法
func verifyElementExists(_ element: XCUIElement, timeout: TimeInterval = 5.0, file: StaticString = #file, line: UInt = #line) {
    let exists = element.waitForExistence(timeout: timeout)
    
    if !exists {
        // 捕获失败时的截图
        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = "失败时的屏幕状态"
        attachment.lifetime = .keepAlways
        add(attachment)
        
        // 记录当前可见元素的层次结构，帮助调试
        let debugInfo = """
        未找到元素：\(element)
        当前可见元素：
        \(app.debugDescription)
        """
        let debugAttachment = XCTAttachment(string: debugInfo)
        debugAttachment.name = "元素层次结构"
        debugAttachment.lifetime = .keepAlways
        add(debugAttachment)
    }
    
    XCTAssertTrue(exists, "元素未在预期时间内出现", file: file, line: line)
}

// 使用辅助方法
func testWithAutomaticFailureScreenshots() {
    app.buttons["登录"].tap()
    
    // 验证欢迎消息出现
    let welcomeMessage = app.staticTexts["欢迎回来"]
    verifyElementExists(welcomeMessage)
    
    // 如果元素不存在，会自动截图并附加到测试报告
}
```

### 截图比较

```swift
func testVisualComparison() {
    // 注意：XCTest 没有内置的截图比较功能
    // 这里展示一个基本方法，实际项目中可能需要使用第三方库
    
    // 导航到要测试的界面
    app.tabBars.buttons["个人资料"].tap()
    
    // 捕获当前状态的截图
    let currentScreenshot = app.screenshot()
    
    // 保存截图到文件系统（仅用于示例）
    let fileManager = FileManager.default
    let documentDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!
    let screenshotURL = documentDirectory.appendingPathComponent("profileScreenshot.png")
    
    // 判断是否已有基准截图
    if fileManager.fileExists(atPath: screenshotURL.path) {
        // 在实际应用中，这里需要使用图像处理库比较两个截图
        // 由于 XCTest 没有内置比较功能，此处仅为示例
        
        let referenceImageData = try! Data(contentsOf: screenshotURL)
        let referenceAttachment = XCTAttachment(data: referenceImageData, uniformTypeIdentifier: "public.png")
        referenceAttachment.name = "参考截图"
        add(referenceAttachment)
        
        let currentAttachment = XCTAttachment(screenshot: currentScreenshot)
        currentAttachment.name = "当前截图"
        add(currentAttachment)
        
        // 注意：实际的比较逻辑需要使用第三方库实现
        // XCTAssertTrue(compareImages(referenceImageData, currentScreenshot), "截图不匹配")
    } else {
        // 首次运行，保存基准截图
        if let imageData = currentScreenshot.pngRepresentation {
            try? imageData.write(to: screenshotURL)
            
            let attachment = XCTAttachment(screenshot: currentScreenshot)
            attachment.name = "基准截图已保存"
            add(attachment)
        }
    }
}

// 使用第三方库进行截图比较的示例（需要添加实际的比较逻辑）
func compareImages(_ referenceData: Data, _ currentScreenshot: XCUIScreenshot) -> Bool {
    // 这里需要实现图像比较逻辑
    // 可以比较像素、计算差异百分比等
    // 返回是否匹配
    return true // 示例返回值
}
```

### 容忍部分差异的截图比较

```swift
// 在实际应用中，可能需要容忍一定程度的差异
// 以下是一个概念性的比较函数
func compareImagesWithTolerance(_ referenceData: Data, _ currentScreenshot: XCUIScreenshot, tolerance: Double = 0.05) -> Bool {
    // 1. 将两个图像转换为相同大小的位图
    // 2. 比较每个像素的 RGB 值
    // 3. 计算差异像素的百分比
    // 4. 如果差异百分比小于容忍度，则认为匹配
    
    // 这里仅为示例，实际实现需要使用图像处理库
    let differencePercentage = 0.03 // 示例值，表示 3% 的像素不同
    
    return differencePercentage <= tolerance
}

// 使用容忍度比较的测试
func testVisualComparisonWithTolerance() {
    // 导航到测试界面
    app.tabBars.buttons["首页"].tap()
    
    // 捕获截图
    let currentScreenshot = app.screenshot()
    
    // 基准图像数据（在实际应用中从文件加载）
    let referenceData = Data() // 示例空数据
    
    // 使用容忍度比较
    let matches = compareImagesWithTolerance(referenceData, currentScreenshot, tolerance: 0.1)
    XCTAssertTrue(matches, "截图差异超过允许的 10% 容忍度")
}
```

### 忽略动态内容的视觉比较

```swift
// 在截图比较中忽略特定区域
func testVisualComparisonIgnoringDynamicContent() {
    // 导航到测试界面
    app.tabBars.buttons["动态内容"].tap()
    
    // 捕获完整界面截图
    let fullScreenshot = app.screenshot()
    
    // 确定动态内容的区域
    let dynamicContentArea = app.otherElements["timeDisplay"].frame
    
    // 在实际应用中，这里需要使用图像处理库来比较除动态区域外的部分
    // 或者使用 Mask 技术在比较前遮盖动态区域
    
    // 将动态内容信息添加到测试报告
    let attachment = XCTAttachment(screenshot: fullScreenshot)
    attachment.name = "带有动态内容的截图"
    add(attachment)
    
    // 记录忽略的区域信息
    let ignoredAreaInfo = "忽略区域：\(dynamicContentArea)"
    let infoAttachment = XCTAttachment(string: ignoredAreaInfo)
    infoAttachment.name = "忽略的动态区域"
    add(infoAttachment)
}
```

### 跨设备的截图比较

```swift
// 针对不同设备的截图比较策略
func testCrossDeviceVisualComparison() {
    // 获取当前设备信息
    let deviceName = UIDevice.current.name
    let screenSize = XCUIScreen.main.bounds.size
    
    // 导航到测试界面
    app.tabBars.buttons["设置"].tap()
    
    // 捕获截图
    let screenshot = app.screenshot()
    
    // 创建设备特定的文件名
    let deviceSpecificName = "settings_\(Int(screenSize.width))x\(Int(screenSize.height))"
    
    // 记录设备信息
    let deviceInfo = """
    设备名称：\(deviceName)
    屏幕尺寸：\(screenSize.width) x \(screenSize.height)
    截图标识：\(deviceSpecificName)
    """
    
    let infoAttachment = XCTAttachment(string: deviceInfo)
    infoAttachment.name = "设备信息"
    add(infoAttachment)
    
    // 将截图添加到报告
    let attachment = XCTAttachment(screenshot: screenshot)
    attachment.name = deviceSpecificName
    add(attachment)
    
    // 在实际应用中，可以根据设备标识加载相应的基准图像进行比较
}
```

### 截图验证布局约束

```swift
func testLayoutConstraints() {
    // 导航到测试界面
    app.tabBars.buttons["布局测试"].tap()
    
    // 捕获整个界面截图
    let screenshot = app.screenshot()
    add(XCTAttachment(screenshot: screenshot))
    
    // 验证关键元素的位置和尺寸
    let headerView = app.otherElements["headerView"]
    let contentView = app.scrollViews["contentView"]
    let footerView = app.otherElements["footerView"]
    
    // 验证垂直排列
    XCTAssertLessThan(headerView.frame.maxY, contentView.frame.minY, "头部应该在内容区域上方")
    XCTAssertLessThan(contentView.frame.maxY, footerView.frame.minY, "内容区域应该在底部上方")
    
    // 验证水平对齐
    XCTAssertEqual(headerView.frame.minX, contentView.frame.minX, "头部和内容左边缘应对齐")
    XCTAssertEqual(contentView.frame.minX, footerView.frame.minX, "内容和底部左边缘应对齐")
    
    // 验证宽度约束
    XCTAssertEqual(headerView.frame.width, app.frame.width, "头部应该占满屏幕宽度")
    XCTAssertEqual(footerView.frame.width, app.frame.width, "底部应该占满屏幕宽度")
    
    // 验证高度约束
    XCTAssertEqual(headerView.frame.height, 100, "头部高度应为 100 点")
    XCTAssertEqual(footerView.frame.height, 50, "底部高度应为 50 点")
}
```

### 跨版本 UI 对比

```swift
func testUIComparisonAcrossVersions() {
    // 在开发新版本时，可以对比新旧版本的 UI 差异
    
    // 记录当前应用版本
    let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "未知版本"
    
    // 导航到测试界面
    app.tabBars.buttons["个人资料"].tap()
    
    // 捕获当前版本的截图
    let currentVersionScreenshot = app.screenshot()
    
    // 添加版本信息到测试报告
    let versionInfo = "应用版本：\(appVersion)"
    let infoAttachment = XCTAttachment(string: versionInfo)
    infoAttachment.name = "版本信息"
    add(infoAttachment)
    
    // 添加当前版本截图到测试报告
    let screenshotAttachment = XCTAttachment(screenshot: currentVersionScreenshot)
    screenshotAttachment.name = "个人资料界面 - 版本 \(appVersion)"
    add(screenshotAttachment)
    
    // 在实际项目中，可以将截图保存到共享位置，或使用专用工具比较不同版本的 UI
}
```

### 使用 Snapshot 测试框架

```swift
// 注意：这需要集成第三方框架，如 iOSSnapshotTestCase (FBSnapshotTestCase)
// 以下代码展示概念，需要适当修改以配合实际使用的框架

// 在实际项目中，可能需要在 Podfile 中添加：
// pod 'iOSSnapshotTestCase'

/*
import FBSnapshotTestCase

class VisualRegressionTests: FBSnapshotTestCase {
    
    override func setUp() {
        super.setUp()
        // 开启记录模式以创建基准图像（首次运行）
        // self.recordMode = true
    }
    
    func testProfileScreen() {
        // 导航到个人资料界面
        let app = XCUIApplication()
        app.launch()
        app.tabBars.buttons["个人资料"].tap()
        
        // 捕获界面截图
        let screenshot = app.screenshot()
        
        // 使用 FBSnapshotVerifyView 比较截图
        // 注意：实际使用时需要调整 API 调用
        FBSnapshotVerifyView(screenshot, identifier: "ProfileScreen")
    }
}
*/
```

### 自定义视觉验证工作流

```swift
// 创建自定义视觉测试工作流
class VisualTestingWorkflow {
    
    enum ComparisonResult {
        case match
        case mismatch(diffPercentage: Double)
        case referenceNotFound
        case error(message: String)
    }
    
    static func captureAndCompare(app: XCUIApplication, identifier: String, tolerance: Double = 0.05) -> ComparisonResult {
        // 捕获当前屏幕截图
        let screenshot = app.screenshot()
        
        // 构建基准图像路径
        let fileManager = FileManager.default
        let documentDirectory = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first!
        let referenceImageURL = documentDirectory.appendingPathComponent("\(identifier).png")
        
        // 检查是否存在基准图像
        if fileManager.fileExists(atPath: referenceImageURL.path) {
            // 加载基准图像
            guard let referenceData = try? Data(contentsOf: referenceImageURL) else {
                return .error(message: "无法加载基准图像")
            }
            
            // 在实际应用中，这里需要实现图像比较逻辑
            // 此处仅为示例
            let diffPercentage = 0.03 // 示例值，表示 3% 的差异
            
            if diffPercentage <= tolerance {
                return .match
            } else {
                return .mismatch(diffPercentage: diffPercentage)
            }
        } else {
            // 保存当前截图作为基准
            if let imageData = screenshot.pngRepresentation {
                do {
                    try imageData.write(to: referenceImageURL)
                    return .referenceNotFound
                } catch {
                    return .error(message: "保存基准图像失败: \(error.localizedDescription)")
                }
            } else {
                return .error(message: "无法从截图创建 PNG 数据")
            }
        }
    }
}

// 使用自定义工作流
func testUsingCustomVisualWorkflow() {
    // 导航到测试界面
    app.tabBars.buttons["设置"].tap()
    
    // 执行视觉比较
    let result = VisualTestingWorkflow.captureAndCompare(app: app, identifier: "SettingsScreen")
    
    // 处理比较结果
    switch result {
    case .match:
        XCTAssertTrue(true, "视觉比较通过")
    case .mismatch(let diffPercentage):
        XCTFail("视觉比较失败，差异百分比: \(diffPercentage)")
    case .referenceNotFound:
        XCTAssertTrue(true, "基准图像不存在，已创建新基准")
    case .error(let message):
        XCTFail("视觉比较出错: \(message)")
    }
}
```

## 测试可访问性

可访问性测试对于确保应用能被所有用户使用至关重要，包括那些使用辅助技术的用户。本节将介绍如何测试 iOS 应用的可访问性。

### 基本可访问性测试

```swift
func testBasicAccessibility() {
    // 验证关键 UI 元素是否具有可访问性标识符
    XCTAssertNotNil(app.buttons["loginButton"].identifier)
    XCTAssertNotNil(app.textFields["usernameField"].identifier)
    XCTAssertNotNil(app.secureTextFields["passwordField"].identifier)
    
    // 验证可访问性标签是否存在且有意义
    let loginButton = app.buttons["loginButton"]
    XCTAssertFalse(loginButton.label.isEmpty, "登录按钮应有可访问性标签")
    
    // 验证元素是否可访问
    XCTAssertTrue(loginButton.isEnabled, "登录按钮应该启用")
    XCTAssertTrue(loginButton.isHittable, "登录按钮应该可点击")
}
```

### 测试可访问性标签和提示

```swift
func testAccessibilityLabelsAndHints() {
    // 验证图像按钮是否有描述性标签
    let addButton = app.buttons["add"]
    XCTAssertEqual(addButton.label, "添加新项目", "图像按钮应有描述性标签")
    
    // 验证文本字段是否有提示
    let usernameField = app.textFields["usernameField"]
    XCTAssertEqual(usernameField.value as? String, "用户名", "文本字段应有占位符")
    
    // 验证自定义控件是否有适当的标签
    let customControl = app.otherElements["customControl"]
    XCTAssertEqual(customControl.label, "自定义评分控件", "自定义控件应有描述性标签")
    
    // 验证可访问性提示是否存在
    // 注意：XCUITest 无法直接访问 accessibilityHint 属性
    // 在应用中可能需要暴露提示作为可测试的属性
}
```

### 测试动态类型适配

```swift
func testDynamicTypeAdaptation() {
    // 注意：XCUITest 不能直接更改系统设置
    // 可以在应用中添加测试钩子来模拟不同字体大小
    
    // 示例：通过 UI 切换字体大小
    app.buttons["增大字体"].tap()
    
    // 验证文本控件适应更大的字体
    let titleLabel = app.staticTexts["titleLabel"]
    let originalFrame = titleLabel.frame
    
    // 进一步增大字体
    app.buttons["进一步增大字体"].tap()
    
    // 验证标签框架扩大以适应更大的文本
    let newFrame = titleLabel.frame
    XCTAssertGreaterThan(newFrame.height, originalFrame.height, "文本标签应随字体大小增加而扩大")
    
    // 验证布局调整以适应更大的文本
    XCTAssertTrue(app.buttons["actionButton"].isHittable, "按钮在大字体下应仍然可交互")
}
```

### 测试VoiceOver兼容性

```swift
func testVoiceOverCompatibility() {
    // 注意：XCUITest 不能直接控制 VoiceOver
    // 可以在应用中添加测试钩子来模拟 VoiceOver 行为
    
    // 示例：通过 UI 启用模拟的 VoiceOver 模式
    app.switches["模拟 VoiceOver"].tap()
    
    // 验证元素可以按照逻辑顺序访问
    // 在模拟 VoiceOver 模式下，应用可能会显示当前焦点元素
    
    // 模拟向右轻扫以移动到下一个元素
    app.buttons["下一个元素"].tap()
    
    // 验证焦点移到了用户名字段
    XCTAssertEqual(app.staticTexts["当前VoiceOver焦点"].label, "用户名输入框")
    
    // 继续移动焦点
    app.buttons["下一个元素"].tap()
    
    // 验证焦点移到了密码字段
    XCTAssertEqual(app.staticTexts["当前VoiceOver焦点"].label, "密码输入框")
    
    // 验证自定义操作可通过 VoiceOver 访问
    app.buttons["执行VoiceOver操作"].tap()
    
    // 验证操作已执行
    XCTAssertTrue(app.alerts["操作已执行"].exists)
}
```

### 测试颜色对比度和无障碍主题

```swift
func testColorContrastAndThemes() {
    // 注意：XCUITest 不能直接测量颜色对比度
    // 可以切换到高对比度主题并验证可见性
    
    // 切换到高对比度主题
    app.buttons["高对比度主题"].tap()
    
    // 验证关键元素在高对比度模式下仍然可见
    let loginButton = app.buttons["loginButton"]
    XCTAssertTrue(loginButton.isHittable, "登录按钮在高对比度模式下应可点击")
    
    // 切换到深色模式
    app.buttons["深色模式"].tap()
    
    // 验证应用正确适应深色模式
    // 通过截图记录深色模式外观
    let darkModeScreenshot = app.screenshot()
    let attachment = XCTAttachment(screenshot: darkModeScreenshot)
    attachment.name = "深色模式界面"
    add(attachment)
}
```

### 测试旋转和布局适配

```swift
func testRotationAndLayoutAdaptation() {
    // 注意：XCUITest 不能直接控制设备旋转
    // 但可以在支持旋转的应用中观察布局变化
    
    // 记录竖屏布局
    let portraitScreenshot = app.screenshot()
    let portraitAttachment = XCTAttachment(screenshot: portraitScreenshot)
    portraitAttachment.name = "竖屏布局"
    add(portraitAttachment)
    
    // 模拟设备旋转
    XCUIDevice.shared.orientation = .landscapeLeft
    
    // 等待布局调整
    sleep(1)
    
    // 记录横屏布局
    let landscapeScreenshot = app.screenshot()
    let landscapeAttachment = XCTAttachment(screenshot: landscapeScreenshot)
    landscapeAttachment.name = "横屏布局"
    add(landscapeAttachment)
    
    // 验证关键元素在横屏模式下仍可访问
    XCTAssertTrue(app.buttons["actionButton"].isHittable, "操作按钮在横屏模式下应可点击")
    
    // 恢复竖屏方向
    XCUIDevice.shared.orientation = .portrait
}
```

### 测试减少动画设置

```swift
func testReducedMotion() {
    // 注意：XCUITest 不能直接更改系统设置
    // 可以在应用中添加测试钩子来模拟减少动画设置
    
    // 启用模拟的减少动画模式
    app.switches["减少动画"].tap()
    
    // 触发通常会有动画的操作
    app.buttons["展开详情"].tap()
    
    // 验证内容在没有动画的情况下显示
    XCTAssertTrue(app.staticTexts["详细内容"].waitForExistence(timeout: 1.0))
    
    // 验证没有进行动画
    // 在应用中，可能需要暴露一个标志来指示是否播放了动画
    XCTAssertEqual(app.staticTexts["动画状态"].label, "无动画")
}
```

### 自定义可访问性检查器

```swift
// 创建自定义的可访问性检查辅助方法
extension XCTestCase {
    func checkAccessibility(of element: XCUIElement, expectedLabel: String? = nil, shouldBeEnabled: Bool = true, shouldBeHittable: Bool = true, file: StaticString = #file, line: UInt = #line) {
        // 检查元素是否存在
        XCTAssertTrue(element.exists, "元素不存在", file: file, line: line)
        
        // 检查可访问性标签
        if let expectedLabel = expectedLabel {
            XCTAssertEqual(element.label, expectedLabel, "可访问性标签不匹配", file: file, line: line)
        } else {
            XCTAssertFalse(element.label.isEmpty, "可访问性标签不应为空", file: file, line: line)
        }
        
        // 检查是否启用
        if shouldBeEnabled {
            XCTAssertTrue(element.isEnabled, "元素应该被启用", file: file, line: line)
        } else {
            XCTAssertFalse(element.isEnabled, "元素应该被禁用", file: file, line: line)
        }
        
        // 检查是否可点击
        if shouldBeHittable {
            XCTAssertTrue(element.isHittable, "元素应该可点击", file: file, line: line)
        }
    }
    
    func checkAccessibilityOfScreen(app: XCUIApplication) {
        // 获取当前屏幕上的所有交互元素
        let buttons = app.buttons.allElementsBoundByIndex
        let textFields = app.textFields.allElementsBoundByIndex
        let staticTexts = app.staticTexts.allElementsBoundByIndex
        
        // 检查按钮
        for button in buttons {
            XCTAssertFalse(button.label.isEmpty, "按钮应有可访问性标签: \(button)")
            if button.isEnabled {
                XCTAssertTrue(button.isHittable || !button.exists, "启用的按钮应该可点击或不可见: \(button)")
            }
        }
        
        // 检查文本字段
        for textField in textFields {
            XCTAssertFalse(textField.identifier.isEmpty, "文本字段应有标识符: \(textField)")
        }
        
        // 添加其他需要的可访问性检查...
    }
}

// 使用自定义可访问性检查器
func testAccessibilityUsingCustomChecker() {
    // 导航到登录界面
    app.buttons["loginScreenButton"].tap()
    
    // 检查特定元素
    checkAccessibility(
        of: app.buttons["loginButton"],
        expectedLabel: "登录",
        shouldBeEnabled: true
    )
    
    // 检查整个屏幕的可访问性
    checkAccessibilityOfScreen(app: app)
}
```

### 测试辅助功能设置

```swift
func testAccessibilitySettings() {
    // 导航到应用的辅助功能设置页面
    app.tabBars.buttons["设置"].tap()
    app.tables.cells["辅助功能"].tap()
    
    // 验证辅助功能选项是否可用
    XCTAssertTrue(app.switches["大字体模式"].exists)
    XCTAssertTrue(app.switches["高对比度"].exists)
    XCTAssertTrue(app.switches["减少动画"].exists)
    
    // 启用大字体模式
    let largeFontSwitch = app.switches["大字体模式"]
    if largeFontSwitch.value as? String == "0" {
        largeFontSwitch.tap()
    }
    
    // 返回主界面
    app.navigationBars["辅助功能"].buttons.element(boundBy: 0).tap()
    app.tabBars.buttons["主页"].tap()
    
    // 验证大字体模式已应用
    // 这里可能需要检查特定标签的尺寸变化或截图比较
}
```

### 自动化可访问性审计

```swift
func testAutomatedAccessibilityAudit() {
    // 注意：这需要自定义实现或第三方库
    
    // 示例：遍历应用的主要屏幕并执行可访问性检查
    let mainScreens = ["主页", "搜索", "个人资料", "设置"]
    
    for screen in mainScreens {
        // 导航到屏幕
        app.tabBars.buttons[screen].tap()
        
        // 执行可访问性检查
        checkAccessibilityOfScreen(app: app)
        
        // 捕获截图作为记录
        let screenshot = app.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = "\(screen)界面可访问性审计"
        add(attachment)
    }
}
```

### 生成可访问性报告

```swift
func testGenerateAccessibilityReport() {
    // 创建一个包含可访问性问题的报告
    var accessibilityIssues: [String] = []
    
    // 检查主界面
    app.tabBars.buttons["主页"].tap()
    
    // 检查没有标签的按钮
    let unlabeledButtons = app.buttons.matching(NSPredicate(format: "label.length == 0"))
    if unlabeledButtons.count > 0 {
        accessibilityIssues.append("发现 \(unlabeledButtons.count) 个没有标签的按钮")
    }
    
    // 检查可能太小的点击目标
    let smallButtons = app.buttons.allElementsBoundByIndex.filter { button in
        let size = button.frame.size
        return size.width < 44 || size.height < 44 // Apple 推荐的最小尺寸
    }
    
    if smallButtons.count > 0 {
        accessibilityIssues.append("发现 \(smallButtons.count) 个尺寸过小的按钮")
    }
    
    // 生成报告
    let report = """
    可访问性测试报告
    -----------------------------
    测试设备: \(UIDevice.current.name)
    iOS 版本: \(UIDevice.current.systemVersion)
    测试日期: \(Date())
    
    发现的问题:
    \(accessibilityIssues.isEmpty ? "没有发现问题" : accessibilityIssues.joined(separator: "\n"))
    -----------------------------
    """
    
    // 将报告添加到测试结果
    let reportAttachment = XCTAttachment(string: report)
    reportAttachment.name = "可访问性测试报告"
    reportAttachment.lifetime = .keepAlways
    add(reportAttachment)
}
```

## 集成到 CI/CD 流程

将 UI 测试集成到持续集成和持续部署(CI/CD)流程中是自动化测试的重要一步。本节将介绍如何在 CI/CD 环境中设置和运行 UI 测试。

### 使用 Xcode 命令行工具

```bash
# 在 CI 环境中运行 UI 测试的基本命令
xcodebuild test \
  -project MyApp.xcodeproj \
  -scheme "MyAppUITests" \
  -destination "platform=iOS Simulator,name=iPhone 12,OS=latest" \
  -resultBundlePath TestResults
```

### 使用 fastlane 自动化测试

```ruby
# Fastfile 示例

# 定义用于 UI 测试的 lane
lane :ui_tests do
  # 确保使用最新的依赖项
  cocoapods if File.exists?("Podfile")
  
  # 构建和运行 UI 测试
  scan(
    scheme: "MyAppUITests",
    devices: ["iPhone 12"],
    clean: true,
    output_types: "html,junit",
    output_directory: "test_results"
  )
  
  # 可选：如果测试失败，发送通知
  if lane_context[SharedValues::SCAN_SUCCEEDED] == false
    slack(
      message: "UI 测试失败",
      success: false
    )
  end
end

# 完整的 CI 流水线示例
lane :ci_pipeline do
  # 运行单元测试
  unit_tests
  
  # 运行 UI 测试
  ui_tests
  
  # 构建应用程序
  build_app
  
  # 上传到测试平台
  upload_to_testflight
end
```

### 配置 GitHub Actions

```yaml
# .github/workflows/ui-tests.yml
name: UI Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: macos-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Ruby
      uses: ruby/setup-ruby@v1
      with:
        ruby-version: 3.0
        
    - name: Install dependencies
      run: |
        gem install bundler
        bundle install
        pod install
        
    - name: Run UI Tests
      run: |
        bundle exec fastlane ui_tests
        
    - name: Upload test results
      uses: actions/upload-artifact@v2
      if: always()
      with:
        name: test-results
        path: test_results/
```

### 设置 Jenkins 或 TeamCity

```groovy
// Jenkinsfile 示例
pipeline {
    agent { label 'macos' }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup') {
            steps {
                sh 'gem install bundler'
                sh 'bundle install'
                sh 'pod install'
            }
        }
        
        stage('UI Tests') {
            steps {
                sh 'bundle exec fastlane ui_tests'
            }
            post {
                always {
                    junit 'test_results/report.junit'
                    archiveArtifacts artifacts: 'test_results/**/*', allowEmptyArchive: true
                }
            }
        }
    }
    
    post {
        failure {
            mail to: 'team@example.com',
                 subject: "失败: ${env.JOB_NAME} [${env.BUILD_NUMBER}]",
                 body: "UI 测试失败，请检查 ${env.BUILD_URL}"
        }
    }
}
```

### 管理模拟器和设备

```bash
# 列出可用的模拟器
xcrun simctl list devices

# 创建新的模拟器
xcrun simctl create "Test iPhone" "iPhone 12" "iOS15.0"

# 启动模拟器
xcrun simctl boot "Test iPhone"

# 安装应用到模拟器
xcrun simctl install "Test iPhone" "/path/to/MyApp.app"

# 在 CI 脚本中使用特定模拟器
SIMULATOR_ID=$(xcrun simctl create "Test iPhone" "iPhone 12" "iOS15.0")
xcrun simctl boot $SIMULATOR_ID

xcodebuild test \
  -project MyApp.xcodeproj \
  -scheme "MyAppUITests" \
  -destination "id=$SIMULATOR_ID" \
  -resultBundlePath TestResults
  
# 测试完成后清理
xcrun simctl shutdown $SIMULATOR_ID
xcrun simctl delete $SIMULATOR_ID
```

### 配置多设备测试矩阵

```ruby
# fastlane 中的设备矩阵

lane :test_matrix do
  # 定义设备矩阵
  devices = [
    "iPhone 12,OS=15.0",
    "iPhone 12 Pro Max,OS=15.0",
    "iPhone SE (2nd generation),OS=14.5",
    "iPad Pro (12.9-inch) (5th generation),OS=15.0"
  ]
  
  # 在每个设备上运行测试
  devices.each do |device|
    scan(
      scheme: "MyAppUITests",
      device: device,
      output_types: "html,junit",
      output_directory: "test_results/#{device.gsub(/[,\s\(\)]/,'_')}"
    )
  end
  
  # 合并测试结果（需要自定义脚本）
  sh "./scripts/merge_test_results.sh"
end
```

### 监控测试耗时和性能

```ruby
# fastlane 中的测试性能监控

lane :monitor_test_performance do
  # 记录开始时间
  start_time = Time.now
  
  # 运行测试
  scan(
    scheme: "MyAppUITests",
    device: "iPhone 12",
    output_types: "html,junit",
    output_directory: "test_results"
  )
  
  # 计算总耗时
  duration = Time.now - start_time
  
  # 记录性能数据
  File.open("test_metrics.txt", "w") do |file|
    file.puts "UI 测试总耗时: #{duration} 秒"
  end
  
  # 分析慢测试（需要自定义脚本）
  sh "./scripts/analyze_slow_tests.rb test_results/report.junit"
  
  # 可选：发送性能报告
  slack(
    message: "UI 测试完成，总耗时: #{duration} 秒",
    success: true
  )
end
```

### 设置测试数据和环境

```bash
# 在 CI 环境中设置测试数据的脚本示例

# 创建测试配置文件
cat > UITestConfig.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>TestEnvironment</key>
    <string>CI</string>
    <key>TestServer</key>
    <string>https://test-api.example.com</string>
    <key>TestCredentials</key>
    <dict>
        <key>Username</key>
        <string>testuser</string>
        <key>Password</key>
        <string>testpass</string>
    </dict>
</dict>
</plist>
EOF

# 确保配置文件被复制到应用包中
# 在 Xcode 项目中添加运行脚本构建阶段，或在 CI 脚本中处理

# 在测试命令中传递环境变量
xcodebuild test \
  -project MyApp.xcodeproj \
  -scheme "MyAppUITests" \
  -destination "platform=iOS Simulator,name=iPhone 12,OS=latest" \
  -resultBundlePath TestResults \
  UITEST_CONFIG_PATH="${PWD}/UITestConfig.plist"
```

### 处理测试结果和报告

```ruby
# fastlane 中的测试报告处理

lane :process_test_reports do
  # 运行测试并生成结果
  scan(
    scheme: "MyAppUITests",
    device: "iPhone 12",
    output_types: "html,junit,json",
    output_directory: "test_results"
  )
  
  # 自定义 HTML 报告（使用 xcpretty）
  sh "cat test_results/report.junit | xcpretty --report html --output test_results/improved_report.html"
  
  # 计算测试覆盖率（如果已配置）
  sh "xcrun xccov view --report --json test_results/*.xcresult > test_results/coverage.json"
  
  # 发布测试结果到仪表板（示例使用自定义脚本）
  sh "./scripts/publish_to_dashboard.rb test_results/report.junit test_results/coverage.json"
  
  # 上传测试快照和视频
  sh "find test_results -name '*.png' -o -name '*.mp4' | zip -j test_results/artifacts.zip -@"
  sh "./scripts/upload_artifacts.rb test_results/artifacts.zip"
}
```

### 使用 Parallel Testing

```ruby
# fastlane 中的并行测试设置

lane :parallel_ui_tests do
  # 获取测试列表
  test_classes = sh("./scripts/list_test_classes.rb")
  test_classes = test_classes.split("\n")
  
  # 分组测试类，示例将测试分为3组
  test_groups = test_classes.each_slice((test_classes.size / 3.0).ceil).to_a
  
  # 并行运行测试组
  test_results = Parallel.map(test_groups, in_processes: 3) do |group|
    group_name = "group_#{test_groups.index(group)}"
    
    # 为每个组创建一个临时方案文件
    create_test_scheme(name: "UITests_#{group_name}", tests: group)
    
    # 运行此组的测试
    scan(
      scheme: "UITests_#{group_name}",
      device: "iPhone 12",
      output_types: "junit",
      output_directory: "test_results/#{group_name}",
      fail_build: false # 允许所有组完成再判断成功/失败
    )
    
    # 返回此组的成功/失败状态
    $?.success?
  end
  
  # 检查是否所有组都成功
  if test_results.all?
    UI.success("所有测试组都通过了")
  else
    UI.error("一个或多个测试组失败")
    exit 1
  end
  
  # 合并测试报告
  sh "./scripts/merge_junit_reports.rb test_results/*/report.junit > test_results/final_report.junit"
end

def create_test_scheme(name:, tests:)
  # 创建仅包含特定测试类的方案
  # 这需要自定义脚本或使用 xcodeproj gem 操作 Xcode 项目
  sh "./scripts/create_test_scheme.rb '#{name}' '#{tests.join(',')}'"
end
```

### 设置视觉回归测试

```ruby
# fastlane 中的视觉回归测试

lane :visual_regression_tests do
  # 运行 UI 测试，生成截图
  scan(
    scheme: "MyAppUITestsVisualValidation",
    device: "iPhone 12",
    output_directory: "test_results"
  )
  
  # 比较截图与基准图像
  # 使用自定义脚本或工具，如 iOSSnapshotTestCase
  sh "./scripts/compare_screenshots.rb reference_images/ test_results/screenshots/"
  
  # 生成视觉差异报告
  sh "./scripts/generate_visual_report.rb test_results/diffs/"
  
  # 上传视觉测试结果
  sh "./scripts/upload_visual_results.rb test_results/visual_report.html"
  
  # 可选：更新基准图像（如在主分支上）
  if git_branch == "main"
    sh "cp -R test_results/screenshots/ reference_images/"
    sh "git add reference_images/"
    sh "git commit -m 'Update visual test reference images [CI SKIP]'"
    sh "git push origin main"
  end
end
```

### 设置夜间测试

```yaml
# GitHub Actions 夜间测试配置
# .github/workflows/nightly-tests.yml
name: Nightly UI Tests

on:
  schedule:
    # 每天凌晨 2 点运行
    - cron: '0 2 * * *'

jobs:
  nightly_tests:
    runs-on: macos-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Ruby
      uses: ruby/setup-ruby@v1
      with:
        ruby-version: 3.0
        
    - name: Install dependencies
      run: |
        gem install bundler
        bundle install
        pod install
        
    - name: Run Comprehensive UI Tests
      run: |
        bundle exec fastlane nightly_tests
        
    - name: Upload test results
      uses: actions/upload-artifact@v2
      if: always()
      with:
        name: nightly-test-results
        path: test_results/
        
    - name: Notify team of results
      if: always()
      run: |
        if [ "${{ job.status }}" == "success" ]; then
          ./scripts/send_notification.sh "夜间测试成功"
        else
          ./scripts/send_notification.sh "夜间测试失败，请查看详细结果"
        fi
```

### 自动化测试报告分析

```python
# test_analyzer.py - 分析测试结果的 Python 脚本示例

import sys
import xml.etree.ElementTree as ET
import json
import matplotlib.pyplot as plt
from datetime import datetime

def analyze_junit_report(junit_file):
    tree = ET.parse(junit_file)
    root = tree.getroot()
    
    # 收集测试统计
    total_tests = int(root.attrib.get('tests', 0))
    failures = int(root.attrib.get('failures', 0))
    errors = int(root.attrib.get('errors', 0))
    skipped = int(root.attrib.get('skipped', 0))
    passed = total_tests - failures - errors - skipped
    
    # 分析失败的测试
    failed_tests = []
    for testcase in root.findall('.//testcase'):
        failure = testcase.find('failure')
        error = testcase.find('error')
        
        if failure is not None or error is not None:
            classname = testcase.attrib.get('classname')
            name = testcase.attrib.get('name')
            time = float(testcase.attrib.get('time', 0))
            
            failed_tests.append({
                'class': classname,
                'name': name,
                'time': time,
                'message': (failure.attrib.get('message') if failure is not None 
                            else error.attrib.get('message'))
            })
    
    # 计算测试时长统计
    test_times = []
    for testcase in root.findall('.//testcase'):
        time = float(testcase.attrib.get('time', 0))
        test_times.append({
            'class': testcase.attrib.get('classname'),
            'name': testcase.attrib.get('name'),
            'time': time
        })
    
    # 按时间排序
    test_times.sort(key=lambda x: x['time'], reverse=True)
    
    # 生成报告
    report = {
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'summary': {
            'total': total_tests,
            'passed': passed,
            'failed': failures + errors,
            'skipped': skipped,
            'success_rate': (passed / total_tests) * 100 if total_tests > 0 else 0
        },
        'failed_tests': failed_tests,
        'slowest_tests': test_times[:10]  # 前 10 个最慢的测试
    }
    
    return report

def generate_charts(report, output_dir):
    # 创建饼图：测试结果分布
    labels = ['通过', '失败', '跳过']
    sizes = [
        report['summary']['passed'],
        report['summary']['failed'],
        report['summary']['skipped']
    ]
    colors = ['#4CAF50', '#F44336', '#FFC107']
    
    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.axis('equal')
    plt.title('UI 测试结果分布')
    plt.savefig(f'{output_dir}/test_results_pie.png')
    plt.close()
    
    # 创建条形图：最慢的测试
    if report['slowest_tests']:
        test_names = [f"{t['name'][:20]}..." if len(t['name']) > 20 else t['name'] 
                      for t in report['slowest_tests'][:5]]
        test_times = [t['time'] for t in report['slowest_tests'][:5]]
        
        plt.figure(figsize=(10, 6))
        plt.barh(test_names, test_times, color='#2196F3')
        plt.xlabel('时间（秒）')
        plt.title('最慢的 5 个测试')
        plt.tight_layout()
        plt.savefig(f'{output_dir}/slowest_tests_bar.png')
        plt.close()

def generate_html_report(report, output_dir):
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>UI 测试报告</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .summary {{ display: flex; justify-content: space-around; margin-bottom: 20px; }}
            .summary-box {{ text-align: center; padding: 15px; border-radius: 5px; color: white; }}
            .total {{ background-color: #2196F3; }}
            .passed {{ background-color: #4CAF50; }}
            .failed {{ background-color: #F44336; }}
            .skipped {{ background-color: #FFC107; color: black; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .charts {{ display: flex; justify-content: space-around; margin: 20px 0; }}
            .chart {{ text-align: center; }}
        </style>
    </head>
    <body>
        <h1>UI 测试报告</h1>
        <p>生成日期：{report['date']}</p>
        
        <div class="summary">
            <div class="summary-box total">
                <h2>{report['summary']['total']}</h2>
                <p>总测试数</p>
            </div>
            <div class="summary-box passed">
                <h2>{report['summary']['passed']}</h2>
                <p>通过</p>
            </div>
            <div class="summary-box failed">
                <h2>{report['summary']['failed']}</h2>
                <p>失败</p>
            </div>
            <div class="summary-box skipped">
                <h2>{report['summary']['skipped']}</h2>
                <p>跳过</p>
            </div>
        </div>
        
        <div class="charts">
            <div class="chart">
                <h3>测试结果分布</h3>
                <img src="test_results_pie.png" alt="测试结果分布" width="400">
            </div>
            <div class="chart">
                <h3>最慢的测试</h3>
                <img src="slowest_tests_bar.png" alt="最慢的测试" width="500">
            </div>
        </div>
        
        <h2>失败的测试</h2>
    """
    
    if report['failed_tests']:
        html += """
        <table>
            <tr>
                <th>类名</th>
                <th>测试名</th>
                <th>耗时(秒)</th>
                <th>错误信息</th>
            </tr>
        """
        
        for test in report['failed_tests']:
            html += f"""
            <tr>
                <td>{test['class']}</td>
                <td>{test['name']}</td>
                <td>{test['time']:.2f}</td>
                <td>{test['message']}</td>
            </tr>
            """
        
        html += "</table>"
    else:
        html += "<p>没有失败的测试。</p>"
    
    html += """
    </body>
    </html>
    """
    
    with open(f'{output_dir}/report.html', 'w') as f:
        f.write(html)

def main():
    if len(sys.argv) < 3:
        print("用法: python test_analyzer.py <junit_report.xml> <output_directory>")
        sys.exit(1)
    
    junit_file = sys.argv[1]
    output_dir = sys.argv[2]
    
    report = analyze_junit_report(junit_file)
    generate_charts(report, output_dir)
    generate_html_report(report, output_dir)
    
    # 保存 JSON 报告
    with open(f'{output_dir}/report.json', 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"分析完成。报告已保存到 {output_dir}")

if __name__ == "__main__":
    main()