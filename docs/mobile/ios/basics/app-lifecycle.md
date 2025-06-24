# iOS 应用生命周期

iOS 应用生命周期是指应用从启动到终止的整个过程中经历的各种状态和转换。理解应用生命周期对于开发高质量的 iOS 应用至关重要，它能帮助开发者在恰当的时机执行相应的操作，管理系统资源，并提供良好的用户体验。

## 目录

- [应用程序状态](#应用程序状态)
- [应用启动过程](#应用启动过程)
- [AppDelegate 和 SceneDelegate](#appdelegate-和-scenedelegate)
- [应用前台与后台切换](#应用前台与后台切换)
- [应用终止](#应用终止)
- [后台任务与执行](#后台任务与执行)
- [状态保存和恢复](#状态保存和恢复)
- [实践建议](#实践建议)

## 应用程序状态

iOS 应用在其生命周期中可以处于以下几种状态：

### 未运行 (Not Running)

应用尚未启动，或已被系统完全终止。

### 前台活跃 (Active)

应用在前台运行，并接收用户事件。这是应用执行大部分工作的状态。

### 前台不活跃 (Inactive)

应用在前台但不接收事件。通常这是短暂的过渡状态，例如当系统弹出提醒或控制中心时。

### 后台 (Background)

应用在后台运行，执行代码。应用可以在一段有限的时间内执行任务，或在特定情况下（如音频播放、位置更新）无限期执行。

### 挂起 (Suspended)

应用在后台但不执行代码。系统可能随时终止挂起的应用，以释放内存资源。

### 状态转换图

```
  +----------------+    +-------------------+    +----------------+
  |                |    |                   |    |                |
  |  Not Running   |--->|      Active       |--->|   Suspended    |
  |                |    |                   |    |                |
  +----------------+    +-------------------+    +----------------+
                         |               ^
                         v               |
                        +----------------+
                        |                |
                        |    Inactive    |
                        |                |
                        +----------------+
                         |               ^
                         v               |
                        +----------------+
                        |                |
                        |   Background   |
                        |                |
                        +----------------+
                                |
                                v
                        +----------------+
                        |                |
                        |  Not Running   |
                        |                |
                        +----------------+
```

## 应用启动过程

iOS 应用的启动过程包含以下关键步骤：

### 1. 系统准备

系统加载应用的二进制文件、所需的框架和资源。

### 2. 执行 main 函数

系统调用应用的 `main` 函数，通常在 `main.swift` 或 `main.m` 中。

```swift
// main.swift (通常由系统自动生成)
import UIKit
UIApplicationMain(
    CommandLine.argc,
    CommandLine.unsafeArgv,
    nil,
    NSStringFromClass(AppDelegate.self)
)
```

### 3. 创建 UIApplication 实例

`UIApplicationMain` 函数创建 `UIApplication` 单例，用于管理应用的事件循环。

### 4. 创建 AppDelegate 实例

系统创建 `AppDelegate` 类的实例，作为应用的委托对象。

### 5. 加载主用户界面

系统从应用的 Info.plist 文件中确定主界面文件（Storyboard 或 XIB），并加载它。

### 6. 调用 AppDelegate 方法

系统调用适当的 AppDelegate 方法，通知应用已启动。

### 启动类型

iOS 应用可能经历几种不同类型的启动：

- **冷启动**：应用从未运行状态启动，完全加载所有资源
- **热启动**：用户重新打开最近运行过的应用
- **恢复启动**：应用从后台或挂起状态恢复到前台

## AppDelegate 和 SceneDelegate

### AppDelegate

`AppDelegate` 类负责响应应用级事件，如启动、终止和后台处理。

```swift
import UIKit

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?  // iOS 12及以下使用
    
    // 应用启动完成
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        // 在这里执行初始化代码
        print("应用已启动")
        return true
    }
    
    // iOS 13+ 下的场景配置
    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }
    
    // 应用将进入前台
    func applicationWillEnterForeground(_ application: UIApplication) {
        print("应用将进入前台")
    }
    
    // 应用已进入活跃状态
    func applicationDidBecomeActive(_ application: UIApplication) {
        print("应用已变为活跃状态")
    }
    
    // 应用将进入非活跃状态
    func applicationWillResignActive(_ application: UIApplication) {
        print("应用将变为非活跃状态")
    }
    
    // 应用已进入后台
    func applicationDidEnterBackground(_ application: UIApplication) {
        print("应用已进入后台")
    }
    
    // 应用将终止
    func applicationWillTerminate(_ application: UIApplication) {
        print("应用将终止")
    }
}
```

### SceneDelegate

iOS 13 引入了多场景支持，将窗口管理职责转移到了 `SceneDelegate` 中。

```swift
import UIKit

class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    
    // 场景已连接
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
        guard let windowScene = (scene as? UIWindowScene) else { return }
        window = UIWindow(windowScene: windowScene)
        // 设置根视图控制器
        window?.rootViewController = ViewController()
        window?.makeKeyAndVisible()
    }
    
    // 场景已进入前台
    func sceneWillEnterForeground(_ scene: UIScene) {
        print("场景将进入前台")
    }
    
    // 场景已变为活跃
    func sceneDidBecomeActive(_ scene: UIScene) {
        print("场景已变为活跃")
    }
    
    // 场景将变为非活跃
    func sceneWillResignActive(_ scene: UIScene) {
        print("场景将变为非活跃")
    }
    
    // 场景已进入后台
    func sceneDidEnterBackground(_ scene: UIScene) {
        print("场景已进入后台")
    }
    
    // 场景将被释放
    func sceneDidDisconnect(_ scene: UIScene) {
        print("场景将被释放")
    }
}
```

### AppDelegate 与 SceneDelegate 的区别

- **iOS 12 及以下**：`AppDelegate` 同时处理应用生命周期和UI生命周期
- **iOS 13 及以上**：
  - `AppDelegate` 主要处理应用级事件
  - `SceneDelegate` 处理UI和场景级事件

## 应用前台与后台切换

### 前台到后台的转换

当用户按下 Home 键、切换到另一个应用或接听电话时，应用会经历以下转换：

1. `sceneWillResignActive(_:)` / `applicationWillResignActive(_:)`
2. `sceneDidEnterBackground(_:)` / `applicationDidEnterBackground(_:)`

此时应用应该：
- 保存用户数据
- 释放共享资源
- 停止敏感操作（如视频捕获）
- 隐藏敏感信息
- 暂停计时器和网络连接

```swift
func sceneDidEnterBackground(_ scene: UIScene) {
    // 保存用户数据
    UserDefaults.standard.synchronize()
    
    // 停止计时器
    myTimer?.invalidate()
    
    // 如果有敏感数据，应该隐藏或模糊处理
    sensitiveDataView.isHidden = true
}
```

### 后台到前台的转换

当用户重新打开应用时，会经历以下转换：

1. `sceneWillEnterForeground(_:)` / `applicationWillEnterForeground(_:)`
2. `sceneDidBecomeActive(_:)` / `applicationDidBecomeActive(_:)`

此时应用应该：
- 刷新界面数据
- 重新启动暂停的任务和计时器
- 重新连接服务
- 重新显示敏感信息

```swift
func sceneDidBecomeActive(_ scene: UIScene) {
    // 刷新数据
    refreshData()
    
    // 重启计时器
    startTimer()
    
    // 重新显示敏感信息
    sensitiveDataView.isHidden = false
}
```

## 应用终止

应用可能因以下原因终止：

1. **用户主动终止**：用户通过应用切换器上滑关闭应用
2. **系统终止**：系统需要释放内存时终止后台应用
3. **异常终止**：应用崩溃或响应超时

### 终止时的回调

当应用正常终止时，系统会调用：
- `applicationWillTerminate(_:)` (仅在前台终止时可靠)

```swift
func applicationWillTerminate(_ application: UIApplication) {
    // 执行最终清理
    saveUserData()
    cleanupResources()
    
    // 通知服务器用户已离开
    logoutFromServer()
}
```

**注意**：不要依赖此方法，因为它在系统终止应用时可能不会被调用。应该在进入后台时执行必要的清理工作。

## 后台任务与执行

iOS 提供多种方式允许应用在后台执行有限的任务：

### 1. 后台执行时间

当应用进入后台时，系统会提供约 30 秒的时间来完成任务。可以请求更多时间：

```swift
func applicationDidEnterBackground(_ application: UIApplication) {
    // 请求额外的后台执行时间
    var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    
    backgroundTask = application.beginBackgroundTask {
        // 如果时间耗尽，在这里执行清理
        application.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }
    
    // 执行后台任务
    performLongRunningTask {
        // 任务完成，结束后台任务
        application.endBackgroundTask(backgroundTask)
        backgroundTask = .invalid
    }
}
```

### 2. 后台模式

应用可以声明特定的后台模式，以在后台无限期执行某些类型的任务：

- **音频**：播放音频内容
- **位置**：跟踪位置变化
- **VOIP**：提供网络语音服务
- **新闻内容下载**：定期下载内容更新
- **外部配件通信**：与蓝牙设备通信
- **后台处理**：执行定期数据更新

在 Info.plist 中配置后台模式：

```xml
<key>UIBackgroundModes</key>
<array>
    <string>audio</string>
    <string>location</string>
</array>
```

### 3. 后台获取

允许应用在后台定期唤醒以更新内容：

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    // 配置后台获取
    UIApplication.shared.setMinimumBackgroundFetchInterval(UIApplication.backgroundFetchIntervalMinimum)
    return true
}

func application(_ application: UIApplication, performFetchWithCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
    // 执行数据更新
    updateData { success, newData in
        if success && newData {
            completionHandler(.newData)
        } else if success {
            completionHandler(.noData)
        } else {
            completionHandler(.failed)
        }
    }
}
```

### 4. 后台处理任务

iOS 13 引入了 `BackgroundTasks` 框架，提供更强大的后台任务管理：

```swift
import BackgroundTasks

func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    // 注册后台任务
    BGTaskScheduler.shared.register(forTaskWithIdentifier: "com.example.app.refresh", using: nil) { task in
        self.handleAppRefresh(task: task as! BGAppRefreshTask)
    }
    return true
}

func scheduleAppRefresh() {
    let request = BGAppRefreshTaskRequest(identifier: "com.example.app.refresh")
    request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60) // 15分钟后
    
    do {
        try BGTaskScheduler.shared.submit(request)
    } catch {
        print("无法安排后台刷新任务: \(error)")
    }
}

func handleAppRefresh(task: BGAppRefreshTask) {
    // 创建一个进度追踪操作
    let operation = LongRunningOperation()
    
    // 提前安排下一次刷新
    scheduleAppRefresh()
    
    // 当系统即将终止任务时执行的操作
    task.expirationHandler = {
        operation.cancel()
    }
    
    // 执行操作
    operation.completionBlock = {
        task.setTaskCompleted(success: !operation.isCancelled)
    }
    
    operationQueue.addOperation(operation)
}
```

## 状态保存和恢复

iOS 提供了状态保存和恢复机制，允许应用在终止后恢复到之前的界面状态。

### 配置状态恢复

首先在 AppDelegate 中实现：

```swift
func application(_ application: UIApplication, shouldSaveApplicationState coder: NSCoder) -> Bool {
    return true
}

func application(_ application: UIApplication, shouldRestoreApplicationState coder: NSCoder) -> Bool {
    return true
}
```

### 视图控制器状态保存

视图控制器需要实现唯一的恢复标识符：

```swift
class MyViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        // 设置恢复标识符
        restorationIdentifier = "MyViewController"
    }
    
    // 编码视图状态
    override func encodeRestorableState(with coder: NSCoder) {
        super.encodeRestorableState(with: coder)
        
        // 保存自定义状态
        coder.encode(currentPage, forKey: "currentPage")
        coder.encode(searchText, forKey: "searchText")
    }
    
    // 解码视图状态
    override func decodeRestorableState(with coder: NSCoder) {
        super.decodeRestorableState(with: coder)
        
        // 恢复自定义状态
        currentPage = coder.decodeInteger(forKey: "currentPage")
        searchText = coder.decodeObject(forKey: "searchText") as? String
        
        // 更新UI以反映恢复的状态
        updateUserInterface()
    }
}
```

## 实践建议

### 响应应用状态变化

- **监听通知**：使用 `NotificationCenter` 监听应用状态变化

```swift
NotificationCenter.default.addObserver(
    self,
    selector: #selector(applicationDidBecomeActive),
    name: UIApplication.didBecomeActiveNotification,
    object: nil
)

@objc func applicationDidBecomeActive() {
    // 响应应用变为活跃状态
}
```

### 优化启动性能

1. **减少启动时间**：
   - 延迟非关键初始化
   - 使用后台线程加载资源
   - 优化 storyboard 和 xib 文件

```swift
func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    // 立即执行关键初始化
    setupUserInterface()
    
    // 延迟非关键初始化
    DispatchQueue.global(qos: .background).async {
        self.initializeAnalytics()
        self.loadCachedData()
        
        DispatchQueue.main.async {
            self.updateUIWithCachedData()
        }
    }
    
    return true
}
```

2. **利用启动屏幕**：
   - 设计与应用初始界面相似的启动屏幕
   - 使用 Launch Storyboard 适应不同设备尺寸

### 有效管理后台时间

- 当进入后台时，优先执行最关键的任务
- 设置任务优先级，确保重要任务先完成
- 使用紧凑代码路径，避免不必要的处理

```swift
func sceneDidEnterBackground(_ scene: UIScene) {
    // 首先保存用户数据
    saveUserData()
    
    // 然后清理和释放资源
    cleanupResources()
    
    // 最后，如果时间允许，执行低优先级任务
    if backgroundTimeRemaining > 5 {
        performLowPriorityTasks()
    }
}
```

### 响应系统事件

应用应适当响应系统事件，如：

- **内存警告**：释放不必要的内存
- **电池电量低**：减少耗电操作
- **系统升级**：保存状态并优雅退出

```swift
// 处理内存警告
override func didReceiveMemoryWarning() {
    super.didReceiveMemoryWarning()
    
    // 清除缓存
    imageCache.removeAllObjects()
    
    // 释放可重新创建的资源
    releaseRecreableResources()
}
```

### 调试生命周期事件

使用 Xcode 中的调试选项来模拟生命周期事件：

1. 运行应用
2. Debug > Simulate Background/Foreground
3. 观察控制台输出和应用行为

## iOS 13 与 iOS 12 的生命周期对比

### iOS 12 及以下（单窗口）

```
AppDelegate: application(_:didFinishLaunchingWithOptions:)
↓
AppDelegate: applicationDidBecomeActive(_:)
↓
AppDelegate: applicationWillResignActive(_:)  ← 用户切换到后台
↓
AppDelegate: applicationDidEnterBackground(_:)
↓
AppDelegate: applicationWillEnterForeground(_:)  ← 用户返回应用
↓
AppDelegate: applicationDidBecomeActive(_:)
↓
AppDelegate: applicationWillTerminate(_:)  ← 应用终止
```

### iOS 13 及以上（多窗口）

```
AppDelegate: application(_:didFinishLaunchingWithOptions:)
↓
AppDelegate: application(_:configurationForConnecting:options:)
↓
SceneDelegate: scene(_:willConnectTo:options:)
↓
SceneDelegate: sceneDidBecomeActive(_:)
↓
SceneDelegate: sceneWillResignActive(_:)  ← 用户切换到后台
↓
SceneDelegate: sceneDidEnterBackground(_:)
↓
SceneDelegate: sceneWillEnterForeground(_:)  ← 用户返回应用
↓
SceneDelegate: sceneDidBecomeActive(_:)
↓
SceneDelegate: sceneDidDisconnect(_:)  ← 场景断开连接
```

## 总结

理解 iOS 应用生命周期对于开发高质量应用至关重要。通过正确响应生命周期事件，应用可以：

- 提供流畅的用户体验
- 高效管理系统资源
- 保护用户数据安全
- 适应各种系统状态变化

遵循本文中的最佳实践，可以帮助您构建更加健壮和用户友好的 iOS 应用。

## 延伸阅读

- [Human Interface Guidelines - App Architecture](https://developer.apple.com/design/human-interface-guidelines/app-architecture)
- [Preparing Your UI to Run in the Background](https://developer.apple.com/documentation/uikit/app_and_environment/scenes/preparing_your_ui_to_run_in_the_background)
- [Managing Your App's Life Cycle](https://developer.apple.com/documentation/uikit/app_and_environment/managing_your_app_s_life_cycle) 