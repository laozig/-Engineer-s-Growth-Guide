# iOS 本地通知 - 用户提醒

本地通知是 iOS 应用程序中一个强大的功能，允许应用程序在不活跃或运行在后台时向用户发送提醒。与远程通知（推送通知）不同，本地通知完全由设备上的应用程序管理，不需要服务器参与。本文将详细介绍如何在 iOS 应用中实现和管理本地通知。

## 目录

- [基础概念](#基础概念)
- [权限请求](#权限请求)
- [通知内容配置](#通知内容配置)
  - [基本属性](#基本属性)
  - [触发条件](#触发条件)
  - [通知内容](#通知内容)
  - [通知附件](#通知附件)
- [添加和管理通知](#添加和管理通知)
  - [添加通知](#添加通知)
  - [移除通知](#移除通知)
  - [更新通知](#更新通知)
  - [获取已计划的通知](#获取已计划的通知)
- [处理通知响应](#处理通知响应)
  - [应用在前台时](#应用在前台时)
  - [点击通知启动应用](#点击通知启动应用)
  - [自定义操作](#自定义操作)
- [通知分类与管理](#通知分类与管理)
  - [创建通知类别](#创建通知类别)
  - [定义自定义操作](#定义自定义操作)
  - [管理多种类别通知](#管理多种类别通知)
- [通知服务扩展](#通知服务扩展)
  - [修改通知内容](#修改通知内容)
  - [下载附加内容](#下载附加内容)
- [通知内容扩展](#通知内容扩展)
  - [自定义通知界面](#自定义通知界面)
  - [添加交互功能](#添加交互功能)
- [最佳实践](#最佳实践)
  - [合理设置通知频率](#合理设置通知频率)
  - [避免过多通知](#避免过多通知)
  - [提供清晰的通知内容](#提供清晰的通知内容)
  - [尊重用户设置](#尊重用户设置)
- [常见问题与解决方案](#常见问题与解决方案)
  - [通知未显示](#通知未显示)
  - [延迟发送问题](#延迟发送问题)
  - [权限问题](#权限问题)
- [适配 iOS 版本差异](#适配-ios-版本差异)
  - [iOS 10 之前](#ios-10-之前)
  - [iOS 10 及以上](#ios-10-及以上)
  - [iOS 12 分组通知](#ios-12-分组通知)
  - [iOS 15+ 焦点模式](#ios-15-焦点模式)
- [测试与调试](#测试与调试)
  - [模拟器测试](#模拟器测试)
  - [调试技巧](#调试技巧)
- [总结](#总结)
- [参考资源](#参考资源)

## 基础概念

本地通知是由应用程序在本地生成和管理的通知，无需与外部服务器通信。它们可以在指定的时间或特定事件发生时触发，即使应用程序不在前台运行。

iOS 通知系统包括两个主要部分：

1. **UserNotifications 框架**：从 iOS 10 开始，这是处理本地和远程通知的主要 API。
2. **UILocalNotification**：iOS 10 之前的旧 API，现已弃用。

本文主要关注现代 UserNotifications 框架，它提供了更强大和灵活的通知管理功能。

### UserNotifications 框架的主要组件

- **UNUserNotificationCenter**：负责管理应用的所有通知相关操作。
- **UNNotificationRequest**：代表一个通知请求，包含通知内容和触发条件。
- **UNNotificationContent**：定义通知的内容，如标题、副标题、正文等。
- **UNNotificationTrigger**：定义何时发送通知的触发条件。
- **UNNotificationResponse**：表示用户对通知的响应。

## 权限请求

在 iOS 中，应用程序必须先获取用户授权才能发送通知。未获授权的应用尝试发送的通知将不会显示给用户。

### 请求通知权限

```swift
import UserNotifications

class NotificationManager {
    static let shared = NotificationManager()
    
    private init() {}
    
    func requestAuthorization(completion: @escaping (Bool) -> Void) {
        let center = UNUserNotificationCenter.current()
        
        // 请求授权显示提醒、播放声音和显示角标
        center.requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                print("请求通知权限时出错: \(error.localizedDescription)")
            }
            
            completion(granted)
        }
    }
}

// 使用方法
NotificationManager.shared.requestAuthorization { granted in
    if granted {
        print("用户已授权通知")
    } else {
        print("用户拒绝了通知授权")
    }
}
```

### 检查通知权限状态

```swift
func checkAuthorizationStatus(completion: @escaping (UNAuthorizationStatus) -> Void) {
    let center = UNUserNotificationCenter.current()
    
    center.getNotificationSettings { settings in
        completion(settings.authorizationStatus)
    }
}

// 使用方法
NotificationManager.shared.checkAuthorizationStatus { status in
    switch status {
    case .authorized:
        print("用户已授权通知")
    case .denied:
        print("用户拒绝了通知授权")
    case .notDetermined:
        print("用户尚未做出选择")
    case .provisional:
        print("用户已授予临时授权")
    case .ephemeral:
        print("用户授予临时授权（在应用剪辑中）")
    @unknown default:
        print("未知状态")
    }
}
```

### 引导用户开启通知

如果用户之前拒绝了通知权限，应用程序不能直接再次请求授权。此时，最佳做法是引导用户通过系统设置启用通知：

```swift
func promptForNotificationSettings() {
    checkAuthorizationStatus { status in
        if status == .denied {
            // 显示引导用户到设置的提示
            DispatchQueue.main.async {
                let alertController = UIAlertController(
                    title: "启用通知",
                    message: "要接收重要提醒，请在设置中启用通知。",
                    preferredStyle: .alert
                )
                
                let cancelAction = UIAlertAction(title: "取消", style: .cancel)
                
                let settingsAction = UIAlertAction(title: "设置", style: .default) { _ in
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                }
                
                alertController.addAction(cancelAction)
                alertController.addAction(settingsAction)
                
                // 在当前视图控制器上显示提醒
                // self.present(alertController, animated: true)
            }
        }
    }
}
```

## 通知内容配置

本地通知由内容、触发条件和可选的附件组成。配置这些组件可以创建各种类型的通知体验。

### 基本属性

通知内容是通过 `UNMutableNotificationContent` 类配置的：

```swift
let content = UNMutableNotificationContent()
content.title = "通知标题"
content.subtitle = "通知副标题"
content.body = "这是通知的详细内容，可以包含更多信息。"
content.badge = 1
content.sound = UNNotificationSound.default
```

这些基本属性包括：

- **title**：通知的主标题
- **subtitle**：显示在标题下方的副标题
- **body**：通知的详细内容
- **badge**：应用图标上显示的数字
- **sound**：通知时播放的声音

### 触发条件

触发条件决定了通知何时显示。UserNotifications 框架提供了几种触发类型：

#### 1. 时间间隔触发器

在指定的时间间隔后触发通知：

```swift
// 创建一个 5 秒后触发的通知
let trigger = UNTimeIntervalNotificationTrigger(
    timeInterval: 5,  // 5 秒后
    repeats: false    // 不重复
)
```

#### 2. 日历触发器

在特定日期和时间触发通知：

```swift
// 创建每天上午 8:30 触发的通知
var dateComponents = DateComponents()
dateComponents.hour = 8
dateComponents.minute = 30

let trigger = UNCalendarNotificationTrigger(
    dateComponents: dateComponents,
    repeats: true  // 每天重复
)
```

#### 3. 位置触发器

当用户进入或离开特定区域时触发通知：

```swift
// 创建一个基于位置的触发器
let center = CLLocationCoordinate2D(latitude: 39.9042, longitude: 116.4074) // 北京坐标
let region = CLCircularRegion(
    center: center,
    radius: 500,  // 500 米半径
    identifier: "BeijingCenter"
)
region.notifyOnEntry = true  // 进入区域时通知
region.notifyOnExit = false  // 离开区域时不通知

let trigger = UNLocationNotificationTrigger(
    region: region,
    repeats: false
)
```

> **注意**：使用位置触发器需要在应用的 Info.plist 中添加位置使用权限，并且用户必须授权应用使用位置服务。

### 通知内容

除了基本属性外，您还可以通过以下方式自定义通知内容：

#### 1. 自定义声音

```swift
// 使用自定义声音文件（需要添加到项目中）
content.sound = UNNotificationSound.sound(named: UNNotificationSoundName("custom_sound.wav"))

// 使用系统声音
content.sound = UNNotificationSound.defaultCritical // iOS 12+ 关键提醒声音
```

#### 2. 用户信息

用户信息可以传递额外数据，当用户与通知交互时获取：

```swift
content.userInfo = [
    "articleId": "12345",
    "category": "sports",
    "deepLink": "myapp://articles/12345"
]
```

#### 3. 线程标识符

线程标识符用于将相关通知分组：

```swift
content.threadIdentifier = "chat-123" // 所有具有相同线程标识符的通知将分组在一起
```

### 通知附件

iOS 支持在通知中显示媒体附件，如图像、音频和视频：

```swift
// 添加图像附件
if let imageURL = Bundle.main.url(forResource: "notification_image", withExtension: "jpg") {
    do {
        let attachment = try UNNotificationAttachment(
            identifier: "imageAttachment",
            url: imageURL,
            options: nil
        )
        content.attachments = [attachment]
    } catch {
        print("添加附件时出错: \(error.localizedDescription)")
    }
}
```

附件注意事项：

- 支持的文件类型包括：JPEG、GIF、PNG、MP3、MOV 等
- 附件文件必须位于应用的容器内
- 文件大小有限制，过大的附件将不会显示
- 可以使用通知服务扩展下载远程附件 

## 添加和管理通知

配置好通知内容和触发条件后，需要将通知添加到系统中以供调度。

### 添加通知

添加通知需要创建 `UNNotificationRequest` 并将其添加到 `UNUserNotificationCenter`：

```swift
func scheduleNotification(with content: UNMutableNotificationContent, trigger: UNNotificationTrigger?) {
    // 创建一个唯一标识符
    let identifier = UUID().uuidString
    
    // 创建通知请求
    let request = UNNotificationRequest(
        identifier: identifier,
        content: content,
        trigger: trigger
    )
    
    // 将请求添加到通知中心
    let center = UNUserNotificationCenter.current()
    center.add(request) { error in
        if let error = error {
            print("添加通知请求时出错: \(error.localizedDescription)")
        } else {
            print("通知已成功安排，标识符: \(identifier)")
        }
    }
}

// 使用方法示例
let content = UNMutableNotificationContent()
content.title = "提醒"
content.body = "别忘了今天下午3点的会议"
content.sound = .default

// 创建触发器 - 30分钟后提醒
let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 30 * 60, repeats: false)

// 安排通知
NotificationManager.shared.scheduleNotification(with: content, trigger: trigger)
```

### 移除通知

可以根据标识符删除特定的通知，或删除所有通知：

```swift
// 删除特定标识符的通知
func removeNotification(with identifier: String) {
    let center = UNUserNotificationCenter.current()
    center.removePendingNotificationRequests(withIdentifiers: [identifier])
}

// 删除所有待处理的通知
func removeAllPendingNotifications() {
    let center = UNUserNotificationCenter.current()
    center.removeAllPendingNotificationRequests()
}

// 删除所有已投递的通知
func removeAllDeliveredNotifications() {
    let center = UNUserNotificationCenter.current()
    center.removeAllDeliveredNotifications()
}
```

### 更新通知

iOS 中没有直接更新通知的 API。要更新通知，需要移除现有通知并添加新通知：

```swift
func updateNotification(with identifier: String, newContent: UNMutableNotificationContent, newTrigger: UNNotificationTrigger?) {
    let center = UNUserNotificationCenter.current()
    
    // 移除旧通知
    center.removePendingNotificationRequests(withIdentifiers: [identifier])
    
    // 创建新的通知请求，使用相同的标识符
    let request = UNNotificationRequest(
        identifier: identifier,
        content: newContent,
        trigger: newTrigger
    )
    
    // 添加新通知
    center.add(request) { error in
        if let error = error {
            print("更新通知时出错: \(error.localizedDescription)")
        } else {
            print("通知已成功更新，标识符: \(identifier)")
        }
    }
}
```

### 获取已计划的通知

可以获取所有待处理和已投递的通知：

```swift
// 获取所有待处理的通知
func getPendingNotifications(completion: @escaping ([UNNotificationRequest]) -> Void) {
    let center = UNUserNotificationCenter.current()
    center.getPendingNotificationRequests { requests in
        completion(requests)
    }
}

// 获取所有已投递的通知
func getDeliveredNotifications(completion: @escaping ([UNNotification]) -> Void) {
    let center = UNUserNotificationCenter.current()
    center.getDeliveredNotifications { notifications in
        completion(notifications)
    }
}

// 使用示例
NotificationManager.shared.getPendingNotifications { requests in
    print("待处理通知数量: \(requests.count)")
    
    for request in requests {
        print("通知标识符: \(request.identifier)")
        print("通知标题: \(request.content.title)")
        print("通知内容: \(request.content.body)")
        
        if let trigger = request.trigger as? UNCalendarNotificationTrigger,
           let nextTriggerDate = trigger.nextTriggerDate() {
            print("下次触发时间: \(nextTriggerDate)")
        }
    }
}
```

## 处理通知响应

应用程序需要处理用户与通知的交互，无论是在前台收到通知还是用户点击通知启动应用。

### 应用在前台时

默认情况下，当应用在前台运行时，通知不会显示给用户。从 iOS 10 开始，您可以选择在前台显示通知，并自定义其表现形式：

```swift
// 在 AppDelegate 或 SceneDelegate 中
func setupNotificationDelegate() {
    UNUserNotificationCenter.current().delegate = self
}

// 实现 UNUserNotificationCenterDelegate
extension AppDelegate: UNUserNotificationCenterDelegate {
    // 当应用在前台时收到通知
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        // 获取通知内容
        let content = notification.request.content
        print("在前台收到通知: \(content.title)")
        
        // 可以根据通知的 userInfo 或其他属性决定如何处理
        let userInfo = content.userInfo
        
        // 选择在前台显示通知的方式
        if #available(iOS 14.0, *) {
            completionHandler([.banner, .sound, .badge, .list])
        } else {
            completionHandler([.alert, .sound, .badge])
        }
        
        // 或者选择不显示通知，而是在应用内处理
        // completionHandler([])
    }
}
```

### 点击通知启动应用

当用户点击通知打开应用时，应用需要处理这一交互：

```swift
extension AppDelegate: UNUserNotificationCenterDelegate {
    // 当用户点击通知时调用
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        // 获取通知内容
        let content = response.notification.request.content
        print("用户响应了通知: \(content.title)")
        
        // 获取响应类型
        let actionIdentifier = response.actionIdentifier
        
        // 用户点击通知打开应用
        if actionIdentifier == UNNotificationDefaultActionIdentifier {
            print("用户点击了通知打开应用")
            
            // 处理通知中的用户信息
            if let articleId = content.userInfo["articleId"] as? String {
                print("跳转到文章 ID: \(articleId)")
                // navigateToArticle(withId: articleId)
            }
            
            // 处理深链接
            if let deepLink = content.userInfo["deepLink"] as? String,
               let url = URL(string: deepLink) {
                print("处理深链接: \(deepLink)")
                // handleDeepLink(url)
            }
        }
        // 用户点击了关闭通知
        else if actionIdentifier == UNNotificationDismissActionIdentifier {
            print("用户关闭了通知")
        }
        // 用户点击了自定义操作
        else {
            print("用户点击了自定义操作: \(actionIdentifier)")
            handleCustomAction(actionIdentifier, for: response.notification)
        }
        
        // 完成处理
        completionHandler()
    }
    
    private func handleCustomAction(_ actionIdentifier: String, for notification: UNNotification) {
        let content = notification.request.content
        
        switch actionIdentifier {
        case "reply":
            if let response = notification.request.content.userInfo["response"] as? String {
                print("用户回复: \(response)")
            }
        case "accept":
            print("用户接受了邀请")
        case "reject":
            print("用户拒绝了邀请")
        default:
            print("未知操作: \(actionIdentifier)")
        }
    }
}
```

### 自定义操作

通知可以包含自定义操作按钮，允许用户直接从通知界面进行交互：

```swift
// 创建自定义操作
let acceptAction = UNNotificationAction(
    identifier: "accept",
    title: "接受",
    options: .foreground
)

let rejectAction = UNNotificationAction(
    identifier: "reject",
    title: "拒绝",
    options: .destructive
)

// 创建文本输入操作
let replyAction = UNTextInputNotificationAction(
    identifier: "reply",
    title: "回复",
    options: [],
    textInputButtonTitle: "发送",
    textInputPlaceholder: "输入您的回复..."
)

// 创建通知类别
let inviteCategory = UNNotificationCategory(
    identifier: "MEETING_INVITATION",
    actions: [acceptAction, rejectAction, replyAction],
    intentIdentifiers: [],
    options: []
)

// 注册通知类别
UNUserNotificationCenter.current().setNotificationCategories([inviteCategory])

// 在通知内容中指定类别
let content = UNMutableNotificationContent()
content.title = "会议邀请"
content.body = "您收到了下午3点的会议邀请"
content.categoryIdentifier = "MEETING_INVITATION" // 关联到已注册的类别
```

## 通知分类与管理

通知分类允许组织不同类型的通知，并为每种类型定义自定义交互。

### 创建通知类别

```swift
class NotificationCategoryManager {
    static let shared = NotificationCategoryManager()
    
    // 通知类别标识符
    struct CategoryIdentifier {
        static let message = "MESSAGE"
        static let reminder = "REMINDER"
        static let news = "NEWS"
    }
    
    // 通知操作标识符
    struct ActionIdentifier {
        static let reply = "REPLY"
        static let markAsRead = "MARK_AS_READ"
        static let remind = "REMIND_LATER"
        static let share = "SHARE"
    }
    
    private init() {}
    
    func registerCategories() {
        // 消息类别
        let reply = UNTextInputNotificationAction(
            identifier: ActionIdentifier.reply,
            title: "回复",
            options: [],
            textInputButtonTitle: "发送",
            textInputPlaceholder: "输入回复..."
        )
        
        let markAsRead = UNNotificationAction(
            identifier: ActionIdentifier.markAsRead,
            title: "标记为已读",
            options: [.authenticationRequired]
        )
        
        let messageCategory = UNNotificationCategory(
            identifier: CategoryIdentifier.message,
            actions: [reply, markAsRead],
            intentIdentifiers: [],
            options: []
        )
        
        // 提醒类别
        let remindLater = UNNotificationAction(
            identifier: ActionIdentifier.remind,
            title: "稍后提醒",
            options: [.foreground]
        )
        
        let reminderCategory = UNNotificationCategory(
            identifier: CategoryIdentifier.reminder,
            actions: [remindLater],
            intentIdentifiers: [],
            options: []
        )
        
        // 新闻类别
        let share = UNNotificationAction(
            identifier: ActionIdentifier.share,
            title: "分享",
            options: [.foreground]
        )
        
        let newsCategory = UNNotificationCategory(
            identifier: CategoryIdentifier.news,
            actions: [share],
            intentIdentifiers: [],
            options: []
        )
        
        // 注册所有类别
        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories([messageCategory, reminderCategory, newsCategory])
    }
}

// 使用
NotificationCategoryManager.shared.registerCategories()
```

### 定义自定义操作

通知操作允许用户直接从通知界面与应用程序交互，无需打开应用。有两种类型的操作：

1. **UNNotificationAction**：基本按钮操作
2. **UNTextInputNotificationAction**：允许用户输入文本

操作选项包括：

- **.foreground**：点击操作会将应用带到前台
- **.destructive**：以红色显示操作，表示删除或负面操作
- **.authenticationRequired**：需要设备解锁才能执行

### 管理多种类别通知

为不同类型的通知分配不同的类别标识符：

```swift
// 发送消息通知
func sendMessageNotification(from sender: String, message: String) {
    let content = UNMutableNotificationContent()
    content.title = sender
    content.body = message
    content.categoryIdentifier = NotificationCategoryManager.CategoryIdentifier.message
    content.userInfo = ["senderId": sender, "messageText": message]
    content.sound = .default
    
    let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false)
    
    let request = UNNotificationRequest(
        identifier: UUID().uuidString,
        content: content,
        trigger: trigger
    )
    
    UNUserNotificationCenter.current().add(request)
}

// 发送提醒通知
func sendReminderNotification(title: String, body: String, date: Date) {
    let content = UNMutableNotificationContent()
    content.title = title
    content.body = body
    content.categoryIdentifier = NotificationCategoryManager.CategoryIdentifier.reminder
    content.sound = .default
    
    let calendar = Calendar.current
    let components = calendar.dateComponents([.year, .month, .day, .hour, .minute], from: date)
    
    let trigger = UNCalendarNotificationTrigger(dateComponents: components, repeats: false)
    
    let request = UNNotificationRequest(
        identifier: UUID().uuidString,
        content: content,
        trigger: trigger
    )
    
    UNUserNotificationCenter.current().add(request)
}
```

## 通知服务扩展

通知服务扩展允许应用程序在通知中添加附加内容，如图像、音频或视频。

### 修改通知内容

```swift
// 添加图像附件
if let imageURL = Bundle.main.url(forResource: "notification_image", withExtension: "jpg") {
    do {
        let attachment = try UNNotificationAttachment(
            identifier: "imageAttachment",
            url: imageURL,
            options: nil
        )
        content.attachments = [attachment]
    } catch {
        print("添加附件时出错: \(error.localizedDescription)")
    }
}
```

### 下载附加内容

可以使用通知服务扩展下载远程附件：

```swift
// 使用 URLSession 下载远程附件
func downloadAttachment(from url: URL, completion: @escaping (Data?) -> Void) {
    let session = URLSession.shared
    let task = session.dataTask(with: url) { data, response, error in
        if let error = error {
            print("下载附件时出错: \(error.localizedDescription)")
            completion(nil)
        } else if let data = data {
            completion(data)
        } else {
            print("下载附件时没有数据返回")
            completion(nil)
        }
    }
    task.resume()
}

// 使用示例
let url = URL(string: "https://example.com/notification_image.jpg")!
NotificationManager.shared.downloadAttachment(from: url) { data in
    if let data = data {
        // 处理下载的数据
        print("附件数据长度: \(data.count)")
    } else {
        print("附件下载失败")
    }
}
```

## 通知内容扩展

通知内容扩展允许自定义通知界面和添加交互功能。

### 自定义通知界面

```swift
// 创建自定义通知界面
func createCustomNotificationView(for notification: UNNotification) -> UIView {
    let view = UIView()
    view.backgroundColor = .systemBackground
    
    let titleLabel = UILabel()
    titleLabel.text = notification.request.content.title
    titleLabel.font = .boldSystemFont(ofSize: 18)
    titleLabel.numberOfLines = 0
    titleLabel.translatesAutoresizingMaskIntoConstraints = false
    
    let bodyLabel = UILabel()
    bodyLabel.text = notification.request.content.body
    bodyLabel.numberOfLines = 0
    bodyLabel.translatesAutoresizingMaskIntoConstraints = false
    
    view.addSubview(titleLabel)
    view.addSubview(bodyLabel)
    
    NSLayoutConstraint.activate([
        titleLabel.topAnchor.constraint(equalTo: view.topAnchor, constant: 16),
        titleLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
        titleLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
        
        bodyLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
        bodyLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
        bodyLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
        bodyLabel.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -16)
    ])
    
    return view
}

// 实现 UNNotificationContentExtension
class NotificationContentExtension: UNNotificationContentExtension {
    func didReceive(_ notification: UNNotification) {
        // 创建自定义通知界面
        let customView = createCustomNotificationView(for: notification)
        
        // 设置通知内容扩展
        self.extensionContext?.notificationContentExtensionResponsePlaceholder = customView
    }
}
```

### 添加交互功能

通知可以包含交互功能，如按钮或文本输入：

```swift
// 创建自定义操作
let acceptAction = UNNotificationAction(
    identifier: "accept",
    title: "接受",
    options: .foreground
)

let rejectAction = UNNotificationAction(
    identifier: "reject",
    title: "拒绝",
    options: .destructive
)

// 创建文本输入操作
let replyAction = UNTextInputNotificationAction(
    identifier: "reply",
    title: "回复",
    options: [],
    textInputButtonTitle: "发送",
    textInputPlaceholder: "输入您的回复..."
)

// 创建通知类别
let inviteCategory = UNNotificationCategory(
    identifier: "MEETING_INVITATION",
    actions: [acceptAction, rejectAction, replyAction],
    intentIdentifiers: [],
    options: []
)

// 注册通知类别
UNUserNotificationCenter.current().setNotificationCategories([inviteCategory])

// 在通知内容中指定类别
let content = UNMutableNotificationContent()
content.title = "会议邀请"
content.body = "您收到了下午3点的会议邀请"
content.categoryIdentifier = "MEETING_INVITATION" // 关联到已注册的类别
```

## 最佳实践

以下是一些最佳实践建议，以确保本地通知的有效使用：

### 合理设置通知频率

不要过于频繁地发送通知，以免打扰用户。根据应用程序的实际需要，合理设置通知频率。

### 避免过多通知

不要一次性发送大量通知，以免用户感到压力。根据用户的兴趣和需求，逐步发送相关通知。

### 提供清晰的通知内容

确保通知内容清晰、简洁，并提供足够的信息，以便用户了解通知的目的和相关操作。

### 尊重用户设置

不要强制用户接收通知，而是根据用户的兴趣和需求，提供个性化的通知体验。

## 常见问题与解决方案

### 通知未显示

如果通知未显示，请检查以下几点：

1. 确保应用程序已获取通知权限。
2. 检查通知内容和触发条件是否正确。
3. 确保通知配置在应用的 Info.plist 中正确配置。

### 延迟发送问题

如果通知延迟发送，请检查以下几点：

1. 确保设备时间准确。
2. 检查网络连接是否稳定。
3. 确保通知配置在应用的 Info.plist 中正确配置。

### 权限问题

如果通知权限问题导致通知无法显示，请检查以下几点：

1. 确保应用程序已获取通知权限。
2. 检查通知权限状态。
3. 确保通知配置在应用的 Info.plist 中正确配置。

## 适配 iOS 版本差异

### iOS 10 之前

在 iOS 10 之前，使用 `UILocalNotification` 来处理本地通知。

### iOS 10 及以上

从 iOS 10 开始，使用 UserNotifications 框架来处理本地通知。

### iOS 12 分组通知

在 iOS 12 及以上版本中，通知可以分组显示。

### iOS 15+ 焦点模式

在 iOS 15 及以上版本中，支持焦点模式，可以优先处理重要通知。

## 测试与调试

### 模拟器测试

在模拟器上测试通知功能，以确保通知配置正确。

### 调试技巧

如果通知问题无法解决，请检查以下几点：

1. 确保设备时间准确。
2. 检查网络连接是否稳定。
3. 确保通知配置在应用的 Info.plist 中正确配置。

## 总结

本地通知是 iOS 应用程序中一个强大的功能，允许应用程序在不活跃或运行在后台时向用户发送提醒。通过本文的介绍，您应该能够理解如何在 iOS 应用中实现和管理本地通知。希望这些信息对您有所帮助，并祝您开发出更好的应用程序！

## 参考资源

- [Apple Developer Documentation](https://developer.apple.com/documentation/usernotifications)
- [WWDC 2018: Introducing UserNotifications](https://developer.apple.com/videos/play/wwdc2018/706/) 