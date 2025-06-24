# 导航模式

在 iOS 应用程序中，导航模式定义了用户在不同屏幕间移动的方式。选择合适的导航模式对于提供直观、高效的用户体验至关重要。本文档将详细介绍 iOS 平台上常用的导航模式、实现方法及最佳实践。

## 目录

- [导航控制器](#导航控制器)
- [标签栏控制器](#标签栏控制器)
- [页面控制器](#页面控制器)
- [模态呈现](#模态呈现)
- [分屏与多窗口](#分屏与多窗口)
- [自定义转场](#自定义转场)
- [导航模式选择](#导航模式选择)
- [SwiftUI 导航](#swiftui-导航)
- [实践建议](#实践建议)

## 导航控制器

导航控制器(UINavigationController)提供了一种基于栈的、层级式的导航模式，适合展示信息的深度浏览。

### 基本用法

```swift
// 创建根视图控制器
let rootViewController = ListViewController()

// 创建导航控制器并设置根视图控制器
let navigationController = UINavigationController(rootViewController: rootViewController)

// 设置为窗口的根视图控制器
window?.rootViewController = navigationController
```

### 导航栈管理

```swift
// 推入新视图控制器
func showDetail(for item: Item) {
    let detailViewController = DetailViewController(item: item)
    navigationController?.pushViewController(detailViewController, animated: true)
}

// 弹出视图控制器
@objc func goBack() {
    navigationController?.popViewController(animated: true)
}

// 返回到根视图控制器
@objc func goToRoot() {
    navigationController?.popToRootViewController(animated: true)
}

// 返回到特定视图控制器
func popToSpecificViewController() {
    if let viewControllers = navigationController?.viewControllers {
        for viewController in viewControllers {
            if let targetVC = viewController as? TargetViewController {
                navigationController?.popToViewController(targetVC, animated: true)
                break
            }
        }
    }
}
```

### 导航栏定制

```swift
override func viewDidLoad() {
    super.viewDidLoad()
    
    // 设置标题
    title = "产品列表"
    
    // 自定义导航栏外观
    if let navigationBar = navigationController?.navigationBar {
        navigationBar.prefersLargeTitles = true // iOS 11+
        navigationBar.tintColor = .systemBlue
        
        // iOS 13+ 外观
        let appearance = UINavigationBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = .white
        appearance.shadowColor = .clear
        
        navigationBar.standardAppearance = appearance
        navigationBar.scrollEdgeAppearance = appearance
    }
    
    // 添加左侧按钮
    let backButton = UIBarButtonItem(
        image: UIImage(systemName: "arrow.left"),
        style: .plain,
        target: self,
        action: #selector(goBack)
    )
    navigationItem.leftBarButtonItem = backButton
    
    // 添加右侧按钮
    let addButton = UIBarButtonItem(
        barButtonSystemItem: .add,
        target: self,
        action: #selector(addNewItem)
    )
    navigationItem.rightBarButtonItem = addButton
    
    // 添加多个右侧按钮
    let editButton = UIBarButtonItem(
        barButtonSystemItem: .edit,
        target: self,
        action: #selector(editItems)
    )
    navigationItem.rightBarButtonItems = [addButton, editButton]
    
    // 自定义标题视图
    let titleView = CustomTitleView()
    navigationItem.titleView = titleView
}
```

## 标签栏控制器

标签栏控制器(UITabBarController)提供了一种平行导航模式，适合展示应用的主要功能模块。

### 基本用法

```swift
// 创建标签栏控制器
let tabBarController = UITabBarController()

// 创建各个标签页对应的视图控制器
let homeVC = HomeViewController()
homeVC.tabBarItem = UITabBarItem(
    title: "首页",
    image: UIImage(systemName: "house"),
    selectedImage: UIImage(systemName: "house.fill")
)

let searchVC = SearchViewController()
searchVC.tabBarItem = UITabBarItem(
    title: "搜索",
    image: UIImage(systemName: "magnifyingglass"),
    selectedImage: nil
)

let profileVC = ProfileViewController()
profileVC.tabBarItem = UITabBarItem(
    title: "我的",
    image: UIImage(systemName: "person"),
    selectedImage: UIImage(systemName: "person.fill")
)

// 将视图控制器包装在导航控制器中
let homeNav = UINavigationController(rootViewController: homeVC)
let searchNav = UINavigationController(rootViewController: searchVC)
let profileNav = UINavigationController(rootViewController: profileVC)

// 设置标签栏控制器的视图控制器
tabBarController.viewControllers = [homeNav, searchNav, profileNav]

// 设置初始选中的标签
tabBarController.selectedIndex = 0

// 设置为窗口的根视图控制器
window?.rootViewController = tabBarController
```

### 标签栏定制

```swift
override func viewDidLoad() {
    super.viewDidLoad()
    
    // 自定义标签栏外观
    if let tabBar = tabBarController?.tabBar {
        tabBar.tintColor = .systemBlue // 选中项颜色
        tabBar.unselectedItemTintColor = .gray // 未选中项颜色
        
        // iOS 13+ 外观
        let appearance = UITabBarAppearance()
        appearance.configureWithOpaqueBackground()
        appearance.backgroundColor = .white
        
        tabBar.standardAppearance = appearance
        if #available(iOS 15.0, *) {
            tabBar.scrollEdgeAppearance = appearance
        }
    }
}

// 动态更改标签
func updateBadge() {
    // 设置徽章
    tabBarController?.viewControllers?[1].tabBarItem.badgeValue = "5"
    
    // 清除徽章
    tabBarController?.viewControllers?[2].tabBarItem.badgeValue = nil
}
```

## 页面控制器

页面控制器(UIPageViewController)提供了一种水平滑动的导航模式，适合展示相似的内容页面。

### 基本用法

```swift
class TutorialPageViewController: UIPageViewController {
    
    private var pages: [UIViewController] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 配置页面控制器
        dataSource = self
        delegate = self
        
        // 创建页面视图控制器
        let page1 = createPage(title: "欢迎", image: "welcome")
        let page2 = createPage(title: "浏览", image: "browse")
        let page3 = createPage(title: "购买", image: "purchase")
        
        pages = [page1, page2, page3]
        
        // 设置初始页面
        if let firstPage = pages.first {
            setViewControllers([firstPage], direction: .forward, animated: false)
        }
        
        // 设置页面指示器
        let appearance = UIPageControl.appearance(whenContainedInInstancesOf: [UIPageViewController.self])
        appearance.pageIndicatorTintColor = .lightGray
        appearance.currentPageIndicatorTintColor = .darkGray
    }
    
    private func createPage(title: String, image: String) -> UIViewController {
        let pageVC = UIViewController()
        // 配置页面内容
        return pageVC
    }
}

// 实现数据源
extension TutorialPageViewController: UIPageViewControllerDataSource {
    
    func pageViewController(_ pageViewController: UIPageViewController, viewControllerBefore viewController: UIViewController) -> UIViewController? {
        guard let index = pages.firstIndex(of: viewController), index > 0 else {
            return nil
        }
        return pages[index - 1]
    }
    
    func pageViewController(_ pageViewController: UIPageViewController, viewControllerAfter viewController: UIViewController) -> UIViewController? {
        guard let index = pages.firstIndex(of: viewController), index < pages.count - 1 else {
            return nil
        }
        return pages[index + 1]
    }
    
    func presentationCount(for pageViewController: UIPageViewController) -> Int {
        return pages.count
    }
    
    func presentationIndex(for pageViewController: UIPageViewController) -> Int {
        guard let currentVC = viewControllers?.first, let index = pages.firstIndex(of: currentVC) else {
            return 0
        }
        return index
    }
}
```

## 模态呈现

模态呈现在当前上下文中显示新内容，要求用户完成操作才能返回。

### 基本用法

```swift
// 模态呈现视图控制器
func presentSettings() {
    let settingsVC = SettingsViewController()
    present(settingsVC, animated: true)
}

// 关闭模态视图控制器
@objc func dismiss() {
    dismiss(animated: true)
}
```

### 呈现样式

```swift
// 设置呈现样式
func presentWithStyle() {
    let detailVC = DetailViewController()
    
    // 设置呈现样式
    detailVC.modalPresentationStyle = .formSheet // 表单样式
    // 其他样式: .fullScreen, .pageSheet, .popover, .automatic
    
    // 设置转场样式
    detailVC.modalTransitionStyle = .coverVertical
    // 其他转场: .crossDissolve, .flipHorizontal, .partialCurl
    
    present(detailVC, animated: true)
}
```

### 模态呈现层次

```swift
// 多层模态呈现
func presentMultipleModals() {
    let firstVC = FirstViewController()
    present(firstVC, animated: true) {
        let secondVC = SecondViewController()
        firstVC.present(secondVC, animated: true)
    }
}
```

### 响应表单样式

```swift
// iOS 13+ 卡片式样式
func presentCardStyle() {
    let detailVC = DetailViewController()
    detailVC.modalPresentationStyle = .automatic // 默认为卡片样式
    detailVC.isModalInPresentation = true // 禁止交互式关闭
    present(detailVC, animated: true)
}

// 实现拖动关闭回调
class DetailViewController: UIViewController, UIAdaptivePresentationControllerDelegate {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        presentationController?.delegate = self
    }
    
    // 询问是否允许关闭
    func presentationControllerShouldDismiss(_ presentationController: UIPresentationController) -> Bool {
        // 检查表单是否已填写或有未保存的更改
        return formValidator.isValid
    }
    
    // 用户尝试关闭时的回调
    func presentationControllerDidAttemptToDismiss(_ presentationController: UIPresentationController) {
        // 显示提示询问用户是否确定放弃更改
        showDiscardAlert()
    }
}
```

## 分屏与多窗口

iPad 上的分屏多任务和多窗口功能允许用户同时使用多个应用或同一应用的多个实例。

### 启用多窗口支持

1. 在 Info.plist 中添加配置：

```xml
<key>UIApplicationSceneManifest</key>
<dict>
    <key>UIApplicationSupportsMultipleScenes</key>
    <true/>
    <key>UISceneConfigurations</key>
    <dict>
        <key>UIWindowSceneSessionRoleApplication</key>
        <array>
            <dict>
                <key>UISceneConfigurationName</key>
                <string>Default Configuration</string>
                <key>UISceneDelegateClassName</key>
                <string>$(PRODUCT_MODULE_NAME).SceneDelegate</string>
            </dict>
        </array>
    </dict>
</dict>
```

2. 实现场景管理：

```swift
// AppDelegate
func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
    return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
}

// SceneDelegate
func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions) {
    guard let windowScene = (scene as? UIWindowScene) else { return }
    
    let window = UIWindow(windowScene: windowScene)
    
    // 创建适合当前场景的根视图控制器
    if let userActivity = connectionOptions.userActivities.first {
        // 从用户活动恢复状态
        window.rootViewController = createRootViewController(from: userActivity)
    } else if let urlContext = connectionOptions.urlContexts.first {
        // 从 URL 创建视图
        window.rootViewController = createRootViewController(from: urlContext.url)
    } else {
        // 创建默认根视图控制器
        window.rootViewController = createDefaultRootViewController()
    }
    
    self.window = window
    window.makeKeyAndVisible()
}
```

3. 实现状态恢复：

```swift
// 保存状态
func stateRestorationActivity() -> NSUserActivity {
    let activity = NSUserActivity(activityType: "com.example.app.browsing")
    activity.title = "浏览产品"
    
    // 保存当前状态数据
    activity.addUserInfoEntries(from: [
        "currentProductId": currentProduct.id,
        "scrollPosition": scrollView.contentOffset.y
    ])
    
    return activity
}

// 视图控制器恢复状态
override func updateUserActivityState(_ activity: NSUserActivity) {
    super.updateUserActivityState(activity)
    
    // 更新活动状态
    activity.addUserInfoEntries(from: [
        "currentProductId": currentProduct.id,
        "scrollPosition": scrollView.contentOffset.y
    ])
}
```

## 自定义转场

自定义转场动画可以增强用户体验，提供更流畅、更有意义的界面转换。

### 自定义模态转场

```swift
class FadeTransitionAnimator: NSObject, UIViewControllerAnimatedTransitioning {
    
    let duration: TimeInterval = 0.5
    let isPresenting: Bool
    
    init(isPresenting: Bool) {
        self.isPresenting = isPresenting
        super.init()
    }
    
    func transitionDuration(using transitionContext: UIViewControllerContextTransitioning?) -> TimeInterval {
        return duration
    }
    
    func animateTransition(using transitionContext: UIViewControllerContextTransitioning) {
        // 获取源视图控制器和目标视图控制器
        guard let fromVC = transitionContext.viewController(forKey: .from),
              let toVC = transitionContext.viewController(forKey: .to) else {
            return
        }
        
        let containerView = transitionContext.containerView
        
        if isPresenting {
            // 呈现动画
            containerView.addSubview(toVC.view)
            toVC.view.alpha = 0
            
            UIView.animate(withDuration: duration, animations: {
                toVC.view.alpha = 1
            }, completion: { _ in
                transitionContext.completeTransition(!transitionContext.transitionWasCancelled)
            })
        } else {
            // 关闭动画
            UIView.animate(withDuration: duration, animations: {
                fromVC.view.alpha = 0
            }, completion: { _ in
                transitionContext.completeTransition(!transitionContext.transitionWasCancelled)
            })
        }
    }
}

// 在视图控制器中使用自定义转场
class ViewController: UIViewController, UIViewControllerTransitioningDelegate {
    
    func presentDetailView() {
        let detailVC = DetailViewController()
        detailVC.transitioningDelegate = self
        detailVC.modalPresentationStyle = .custom
        present(detailVC, animated: true)
    }
    
    // UIViewControllerTransitioningDelegate 方法
    func animationController(forPresented presented: UIViewController, presenting: UIViewController, source: UIViewController) -> UIViewControllerAnimatedTransitioning? {
        return FadeTransitionAnimator(isPresenting: true)
    }
    
    func animationController(forDismissed dismissed: UIViewController) -> UIViewControllerAnimatedTransitioning? {
        return FadeTransitionAnimator(isPresenting: false)
    }
}
```

### 交互式转场

```swift
class InteractiveTransitionController: UIPercentDrivenInteractiveTransition {
    var viewController: UIViewController
    var isInteracting: Bool = false
    
    init(viewController: UIViewController) {
        self.viewController = viewController
        super.init()
        setupGestureRecognizer()
    }
    
    private func setupGestureRecognizer() {
        let gesture = UIPanGestureRecognizer(target: self, action: #selector(handlePan(_:)))
        viewController.view.addGestureRecognizer(gesture)
    }
    
    @objc private func handlePan(_ gestureRecognizer: UIPanGestureRecognizer) {
        let translation = gestureRecognizer.translation(in: gestureRecognizer.view)
        let verticalMovement = translation.y / viewController.view.bounds.height
        let progress = max(0, min(1, verticalMovement))
        
        switch gestureRecognizer.state {
        case .began:
            isInteracting = true
            viewController.dismiss(animated: true)
        case .changed:
            update(progress)
        case .cancelled:
            isInteracting = false
            cancel()
        case .ended:
            isInteracting = false
            if progress > 0.5 {
                finish()
            } else {
                cancel()
            }
        default:
            break
        }
    }
}
```

## 导航模式选择

### 应用场景比较

| 导航模式 | 适用场景 | 优势 | 劣势 |
|---------|---------|------|------|
| 导航控制器 | 层级内容浏览 | 深度导航直观，标准模式 | 单一导航路径，返回路径固定 |
| 标签栏控制器 | 主要功能分类 | 平行访问多个功能，快速切换 | 标签数量有限，深度有限 |
| 页面控制器 | 类似内容分页浏览 | 流畅的水平滑动，适合教程和图片浏览 | 不适合不相关内容，深度导航能力弱 |
| 模态呈现 | 临时任务或聚焦场景 | 聚焦用户注意力，突出重要内容 | 中断当前上下文，不适合频繁使用 |

### 选择建议

1. **内容层级深度**：
   - 1-2 层：考虑平铺布局或简单标签栏
   - 3+ 层：使用导航控制器

2. **主要功能区域**：
   - 2-5 个独立功能区域：标签栏控制器
   - 单一主要功能：导航控制器

3. **用户行为**：
   - 需要频繁切换不同功能：标签栏
   - 线性探索内容：导航控制器或页面控制器
   - 完成独立任务：模态呈现

4. **混合策略**：
   - 标签栏 + 导航控制器：每个标签包含一个导航堆栈
   - 导航控制器 + 模态呈现：主流程使用导航，辅助任务使用模态
   - 自定义组合：根据特定需求组合多种导航模式

## SwiftUI 导航

SwiftUI 提供了声明式的导航 API，简化了导航逻辑的实现。

### NavigationView 与 NavigationLink

```swift
struct ContentView: View {
    var body: some View {
        NavigationView {
            List(items) { item in
                NavigationLink(destination: DetailView(item: item)) {
                    ItemRow(item: item)
                }
            }
            .navigationBarTitle("Items")
            .navigationBarItems(trailing:
                Button("Add") {
                    // 添加新项目
                }
            )
        }
    }
}

// iOS 16+ 新导航 API
struct ContentView: View {
    var body: some View {
        NavigationStack {
            List(items) { item in
                NavigationLink(value: item) {
                    ItemRow(item: item)
                }
            }
            .navigationDestination(for: Item.self) { item in
                DetailView(item: item)
            }
            .navigationTitle("Items")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Add") {
                        // 添加新项目
                    }
                }
            }
        }
    }
}
```

### TabView

```swift
struct MainView: View {
    var body: some View {
        TabView {
            HomeView()
                .tabItem {
                    Label("Home", systemImage: "house")
                }
            
            SearchView()
                .tabItem {
                    Label("Search", systemImage: "magnifyingglass")
                }
            
            ProfileView()
                .tabItem {
                    Label("Profile", systemImage: "person")
                }
        }
    }
}
```

### 模态呈现

```swift
struct ContentView: View {
    @State private var showingSettings = false
    
    var body: some View {
        Button("Show Settings") {
            showingSettings = true
        }
        .sheet(isPresented: $showingSettings) {
            SettingsView()
        }
    }
}
```

### 深度链接与路径

```swift
struct AppView: View {
    @StateObject var router = Router()
    
    var body: some View {
        NavigationStack(path: $router.path) {
            HomeView()
                .navigationDestination(for: Route.self) { route in
                    switch route {
                    case .productList(let category):
                        ProductListView(category: category)
                    case .productDetail(let product):
                        ProductDetailView(product: product)
                    case .checkout:
                        CheckoutView()
                    case .profile:
                        ProfileView()
                    }
                }
        }
        .environmentObject(router)
    }
}

class Router: ObservableObject {
    @Published var path: [Route] = []
    
    func navigate(to route: Route) {
        path.append(route)
    }
    
    func navigateBack() {
        _ = path.popLast()
    }
    
    func navigateToRoot() {
        path.removeAll()
    }
}

enum Route: Hashable {
    case productList(Category)
    case productDetail(Product)
    case checkout
    case profile
}
```

## 实践建议

### 导航最佳实践

1. **保持一致性**：在整个应用中使用一致的导航模式
2. **提供明确的视觉提示**：用户应该知道当前位置和可用的导航选项
3. **深度限制**：避免过深的导航层级（通常不超过 5 层）
4. **提供快捷方式**：对于常用功能，提供多种导航路径
5. **考虑可访问性**：确保导航元素易于触摸和识别

### 导航控制器

1. **清晰的标题**：每个屏幕使用描述性标题
2. **返回按钮定制**：如需要，定制返回按钮文本
3. **导航栏一致性**：保持导航栏风格一致

### 标签栏

1. **限制标签数量**：通常不超过 5 个
2. **使用清晰图标**：选择直观的图标并搭配文字
3. **考虑层级**：每个标签下的导航应该相对独立

### 模态呈现

1. **适度使用**：仅用于需要用户专注的临时任务
2. **提供明确的关闭方式**：总是提供返回或关闭按钮
3. **保留上下文**：模态视图应该保留一些视觉上下文

### 手势导航

1. **标准手势**：遵循系统标准手势（如向左轻扫返回）
2. **避免冲突**：确保自定义手势不与系统手势冲突
3. **提供视觉提示**：对于自定义手势，提供视觉指示 