# SwiftUI 基础

SwiftUI 是 Apple 在 WWDC 2019 上发布的现代化声明式 UI 框架，用于构建适用于 iOS、macOS、watchOS 和 tvOS 的用户界面。本教程将介绍 SwiftUI 的基础概念和核心组件。

## 目录

- [SwiftUI 简介](#swiftui-简介)
- [开发环境](#开发环境)
- [基本视图](#基本视图)
- [布局系统](#布局系统)
- [状态管理](#状态管理)
- [数据流](#数据流)
- [导航](#导航)
- [列表与集合](#列表与集合)
- [用户输入](#用户输入)
- [与 UIKit 集成](#与-uikit-集成)
- [小结与最佳实践](#小结与最佳实践)

## SwiftUI 简介

### 什么是 SwiftUI？

SwiftUI 是一个声明式 UI 框架，使用简洁的 Swift 语法来描述用户界面的外观和行为。与传统的命令式编程相比，声明式 UI 使开发者专注于描述"界面应该是什么样子"，而不是关注"如何构建界面"的具体过程。

### SwiftUI 的核心优势

1. **声明式语法** - 简洁直观的代码描述 UI 和状态
2. **实时预览** - 在 Xcode 中实时查看设计效果
3. **自动适配** - 一套代码适配多种设备和布局
4. **一致性** - 跨平台统一的 API
5. **状态驱动** - 响应式设计简化状态管理
6. **内置动画** - 简化复杂的动画实现
7. **SwiftUI 和 UIKit 互操作** - 可以混合使用现有 UIKit 代码

## 开发环境

### 系统要求

- iOS 13+ / macOS 10.15+ / watchOS 6+ / tvOS 13+
- Xcode 11+
- Swift 5.1+

### 创建 SwiftUI 项目

1. 打开 Xcode
2. 选择 "File" > "New" > "Project"
3. 选择 "App" 模板
4. 在 "Interface" 选项中选择 "SwiftUI"
5. 填写项目信息并创建项目

### SwiftUI 预览

SwiftUI 最强大的功能之一是实时预览：

```swift
struct ContentView: View {
    var body: some View {
        Text("Hello, SwiftUI!")
    }
}

// 预览代码
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
```

预览配置选项：

```swift
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        Group {
            ContentView()
                .previewDevice("iPhone 13")
                .previewDisplayName("iPhone 13")
            
            ContentView()
                .previewDevice("iPhone SE (3rd generation)")
                .previewDisplayName("iPhone SE")
                .environment(\.colorScheme, .dark)
        }
    }
}
```

## 基本视图

SwiftUI 提供了丰富的内置视图组件。以下是一些最常用的基本视图：

### 文本显示

```swift
// 基本文本
Text("Hello, World!")

// 样式修改
Text("Styled Text")
    .font(.title)
    .fontWeight(.bold)
    .foregroundColor(.blue)
    .padding()
    .background(Color.yellow)
    .cornerRadius(10)

// 多行文本
Text("This is a longer text that will automatically wrap to multiple lines when the text is too long to fit on a single line.")
    .lineLimit(2)
    .truncationMode(.tail)

// 富文本
Text("Swift").foregroundColor(.red) +
Text("UI").foregroundColor(.blue).bold()
```

### 图片

```swift
// 从资源加载图片
Image("logo")
    .resizable()
    .scaledToFit()
    .frame(width: 100, height: 100)

// 系统图标
Image(systemName: "heart.fill")
    .font(.system(size: 50))
    .foregroundColor(.red)

// 远程图片（需要使用 AsyncImage iOS 15+）
AsyncImage(url: URL(string: "https://example.com/image.jpg")) { image in
    image
        .resizable()
        .scaledToFit()
} placeholder: {
    ProgressView()
}
.frame(width: 200, height: 200)
```

### 按钮与交互控件

```swift
// 基本按钮
Button("Tap Me") {
    print("Button tapped!")
}

// 自定义按钮样式
Button(action: {
    print("Custom button tapped!")
}) {
    HStack {
        Image(systemName: "star.fill")
        Text("Star")
    }
    .padding()
    .background(Color.yellow)
    .foregroundColor(.white)
    .cornerRadius(10)
}

// 开关控件
@State private var isToggled = false

Toggle("Notifications", isOn: $isToggled)
    .padding()

// 滑块
@State private var sliderValue = 50.0

Slider(value: $sliderValue, in: 0...100) {
    Text("Slider")
}
.padding()

// 步进器
@State private var stepperValue = 0

Stepper("Quantity: \(stepperValue)", value: $stepperValue, in: 0...10)
    .padding()
```

### 基本容器

```swift
// 卡片布局
VStack {
    Image(systemName: "photo")
        .font(.system(size: 50))
        .padding()
    Text("Photo Title")
        .font(.headline)
    Text("Photo description goes here and provides more details about the image.")
        .font(.subheadline)
        .foregroundColor(.secondary)
}
.padding()
.background(Color(.systemBackground))
.cornerRadius(10)
.shadow(radius: 5)
```

## 布局系统

SwiftUI 使用强大的布局系统来组织和排列界面元素。

### 堆栈视图

```swift
// 垂直堆栈
VStack(alignment: .leading, spacing: 10) {
    Text("Title").font(.title)
    Text("Subtitle").font(.subheadline)
}

// 水平堆栈
HStack(alignment: .center, spacing: 20) {
    Image(systemName: "person.circle")
        .font(.largeTitle)
    VStack(alignment: .leading) {
        Text("John Doe")
        Text("Designer")
            .font(.subheadline)
            .foregroundColor(.secondary)
    }
}

// 深度堆栈（Z轴）
ZStack {
    Color.blue.edgesIgnoringSafeArea(.all)
    Text("Foreground Content")
        .foregroundColor(.white)
        .font(.largeTitle)
}
```

### Spacer 和 Divider

```swift
VStack {
    Text("Top")
    Spacer() // 创建可伸缩的空间
    Text("Middle")
    Spacer()
    Text("Bottom")
}
.frame(height: 200)

HStack {
    Text("Left")
    Divider() // 添加分割线
        .background(Color.black)
    Text("Right")
}
.padding()
```

### Frame 和尺寸控制

```swift
// 固定尺寸
Text("Fixed Size")
    .frame(width: 100, height: 50)
    .background(Color.red)

// 最小和最大尺寸
Text("Flexible Size")
    .frame(minWidth: 100, maxWidth: .infinity, minHeight: 50)
    .background(Color.green)

// 自适应尺寸
Text("Auto Size")
    .padding()
    .background(Color.blue)
    .foregroundColor(.white)
```

### 内边距和边缘

```swift
// 所有边缘添加内边距
Text("Padding All Edges")
    .padding()
    .background(Color.yellow)

// 特定边缘添加内边距
Text("Padding Specific Edges")
    .padding([.top, .leading], 20)
    .background(Color.orange)

// 忽略安全区域
Color.purple
    .edgesIgnoringSafeArea(.all)
    .overlay(
        Text("Full Screen")
            .foregroundColor(.white)
    )
```

## 状态管理

SwiftUI 使用声明式编程范式，UI 状态变化会自动反映在界面上。

### @State

用于组件内部状态管理：

```swift
struct CounterView: View {
    @State private var count = 0
    
    var body: some View {
        VStack {
            Text("Count: \(count)")
                .font(.headline)
            
            Button("Increment") {
                count += 1
            }
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(10)
        }
        .padding()
    }
}
```

### @Binding

用于在视图之间传递可变状态：

```swift
struct ToggleView: View {
    @Binding var isOn: Bool
    
    var body: some View {
        Toggle("Feature Enabled", isOn: $isOn)
            .padding()
    }
}

struct ParentView: View {
    @State private var featureEnabled = false
    
    var body: some View {
        VStack {
            Text("Feature is \(featureEnabled ? "enabled" : "disabled")")
            
            ToggleView(isOn: $featureEnabled)
            
            Button("Reset") {
                featureEnabled = false
            }
        }
        .padding()
    }
}
```

### @ObservedObject

用于观察外部对象的变化：

```swift
class UserData: ObservableObject {
    @Published var username = ""
    @Published var isLoggedIn = false
}

struct ProfileView: View {
    @ObservedObject var userData: UserData
    
    var body: some View {
        VStack {
            if userData.isLoggedIn {
                Text("Welcome, \(userData.username)!")
                Button("Logout") {
                    userData.isLoggedIn = false
                    userData.username = ""
                }
            } else {
                TextField("Username", text: $userData.username)
                    .padding()
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                
                Button("Login") {
                    userData.isLoggedIn = true
                }
                .disabled(userData.username.isEmpty)
            }
        }
        .padding()
    }
}

struct ContentView: View {
    @StateObject var userData = UserData()
    
    var body: some View {
        ProfileView(userData: userData)
    }
}
```

### @Environment

访问环境值：

```swift
struct AdaptiveView: View {
    @Environment(\.colorScheme) var colorScheme
    @Environment(\.horizontalSizeClass) var sizeClass
    
    var body: some View {
        VStack {
            Text("Current mode: \(colorScheme == .dark ? "Dark" : "Light")")
            
            Text("Size class: \(sizeClass == .compact ? "Compact" : "Regular")")
            
            if colorScheme == .dark {
                Text("Dark mode enabled")
                    .padding()
                    .background(Color.white)
                    .foregroundColor(.black)
            } else {
                Text("Light mode enabled")
                    .padding()
                    .background(Color.black)
                    .foregroundColor(.white)
            }
        }
        .padding()
    }
}
```

## 数据流

SwiftUI 提供多种数据流机制来管理应用状态。

### @StateObject

创建和管理 ObservableObject 实例的生命周期：

```swift
class TaskStore: ObservableObject {
    @Published var tasks: [String] = []
    
    func addTask(_ task: String) {
        tasks.append(task)
    }
}

struct TaskListView: View {
    @StateObject private var taskStore = TaskStore()
    @State private var newTask = ""
    
    var body: some View {
        VStack {
            HStack {
                TextField("New task", text: $newTask)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                
                Button(action: {
                    if !newTask.isEmpty {
                        taskStore.addTask(newTask)
                        newTask = ""
                    }
                }) {
                    Image(systemName: "plus.circle.fill")
                        .font(.title)
                }
            }
            .padding()
            
            List(taskStore.tasks, id: \.self) { task in
                Text(task)
            }
        }
    }
}
```

### EnvironmentObject

跨多个视图共享数据：

```swift
class AppSettings: ObservableObject {
    @Published var isDarkMode = false
    @Published var fontSize: CGFloat = 14
}

struct SettingsView: View {
    @EnvironmentObject var settings: AppSettings
    
    var body: some View {
        Form {
            Toggle("Dark Mode", isOn: $settings.isDarkMode)
            
            Stepper("Font Size: \(Int(settings.fontSize))", value: $settings.fontSize, in: 10...30)
        }
        .navigationTitle("Settings")
    }
}

struct ContentView: View {
    @StateObject private var settings = AppSettings()
    
    var body: some View {
        NavigationView {
            List {
                NavigationLink("Settings") {
                    SettingsView()
                }
                
                NavigationLink("Content") {
                    Text("This is some sample text")
                        .font(.system(size: settings.fontSize))
                        .preferredColorScheme(settings.isDarkMode ? .dark : .light)
                }
            }
            .navigationTitle("App")
        }
        .environmentObject(settings)
    }
}
```

## 导航

SwiftUI 提供了多种导航和屏幕转换方式。

### NavigationView

```swift
struct ArticleListView: View {
    let articles = [
        "Swift 5.5 新特性",
        "SwiftUI 技巧与窍门",
        "Combine 框架入门"
    ]
    
    var body: some View {
        NavigationView {
            List(articles, id: \.self) { article in
                NavigationLink(destination: ArticleDetailView(title: article)) {
                    Text(article)
                }
            }
            .navigationTitle("Articles")
        }
    }
}

struct ArticleDetailView: View {
    let title: String
    
    var body: some View {
        VStack {
            Text(title)
                .font(.title)
                .padding()
            
            Text("这里是关于 \(title) 的详细内容...")
                .padding()
            
            Spacer()
        }
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.inline)
    }
}
```

### 表单与编辑屏幕

```swift
struct ProfileEditView: View {
    @State private var name = ""
    @State private var email = ""
    @State private var birthDate = Date()
    @State private var notificationsEnabled = false
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("个人信息")) {
                    TextField("姓名", text: $name)
                    TextField("邮箱", text: $email)
                        .keyboardType(.emailAddress)
                    DatePicker("出生日期", selection: $birthDate, displayedComponents: .date)
                }
                
                Section(header: Text("偏好设置")) {
                    Toggle("启用通知", isOn: $notificationsEnabled)
                }
                
                Section {
                    Button("保存") {
                        // 保存逻辑
                        presentationMode.wrappedValue.dismiss()
                    }
                }
            }
            .navigationTitle("编辑资料")
            .navigationBarItems(trailing: Button("取消") {
                presentationMode.wrappedValue.dismiss()
            })
        }
    }
}
```

### 模态展示

```swift
struct ContentView: View {
    @State private var showingModal = false
    
    var body: some View {
        Button("显示模态视图") {
            showingModal = true
        }
        .sheet(isPresented: $showingModal) {
            ModalView()
        }
    }
}

struct ModalView: View {
    @Environment(\.presentationMode) var presentationMode
    
    var body: some View {
        NavigationView {
            VStack {
                Text("这是一个模态视图")
                    .font(.title)
                    .padding()
                
                Button("关闭") {
                    presentationMode.wrappedValue.dismiss()
                }
                .padding()
            }
            .navigationTitle("模态")
            .navigationBarItems(trailing: Button("完成") {
                presentationMode.wrappedValue.dismiss()
            })
        }
    }
}
```

### TabView

```swift
struct MainTabView: View {
    @State private var selectedTab = 0
    
    var body: some View {
        TabView(selection: $selectedTab) {
            HomeView()
                .tabItem {
                    Label("主页", systemImage: "house")
                }
                .tag(0)
            
            SearchView()
                .tabItem {
                    Label("搜索", systemImage: "magnifyingglass")
                }
                .tag(1)
            
            ProfileView()
                .tabItem {
                    Label("我的", systemImage: "person")
                }
                .tag(2)
        }
    }
}

struct HomeView: View {
    var body: some View {
        Text("主页内容")
            .font(.largeTitle)
    }
}

struct SearchView: View {
    var body: some View {
        Text("搜索内容")
            .font(.largeTitle)
    }
}

struct ProfileView: View {
    var body: some View {
        Text("个人资料")
            .font(.largeTitle)
    }
}
```

## 列表与集合

### 基本列表

```swift
struct SimpleListView: View {
    let items = ["苹果", "香蕉", "橙子", "草莓", "葡萄"]
    
    var body: some View {
        List {
            ForEach(items, id: \.self) { item in
                Text(item)
            }
        }
    }
}
```

### 分组列表

```swift
struct GroupedListView: View {
    let fruits = ["苹果", "香蕉", "橙子"]
    let vegetables = ["胡萝卜", "菠菜", "土豆"]
    
    var body: some View {
        List {
            Section(header: Text("水果")) {
                ForEach(fruits, id: \.self) { fruit in
                    Text(fruit)
                }
            }
            
            Section(header: Text("蔬菜")) {
                ForEach(vegetables, id: \.self) { vegetable in
                    Text(vegetable)
                }
            }
        }
        .listStyle(GroupedListStyle())
    }
}
```

### 可编辑列表

```swift
struct EditableListView: View {
    @State private var tasks = ["学习 SwiftUI", "写代码", "测试应用", "发布应用"]
    
    var body: some View {
        NavigationView {
            List {
                ForEach(tasks, id: \.self) { task in
                    Text(task)
                }
                .onDelete(perform: deleteTasks)
                .onMove(perform: moveTasks)
            }
            .navigationTitle("任务清单")
            .navigationBarItems(
                leading: EditButton(),
                trailing: Button(action: {
                    tasks.append("新任务 \(tasks.count + 1)")
                }) {
                    Image(systemName: "plus")
                }
            )
        }
    }
    
    func deleteTasks(at offsets: IndexSet) {
        tasks.remove(atOffsets: offsets)
    }
    
    func moveTasks(from source: IndexSet, to destination: Int) {
        tasks.move(fromOffsets: source, toOffset: destination)
    }
}
```

### LazyVGrid 和 LazyHGrid

```swift
struct GridView: View {
    let colors: [Color] = [.red, .green, .blue, .yellow, .purple, .orange, .pink]
    
    var body: some View {
        ScrollView {
            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
                GridItem(.flexible())
            ], spacing: 20) {
                ForEach(0..<20) { index in
                    RoundedRectangle(cornerRadius: 10)
                        .fill(colors[index % colors.count])
                        .frame(height: 100)
                        .overlay(
                            Text("\(index)")
                                .foregroundColor(.white)
                                .font(.title)
                        )
                }
            }
            .padding()
        }
    }
}
```

## 用户输入

### 文本输入

```swift
struct TextInputView: View {
    @State private var name = ""
    @State private var email = ""
    @State private var password = ""
    @State private var comment = ""
    
    var body: some View {
        Form {
            Section(header: Text("个人信息")) {
                TextField("姓名", text: $name)
                    .autocapitalization(.words)
                
                TextField("邮箱", text: $email)
                    .keyboardType(.emailAddress)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                
                SecureField("密码", text: $password)
            }
            
            Section(header: Text("反馈")) {
                TextEditor(text: $comment)
                    .frame(height: 100)
            }
            
            Section {
                Button("提交") {
                    // 提交表单
                }
                .disabled(name.isEmpty || email.isEmpty || password.isEmpty)
            }
        }
    }
}
```

### 手势

```swift
struct GestureView: View {
    @State private var scale: CGFloat = 1.0
    @State private var rotation: Angle = .zero
    @State private var offset: CGSize = .zero
    
    var body: some View {
        VStack {
            Image(systemName: "star.fill")
                .font(.system(size: 100))
                .foregroundColor(.yellow)
                .scaleEffect(scale)
                .rotationEffect(rotation)
                .offset(offset)
                .gesture(
                    DragGesture()
                        .onChanged { value in
                            offset = value.translation
                        }
                        .onEnded { _ in
                            withAnimation {
                                offset = .zero
                            }
                        }
                )
                .gesture(
                    MagnificationGesture()
                        .onChanged { value in
                            scale = value
                        }
                        .onEnded { _ in
                            withAnimation {
                                scale = 1.0
                            }
                        }
                )
                .gesture(
                    RotationGesture()
                        .onChanged { value in
                            rotation = value
                        }
                        .onEnded { _ in
                            withAnimation {
                                rotation = .zero
                            }
                        }
                )
            
            Text("拖动、捏合和旋转手势")
                .padding()
        }
    }
}
```

### 弹出警告和操作表

```swift
struct AlertsAndActionSheetsView: View {
    @State private var showingAlert = false
    @State private var showingActionSheet = false
    
    var body: some View {
        VStack(spacing: 20) {
            Button("显示警告") {
                showingAlert = true
            }
            .alert(isPresented: $showingAlert) {
                Alert(
                    title: Text("警告"),
                    message: Text("这是一个警告消息"),
                    primaryButton: .destructive(Text("删除")) {
                        print("用户选择了删除")
                    },
                    secondaryButton: .cancel()
                )
            }
            
            Button("显示操作表") {
                showingActionSheet = true
            }
            .actionSheet(isPresented: $showingActionSheet) {
                ActionSheet(
                    title: Text("选择操作"),
                    message: Text("请选择以下操作之一"),
                    buttons: [
                        .default(Text("分享")) {
                            print("用户选择了分享")
                        },
                        .default(Text("编辑")) {
                            print("用户选择了编辑")
                        },
                        .destructive(Text("删除")) {
                            print("用户选择了删除")
                        },
                        .cancel()
                    ]
                )
            }
        }
    }
}
```

## 与 UIKit 集成

SwiftUI 可以与现有的 UIKit 代码无缝集成。

### 在 SwiftUI 中使用 UIKit 视图

```swift
import SwiftUI
import UIKit

// 将 UIKit 视图包装为 SwiftUI 视图
struct UIKitMapView: UIViewRepresentable {
    func makeUIView(context: Context) -> MKMapView {
        let mapView = MKMapView()
        mapView.showsUserLocation = true
        return mapView
    }
    
    func updateUIView(_ uiView: MKMapView, context: Context) {
        // 更新地图视图
    }
}

// 使用包装的 UIKit 视图
struct MapContainerView: View {
    var body: some View {
        VStack {
            Text("地图示例")
                .font(.title)
                .padding()
            
            UIKitMapView()
                .edgesIgnoringSafeArea(.bottom)
        }
    }
}
```

### 在 UIKit 中使用 SwiftUI 视图

```swift
import SwiftUI
import UIKit

// SwiftUI 视图
struct WelcomeView: View {
    var name: String
    var onButtonTap: () -> Void
    
    var body: some View {
        VStack {
            Text("欢迎, \(name)!")
                .font(.title)
                .padding()
            
            Button("继续") {
                onButtonTap()
            }
            .padding()
            .background(Color.blue)
            .foregroundColor(.white)
            .cornerRadius(10)
        }
    }
}

// UIKit 视图控制器中使用 SwiftUI
class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 创建 SwiftUI 视图
        let welcomeView = WelcomeView(name: "用户", onButtonTap: {
            print("按钮被点击")
        })
        
        // 将 SwiftUI 视图托管到 UIHostingController
        let hostingController = UIHostingController(rootView: welcomeView)
        
        // 添加为子视图控制器
        addChild(hostingController)
        view.addSubview(hostingController.view)
        hostingController.view.translatesAutoresizingMaskIntoConstraints = false
        
        // 设置约束
        NSLayoutConstraint.activate([
            hostingController.view.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            hostingController.view.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            hostingController.view.widthAnchor.constraint(equalTo: view.widthAnchor, multiplier: 0.8),
            hostingController.view.heightAnchor.constraint(equalToConstant: 200)
        ])
        
        hostingController.didMove(toParent: self)
    }
}
```

## 小结与最佳实践

### SwiftUI 开发技巧

1. **组件化设计** - 将 UI 拆分为小型、可重用的组件
2. **预览驱动开发** - 使用实时预览加速开发流程
3. **状态管理分层** - 根据作用域选择合适的状态管理工具
4. **一致性设计** - 创建和使用设计系统以保持 UI 一致性
5. **组合而非继承** - 通过组合视图创建复杂界面

### 常见陷阱

1. **过度嵌套** - 避免视图过度嵌套导致的性能问题
2. **状态管理混乱** - 避免在单个视图中使用过多状态变量
3. **未优化的列表渲染** - 大型列表应使用懒加载视图
4. **忽略生命周期** - 注意状态对象的生命周期管理

### 性能优化

1. 使用 `@State` 仅存储简单值，复杂对象使用 `@StateObject` 或 `@ObservedObject`
2. 使用 `LazyVStack` 和 `LazyHGrid` 处理大量数据
3. 避免频繁重建视图层次结构
4. 使用 `@ViewBuilder` 和条件渲染分离逻辑

## 下一步学习

完成这个基础教程后，您可以进一步学习：

1. [SwiftUI 进阶](swiftui-advanced.md) - 学习更复杂的 SwiftUI 技术
2. [Combine 框架](../async/combine.md) - 掌握响应式编程
3. [SwiftUI 与 UIKit 混合开发](uikit-swiftui.md) - 学习如何在现有项目中集成 SwiftUI

SwiftUI 是快速发展的技术，建议定期关注 Apple 开发者文档和 WWDC 会议以了解最新功能和最佳实践。 