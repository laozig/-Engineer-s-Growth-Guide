# SwiftUI 进阶

本文档将深入探讨 SwiftUI 的高级特性和技术，帮助开发者构建更复杂、更高效的用户界面。

## 目录

- [状态管理进阶](#状态管理进阶)
- [自定义视图与修饰符](#自定义视图与修饰符)
- [动画与过渡](#动画与过渡)
- [布局系统深入](#布局系统深入)
- [性能优化](#性能优化)
- [与 UIKit 集成](#与-uikit-集成)
- [复杂界面开发](#复杂界面开发)
- [测试与调试](#测试与调试)

## 状态管理进阶

SwiftUI 提供了多种状态管理工具，适用于不同的场景和复杂度。

### 属性包装器深入理解

```swift
// @State - 用于简单的视图本地状态
struct CounterView: View {
    @State private var count = 0
    
    var body: some View {
        VStack {
            Text("Count: \(count)")
            Button("Increment") {
                count += 1
            }
        }
    }
}

// @Binding - 允许子视图修改父视图的状态
struct ToggleButton: View {
    @Binding var isOn: Bool
    
    var body: some View {
        Button(action: {
            isOn.toggle()
        }) {
            Text(isOn ? "On" : "Off")
        }
    }
}

// @ObservedObject - 用于从外部注入可观察对象
class UserSettings: ObservableObject {
    @Published var username = ""
    @Published var isLoggedIn = false
}

struct ProfileView: View {
    @ObservedObject var settings: UserSettings
    
    var body: some View {
        VStack {
            TextField("Username", text: $settings.username)
            Text("Current user: \(settings.username)")
        }
    }
}

// @StateObject - 类似于 @ObservedObject，但由视图拥有生命周期
struct MainView: View {
    @StateObject private var settings = UserSettings()
    
    var body: some View {
        ProfileView(settings: settings)
    }
}

// @EnvironmentObject - 用于在视图层次结构中共享数据
struct ContentView: View {
    @EnvironmentObject var settings: UserSettings
    
    var body: some View {
        if settings.isLoggedIn {
            Text("Welcome, \(settings.username)!")
        } else {
            Text("Please log in")
        }
    }
}

// @Environment - 访问环境值
struct AdaptiveView: View {
    @Environment(\.colorScheme) var colorScheme
    
    var body: some View {
        Text("Current mode: \(colorScheme == .dark ? "Dark" : "Light")")
            .foregroundColor(colorScheme == .dark ? .white : .black)
    }
}
```

### 属性包装器的选择策略

选择正确的属性包装器对于应用性能和架构至关重要：

1. **@State**
   - 使用场景：简单的视图内部状态
   - 生命周期：由 SwiftUI 管理，与视图生命周期绑定
   - 最佳实践：使用 `private` 修饰，避免外部访问

2. **@Binding**
   - 使用场景：子视图需要修改父视图状态
   - 生命周期：引用父视图状态，无独立存储
   - 最佳实践：通过参数传递，而非全局访问

3. **@StateObject vs @ObservedObject**
   - @StateObject：由当前视图拥有和初始化对象
   - @ObservedObject：对象由外部创建并传入
   - 关键区别：@StateObject 在视图重建时保持状态，@ObservedObject 不保证

4. **@EnvironmentObject**
   - 使用场景：需要在视图树的多个层级共享状态
   - 注入方式：`.environmentObject(someObject)`
   - 最佳实践：适用于应用级别状态（如用户会话、主题设置）

### 高级状态管理模式

#### 组合多个 ObservableObject

处理复杂应用时，可以组合多个 ObservableObject：

```swift
// 用户相关状态
class UserStore: ObservableObject {
    @Published var currentUser: User?
    @Published var isLoggedIn = false
    
    func login(username: String, password: String) async throws {
        // 登录逻辑
        currentUser = try await authService.login(username: username, password: password)
        isLoggedIn = currentUser != nil
    }
    
    func logout() {
        currentUser = nil
        isLoggedIn = false
    }
}

// 应用设置状态
class AppSettings: ObservableObject {
    @Published var darkModeEnabled = false
    @Published var notificationsEnabled = true
    @Published var fontScale: CGFloat = 1.0
}

// 应用状态容器
class AppState: ObservableObject {
    @Published var userStore: UserStore
    @Published var settings: AppSettings
    
    init(userStore: UserStore = UserStore(), settings: AppSettings = AppSettings()) {
        self.userStore = userStore
        self.settings = settings
    }
}

// 在应用根视图中注入
@main
struct MyApp: App {
    @StateObject private var appState = AppState()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .environmentObject(appState.userStore)
                .environmentObject(appState.settings)
        }
    }
}
```

#### 状态恢复与持久化

实现应用状态的持久化和恢复：

```swift
class PersistentAppSettings: ObservableObject {
    @Published var darkModeEnabled: Bool {
        didSet {
            UserDefaults.standard.set(darkModeEnabled, forKey: "darkModeEnabled")
        }
    }
    
    @Published var fontScale: CGFloat {
        didSet {
            UserDefaults.standard.set(fontScale, forKey: "fontScale")
        }
    }
    
    init() {
        self.darkModeEnabled = UserDefaults.standard.bool(forKey: "darkModeEnabled")
        self.fontScale = UserDefaults.standard.double(forKey: "fontScale") == 0 ? 1.0 : UserDefaults.standard.double(forKey: "fontScale")
    }
}
```

#### 使用 @AppStorage 简化持久化

```swift
struct SettingsView: View {
    // 直接绑定到 UserDefaults
    @AppStorage("darkModeEnabled") private var darkModeEnabled = false
    @AppStorage("fontScale") private var fontScale = 1.0
    
    var body: some View {
        Form {
            Toggle("Dark Mode", isOn: $darkModeEnabled)
            
            Slider(value: $fontScale, in: 0.8...1.4, step: 0.1) {
                Text("Font Scale: \(fontScale, specifier: "%.1f")")
            }
        }
    }
}
```

### 状态与副作用

#### 使用 onChange 监听状态变化

```swift
struct SearchView: View {
    @State private var searchQuery = ""
    @State private var searchResults: [Result] = []
    
    var body: some View {
        VStack {
            TextField("Search", text: $searchQuery)
                .onChange(of: searchQuery) { newValue in
                    // 当查询改变时执行搜索
                    if !newValue.isEmpty && newValue.count > 2 {
                        performSearch(query: newValue)
                    } else {
                        searchResults = []
                    }
                }
            
            List(searchResults) { result in
                ResultRow(result: result)
            }
        }
    }
    
    private func performSearch(query: String) {
        // 执行搜索逻辑
    }
}
```

#### 使用 task 修饰符处理异步操作

```swift
struct ProductView: View {
    let productId: String
    @State private var product: Product?
    @State private var isLoading = false
    @State private var error: Error?
    
    var body: some View {
        VStack {
            if isLoading {
                ProgressView()
            } else if let product = product {
                ProductDetailView(product: product)
            } else if let error = error {
                ErrorView(error: error)
            }
        }
        .task {
            // 视图出现时自动加载数据
            do {
                isLoading = true
                product = try await ProductService.fetchProduct(id: productId)
                isLoading = false
            } catch {
                self.error = error
                isLoading = false
            }
        }
    }
}
```

### 依赖注入模式

通过环境或构造器实现依赖注入：

```swift
// 服务协议
protocol UserService {
    func fetchUser(id: String) async throws -> User
    func updateUser(_ user: User) async throws
}

// 服务实现
class APIUserService: UserService {
    func fetchUser(id: String) async throws -> User {
        // 实际实现...
    }
    
    func updateUser(_ user: User) async throws {
        // 实际实现...
    }
}

// 通过环境注入
struct UserEnvironmentKey: EnvironmentKey {
    static var defaultValue: UserService = APIUserService()
}

extension EnvironmentValues {
    var userService: UserService {
        get { self[UserEnvironmentKey.self] }
        set { self[UserEnvironmentKey.self] = newValue }
    }
}

// 在视图中使用
struct UserProfileView: View {
    let userId: String
    @Environment(\.userService) private var userService
    @State private var user: User?
    
    var body: some View {
        VStack {
            // 视图内容
        }
        .task {
            user = try? await userService.fetchUser(id: userId)
        }
    }
}

// 注入模拟服务进行测试
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        UserProfileView(userId: "test-id")
            .environment(\.userService, MockUserService())
    }
}
``` 

## 动画与过渡

SwiftUI 提供了强大而简洁的动画系统，使界面交互更加生动流畅。

### 基础动画技术

```swift
struct AnimationBasicsView: View {
    @State private var scale: CGFloat = 1.0
    @State private var rotation: Double = 0
    @State private var opacity: Double = 1.0
    
    var body: some View {
        VStack(spacing: 30) {
            RoundedRectangle(cornerRadius: 20)
                .fill(Color.blue)
                .frame(width: 100, height: 100)
                .scaleEffect(scale)
                .rotationEffect(.degrees(rotation))
                .opacity(opacity)
            
            HStack(spacing: 20) {
                // 隐式动画
                Button("隐式动画") {
                    scale = scale == 1.0 ? 1.5 : 1.0
                    rotation = rotation == 0 ? 45 : 0
                    opacity = opacity == 1.0 ? 0.5 : 1.0
                }
                .buttonStyle(.bordered)
                
                // 显式动画
                Button("显式动画") {
                    withAnimation(.spring(response: 0.5, dampingFraction: 0.5)) {
                        scale = scale == 1.0 ? 1.5 : 1.0
                        rotation = rotation == 0 ? 45 : 0
                    }
                    
                    // 延迟动画
                    withAnimation(.easeInOut.delay(0.3)) {
                        opacity = opacity == 1.0 ? 0.5 : 1.0
                    }
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        // 为整个视图添加隐式动画
        .animation(.easeInOut, value: scale)
    }
}
```

### 高级过渡效果

```swift
struct AdvancedTransitionsView: View {
    @State private var showDetail = false
    
    var body: some View {
        VStack {
            Button("切换视图") {
                withAnimation {
                    showDetail.toggle()
                }
            }
            .padding()
            
            if showDetail {
                DetailTransitionView()
                    .transition(.asymmetric(
                        insertion: .scale.combined(with: .opacity),
                        removal: .slide.combined(with: .opacity)
                    ))
            } else {
                SummaryTransitionView()
                    .transition(.asymmetric(
                        insertion: .slide.combined(with: .opacity),
                        removal: .scale.combined(with: .opacity)
                    ))
            }
        }
    }
}

struct DetailTransitionView: View {
    var body: some View {
        VStack {
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 60))
            
            Text("详细信息视图")
                .font(.title)
                .padding()
            
            Text("这是一个展示高级转场效果的详细视图示例。包含更多信息和互动元素。")
                .multilineTextAlignment(.center)
                .padding()
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color.blue.opacity(0.1))
        .cornerRadius(20)
        .padding()
    }
}

struct SummaryTransitionView: View {
    var body: some View {
        HStack {
            Image(systemName: "doc.text")
                .font(.system(size: 30))
            
            Text("摘要视图")
                .font(.headline)
        }
        .frame(maxWidth: .infinity)
        .padding()
        .background(Color.green.opacity(0.1))
        .cornerRadius(10)
        .padding()
    }
}
```

### 自定义转场动画

```swift
struct CustomTransition: ViewModifier {
    let active: Bool
    let anchor: UnitPoint
    
    func body(content: Content) -> some View {
        content
            .rotation3DEffect(
                .degrees(active ? 0 : 180),
                axis: (x: 0.0, y: 1.0, z: 0.0),
                anchor: anchor,
                perspective: 0.3
            )
    }
}

extension AnyTransition {
    static func flip(anchor: UnitPoint = .center) -> AnyTransition {
        .modifier(
            active: CustomTransition(active: true, anchor: anchor),
            identity: CustomTransition(active: false, anchor: anchor)
        )
    }
    
    static var cardFlip: AnyTransition {
        .asymmetric(
            insertion: .opacity.combined(with: .flip(anchor: .leading)),
            removal: .opacity.combined(with: .flip(anchor: .trailing))
        )
    }
}

struct FlipCardView: View {
    @State private var isShowingFront = true
    
    var body: some View {
        VStack {
            Button("翻转卡片") {
                withAnimation(.easeInOut(duration: 0.7)) {
                    isShowingFront.toggle()
                }
            }
            .padding()
            
            ZStack {
                if isShowingFront {
                    CardFront()
                        .transition(.cardFlip)
                } else {
                    CardBack()
                        .transition(.cardFlip)
                }
            }
            .frame(width: 300, height: 200)
            .padding()
        }
    }
}

struct CardFront: View {
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 20)
                .fill(Color.blue)
                .shadow(radius: 10)
            
            VStack {
                Text("卡片正面")
                    .font(.title)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                
                Image(systemName: "creditcard.fill")
                    .font(.system(size: 50))
                    .foregroundColor(.white.opacity(0.8))
            }
        }
    }
}

struct CardBack: View {
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 20)
                .fill(Color.green)
                .shadow(radius: 10)
            
            VStack {
                Text("卡片背面")
                    .font(.title)
                    .fontWeight(.bold)
                    .foregroundColor(.white)
                
                Text("1234 5678 9012 3456")
                    .font(.body)
                    .foregroundColor(.white.opacity(0.8))
                    .padding(.top)
            }
        }
    }
}
```

### 手势驱动动画

```swift
struct GestureAnimationView: View {
    @State private var offset: CGSize = .zero
    @State private var scale: CGFloat = 1.0
    @State private var rotation: Angle = .zero
    @GestureState private var dragState = false
    
    var body: some View {
        VStack {
            Text("拖动、缩放和旋转图片")
                .font(.headline)
                .padding()
            
            Image(systemName: "photo")
                .font(.system(size: 100))
                .frame(width: 200, height: 200)
                .background(Color.blue.opacity(0.1))
                .cornerRadius(20)
                .scaleEffect(scale)
                .rotationEffect(rotation)
                .offset(offset)
                .gesture(
                    DragGesture()
                        .updating($dragState) { _, state, _ in
                            state = true
                        }
                        .onChanged { value in
                            self.offset = value.translation
                        }
                        .onEnded { value in
                            withAnimation(.spring()) {
                                self.offset = .zero
                            }
                        }
                )
                .gesture(
                    MagnificationGesture()
                        .onChanged { value in
                            self.scale = value
                        }
                        .onEnded { _ in
                            withAnimation(.spring()) {
                                self.scale = 1.0
                            }
                        }
                )
                .gesture(
                    RotationGesture()
                        .onChanged { value in
                            self.rotation = value
                        }
                        .onEnded { _ in
                            withAnimation(.spring()) {
                                self.rotation = .zero
                            }
                        }
                )
                .shadow(radius: dragState ? 10 : 0)
                .animation(.easeInOut, value: dragState)
        }
    }
}
```

### 动画状态机

```swift
enum LoadingState {
    case idle, loading, success, failure
}

struct AnimatedLoadingButton: View {
    @State private var state: LoadingState = .idle
    @State private var isAnimating = false
    
    var body: some View {
        VStack {
            Button {
                withAnimation {
                    state = .loading
                }
                
                // 模拟网络请求
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    withAnimation {
                        state = Bool.random() ? .success : .failure
                    }
                    
                    // 重置状态
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        withAnimation {
                            state = .idle
                        }
                    }
                }
            } label: {
                HStack {
                    switch state {
                    case .idle:
                        Text("登录")
                    case .loading:
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    case .success:
                        Image(systemName: "checkmark")
                            .font(.headline)
                    case .failure:
                        Image(systemName: "xmark")
                            .font(.headline)
                    }
                }
                .foregroundColor(.white)
                .frame(width: 100, height: 44)
                .background(
                    RoundedRectangle(cornerRadius: 10)
                        .fill(backgroundColor)
                )
            }
            .disabled(state != .idle)
            
            Text("当前状态: \(stateDescription)")
                .font(.caption)
                .padding(.top)
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 1.5).repeatForever()) {
                isAnimating = true
            }
        }
    }
    
    private var backgroundColor: Color {
        switch state {
        case .idle:
            return .blue
        case .loading:
            return .orange
        case .success:
            return .green
        case .failure:
            return .red
        }
    }
    
    private var stateDescription: String {
        switch state {
        case .idle:
            return "等待操作"
        case .loading:
            return "加载中..."
        case .success:
            return "操作成功！"
        case .failure:
            return "操作失败！"
        }
    }
}
```

## 性能优化

SwiftUI 虽然简化了 UI 开发，但在构建复杂应用时仍需注意性能优化。

### 视图渲染优化

```swift
// 使用 @State 和 Equatable 优化渲染
struct OptimizedCounterView: View {
    @State private var count = 0
    
    var body: some View {
        VStack {
            Text("计数: \(count)")
                .font(.largeTitle)
            
            CounterControlsView(count: $count)
            
            // 提取为独立视图，防止父视图重绘
            ExpensiveView()
        }
    }
}

// 独立视图组件，只在自身状态变化时更新
struct CounterControlsView: View {
    @Binding var count: Int
    
    var body: some View {
        HStack {
            Button("-") { count -= 1 }
                .buttonStyle(.bordered)
            
            Button("+") { count += 1 }
                .buttonStyle(.bordered)
        }
        .padding()
    }
}

// 使用 equatable 优化渲染
struct ExpensiveView: View, Equatable {
    var body: some View {
        VStack {
            Text("重量级视图")
                .font(.headline)
            
            // 假设这里有复杂的渲染逻辑
            ComplexVisualization()
        }
        .padding()
        .background(Color.gray.opacity(0.1))
        .cornerRadius(10)
        .padding()
        .onAppear {
            print("ExpensiveView appeared")
        }
    }
    
    // 实现 Equatable，明确告诉 SwiftUI 何时需要重新渲染
    static func == (lhs: ExpensiveView, rhs: ExpensiveView) -> Bool {
        return true // 该视图永远不需要更新，因为它没有依赖外部状态
    }
}

struct ComplexVisualization: View {
    var body: some View {
        // 模拟复杂可视化
        ZStack {
            ForEach(0..<20) { i in
                Circle()
                    .stroke(Color.blue.opacity(Double(i) / 40), lineWidth: 2)
                    .frame(width: CGFloat(i * 10), height: CGFloat(i * 10))
            }
        }
        .frame(height: 200)
    }
}
```

### 懒加载与内存管理

```swift
struct LazyLoadingDemo: View {
    var body: some View {
        // 使用 LazyVStack 替代 VStack
        ScrollView {
            LazyVStack {
                ForEach(1...1000, id: \.self) { index in
                    LazyRowItem(index: index)
                }
            }
            .padding()
        }
    }
}

struct LazyRowItem: View {
    let index: Int
    
    var body: some View {
        HStack {
            Text("Row \(index)")
                .frame(maxWidth: .infinity, alignment: .leading)
            
            // 仅在视图可见时加载图像
            AsyncImage(url: URL(string: "https://picsum.photos/id/\(index % 100)/200")) { phase in
                switch phase {
                case .empty:
                    ProgressView()
                case .success(let image):
                    image
                        .resizable()
                        .scaledToFill()
                case .failure:
                    Image(systemName: "photo")
                        .foregroundColor(.gray)
                @unknown default:
                    EmptyView()
                }
            }
            .frame(width: 50, height: 50)
            .cornerRadius(8)
        }
        .padding()
        .background(Color.gray.opacity(0.1))
        .cornerRadius(10)
        .padding(.vertical, 4)
        .onAppear {
            print("Row \(index) appeared")
        }
        .onDisappear {
            print("Row \(index) disappeared")
        }
    }
}
```

### 列表性能优化

```swift
struct OptimizedListView: View {
    @StateObject private var viewModel = ListViewModel()
    
    var body: some View {
        List {
            ForEach(viewModel.sections.indices, id: \.self) { sectionIndex in
                Section {
                    ForEach(viewModel.sections[sectionIndex].items) { item in
                        OptimizedRow(item: item)
                            .onAppear {
                                viewModel.itemAppeared(item)
                            }
                    }
                } header: {
                    Text(viewModel.sections[sectionIndex].title)
                        .font(.headline)
                }
            }
        }
        .listStyle(.insetGrouped)
    }
}

struct OptimizedRow: View, Equatable {
    let item: ListItem
    
    var body: some View {
        HStack {
            Text(item.title)
                .font(.body)
            
            Spacer()
            
            if item.isHighlighted {
                Image(systemName: "star.fill")
                    .foregroundColor(.yellow)
            }
        }
        .contentShape(Rectangle())
    }
    
    // 只有当相关属性变化时才重绘
    static func == (lhs: OptimizedRow, rhs: OptimizedRow) -> Bool {
        return lhs.item.id == rhs.item.id &&
               lhs.item.title == rhs.item.title &&
               lhs.item.isHighlighted == rhs.item.isHighlighted
    }
}

struct ListItem: Identifiable, Equatable {
    let id: UUID
    var title: String
    var isHighlighted: Bool
    
    init(id: UUID = UUID(), title: String, isHighlighted: Bool = false) {
        self.id = id
        self.title = title
        self.isHighlighted = isHighlighted
    }
}

struct ListSection: Identifiable {
    let id: UUID
    var title: String
    var items: [ListItem]
    
    init(id: UUID = UUID(), title: String, items: [ListItem]) {
        self.id = id
        self.title = title
        self.items = items
    }
}

class ListViewModel: ObservableObject {
    @Published var sections: [ListSection] = []
    
    init() {
        // 生成示例数据
        generateSections()
    }
    
    private func generateSections() {
        let section1Items = (1...20).map { ListItem(title: "项目 \($0)") }
        let section2Items = (21...40).map { ListItem(title: "项目 \($0)") }
        let section3Items = (41...60).map { ListItem(title: "项目 \($0)") }
        
        sections = [
            ListSection(title: "第一组", items: section1Items),
            ListSection(title: "第二组", items: section2Items),
            ListSection(title: "第三组", items: section3Items)
        ]
    }
    
    func itemAppeared(_ item: ListItem) {
        // 可以在这里执行预加载逻辑
        print("Item appeared: \(item.title)")
    }
}
```

### 异步操作与计算

```swift
struct PerformanceOptimizedView: View {
    @StateObject private var viewModel = PerformanceViewModel()
    
    var body: some View {
        VStack {
            Text("计算状态: \(viewModel.computationStatus)")
                .font(.headline)
                .padding()
            
            if viewModel.isComputing {
                ProgressView()
                    .padding()
            }
            
            Button(viewModel.isComputing ? "取消" : "开始复杂计算") {
                if viewModel.isComputing {
                    viewModel.cancelComputation()
                } else {
                    Task {
                        await viewModel.performComplexComputation()
                    }
                }
            }
            .padding()
            
            if let result = viewModel.computationResult {
                Text("计算结果: \(result)")
                    .padding()
            }
            
            List(viewModel.computationHistory, id: \.self) { entry in
                Text(entry)
            }
            .frame(height: 200)
        }
        .padding()
    }
}

class PerformanceViewModel: ObservableObject {
    @Published var isComputing = false
    @Published var computationResult: String?
    @Published var computationStatus = "空闲"
    @Published var computationHistory: [String] = []
    
    private var computationTask: Task<Void, Never>?
    
    func performComplexComputation() async {
        await MainActor.run {
            isComputing = true
            computationStatus = "计算中..."
            computationResult = nil
        }
        
        computationTask = Task {
            // 模拟一个复杂的、可能阻塞UI的计算
            var result = 0
            
            for i in 1...10 {
                if Task.isCancelled {
                    await MainActor.run {
                        computationStatus = "已取消"
                        isComputing = false
                        computationHistory.append("计算已取消")
                    }
                    return
                }
                
                // 模拟耗时操作
                try? await Task.sleep(nanoseconds: 500_000_000) // 0.5秒
                
                result += i
                
                // 更新UI
                await MainActor.run {
                    computationStatus = "计算中...(\(i*10)%)"
                }
            }
            
            // 完成后更新UI
            if !Task.isCancelled {
                await MainActor.run {
                    computationResult = "\(result)"
                    computationStatus = "完成"
                    isComputing = false
                    computationHistory.append("计算完成: \(result)")
                }
            }
        }
    }
    
    func cancelComputation() {
        computationTask?.cancel()
        computationTask = nil
    }
}
```

### 图像优化

```swift
struct ImageOptimizationView: View {
    @State private var optimizedImage: UIImage?
    @State private var isLoading = false
    @State private var optimizationLevel = 0.5
    
    var body: some View {
        VStack {
            if let image = optimizedImage {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(height: 300)
                    .cornerRadius(12)
            } else if isLoading {
                ProgressView()
                    .frame(height: 300)
            } else {
                Image(systemName: "photo")
                    .font(.system(size: 100))
                    .foregroundColor(.gray)
                    .frame(height: 300)
            }
            
            Slider(value: $optimizationLevel, in: 0.1...1.0, step: 0.1) {
                Text("压缩质量: \(Int(optimizationLevel * 100))%")
            }
            .padding()
            
            HStack {
                Button("加载原始图像") {
                    loadOriginalImage()
                }
                .buttonStyle(.bordered)
                
                Button("优化图像") {
                    optimizeImage()
                }
                .buttonStyle(.bordered)
                .disabled(optimizedImage == nil)
            }
            .padding()
            
            if let image = optimizedImage {
                Text("图像尺寸: \(Int(image.size.width)) x \(Int(image.size.height))")
                
                if let imageData = image.jpegData(compressionQuality: 1.0) {
                    Text("内存占用: \(formatBytes(imageData.count))")
                }
            }
        }
        .padding()
    }
    
    private func loadOriginalImage() {
        isLoading = true
        
        // 模拟加载大图像
        DispatchQueue.global().async {
            // 在实际应用中，这里会加载实际图像
            // 这里创建一个示例图像
            let size = CGSize(width: 3000, height: 2000)
            UIGraphicsBeginImageContextWithOptions(size, false, 1.0)
            UIColor.blue.withAlphaComponent(0.3).setFill()
            UIRectFill(CGRect(origin: .zero, size: size))
            
            // 绘制一些内容使图像看起来更真实
            for i in 0..<20 {
                let rect = CGRect(x: CGFloat.random(in: 0..<size.width),
                                 y: CGFloat.random(in: 0..<size.height),
                                 width: CGFloat.random(in: 100..<500),
                                 height: CGFloat.random(in: 100..<500))
                
                UIColor.random.setFill()
                UIBezierPath(roundedRect: rect, cornerRadius: 20).fill()
            }
            
            let image = UIGraphicsGetImageFromCurrentImageContext()
            UIGraphicsEndImageContext()
            
            DispatchQueue.main.async {
                self.optimizedImage = image
                self.isLoading = false
            }
        }
    }
    
    private func optimizeImage() {
        guard let originalImage = optimizedImage else { return }
        
        isLoading = true
        
        DispatchQueue.global().async {
            // 调整图像尺寸（在实际应用中可能基于需求动态计算）
            let targetSize = CGSize(width: 1200, height: 800)
            
            UIGraphicsBeginImageContextWithOptions(targetSize, false, 0.0)
            originalImage.draw(in: CGRect(origin: .zero, size: targetSize))
            let resizedImage = UIGraphicsGetImageFromCurrentImageContext()
            UIGraphicsEndImageContext()
            
            // 压缩质量
            let compressedImageData = resizedImage?.jpegData(compressionQuality: CGFloat(optimizationLevel))
            let finalImage = compressedImageData.flatMap { UIImage(data: $0) }
            
            DispatchQueue.main.async {
                self.optimizedImage = finalImage
                self.isLoading = false
            }
        }
    }
    
    private func formatBytes(_ bytes: Int) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

extension UIColor {
    static var random: UIColor {
        return UIColor(
            red: .random(in: 0...1),
            green: .random(in: 0...1),
            blue: .random(in: 0...1),
            alpha: 1.0
        )
    }
}
``` 

## 与 UIKit 集成

SwiftUI 与 UIKit 可以很好地协同工作，便于渐进式迁移或结合两者的优势。

### 在 SwiftUI 中使用 UIKit 组件

```swift
// 将 UIKit 视图包装到 SwiftUI 中
struct UIKitMapView: UIViewRepresentable {
    var coordinate: CLLocationCoordinate2D
    var annotationTitle: String
    
    func makeUIView(context: Context) -> MKMapView {
        let mapView = MKMapView()
        mapView.delegate = context.coordinator
        return mapView
    }
    
    func updateUIView(_ mapView: MKMapView, context: Context) {
        // 更新视图
        let annotation = MKPointAnnotation()
        annotation.coordinate = coordinate
        annotation.title = annotationTitle
        
        mapView.removeAnnotations(mapView.annotations)
        mapView.addAnnotation(annotation)
        
        let region = MKCoordinateRegion(
            center: coordinate,
            span: MKCoordinateSpan(latitudeDelta: 0.01, longitudeDelta: 0.01)
        )
        mapView.setRegion(region, animated: true)
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, MKMapViewDelegate {
        var parent: UIKitMapView
        
        init(_ parent: UIKitMapView) {
            self.parent = parent
        }
        
        func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
            let identifier = "mapPin"
            var annotationView = mapView.dequeueReusableAnnotationView(withIdentifier: identifier) as? MKMarkerAnnotationView
            
            if annotationView == nil {
                annotationView = MKMarkerAnnotationView(annotation: annotation, reuseIdentifier: identifier)
                annotationView?.canShowCallout = true
            } else {
                annotationView?.annotation = annotation
            }
            
            return annotationView
        }
    }
}

// 使用方式
struct LocationDetailView: View {
    let coordinate: CLLocationCoordinate2D
    let locationName: String
    
    var body: some View {
        VStack {
            UIKitMapView(coordinate: coordinate, annotationTitle: locationName)
                .frame(height: 300)
            
            Text(locationName)
                .font(.title)
                .padding()
        }
    }
}
```

### 使用 UIKit 控制器

```swift
// 包装 UIViewController
struct ImagePickerView: UIViewControllerRepresentable {
    @Binding var selectedImage: UIImage?
    @Environment(\.presentationMode) private var presentationMode
    
    func makeUIViewController(context: Context) -> UIImagePickerController {
        let picker = UIImagePickerController()
        picker.delegate = context.coordinator
        picker.allowsEditing = true
        return picker
    }
    
    func updateUIViewController(_ uiViewController: UIImagePickerController, context: Context) {
        // 更新不需要操作
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, UINavigationControllerDelegate, UIImagePickerControllerDelegate {
        let parent: ImagePickerView
        
        init(_ parent: ImagePickerView) {
            self.parent = parent
        }
        
        func imagePickerController(_ picker: UIImagePickerController, didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey : Any]) {
            if let editedImage = info[.editedImage] as? UIImage {
                parent.selectedImage = editedImage
            } else if let originalImage = info[.originalImage] as? UIImage {
                parent.selectedImage = originalImage
            }
            
            parent.presentationMode.wrappedValue.dismiss()
        }
        
        func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
            parent.presentationMode.wrappedValue.dismiss()
        }
    }
}

// 使用方式
struct ProfileImagePicker: View {
    @State private var selectedImage: UIImage?
    @State private var showingImagePicker = false
    
    var body: some View {
        VStack {
            if let image = selectedImage {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .frame(width: 150, height: 150)
                    .clipShape(Circle())
            } else {
                Image(systemName: "person.circle.fill")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 150, height: 150)
                    .foregroundColor(.gray)
            }
            
            Button("选择照片") {
                showingImagePicker = true
            }
            .padding()
        }
        .sheet(isPresented: $showingImagePicker) {
            ImagePickerView(selectedImage: $selectedImage)
        }
    }
}
```

### 自定义 UIKit 行为

```swift
// 使用协调器处理 UIKit 回调
struct CustomTextFieldView: UIViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var keyboardType: UIKeyboardType
    
    func makeUIView(context: Context) -> UITextField {
        let textField = UITextField()
        textField.delegate = context.coordinator
        textField.placeholder = placeholder
        textField.keyboardType = keyboardType
        textField.returnKeyType = .done
        textField.borderStyle = .roundedRect
        textField.autocorrectionType = .no
        
        // 创建工具栏
        let toolbar = UIToolbar()
        toolbar.sizeToFit()
        let flexSpace = UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil)
        let doneButton = UIBarButtonItem(barButtonSystemItem: .done, target: context.coordinator, action: #selector(Coordinator.doneButtonTapped))
        
        toolbar.items = [flexSpace, doneButton]
        textField.inputAccessoryView = toolbar
        
        return textField
    }
    
    func updateUIView(_ textField: UITextField, context: Context) {
        textField.text = text
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, UITextFieldDelegate {
        var parent: CustomTextFieldView
        
        init(_ parent: CustomTextFieldView) {
            self.parent = parent
        }
        
        func textFieldDidChangeSelection(_ textField: UITextField) {
            parent.text = textField.text ?? ""
        }
        
        func textFieldShouldReturn(_ textField: UITextField) -> Bool {
            textField.resignFirstResponder()
            return true
        }
        
        @objc func doneButtonTapped() {
            UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
        }
    }
}

// 使用示例
struct EnhancedFormView: View {
    @State private var phoneNumber = ""
    @State private var email = ""
    
    var body: some View {
        Form {
            Section(header: Text("联系方式")) {
                CustomTextFieldView(
                    text: $phoneNumber,
                    placeholder: "手机号码",
                    keyboardType: .phonePad
                )
                .frame(height: 44)
                
                CustomTextFieldView(
                    text: $email,
                    placeholder: "电子邮箱",
                    keyboardType: .emailAddress
                )
                .frame(height: 44)
            }
            
            Section {
                Button("提交") {
                    print("电话: \(phoneNumber), 邮箱: \(email)")
                }
                .frame(maxWidth: .infinity)
            }
        }
    }
}
```

### 在 UIKit 中嵌入 SwiftUI

```swift
// 将 SwiftUI 视图嵌入到 UIKit 应用中
class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 创建 SwiftUI 视图
        let swiftUIView = UIHostingController(rootView: 
            FeatureView(title: "SwiftUI 功能")
                .environment(\.colorScheme, .light)
        )
        
        // 添加为子控制器
        addChild(swiftUIView)
        
        // 添加 SwiftUI 视图到视图层次结构
        swiftUIView.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(swiftUIView.view)
        
        // 设置约束
        NSLayoutConstraint.activate([
            swiftUIView.view.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            swiftUIView.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            swiftUIView.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            swiftUIView.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        
        swiftUIView.didMove(toParent: self)
    }
}

// SwiftUI 视图
struct FeatureView: View {
    let title: String
    @State private var counter = 0
    
    var body: some View {
        VStack(spacing: 20) {
            Text(title)
                .font(.largeTitle)
                .fontWeight(.bold)
            
            Text("计数器: \(counter)")
                .font(.title)
            
            Button("增加") {
                counter += 1
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

## 测试与调试

高效的测试和调试是保证 SwiftUI 应用质量的关键。

### 单元测试 SwiftUI 视图模型

```swift
// 可测试的视图模型
class CounterViewModel: ObservableObject {
    @Published var count: Int = 0
    @Published var isEven: Bool = true
    
    func increment() {
        count += 1
        updateEvenStatus()
    }
    
    func decrement() {
        if count > 0 {
            count -= 1
            updateEvenStatus()
        }
    }
    
    func reset() {
        count = 0
        updateEvenStatus()
    }
    
    private func updateEvenStatus() {
        isEven = count % 2 == 0
    }
}

// 单元测试
import XCTest
@testable import MyApp

class CounterViewModelTests: XCTestCase {
    var viewModel: CounterViewModel!
    
    override func setUp() {
        super.setUp()
        viewModel = CounterViewModel()
    }
    
    override func tearDown() {
        viewModel = nil
        super.tearDown()
    }
    
    func testInitialState() {
        XCTAssertEqual(viewModel.count, 0)
        XCTAssertTrue(viewModel.isEven)
    }
    
    func testIncrement() {
        viewModel.increment()
        XCTAssertEqual(viewModel.count, 1)
        XCTAssertFalse(viewModel.isEven)
        
        viewModel.increment()
        XCTAssertEqual(viewModel.count, 2)
        XCTAssertTrue(viewModel.isEven)
    }
    
    func testDecrement() {
        // 初始值为0时减少
        viewModel.decrement()
        XCTAssertEqual(viewModel.count, 0)
        XCTAssertTrue(viewModel.isEven)
        
        // 先增加再减少
        viewModel.increment()
        viewModel.increment()
        XCTAssertEqual(viewModel.count, 2)
        
        viewModel.decrement()
        XCTAssertEqual(viewModel.count, 1)
        XCTAssertFalse(viewModel.isEven)
    }
    
    func testReset() {
        viewModel.increment()
        viewModel.increment()
        viewModel.increment()
        XCTAssertEqual(viewModel.count, 3)
        
        viewModel.reset()
        XCTAssertEqual(viewModel.count, 0)
        XCTAssertTrue(viewModel.isEven)
    }
}
```

### UI 测试

```swift
import XCTest

class SwiftUIUITests: XCTestCase {
    var app: XCUIApplication!
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments = ["UI-Testing"]
        app.launch()
    }
    
    func testCounterIncrement() {
        // 访问计数器界面
        app.tabBars.buttons["计数器"].tap()
        
        // 检查初始状态
        XCTAssertTrue(app.staticTexts["计数: 0"].exists)
        
        // 点击增加按钮
        app.buttons["+"].tap()
        
        // 检查更新后的状态
        XCTAssertTrue(app.staticTexts["计数: 1"].exists)
        
        // 再次点击
        app.buttons["+"].tap()
        
        // 再次验证
        XCTAssertTrue(app.staticTexts["计数: 2"].exists)
    }
    
    func testFormSubmission() {
        // 访问表单界面
        app.tabBars.buttons["表单"].tap()
        
        // 填写表单
        let nameTextField = app.textFields["姓名"]
        nameTextField.tap()
        nameTextField.typeText("张三")
        
        let emailTextField = app.textFields["邮箱"]
        emailTextField.tap()
        emailTextField.typeText("zhangsan@example.com")
        
        // 关闭键盘
        app.buttons["完成"].tap()
        
        // 提交表单
        app.buttons["提交"].tap()
        
        // 验证成功消息
        XCTAssertTrue(app.alerts["提交成功"].exists)
        app.alerts["提交成功"].buttons["确定"].tap()
        
        // 验证表单已重置
        XCTAssertEqual(nameTextField.value as? String, "")
    }
}
```

### 预览调试技巧

```swift
// 使用预览模拟不同设备和状态
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        Group {
            // 模拟不同设备
            ContentView()
                .previewDevice(PreviewDevice(rawValue: "iPhone SE (2nd generation)"))
                .previewDisplayName("iPhone SE")
            
            ContentView()
                .previewDevice(PreviewDevice(rawValue: "iPhone 13 Pro Max"))
                .previewDisplayName("iPhone 13 Pro Max")
            
            // 模拟不同显示模式
            ContentView()
                .preferredColorScheme(.dark)
                .previewDisplayName("深色模式")
            
            // 模拟不同语言环境
            ContentView()
                .environment(\.locale, Locale(identifier: "zh-Hans"))
                .previewDisplayName("中文")
            
            // 模拟动态字体大小
            ContentView()
                .environment(\.sizeCategory, .accessibilityExtraExtraExtraLarge)
                .previewDisplayName("超大字体")
            
            // 模拟不同状态
            ContentView(viewModel: ContentViewModel(isLoading: true))
                .previewDisplayName("加载中")
            
            ContentView(viewModel: ContentViewModel(hasError: true))
                .previewDisplayName("错误状态")
        }
    }
}

// 模拟网络请求预览
struct NetworkView_Previews: PreviewProvider {
    static var previews: some View {
        let mockSuccessVM = ProductViewModel()
        mockSuccessVM.products = [
            Product(id: "1", name: "商品1", price: 99.9),
            Product(id: "2", name: "商品2", price: 199.9)
        ]
        
        let mockLoadingVM = ProductViewModel()
        mockLoadingVM.isLoading = true
        
        let mockErrorVM = ProductViewModel()
        mockErrorVM.error = NSError(domain: "网络错误", code: 404, userInfo: nil)
        
        return Group {
            ProductListView(viewModel: mockSuccessVM)
                .previewDisplayName("成功加载")
            
            ProductListView(viewModel: mockLoadingVM)
                .previewDisplayName("加载中")
            
            ProductListView(viewModel: mockErrorVM)
                .previewDisplayName("加载失败")
        }
    }
}
```

### 调试工具与技巧

```swift
// 使用 print 和自定义 Publisher 扩展进行调试
extension Publisher {
    func debugPrint(_ prefix: String = "") -> some Publisher where Output == Self.Output, Failure == Self.Failure {
        handleEvents(
            receiveSubscription: { _ in print("\(prefix)收到订阅") },
            receiveOutput: { value in print("\(prefix)输出值: \(value)") },
            receiveCompletion: { completion in
                switch completion {
                case .finished:
                    print("\(prefix)正常完成")
                case .failure(let error):
                    print("\(prefix)失败: \(error)")
                }
            },
            receiveCancel: { print("\(prefix)取消") }
        )
    }
}

// 使用 ViewModifier 进行边框调试
struct DebugBorder: ViewModifier {
    let color: Color
    
    func body(content: Content) -> some View {
        content
            .border(color)
            .overlay(
                Text(String(describing: type(of: content)))
                    .font(.caption2)
                    .foregroundColor(color)
                    .background(Color.white.opacity(0.8))
                    .allowsHitTesting(false),
                alignment: .topLeading
            )
    }
}

extension View {
    func debugBorder(_ color: Color = .red) -> some View {
        #if DEBUG
        return self.modifier(DebugBorder(color: color))
        #else
        return self
        #endif
    }
}

// 条件编译和环境变量
struct DebugMenu: View {
    var body: some View {
        #if DEBUG
        List {
            Section(header: Text("调试选项")) {
                Button("重置所有数据") {
                    // 重置逻辑
                }
                
                Button("模拟网络错误") {
                    // 模拟错误
                }
                
                Button("切换 API 环境") {
                    // 切换环境
                }
            }
        }
        .navigationTitle("调试菜单")
        #else
        EmptyView()
        #endif
    }
}

// 在视图中使用检查点
struct ComplexView: View {
    @ObservedObject var viewModel: ComplexViewModel
    
    var body: some View {
        List {
            ForEach(viewModel.items) { item in
                Text(item.title)
                    .onAppear {
                        print("🔍 加载 item: \(item.id)")
                        viewModel.itemAppeared(item)
                    }
            }
        }
        .onAppear {
            print("⚠️ ComplexView 出现")
        }
        .onDisappear {
            print("⚠️ ComplexView 消失")
        }
    }
}
```

## 布局系统深入

SwiftUI 提供了强大而灵活的布局系统，深入了解其工作原理有助于构建复杂界面。

### 布局过程与原理

SwiftUI 的布局系统基于父视图与子视图协商的模型：

1. 父视图向子视图提供可用空间
2. 子视图决定其理想尺寸
3. 父视图基于子视图的理想尺寸和自身规则，确定子视图的最终位置和大小

```swift
struct LayoutDemonstrationView: View {
    var body: some View {
        VStack(spacing: 20) {
            Text("SwiftUI 布局系统")
                .font(.headline)
            
            // 固有尺寸演示
            Text("文本有固有尺寸")
                .border(Color.red)
            
            Image(systemName: "star.fill")
                .resizable() // 移除固有尺寸
                .frame(width: 50, height: 50) // 提供显式尺寸
                .border(Color.green)
            
            // 父视图影响演示
            HStack {
                Text("HStack 中的子视图")
                    .border(Color.blue)
                
                Spacer() // 使用所有可用空间
                
                Text("右对齐")
                    .border(Color.blue)
            }
            .border(Color.orange)
            
            // 布局优先级演示
            HStack {
                Text("高优先级")
                    .layoutPriority(1)
                    .border(Color.purple)
                
                Text("这是一段很长的文本，但由于其布局优先级较低，将被截断")
                    .lineLimit(1)
                    .border(Color.purple)
            }
            .border(Color.yellow)
        }
        .padding()
    }
}
```

### 自定义布局

从 iOS 16 开始，SwiftUI 提供了自定义布局功能，可以创建复杂的排列方式：

```swift
// 瀑布流布局
struct WaterfallLayout: Layout {
    var columns: Int
    var spacing: CGFloat
    
    init(columns: Int = 2, spacing: CGFloat = 8) {
        self.columns = columns
        self.spacing = spacing
    }
    
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout Void) -> CGSize {
        let width = proposal.width ?? 0
        let columnWidth = (width - spacing * CGFloat(columns - 1)) / CGFloat(columns)
        
        var heights = Array(repeating: CGFloat(0), count: columns)
        
        for subview in subviews {
            // 找到最短的列
            let columnIndex = heights.indices.min(by: { heights[$0] < heights[$1] }) ?? 0
            
            // 计算子视图高度
            let subviewSize = subview.sizeThatFits(.init(width: columnWidth, height: nil))
            
            // 更新列高
            heights[columnIndex] += subviewSize.height + spacing
        }
        
        // 最终高度是最高的列的高度
        return CGSize(width: width, height: heights.max() ?? 0)
    }
    
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout Void) {
        let width = bounds.width
        let columnWidth = (width - spacing * CGFloat(columns - 1)) / CGFloat(columns)
        
        var heights = Array(repeating: bounds.minY, count: columns)
        
        for subview in subviews {
            // 找到最短的列
            let columnIndex = heights.indices.min(by: { heights[$0] < heights[$1] }) ?? 0
            
            // 计算子视图高度
            let subviewSize = subview.sizeThatFits(.init(width: columnWidth, height: nil))
            
            // 计算放置位置
            let xPos = bounds.minX + CGFloat(columnIndex) * (columnWidth + spacing)
            let yPos = heights[columnIndex]
            
            // 放置子视图
            subview.place(at: CGPoint(x: xPos, y: yPos), proposal: .init(width: columnWidth, height: subviewSize.height))
            
            // 更新列高
            heights[columnIndex] += subviewSize.height + spacing
        }
    }
}

// 使用自定义布局
struct WaterfallGridDemo: View {
    let items = (1...20).map { "项目 \($0)" }
    
    var body: some View {
        ScrollView {
            WaterfallLayout(columns: 2, spacing: 10) {
                ForEach(items, id: \.self) { item in
                    ItemView(title: item, height: CGFloat.random(in: 100...200))
                }
            }
            .padding()
        }
    }
}

struct ItemView: View {
    let title: String
    let height: CGFloat
    
    var body: some View {
        Text(title)
            .frame(maxWidth: .infinity, minHeight: height)
            .padding()
            .background(Color.blue.opacity(0.2))
            .cornerRadius(10)
    }
}
```

### 布局辅助工具

```swift
// 尺寸读取器
struct SizePreferenceKey: PreferenceKey {
    static var defaultValue: CGSize = .zero
    
    static func reduce(value: inout CGSize, nextValue: () -> CGSize) {
        value = nextValue()
    }
}

extension View {
    func readSize(onChange: @escaping (CGSize) -> Void) -> some View {
        background(
            GeometryReader { geo in
                Color.clear
                    .preference(key: SizePreferenceKey.self, value: geo.size)
                    .onPreferenceChange(SizePreferenceKey.self, perform: onChange)
            }
        )
    }
}

// 动态尺寸调整视图
struct DynamicSizeDemo: View {
    @State private var textSize: CGSize = .zero
    @State private var containerWidth: CGFloat = 300
    
    var body: some View {
        VStack(spacing: 20) {
            Text("尺寸读取演示")
                .font(.headline)
            
            // 动态调整尺寸的文本
            Text("这是一段文本，我们将读取其尺寸并根据尺寸动态调整其他元素。")
                .frame(width: containerWidth)
                .padding()
                .background(Color.yellow.opacity(0.3))
                .cornerRadius(10)
                .readSize { size in
                    textSize = size
                }
            
            Text("文本尺寸: \(Int(textSize.width)) x \(Int(textSize.height))")
            
            // 基于文本尺寸创建视图
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.blue.opacity(0.3))
                .frame(width: textSize.width, height: 40)
            
            // 调整宽度滑块
            Slider(value: $containerWidth, in: 200...350, step: 10) {
                Text("调整容器宽度")
            }
        }
        .padding()
    }
}
```

### 对齐与坐标系统

```swift
// 自定义对齐指南
extension VerticalAlignment {
    struct CustomVerticalAlignment: AlignmentID {
        static func defaultValue(in context: ViewDimensions) -> CGFloat {
            context[.bottom]
        }
    }
    
    static let customAlignment = VerticalAlignment(CustomVerticalAlignment.self)
}

// 对齐与坐标系统演示
struct AlignmentDemo: View {
    var body: some View {
        VStack(spacing: 40) {
            Text("对齐演示")
                .font(.headline)
            
            // 基本对齐
            HStack(alignment: .lastTextBaseline) {
                Text("小文本")
                    .font(.body)
                
                Text("大文本")
                    .font(.largeTitle)
                
                Text("中等文本")
                    .font(.title3)
            }
            .border(Color.gray)
            
            // 自定义对齐
            HStack(alignment: .customAlignment) {
                VStack {
                    Spacer()
                    Circle()
                        .fill(Color.red)
                        .frame(width: 50, height: 50)
                        .alignmentGuide(.customAlignment) { d in
                            d[.bottom] - 10 // 圆形底部上移10点
                        }
                }
                .frame(height: 120)
                
                VStack {
                    Rectangle()
                        .fill(Color.green)
                        .frame(width: 50, height: 80)
                        .alignmentGuide(.customAlignment) { d in
                            d[.bottom]
                        }
                    Spacer()
                }
                .frame(height: 120)
                
                VStack {
                    Spacer()
                    Rectangle()
                        .fill(Color.blue)
                        .frame(width: 50, height: 30)
                }
                .frame(height: 120)
            }
            .border(Color.gray)
            
            // 坐标空间演示
            CoordinateSpaceDemo()
        }
        .padding()
    }
}

struct CoordinateSpaceDemo: View {
    @State private var localPosition: CGPoint = .zero
    @State private var globalPosition: CGPoint = .zero
    @State private var namedPosition: CGPoint = .zero
    
    var body: some View {
        VStack {
            Text("坐标空间演示")
                .font(.headline)
            
            // 拖动区域
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(Color.blue.opacity(0.1))
                
                Circle()
                    .fill(Color.red)
                    .frame(width: 40, height: 40)
                    .position(localPosition)
                    .gesture(
                        DragGesture(coordinateSpace: .local)
                            .onChanged { value in
                                localPosition = value.location
                            }
                    )
                
                Text("拖动红色圆形")
                    .font(.caption)
                    .position(x: 100, y: 20)
            }
            .frame(width: 200, height: 200)
            .coordinateSpace(name: "customSpace")
            .background(
                GeometryReader { geo in
                    Color.clear
                        .preference(key: GlobalPositionPreferenceKey.self, value: geo.frame(in: .global).origin)
                        .preference(key: NamedPositionPreferenceKey.self, value: geo.frame(in: .named("customSpace")).origin)
                }
            )
            .onPreferenceChange(GlobalPositionPreferenceKey.self) { pos in
                globalPosition = pos
            }
            .onPreferenceChange(NamedPositionPreferenceKey.self) { pos in
                namedPosition = pos
            }
            
            // 显示不同坐标空间中的位置
            Group {
                Text("本地坐标: \(Int(localPosition.x)) x \(Int(localPosition.y))")
                Text("全局坐标: \(Int(globalPosition.x)) x \(Int(globalPosition.y))")
                Text("命名坐标: \(Int(namedPosition.x)) x \(Int(namedPosition.y))")
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top)
        }
    }
}

// 位置偏好键
struct GlobalPositionPreferenceKey: PreferenceKey {
    static var defaultValue: CGPoint = .zero
    
    static func reduce(value: inout CGPoint, nextValue: () -> CGPoint) {
        value = nextValue()
    }
}

struct NamedPositionPreferenceKey: PreferenceKey {
    static var defaultValue: CGPoint = .zero
    
    static func reduce(value: inout CGPoint, nextValue: () -> CGPoint) {
        value = nextValue()
    }
}
```

### 容器布局行为

```swift
// 不同容器的布局行为
struct ContainerLayoutBehaviorDemo: View {
    var body: some View {
        VStack(spacing: 20) {
            Text("容器布局行为")
                .font(.headline)
            
            Group {
                Text("HStack 均匀分布")
                
                HStack {
                    ForEach(1...3, id: \.self) { index in
                        Text("项目 \(index)")
                            .padding()
                            .background(Color.blue.opacity(0.2))
                    }
                }
                .border(Color.gray)
                
                Text("HStack 带 Spacer")
                
                HStack {
                    ForEach(1...3, id: \.self) { index in
                        Text("项目 \(index)")
                            .padding()
                            .background(Color.green.opacity(0.2))
                        
                        if index < 3 {
                            Spacer()
                        }
                    }
                }
                .border(Color.gray)
                
                Text("ZStack 居中")
                
                ZStack {
                    RoundedRectangle(cornerRadius: 10)
                        .fill(Color.yellow.opacity(0.3))
                        .frame(width: 200, height: 100)
                    
                    Text("居中文本")
                        .padding()
                        .background(Color.white.opacity(0.8))
                        .cornerRadius(5)
                }
                .border(Color.gray)
                
                Text("ZStack 自定义位置")
                
                ZStack(alignment: .topTrailing) {
                    RoundedRectangle(cornerRadius: 10)
                        .fill(Color.purple.opacity(0.3))
                        .frame(width: 200, height: 100)
                    
                    Text("右上角")
                        .padding(8)
                        .background(Color.white.opacity(0.8))
                        .cornerRadius(5)
                        .padding(5)
                }
                .border(Color.gray)
                
                Text("LazyVGrid 行为")
                
                ScrollView(.horizontal) {
                    LazyHGrid(rows: [
                        GridItem(.fixed(50)),
                        GridItem(.flexible(minimum: 30))
                    ], spacing: 10) {
                        ForEach(1...10, id: \.self) { index in
                            Text("\(index)")
                                .frame(width: 40)
                                .padding()
                                .background(Color.orange.opacity(0.3))
                                .cornerRadius(8)
                        }
                    }
                    .padding(.horizontal)
                }
                .frame(height: 150)
                .border(Color.gray)
            }
        }
        .padding()
    }
}
```

### GeometryReader 高级应用

```swift
// GeometryReader 的高级应用
struct AdvancedGeometryReaderDemo: View {
    var body: some View {
        ScrollView {
            VStack(spacing: 30) {
                Text("GeometryReader 高级应用")
                    .font(.headline)
                
                // 基于滚动位置的视差效果
                ScrollParallaxView()
                
                // 基于尺寸的响应式布局
                ResponsiveGridView()
                
                // 自定义进度条
                CustomProgressBar(value: 0.7)
                    .frame(height: 20)
                    .padding(.horizontal)
            }
            .padding()
        }
    }
}

// 滚动视差效果
struct ScrollParallaxView: View {
    var body: some View {
        GeometryReader { outerGeo in
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 0) {
                    ForEach(1...5, id: \.self) { index in
                        GeometryReader { innerGeo in
                            RoundedRectangle(cornerRadius: 20)
                                .fill(Color(hue: Double(index) * 0.1, saturation: 0.8, brightness: 0.9))
                                .overlay(
                                    Text("卡片 \(index)")
                                        .font(.largeTitle)
                                        .fontWeight(.bold)
                                        .foregroundColor(.white)
                                )
                                // 基于滚动位置计算缩放效果
                                .scaleEffect(parallaxScale(outerGeo: outerGeo, innerGeo: innerGeo))
                                // 基于滚动位置计算旋转效果
                                .rotation3DEffect(
                                    parallaxAngle(outerGeo: outerGeo, innerGeo: innerGeo),
                                    axis: (x: 0, y: 1, z: 0)
                                )
                        }
                        .frame(width: outerGeo.size.width * 0.8, height: 200)
                        .padding(.horizontal, outerGeo.size.width * 0.1)
                    }
                }
                .padding(.horizontal, outerGeo.size.width * 0.1)
            }
        }
        .frame(height: 250)
    }
    
    private func parallaxScale(outerGeo: GeometryProxy, innerGeo: GeometryProxy) -> CGFloat {
        let midX = innerGeo.frame(in: .global).midX
        let screenWidth = outerGeo.frame(in: .global).width
        let screenMidX = outerGeo.frame(in: .global).midX
        
        // 计算距中心的偏移
        let offset = abs(midX - screenMidX) / screenWidth
        
        // 根据偏移计算缩放值：中心位置1.0，边缘位置0.8
        return 1.0 - (offset * 0.2)
    }
    
    private func parallaxAngle(outerGeo: GeometryProxy, innerGeo: GeometryProxy) -> Angle {
        let midX = innerGeo.frame(in: .global).midX
        let screenWidth = outerGeo.frame(in: .global).width
        let screenMidX = outerGeo.frame(in: .global).midX
        
        // 计算距中心的偏移
        let offset = (midX - screenMidX) / screenWidth
        
        // 根据偏移计算旋转角度：最大±15度
        return Angle(degrees: -15 * Double(offset))
    }
}

// 响应式网格布局
struct ResponsiveGridView: View {
    let items = (1...12).map { "项目 \($0)" }
    
    var body: some View {
        GeometryReader { geo in
            let columns = columnsForWidth(geo.size.width)
            let spacing: CGFloat = 10
            let width = (geo.size.width - (spacing * CGFloat(columns - 1))) / CGFloat(columns)
            
            VStack(alignment: .leading) {
                Text("响应式网格 (\(columns) 列)")
                    .font(.subheadline)
                    .padding(.bottom, 5)
                
                FlowLayout(columns: columns, spacing: spacing) {
                    ForEach(items, id: \.self) { item in
                        Text(item)
                            .frame(width: width, height: 60)
                            .background(Color.blue.opacity(0.2))
                            .cornerRadius(8)
                    }
                }
            }
        }
        .frame(height: 250)
    }
    
    private func columnsForWidth(_ width: CGFloat) -> Int {
        switch width {
        case 0..<300:
            return 1
        case 300..<500:
            return 2
        case 500..<700:
            return 3
        default:
            return 4
        }
    }
}

// 简单流布局
struct FlowLayout: View {
    let columns: Int
    let spacing: CGFloat
    let content: [AnyView]
    
    init<Content: View>(columns: Int, spacing: CGFloat = 10, @ViewBuilder content: () -> Content) {
        self.columns = columns
        self.spacing = spacing
        self.content = [AnyView(content())]
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: spacing) {
            ForEach(0..<rows, id: \.self) { row in
                HStack(spacing: spacing) {
                    ForEach(0..<columns, id: \.self) { column in
                        let index = row * columns + column
                        if index < content.count {
                            content[index]
                        } else {
                            Spacer()
                        }
                    }
                }
            }
        }
    }
    
    private var rows: Int {
        (content.count + columns - 1) / columns
    }
}

// 自定义进度条
struct CustomProgressBar: View {
    var value: Double // 0.0 - 1.0
    var color: Color = .blue
    var backgroundColor: Color = .gray.opacity(0.3)
    
    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                // 背景
                RoundedRectangle(cornerRadius: geo.size.height / 2)
                    .fill(backgroundColor)
                
                // 进度
                RoundedRectangle(cornerRadius: geo.size.height / 2)
                    .fill(color)
                    .frame(width: max(geo.size.height, geo.size.width * CGFloat(value)))
                
                // 进度指示器
                Circle()
                    .fill(Color.white)
                    .frame(width: geo.size.height * 0.8, height: geo.size.height * 0.8)
                    .shadow(radius: 2)
                    .offset(x: max(0, (geo.size.width - geo.size.height) * CGFloat(value)))
            }
        }
    }
}
``` 