# iOS电商应用开发

本教程将指导您构建一个功能完整的iOS电商应用，包括产品浏览、购物车、结账流程等核心功能。

## 目录

- [项目概述](#项目概述)
- [技术栈](#技术栈)
- [项目架构](#项目架构)
- [核心功能实现](#核心功能实现)
- [UI/UX设计](#uiux设计)
- [性能优化](#性能优化)
- [应用发布](#应用发布)

## 项目概述

我们将开发的电商应用具有以下核心功能：

- 用户认证与个人资料管理
- 产品分类与搜索
- 产品详情展示
- 购物车管理
- 结账流程
- 订单历史与跟踪
- 收藏与推荐系统

### 应用预览

![应用预览](../../assets/ios/ecommerce-preview.png)

## 技术栈

### 前端/客户端

- **UI框架**: UIKit + SwiftUI（混合开发）
- **架构模式**: MVVM + Coordinator
- **网络层**: Alamofire + Combine
- **数据持久化**: Core Data + Keychain
- **图片加载**: Kingfisher
- **动画**: Lottie

### 后端集成

- **API服务**: RESTful API
- **支付集成**: Apple Pay + Stripe
- **分析工具**: Firebase Analytics
- **云存储**: Firebase Storage

## 项目架构

### 目录结构

```
ShopApp/
├── App/
│   ├── AppDelegate.swift
│   ├── SceneDelegate.swift
│   └── AppCoordinator.swift
├── Core/
│   ├── Extensions/
│   ├── Networking/
│   ├── Storage/
│   └── Utilities/
├── Services/
│   ├── AuthService.swift
│   ├── ProductService.swift
│   ├── CartService.swift
│   ├── OrderService.swift
│   └── PaymentService.swift
├── Models/
│   ├── User.swift
│   ├── Product.swift
│   ├── CartItem.swift
│   ├── Order.swift
│   └── Address.swift
├── Scenes/
│   ├── Auth/
│   ├── Home/
│   ├── Catalog/
│   ├── Product/
│   ├── Cart/
│   ├── Checkout/
│   ├── Orders/
│   └── Profile/
└── Resources/
    ├── Assets.xcassets
    ├── Localizations/
    └── LaunchScreen.storyboard
```

### MVVM + Coordinator架构

我们采用MVVM模式处理视图逻辑，使用Coordinator模式管理导航流程：

```swift
// Coordinator基础协议
protocol Coordinator: AnyObject {
    var childCoordinators: [Coordinator] { get set }
    var navigationController: UINavigationController { get set }
    
    func start()
}

// 主应用Coordinator
class AppCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    
    init(navigationController: UINavigationController) {
        self.navigationController = navigationController
    }
    
    func start() {
        if AuthService.shared.isUserLoggedIn {
            showMainApp()
        } else {
            showLogin()
        }
    }
    
    private func showLogin() {
        let authCoordinator = AuthCoordinator(navigationController: navigationController)
        childCoordinators.append(authCoordinator)
        authCoordinator.delegate = self
        authCoordinator.start()
    }
    
    private func showMainApp() {
        let tabBarCoordinator = TabBarCoordinator(navigationController: navigationController)
        childCoordinators.append(tabBarCoordinator)
        tabBarCoordinator.start()
    }
}

// 商品列表ViewModel示例
class ProductListViewModel: ObservableObject {
    @Published var products: [Product] = []
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    
    private let productService: ProductServiceProtocol
    
    init(productService: ProductServiceProtocol = ProductService()) {
        self.productService = productService
    }
    
    func fetchProducts(categoryId: String? = nil) {
        isLoading = true
        
        Task {
            do {
                let fetchedProducts = try await productService.fetchProducts(categoryId: categoryId)
                
                await MainActor.run {
                    self.products = fetchedProducts
                    self.isLoading = false
                }
            } catch {
                await MainActor.run {
                    self.errorMessage = error.localizedDescription
                    self.isLoading = false
                }
            }
        }
    }
}
```

## 核心功能实现

### 1. 用户认证系统

```swift
// AuthService.swift
class AuthService {
    static let shared = AuthService()
    
    private let keychain = KeychainSwift()
    private let userDefaults = UserDefaults.standard
    
    var isUserLoggedIn: Bool {
        return keychain.get("authToken") != nil
    }
    
    var currentUser: User? {
        get {
            guard let userData = userDefaults.data(forKey: "currentUser"),
                  let user = try? JSONDecoder().decode(User.self, from: userData) else {
                return nil
            }
            return user
        }
        set {
            if let user = newValue, let userData = try? JSONEncoder().encode(user) {
                userDefaults.set(userData, forKey: "currentUser")
            } else {
                userDefaults.removeObject(forKey: "currentUser")
            }
        }
    }
    
    func signIn(email: String, password: String) async throws -> User {
        // 实现登录API请求
        // 保存令牌到Keychain
        // 返回用户信息
    }
    
    func signUp(email: String, password: String, name: String) async throws -> User {
        // 实现注册API请求
    }
    
    func signOut() {
        keychain.delete("authToken")
        currentUser = nil
    }
}
```

### 2. 产品目录与搜索

```swift
// 使用Core Data存储产品数据
extension Product {
    static func fetchFeaturedProducts(context: NSManagedObjectContext) -> [Product] {
        let request: NSFetchRequest<Product> = Product.fetchRequest()
        request.predicate = NSPredicate(format: "isFeatured == %@", NSNumber(value: true))
        request.fetchLimit = 10
        
        do {
            return try context.fetch(request)
        } catch {
            print("获取精选产品失败: \(error)")
            return []
        }
    }
    
    static func searchProducts(query: String, context: NSManagedObjectContext) -> [Product] {
        let request: NSFetchRequest<Product> = Product.fetchRequest()
        request.predicate = NSPredicate(format: "name CONTAINS[cd] %@ OR description CONTAINS[cd] %@", query, query)
        
        do {
            return try context.fetch(request)
        } catch {
            print("搜索产品失败: \(error)")
            return []
        }
    }
}

// 产品列表视图
struct ProductGridView: View {
    @ObservedObject var viewModel: ProductListViewModel
    let columns = [GridItem(.flexible()), GridItem(.flexible())]
    
    var body: some View {
        Group {
            if viewModel.isLoading {
                ProgressView("加载中...")
            } else if let errorMessage = viewModel.errorMessage {
                Text("错误: \(errorMessage)")
                    .foregroundColor(.red)
            } else {
                ScrollView {
                    LazyVGrid(columns: columns, spacing: 16) {
                        ForEach(viewModel.products) { product in
                            ProductCell(product: product)
                                .frame(height: 220)
                        }
                    }
                    .padding()
                }
            }
        }
        .onAppear {
            viewModel.fetchProducts()
        }
    }
}
```

### 3. 购物车管理

```swift
// CartManager.swift
class CartManager: ObservableObject {
    @Published var items: [CartItem] = []
    
    var itemCount: Int {
        items.reduce(0) { $0 + $1.quantity }
    }
    
    var subtotal: Decimal {
        items.reduce(0) { $0 + $1.subtotal }
    }
    
    func addToCart(product: Product, quantity: Int = 1) {
        if let index = items.firstIndex(where: { $0.product.id == product.id }) {
            items[index].quantity += quantity
        } else {
            let newItem = CartItem(product: product, quantity: quantity)
            items.append(newItem)
        }
        
        saveCart()
    }
    
    func updateQuantity(for item: CartItem, quantity: Int) {
        if let index = items.firstIndex(where: { $0.id == item.id }) {
            items[index].quantity = max(1, quantity)
            saveCart()
        }
    }
    
    func removeFromCart(item: CartItem) {
        items.removeAll { $0.id == item.id }
        saveCart()
    }
    
    func clearCart() {
        items.removeAll()
        saveCart()
    }
    
    private func saveCart() {
        // 保存购物车到UserDefaults或Core Data
    }
}

// CartItem模型
struct CartItem: Identifiable, Codable {
    let id = UUID()
    let product: Product
    var quantity: Int
    
    var subtotal: Decimal {
        return product.price * Decimal(quantity)
    }
}
```

### 4. 结账流程

```swift
// CheckoutCoordinator.swift
class CheckoutCoordinator: Coordinator {
    var childCoordinators: [Coordinator] = []
    var navigationController: UINavigationController
    private let cartManager: CartManager
    
    init(navigationController: UINavigationController, cartManager: CartManager) {
        self.navigationController = navigationController
        self.cartManager = cartManager
    }
    
    func start() {
        showShippingAddress()
    }
    
    private func showShippingAddress() {
        let viewModel = ShippingAddressViewModel()
        viewModel.delegate = self
        
        let viewController = ShippingAddressViewController(viewModel: viewModel)
        navigationController.pushViewController(viewController, animated: true)
    }
    
    private func showPaymentMethod(with address: Address) {
        let viewModel = PaymentMethodViewModel(shippingAddress: address)
        viewModel.delegate = self
        
        let viewController = PaymentMethodViewController(viewModel: viewModel)
        navigationController.pushViewController(viewController, animated: true)
    }
    
    private func showOrderReview(with address: Address, paymentMethod: PaymentMethod) {
        let viewModel = OrderReviewViewModel(
            cartManager: cartManager,
            shippingAddress: address,
            paymentMethod: paymentMethod
        )
        viewModel.delegate = self
        
        let viewController = OrderReviewViewController(viewModel: viewModel)
        navigationController.pushViewController(viewController, animated: true)
    }
    
    private func processPayment(order: Order) {
        // 实现支付处理逻辑
    }
}
```

## UI/UX设计

### 主题与样式

```swift
// AppTheme.swift
struct AppTheme {
    // 颜色
    static let primaryColor = UIColor(red: 0.2, green: 0.5, blue: 0.9, alpha: 1.0)
    static let secondaryColor = UIColor(red: 0.95, green: 0.61, blue: 0.07, alpha: 1.0)
    static let backgroundColor = UIColor.systemBackground
    static let cardColor = UIColor.secondarySystemBackground
    
    // 字体
    enum Typography {
        static let titleFont = UIFont.systemFont(ofSize: 24, weight: .bold)
        static let subtitleFont = UIFont.systemFont(ofSize: 18, weight: .semibold)
        static let bodyFont = UIFont.systemFont(ofSize: 16, weight: .regular)
        static let captionFont = UIFont.systemFont(ofSize: 14, weight: .regular)
    }
    
    // 间距
    enum Spacing {
        static let small: CGFloat = 8
        static let medium: CGFloat = 16
        static let large: CGFloat = 24
    }
    
    // 圆角
    enum CornerRadius {
        static let small: CGFloat = 4
        static let medium: CGFloat = 8
        static let large: CGFloat = 16
    }
}
```

### 自定义组件

```swift
// ProductCell.swift (SwiftUI)
struct ProductCell: View {
    let product: Product
    
    var body: some View {
        VStack(alignment: .leading) {
            // 产品图片
            AsyncImage(url: URL(string: product.imageURL)) { phase in
                switch phase {
                case .empty:
                    Rectangle()
                        .foregroundColor(.gray.opacity(0.3))
                case .success(let image):
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                case .failure:
                    Image(systemName: "photo")
                        .foregroundColor(.gray)
                @unknown default:
                    EmptyView()
                }
            }
            .frame(height: 150)
            .clipShape(RoundedRectangle(cornerRadius: 8))
            
            // 产品信息
            VStack(alignment: .leading, spacing: 4) {
                Text(product.name)
                    .font(.headline)
                    .lineLimit(1)
                
                Text("$\(product.price, specifier: "%.2f")")
                    .font(.subheadline)
                    .foregroundColor(.blue)
                
                HStack {
                    ForEach(0..<5) { index in
                        Image(systemName: index < Int(product.rating) ? "star.fill" : "star")
                            .foregroundColor(.yellow)
                            .font(.caption)
                    }
                    Text("(\(product.reviewCount))")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding(.horizontal, 6)
            .padding(.vertical, 8)
        }
        .background(Color(UIColor.secondarySystemBackground))
        .cornerRadius(12)
        .shadow(radius: 2)
    }
}
```

## 性能优化

### 图片加载优化

```swift
// 扩展UIImageView使用Kingfisher加载图片
extension UIImageView {
    func loadImage(from urlString: String, placeholder: UIImage? = nil) {
        let url = URL(string: urlString)
        
        let processor = DownsamplingImageProcessor(size: bounds.size)
            |> RoundCornerImageProcessor(cornerRadius: 8)
        
        kf.indicatorType = .activity
        kf.setImage(
            with: url,
            placeholder: placeholder,
            options: [
                .processor(processor),
                .scaleFactor(UIScreen.main.scale),
                .transition(.fade(0.2)),
                .cacheOriginalImage
            ]
        )
    }
}
```

### 数据预加载与缓存

```swift
// ProductService.swift
class ProductService: ProductServiceProtocol {
    private let cacheManager = CacheManager.shared
    private let networkManager: NetworkManager
    
    init(networkManager: NetworkManager = .shared) {
        self.networkManager = networkManager
    }
    
    func fetchProducts(categoryId: String? = nil) async throws -> [Product] {
        // 检查缓存
        let cacheKey = "products_\(categoryId ?? "all")"
        if let cachedProducts: [Product] = cacheManager.get(for: cacheKey) {
            return cachedProducts
        }
        
        // 从网络获取
        var endpoint = "products"
        if let categoryId = categoryId {
            endpoint += "?category=\(categoryId)"
        }
        
        let products: [Product] = try await networkManager.request(endpoint: endpoint, method: .get)
        
        // 缓存结果
        cacheManager.set(products, for: cacheKey, expiry: .seconds(60 * 15))
        
        return products
    }
}
```

## 应用发布

### App Store准备

1. 创建应用图标和截图
2. 撰写应用描述和关键词
3. 准备隐私政策
4. 配置App Store Connect

### 测试与质量保证

```swift
// 单元测试示例 - CartManagerTests.swift
class CartManagerTests: XCTestCase {
    var cartManager: CartManager!
    var testProduct: Product!
    
    override func setUp() {
        super.setUp()
        cartManager = CartManager()
        testProduct = Product(id: "1", name: "Test Product", price: 9.99, imageURL: "")
    }
    
    override func tearDown() {
        cartManager = nil
        testProduct = nil
        super.tearDown()
    }
    
    func testAddToCart() {
        // 添加产品到购物车
        cartManager.addToCart(product: testProduct, quantity: 2)
        
        // 验证
        XCTAssertEqual(cartManager.items.count, 1)
        XCTAssertEqual(cartManager.items[0].product.id, "1")
        XCTAssertEqual(cartManager.items[0].quantity, 2)
    }
    
    func testUpdateQuantity() {
        // 添加产品并更新数量
        cartManager.addToCart(product: testProduct)
        let item = cartManager.items[0]
        cartManager.updateQuantity(for: item, quantity: 5)
        
        // 验证
        XCTAssertEqual(cartManager.items[0].quantity, 5)
    }
}
```

### 发布策略

1. **软发布**：先在小范围市场发布，收集反馈
2. **分阶段推出**：逐步向更多用户推出
3. **持续更新**：根据用户反馈和数据分析进行优化

## 总结

本教程介绍了如何构建一个功能完整的iOS电商应用，涵盖了从架构设计到UI实现的各个方面。通过使用MVVM架构模式和现代Swift特性，我们创建了一个可维护、可扩展的应用程序。

通过完成本项目，您将学习到：

1. 电商应用的架构设计与实现
2. 用户认证与状态管理
3. 产品目录与购物车功能
4. 结账流程与支付集成
5. UI/UX设计最佳实践
6. 性能优化与发布策略

## 下一步

- 实现高级功能，如产品推荐和个性化
- 添加社交分享和用户评论功能
- 集成更多支付方式
- 优化离线体验
- 国际化支持

## 参考资源

- [Swift与MVVM](../architecture/mvvm.md)
- [iOS用户认证最佳实践](../networking/authentication.md)
- [iOS电子商务UX设计](../ui/ux-design.md)
- [SwiftUI与UIKit集成](../ui/swiftui-uikit.md) 