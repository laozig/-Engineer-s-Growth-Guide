## 在 Swift 中实现依赖注入

Swift 语言提供了多种实现依赖注入的方法，从简单的手动注入到使用专门的依赖注入框架，以下是几种常见的实现方式：

### 使用协议

Swift 的协议（Protocol）是实现依赖注入的强大工具。通过定义协议，我们可以将类的依赖从具体实现抽象为接口，从而实现松耦合。

**基本示例：**

```swift
// 定义协议
protocol DataFetchable {
    func fetchData(completion: @escaping (Result<Data, Error>) -> Void)
}

// 实现协议的具体类
class NetworkDataFetcher: DataFetchable {
    func fetchData(completion: @escaping (Result<Data, Error>) -> Void) {
        // 实际的网络请求实现
        URLSession.shared.dataTask(with: URL(string: "https://api.example.com/data")!) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            if let data = data {
                completion(.success(data))
            } else {
                completion(.failure(NSError(domain: "NetworkError", code: 0, userInfo: nil)))
            }
        }.resume()
    }
}

// 用于测试的模拟实现
class MockDataFetcher: DataFetchable {
    var mockedData: Data?
    var mockedError: Error?
    
    func fetchData(completion: @escaping (Result<Data, Error>) -> Void) {
        if let error = mockedError {
            completion(.failure(error))
        } else if let data = mockedData {
            completion(.success(data))
        } else {
            completion(.failure(NSError(domain: "MockError", code: 0, userInfo: nil)))
        }
    }
}

// 依赖于协议而非具体实现的类
class DataProcessor {
    private let dataFetcher: DataFetchable
    
    init(dataFetcher: DataFetchable) {
        self.dataFetcher = dataFetcher
    }
    
    func processData(completion: @escaping (Result<ProcessedData, Error>) -> Void) {
        dataFetcher.fetchData { result in
            switch result {
            case .success(let data):
                do {
                    let processedData = try self.process(data)
                    completion(.success(processedData))
                } catch {
                    completion(.failure(error))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    private func process(_ data: Data) throws -> ProcessedData {
        // 处理数据的逻辑
        return ProcessedData()
    }
}

// 使用示例
struct ProcessedData {}

// 生产环境
let realFetcher = NetworkDataFetcher()
let processor = DataProcessor(dataFetcher: realFetcher)

// 测试环境
let mockFetcher = MockDataFetcher()
mockFetcher.mockedData = "Test data".data(using: .utf8)
let testProcessor = DataProcessor(dataFetcher: mockFetcher)
```

**使用协议扩展提供默认实现：**

Swift 的协议扩展允许我们为协议提供默认实现，这样可以减少重复代码，同时保持依赖注入的灵活性。

```swift
protocol LoggerProtocol {
    func log(_ message: String, level: LogLevel)
    func logError(_ error: Error)
}

enum LogLevel {
    case info, warning, error, debug
}

extension LoggerProtocol {
    func logError(_ error: Error) {
        log(error.localizedDescription, level: .error)
    }
    
    // 提供更多默认实现...
}

class ConsoleLogger: LoggerProtocol {
    func log(_ message: String, level: LogLevel) {
        print("[\(level)]: \(message)")
    }
    
    // 不需要实现 logError，因为它使用默认实现
}

class FileLogger: LoggerProtocol {
    func log(_ message: String, level: LogLevel) {
        // 将日志写入文件
    }
    
    // 可以覆盖默认实现以提供特定行为
    func logError(_ error: Error) {
        log("Custom error format: \(error.localizedDescription)", level: .error)
        // 额外记录错误的堆栈跟踪等
    }
}
```

**使用协议组合：**

Swift 允许我们组合多个协议，这对于依赖注入非常有用，尤其是当一个类需要多个不同功能的依赖项时。

```swift
protocol Readable {
    func read() -> Data?
}

protocol Writable {
    func write(_ data: Data) -> Bool
}

// 组合协议
typealias ReadWritable = Readable & Writable

// 实现组合协议的类
class FileHandler: ReadWritable {
    private let fileURL: URL
    
    init(fileURL: URL) {
        self.fileURL = fileURL
    }
    
    func read() -> Data? {
        return try? Data(contentsOf: fileURL)
    }
    
    func write(_ data: Data) -> Bool {
        do {
            try data.write(to: fileURL)
            return true
        } catch {
            return false
        }
    }
}

// 依赖于组合协议的类
class DataManager {
    private let storage: ReadWritable
    
    init(storage: ReadWritable) {
        self.storage = storage
    }
    
    func saveData(_ data: Data) -> Bool {
        return storage.write(data)
    }
    
    func loadData() -> Data? {
        return storage.read()
    }
}
```

### 使用泛型

Swift 的泛型是实现依赖注入的另一种强大工具，尤其是当你需要保持类型安全的同时提供灵活性时。

**基本示例：**

```swift
class GenericRepository<T, StorageType> where StorageType: StorageProtocol {
    private let storage: StorageType
    
    init(storage: StorageType) {
        self.storage = storage
    }
    
    func save(_ item: T) -> Bool {
        guard let data = try? JSONEncoder().encode(item) else {
            return false
        }
        return storage.save(data, forKey: String(describing: T.self))
    }
    
    func fetch() -> T? {
        guard let data = storage.fetch(forKey: String(describing: T.self)),
              let item = try? JSONDecoder().decode(T.self, from: data) else {
            return nil
        }
        return item
    }
}

protocol StorageProtocol {
    func save(_ data: Data, forKey key: String) -> Bool
    func fetch(forKey key: String) -> Data?
}

class UserDefaultsStorage: StorageProtocol {
    func save(_ data: Data, forKey key: String) -> Bool {
        UserDefaults.standard.set(data, forKey: key)
        return true
    }
    
    func fetch(forKey key: String) -> Data? {
        return UserDefaults.standard.data(forKey: key)
    }
}

class FileStorage: StorageProtocol {
    private let baseURL: URL
    
    init(baseURL: URL) {
        self.baseURL = baseURL
    }
    
    func save(_ data: Data, forKey key: String) -> Bool {
        let fileURL = baseURL.appendingPathComponent(key)
        do {
            try data.write(to: fileURL)
            return true
        } catch {
            return false
        }
    }
    
    func fetch(forKey key: String) -> Data? {
        let fileURL = baseURL.appendingPathComponent(key)
        return try? Data(contentsOf: fileURL)
    }
}

// 使用
struct User: Codable {
    let id: String
    let name: String
}

// 使用 UserDefaults 存储
let userDefaultsStorage = UserDefaultsStorage()
let userRepository = GenericRepository<User, UserDefaultsStorage>(storage: userDefaultsStorage)

// 使用文件存储
let documentsURL = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
let fileStorage = FileStorage(baseURL: documentsURL)
let fileUserRepository = GenericRepository<User, FileStorage>(storage: fileStorage)
```

**使用泛型约束：**

泛型约束可以让我们在保持灵活性的同时，确保依赖项满足特定要求。

```swift
protocol Storable {
    associatedtype StoredType
    func store(_ item: StoredType) -> Bool
    func retrieve() -> StoredType?
}

class UserStorage: Storable {
    typealias StoredType = User
    
    func store(_ item: User) -> Bool {
        // 存储用户
        return true
    }
    
    func retrieve() -> User? {
        // 检索用户
        return User(id: "1", name: "Test")
    }
}

class GenericService<S: Storable> {
    private let storage: S
    
    init(storage: S) {
        self.storage = storage
    }
    
    func save(_ item: S.StoredType) -> Bool {
        return storage.store(item)
    }
    
    func load() -> S.StoredType? {
        return storage.retrieve()
    }
}

// 使用
let userStorage = UserStorage()
let userService = GenericService(storage: userStorage)
```

### 工厂模式

工厂模式是依赖注入的一种常见实现方式，尤其是当对象的创建过程较为复杂时。

**基本工厂模式：**

```swift
protocol APIClientProtocol {
    func request<T: Decodable>(endpoint: String, completion: @escaping (Result<T, Error>) -> Void)
}

class APIClient: APIClientProtocol {
    func request<T: Decodable>(endpoint: String, completion: @escaping (Result<T, Error>) -> Void) {
        // 实际的网络请求实现
    }
}

protocol ServiceFactory {
    func makeAPIClient() -> APIClientProtocol
    func makeUserService() -> UserServiceProtocol
    func makeProductService() -> ProductServiceProtocol
}

class DefaultServiceFactory: ServiceFactory {
    func makeAPIClient() -> APIClientProtocol {
        return APIClient()
    }
    
    func makeUserService() -> UserServiceProtocol {
        let apiClient = makeAPIClient()
        return UserService(apiClient: apiClient)
    }
    
    func makeProductService() -> ProductServiceProtocol {
        let apiClient = makeAPIClient()
        return ProductService(apiClient: apiClient)
    }
}

protocol UserServiceProtocol {
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void)
}

class UserService: UserServiceProtocol {
    private let apiClient: APIClientProtocol
    
    init(apiClient: APIClientProtocol) {
        self.apiClient = apiClient
    }
    
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void) {
        apiClient.request(endpoint: "users/\(id)") { (result: Result<User, Error>) in
            completion(result)
        }
    }
}

protocol ProductServiceProtocol {
    func fetchProduct(id: String, completion: @escaping (Result<Product, Error>) -> Void)
}

class ProductService: ProductServiceProtocol {
    private let apiClient: APIClientProtocol
    
    init(apiClient: APIClientProtocol) {
        self.apiClient = apiClient
    }
    
    func fetchProduct(id: String, completion: @escaping (Result<Product, Error>) -> Void) {
        apiClient.request(endpoint: "products/\(id)") { (result: Result<Product, Error>) in
            completion(result)
        }
    }
}

// 使用
let factory = DefaultServiceFactory()
let userService = factory.makeUserService()
let productService = factory.makeProductService()

// 在视图控制器中使用
class UserViewController: UIViewController {
    private let userService: UserServiceProtocol
    
    init(userService: UserServiceProtocol) {
        self.userService = userService
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        userService.fetchUser(id: "123") { result in
            // 处理结果
        }
    }
}

// 创建视图控制器
let factory = DefaultServiceFactory()
let userService = factory.makeUserService()
let userViewController = UserViewController(userService: userService)
```

**抽象工厂模式：**

抽象工厂模式可以让我们创建相关对象的家族，而不需要指定其具体类。

```swift
// 抽象工厂协议
protocol ServiceFactoryProtocol {
    func makeNetworkService() -> NetworkServiceProtocol
    func makeDatabaseService() -> DatabaseServiceProtocol
    func makeAuthService() -> AuthServiceProtocol
}

// 生产环境工厂
class ProductionServiceFactory: ServiceFactoryProtocol {
    func makeNetworkService() -> NetworkServiceProtocol {
        return RealNetworkService()
    }
    
    func makeDatabaseService() -> DatabaseServiceProtocol {
        return SQLiteDatabaseService()
    }
    
    func makeAuthService() -> AuthServiceProtocol {
        let networkService = makeNetworkService()
        return RealAuthService(networkService: networkService)
    }
}

// 测试环境工厂
class TestServiceFactory: ServiceFactoryProtocol {
    func makeNetworkService() -> NetworkServiceProtocol {
        return MockNetworkService()
    }
    
    func makeDatabaseService() -> DatabaseServiceProtocol {
        return InMemoryDatabaseService()
    }
    
    func makeAuthService() -> AuthServiceProtocol {
        return MockAuthService()
    }
}

// 依赖于工厂的应用
class Application {
    private let serviceFactory: ServiceFactoryProtocol
    
    init(serviceFactory: ServiceFactoryProtocol) {
        self.serviceFactory = serviceFactory
    }
    
    func start() {
        let authService = serviceFactory.makeAuthService()
        let networkService = serviceFactory.makeNetworkService()
        let databaseService = serviceFactory.makeDatabaseService()
        
        // 使用这些服务...
    }
}

// 使用
#if DEBUG
let factory = TestServiceFactory()
#else
let factory = ProductionServiceFactory()
#endif

let app = Application(serviceFactory: factory)
app.start()
```

### 服务定位器

服务定位器是一种环境注入的形式，它提供了一个中心位置来注册和检索依赖项。虽然这种方法有一些缺点（如隐藏依赖项），但在某些情况下它可能很有用。

**基本服务定位器：**

```swift
class ServiceLocator {
    static let shared = ServiceLocator()
    
    private var services: [String: Any] = [:]
    
    private init() {}
    
    func register<T>(_ service: T, for key: String = String(describing: T.self)) {
        services[key] = service
    }
    
    func resolve<T>(_ key: String = String(describing: T.self)) -> T? {
        return services[key] as? T
    }
}

// 注册服务
ServiceLocator.shared.register(RealNetworkService() as NetworkServiceProtocol)
ServiceLocator.shared.register(SQLiteDatabaseService() as DatabaseServiceProtocol)

// 使用服务
class UserService {
    private let networkService: NetworkServiceProtocol
    
    init() {
        // 从服务定位器中解析依赖项
        guard let networkService = ServiceLocator.shared.resolve() as NetworkServiceProtocol? else {
            fatalError("NetworkService not registered")
        }
        
        self.networkService = networkService
    }
    
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void) {
        // 使用 networkService...
    }
}
```

**类型安全的服务定位器：**

通过使用泛型，我们可以创建一个更加类型安全的服务定位器。

```swift
class TypeSafeServiceLocator {
    static let shared = TypeSafeServiceLocator()
    
    private var services: [ObjectIdentifier: Any] = [:]
    
    private init() {}
    
    func register<T>(_ service: T, for protocolType: T.Type) {
        let key = ObjectIdentifier(protocolType)
        services[key] = service
    }
    
    func resolve<T>(_ protocolType: T.Type = T.self) -> T? {
        let key = ObjectIdentifier(protocolType)
        return services[key] as? T
    }
}

// 注册服务
let locator = TypeSafeServiceLocator.shared
locator.register(RealNetworkService(), for: NetworkServiceProtocol.self)
locator.register(SQLiteDatabaseService(), for: DatabaseServiceProtocol.self)

// 使用服务
class UserService {
    private let networkService: NetworkServiceProtocol
    
    init() {
        // 从服务定位器中解析依赖项
        guard let networkService = TypeSafeServiceLocator.shared.resolve(NetworkServiceProtocol.self) else {
            fatalError("NetworkService not registered")
        }
        
        self.networkService = networkService
    }
    
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void) {
        // 使用 networkService...
    }
}
```

**使用类型擦除：**

Swift 的类型擦除技术可以帮助我们创建更灵活的依赖注入系统。

```swift
struct AnyService<T> {
    private let _fetch: (String) -> T?
    
    init<S: ServiceType>(_ service: S) where S.ResultType == T {
        _fetch = service.fetch
    }
    
    func fetch(_ key: String) -> T? {
        return _fetch(key)
    }
}

protocol ServiceType {
    associatedtype ResultType
    func fetch(_ key: String) -> ResultType?
}

struct UserService: ServiceType {
    typealias ResultType = User
    
    func fetch(_ key: String) -> User? {
        // 实现获取用户的逻辑
        return User(id: key, name: "User \(key)")
    }
}

struct ProductService: ServiceType {
    typealias ResultType = Product
    
    func fetch(_ key: String) -> Product? {
        // 实现获取产品的逻辑
        return Product(id: key, name: "Product \(key)", price: 99.9)
    }
}

// 使用
let userService = UserService()
let productService = ProductService()

let anyUserService = AnyService<User>(userService)
let anyProductService = AnyService<Product>(productService)

if let user = anyUserService.fetch("123") {
    print("Found user: \(user.name)")
}

if let product = anyProductService.fetch("456") {
    print("Found product: \(product.name), price: \(product.price)")
}
```

这些是在 Swift 中实现依赖注入的一些常见方法。选择哪种方法取决于你的项目需求、团队偏好和代码复杂性。在大多数情况下，简单的基于协议的依赖注入是一个很好的起点，随着项目的增长，你可以根据需要引入更复杂的方法。

## 依赖注入容器

依赖注入容器是一种用于管理依赖项创建和生命周期的工具。它简化了依赖项的注册、解析和重用，特别是在依赖图较为复杂的应用中。

### 自定义依赖注入容器

在 Swift 中，我们可以创建自定义的依赖注入容器。以下是一个简单但功能完整的示例：

```swift
class DependencyContainer {
    // 用于存储工厂方法的字典
    private var factories: [ObjectIdentifier: Any] = [:]
    
    // 用于存储单例实例的字典
    private var singletons: [ObjectIdentifier: Any] = [:]
    
    // 注册一个类型，每次解析时创建新实例
    func register<T>(_ type: T.Type, factory: @escaping () -> T) {
        let key = ObjectIdentifier(type)
        factories[key] = factory
    }
    
    // 注册一个类型，解析时返回同一个实例（单例）
    func registerSingleton<T>(_ type: T.Type, factory: @escaping () -> T) {
        let key = ObjectIdentifier(type)
        let instance = factory()
        singletons[key] = instance
    }
    
    // 解析一个类型
    func resolve<T>(_ type: T.Type) -> T? {
        let key = ObjectIdentifier(type)
        
        // 首先检查是否有单例实例
        if let singleton = singletons[key] as? T {
            return singleton
        }
        
        // 然后检查是否有工厂方法
        if let factory = factories[key] as? () -> T {
            return factory()
        }
        
        return nil
    }
    
    // 注册一个实现了特定协议的具体类型
    func register<Protocol, Concrete>(_ protocolType: Protocol.Type, concrete: @escaping () -> Concrete) where Concrete: Protocol {
        let key = ObjectIdentifier(protocolType)
        factories[key] = concrete
    }
    
    // 注册一个实现了特定协议的单例
    func registerSingleton<Protocol, Concrete>(_ protocolType: Protocol.Type, concrete: @escaping () -> Concrete) where Concrete: Protocol {
        let key = ObjectIdentifier(protocolType)
        let instance = concrete()
        singletons[key] = instance
    }
}

// 使用示例
protocol NetworkServiceProtocol {
    func fetchData(from url: URL, completion: @escaping (Data?, Error?) -> Void)
}

class RealNetworkService: NetworkServiceProtocol {
    func fetchData(from url: URL, completion: @escaping (Data?, Error?) -> Void) {
        URLSession.shared.dataTask(with: url) { data, response, error in
            completion(data, error)
        }.resume()
    }
}

class MockNetworkService: NetworkServiceProtocol {
    var mockedData: Data?
    var mockedError: Error?
    
    func fetchData(from url: URL, completion: @escaping (Data?, Error?) -> Void) {
        completion(mockedData, mockedError)
    }
}

class UserService {
    private let networkService: NetworkServiceProtocol
    
    init(networkService: NetworkServiceProtocol) {
        self.networkService = networkService
    }
    
    func fetchUser(id: String, completion: @escaping (User?, Error?) -> Void) {
        let url = URL(string: "https://api.example.com/users/\(id)")!
        networkService.fetchData(from: url) { data, error in
            if let error = error {
                completion(nil, error)
                return
            }
            
            guard let data = data else {
                completion(nil, NSError(domain: "UserService", code: 0, userInfo: [NSLocalizedDescriptionKey: "No data received"]))
                return
            }
            
            do {
                let user = try JSONDecoder().decode(User.self, from: data)
                completion(user, nil)
            } catch {
                completion(nil, error)
            }
        }
    }
}

// 设置依赖注入容器
let container = DependencyContainer()

#if DEBUG
// 在测试环境使用 MockNetworkService
container.registerSingleton(NetworkServiceProtocol.self) {
    let mockService = MockNetworkService()
    mockService.mockedData = "{\"id\":\"123\",\"name\":\"Test User\"}".data(using: .utf8)
    return mockService
}
#else
// 在生产环境使用 RealNetworkService
container.registerSingleton(NetworkServiceProtocol.self) {
    return RealNetworkService()
}
#endif

// 注册 UserService，它依赖于 NetworkServiceProtocol
container.register(UserService.self) {
    guard let networkService = container.resolve(NetworkServiceProtocol.self) else {
        fatalError("NetworkServiceProtocol not registered")
    }
    return UserService(networkService: networkService)
}

// 在视图控制器中使用
class UserViewController: UIViewController {
    private var userService: UserService!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 从容器中解析 UserService
        userService = container.resolve(UserService.self)
        
        // 使用 userService
        userService.fetchUser(id: "123") { user, error in
            if let user = user {
                // 更新 UI
                print("User: \(user.name)")
            } else if let error = error {
                // 处理错误
                print("Error: \(error)")
            }
        }
    }
}
```

**高级功能：**

我们可以扩展依赖注入容器以支持更多高级功能：

```swift
class AdvancedDependencyContainer {
    private var factories: [ObjectIdentifier: Any] = [:]
    private var singletons: [ObjectIdentifier: Any] = [:]
    
    // 支持依赖容器层级
    private weak var parent: AdvancedDependencyContainer?
    
    init(parent: AdvancedDependencyContainer? = nil) {
        self.parent = parent
    }
    
    // 注册一个类型，支持名称（用于同一类型的多个实现）
    func register<T>(_ type: T.Type, name: String? = nil, factory: @escaping (AdvancedDependencyContainer) -> T) {
        let key = makeKey(for: type, name: name)
        factories[key] = factory
    }
    
    // 注册单例
    func registerSingleton<T>(_ type: T.Type, name: String? = nil, factory: @escaping (AdvancedDependencyContainer) -> T) {
        let key = makeKey(for: type, name: name)
        singletons[key] = factory(self)
    }
    
    // 解析类型，支持名称和父容器查找
    func resolve<T>(_ type: T.Type, name: String? = nil) -> T? {
        let key = makeKey(for: type, name: name)
        
        // 首先检查单例
        if let singleton = singletons[key] as? T {
            return singleton
        }
        
        // 然后检查工厂
        if let factory = factories[key] as? (AdvancedDependencyContainer) -> T {
            return factory(self)
        }
        
        // 最后检查父容器
        if let parent = parent {
            return parent.resolve(type, name: name)
        }
        
        return nil
    }
    
    // 为类型和名称创建唯一键
    private func makeKey<T>(for type: T.Type, name: String?) -> ObjectIdentifier {
        let typeId = ObjectIdentifier(type)
        if let name = name {
            let combinedType = "\(typeId):\(name)" as AnyObject
            return ObjectIdentifier(combinedType)
        }
        return typeId
    }
    
    // 创建子容器
    func makeChildContainer() -> AdvancedDependencyContainer {
        return AdvancedDependencyContainer(parent: self)
    }
}

// 使用示例

// 创建应用级别的容器
let appContainer = AdvancedDependencyContainer()

// 注册基础服务
appContainer.registerSingleton(NetworkServiceProtocol.self) { _ in
    return RealNetworkService()
}

appContainer.registerSingleton(LoggerProtocol.self) { _ in
    return ConsoleLogger()
}

// 注册多个同一类型的实现，使用名称区分
appContainer.registerSingleton(DatabaseProtocol.self, name: "sqlite") { _ in
    return SQLiteDatabase()
}

appContainer.registerSingleton(DatabaseProtocol.self, name: "realm") { _ in
    return RealmDatabase()
}

// 注册依赖于其他服务的服务
appContainer.registerSingleton(UserServiceProtocol.self) { container in
    guard let networkService = container.resolve(NetworkServiceProtocol.self),
          let database = container.resolve(DatabaseProtocol.self, name: "sqlite") else {
        fatalError("Required dependencies not registered")
    }
    
    return UserService(networkService: networkService, database: database)
}

// 为特定功能创建子容器
let featuredProductsContainer = appContainer.makeChildContainer()

// 在子容器中注册特定功能所需的服务
featuredProductsContainer.register(ProductServiceProtocol.self) { container in
    guard let networkService = container.resolve(NetworkServiceProtocol.self) else {
        fatalError("NetworkServiceProtocol not registered")
    }
    
    // 使用特定于功能的配置
    return FeaturedProductService(networkService: networkService, featuredOnly: true)
}

// 在视图控制器中使用
class ProductViewController: UIViewController {
    private var productService: ProductServiceProtocol!
    
    init(container: AdvancedDependencyContainer) {
        super.init(nibName: nil, bundle: nil)
        productService = container.resolve(ProductServiceProtocol.self)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 使用依赖项
        productService.fetchProducts { products in
            // 更新 UI
        }
    }
}

// 创建视图控制器
let productViewController = ProductViewController(container: featuredProductsContainer)
```

### 第三方依赖注入框架

虽然我们可以创建自定义的依赖注入容器，但在实际项目中，使用成熟的第三方框架可能更加方便。以下是 Swift 生态系统中一些流行的依赖注入框架：

#### Swinject

[Swinject](https://github.com/Swinject/Swinject) 是 Swift 最流行的依赖注入框架之一，它提供了轻量级但功能强大的 API。

**基本用法：**

```swift
import Swinject

// 创建容器
let container = Container()

// 注册服务
container.register(NetworkServiceProtocol.self) { _ in
    return RealNetworkService()
}

container.register(UserServiceProtocol.self) { resolver in
    guard let networkService = resolver.resolve(NetworkServiceProtocol.self) else {
        fatalError("NetworkServiceProtocol not registered")
    }
    
    return UserService(networkService: networkService)
}

// 解析服务
let userService = container.resolve(UserServiceProtocol.self)!
```

**高级功能：**

Swinject 支持许多高级功能，如对象作用域、命名注册、循环依赖解析等。

```swift
import Swinject

let container = Container()

// 注册为单例
container.register(NetworkServiceProtocol.self) { _ in
    return RealNetworkService()
}.inObjectScope(.container) // 在容器生命周期内为单例

// 使用名称注册多个实现
container.register(DatabaseProtocol.self, name: "sqlite") { _ in
    return SQLiteDatabase()
}

container.register(DatabaseProtocol.self, name: "realm") { _ in
    return RealmDatabase()
}

// 使用参数注册
container.register(UserServiceProtocol.self) { (resolver, apiKey: String) in
    let networkService = resolver.resolve(NetworkServiceProtocol.self)!
    return UserService(networkService: networkService, apiKey: apiKey)
}

// 使用参数解析
let userService = container.resolve(UserServiceProtocol.self, argument: "my-api-key")!

// 组装器模式
let assembler = Assembler([
    NetworkAssembly(),
    DatabaseAssembly(),
    ServiceAssembly()
])

class NetworkAssembly: Assembly {
    func assemble(container: Container) {
        container.register(NetworkServiceProtocol.self) { _ in
            return RealNetworkService()
        }.inObjectScope(.container)
    }
}
```

#### Cleanse

[Cleanse](https://github.com/square/Cleanse) 是由 Square 开发的依赖注入框架，它受到 Google 的 Guice 框架的启发。Cleanse 的特点是类型安全和编译时验证。

**基本用法：**

```swift
import Cleanse

// 定义模块
struct NetworkModule: Cleanse.Module {
    static func configure(binder: Binder<Unscoped>) {
        binder.bind(NetworkServiceProtocol.self)
            .to(factory: RealNetworkService.init)
    }
}

struct ServiceModule: Cleanse.Module {
    static func configure(binder: Binder<Unscoped>) {
        binder.bind(UserServiceProtocol.self)
            .to { (networkService: NetworkServiceProtocol) in
                return UserService(networkService: networkService)
            }
    }
}

// 定义组件
struct AppComponent: Cleanse.RootComponent {
    typealias Root = UserServiceProtocol
    
    static func configure(binder: Binder<Singleton>) {
        binder.install(NetworkModule.self)
        binder.install(ServiceModule.self)
    }
}

// 使用
let userService = try! ComponentFactory.of(AppComponent.self).build()
```

#### Needle

[Needle](https://github.com/uber/needle) 是由 Uber 开发的依赖注入框架，它的特点是在编译时生成代码，减少运行时开销，并提供更好的错误检查。

**基本用法：**

```swift
import NeedleFoundation

// 基础组件
protocol NetworkServiceDependency {
    var networkService: NetworkServiceProtocol { get }
}

class NetworkComponent: Component<EmptyDependency> {
    var networkService: NetworkServiceProtocol {
        return shared {
            RealNetworkService()
        }
    }
}

// 依赖其他组件的组件
protocol UserServiceDependency: NetworkServiceDependency {}

class UserComponent: Component<UserServiceDependency> {
    var userService: UserServiceProtocol {
        return shared {
            UserService(networkService: dependency.networkService)
        }
    }
}

// 根组件
class RootComponent: BootstrapComponent {
    var networkComponent: NetworkComponent {
        return NetworkComponent(parent: self)
    }
    
    var userComponent: UserComponent {
        return UserComponent(parent: self)
    }
}

// 使用
let rootComponent = RootComponent()
let userService = rootComponent.userComponent.userService
```

#### DITranquillity

[DITranquillity](https://github.com/ivlevAstef/DITranquillity) 是一个功能丰富的依赖注入框架，支持多种注册方式和生命周期管理。

**基本用法：**

```swift
import DITranquillity

// 创建容器
let container = DIContainer()

// 注册服务
container.register(RealNetworkService.init)
    .as(NetworkServiceProtocol.self)
    .lifetime(.single)

container.register { (networkService: NetworkServiceProtocol) -> UserService in
    return UserService(networkService: networkService)
}
.as(UserServiceProtocol.self)

// 使用模块
class AppModule: DIModule {
    static func load(container: DIContainer) {
        container.register(RealNetworkService.init)
            .as(NetworkServiceProtocol.self)
            .lifetime(.single)
        
        container.register { (networkService: NetworkServiceProtocol) -> UserService in
            return UserService(networkService: networkService)
        }
        .as(UserServiceProtocol.self)
    }
}

container.append(module: AppModule.self)

// 创建框架并解析服务
let userService: UserServiceProtocol = try! container.resolve()
```

这些第三方框架提供了比自定义解决方案更丰富的功能和更好的性能，适合在中大型项目中使用。选择哪个框架取决于项目需求、团队偏好和对特定功能的需要。

## 依赖注入在测试中的应用

依赖注入的一个主要优势是提高代码的可测试性。通过依赖注入，我们可以轻松地用测试替身（Test Doubles）替换真实依赖项，从而实现单元测试和集成测试。

### 单元测试

单元测试的目标是测试单个组件的行为，而不依赖于其外部依赖项。依赖注入使这一目标变得更容易实现。

**基本示例：**

```swift
// 被测试的类
class UserViewModel {
    private let userService: UserServiceProtocol
    
    var userName: String = ""
    var isLoading: Bool = false
    var errorMessage: String?
    
    init(userService: UserServiceProtocol) {
        self.userService = userService
    }
    
    func loadUser(id: String, completion: @escaping () -> Void) {
        isLoading = true
        errorMessage = nil
        
        userService.fetchUser(id: id) { [weak self] result in
            self?.isLoading = false
            
            switch result {
            case .success(let user):
                self?.userName = user.name
            case .failure(let error):
                self?.errorMessage = error.localizedDescription
            }
            
            completion()
        }
    }
}

// 测试
import XCTest

class UserViewModelTests: XCTestCase {
    func testLoadUserSuccess() {
        // 准备
        let mockUserService = MockUserService()
        mockUserService.mockResult = .success(User(id: "123", name: "测试用户"))
        
        let viewModel = UserViewModel(userService: mockUserService)
        
        let expectation = self.expectation(description: "User loading completes")
        
        // 执行
        viewModel.loadUser(id: "123") {
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 1.0, handler: nil)
        
        // 验证
        XCTAssertFalse(viewModel.isLoading)
        XCTAssertNil(viewModel.errorMessage)
        XCTAssertEqual(viewModel.userName, "测试用户")
    }
    
    func testLoadUserFailure() {
        // 准备
        let mockUserService = MockUserService()
        let testError = NSError(domain: "test", code: 0, userInfo: [NSLocalizedDescriptionKey: "网络错误"])
        mockUserService.mockResult = .failure(testError)
        
        let viewModel = UserViewModel(userService: mockUserService)
        
        let expectation = self.expectation(description: "User loading completes with error")
        
        // 执行
        viewModel.loadUser(id: "123") {
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 1.0, handler: nil)
        
        // 验证
        XCTAssertFalse(viewModel.isLoading)
        XCTAssertEqual(viewModel.errorMessage, "网络错误")
        XCTAssertEqual(viewModel.userName, "")
    }
}

// 测试替身
class MockUserService: UserServiceProtocol {
    var mockResult: Result<User, Error>!
    
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void) {
        completion(mockResult)
    }
}
```

**使用更高级的模拟技术：**

随着测试变得更加复杂，我们可能需要更高级的模拟技术，如验证调用次数、捕获参数等。

```swift
class AdvancedMockUserService: UserServiceProtocol {
    // 存储调用信息
    struct Call {
        let id: String
    }
    
    var calls: [Call] = []
    var mockResult: Result<User, Error>!
    var completionDelay: TimeInterval = 0
    
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void) {
        // 记录调用
        calls.append(Call(id: id))
        
        // 模拟异步行为
        DispatchQueue.main.asyncAfter(deadline: .now() + completionDelay) {
            completion(self.mockResult)
        }
    }
    
    // 辅助方法：验证调用次数
    func verifyFetchUserCalledOnce(with id: String? = nil, file: StaticString = #file, line: UInt = #line) {
        if calls.count != 1 {
            XCTFail("Expected fetchUser to be called once, but was called \(calls.count) times", file: file, line: line)
            return
        }
        
        if let id = id, calls.first?.id != id {
            XCTFail("Expected fetchUser to be called with id \(id), but was called with id \(calls.first?.id ?? "nil")", file: file, line: line)
        }
    }
}

// 更复杂的测试示例
class AdvancedUserViewModelTests: XCTestCase {
    func testLoadUserCallsServiceWithCorrectID() {
        // 准备
        let mockUserService = AdvancedMockUserService()
        mockUserService.mockResult = .success(User(id: "123", name: "测试用户"))
        
        let viewModel = UserViewModel(userService: mockUserService)
        
        let expectation = self.expectation(description: "User loading completes")
        
        // 执行
        viewModel.loadUser(id: "123") {
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 1.0, handler: nil)
        
        // 验证
        mockUserService.verifyFetchUserCalledOnce(with: "123")
    }
    
    func testConcurrentLoads() {
        // 准备
        let mockUserService = AdvancedMockUserService()
        mockUserService.mockResult = .success(User(id: "123", name: "测试用户"))
        mockUserService.completionDelay = 0.5
        
        let viewModel = UserViewModel(userService: mockUserService)
        
        let expectation1 = self.expectation(description: "First load completes")
        let expectation2 = self.expectation(description: "Second load completes")
        
        // 执行 - 两次连续加载
        viewModel.loadUser(id: "123") {
            expectation1.fulfill()
        }
        
        viewModel.loadUser(id: "456") {
            expectation2.fulfill()
        }
        
        waitForExpectations(timeout: 1.0, handler: nil)
        
        // 验证
        XCTAssertEqual(mockUserService.calls.count, 2)
        XCTAssertEqual(mockUserService.calls[0].id, "123")
        XCTAssertEqual(mockUserService.calls[1].id, "456")
    }
}
```

### 使用 Mock 对象

Mock 对象是测试替身的一种，它们可以验证与被测试代码的交互。下面是创建和使用 Mock 对象的几种方法：

**手动创建 Mock：**

```swift
protocol DataProviderProtocol {
    func fetchData(completion: @escaping (Result<[String], Error>) -> Void)
    func saveData(_ data: [String], completion: @escaping (Bool) -> Void)
}

class MockDataProvider: DataProviderProtocol {
    enum CallType {
        case fetchData
        case saveData([String])
    }
    
    var calls: [CallType] = []
    var fetchDataResult: Result<[String], Error> = .success([])
    var saveDataResult: Bool = true
    
    func fetchData(completion: @escaping (Result<[String], Error>) -> Void) {
        calls.append(.fetchData)
        completion(fetchDataResult)
    }
    
    func saveData(_ data: [String], completion: @escaping (Bool) -> Void) {
        calls.append(.saveData(data))
        completion(saveDataResult)
    }
}

// 测试
class DataManagerTests: XCTestCase {
    func testDataManager() {
        let mockProvider = MockDataProvider()
        mockProvider.fetchDataResult = .success(["Item 1", "Item 2"])
        
        let dataManager = DataManager(dataProvider: mockProvider)
        
        let expectation = self.expectation(description: "Data fetched")
        
        dataManager.loadData {
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 1.0, handler: nil)
        
        // 验证调用
        XCTAssertEqual(mockProvider.calls.count, 1)
        if case .fetchData = mockProvider.calls.first! {
            // 调用类型正确
        } else {
            XCTFail("Expected fetchData to be called")
        }
        
        // 验证数据管理器状态
        XCTAssertEqual(dataManager.items.count, 2)
    }
}
```

**使用第三方框架：**

有一些第三方框架可以简化 Mock 对象的创建和使用，如 [Mockingbird](https://github.com/birdrides/mockingbird)。

```swift
// 使用 Mockingbird 框架
import Mockingbird
import XCTest

class DataManagerTests: XCTestCase {
    func testDataManager() {
        // 创建 mock
        let mockProvider = mock(DataProviderProtocol.self)
        
        // 设置期望行为
        given(mockProvider.fetchData(completion: any()))
            .will { completion in
                completion(.success(["Item 1", "Item 2"]))
            }
        
        let dataManager = DataManager(dataProvider: mockProvider)
        
        let expectation = self.expectation(description: "Data fetched")
        
        dataManager.loadData {
            expectation.fulfill()
        }
        
        waitForExpectations(timeout: 1.0, handler: nil)
        
        // 验证调用
        verify(mockProvider.fetchData(completion: any())).wasCalled()
        
        // 验证数据管理器状态
        XCTAssertEqual(dataManager.items.count, 2)
    }
}
```

### 测试替身

除了 Mock 对象外，还有其他几种类型的测试替身，每种都有其特定的用途：

**1. Stub（存根）：**

Stub 提供了固定的响应，不关心输入参数，也不验证调用。

```swift
class StubNetworkService: NetworkServiceProtocol {
    let stubbedData: Data
    
    init(stubbedData: Data) {
        self.stubbedData = stubbedData
    }
    
    func request(endpoint: String, completion: @escaping (Result<Data, Error>) -> Void) {
        // 忽略输入，返回预定的响应
        completion(.success(stubbedData))
    }
}

// 使用
let userJSON = """
{
    "id": "123",
    "name": "测试用户",
    "email": "test@example.com"
}
""".data(using: .utf8)!

let stubService = StubNetworkService(stubbedData: userJSON)
let userService = UserService(networkService: stubService)

// 测试 userService，它将始终接收相同的 JSON 数据
```

**2. Fake（伪造）：**

Fake 是真实实现的简化版本，通常用于替换复杂的外部依赖，如数据库或网络。

```swift
class InMemoryUserRepository: UserRepositoryProtocol {
    private var users: [String: User] = [:]
    
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void) {
        if let user = users[id] {
            completion(.success(user))
        } else {
            completion(.failure(NSError(domain: "InMemoryUserRepository", code: 0, userInfo: [NSLocalizedDescriptionKey: "User not found"])))
        }
    }
    
    func saveUser(_ user: User, completion: @escaping (Result<Void, Error>) -> Void) {
        users[user.id] = user
        completion(.success(()))
    }
    
    func deleteUser(id: String, completion: @escaping (Result<Void, Error>) -> Void) {
        users[id] = nil
        completion(.success(()))
    }
}

// 使用
let fakeRepository = InMemoryUserRepository()
let userManager = UserManager(repository: fakeRepository)

// 测试 userManager，它将使用内存中的用户存储
```

**3. Spy（间谍）：**

Spy 记录方法调用的信息，但不改变原始行为。

```swift
class NetworkServiceSpy: NetworkServiceProtocol {
    private let realService: NetworkServiceProtocol
    private(set) var requestCalls: [(endpoint: String)] = []
    
    init(realService: NetworkServiceProtocol) {
        self.realService = realService
    }
    
    func request(endpoint: String, completion: @escaping (Result<Data, Error>) -> Void) {
        // 记录调用
        requestCalls.append((endpoint: endpoint))
        
        // 委托给实际服务
        realService.request(endpoint: endpoint, completion: completion)
    }
}

// 使用
let realService = RealNetworkService()
let spyService = NetworkServiceSpy(realService: realService)
let userService = UserService(networkService: spyService)

// 使用 userService
userService.fetchUser(id: "123") { _ in }

// 验证调用
XCTAssertEqual(spyService.requestCalls.count, 1)
XCTAssertEqual(spyService.requestCalls.first?.endpoint, "users/123")
```

**4. Dummy（傀儡）：**

Dummy 对象是传递给方法但从不实际使用的对象。

```swift
class DummyLogger: LoggerProtocol {
    func log(_ message: String, level: LogLevel) {
        // 不做任何事
    }
}

// 使用
let dummyLogger = DummyLogger()
let service = Service(logger: dummyLogger)

// 测试 service 的行为，不关心日志记录
```

通过使用这些不同类型的测试替身，我们可以有效地隔离被测试的代码，使测试更加可靠和高效。依赖注入使这种隔离变得简单，因为我们可以轻松地替换真实依赖项为测试替身。

## 依赖注入在 UIKit 中的应用

依赖注入在 UIKit 应用程序中尤为重要，因为视图控制器通常依赖于多个服务和管理器。然而，UIKit 的某些特性（如 Storyboard）使得依赖注入变得有些复杂。下面是在 UIKit 中实现依赖注入的几种方法：

### 视图控制器中的依赖注入

最直接的方法是通过构造器或属性注入向视图控制器提供依赖项。

**手动实例化视图控制器：**

```swift
class UserViewController: UIViewController {
    private let userService: UserServiceProtocol
    private let analyticsService: AnalyticsServiceProtocol
    
    private let userId: String
    
    // 通过构造器注入依赖
    init(userId: String, userService: UserServiceProtocol, analyticsService: AnalyticsServiceProtocol) {
        self.userId = userId
        self.userService = userService
        self.analyticsService = analyticsService
        
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 使用注入的服务
        userService.fetchUser(id: userId) { [weak self] result in
            // 处理结果
        }
        
        analyticsService.trackScreenView("UserViewController")
    }
}

// 使用
let userService = container.resolve(UserServiceProtocol.self)!
let analyticsService = container.resolve(AnalyticsServiceProtocol.self)!
let viewController = UserViewController(userId: "123", userService: userService, analyticsService: analyticsService)

navigationController.pushViewController(viewController, animated: true)
```

### 使用 Storyboard

当使用 Storyboard 时，视图控制器通常由 UIKit 框架实例化，这使得构造器注入变得困难。以下是处理这种情况的几种方法：

**1. 属性注入：**

```swift
class UserViewController: UIViewController {
    var userService: UserServiceProtocol!
    var analyticsService: AnalyticsServiceProtocol!
    var userId: String!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 验证依赖项是否已注入
        guard userService != nil, analyticsService != nil, userId != nil else {
            fatalError("Dependencies not injected")
        }
        
        // 使用依赖项
        userService.fetchUser(id: userId) { [weak self] result in
            // 处理结果
        }
        
        analyticsService.trackScreenView("UserViewController")
    }
}

// 在 prepare(for:sender:) 中注入依赖项
override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
    if let userVC = segue.destination as? UserViewController {
        userVC.userService = container.resolve(UserServiceProtocol.self)
        userVC.analyticsService = container.resolve(AnalyticsServiceProtocol.self)
        userVC.userId = "123"
    }
}
```

**2. 使用工厂方法：**

```swift
// 在 Storyboard 中为视图控制器创建工厂
protocol ViewControllerFactory {
    func createUserViewController(userId: String) -> UserViewController
}

class DefaultViewControllerFactory: ViewControllerFactory {
    private let container: DependencyContainer
    
    init(container: DependencyContainer) {
        self.container = container
    }
    
    func createUserViewController(userId: String) -> UserViewController {
        // 从 Storyboard 加载视图控制器
        let storyboard = UIStoryboard(name: "Main", bundle: nil)
        let viewController = storyboard.instantiateViewController(withIdentifier: "UserViewController") as! UserViewController
        
        // 注入依赖项
        viewController.userService = container.resolve(UserServiceProtocol.self)
        viewController.analyticsService = container.resolve(AnalyticsServiceProtocol.self)
        viewController.userId = userId
        
        return viewController
    }
}

// 在 AppDelegate 或 SceneDelegate 中设置
let container = setupDependencyContainer()
let viewControllerFactory = DefaultViewControllerFactory(container: container)

// 使用工厂
let userViewController = viewControllerFactory.createUserViewController(userId: "123")
navigationController.pushViewController(userViewController, animated: true)
```

**3. 使用 Storyboard 的扩展方法：**

```swift
extension UIStoryboard {
    func instantiateViewController<T: UIViewController>(
        withIdentifier identifier: String,
        configure: (T) -> Void
    ) -> T {
        let viewController = instantiateViewController(withIdentifier: identifier) as! T
        configure(viewController)
        return viewController
    }
}

// 使用
let userViewController = storyboard.instantiateViewController(
    withIdentifier: "UserViewController",
    configure: { (viewController: UserViewController) in
        viewController.userService = container.resolve(UserServiceProtocol.self)
        viewController.analyticsService = container.resolve(AnalyticsServiceProtocol.self)
        viewController.userId = "123"
    }
)

navigationController.pushViewController(userViewController, animated: true)
```

### 在 Coordinator 模式中的应用

Coordinator 模式是一种处理应用程序导航的模式，它非常适合与依赖注入一起使用。Coordinator 可以负责创建视图控制器并注入其依赖项。

```swift
protocol Coordinator {
    func start()
}

class UserCoordinator: Coordinator {
    private let navigationController: UINavigationController
    private let container: DependencyContainer
    private let userId: String
    
    init(navigationController: UINavigationController, container: DependencyContainer, userId: String) {
        self.navigationController = navigationController
        self.container = container
        self.userId = userId
    }
    
    func start() {
        let userService = container.resolve(UserServiceProtocol.self)!
        let analyticsService = container.resolve(AnalyticsServiceProtocol.self)!
        
        let viewController = UserViewController(
            userId: userId,
            userService: userService,
            analyticsService: analyticsService
        )
        
        // 注入回调以处理导航
        viewController.onEditProfile = { [weak self] user in
            self?.showEditProfile(user: user)
        }
        
        navigationController.pushViewController(viewController, animated: true)
    }
    
    private func showEditProfile(user: User) {
        // 创建并配置编辑配置文件视图控制器，注入其依赖项
        // ...
    }
}

// 使用
let container = setupDependencyContainer()
let coordinator = UserCoordinator(
    navigationController: navigationController,
    container: container,
    userId: "123"
)
coordinator.start()
```

Coordinator 模式与依赖注入结合使用时，可以实现清晰的职责分离：
- Coordinator 负责导航和视图控制器的创建
- 依赖注入容器负责管理服务和其他依赖项
- 视图控制器只关注其 UI 和用户交互

## 依赖注入在 SwiftUI 中的应用

SwiftUI 提供了几种内置机制，使依赖注入变得更加简单。以下是在 SwiftUI 中实现依赖注入的几种方法：

### 使用 @Environment

SwiftUI 的 `@Environment` 属性包装器允许视图从环境中读取值。我们可以扩展 `EnvironmentValues` 来存储自定义依赖项。

```swift
// 定义环境键
private struct UserServiceKey: EnvironmentKey {
    static let defaultValue: UserServiceProtocol = DefaultUserService()
}

// 扩展 EnvironmentValues 以包含自定义服务
extension EnvironmentValues {
    var userService: UserServiceProtocol {
        get { self[UserServiceKey.self] }
        set { self[UserServiceKey.self] = newValue }
    }
}

// 在视图中使用环境值
struct UserView: View {
    let userId: String
    
    // 从环境中读取服务
    @Environment(\.userService) private var userService
    
    @State private var user: User?
    @State private var isLoading = false
    @State private var errorMessage: String?
    
    var body: some View {
        Group {
            if isLoading {
                ProgressView("加载中...")
            } else if let user = user {
                VStack {
                    Text(user.name)
                        .font(.title)
                    Text(user.email)
                        .font(.subheadline)
                    // 更多 UI...
                }
            } else if let errorMessage = errorMessage {
                Text("错误: \(errorMessage)")
                    .foregroundColor(.red)
            } else {
                Text("无数据")
            }
        }
        .onAppear {
            loadUser()
        }
    }
    
    private func loadUser() {
        isLoading = true
        errorMessage = nil
        
        userService.fetchUser(id: userId) { result in
            isLoading = false
            
            switch result {
            case .success(let loadedUser):
                user = loadedUser
            case .failure(let error):
                errorMessage = error.localizedDescription
            }
        }
    }
}

// 在应用程序或场景中设置环境
let userService = RealUserService()

ContentView()
    .environment(\.userService, userService)
```

### 使用 @EnvironmentObject

`@EnvironmentObject` 是另一种用于注入依赖项的属性包装器，特别适合于注入可观察对象。

```swift
// 定义可观察对象
class UserService: ObservableObject {
    @Published var currentUser: User?
    @Published var isLoading = false
    @Published var errorMessage: String?
    
    func fetchUser(id: String) {
        isLoading = true
        errorMessage = nil
        
        // 模拟网络请求
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            // 模拟成功响应
            self.currentUser = User(id: id, name: "测试用户", email: "test@example.com")
            self.isLoading = false
        }
    }
}

// 在视图中使用环境对象
struct UserProfileView: View {
    let userId: String
    
    // 从环境中读取服务
    @EnvironmentObject var userService: UserService
    
    var body: some View {
        Group {
            if userService.isLoading {
                ProgressView("加载中...")
            } else if let user = userService.currentUser {
                VStack {
                    Text(user.name)
                        .font(.title)
                    Text(user.email)
                        .font(.subheadline)
                    // 更多 UI...
                }
            } else if let errorMessage = userService.errorMessage {
                Text("错误: \(errorMessage)")
                    .foregroundColor(.red)
            } else {
                Text("无数据")
            }
        }
        .onAppear {
            userService.fetchUser(id: userId)
        }
    }
}

// 在应用程序或场景中设置环境对象
let userService = UserService()

ContentView()
    .environmentObject(userService)
```

### 使用 @ObservedObject

对于不需要全局共享的依赖项，可以使用 `@ObservedObject` 属性包装器，通过构造器注入依赖项。

```swift
// 定义视图模型
class UserViewModel: ObservableObject {
    private let userService: UserServiceProtocol
    
    @Published var user: User?
    @Published var isLoading = false
    @Published var errorMessage: String?
    
    init(userService: UserServiceProtocol) {
        self.userService = userService
    }
    
    func loadUser(id: String) {
        isLoading = true
        errorMessage = nil
        
        userService.fetchUser(id: id) { [weak self] result in
            guard let self = self else { return }
            
            self.isLoading = false
            
            switch result {
            case .success(let user):
                self.user = user
            case .failure(let error):
                self.errorMessage = error.localizedDescription
            }
        }
    }
}

// 在视图中使用
struct UserDetailView: View {
    let userId: String
    
    // 通过构造器注入视图模型
    @ObservedObject var viewModel: UserViewModel
    
    init(userId: String, userService: UserServiceProtocol) {
        self.userId = userId
        self.viewModel = UserViewModel(userService: userService)
    }
    
    var body: some View {
        Group {
            if viewModel.isLoading {
                ProgressView("加载中...")
            } else if let user = viewModel.user {
                VStack {
                    Text(user.name)
                        .font(.title)
                    Text(user.email)
                        .font(.subheadline)
                    // 更多 UI...
                }
            } else if let errorMessage = viewModel.errorMessage {
                Text("错误: \(errorMessage)")
                    .foregroundColor(.red)
            } else {
                Text("无数据")
            }
        }
        .onAppear {
            viewModel.loadUser(id: userId)
        }
    }
}

// 使用
let userService = RealUserService()
let userDetailView = UserDetailView(userId: "123", userService: userService)
```

### 组合依赖注入方法

在实际应用程序中，通常需要组合使用这些方法，根据依赖项的性质和共享范围选择最合适的方法。

```swift
// 应用程序级别的依赖项容器
class AppDependencies: ObservableObject {
    let userService: UserServiceProtocol
    let authService: AuthServiceProtocol
    let analyticsService: AnalyticsServiceProtocol
    
    init(
        userService: UserServiceProtocol = RealUserService(),
        authService: AuthServiceProtocol = RealAuthService(),
        analyticsService: AnalyticsServiceProtocol = RealAnalyticsService()
    ) {
        self.userService = userService
        self.authService = authService
        self.analyticsService = analyticsService
    }
}

// 为环境值添加自定义键
private struct UserServiceKey: EnvironmentKey {
    static let defaultValue: UserServiceProtocol = DefaultUserService()
}

private struct AuthServiceKey: EnvironmentKey {
    static let defaultValue: AuthServiceProtocol = DefaultAuthService()
}

extension EnvironmentValues {
    var userService: UserServiceProtocol {
        get { self[UserServiceKey.self] }
        set { self[UserServiceKey.self] = newValue }
    }
    
    var authService: AuthServiceProtocol {
        get { self[AuthServiceKey.self] }
        set { self[AuthServiceKey.self] = newValue }
    }
}

// 在 App 中设置依赖项
@main
struct MyApp: App {
    // 应用程序级别的依赖项
    @StateObject private var dependencies = AppDependencies()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                // 注入可观察对象
                .environmentObject(dependencies)
                // 注入单独的服务
                .environment(\.userService, dependencies.userService)
                .environment(\.authService, dependencies.authService)
        }
    }
}

// 在视图中使用
struct ContentView: View {
    @EnvironmentObject var dependencies: AppDependencies
    @Environment(\.userService) private var userService
    
    var body: some View {
        // 使用依赖项...
        
        // 为子视图传递依赖项
        UserDetailView(userId: "123", userService: userService)
    }
}
```

SwiftUI 的依赖注入机制提供了很大的灵活性，但也需要谨慎选择合适的方法，以避免过度复杂化代码。 

## 常见问题与解决方案

在使用依赖注入时，开发者可能会遇到一些常见问题。以下是这些问题及其解决方案：

### 循环依赖

循环依赖是指两个或多个对象相互依赖的情况，这可能导致内存泄漏或初始化问题。

**问题示例：**

```swift
// ServiceA 依赖 ServiceB
class ServiceA {
    private let serviceB: ServiceB
    
    init(serviceB: ServiceB) {
        self.serviceB = serviceB
    }
}

// ServiceB 依赖 ServiceA
class ServiceB {
    private let serviceA: ServiceA
    
    init(serviceA: ServiceA) {
        self.serviceA = serviceA
    }
}

// 尝试创建实例
// let serviceA = ServiceA(serviceB: serviceB) // 但 serviceB 需要 serviceA
// let serviceB = ServiceB(serviceA: serviceA) // 但 serviceA 需要 serviceB
// 陷入死锁！
```

**解决方案：**

1. **重新设计对象关系**：最好的解决方案是重新设计对象关系，避免循环依赖。

2. **使用协议打破循环**：通过引入协议，可以打破直接循环依赖。

   ```swift
   protocol ServiceAProtocol {
       func doSomething()
   }
   
   protocol ServiceBProtocol {
       func doSomethingElse()
   }
   
   class ServiceA: ServiceAProtocol {
       private let serviceB: ServiceBProtocol
       
       init(serviceB: ServiceBProtocol) {
           self.serviceB = serviceB
       }
       
       func doSomething() {
           // 实现...
       }
   }
   
   class ServiceB: ServiceBProtocol {
       weak var serviceA: ServiceAProtocol?
       
       func doSomethingElse() {
           // 实现...
       }
   }
   
   // 创建实例
   let serviceB = ServiceB()
   let serviceA = ServiceA(serviceB: serviceB)
   serviceB.serviceA = serviceA
   ```

3. **使用属性注入而非构造器注入**：在某些情况下，可以使用属性注入解决循环依赖问题。

   ```swift
   class ServiceA {
       var serviceB: ServiceB?
       
       func doSomething() {
           serviceB?.doSomethingElse()
       }
   }
   
   class ServiceB {
       var serviceA: ServiceA?
       
       func doSomethingElse() {
           serviceA?.doSomething()
       }
   }
   
   // 创建实例
   let serviceA = ServiceA()
   let serviceB = ServiceB()
   serviceA.serviceB = serviceB
   serviceB.serviceA = serviceA
   ```

4. **使用懒加载**：延迟初始化依赖项可以帮助解决某些循环依赖问题。

   ```swift
   class ServiceA {
       private let serviceB: ServiceB
       
       init(serviceB: ServiceB) {
           self.serviceB = serviceB
       }
   }
   
   class ServiceB {
       private let serviceAProvider: () -> ServiceA
       private lazy var serviceA: ServiceA = serviceAProvider()
       
       init(serviceAProvider: @escaping () -> ServiceA) {
           self.serviceAProvider = serviceAProvider
       }
   }
   
   // 创建实例
   var serviceA: ServiceA!
   let serviceB = ServiceB { serviceA }
   serviceA = ServiceA(serviceB: serviceB)
   ```

### 过度使用依赖注入

过度使用依赖注入可能导致代码变得复杂和难以理解。

**问题示例：**

```swift
// 为每个微小的功能都创建协议和注入依赖
protocol StringFormatterProtocol {
    func format(_ string: String) -> String
}

protocol DateFormatterProtocol {
    func format(_ date: Date) -> String
}

protocol NumberFormatterProtocol {
    func format(_ number: Double) -> String
}

class ViewModel {
    private let stringFormatter: StringFormatterProtocol
    private let dateFormatter: DateFormatterProtocol
    private let numberFormatter: NumberFormatterProtocol
    
    init(
        stringFormatter: StringFormatterProtocol,
        dateFormatter: DateFormatterProtocol,
        numberFormatter: NumberFormatterProtocol
    ) {
        self.stringFormatter = stringFormatter
        self.dateFormatter = dateFormatter
        self.numberFormatter = numberFormatter
    }
    
    // 使用注入的依赖项...
}

// 使用 - 过于复杂
let stringFormatter = DefaultStringFormatter()
let dateFormatter = DefaultDateFormatter()
let numberFormatter = DefaultNumberFormatter()
let viewModel = ViewModel(
    stringFormatter: stringFormatter,
    dateFormatter: dateFormatter,
    numberFormatter: numberFormatter
)
```

**解决方案：**

1. **只为真正需要抽象的组件创建协议**：不是每个类都需要一个协议。只为那些需要替换或模拟的组件创建协议。

   ```swift
   // 简化版本 - 只为核心服务创建协议
   class ViewModel {
       private let userService: UserServiceProtocol
       
       // 使用具体类型的简单格式化器
       private let dateFormatter = DateFormatter()
       private let numberFormatter = NumberFormatter()
       
       init(userService: UserServiceProtocol) {
           self.userService = userService
           
           // 配置格式化器
           dateFormatter.dateStyle = .medium
           numberFormatter.numberStyle = .decimal
       }
       
       // 使用服务和格式化器...
   }
   ```

2. **组合相关依赖项**：将相关的依赖项组合到一个更大的依赖项中。

   ```swift
   // 将所有格式化器组合到一个格式化服务中
   protocol FormattingServiceProtocol {
       func formatString(_ string: String) -> String
       func formatDate(_ date: Date) -> String
       func formatNumber(_ number: Double) -> String
   }
   
   class FormattingService: FormattingServiceProtocol {
       private let dateFormatter = DateFormatter()
       private let numberFormatter = NumberFormatter()
       
       init() {
           dateFormatter.dateStyle = .medium
           numberFormatter.numberStyle = .decimal
       }
       
       func formatString(_ string: String) -> String {
           return string.trimmingCharacters(in: .whitespacesAndNewlines)
       }
       
       func formatDate(_ date: Date) -> String {
           return dateFormatter.string(from: date)
       }
       
       func formatNumber(_ number: Double) -> String {
           return numberFormatter.string(from: NSNumber(value: number)) ?? "\(number)"
       }
   }
   
   // 使用简化后的依赖项
   class ViewModel {
       private let userService: UserServiceProtocol
       private let formattingService: FormattingServiceProtocol
       
       init(userService: UserServiceProtocol, formattingService: FormattingServiceProtocol) {
           self.userService = userService
           self.formattingService = formattingService
       }
       
       // 使用服务...
   }
   ```

### 管理复杂依赖图

随着应用程序的增长，依赖图可能变得非常复杂，导致难以管理和维护。

**问题示例：**

```swift
// 复杂的手动依赖图
let networkClient = NetworkClient(baseURL: "https://api.example.com")
let authService = AuthService(networkClient: networkClient)
let userService = UserService(networkClient: networkClient, authService: authService)
let productService = ProductService(networkClient: networkClient)
let cartService = CartService(productService: productService, userService: userService)
let paymentService = PaymentService(networkClient: networkClient, cartService: cartService)
let checkoutManager = CheckoutManager(cartService: cartService, paymentService: paymentService, userService: userService)

// 在多个地方重复这种复杂的设置...
```

**解决方案：**

1. **使用依赖注入容器**：如前面章节所述，依赖注入容器可以帮助管理复杂的依赖图。

   ```swift
   // 使用依赖注入容器
   let container = DependencyContainer()
   
   // 注册服务
   container.registerSingleton(NetworkClient.self) {
       return NetworkClient(baseURL: "https://api.example.com")
   }
   
   container.register(AuthServiceProtocol.self) { resolver in
       let networkClient = resolver.resolve(NetworkClient.self)!
       return AuthService(networkClient: networkClient)
   }
   
   // 注册更多服务...
   
   // 解析需要的服务
   let checkoutManager = container.resolve(CheckoutManager.self)!
   ```

2. **使用模块化架构**：将应用程序分解为模块，每个模块管理自己的依赖项。

   ```swift
   // 网络模块
   class NetworkModule {
       static func register(in container: DependencyContainer) {
           container.registerSingleton(NetworkClient.self) {
               return NetworkClient(baseURL: "https://api.example.com")
           }
       }
   }
   
   // 用户模块
   class UserModule {
       static func register(in container: DependencyContainer) {
           container.register(AuthServiceProtocol.self) { resolver in
               let networkClient = resolver.resolve(NetworkClient.self)!
               return AuthService(networkClient: networkClient)
           }
           
           container.register(UserServiceProtocol.self) { resolver in
               let networkClient = resolver.resolve(NetworkClient.self)!
               let authService = resolver.resolve(AuthServiceProtocol.self)!
               return UserService(networkClient: networkClient, authService: authService)
           }
       }
   }
   
   // 使用
   let container = DependencyContainer()
   NetworkModule.register(in: container)
   UserModule.register(in: container)
   // 注册其他模块...
   ```

3. **使用工厂方法**：为复杂对象创建工厂方法，隐藏依赖项的创建细节。

   ```swift
   protocol ServiceFactory {
       func makeUserService() -> UserServiceProtocol
       func makeProductService() -> ProductServiceProtocol
       func makeCartService() -> CartServiceProtocol
   }
   
   class DefaultServiceFactory: ServiceFactory {
       private let container: DependencyContainer
       
       init(container: DependencyContainer) {
           self.container = container
       }
       
       func makeUserService() -> UserServiceProtocol {
           return container.resolve(UserServiceProtocol.self)!
       }
       
       func makeProductService() -> ProductServiceProtocol {
           return container.resolve(ProductServiceProtocol.self)!
       }
       
       func makeCartService() -> CartServiceProtocol {
           return container.resolve(CartServiceProtocol.self)!
       }
   }
   
   // 使用
   let factory = DefaultServiceFactory(container: container)
   let userService = factory.makeUserService()
   ```

## 最佳实践

以下是在 iOS 开发中使用依赖注入的一些最佳实践：

### 什么时候使用依赖注入

依赖注入不是万能的，应该根据项目需求和复杂性来决定是否使用以及使用的程度：

1. **小型项目**：对于小型或简单的项目，可能不需要完整的依赖注入系统。简单的工厂方法或单例可能就足够了。

2. **中型项目**：考虑使用基本的依赖注入技术，如构造器注入和协议抽象，但可能不需要依赖注入容器。

3. **大型项目**：对于大型或复杂的项目，特别是有多个团队协作的项目，使用完整的依赖注入系统（包括容器）可能是值得的。

4. **测试驱动开发**：如果你正在进行测试驱动开发，依赖注入是必不可少的，因为它使单元测试变得更加简单。

### 哪种注入方式最适合

选择合适的依赖注入方式取决于具体情况：

1. **构造器注入**：这是首选方法，因为它使依赖项明确并强制在创建对象时提供依赖项。适用于必需的依赖项。

   ```swift
   class UserService {
       private let networkService: NetworkServiceProtocol
       
       init(networkService: NetworkServiceProtocol) {
           self.networkService = networkService
       }
   }
   ```

2. **属性注入**：当使用框架（如 UIKit）且无法控制对象创建时，或者对于可选依赖项，属性注入很有用。

   ```swift
   class ViewController: UIViewController {
       var userService: UserServiceProtocol!
       
       override func viewDidLoad() {
           super.viewDidLoad()
           assert(userService != nil, "UserService must be injected")
       }
   }
   ```

3. **方法注入**：当依赖项仅用于特定方法且不需要存储时，方法注入是合适的。

   ```swift
   class UserManager {
       func fetchUser(id: String, using networkService: NetworkServiceProtocol, completion: @escaping (User?) -> Void) {
           // 使用传入的 networkService 获取用户
       }
   }
   ```

4. **环境注入**：对于真正的全局依赖项（如日志记录或分析），环境注入可能是合适的。

   ```swift
   // 使用 SwiftUI 的环境
   struct ContentView: View {
       @Environment(\.logger) private var logger
       
       var body: some View {
           Button("Log Event") {
               logger.log("Button tapped")
           }
       }
   }
   ```

### 如何组织代码

良好的代码组织对于使依赖注入系统易于维护和理解至关重要：

1. **按功能组织代码**：将相关的服务、模型和视图控制器组织在一起，每个功能模块管理自己的依赖项。

   ```
   MyApp/
   ├── Core/
   │   ├── Network/
   │   ├── Storage/
   │   └── DI/
   ├── Features/
   │   ├── Authentication/
   │   │   ├── Services/
   │   │   ├── Models/
   │   │   ├── ViewControllers/
   │   │   └── AuthenticationAssembly.swift
   │   ├── UserProfile/
   │   └── Products/
   └── App/
       ├── AppDelegate.swift
       ├── SceneDelegate.swift
       └── AppAssembly.swift
   ```

2. **使用组装器模式**：创建负责注册和配置依赖项的组装器类。

   ```swift
   protocol Assembly {
       func register(in container: DependencyContainer)
   }
   
   class NetworkAssembly: Assembly {
       func register(in container: DependencyContainer) {
           container.registerSingleton(NetworkClient.self) {
               return NetworkClient(baseURL: "https://api.example.com")
           }
       }
   }
   
   class ServiceAssembly: Assembly {
       func register(in container: DependencyContainer) {
           container.register(UserServiceProtocol.self) { resolver in
               let networkClient = resolver.resolve(NetworkClient.self)!
               return UserService(networkClient: networkClient)
           }
       }
   }
   
   // 使用
   let container = DependencyContainer()
   let assemblies: [Assembly] = [
       NetworkAssembly(),
       ServiceAssembly()
   ]
   
   for assembly in assemblies {
       assembly.register(in: container)
   }
   ```

3. **清晰的依赖声明**：确保每个类都清晰地声明其依赖项，使用协议而非具体类。

   ```swift
   // 清晰声明依赖项
   protocol UserViewControllerDependencies {
       var userService: UserServiceProtocol { get }
       var analyticsService: AnalyticsServiceProtocol { get }
   }
   
   class UserViewController: UIViewController {
       private let dependencies: UserViewControllerDependencies
       
       init(dependencies: UserViewControllerDependencies) {
           self.dependencies = dependencies
           super.init(nibName: nil, bundle: nil)
       }
       
       required init?(coder: NSCoder) {
           fatalError("init(coder:) has not been implemented")
       }
   }
   ```

4. **避免全局状态**：尽量避免使用全局变量或单例来管理依赖项。如果需要全局访问，使用依赖注入容器。

   ```swift
   // 不好的做法
   class GlobalServices {
       static let shared = GlobalServices()
       
       let userService = UserService()
       let analyticsService = AnalyticsService()
   }
   
   // 更好的做法
   let container = DependencyContainer()
   // 注册服务...
   
   // 在应用程序启动时配置
   func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
       // 配置容器...
       
       let rootViewController = RootViewController(container: container)
       window?.rootViewController = rootViewController
       
       return true
   }
   ```

5. **不要过度工程化**：根据项目的复杂性和需求选择适当级别的依赖注入。对于简单的项目，简单的手动注入可能就足够了。 

## 实际案例

以下是依赖注入在常见 iOS 开发场景中的实际应用案例：

### 网络层

网络层是依赖注入特别有用的一个领域，因为它需要高度的可测试性和可配置性。

```swift
// 定义协议
protocol NetworkClientProtocol {
    func request<T: Decodable>(endpoint: String, method: HTTPMethod, parameters: [String: Any]?, completion: @escaping (Result<T, Error>) -> Void)
}

enum HTTPMethod: String {
    case get = "GET"
    case post = "POST"
    case put = "PUT"
    case delete = "DELETE"
}

// 实现
class NetworkClient: NetworkClientProtocol {
    private let baseURL: URL
    private let session: URLSession
    
    init(baseURL: String, session: URLSession = .shared) {
        guard let url = URL(string: baseURL) else {
            fatalError("Invalid base URL: \(baseURL)")
        }
        self.baseURL = url
        self.session = session
    }
    
    func request<T: Decodable>(endpoint: String, method: HTTPMethod, parameters: [String: Any]? = nil, completion: @escaping (Result<T, Error>) -> Void) {
        guard let url = URL(string: endpoint, relativeTo: baseURL) else {
            completion(.failure(NSError(domain: "NetworkError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])))
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        
        if let parameters = parameters {
            if method == .get {
                // 添加查询参数
                var components = URLComponents(url: url, resolvingAgainstBaseURL: true)!
                components.queryItems = parameters.map { URLQueryItem(name: $0.key, value: String(describing: $0.value)) }
                request.url = components.url
            } else {
                // 添加 JSON 主体
                do {
                    request.httpBody = try JSONSerialization.data(withJSONObject: parameters)
                    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
                } catch {
                    completion(.failure(error))
                    return
                }
            }
        }
        
        let task = session.dataTask(with: request) { data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse else {
                completion(.failure(NSError(domain: "NetworkError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }
            
            guard 200..<300 ~= httpResponse.statusCode else {
                completion(.failure(NSError(domain: "NetworkError", code: httpResponse.statusCode, userInfo: [NSLocalizedDescriptionKey: "HTTP error \(httpResponse.statusCode)"])))
                return
            }
            
            guard let data = data else {
                completion(.failure(NSError(domain: "NetworkError", code: 0, userInfo: [NSLocalizedDescriptionKey: "No data received"])))
                return
            }
            
            do {
                let decoder = JSONDecoder()
                let object = try decoder.decode(T.self, from: data)
                completion(.success(object))
            } catch {
                completion(.failure(error))
            }
        }
        
        task.resume()
    }
}

// 用于测试的模拟实现
class MockNetworkClient: NetworkClientProtocol {
    var mockResponses: [String: Any] = [:]
    var requestedEndpoints: [String] = []
    
    func request<T: Decodable>(endpoint: String, method: HTTPMethod, parameters: [String: Any]?, completion: @escaping (Result<T, Error>) -> Void) {
        requestedEndpoints.append(endpoint)
        
        guard let mockData = mockResponses[endpoint] else {
            completion(.failure(NSError(domain: "MockError", code: 0, userInfo: [NSLocalizedDescriptionKey: "No mock response for endpoint: \(endpoint)"])))
            return
        }
        
        if let error = mockData as? Error {
            completion(.failure(error))
        } else if let response = mockData as? T {
            completion(.success(response))
        } else if let data = mockData as? Data {
            do {
                let decoder = JSONDecoder()
                let object = try decoder.decode(T.self, from: data)
                completion(.success(object))
            } catch {
                completion(.failure(error))
            }
        } else {
            completion(.failure(NSError(domain: "MockError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid mock response type"])))
        }
    }
}

// 使用
struct User: Codable {
    let id: String
    let name: String
    let email: String
}

class UserService {
    private let networkClient: NetworkClientProtocol
    
    init(networkClient: NetworkClientProtocol) {
        self.networkClient = networkClient
    }
    
    func fetchUser(id: String, completion: @escaping (Result<User, Error>) -> Void) {
        networkClient.request(endpoint: "users/\(id)", method: .get, parameters: nil, completion: completion)
    }
    
    func createUser(name: String, email: String, completion: @escaping (Result<User, Error>) -> Void) {
        let parameters: [String: Any] = [
            "name": name,
            "email": email
        ]
        
        networkClient.request(endpoint: "users", method: .post, parameters: parameters, completion: completion)
    }
}

// 生产环境设置
let prodNetworkClient = NetworkClient(baseURL: "https://api.example.com")
let userService = UserService(networkClient: prodNetworkClient)

// 测试设置
let mockNetworkClient = MockNetworkClient()
mockNetworkClient.mockResponses["users/123"] = User(id: "123", name: "测试用户", email: "test@example.com")
let testUserService = UserService(networkClient: mockNetworkClient)

// 单元测试
func testFetchUser() {
    let mockNetworkClient = MockNetworkClient()
    mockNetworkClient.mockResponses["users/123"] = User(id: "123", name: "测试用户", email: "test@example.com")
    
    let userService = UserService(networkClient: mockNetworkClient)
    
    let expectation = XCTestExpectation(description: "Fetch user")
    
    userService.fetchUser(id: "123") { result in
        switch result {
        case .success(let user):
            XCTAssertEqual(user.id, "123")
            XCTAssertEqual(user.name, "测试用户")
            XCTAssertEqual(user.email, "test@example.com")
        case .failure:
            XCTFail("Expected success")
        }
        
        expectation.fulfill()
    }
    
    wait(for: [expectation], timeout: 1.0)
    
    XCTAssertEqual(mockNetworkClient.requestedEndpoints, ["users/123"])
}
```

### 数据持久化

数据持久化是另一个依赖注入非常有用的领域，因为它允许我们在测试中使用内存存储而不是实际的数据库。

```swift
// 定义协议
protocol UserStorageProtocol {
    func saveUser(_ user: User) throws
    func fetchUser(id: String) throws -> User?
    func deleteUser(id: String) throws
    func fetchAllUsers() throws -> [User]
}

// Core Data 实现
class CoreDataUserStorage: UserStorageProtocol {
    private let container: NSPersistentContainer
    
    init(container: NSPersistentContainer) {
        self.container = container
        container.loadPersistentStores { _, error in
            if let error = error {
                fatalError("Failed to load Core Data stack: \(error)")
            }
        }
    }
    
    func saveUser(_ user: User) throws {
        let context = container.viewContext
        
        // 检查用户是否已存在
        let fetchRequest: NSFetchRequest<UserEntity> = UserEntity.fetchRequest()
        fetchRequest.predicate = NSPredicate(format: "id == %@", user.id)
        
        let existingUsers = try context.fetch(fetchRequest)
        
        let userEntity: UserEntity
        
        if let existingUser = existingUsers.first {
            // 更新现有用户
            userEntity = existingUser
        } else {
            // 创建新用户
            userEntity = UserEntity(context: context)
            userEntity.id = user.id
        }
        
        userEntity.name = user.name
        userEntity.email = user.email
        
        try context.save()
    }
    
    func fetchUser(id: String) throws -> User? {
        let context = container.viewContext
        
        let fetchRequest: NSFetchRequest<UserEntity> = UserEntity.fetchRequest()
        fetchRequest.predicate = NSPredicate(format: "id == %@", id)
        
        let users = try context.fetch(fetchRequest)
        
        return users.first.map { User(id: $0.id!, name: $0.name!, email: $0.email!) }
    }
    
    func deleteUser(id: String) throws {
        let context = container.viewContext
        
        let fetchRequest: NSFetchRequest<UserEntity> = UserEntity.fetchRequest()
        fetchRequest.predicate = NSPredicate(format: "id == %@", id)
        
        let users = try context.fetch(fetchRequest)
        
        for user in users {
            context.delete(user)
        }
        
        try context.save()
    }
    
    func fetchAllUsers() throws -> [User] {
        let context = container.viewContext
        
        let fetchRequest: NSFetchRequest<UserEntity> = UserEntity.fetchRequest()
        
        let userEntities = try context.fetch(fetchRequest)
        
        return userEntities.map { User(id: $0.id!, name: $0.name!, email: $0.email!) }
    }
}

// 内存存储实现，用于测试
class InMemoryUserStorage: UserStorageProtocol {
    private var users: [String: User] = [:]
    
    func saveUser(_ user: User) throws {
        users[user.id] = user
    }
    
    func fetchUser(id: String) throws -> User? {
        return users[id]
    }
    
    func deleteUser(id: String) throws {
        users[id] = nil
    }
    
    func fetchAllUsers() throws -> [User] {
        return Array(users.values)
    }
}

// 用户仓库
class UserRepository {
    private let storage: UserStorageProtocol
    
    init(storage: UserStorageProtocol) {
        self.storage = storage
    }
    
    func saveUser(_ user: User) throws {
        try storage.saveUser(user)
    }
    
    func fetchUser(id: String) throws -> User? {
        return try storage.fetchUser(id: id)
    }
    
    func deleteUser(id: String) throws {
        try storage.deleteUser(id: id)
    }
    
    func fetchAllUsers() throws -> [User] {
        return try storage.fetchAllUsers()
    }
}

// 生产环境设置
let coreDataContainer = NSPersistentContainer(name: "MyApp")
let coreDataStorage = CoreDataUserStorage(container: coreDataContainer)
let userRepository = UserRepository(storage: coreDataStorage)

// 测试设置
let inMemoryStorage = InMemoryUserStorage()
let testUserRepository = UserRepository(storage: inMemoryStorage)

// 单元测试
func testUserRepository() {
    let storage = InMemoryUserStorage()
    let repository = UserRepository(storage: storage)
    
    let user = User(id: "123", name: "测试用户", email: "test@example.com")
    
    do {
        try repository.saveUser(user)
        
        guard let fetchedUser = try repository.fetchUser(id: "123") else {
            XCTFail("Failed to fetch user")
            return
        }
        
        XCTAssertEqual(fetchedUser.id, "123")
        XCTAssertEqual(fetchedUser.name, "测试用户")
        XCTAssertEqual(fetchedUser.email, "test@example.com")
        
        try repository.deleteUser(id: "123")
        
        XCTAssertNil(try repository.fetchUser(id: "123"))
    } catch {
        XCTFail("Test failed with error: \(error)")
    }
}
```

### 认证系统

认证系统通常需要与多个组件（如网络、存储和 UI）交互，这使其成为依赖注入的理想候选。

```swift
// 定义协议
protocol AuthenticationServiceProtocol {
    var currentUser: User? { get }
    func login(email: String, password: String, completion: @escaping (Result<User, Error>) -> Void)
    func register(name: String, email: String, password: String, completion: @escaping (Result<User, Error>) -> Void)
    func logout(completion: @escaping (Result<Void, Error>) -> Void)
}

protocol TokenStorageProtocol {
    func saveToken(_ token: String) throws
    func fetchToken() throws -> String?
    func deleteToken() throws
}

// 实现
class KeychainTokenStorage: TokenStorageProtocol {
    private let service: String
    private let account: String
    
    init(service: String, account: String) {
        self.service = service
        self.account = account
    }
    
    func saveToken(_ token: String) throws {
        let data = token.data(using: .utf8)!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data
        ]
        
        // 删除任何现有项目
        SecItemDelete(query as CFDictionary)
        
        // 添加新项目
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to save token to keychain"])
        }
    }
    
    func fetchToken() throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status != errSecItemNotFound else {
            return nil
        }
        
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to fetch token from keychain"])
        }
        
        guard let data = item as? Data, let token = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return token
    }
    
    func deleteToken() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: [NSLocalizedDescriptionKey: "Failed to delete token from keychain"])
        }
    }
}

class AuthenticationService: AuthenticationServiceProtocol {
    private let networkClient: NetworkClientProtocol
    private let tokenStorage: TokenStorageProtocol
    
    private(set) var currentUser: User?
    
    init(networkClient: NetworkClientProtocol, tokenStorage: TokenStorageProtocol) {
        self.networkClient = networkClient
        self.tokenStorage = tokenStorage
        
        // 尝试加载现有令牌并验证用户
        loadCurrentUser()
    }
    
    private func loadCurrentUser() {
        guard let token = try? tokenStorage.fetchToken() else {
            return
        }
        
        // 使用令牌获取当前用户
        networkClient.request(endpoint: "auth/me", method: .get, parameters: nil) { [weak self] (result: Result<User, Error>) in
            if case .success(let user) = result {
                self?.currentUser = user
            }
        }
    }
    
    func login(email: String, password: String, completion: @escaping (Result<User, Error>) -> Void) {
        let parameters: [String: Any] = [
            "email": email,
            "password": password
        ]
        
        networkClient.request(endpoint: "auth/login", method: .post, parameters: parameters) { [weak self] (result: Result<AuthResponse, Error>) in
            switch result {
            case .success(let response):
                do {
                    // 保存令牌
                    try self?.tokenStorage.saveToken(response.token)
                    
                    // 设置当前用户
                    self?.currentUser = response.user
                    
                    completion(.success(response.user))
                } catch {
                    completion(.failure(error))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func register(name: String, email: String, password: String, completion: @escaping (Result<User, Error>) -> Void) {
        let parameters: [String: Any] = [
            "name": name,
            "email": email,
            "password": password
        ]
        
        networkClient.request(endpoint: "auth/register", method: .post, parameters: parameters) { [weak self] (result: Result<AuthResponse, Error>) in
            switch result {
            case .success(let response):
                do {
                    // 保存令牌
                    try self?.tokenStorage.saveToken(response.token)
                    
                    // 设置当前用户
                    self?.currentUser = response.user
                    
                    completion(.success(response.user))
                } catch {
                    completion(.failure(error))
                }
            case .failure(let error):
                completion(.failure(error))
            }
        }
    }
    
    func logout(completion: @escaping (Result<Void, Error>) -> Void) {
        do {
            // 删除令牌
            try tokenStorage.deleteToken()
            
            // 清除当前用户
            currentUser = nil
            
            completion(.success(()))
        } catch {
            completion(.failure(error))
        }
    }
    
    // 辅助结构体
    private struct AuthResponse: Decodable {
        let user: User
        let token: String
    }
}

// 使用
let networkClient = NetworkClient(baseURL: "https://api.example.com")
let tokenStorage = KeychainTokenStorage(service: "com.example.myapp", account: "auth")
let authService = AuthenticationService(networkClient: networkClient, tokenStorage: tokenStorage)

// 登录
authService.login(email: "user@example.com", password: "password") { result in
    switch result {
    case .success(let user):
        print("Logged in as \(user.name)")
    case .failure(let error):
        print("Login failed: \(error)")
    }
}

// 在视图控制器中使用
class LoginViewController: UIViewController {
    private let authService: AuthenticationServiceProtocol
    
    @IBOutlet weak var emailTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    
    init(authService: AuthenticationServiceProtocol) {
        self.authService = authService
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }
    
    @IBAction func loginButtonTapped(_ sender: UIButton) {
        guard let email = emailTextField.text, !email.isEmpty,
              let password = passwordTextField.text, !password.isEmpty else {
            // 显示错误
            return
        }
        
        authService.login(email: email, password: password) { [weak self] result in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    // 导航到主屏幕
                    self?.navigateToMainScreen()
                case .failure(let error):
                    // 显示错误
                    self?.showError(error)
                }
            }
        }
    }
    
    private func navigateToMainScreen() {
        // 导航实现...
    }
    
    private func showError(_ error: Error) {
        // 错误显示实现...
    }
}
```

这些实际案例展示了依赖注入在真实 iOS 开发场景中的应用。通过使用依赖注入，我们可以创建更加模块化、可测试和可维护的代码。

## 总结

依赖注入是一种强大的设计模式，可以帮助我们创建更加模块化、可测试和可维护的 iOS 应用程序。本文详细介绍了依赖注入的概念、类型、实现方法以及最佳实践。

### 主要优势

1. **解耦**：依赖注入减少了组件之间的耦合，使系统更加模块化。

2. **可测试性**：通过依赖注入，我们可以轻松地用测试替身替换真实依赖项，便于单元测试。

3. **灵活性**：我们可以在运行时更改依赖项的实现，增加了系统的灵活性。

4. **可维护性**：松耦合的代码更清晰、更易于理解和维护。

5. **关注点分离**：依赖注入促进了关注点分离，使每个组件只专注于其核心功能。

### 挑战

1. **额外的复杂性**：依赖注入可能增加代码的复杂性，特别是对于小型项目。

2. **学习曲线**：理解和正确使用依赖注入需要时间和经验。

3. **过度工程**：过度使用依赖注入可能导致过度工程，使代码不必要地复杂。

### 最佳做法

1. **选择合适的注入方式**：根据具体情况选择构造器注入、属性注入或方法注入。

2. **使用协议**：通过协议抽象依赖项，而不是依赖具体实现。

3. **组织代码**：按功能组织代码，使用组装器模式管理依赖项。

4. **避免全局状态**：尽量避免使用全局变量或单例来管理依赖项。

5. **平衡复杂性**：根据项目的复杂性和需求选择适当级别的依赖注入。

通过遵循这些原则和最佳实践，我们可以充分利用依赖注入的优势，同时避免其潜在的缺点，从而创建更加健壮和可维护的 iOS 应用程序。

## 参考资源

- [Dependency Injection in Swift](https://www.swiftbysundell.com/articles/dependency-injection-in-swift/)
- [Swinject - Dependency Injection Framework for Swift](https://github.com/Swinject/Swinject)
- [Cleanse - Lightweight Swift Dependency Injection Framework](https://github.com/square/Cleanse)
- [Needle - Compile-time Swift Dependency Injection Framework](https://github.com/uber/needle)
- [Swift Talk - Dependency Injection](https://talk.objc.io/episodes/S01E38-dependency-injection)
- [Testing in Swift: Dependency Injection](https://www.objc.io/books/advanced-swift-testing/)
- [WWDC 2020 - Eliminate dependencies with Swift](https://developer.apple.com/videos/play/wwdc2020/10180/)
- [Unit Testing with Swift: Dependency Injection](https://www.raywenderlich.com/262-dependency-injection-in-swift)
- [Protocol-Oriented Programming in Swift](https://developer.apple.com/videos/play/wwdc2015/408/)
- [SwiftUI and Dependency Injection](https://www.pointfree.co/collections/composable-architecture/SwiftUI-and-dependency-injection/)