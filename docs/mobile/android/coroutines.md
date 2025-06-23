# Kotlin协程

Kotlin协程是一种强大的异步编程解决方案，特别适用于Android开发中的并发任务处理。本文档将介绍协程的基础知识、在Android中的应用以及最佳实践。

## 协程基础

### 什么是协程

协程是一种轻量级线程，可以在不阻塞主线程的情况下执行异步操作。与传统线程相比，协程具有以下优势：

- 轻量级：可以创建大量协程而不会消耗过多系统资源
- 内置取消支持：可以轻松取消正在运行的协程
- 结构化并发：通过作用域管理协程生命周期
- 顺序代码风格：使用挂起函数编写异步代码，避免回调地狱

### 协程的核心概念

1. **挂起函数(Suspending Functions)**：使用`suspend`关键字标记，可以在不阻塞线程的情况下暂停执行
2. **协程作用域(CoroutineScope)**：定义协程的生命周期范围
3. **协程构建器(Coroutine Builders)**：如`launch`、`async`等用于创建协程
4. **调度器(Dispatchers)**：指定协程运行的线程或线程池
5. **Job**：代表协程的生命周期，可用于控制协程

## 在Android中使用协程

### 添加依赖

在build.gradle文件中添加协程依赖：

```gradle
dependencies {
    // Kotlin协程核心库
    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4"
    
    // Android特定的协程库
    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.6.4"
    
    // 生命周期感知的协程作用域
    implementation "androidx.lifecycle:lifecycle-viewmodel-ktx:2.6.1"
    implementation "androidx.lifecycle:lifecycle-runtime-ktx:2.6.1"
}
```

### 协程作用域

Android中常用的协程作用域：

1. **GlobalScope**：应用程序级别的作用域，生命周期与应用相同（不推荐在一般情况下使用）
2. **LifecycleScope**：与Activity/Fragment生命周期绑定的作用域
3. **ViewModelScope**：与ViewModel生命周期绑定的作用域

```kotlin
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // 使用lifecycleScope
        lifecycleScope.launch {
            // 这个协程会在Activity销毁时自动取消
            val result = fetchData()
            updateUI(result)
        }
    }
    
    // 在特定生命周期状态启动协程
    private fun loadDataWhenResumed() {
        lifecycleScope.launchWhenResumed {
            // 只有在Activity处于RESUMED状态时才会执行
            val result = fetchData()
            updateUI(result)
        }
    }
}

class MyViewModel : ViewModel() {
    init {
        // 使用viewModelScope
        viewModelScope.launch {
            // 这个协程会在ViewModel被清除时自动取消
            val result = repository.fetchData()
            _data.value = result
        }
    }
}
```

### 创建自定义作用域

在需要时可以创建自定义协程作用域：

```kotlin
class DataManager {
    // 创建自定义作用域
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    fun loadData() {
        scope.launch {
            // 执行异步操作
        }
    }
    
    fun cleanup() {
        // 取消所有协程
        scope.cancel()
    }
}
```

## 协程构建器

### launch

`launch`用于启动一个不返回结果的协程：

```kotlin
// 基本用法
lifecycleScope.launch {
    // 协程代码
}

// 指定调度器
lifecycleScope.launch(Dispatchers.IO) {
    // 在IO线程池中执行
}

// 异常处理
lifecycleScope.launch {
    try {
        val result = fetchData() // 可能抛出异常的操作
        processResult(result)
    } catch (e: Exception) {
        handleError(e)
    }
}
```

### async

`async`用于启动一个返回结果的协程，返回一个`Deferred<T>`对象：

```kotlin
lifecycleScope.launch {
    // 并行执行两个操作
    val deferred1 = async { fetchDataFromSource1() }
    val deferred2 = async { fetchDataFromSource2() }
    
    // 等待两个操作完成并获取结果
    val result1 = deferred1.await()
    val result2 = deferred2.await()
    
    // 处理结果
    combineResults(result1, result2)
}
```

### withContext

`withContext`用于切换协程的上下文（通常是调度器），并等待其完成：

```kotlin
lifecycleScope.launch {
    // UI线程上的代码
    
    val result = withContext(Dispatchers.IO) {
        // IO线程上的代码
        fetchDataFromNetwork()
    }
    
    // 回到UI线程处理结果
    updateUI(result)
}
```

## 调度器

Kotlin协程提供了几种预定义的调度器：

1. **Dispatchers.Main**：Android主线程，用于UI操作
2. **Dispatchers.IO**：针对磁盘和网络IO优化的线程池
3. **Dispatchers.Default**：针对CPU密集型任务优化的线程池
4. **Dispatchers.Unconfined**：在调用者线程执行，直到第一个挂起点

```kotlin
lifecycleScope.launch {
    // UI操作 (Main)
    showLoading()
    
    // IO操作
    val data = withContext(Dispatchers.IO) {
        fetchDataFromNetwork()
    }
    
    // CPU密集型操作
    val processedData = withContext(Dispatchers.Default) {
        processData(data)
    }
    
    // 回到UI线程
    hideLoading()
    displayData(processedData)
}
```

## 异常处理

### 协程中的异常传播

1. **launch**：异常会被传播到父协程
2. **async**：异常会被封装在返回的Deferred对象中，直到调用`await()`时才会抛出

```kotlin
// launch中的异常处理
val job = lifecycleScope.launch {
    try {
        riskyOperation()
    } catch (e: Exception) {
        handleException(e)
    }
}

// async中的异常处理
val deferred = lifecycleScope.async {
    riskyOperation()
}

try {
    val result = deferred.await() // 可能抛出异常
} catch (e: Exception) {
    handleException(e)
}
```

### 使用异常处理器

可以为协程作用域设置全局异常处理器：

```kotlin
val handler = CoroutineExceptionHandler { _, exception ->
    Log.e("Coroutine", "捕获到异常: ${exception.message}", exception)
}

lifecycleScope.launch(handler) {
    riskyOperation() // 如果抛出异常，会被handler捕获
}
```

### SupervisorJob

使用`SupervisorJob`可以防止一个子协程的失败影响其他子协程：

```kotlin
val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

// 第一个子协程
scope.launch {
    delay(100)
    throw RuntimeException("协程1失败") // 不会影响协程2
}

// 第二个子协程
scope.launch {
    delay(200)
    println("协程2成功") // 仍然会执行
}
```

### supervisorScope

`supervisorScope`创建一个使用`SupervisorJob`的协程作用域：

```kotlin
lifecycleScope.launch {
    supervisorScope {
        // 第一个子协程
        launch {
            try {
                riskyOperation1()
            } catch (e: Exception) {
                handleError1(e)
            }
        }
        
        // 第二个子协程，不会受第一个协程失败的影响
        launch {
            riskyOperation2()
        }
    }
}
```

## 协程取消

### 取消协程

协程可以通过`Job`对象取消：

```kotlin
val job = lifecycleScope.launch {
    while (isActive) { // 检查协程是否活跃
        doWork()
    }
}

// 取消协程
job.cancel()

// 或者带原因取消
job.cancel("不再需要")
```

### 取消的协作

协程的取消是协作的，需要协程代码检查取消状态或使用支持取消的挂起函数：

```kotlin
lifecycleScope.launch {
    try {
        while (isActive) { // 检查是否被取消
            doWork()
            yield() // 检查取消并让出线程
        }
    } finally {
        // 清理资源
        cleanup()
    }
}
```

### 超时处理

可以使用`withTimeout`或`withTimeoutOrNull`设置协程的超时时间：

```kotlin
// 超时抛出异常
try {
    withTimeout(1000L) { // 1秒超时
        longRunningOperation()
    }
} catch (e: TimeoutCancellationException) {
    handleTimeout()
}

// 超时返回null
val result = withTimeoutOrNull(1000L) {
    longRunningOperation()
}

if (result == null) {
    // 操作超时
} else {
    // 操作成功完成
}
```

## 协程的实际应用

### 网络请求

使用协程简化网络请求：

```kotlin
// Retrofit支持协程
interface ApiService {
    @GET("users/{userId}")
    suspend fun getUser(@Path("userId") userId: String): User
}

class UserRepository(private val apiService: ApiService) {
    suspend fun getUser(userId: String): Result<User> {
        return try {
            Result.success(apiService.getUser(userId))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

class UserViewModel(private val repository: UserRepository) : ViewModel() {
    private val _user = MutableLiveData<Result<User>>()
    val user: LiveData<Result<User>> = _user
    
    fun loadUser(userId: String) {
        viewModelScope.launch {
            _user.value = repository.getUser(userId)
        }
    }
}
```

### 数据库操作

结合Room使用协程：

```kotlin
@Dao
interface UserDao {
    @Query("SELECT * FROM users")
    suspend fun getAllUsers(): List<User>
    
    @Insert
    suspend fun insertUser(user: User)
    
    @Update
    suspend fun updateUser(user: User)
    
    @Delete
    suspend fun deleteUser(user: User)
}

class UserRepository(private val userDao: UserDao) {
    suspend fun getAllUsers() = userDao.getAllUsers()
    
    suspend fun saveUser(user: User) {
        userDao.insertUser(user)
    }
}
```

### 并行分解

使用协程并行执行多个操作：

```kotlin
suspend fun loadDashboard(): DashboardData {
    return coroutineScope {
        val news = async { newsRepository.getLatestNews() }
        val weather = async { weatherRepository.getCurrentWeather() }
        val notifications = async { notificationRepository.getPendingNotifications() }
        
        DashboardData(
            news = news.await(),
            weather = weather.await(),
            notifications = notifications.await()
        )
    }
}
```

### 顺序执行

按顺序执行多个操作：

```kotlin
suspend fun processDocument(documentId: String) {
    // 按顺序执行，每一步依赖前一步的结果
    val document = documentRepository.getDocument(documentId)
    val processedContent = processContent(document.content)
    val formattedContent = formatContent(processedContent)
    documentRepository.updateDocument(documentId, formattedContent)
}
```

### 协程与Flow

Flow是基于协程的响应式流API：

```kotlin
// 创建Flow
fun getStockUpdates(symbol: String): Flow<StockUpdate> = flow {
    while (true) {
        val update = stockApi.fetchUpdate(symbol)
        emit(update) // 发射值
        delay(1000) // 每秒更新一次
    }
}

// 收集Flow
viewModelScope.launch {
    getStockUpdates("GOOG")
        .filter { it.price > threshold }
        .map { it.format() }
        .collect { update ->
            // 处理每个更新
            updateUI(update)
        }
}
```

## 测试协程

### 测试挂起函数

使用`runTest`测试挂起函数：

```kotlin
@Test
fun testFetchUser() = runTest {
    // 准备
    val userId = "123"
    val mockUser = User(userId, "测试用户")
    coEvery { mockApiService.getUser(userId) } returns mockUser
    
    // 执行
    val result = userRepository.getUser(userId)
    
    // 验证
    assertTrue(result.isSuccess)
    assertEquals(mockUser, result.getOrNull())
}
```

### 使用TestDispatcher

使用`StandardTestDispatcher`或`UnconfinedTestDispatcher`控制协程执行：

```kotlin
@OptIn(ExperimentalCoroutinesApi::class)
class UserViewModelTest {
    private val testDispatcher = StandardTestDispatcher()
    
    @Before
    fun setup() {
        Dispatchers.setMain(testDispatcher) // 替换Main调度器
    }
    
    @After
    fun tearDown() {
        Dispatchers.resetMain() // 重置Main调度器
    }
    
    @Test
    fun testLoadUser() = runTest {
        // 准备
        val mockRepository = mockk<UserRepository>()
        val userId = "123"
        val mockUser = User(userId, "测试用户")
        coEvery { mockRepository.getUser(userId) } returns Result.success(mockUser)
        
        val viewModel = UserViewModel(mockRepository)
        
        // 执行
        viewModel.loadUser(userId)
        testDispatcher.scheduler.advanceUntilIdle() // 推进时间直到所有协程完成
        
        // 验证
        val result = viewModel.user.value
        assertNotNull(result)
        assertTrue(result!!.isSuccess)
        assertEquals(mockUser, result.getOrNull())
    }
}
```

## 协程最佳实践

1. **使用结构化并发**：
   - 避免使用GlobalScope
   - 使用适当的作用域（lifecycleScope、viewModelScope等）
   - 确保协程在不再需要时被取消

2. **异常处理**：
   - 在适当的级别处理异常
   - 使用SupervisorJob或supervisorScope隔离失败
   - 为关键协程提供异常处理器

3. **调度器使用**：
   - UI操作使用Dispatchers.Main
   - IO操作使用Dispatchers.IO
   - CPU密集型操作使用Dispatchers.Default
   - 避免在Dispatchers.Main上执行耗时操作

4. **取消协作**：
   - 定期检查isActive状态
   - 使用yield()让出执行权并检查取消
   - 在finally块中清理资源

5. **避免协程泄漏**：
   - 确保所有协程都有明确的生命周期
   - 在组件销毁时取消相关协程

6. **协程与其他异步机制的结合**：
   - 使用适配器将回调转换为挂起函数
   - 使用Flow替代RxJava等其他响应式编程库

## 总结

Kotlin协程为Android开发中的异步编程提供了强大而优雅的解决方案。通过使用协程，可以：

1. 编写更简洁、更易读的异步代码
2. 有效管理并发操作
3. 简化错误处理
4. 与Android生命周期组件无缝集成
5. 提高应用性能和响应性

掌握协程的基本概念和实践技巧，可以显著提升Android应用的开发效率和代码质量。

## 相关资源

- [Kotlin协程官方文档](https://kotlinlang.org/docs/coroutines-overview.html)
- [Android开发者文档 - 协程](https://developer.android.com/kotlin/coroutines)
- [协程最佳实践](https://developer.android.com/kotlin/coroutines/coroutines-best-practices)
- [Kotlin Flow指南](https://developer.android.com/kotlin/flow)
- [协程测试](https://kotlin.github.io/kotlinx.coroutines/kotlinx-coroutines-test/)
