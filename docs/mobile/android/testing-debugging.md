# Android测试与调试

测试和调试是确保Android应用质量的关键环节。本文档将介绍Android开发中的测试方法、调试技巧以及常用工具，帮助开发者构建可靠、稳定的应用。

## 测试基础

### 测试金字塔

Android测试遵循测试金字塔原则，从底到顶分为：

1. **单元测试**：测试独立的代码单元，运行快速，数量最多
2. **集成测试**：测试多个组件的交互
3. **UI测试**：测试整个应用的用户交互，运行较慢，数量较少

![测试金字塔](https://developer.android.com/images/training/testing/pyramid_2x.png)

### 测试类型

根据是否需要Android环境，测试可分为：

1. **本地测试**：在JVM上运行，不需要Android设备或模拟器
2. **仪器测试**：在Android设备或模拟器上运行，可以访问Android框架API

## 单元测试

单元测试用于验证应用中的最小可测试单元（通常是方法）的行为。

### 添加依赖

```gradle
dependencies {
    // JUnit4框架
    testImplementation 'junit:junit:4.13.2'
    
    // Mockito模拟框架
    testImplementation 'org.mockito:mockito-core:4.0.0'
    testImplementation 'org.mockito:mockito-inline:4.0.0' // 用于模拟final类
    
    // Kotlin协程测试
    testImplementation 'org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4'
    
    // Truth断言库
    testImplementation 'com.google.truth:truth:1.1.3'
}
```

### 编写单元测试

```kotlin
// 被测试的类
class Calculator {
    fun add(a: Int, b: Int): Int = a + b
    fun subtract(a: Int, b: Int): Int = a - b
    fun multiply(a: Int, b: Int): Int = a * b
    fun divide(a: Int, b: Int): Int {
        require(b != 0) { "除数不能为零" }
        return a / b
    }
}

// 单元测试
class CalculatorTest {
    private lateinit var calculator: Calculator
    
    @Before
    fun setUp() {
        calculator = Calculator()
    }
    
    @Test
    fun add_twoPositiveNumbers_returnsSum() {
        // 准备
        val a = 2
        val b = 3
        
        // 执行
        val result = calculator.add(a, b)
        
        // 验证
        assertEquals(5, result)
    }
    
    @Test
    fun subtract_largerFromSmaller_returnsNegative() {
        assertEquals(-1, calculator.subtract(2, 3))
    }
    
    @Test
    fun multiply_twoPositiveNumbers_returnsProduct() {
        assertEquals(6, calculator.multiply(2, 3))
    }
    
    @Test
    fun divide_evenlyDivisible_returnsQuotient() {
        assertEquals(2, calculator.divide(6, 3))
    }
    
    @Test(expected = IllegalArgumentException::class)
    fun divide_byZero_throwsException() {
        calculator.divide(6, 0)
    }
}
```

### 使用Mockito模拟依赖

```kotlin
// 数据源接口
interface UserDataSource {
    suspend fun getUser(userId: String): User
    suspend fun saveUser(user: User): Boolean
}

// 仓库类
class UserRepository(private val remoteDataSource: UserDataSource, private val localDataSource: UserDataSource) {
    suspend fun getUser(userId: String): User {
        return try {
            val remoteUser = remoteDataSource.getUser(userId)
            localDataSource.saveUser(remoteUser) // 缓存到本地
            remoteUser
        } catch (e: Exception) {
            // 远程获取失败，尝试从本地获取
            localDataSource.getUser(userId)
        }
    }
}

// 测试仓库类
@RunWith(MockitoJUnitRunner::class)
class UserRepositoryTest {
    
    @Mock
    private lateinit var mockRemoteDataSource: UserDataSource
    
    @Mock
    private lateinit var mockLocalDataSource: UserDataSource
    
    private lateinit var userRepository: UserRepository
    
    @Before
    fun setUp() {
        userRepository = UserRepository(mockRemoteDataSource, mockLocalDataSource)
    }
    
    @Test
    fun getUser_remoteSuccess_returnsRemoteUserAndSavesToLocal() = runTest {
        // 准备
        val userId = "user123"
        val remoteUser = User(userId, "Remote User", "remote@example.com")
        
        // 设置模拟行为
        `when`(mockRemoteDataSource.getUser(userId)).thenReturn(remoteUser)
        `when`(mockLocalDataSource.saveUser(remoteUser)).thenReturn(true)
        
        // 执行
        val result = userRepository.getUser(userId)
        
        // 验证
        assertEquals(remoteUser, result)
        verify(mockLocalDataSource).saveUser(remoteUser) // 验证调用了保存方法
    }
    
    @Test
    fun getUser_remoteFailure_returnsLocalUser() = runTest {
        // 准备
        val userId = "user123"
        val localUser = User(userId, "Local User", "local@example.com")
        
        // 设置模拟行为
        `when`(mockRemoteDataSource.getUser(userId)).thenThrow(IOException("网络错误"))
        `when`(mockLocalDataSource.getUser(userId)).thenReturn(localUser)
        
        // 执行
        val result = userRepository.getUser(userId)
        
        // 验证
        assertEquals(localUser, result)
        verify(mockLocalDataSource, never()).saveUser(any()) // 验证没有调用保存方法
    }
}
```

### 测试ViewModel

```kotlin
// ViewModel
class UserViewModel(private val userRepository: UserRepository) : ViewModel() {
    private val _userState = MutableLiveData<Result<User>>()
    val userState: LiveData<Result<User>> = _userState
    
    fun loadUser(userId: String) {
        viewModelScope.launch {
            try {
                val user = userRepository.getUser(userId)
                _userState.value = Result.success(user)
            } catch (e: Exception) {
                _userState.value = Result.failure(e)
            }
        }
    }
}

// ViewModel测试
@RunWith(MockitoJUnitRunner::class)
class UserViewModelTest {
    
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule() // 使LiveData立即执行
    
    @Mock
    private lateinit var mockUserRepository: UserRepository
    
    private lateinit var userViewModel: UserViewModel
    
    @Before
    fun setUp() {
        Dispatchers.setMain(StandardTestDispatcher()) // 替换主调度器
        userViewModel = UserViewModel(mockUserRepository)
    }
    
    @After
    fun tearDown() {
        Dispatchers.resetMain() // 重置主调度器
    }
    
    @Test
    fun loadUser_success_updatesLiveDataWithSuccess() = runTest {
        // 准备
        val userId = "user123"
        val user = User(userId, "Test User", "test@example.com")
        
        // 设置模拟行为
        `when`(mockUserRepository.getUser(userId)).thenReturn(user)
        
        // 执行
        userViewModel.loadUser(userId)
        advanceUntilIdle() // 推进时间直到所有协程完成
        
        // 验证
        val result = userViewModel.userState.value
        assertNotNull(result)
        assertTrue(result is Result.Success)
        assertEquals(user, (result as Result.Success).data)
    }
    
    @Test
    fun loadUser_error_updatesLiveDataWithFailure() = runTest {
        // 准备
        val userId = "user123"
        val exception = IOException("网络错误")
        
        // 设置模拟行为
        `when`(mockUserRepository.getUser(userId)).thenThrow(exception)
        
        // 执行
        userViewModel.loadUser(userId)
        advanceUntilIdle() // 推进时间直到所有协程完成
        
        // 验证
        val result = userViewModel.userState.value
        assertNotNull(result)
        assertTrue(result is Result.Failure)
        assertEquals(exception, (result as Result.Failure).exception)
    }
}
```

### 使用Truth进行断言

```kotlin
// 使用Google Truth库进行更可读的断言
@Test
fun userValidation_validUser_returnsTrue() {
    val user = User("user123", "Test User", "test@example.com")
    
    val result = UserValidator.validate(user)
    
    // 使用Truth断言
    assertThat(result).isTrue()
}

@Test
fun parseUserJson_validJson_returnsUser() {
    val json = """{"id":"user123","name":"Test User","email":"test@example.com"}"""
    
    val user = UserParser.parse(json)
    
    // 链式断言
    assertThat(user).apply {
        isNotNull()
        prop("id").isEqualTo("user123")
        prop("name").isEqualTo("Test User")
        prop("email").isEqualTo("test@example.com")
    }
}
```

## 仪器测试

仪器测试在真实设备或模拟器上运行，可以测试需要Android框架的组件。

### 添加依赖

```gradle
dependencies {
    // AndroidX Test核心库
    androidTestImplementation 'androidx.test:core:1.5.0'
    androidTestImplementation 'androidx.test:runner:1.5.2'
    androidTestImplementation 'androidx.test:rules:1.5.0'
    
    // Espresso UI测试
    androidTestImplementation 'androidx.test.espresso:espresso-core:3.5.1'
    
    // JUnit扩展
    androidTestImplementation 'androidx.test.ext:junit:1.1.5'
    
    // 模拟框架
    androidTestImplementation 'org.mockito:mockito-android:4.0.0'
}
```

### 测试Activity

```kotlin
@RunWith(AndroidJUnit4::class)
class MainActivityTest {
    
    @get:Rule
    val activityRule = ActivityScenarioRule(MainActivity::class.java)
    
    @Test
    fun clickLoginButton_opensLoginScreen() {
        // 找到登录按钮并点击
        onView(withId(R.id.login_button))
            .perform(click())
        
        // 验证登录界面已显示
        onView(withId(R.id.login_screen))
            .check(matches(isDisplayed()))
    }
    
    @Test
    fun displayUsername_afterSuccessfulLogin() {
        // 点击登录按钮
        onView(withId(R.id.login_button))
            .perform(click())
        
        // 输入用户名和密码
        onView(withId(R.id.username_input))
            .perform(typeText("testuser"), closeSoftKeyboard())
        
        onView(withId(R.id.password_input))
            .perform(typeText("password"), closeSoftKeyboard())
        
        // 点击提交按钮
        onView(withId(R.id.submit_button))
            .perform(click())
        
        // 验证主界面显示了用户名
        onView(withId(R.id.welcome_text))
            .check(matches(withText(containsString("testuser"))))
    }
}
```

### 测试Fragment

```kotlin
@RunWith(AndroidJUnit4::class)
class UserProfileFragmentTest {
    
    @get:Rule
    val fragmentScenarioRule = FragmentScenarioRule(UserProfileFragment::class.java)
    
    @Test
    fun displayUserData_whenFragmentLaunched() {
        // 准备测试数据
        val user = User("user123", "Test User", "test@example.com")
        
        // 启动Fragment并传递参数
        launchFragmentInContainer<UserProfileFragment>(
            fragmentArgs = bundleOf("USER_ID" to "user123"),
            themeResId = R.style.Theme_AppCompat
        ).onFragment { fragment ->
            // 注入测试数据
            fragment.viewModel.setUser(user)
        }
        
        // 验证UI显示了正确的数据
        onView(withId(R.id.user_name))
            .check(matches(withText("Test User")))
        
        onView(withId(R.id.user_email))
            .check(matches(withText("test@example.com")))
    }
}
```

### 测试RecyclerView

```kotlin
@Test
fun recyclerView_scrollToPosition_andClickItem() {
    // 滚动到指定位置
    onView(withId(R.id.recycler_view))
        .perform(RecyclerViewActions.scrollToPosition<RecyclerView.ViewHolder>(10))
    
    // 点击指定位置的项
    onView(withId(R.id.recycler_view))
        .perform(RecyclerViewActions.actionOnItemAtPosition<RecyclerView.ViewHolder>(10, click()))
    
    // 验证详情页面已打开
    onView(withId(R.id.detail_container))
        .check(matches(isDisplayed()))
}

@Test
fun recyclerView_scrollToItemWithText() {
    // 滚动到包含特定文本的项
    onView(withId(R.id.recycler_view))
        .perform(
            RecyclerViewActions.scrollTo<RecyclerView.ViewHolder>(
                hasDescendant(withText("特定项目"))
            )
        )
    
    // 验证项目可见
    onView(withText("特定项目"))
        .check(matches(isDisplayed()))
}
```

### 测试自定义匹配器

```kotlin
// 自定义匹配器，匹配带有特定标签的视图
fun withTag(tag: String): Matcher<View> {
    return object : BoundedMatcher<View, View>(View::class.java) {
        override fun describeTo(description: Description) {
            description.appendText("with tag: $tag")
        }
        
        override fun matchesSafely(item: View): Boolean {
            return item.tag == tag
        }
    }
}

@Test
fun customMatcher_findsViewWithTag() {
    onView(withTag("profile_section"))
        .check(matches(isDisplayed()))
}
```

## UI自动化测试

### Espresso测试录制器

Android Studio提供了Espresso测试录制器，可以通过记录用户操作自动生成测试代码：

1. 右键点击测试类 -> Record Espresso Test
2. 在模拟器或设备上执行操作
3. 停止录制，生成测试代码

### UI Automator

UI Automator可以测试跨应用的用户交互：

```kotlin
@RunWith(AndroidJUnit4::class)
class CrossAppTest {
    
    private lateinit var device: UiDevice
    
    @Before
    fun setUp() {
        // 初始化UiDevice实例
        device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        
        // 回到主屏幕
        device.pressHome()
    }
    
    @Test
    fun testShareToOtherApp() {
        // 启动应用
        val context = ApplicationProvider.getApplicationContext<Context>()
        val intent = context.packageManager.getLaunchIntentForPackage("com.example.myapp")
        intent?.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
        context.startActivity(intent)
        
        // 等待应用启动
        device.wait(Until.hasObject(By.pkg("com.example.myapp").depth(0)), 5000)
        
        // 点击分享按钮
        device.findObject(UiSelector().resourceId("com.example.myapp:id/share_button")).click()
        
        // 等待分享菜单出现
        device.wait(Until.hasObject(By.text("分享到")), 2000)
        
        // 选择分享到的应用
        device.findObject(UiSelector().text("Gmail")).click()
        
        // 验证Gmail已打开
        assertTrue(device.wait(Until.hasObject(By.pkg("com.google.android.gm").depth(0)), 5000))
    }
}
```

## 测试覆盖率

### 配置Jacoco

```gradle
android {
    buildTypes {
        debug {
            testCoverageEnabled true
        }
    }
}

dependencies {
    testImplementation 'org.jacoco:org.jacoco.core:0.8.7'
}

tasks.withType(Test) {
    jacoco.includeNoLocationClasses = true
    jacoco.excludes = ['jdk.internal.*']
}

task jacocoTestReport(type: JacocoReport, dependsOn: ['testDebugUnitTest']) {
    reports {
        xml.enabled = true
        html.enabled = true
    }
    
    def fileFilter = ['**/R.class', '**/R$*.class', '**/BuildConfig.*', '**/Manifest*.*']
    def debugTree = fileTree(dir: "${buildDir}/intermediates/javac/debug", excludes: fileFilter)
    def mainSrc = "${project.projectDir}/src/main/java"
    
    sourceDirectories.setFrom(files([mainSrc]))
    classDirectories.setFrom(files([debugTree]))
    executionData.setFrom(fileTree(dir: "$buildDir", includes: [
        "jacoco/testDebugUnitTest.exec",
        "outputs/code-coverage/connected/*coverage.ec"
    ]))
}
```

运行测试覆盖率报告：

```bash
./gradlew jacocoTestReport
```

## 调试技巧

### 使用Logcat

```kotlin
// 不同级别的日志
Log.v(TAG, "详细信息") // Verbose
Log.d(TAG, "调试信息") // Debug
Log.i(TAG, "一般信息") // Info
Log.w(TAG, "警告信息") // Warning
Log.e(TAG, "错误信息") // Error

// 带异常的日志
try {
    // 可能抛出异常的代码
} catch (e: Exception) {
    Log.e(TAG, "操作失败", e)
}

// 条件日志（仅在调试版本中输出）
if (BuildConfig.DEBUG) {
    Log.d(TAG, "这条日志只在调试版本中显示")
}
```

### 使用调试器

Android Studio提供了强大的调试工具：

1. **设置断点**：点击代码行号左侧设置断点
2. **调试模式运行**：点击"Debug"按钮或按Shift+F9
3. **调试控制**：
   - Step Over (F8)：执行当前行，不进入函数
   - Step Into (F7)：进入函数内部
   - Step Out (Shift+F8)：执行完当前函数并返回
   - Resume (F9)：继续执行直到下一个断点

4. **观察变量**：
   - 在Variables窗口查看变量值
   - 添加Watch表达式监控特定变量或表达式
   - 使用Evaluate Expression (Alt+F8) 计算表达式值

### 使用Layout Inspector

Layout Inspector是Android Studio中的工具，用于检查应用的视图层次结构：

1. 运行应用
2. 选择菜单：Tools > Layout Inspector
3. 选择要检查的进程
4. 查看视图层次结构、属性和3D视图

### 使用Profiler

Android Profiler是性能分析工具，包含多个分析器：

1. **CPU Profiler**：监控CPU使用情况，查找性能瓶颈
2. **内存Profiler**：监控内存分配和泄漏
3. **网络Profiler**：监控网络活动和请求
4. **电池Profiler**：分析耗电情况

使用步骤：
1. 运行应用
2. 选择菜单：View > Tool Windows > Profiler
3. 选择要分析的进程
4. 选择要使用的分析器

### 调试WebView

```kotlin
// 启用WebView调试
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
    WebView.setWebContentsDebuggingEnabled(true)
}

// 然后在Chrome浏览器中访问：chrome://inspect/#devices
```

### 使用Stetho

Stetho是Facebook开发的调试桥，允许使用Chrome开发者工具检查应用：

1. 添加依赖：

```gradle
dependencies {
    implementation 'com.facebook.stetho:stetho:1.6.0'
    implementation 'com.facebook.stetho:stetho-okhttp3:1.6.0' // 用于网络检查
}
```

2. 在Application中初始化：

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) {
            Stetho.initializeWithDefaults(this)
        }
    }
}
```

3. 在Chrome浏览器中访问：chrome://inspect/#devices

### 使用LeakCanary检测内存泄漏

```gradle
dependencies {
    debugImplementation 'com.squareup.leakcanary:leakcanary-android:2.9.1'
}
```

LeakCanary会自动检测Activity和Fragment的内存泄漏，并在应用中显示通知。

## 常见问题与解决方案

### 测试问题

1. **测试执行缓慢**：
   - 减少仪器测试，增加单元测试
   - 使用模拟对象代替真实实现
   - 配置测试并行执行

2. **测试不稳定**：
   - 使用idling resources等待异步操作完成
   - 添加适当的等待和超时机制
   - 确保测试环境的一致性

3. **测试覆盖率低**：
   - 优先测试核心业务逻辑
   - 使用测试驱动开发(TDD)方法
   - 建立持续集成流程，监控覆盖率

### 调试问题

1. **应用崩溃但没有明显错误**：
   - 检查Logcat中的异常信息
   - 使用try-catch捕获并记录异常
   - 在关键点添加日志

2. **UI问题**：
   - 使用Layout Inspector检查视图层次
   - 添加视图边界（在开发者选项中启用"显示布局边界"）
   - 使用Hierarchy Viewer分析视图性能

3. **性能问题**：
   - 使用Profiler识别瓶颈
   - 检查主线程中的耗时操作
   - 使用Strict Mode检测潜在问题

## 最佳实践

1. **测试策略**：
   - 遵循测试金字塔原则
   - 编写可维护的测试
   - 定期运行测试套件

2. **调试技巧**：
   - 使用适当级别的日志
   - 熟练使用调试器
   - 利用Android Studio提供的工具

3. **持续集成**：
   - 配置自动化测试
   - 使用静态分析工具
   - 监控测试覆盖率和性能指标

## 总结

测试和调试是Android开发中不可或缺的环节，良好的测试策略和调试技巧可以显著提高应用质量和开发效率。通过本文介绍的方法和工具，开发者可以构建更可靠、更稳定的Android应用。

## 相关资源

- [Android测试文档](https://developer.android.com/training/testing)
- [Espresso测试框架](https://developer.android.com/training/testing/espresso)
- [JUnit文档](https://junit.org/junit4/)
- [Mockito文档](https://site.mockito.org/)
- [Android调试技巧](https://developer.android.com/studio/debug)
- [Android Profiler指南](https://developer.android.com/studio/profile/android-profiler)
