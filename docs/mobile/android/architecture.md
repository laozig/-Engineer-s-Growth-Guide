# Android应用架构

良好的应用架构是构建高质量Android应用的基础，它能提高代码的可维护性、可测试性和可扩展性。本文档将介绍Android应用开发中常用的架构模式、设计原则和依赖注入技术。

## 架构设计原则

在选择或设计应用架构时，应遵循以下核心原则：

1. **关注点分离**：将应用划分为不同的责任层，每层只关注自己的职责
2. **依赖规则**：源代码依赖只应指向更抽象的层，而不是具体实现
3. **单一职责**：每个类应该只有一个变更的理由
4. **可测试性**：架构应该允许在不依赖Android框架的情况下测试业务逻辑
5. **可维护性**：代码应该易于理解和修改
6. **可扩展性**：架构应该能够适应需求变化和功能扩展

## MVC架构

MVC (Model-View-Controller) 是一种传统的架构模式，在Android中的实现通常如下：

- **Model**：数据和业务逻辑
- **View**：UI元素，在Android中通常是XML布局
- **Controller**：处理用户输入，在Android中通常是Activity或Fragment

```kotlin
// Model
data class User(val id: String, val name: String, val email: String)

class UserRepository {
    fun getUser(userId: String): User {
        // 从数据源获取用户
        return User(userId, "张三", "zhangsan@example.com")
    }
}

// Controller (Activity)
class UserProfileActivity : AppCompatActivity() {
    private lateinit var userRepository: UserRepository
    private lateinit var nameTextView: TextView
    private lateinit var emailTextView: TextView
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_user_profile) // View
        
        // 初始化View
        nameTextView = findViewById(R.id.name_text_view)
        emailTextView = findViewById(R.id.email_text_view)
        
        // 初始化Model
        userRepository = UserRepository()
        
        // 加载数据
        val userId = intent.getStringExtra("USER_ID") ?: return
        val user = userRepository.getUser(userId)
        
        // 更新View
        updateUI(user)
    }
    
    private fun updateUI(user: User) {
        nameTextView.text = user.name
        emailTextView.text = user.email
    }
}
```

**MVC的问题**：在Android中，Activity和Fragment既作为Controller又包含View的引用，导致它们变得臃肿且难以测试。

## MVP架构

MVP (Model-View-Presenter) 通过引入Presenter层解决了MVC中Controller的问题：

- **Model**：数据和业务逻辑
- **View**：UI元素和用户交互，通常是Activity或Fragment
- **Presenter**：处理View的事件并更新View，但不直接引用Android框架类

```kotlin
// Model
data class User(val id: String, val name: String, val email: String)

class UserRepository {
    fun getUser(userId: String, callback: (User) -> Unit) {
        // 模拟异步操作
        Handler(Looper.getMainLooper()).postDelayed({
            callback(User(userId, "张三", "zhangsan@example.com"))
        }, 1000)
    }
}

// View接口
interface UserProfileView {
    fun showLoading()
    fun hideLoading()
    fun displayUser(user: User)
    fun showError(message: String)
}

// Presenter
class UserProfilePresenter(
    private val view: UserProfileView,
    private val userRepository: UserRepository
) {
    fun loadUser(userId: String) {
        view.showLoading()
        userRepository.getUser(userId) { user ->
            view.hideLoading()
            view.displayUser(user)
        }
    }
}

// View实现
class UserProfileActivity : AppCompatActivity(), UserProfileView {
    private lateinit var presenter: UserProfilePresenter
    private lateinit var nameTextView: TextView
    private lateinit var emailTextView: TextView
    private lateinit var progressBar: ProgressBar
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_user_profile)
        
        // 初始化View
        nameTextView = findViewById(R.id.name_text_view)
        emailTextView = findViewById(R.id.email_text_view)
        progressBar = findViewById(R.id.progress_bar)
        
        // 创建Presenter
        presenter = UserProfilePresenter(this, UserRepository())
        
        // 加载用户
        val userId = intent.getStringExtra("USER_ID") ?: return
        presenter.loadUser(userId)
    }
    
    // View接口实现
    override fun showLoading() {
        progressBar.visibility = View.VISIBLE
    }
    
    override fun hideLoading() {
        progressBar.visibility = View.GONE
    }
    
    override fun displayUser(user: User) {
        nameTextView.text = user.name
        emailTextView.text = user.email
    }
    
    override fun showError(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
```

**MVP的优势**：
- Presenter不依赖Android框架，可以单独测试
- View和Model完全分离
- Activity/Fragment代码更简洁

**MVP的问题**：
- 需要为每个界面创建多个接口
- Presenter可能会随着功能增加而变得臃肿
- 手动管理View和Presenter的生命周期

## MVVM架构

MVVM (Model-View-ViewModel) 是Google推荐的Android应用架构模式，它使用数据绑定机制自动同步View和ViewModel：

- **Model**：数据和业务逻辑
- **View**：UI元素和用户交互，通常是Activity或Fragment
- **ViewModel**：处理View的事件并维护View状态，通过LiveData或Flow与View通信

```kotlin
// Model
data class User(val id: String, val name: String, val email: String)

class UserRepository {
    suspend fun getUser(userId: String): User {
        delay(1000) // 模拟网络请求
        return User(userId, "张三", "zhangsan@example.com")
    }
}

// ViewModel
class UserProfileViewModel(private val userRepository: UserRepository) : ViewModel() {
    private val _user = MutableLiveData<User>()
    val user: LiveData<User> = _user
    
    private val _isLoading = MutableLiveData<Boolean>()
    val isLoading: LiveData<Boolean> = _isLoading
    
    private val _error = MutableLiveData<String?>()
    val error: LiveData<String?> = _error
    
    fun loadUser(userId: String) {
        viewModelScope.launch {
            try {
                _isLoading.value = true
                _error.value = null
                
                val result = userRepository.getUser(userId)
                _user.value = result
            } catch (e: Exception) {
                _error.value = e.message
            } finally {
                _isLoading.value = false
            }
        }
    }
}

// View
class UserProfileActivity : AppCompatActivity() {
    private lateinit var viewModel: UserProfileViewModel
    private lateinit var binding: ActivityUserProfileBinding
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 使用DataBinding
        binding = DataBindingUtil.setContentView(this, R.layout.activity_user_profile)
        binding.lifecycleOwner = this
        
        // 创建ViewModel
        val factory = ViewModelFactory(UserRepository())
        viewModel = ViewModelProvider(this, factory)[UserProfileViewModel::class.java]
        
        // 绑定ViewModel
        binding.viewModel = viewModel
        
        // 观察数据变化
        viewModel.user.observe(this) { user ->
            // 可以执行额外的UI更新
        }
        
        viewModel.error.observe(this) { errorMsg ->
            errorMsg?.let {
                Toast.makeText(this, it, Toast.LENGTH_SHORT).show()
            }
        }
        
        // 加载用户
        val userId = intent.getStringExtra("USER_ID") ?: return
        viewModel.loadUser(userId)
    }
}
```

XML布局文件使用DataBinding：

```xml
<layout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto">
    
    <data>
        <import type="android.view.View" />
        <variable
            name="viewModel"
            type="com.example.app.UserProfileViewModel" />
    </data>
    
    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="vertical"
        android:padding="16dp">
        
        <ProgressBar
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:layout_gravity="center"
            android:visibility="@{viewModel.isLoading ? View.VISIBLE : View.GONE}" />
            
        <TextView
            android:id="@+id/name_text_view"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:text="@{viewModel.user.name}"
            android:textSize="18sp" />
            
        <TextView
            android:id="@+id/email_text_view"
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:text="@{viewModel.user.email}"
            android:textSize="16sp" />
    </LinearLayout>
</layout>
```

**MVVM的优势**：
- ViewModel不持有View的引用，降低了耦合度
- 数据绑定减少了样板代码
- ViewModel可以在配置更改时保留数据
- 使用LiveData/Flow自动处理生命周期

## Clean Architecture

Clean Architecture是一种分层架构模式，强调关注点分离和依赖规则。在Android中，通常将其划分为以下几层：

1. **表示层(Presentation)**：包含UI组件和ViewModels
2. **领域层(Domain)**：包含业务逻辑和用例
3. **数据层(Data)**：包含数据源实现和仓库

### 实现Clean Architecture

**领域层(Domain)**：

```kotlin
// 实体
data class User(
    val id: String,
    val name: String,
    val email: String,
    val profilePictureUrl: String
)

// 仓库接口
interface UserRepository {
    suspend fun getUser(userId: String): Result<User>
    suspend fun updateUserProfile(user: User): Result<Boolean>
}

// 用例(Use Cases)
class GetUserUseCase(private val userRepository: UserRepository) {
    suspend operator fun invoke(userId: String): Result<User> {
        return userRepository.getUser(userId)
    }
}

class UpdateUserProfileUseCase(private val userRepository: UserRepository) {
    suspend operator fun invoke(user: User): Result<Boolean> {
        return userRepository.updateUserProfile(user)
    }
}
```

**数据层(Data)**：

```kotlin
// 远程数据源
interface UserRemoteDataSource {
    suspend fun getUser(userId: String): UserDto
    suspend fun updateUser(userDto: UserDto): Boolean
}

// 本地数据源
interface UserLocalDataSource {
    suspend fun getUser(userId: String): UserEntity?
    suspend fun saveUser(userEntity: UserEntity)
}

// 数据传输对象(DTO)
data class UserDto(
    val id: String,
    val name: String,
    val email: String,
    val profilePicture: String
)

// 数据库实体
@Entity(tableName = "users")
data class UserEntity(
    @PrimaryKey val id: String,
    val name: String,
    val email: String,
    val profilePictureUrl: String
)

// 仓库实现
class UserRepositoryImpl(
    private val remoteDataSource: UserRemoteDataSource,
    private val localDataSource: UserLocalDataSource
) : UserRepository {
    
    override suspend fun getUser(userId: String): Result<User> {
        return try {
            // 先尝试从本地获取
            val localUser = localDataSource.getUser(userId)
            
            if (localUser != null) {
                // 返回本地数据
                Result.success(localUser.toDomain())
            } else {
                // 从远程获取
                val remoteUser = remoteDataSource.getUser(userId)
                
                // 保存到本地
                localDataSource.saveUser(remoteUser.toEntity())
                
                // 返回远程数据
                Result.success(remoteUser.toDomain())
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    override suspend fun updateUserProfile(user: User): Result<Boolean> {
        return try {
            val result = remoteDataSource.updateUser(user.toDto())
            if (result) {
                localDataSource.saveUser(user.toEntity())
            }
            Result.success(result)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

// 扩展函数用于转换数据模型
fun UserDto.toDomain() = User(id, name, email, profilePicture)
fun UserEntity.toDomain() = User(id, name, email, profilePictureUrl)
fun User.toDto() = UserDto(id, name, email, profilePictureUrl)
fun User.toEntity() = UserEntity(id, name, email, profilePictureUrl)
fun UserDto.toEntity() = UserEntity(id, name, email, profilePicture)
```

**表示层(Presentation)**：

```kotlin
class UserProfileViewModel(
    private val getUserUseCase: GetUserUseCase,
    private val updateUserProfileUseCase: UpdateUserProfileUseCase
) : ViewModel() {
    
    private val _uiState = MutableStateFlow<UserProfileUiState>(UserProfileUiState.Loading)
    val uiState: StateFlow<UserProfileUiState> = _uiState
    
    fun loadUser(userId: String) {
        viewModelScope.launch {
            _uiState.value = UserProfileUiState.Loading
            
            getUserUseCase(userId).fold(
                onSuccess = { user ->
                    _uiState.value = UserProfileUiState.Success(user)
                },
                onFailure = { error ->
                    _uiState.value = UserProfileUiState.Error(error.message ?: "未知错误")
                }
            )
        }
    }
    
    fun updateProfile(user: User) {
        viewModelScope.launch {
            _uiState.value = UserProfileUiState.Loading
            
            updateUserProfileUseCase(user).fold(
                onSuccess = { success ->
                    if (success) {
                        _uiState.value = UserProfileUiState.Success(user)
                    } else {
                        _uiState.value = UserProfileUiState.Error("更新失败")
                    }
                },
                onFailure = { error ->
                    _uiState.value = UserProfileUiState.Error(error.message ?: "未知错误")
                }
            )
        }
    }
}

// UI状态
sealed class UserProfileUiState {
    object Loading : UserProfileUiState()
    data class Success(val user: User) : UserProfileUiState()
    data class Error(val message: String) : UserProfileUiState()
}

// Fragment
class UserProfileFragment : Fragment() {
    private lateinit var binding: FragmentUserProfileBinding
    private val viewModel: UserProfileViewModel by viewModels { viewModelFactory }
    
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        binding = FragmentUserProfileBinding.inflate(inflater, container, false)
        return binding.root
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        // 收集UI状态
        lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    when (state) {
                        is UserProfileUiState.Loading -> showLoading()
                        is UserProfileUiState.Success -> showUserProfile(state.user)
                        is UserProfileUiState.Error -> showError(state.message)
                    }
                }
            }
        }
        
        // 加载用户
        val userId = arguments?.getString("USER_ID") ?: return
        viewModel.loadUser(userId)
        
        // 设置保存按钮点击事件
        binding.saveButton.setOnClickListener {
            val currentState = viewModel.uiState.value
            if (currentState is UserProfileUiState.Success) {
                val updatedUser = currentState.user.copy(
                    name = binding.nameEditText.text.toString(),
                    email = binding.emailEditText.text.toString()
                )
                viewModel.updateProfile(updatedUser)
            }
        }
    }
    
    private fun showLoading() {
        binding.progressBar.visibility = View.VISIBLE
        binding.contentGroup.visibility = View.GONE
        binding.errorText.visibility = View.GONE
    }
    
    private fun showUserProfile(user: User) {
        binding.progressBar.visibility = View.GONE
        binding.contentGroup.visibility = View.VISIBLE
        binding.errorText.visibility = View.GONE
        
        binding.nameEditText.setText(user.name)
        binding.emailEditText.setText(user.email)
        Glide.with(this)
            .load(user.profilePictureUrl)
            .into(binding.profileImageView)
    }
    
    private fun showError(message: String) {
        binding.progressBar.visibility = View.GONE
        binding.contentGroup.visibility = View.GONE
        binding.errorText.visibility = View.VISIBLE
        binding.errorText.text = message
    }
}
```

**Clean Architecture的优势**：
- 关注点分离，每层有明确的职责
- 业务逻辑独立于框架，便于测试
- 依赖指向内层，内层不知道外层的存在
- 可以独立更换任何层的实现而不影响其他层

## 依赖注入

依赖注入(DI)是一种设计模式，用于提供对象所需的依赖，而不是让对象自己创建依赖。在Android中，常用的DI框架有Dagger、Hilt和Koin。

### Hilt

Hilt是Google基于Dagger开发的Android专用依赖注入库，提供了更简单的API和标准化的组件。

1. 添加依赖：

```gradle
// build.gradle (项目级)
buildscript {
    dependencies {
        classpath 'com.google.dagger:hilt-android-gradle-plugin:2.44'
    }
}

// build.gradle (应用级)
plugins {
    id 'kotlin-kapt'
    id 'dagger.hilt.android.plugin'
}

dependencies {
    implementation "com.google.dagger:hilt-android:2.44"
    kapt "com.google.dagger:hilt-compiler:2.44"
}
```

2. 创建Application类：

```kotlin
@HiltAndroidApp
class MyApplication : Application()
```

3. 提供依赖：

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    
    @Provides
    @Singleton
    fun provideUserRemoteDataSource(apiService: ApiService): UserRemoteDataSource {
        return UserRemoteDataSourceImpl(apiService)
    }
    
    @Provides
    @Singleton
    fun provideUserLocalDataSource(database: AppDatabase): UserLocalDataSource {
        return UserLocalDataSourceImpl(database.userDao())
    }
    
    @Provides
    @Singleton
    fun provideUserRepository(
        remoteDataSource: UserRemoteDataSource,
        localDataSource: UserLocalDataSource
    ): UserRepository {
        return UserRepositoryImpl(remoteDataSource, localDataSource)
    }
    
    @Provides
    @Singleton
    fun provideGetUserUseCase(repository: UserRepository): GetUserUseCase {
        return GetUserUseCase(repository)
    }
    
    @Provides
    @Singleton
    fun provideUpdateUserProfileUseCase(repository: UserRepository): UpdateUserProfileUseCase {
        return UpdateUserProfileUseCase(repository)
    }
    
    @Provides
    @Singleton
    fun provideApiService(): ApiService {
        return Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(ApiService::class.java)
    }
    
    @Provides
    @Singleton
    fun provideAppDatabase(@ApplicationContext context: Context): AppDatabase {
        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "app_database"
        ).build()
    }
}
```

4. 在Activity/Fragment中注入依赖：

```kotlin
@AndroidEntryPoint
class UserProfileFragment : Fragment() {
    
    @Inject
    lateinit var getUserUseCase: GetUserUseCase
    
    @Inject
    lateinit var updateUserProfileUseCase: UpdateUserProfileUseCase
    
    private val viewModel: UserProfileViewModel by viewModels()
    
    // ...
}
```

5. 在ViewModel中注入依赖：

```kotlin
@HiltViewModel
class UserProfileViewModel @Inject constructor(
    private val getUserUseCase: GetUserUseCase,
    private val updateUserProfileUseCase: UpdateUserProfileUseCase
) : ViewModel() {
    // ...
}
```

### Koin

Koin是一个轻量级的依赖注入框架，使用纯Kotlin实现，不需要代码生成。

1. 添加依赖：

```gradle
dependencies {
    implementation "io.insert-koin:koin-android:3.3.0"
    implementation "io.insert-koin:koin-androidx-viewmodel:3.3.0"
}
```

2. 创建模块：

```kotlin
val appModule = module {
    // API服务
    single { 
        Retrofit.Builder()
            .baseUrl("https://api.example.com/")
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(ApiService::class.java)
    }
    
    // 数据库
    single { 
        Room.databaseBuilder(
            androidContext(),
            AppDatabase::class.java,
            "app_database"
        ).build() 
    }
    
    // DAO
    single { get<AppDatabase>().userDao() }
    
    // 数据源
    single<UserRemoteDataSource> { UserRemoteDataSourceImpl(get()) }
    single<UserLocalDataSource> { UserLocalDataSourceImpl(get()) }
    
    // 仓库
    single<UserRepository> { UserRepositoryImpl(get(), get()) }
    
    // 用例
    single { GetUserUseCase(get()) }
    single { UpdateUserProfileUseCase(get()) }
    
    // ViewModel
    viewModel { UserProfileViewModel(get(), get()) }
}
```

3. 在Application中启动Koin：

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        startKoin {
            androidContext(this@MyApplication)
            modules(appModule)
        }
    }
}
```

4. 在Activity/Fragment中使用：

```kotlin
class UserProfileFragment : Fragment() {
    
    // 通过注入获取ViewModel
    private val viewModel: UserProfileViewModel by viewModel()
    
    // 或者直接注入依赖
    private val getUserUseCase: GetUserUseCase by inject()
    
    // ...
}
```

## 架构模式比较

| 架构模式 | 优点 | 缺点 | 适用场景 |
|---------|------|------|----------|
| MVC | 简单易懂，上手快 | Activity/Fragment职责过重，难以测试 | 简单应用，原型开发 |
| MVP | 关注点分离，可测试性好 | 需要大量接口，Presenter可能臃肿 | 中等复杂度应用 |
| MVVM | 数据绑定减少样板代码，生命周期管理简单 | 调试数据流可能复杂，过度使用数据绑定可能导致性能问题 | 大多数现代Android应用 |
| Clean Architecture | 高度模块化，关注点分离，可测试性极佳 | 初始设置复杂，对于简单应用可能过度设计 | 大型团队协作的复杂应用 |

## 最佳实践

1. **根据项目规模选择合适的架构**：
   - 小型项目：MVVM可能足够
   - 中大型项目：考虑MVVM+Clean Architecture

2. **使用依赖注入**：
   - 避免手动创建依赖
   - 使用Hilt或Koin简化依赖管理

3. **单向数据流**：
   - 使用不可变状态
   - 从ViewModel向UI层单向流动数据
   - 使用事件来处理一次性操作

4. **模块化**：
   - 按功能或层划分模块
   - 定义清晰的模块边界和API

5. **测试驱动开发**：
   - 编写单元测试验证业务逻辑
   - 使用UI测试验证用户交互

6. **持续重构**：
   - 随着应用增长，不断调整架构
   - 消除技术债务

## 总结

选择合适的应用架构是Android开发的关键决策之一。MVVM结合Clean Architecture和依赖注入是当前Android开发的主流架构方案，它提供了良好的关注点分离、可测试性和可维护性。

无论选择哪种架构，最重要的是保持一致性，并确保团队成员理解并遵循所选架构的原则。随着应用的发展，架构也应该能够适应变化，并支持应用的持续增长。

## 相关资源

- [Android应用架构指南](https://developer.android.com/topic/architecture)
- [Android架构组件](https://developer.android.com/topic/libraries/architecture)
- [Hilt依赖注入](https://developer.android.com/training/dependency-injection/hilt-android)
- [Koin官方文档](https://insert-koin.io/)
- [Clean Architecture for Android](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
