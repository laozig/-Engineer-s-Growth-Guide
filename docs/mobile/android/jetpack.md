# Android Jetpack组件

Android Jetpack是一套库、工具和架构指南的集合，旨在帮助开发者更轻松地构建高质量的Android应用。本文档介绍Jetpack的核心组件及其使用方法。

## Jetpack架构组件

### ViewModel

ViewModel用于存储和管理UI相关的数据，使数据在配置更改（如屏幕旋转）时不会丢失。

```kotlin
// 添加依赖
// build.gradle (app)
dependencies {
    implementation "androidx.lifecycle:lifecycle-viewmodel-ktx:2.6.1"
}

// 创建ViewModel类
class UserViewModel : ViewModel() {
    // 用LiveData包装数据，使UI可以观察数据变化
    private val _user = MutableLiveData<User>()
    val user: LiveData<User> = _user
    
    // 在ViewModel中处理业务逻辑
    fun loadUser(userId: String) {
        viewModelScope.launch {
            try {
                val result = userRepository.getUser(userId)
                _user.value = result
            } catch (e: Exception) {
                // 处理错误
            }
        }
    }
    
    // ViewModel被销毁时调用
    override fun onCleared() {
        super.onCleared()
        // 清理资源
    }
}

// 在Activity/Fragment中使用ViewModel
class UserProfileActivity : AppCompatActivity() {
    private lateinit var viewModel: UserViewModel
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_user_profile)
        
        // 获取ViewModel实例
        viewModel = ViewModelProvider(this).get(UserViewModel::class.java)
        
        // 观察LiveData
        viewModel.user.observe(this) { user ->
            // 更新UI
            updateUI(user)
        }
        
        // 加载数据
        viewModel.loadUser("user_123")
    }
}
```

### LiveData

LiveData是一个可观察的数据持有者类，它遵循应用组件的生命周期。

```kotlin
// 在ViewModel中使用LiveData
class WeatherViewModel : ViewModel() {
    private val _temperature = MutableLiveData<Float>()
    val temperature: LiveData<Float> = _temperature
    
    private val _weatherCondition = MutableLiveData<String>()
    val weatherCondition: LiveData<String> = _weatherCondition
    
    fun refreshWeather() {
        viewModelScope.launch {
            val weatherData = weatherRepository.getLatestWeather()
            _temperature.value = weatherData.temperature
            _weatherCondition.value = weatherData.condition
        }
    }
}

// 在Fragment中观察LiveData
class WeatherFragment : Fragment() {
    private lateinit var viewModel: WeatherViewModel
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        viewModel = ViewModelProvider(requireActivity()).get(WeatherViewModel::class.java)
        
        // 观察多个LiveData
        viewModel.temperature.observe(viewLifecycleOwner) { temp ->
            temperatureTextView.text = "$temp°C"
        }
        
        viewModel.weatherCondition.observe(viewLifecycleOwner) { condition ->
            conditionTextView.text = condition
            updateWeatherIcon(condition)
        }
        
        refreshButton.setOnClickListener {
            viewModel.refreshWeather()
        }
    }
}
```

### Transformations

LiveData可以使用Transformations进行转换：

```kotlin
// 在ViewModel中转换LiveData
class ProfileViewModel : ViewModel() {
    private val _userId = MutableLiveData<String>()
    
    // 使用Transformations.switchMap根据userId获取用户资料
    val userProfile: LiveData<UserProfile> = Transformations.switchMap(_userId) { id ->
        repository.getUserProfile(id)
    }
    
    // 使用Transformations.map转换数据
    val userName: LiveData<String> = Transformations.map(userProfile) { profile ->
        "${profile.firstName} ${profile.lastName}"
    }
    
    fun setUserId(id: String) {
        _userId.value = id
    }
}
```

### DataBinding

DataBinding库允许你以声明式的方式将布局中的UI组件绑定到应用程序的数据源。

1. 启用DataBinding：

```gradle
// build.gradle (app)
android {
    ...
    buildFeatures {
        dataBinding true
    }
}
```

2. 创建绑定布局：

```xml
<!-- activity_user_profile.xml -->
<layout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto">
    
    <data>
        <variable
            name="viewModel"
            type="com.example.app.UserViewModel" />
    </data>
    
    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        android:orientation="vertical"
        android:padding="16dp">
        
        <TextView
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="@{viewModel.user.name}"
            android:textSize="18sp" />
            
        <TextView
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="@{viewModel.user.email}"
            android:textSize="16sp" />
            
        <Button
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="更新"
            android:onClick="@{() -> viewModel.refreshUser()}" />
    </LinearLayout>
</layout>
```

3. 在Activity中使用DataBinding：

```kotlin
class UserProfileActivity : AppCompatActivity() {
    private lateinit var binding: ActivityUserProfileBinding
    private lateinit var viewModel: UserViewModel
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 设置DataBinding
        binding = DataBindingUtil.setContentView(this, R.layout.activity_user_profile)
        
        // 获取ViewModel
        viewModel = ViewModelProvider(this).get(UserViewModel::class.java)
        
        // 设置绑定变量
        binding.viewModel = viewModel
        
        // 设置生命周期所有者，以便LiveData可以自动更新UI
        binding.lifecycleOwner = this
    }
}
```

### Room数据库

Room是SQLite的抽象层，提供了更强大的数据库访问机制。

1. 添加依赖：

```gradle
dependencies {
    implementation "androidx.room:room-runtime:2.5.2"
    kapt "androidx.room:room-compiler:2.5.2"
    implementation "androidx.room:room-ktx:2.5.2" // Kotlin扩展
}
```

2. 定义实体类：

```kotlin
@Entity(tableName = "users")
data class User(
    @PrimaryKey val id: String,
    val name: String,
    val email: String,
    val age: Int
)
```

3. 创建DAO（数据访问对象）：

```kotlin
@Dao
interface UserDao {
    @Query("SELECT * FROM users")
    fun getAllUsers(): Flow<List<User>>
    
    @Query("SELECT * FROM users WHERE id = :userId")
    fun getUserById(userId: String): Flow<User?>
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertUser(user: User)
    
    @Update
    suspend fun updateUser(user: User)
    
    @Delete
    suspend fun deleteUser(user: User)
}
```

4. 创建数据库类：

```kotlin
@Database(entities = [User::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
    
    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null
        
        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "app_database"
                )
                .fallbackToDestructiveMigration()
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
```

5. 在应用中使用Room：

```kotlin
class UserRepository(private val userDao: UserDao) {
    // 获取所有用户
    val allUsers: Flow<List<User>> = userDao.getAllUsers()
    
    // 获取指定用户
    fun getUserById(id: String): Flow<User?> {
        return userDao.getUserById(id)
    }
    
    // 插入用户
    suspend fun insert(user: User) {
        userDao.insertUser(user)
    }
    
    // 更新用户
    suspend fun update(user: User) {
        userDao.updateUser(user)
    }
    
    // 删除用户
    suspend fun delete(user: User) {
        userDao.deleteUser(user)
    }
}

// 在应用中初始化
class MyApplication : Application() {
    val database by lazy { AppDatabase.getDatabase(this) }
    val repository by lazy { UserRepository(database.userDao()) }
}
```

## Navigation组件

Navigation组件帮助实现应用内导航，处理Fragment事务、返回栈等。

1. 添加依赖：

```gradle
dependencies {
    implementation "androidx.navigation:navigation-fragment-ktx:2.6.0"
    implementation "androidx.navigation:navigation-ui-ktx:2.6.0"
}
```

2. 创建导航图（res/navigation/nav_graph.xml）：

```xml
<?xml version="1.0" encoding="utf-8"?>
<navigation xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:id="@+id/nav_graph"
    app:startDestination="@id/homeFragment">

    <fragment
        android:id="@+id/homeFragment"
        android:name="com.example.app.HomeFragment"
        android:label="首页"
        tools:layout="@layout/fragment_home">
        <action
            android:id="@+id/action_home_to_detail"
            app:destination="@id/detailFragment" />
    </fragment>
    
    <fragment
        android:id="@+id/detailFragment"
        android:name="com.example.app.DetailFragment"
        android:label="详情"
        tools:layout="@layout/fragment_detail">
        <argument
            android:name="itemId"
            app:argType="string" />
    </fragment>
</navigation>
```

3. 在Activity中设置NavController：

```kotlin
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        val navHostFragment = supportFragmentManager
            .findFragmentById(R.id.nav_host_fragment) as NavHostFragment
        val navController = navHostFragment.navController
        
        // 设置ActionBar与NavController联动
        setupActionBarWithNavController(navController)
    }
    
    override fun onSupportNavigateUp(): Boolean {
        val navController = findNavController(R.id.nav_host_fragment)
        return navController.navigateUp() || super.onSupportNavigateUp()
    }
}
```

4. 在Fragment中进行导航：

```kotlin
class HomeFragment : Fragment() {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        itemButton.setOnClickListener {
            // 导航到详情页面并传递参数
            val action = HomeFragmentDirections.actionHomeToDetail("item_123")
            findNavController().navigate(action)
        }
    }
}

class DetailFragment : Fragment() {
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        // 获取传递的参数
        val args: DetailFragmentArgs by navArgs()
        val itemId = args.itemId
        
        // 使用itemId加载数据
        viewModel.loadItem(itemId)
    }
}
```

## WorkManager

WorkManager用于管理可延期的后台任务，即使应用退出或设备重启也能保证任务最终会执行。

1. 添加依赖：

```gradle
dependencies {
    implementation "androidx.work:work-runtime-ktx:2.8.1"
}
```

2. 创建Worker类：

```kotlin
class ImageUploadWorker(
    context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {
    
    override suspend fun doWork(): Result {
        val imageUriString = inputData.getString("IMAGE_URI") ?: return Result.failure()
        
        return try {
            // 执行上传操作
            val uploadSuccess = uploadImage(imageUriString)
            
            if (uploadSuccess) {
                // 创建输出数据
                val outputData = workDataOf("UPLOAD_URL" to "https://example.com/images/123")
                Result.success(outputData)
            } else {
                Result.retry()
            }
        } catch (e: Exception) {
            if (runAttemptCount < 3) {
                Result.retry()
            } else {
                Result.failure()
            }
        }
    }
    
    private suspend fun uploadImage(uriString: String): Boolean {
        // 实现图片上传逻辑
        delay(2000) // 模拟网络请求
        return true
    }
}
```

3. 调度工作任务：

```kotlin
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        uploadButton.setOnClickListener {
            scheduleImageUpload("content://media/external/images/123")
        }
    }
    
    private fun scheduleImageUpload(imageUri: String) {
        // 创建输入数据
        val inputData = workDataOf("IMAGE_URI" to imageUri)
        
        // 创建约束条件
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED) // 需要网络连接
            .setRequiresBatteryNotLow(true) // 电池电量不低
            .build()
        
        // 创建一次性工作请求
        val uploadWorkRequest = OneTimeWorkRequestBuilder<ImageUploadWorker>()
            .setInputData(inputData)
            .setConstraints(constraints)
            .setBackoffCriteria(BackoffPolicy.LINEAR, 10, TimeUnit.MINUTES)
            .build()
        
        // 提交工作请求
        WorkManager.getInstance(this).enqueue(uploadWorkRequest)
        
        // 观察工作状态
        WorkManager.getInstance(this)
            .getWorkInfoByIdLiveData(uploadWorkRequest.id)
            .observe(this) { workInfo ->
                when (workInfo.state) {
                    WorkInfo.State.SUCCEEDED -> {
                        val uploadUrl = workInfo.outputData.getString("UPLOAD_URL")
                        showSuccess("上传成功: $uploadUrl")
                    }
                    WorkInfo.State.FAILED -> showError("上传失败")
                    WorkInfo.State.RUNNING -> showProgress("上传中...")
                    else -> { /* 其他状态 */ }
                }
            }
    }
    
    // 创建定期工作请求
    private fun schedulePeriodicSync() {
        val syncRequest = PeriodicWorkRequestBuilder<SyncWorker>(
            1, TimeUnit.DAYS, // 每天执行一次
            15, TimeUnit.MINUTES // 灵活时间窗口
        ).build()
        
        // 使用唯一工作名称，确保只有一个同步任务
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "daily_sync",
            ExistingPeriodicWorkPolicy.KEEP, // 如果已存在，保留现有的
            syncRequest
        )
    }
    
    // 链接多个工作
    private fun scheduleImageProcessingChain(imageUri: String) {
        val inputData = workDataOf("IMAGE_URI" to imageUri)
        
        // 第一步：压缩图片
        val compressWork = OneTimeWorkRequestBuilder<CompressImageWorker>()
            .setInputData(inputData)
            .build()
        
        // 第二步：应用滤镜
        val filterWork = OneTimeWorkRequestBuilder<ApplyFilterWorker>()
            .build()
        
        // 第三步：上传图片
        val uploadWork = OneTimeWorkRequestBuilder<ImageUploadWorker>()
            .setConstraints(Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build())
            .build()
        
        // 创建工作链
        WorkManager.getInstance(this)
            .beginWith(compressWork) // 先压缩
            .then(filterWork) // 再应用滤镜
            .then(uploadWork) // 最后上传
            .enqueue()
    }
}
```

## Paging

Paging库帮助加载和显示来自本地数据库或网络的大型数据集。

1. 添加依赖：

```gradle
dependencies {
    implementation "androidx.paging:paging-runtime-ktx:3.2.0"
}
```

2. 创建PagingSource：

```kotlin
class ArticlePagingSource(
    private val apiService: ArticleApiService
) : PagingSource<Int, Article>() {
    
    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, Article> {
        val page = params.key ?: 1
        
        return try {
            val response = apiService.getArticles(page, params.loadSize)
            val articles = response.articles
            
            LoadResult.Page(
                data = articles,
                prevKey = if (page == 1) null else page - 1,
                nextKey = if (articles.isEmpty()) null else page + 1
            )
        } catch (e: Exception) {
            LoadResult.Error(e)
        }
    }
    
    override fun getRefreshKey(state: PagingState<Int, Article>): Int? {
        return state.anchorPosition?.let { anchorPosition ->
            state.closestPageToPosition(anchorPosition)?.prevKey?.plus(1)
                ?: state.closestPageToPosition(anchorPosition)?.nextKey?.minus(1)
        }
    }
}
```

3. 创建Pager：

```kotlin
class ArticleRepository(private val apiService: ArticleApiService) {
    fun getArticleStream(): Flow<PagingData<Article>> {
        return Pager(
            config = PagingConfig(
                pageSize = 20,
                enablePlaceholders = false,
                maxSize = 100
            ),
            pagingSourceFactory = { ArticlePagingSource(apiService) }
        ).flow
    }
}
```

4. 在ViewModel中使用：

```kotlin
class ArticleViewModel(private val repository: ArticleRepository) : ViewModel() {
    val articles: Flow<PagingData<Article>> = repository.getArticleStream()
        .cachedIn(viewModelScope)
}
```

5. 在UI中显示：

```kotlin
class ArticleListFragment : Fragment() {
    private lateinit var viewModel: ArticleViewModel
    private val adapter = ArticlePagingAdapter()
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        viewModel = ViewModelProvider(this).get(ArticleViewModel::class.java)
        
        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        recyclerView.adapter = adapter
        
        // 收集分页数据流
        lifecycleScope.launch {
            viewModel.articles.collectLatest { pagingData ->
                adapter.submitData(pagingData)
            }
        }
        
        // 添加加载状态适配器
        adapter.addLoadStateListener { loadState ->
            // 显示加载状态
            progressBar.isVisible = loadState.source.refresh is LoadState.Loading
            
            // 显示错误状态
            val errorState = loadState.source.refresh as? LoadState.Error
                ?: loadState.source.append as? LoadState.Error
                ?: loadState.source.prepend as? LoadState.Error
            
            errorState?.let {
                Toast.makeText(
                    requireContext(),
                    "加载失败: ${it.error.message}",
                    Toast.LENGTH_SHORT
                ).show()
            }
        }
    }
}

// 创建PagingAdapter
class ArticlePagingAdapter : PagingDataAdapter<Article, ArticleViewHolder>(ARTICLE_COMPARATOR) {
    
    override fun onBindViewHolder(holder: ArticleViewHolder, position: Int) {
        val article = getItem(position)
        article?.let { holder.bind(it) }
    }
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ArticleViewHolder {
        return ArticleViewHolder(
            LayoutInflater.from(parent.context)
                .inflate(R.layout.item_article, parent, false)
        )
    }
    
    companion object {
        private val ARTICLE_COMPARATOR = object : DiffUtil.ItemCallback<Article>() {
            override fun areItemsTheSame(oldItem: Article, newItem: Article): Boolean {
                return oldItem.id == newItem.id
            }
            
            override fun areContentsTheSame(oldItem: Article, newItem: Article): Boolean {
                return oldItem == newItem
            }
        }
    }
}
```

## CameraX

CameraX是一个Jetpack库，简化了相机应用的开发。

1. 添加依赖：

```gradle
dependencies {
    implementation "androidx.camera:camera-core:1.2.3"
    implementation "androidx.camera:camera-camera2:1.2.3"
    implementation "androidx.camera:camera-lifecycle:1.2.3"
    implementation "androidx.camera:camera-view:1.2.3"
}
```

2. 基本用法：

```kotlin
class CameraFragment : Fragment() {
    private lateinit var cameraProviderFuture: ListenableFuture<ProcessCameraProvider>
    private lateinit var previewView: PreviewView
    private var imageCapture: ImageCapture? = null
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        previewView = view.findViewById(R.id.preview_view)
        
        // 请求相机权限
        if (allPermissionsGranted()) {
            startCamera()
        } else {
            ActivityCompat.requestPermissions(
                requireActivity(),
                REQUIRED_PERMISSIONS,
                REQUEST_CODE_PERMISSIONS
            )
        }
        
        // 拍照按钮
        captureButton.setOnClickListener {
            takePhoto()
        }
    }
    
    private fun startCamera() {
        cameraProviderFuture = ProcessCameraProvider.getInstance(requireContext())
        
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()
            
            // 创建预览用例
            val preview = Preview.Builder().build()
            preview.setSurfaceProvider(previewView.surfaceProvider)
            
            // 创建拍照用例
            imageCapture = ImageCapture.Builder()
                .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
                .build()
            
            // 选择后置摄像头
            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
            
            try {
                // 解绑所有用例
                cameraProvider.unbindAll()
                
                // 绑定用例到相机
                cameraProvider.bindToLifecycle(
                    this, cameraSelector, preview, imageCapture
                )
            } catch (e: Exception) {
                Log.e(TAG, "相机绑定失败", e)
            }
        }, ContextCompat.getMainExecutor(requireContext()))
    }
    
    private fun takePhoto() {
        val imageCapture = imageCapture ?: return
        
        // 创建带时间戳的文件名
        val fileName = "yyyy-MM-dd-HH-mm-ss-SSS".format(System.currentTimeMillis())
        val photoFile = File(
            outputDirectory,
            "$fileName.jpg"
        )
        
        // 创建输出选项
        val outputOptions = ImageCapture.OutputFileOptions.Builder(photoFile).build()
        
        // 拍照并保存
        imageCapture.takePicture(
            outputOptions,
            ContextCompat.getMainExecutor(requireContext()),
            object : ImageCapture.OnImageSavedCallback {
                override fun onImageSaved(output: ImageCapture.OutputFileResults) {
                    val savedUri = Uri.fromFile(photoFile)
                    val msg = "照片保存成功: $savedUri"
                    Toast.makeText(requireContext(), msg, Toast.LENGTH_SHORT).show()
                }
                
                override fun onError(exception: ImageCaptureException) {
                    Log.e(TAG, "拍照失败: ${exception.message}", exception)
                }
            }
        )
    }
    
    private fun allPermissionsGranted() = REQUIRED_PERMISSIONS.all {
        ContextCompat.checkSelfPermission(requireContext(), it) == PackageManager.PERMISSION_GRANTED
    }
    
    companion object {
        private const val TAG = "CameraFragment"
        private const val REQUEST_CODE_PERMISSIONS = 10
        private val REQUIRED_PERMISSIONS = arrayOf(Manifest.permission.CAMERA)
    }
}
```

## 总结

Android Jetpack组件提供了一系列强大的工具，帮助开发者构建高质量、可维护的Android应用。通过使用这些组件，可以：

1. 遵循最佳实践和推荐的架构模式
2. 减少样板代码，提高开发效率
3. 创建更健壮、可测试的应用
4. 更轻松地处理Android系统的复杂性，如生命周期管理

建议在新项目中尽可能采用Jetpack组件，并考虑将现有项目逐步迁移到这些组件上，以获得更好的开发体验和应用质量。

## 相关资源

- [Android Jetpack官方文档](https://developer.android.com/jetpack)
- [Android Architecture Components](https://developer.android.com/topic/libraries/architecture)
- [Jetpack Compose](https://developer.android.com/jetpack/compose)
- [Android开发者博客](https://android-developers.googleblog.com/)
- [Jetpack示例代码](https://github.com/android/architecture-components-samples)
