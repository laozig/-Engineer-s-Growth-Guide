# Android性能优化

性能优化是Android应用开发中的关键环节，直接影响用户体验和应用评价。本文档将介绍Android应用的性能优化技术，包括内存管理、电池优化、渲染性能、启动时间等方面。

## 性能分析工具

### Android Profiler

Android Profiler是Android Studio中内置的性能分析工具，提供了CPU、内存、网络和电池使用情况的实时监控：

1. 在Android Studio中，选择View > Tool Windows > Profiler
2. 选择要分析的进程
3. 使用各个分析器查看性能数据

#### CPU Profiler

CPU Profiler显示应用的CPU使用情况，帮助识别性能瓶颈：

- 记录方法跟踪
- 查看调用堆栈
- 分析热点方法

```kotlin
// 示例：使用Trace标记需要分析的代码段
Trace.beginSection("LoadUserData")
try {
    // 执行需要分析的代码
    loadUserData()
} finally {
    Trace.endSection()
}
```

#### 内存Profiler

内存Profiler用于监控应用的内存分配和回收：

- 强制GC并查看内存变化
- 捕获堆转储并分析对象
- 跟踪内存分配

#### 网络Profiler

网络Profiler显示应用的网络活动：

- 查看请求和响应详情
- 分析数据传输速度
- 识别过度的网络使用

#### 电池Profiler

电池Profiler帮助分析应用的能耗情况：

- 监控CPU唤醒
- 分析网络活动
- 识别耗电操作

### 其他性能分析工具

1. **Systrace**：分析系统级性能问题
2. **Perfetto**：系统性能跟踪平台
3. **StrictMode**：检测主线程IO和网络操作
4. **LeakCanary**：检测内存泄漏

```kotlin
// 启用StrictMode检测主线程IO和网络操作
if (BuildConfig.DEBUG) {
    StrictMode.setThreadPolicy(
        StrictMode.ThreadPolicy.Builder()
            .detectDiskReads()
            .detectDiskWrites()
            .detectNetwork()
            .penaltyLog() // 记录违规到Logcat
            .build()
    )
    
    StrictMode.setVmPolicy(
        StrictMode.VmPolicy.Builder()
            .detectLeakedSqlLiteObjects()
            .detectLeakedClosableObjects()
            .detectActivityLeaks()
            .penaltyLog()
            .build()
    )
}
```

## 内存优化

### 内存泄漏

内存泄漏是指应用不再使用的对象无法被垃圾回收器回收，常见原因包括：

1. **静态变量持有Activity/Context引用**
2. **内部类和匿名内部类持有外部类引用**
3. **未注销的监听器和回调**
4. **未关闭的资源（Cursor、InputStream等）**

#### 避免静态Activity/Context引用

```kotlin
// 错误示例：静态变量持有Activity引用
class BadSingleton {
    companion object {
        private var instance: BadSingleton? = null
        private lateinit var context: Context // 可能导致内存泄漏
        
        fun getInstance(context: Context): BadSingleton {
            if (instance == null) {
                this.context = context // 持有Activity引用
                instance = BadSingleton()
            }
            return instance!!
        }
    }
}

// 正确示例：使用Application Context
class GoodSingleton {
    companion object {
        private var instance: GoodSingleton? = null
        private lateinit var applicationContext: Context
        
        fun getInstance(context: Context): GoodSingleton {
            if (instance == null) {
                this.applicationContext = context.applicationContext // 使用Application Context
                instance = GoodSingleton()
            }
            return instance!!
        }
    }
}
```

#### 处理内部类引用

```kotlin
// 错误示例：非静态内部类持有外部Activity引用
class LeakyActivity : AppCompatActivity() {
    private val handler = object : Handler() {
        override fun handleMessage(msg: Message) {
            // 使用Activity，可能导致泄漏
        }
    }
}

// 正确示例：使用静态内部类和弱引用
class NonLeakyActivity : AppCompatActivity() {
    private var handler: MyHandler? = null
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handler = MyHandler(this)
    }
    
    override fun onDestroy() {
        super.onDestroy()
        handler?.removeCallbacksAndMessages(null) // 清除所有回调和消息
        handler = null
    }
    
    // 静态内部类不持有外部类引用
    private class MyHandler(activity: NonLeakyActivity) : Handler() {
        // 使用弱引用避免内存泄漏
        private val activityRef: WeakReference<NonLeakyActivity> = WeakReference(activity)
        
        override fun handleMessage(msg: Message) {
            val activity = activityRef.get()
            if (activity != null && !activity.isFinishing) {
                // 安全地使用Activity
            }
        }
    }
}
```

#### 注销监听器和回调

```kotlin
class MyFragment : Fragment() {
    private lateinit var locationManager: LocationManager
    private lateinit var locationListener: LocationListener
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        locationManager = requireContext().getSystemService(Context.LOCATION_SERVICE) as LocationManager
        locationListener = object : LocationListener {
            // 实现方法
        }
        
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED) {
            locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0f, locationListener)
        }
    }
    
    override fun onDestroyView() {
        super.onDestroyView()
        // 注销监听器
        locationManager.removeUpdates(locationListener)
    }
}
```

#### 关闭资源

```kotlin
// 使用try-with-resources自动关闭资源
fun readFile(filePath: String): String {
    return FileInputStream(filePath).use { inputStream ->
        BufferedReader(InputStreamReader(inputStream)).use { reader ->
            val stringBuilder = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                stringBuilder.append(line).append('\n')
            }
            stringBuilder.toString()
        }
    }
}
```

### 内存使用优化

#### 使用适当的数据结构

```kotlin
// 对于大量数据，使用SparseArray代替HashMap可以减少内存使用
// HashMap<Integer, Object> 替代
val sparseArray = SparseArray<Any>()
sparseArray.put(1, "Value 1")
sparseArray.put(2, "Value 2")

// HashMap<Integer, Boolean> 替代
val sparseBooleanArray = SparseBooleanArray()
sparseBooleanArray.put(1, true)
sparseBooleanArray.put(2, false)

// HashMap<Integer, Integer> 替代
val sparseIntArray = SparseIntArray()
sparseIntArray.put(1, 100)
sparseIntArray.put(2, 200)

// HashMap<Long, Object> 替代
val longSparseArray = LongSparseArray<Any>()
longSparseArray.put(1L, "Value 1")
longSparseArray.put(2L, "Value 2")
```

#### 优化Bitmap内存

```kotlin
// 加载适当大小的Bitmap
fun decodeSampledBitmapFromResource(
    res: Resources,
    resId: Int,
    reqWidth: Int,
    reqHeight: Int
): Bitmap {
    // 首先只解码尺寸
    val options = BitmapFactory.Options().apply {
        inJustDecodeBounds = true
    }
    BitmapFactory.decodeResource(res, resId, options)
    
    // 计算采样率
    options.inSampleSize = calculateInSampleSize(options, reqWidth, reqHeight)
    
    // 使用采样率解码图片
    options.inJustDecodeBounds = false
    return BitmapFactory.decodeResource(res, resId, options)
}

// 计算采样率
fun calculateInSampleSize(
    options: BitmapFactory.Options,
    reqWidth: Int,
    reqHeight: Int
): Int {
    val (height: Int, width: Int) = options.run { outHeight to outWidth }
    var inSampleSize = 1
    
    if (height > reqHeight || width > reqWidth) {
        val halfHeight: Int = height / 2
        val halfWidth: Int = width / 2
        
        // 计算最大的采样率，使得结果不小于请求的宽高
        while (halfHeight / inSampleSize >= reqHeight && halfWidth / inSampleSize >= reqWidth) {
            inSampleSize *= 2
        }
    }
    
    return inSampleSize
}
```

#### 使用对象池

```kotlin
// 简单对象池实现
class ObjectPool<T>(
    private val maxSize: Int,
    private val factory: () -> T,
    private val reset: (T) -> Unit
) {
    private val pool = ArrayDeque<T>(maxSize)
    
    @Synchronized
    fun acquire(): T {
        return if (pool.isEmpty()) {
            factory()
        } else {
            pool.removeFirst()
        }
    }
    
    @Synchronized
    fun release(obj: T) {
        if (pool.size < maxSize) {
            reset(obj)
            pool.addLast(obj)
        }
    }
}

// 使用示例
val rectPool = ObjectPool(
    maxSize = 50,
    factory = { Rect() },
    reset = { it.setEmpty() }
)

fun processRects() {
    val rect = rectPool.acquire()
    try {
        // 使用rect
        rect.set(0, 0, 100, 100)
        // 处理逻辑...
    } finally {
        rectPool.release(rect)
    }
}
```

## 电池优化

### 减少唤醒锁使用

```kotlin
// 谨慎使用WakeLock
val wakeLock: PowerManager.WakeLock = (getSystemService(Context.POWER_SERVICE) as PowerManager).run {
    newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MyApp::MyWakelockTag").apply {
        acquire(10*60*1000L /*10分钟*/)
    }
}

// 使用完毕后释放
wakeLock.release()
```

### 批量处理操作

```kotlin
// 使用JobScheduler批量处理后台任务
val jobScheduler = getSystemService(Context.JOB_SCHEDULER_SERVICE) as JobScheduler

val jobInfo = JobInfo.Builder(JOB_ID, ComponentName(this, MyJobService::class.java))
    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_UNMETERED) // 仅在WiFi下执行
    .setRequiresCharging(true) // 仅在充电时执行
    .setRequiresDeviceIdle(true) // 仅在设备空闲时执行
    .setPersisted(true) // 设备重启后任务仍然有效
    .setPeriodic(15 * 60 * 1000) // 每15分钟执行一次
    .build()

jobScheduler.schedule(jobInfo)
```

### 优化位置更新

```kotlin
// 根据需求设置适当的位置更新频率
val locationRequest = LocationRequest.create().apply {
    interval = 10000 // 10秒更新一次
    fastestInterval = 5000 // 最快5秒更新一次
    priority = LocationRequest.PRIORITY_BALANCED_POWER_ACCURACY // 平衡精度和电量
}

// 使用位置围栏代替持续位置更新
val geofencingClient = LocationServices.getGeofencingClient(this)
val geofence = Geofence.Builder()
    .setRequestId("my_geofence")
    .setCircularRegion(latitude, longitude, radius)
    .setExpirationDuration(Geofence.NEVER_EXPIRE)
    .setTransitionTypes(Geofence.GEOFENCE_TRANSITION_ENTER or Geofence.GEOFENCE_TRANSITION_EXIT)
    .build()

val geofencingRequest = GeofencingRequest.Builder()
    .setInitialTrigger(GeofencingRequest.INITIAL_TRIGGER_ENTER)
    .addGeofence(geofence)
    .build()

geofencingClient.addGeofences(geofencingRequest, geofencePendingIntent)
```

### 优化网络请求

```kotlin
// 使用WorkManager执行可延迟的网络请求
val constraints = Constraints.Builder()
    .setRequiredNetworkType(NetworkType.UNMETERED) // 仅在WiFi下执行
    .setRequiresBatteryNotLow(true) // 电量不低时执行
    .build()

val syncWorkRequest = PeriodicWorkRequestBuilder<SyncWorker>(1, TimeUnit.HOURS)
    .setConstraints(constraints)
    .build()

WorkManager.getInstance(this).enqueueUniquePeriodicWork(
    "sync_data",
    ExistingPeriodicWorkPolicy.KEEP,
    syncWorkRequest
)
```

## 渲染优化

### 避免UI线程阻塞

```kotlin
// 错误示例：在主线程执行耗时操作
fun onButtonClick() {
    // 直接在UI线程执行网络请求，会导致UI卡顿
    val response = api.fetchData()
    updateUI(response)
}

// 正确示例：使用协程在后台线程执行耗时操作
fun onButtonClick() {
    lifecycleScope.launch {
        // 显示加载状态
        showLoading()
        
        // 在IO线程执行网络请求
        val response = withContext(Dispatchers.IO) {
            api.fetchData()
        }
        
        // 自动切回主线程更新UI
        hideLoading()
        updateUI(response)
    }
}
```

### 优化布局层次

```xml
<!-- 过深的布局层次 -->
<LinearLayout>
    <LinearLayout>
        <LinearLayout>
            <TextView />
            <TextView />
        </LinearLayout>
    </LinearLayout>
</LinearLayout>

<!-- 优化后的布局层次 -->
<androidx.constraintlayout.widget.ConstraintLayout>
    <TextView
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintStart_toStartOf="parent" />
    <TextView
        app:layout_constraintTop_toBottomOf="@id/first_text_view"
        app:layout_constraintStart_toStartOf="parent" />
</androidx.constraintlayout.widget.ConstraintLayout>
```

使用布局优化工具：

1. **Layout Inspector**：分析运行时的视图层次
2. **Hierarchy Viewer**：查看布局性能
3. **Lint**：检测布局问题

### 使用ViewHolder模式

```kotlin
// RecyclerView中使用ViewHolder模式
class MyAdapter : RecyclerView.Adapter<MyAdapter.ViewHolder>() {
    
    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val titleView: TextView = view.findViewById(R.id.title)
        val descriptionView: TextView = view.findViewById(R.id.description)
        val imageView: ImageView = view.findViewById(R.id.image)
    }
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_view, parent, false)
        return ViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.titleView.text = item.title
        holder.descriptionView.text = item.description
        Glide.with(holder.imageView.context)
            .load(item.imageUrl)
            .into(holder.imageView)
    }
    
    override fun getItemCount() = items.size
}
```

### 避免过度绘制

1. **启用过度绘制调试**：
   - 设置 > 开发者选项 > 调试GPU过度绘制

2. **减少过度绘制的方法**：
   - 移除不必要的背景
   - 使用`clipRect()`和`quickReject()`减少绘制区域
   - 扁平化视图层次
   - 使用自定义视图合并绘制操作

```kotlin
// 自定义View中优化绘制
override fun onDraw(canvas: Canvas) {
    // 检查是否需要绘制
    if (!isVisible || alpha == 0f) {
        return
    }
    
    // 使用clipRect限制绘制区域
    canvas.save()
    canvas.clipRect(visibleRect)
    
    // 执行绘制
    // ...
    
    canvas.restore()
}
```

### 使用硬件加速

```xml
<!-- 在AndroidManifest.xml中启用硬件加速 -->
<application
    android:hardwareAccelerated="true"
    ...>
</application>

<!-- 对特定Activity禁用硬件加速 -->
<activity
    android:name=".MyActivity"
    android:hardwareAccelerated="false" />
```

```kotlin
// 在代码中为特定View启用/禁用硬件加速
view.setLayerType(View.LAYER_TYPE_HARDWARE, null) // 启用
view.setLayerType(View.LAYER_TYPE_SOFTWARE, null) // 禁用
```

## 启动时间优化

### 测量启动时间

```kotlin
// 在Application中记录启动时间
class MyApplication : Application() {
    override fun onCreate() {
        val startTime = System.currentTimeMillis()
        super.onCreate()
        
        // 初始化操作...
        
        val endTime = System.currentTimeMillis()
        Log.d("AppStartup", "Application初始化时间: ${endTime - startTime}ms")
    }
}

// 在首个Activity中记录可见时间
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        val startTime = System.currentTimeMillis()
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // 记录布局加载时间
        val layoutTime = System.currentTimeMillis()
        Log.d("AppStartup", "布局加载时间: ${layoutTime - startTime}ms")
        
        // 使用ViewTreeObserver监听第一帧绘制
        window.decorView.viewTreeObserver.addOnPreDrawListener(object : ViewTreeObserver.OnPreDrawListener {
            override fun onPreDraw(): Boolean {
                window.decorView.viewTreeObserver.removeOnPreDrawListener(this)
                val firstDrawTime = System.currentTimeMillis()
                Log.d("AppStartup", "首帧绘制时间: ${firstDrawTime - startTime}ms")
                return true
            }
        })
    }
}
```

### 延迟初始化

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // 必须立即初始化的组件
        initCriticalComponents()
        
        // 延迟初始化非关键组件
        Handler(Looper.getMainLooper()).post {
            initNonCriticalComponents()
        }
        
        // 在首个Activity可见后初始化
        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityResumed(activity: Activity) {
                if (activity is MainActivity) {
                    unregisterActivityLifecycleCallbacks(this)
                    initDeferredComponents()
                }
            }
            
            // 其他回调方法...
        })
    }
    
    private fun initCriticalComponents() {
        // 初始化崩溃报告、核心配置等
    }
    
    private fun initNonCriticalComponents() {
        // 初始化分析工具、远程配置等
    }
    
    private fun initDeferredComponents() {
        // 初始化推送服务、广告SDK等
    }
}
```

### 使用App Startup库

```gradle
dependencies {
    implementation "androidx.startup:startup-runtime:1.1.1"
}
```

```kotlin
// 创建初始化器
class AnalyticsInitializer : Initializer<AnalyticsManager> {
    override fun create(context: Context): AnalyticsManager {
        // 初始化分析管理器
        AnalyticsManager.init(context)
        return AnalyticsManager.getInstance()
    }
    
    override fun dependencies(): List<Class<out Initializer<*>>> {
        // 声明依赖的其他初始化器
        return emptyList()
    }
}

// 在AndroidManifest.xml中注册
<provider
    android:name="androidx.startup.InitializationProvider"
    android:authorities="${applicationId}.androidx-startup"
    android:exported="false">
    <meta-data
        android:name="com.example.AnalyticsInitializer"
        android:value="androidx.startup" />
</provider>
```

### 优化布局加载

```kotlin
// 使用ViewStub延迟加载不立即可见的复杂布局
<ViewStub
    android:id="@+id/stub_detail"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:layout="@layout/layout_detail" />

// 在需要时加载
val viewStub = findViewById<ViewStub>(R.id.stub_detail)
val detailView = viewStub.inflate()
```

```kotlin
// 使用AsyncLayoutInflater异步加载布局
val asyncInflater = AsyncLayoutInflater(this)
asyncInflater.inflate(R.layout.complex_layout, null) { view, resid, parent ->
    container.addView(view)
    // 初始化视图...
}
```

## 网络优化

### 减少请求次数

```kotlin
// 使用批量API
interface UserApi {
    @GET("users/{userId}")
    suspend fun getUser(@Path("userId") userId: String): User
    
    @GET("users")
    suspend fun getUsers(@Query("ids") userIds: String): List<User>
}

// 批量获取用户
val userIds = listOf("1", "2", "3").joinToString(",")
val users = api.getUsers(userIds)
```

### 压缩数据

```kotlin
// 使用OkHttp的GzipInterceptor
val client = OkHttpClient.Builder()
    .addInterceptor { chain ->
        val originalRequest = chain.request()
        val compressedRequest = originalRequest.newBuilder()
            .header("Accept-Encoding", "gzip")
            .build()
        chain.proceed(compressedRequest)
    }
    .build()
```

### 缓存响应

```kotlin
// 配置OkHttp缓存
val cacheSize = 10 * 1024 * 1024 // 10 MB
val cache = Cache(File(cacheDir, "http_cache"), cacheSize.toLong())

val client = OkHttpClient.Builder()
    .cache(cache)
    .addNetworkInterceptor { chain ->
        val response = chain.proceed(chain.request())
        // 缓存一周
        response.newBuilder()
            .header("Cache-Control", "public, max-age=604800")
            .build()
    }
    .build()
```

### 使用高效的序列化

```gradle
dependencies {
    implementation "com.squareup.moshi:moshi:1.13.0"
    implementation "com.squareup.moshi:moshi-kotlin:1.13.0"
}
```

```kotlin
// 使用Moshi替代Gson
val moshi = Moshi.Builder()
    .add(KotlinJsonAdapterFactory())
    .build()

val retrofit = Retrofit.Builder()
    .baseUrl("https://api.example.com/")
    .addConverterFactory(MoshiConverterFactory.create(moshi))
    .client(client)
    .build()
```

## 总结

Android性能优化是一个持续的过程，需要从多个方面入手：

1. **内存优化**：避免内存泄漏，减少内存使用，合理管理对象生命周期
2. **电池优化**：减少唤醒锁使用，批量处理操作，优化位置更新和网络请求
3. **渲染优化**：避免UI线程阻塞，优化布局层次，减少过度绘制
4. **启动时间优化**：延迟初始化，异步加载布局，使用App Startup库
5. **网络优化**：减少请求次数，压缩数据，缓存响应，使用高效序列化

通过使用本文介绍的工具和技术，可以显著提高Android应用的性能和用户体验。记住，性能优化应该是一个持续的过程，而不是一次性的任务。

## 相关资源

- [Android性能优化最佳实践](https://developer.android.com/topic/performance)
- [Android Profiler指南](https://developer.android.com/studio/profile/android-profiler)
- [内存泄漏分析](https://developer.android.com/studio/profile/memory-profiler)
- [电池优化](https://developer.android.com/topic/performance/power)
- [渲染性能](https://developer.android.com/topic/performance/rendering)
- [应用启动时间](https://developer.android.com/topic/performance/vitals/launch-time)
