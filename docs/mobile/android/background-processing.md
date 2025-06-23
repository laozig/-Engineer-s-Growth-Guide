# Android后台处理

在Android应用中，后台处理是指在不阻塞主线程（UI线程）的情况下执行耗时操作的机制。本文档介绍Android中各种后台处理技术，包括线程、Handler、Service、WorkManager等。

## 线程基础

### 主线程与工作线程

Android应用启动时会创建一个主线程（UI线程），负责处理用户交互和UI更新。在主线程上执行耗时操作会导致应用无响应（ANR - Application Not Responding）。

```kotlin
// 错误示例：在主线程执行耗时操作
fun onButtonClick() {
    // 这会阻塞UI线程，可能导致ANR
    Thread.sleep(5000) // 模拟耗时操作
    updateUI() // 更新UI
}

// 正确示例：使用工作线程
fun onButtonClick() {
    Thread {
        // 在工作线程执行耗时操作
        Thread.sleep(5000) // 模拟耗时操作
        
        // 在主线程更新UI
        runOnUiThread {
            updateUI()
        }
    }.start()
}
```

### 使用Handler进行线程通信

Handler允许在不同线程之间发送和处理消息，通常用于工作线程和UI线程之间的通信：

```kotlin
// 在主线程创建Handler
private val handler = Handler(Looper.getMainLooper())

fun onButtonClick() {
    Thread {
        // 在工作线程执行耗时操作
        val result = performLongOperation()
        
        // 使用Handler将结果发送到主线程
        handler.post {
            updateUI(result)
        }
        
        // 或者延迟执行
        handler.postDelayed({
            showToast("操作完成")
        }, 1000) // 1秒后执行
    }.start()
}

private fun performLongOperation(): String {
    Thread.sleep(3000) // 模拟耗时操作
    return "操作结果"
}
```

### 使用HandlerThread

HandlerThread是一个具有消息循环的线程，更适合需要顺序处理消息的场景：

```kotlin
private lateinit var handlerThread: HandlerThread
private lateinit var backgroundHandler: Handler

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    
    // 创建并启动HandlerThread
    handlerThread = HandlerThread("BackgroundThread")
    handlerThread.start()
    
    // 在HandlerThread的Looper上创建Handler
    backgroundHandler = Handler(handlerThread.looper)
}

fun processImage(bitmap: Bitmap) {
    // 在后台线程处理图片
    backgroundHandler.post {
        val processedBitmap = applyFilter(bitmap)
        
        // 在主线程更新UI
        runOnUiThread {
            imageView.setImageBitmap(processedBitmap)
        }
    }
}

override fun onDestroy() {
    super.onDestroy()
    // 退出HandlerThread
    handlerThread.quit()
}
```

## 异步任务

### 使用Kotlin协程

Kotlin协程是一种轻量级线程，提供了简洁的异步编程方式：

1. 添加依赖：

```gradle
dependencies {
    implementation 'org.jetbrains.kotlinx:kotlinx-coroutines-android:1.6.4'
}
```

2. 基本用法：

```kotlin
// 在ViewModel中使用协程
class MyViewModel : ViewModel() {
    private val viewModelScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    
    fun fetchData() {
        viewModelScope.launch {
            // 在IO调度器上执行网络请求
            val result = withContext(Dispatchers.IO) {
                api.fetchData() // 挂起函数
            }
            
            // 回到主线程更新UI
            updateUI(result)
        }
    }
    
    override fun onCleared() {
        super.onCleared()
        viewModelScope.cancel() // 取消所有协程
    }
}

// 在Activity/Fragment中使用lifecycleScope
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        lifecycleScope.launch {
            // 在IO调度器上执行耗时操作
            val result = withContext(Dispatchers.IO) {
                performLongOperation()
            }
            
            // 自动回到主线程
            updateUI(result)
        }
    }
}
```

3. 协程的异常处理：

```kotlin
viewModelScope.launch {
    try {
        val result = withContext(Dispatchers.IO) {
            api.fetchData()
        }
        updateUI(result)
    } catch (e: Exception) {
        handleError(e)
    }
}

// 使用supervisorScope处理子协程异常
viewModelScope.launch {
    supervisorScope {
        val deferredResult1 = async(Dispatchers.IO) { api.fetchData1() }
        val deferredResult2 = async(Dispatchers.IO) { api.fetchData2() }
        
        try {
            val result1 = deferredResult1.await()
            updateUI1(result1)
        } catch (e: Exception) {
            handleError1(e)
        }
        
        try {
            val result2 = deferredResult2.await()
            updateUI2(result2)
        } catch (e: Exception) {
            handleError2(e)
        }
    }
}
```

4. 协程的取消：

```kotlin
// 创建可取消的协程
val job = lifecycleScope.launch {
    while (isActive) { // 检查协程是否活跃
        delay(1000)
        updateProgress()
    }
}

// 取消协程
fun cancelOperation() {
    job.cancel()
}
```

### RxJava

RxJava是一个响应式编程库，提供了强大的异步操作和数据流处理能力：

1. 添加依赖：

```gradle
dependencies {
    implementation 'io.reactivex.rxjava3:rxjava:3.1.5'
    implementation 'io.reactivex.rxjava3:rxandroid:3.0.2'
}
```

2. 基本用法：

```kotlin
// 创建Observable
val observable = Observable.create<String> { emitter ->
    try {
        val result = performLongOperation()
        emitter.onNext(result)
        emitter.onComplete()
    } catch (e: Exception) {
        emitter.onError(e)
    }
}

// 订阅Observable
val disposable = observable
    .subscribeOn(Schedulers.io()) // 在IO线程执行
    .observeOn(AndroidSchedulers.mainThread()) // 在主线程观察结果
    .subscribe(
        { result -> updateUI(result) }, // onNext
        { error -> handleError(error) }, // onError
        { Log.d("RxJava", "Completed") } // onComplete
    )

// 不再需要时释放资源
override fun onDestroy() {
    super.onDestroy()
    disposable.dispose()
}
```

3. 操作符示例：

```kotlin
// map操作符：转换数据
Observable.just("Hello")
    .map { it + " World" }
    .subscribe { Log.d("RxJava", it) } // 输出: Hello World

// filter操作符：过滤数据
Observable.fromArray(1, 2, 3, 4, 5)
    .filter { it % 2 == 0 }
    .subscribe { Log.d("RxJava", "$it") } // 输出: 2, 4

// flatMap操作符：转换为新的Observable
Observable.just("user123")
    .flatMap { userId -> getUserDetails(userId) }
    .subscribe { userDetails ->
        Log.d("RxJava", "User: $userDetails")
    }

private fun getUserDetails(userId: String): Observable<String> {
    return Observable.just("User details for $userId")
}
```

## Service

Service是Android组件，用于在后台执行长时间运行的操作，即使用户切换到其他应用也能继续运行。

### 基本Service

```kotlin
// 定义Service
class MyService : Service() {
    override fun onBind(intent: Intent?): IBinder? {
        return null // 返回null表示这是一个"启动型"Service
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 执行后台任务
        Thread {
            performLongRunningTask()
        }.start()
        
        // 返回值决定系统如何在Service被杀死后重新创建它
        return START_STICKY
    }
    
    private fun performLongRunningTask() {
        // 执行耗时操作
    }
    
    override fun onDestroy() {
        super.onDestroy()
        // 清理资源
    }
}

// 在AndroidManifest.xml中注册Service
// <service android:name=".MyService" />

// 启动Service
fun startMyService() {
    val intent = Intent(this, MyService::class.java)
    startService(intent)
}

// 停止Service
fun stopMyService() {
    val intent = Intent(this, MyService::class.java)
    stopService(intent)
}
```

### 前台Service

前台Service显示一个通知，告知用户应用正在后台运行，这样可以避免系统在资源紧张时终止Service：

```kotlin
class MyForegroundService : Service() {
    private val NOTIFICATION_ID = 1
    private val CHANNEL_ID = "ForegroundServiceChannel"
    
    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 创建通知
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("前台服务运行中")
            .setContentText("正在执行后台任务...")
            .setSmallIcon(R.drawable.ic_notification)
            .build()
        
        // 启动为前台服务
        startForeground(NOTIFICATION_ID, notification)
        
        // 执行后台任务
        Thread {
            performLongRunningTask()
        }.start()
        
        return START_STICKY
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                "前台服务通道",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(serviceChannel)
        }
    }
}

// 在AndroidManifest.xml中添加权限
// <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />

// 启动前台服务
fun startForegroundService() {
    val intent = Intent(this, MyForegroundService::class.java)
    
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        startForegroundService(intent)
    } else {
        startService(intent)
    }
}
```

### IntentService（已弃用）

IntentService是一个处理异步请求的Service子类，它会创建一个工作线程来处理所有请求，处理完成后自动停止。从Android 11开始，IntentService已被弃用，推荐使用WorkManager或JobIntentService。

```kotlin
// 使用JobIntentService替代IntentService
class MyJobIntentService : JobIntentService() {
    companion object {
        private const val JOB_ID = 1000
        
        fun enqueueWork(context: Context, work: Intent) {
            enqueueWork(context, MyJobIntentService::class.java, JOB_ID, work)
        }
    }
    
    override fun onHandleWork(intent: Intent) {
        // 在工作线程中执行任务
        Log.d("MyJobIntentService", "执行后台任务")
        Thread.sleep(5000) // 模拟耗时操作
    }
}

// 在AndroidManifest.xml中添加权限
// <uses-permission android:name="android.permission.WAKE_LOCK" />
// <uses-permission android:name="android.permission.BIND_JOB_SERVICE" />

// 启动JobIntentService
fun startJobIntentService() {
    val intent = Intent()
    intent.putExtra("key", "value")
    MyJobIntentService.enqueueWork(this, intent)
}
```

### 绑定Service

绑定Service允许组件（如Activity）与Service进行交互，发送请求、获取结果等：

```kotlin
// 定义绑定Service
class MyBindService : Service() {
    // Binder提供客户端与Service交互的接口
    inner class LocalBinder : Binder() {
        fun getService(): MyBindService = this@MyBindService
    }
    
    private val binder = LocalBinder()
    
    override fun onBind(intent: Intent): IBinder {
        return binder
    }
    
    // Service提供的方法
    fun performOperation(): String {
        return "操作结果"
    }
}

// 在Activity中绑定Service
class MainActivity : AppCompatActivity() {
    private var myService: MyBindService? = null
    private var isBound = false
    
    // Service连接监听器
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as MyBindService.LocalBinder
            myService = binder.getService()
            isBound = true
            
            // 可以调用Service的方法
            val result = myService?.performOperation()
            Log.d("MainActivity", "Service返回结果: $result")
        }
        
        override fun onServiceDisconnected(name: ComponentName?) {
            myService = null
            isBound = false
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }
    
    override fun onStart() {
        super.onStart()
        // 绑定Service
        Intent(this, MyBindService::class.java).also { intent ->
            bindService(intent, connection, Context.BIND_AUTO_CREATE)
        }
    }
    
    override fun onStop() {
        super.onStop()
        // 解绑Service
        if (isBound) {
            unbindService(connection)
            isBound = false
        }
    }
}
```

## WorkManager

WorkManager是Jetpack库，提供了一种可靠的方式来调度可延迟的异步任务，即使应用退出或设备重启也能保证任务执行。

### 添加依赖

```gradle
dependencies {
    implementation "androidx.work:work-runtime-ktx:2.8.1"
}
```

### 创建Worker

```kotlin
class DataSyncWorker(
    context: Context,
    workerParams: WorkerParameters
) : Worker(context, workerParams) {
    
    override fun doWork(): Result {
        try {
            // 获取输入数据
            val dataSource = inputData.getString("DATA_SOURCE")
            Log.d("DataSyncWorker", "开始同步数据，来源: $dataSource")
            
            // 执行后台任务
            syncData()
            
            // 创建输出数据
            val outputData = workDataOf("SYNC_RESULT" to "同步成功")
            
            // 返回成功结果和输出数据
            return Result.success(outputData)
        } catch (e: Exception) {
            Log.e("DataSyncWorker", "同步失败", e)
            
            // 根据错误类型决定是否重试
            return if (isRetryable(e)) {
                Result.retry()
            } else {
                Result.failure()
            }
        }
    }
    
    private fun syncData() {
        // 模拟同步操作
        Thread.sleep(3000)
    }
    
    private fun isRetryable(exception: Exception): Boolean {
        // 判断异常是否可重试
        return exception is IOException
    }
}
```

### 调度一次性任务

```kotlin
fun scheduleOneTimeWork() {
    // 创建输入数据
    val inputData = workDataOf(
        "DATA_SOURCE" to "cloud",
        "SYNC_TYPE" to "full"
    )
    
    // 创建工作请求
    val syncWorkRequest = OneTimeWorkRequestBuilder<DataSyncWorker>()
        .setInputData(inputData)
        .setConstraints(createConstraints())
        .setBackoffCriteria(
            BackoffPolicy.LINEAR,
            OneTimeWorkRequest.MIN_BACKOFF_MILLIS,
            TimeUnit.MILLISECONDS
        )
        .build()
    
    // 提交工作请求
    WorkManager.getInstance(this)
        .enqueue(syncWorkRequest)
    
    // 观察工作状态
    WorkManager.getInstance(this)
        .getWorkInfoByIdLiveData(syncWorkRequest.id)
        .observe(this) { workInfo ->
            if (workInfo != null) {
                when (workInfo.state) {
                    WorkInfo.State.SUCCEEDED -> {
                        val result = workInfo.outputData.getString("SYNC_RESULT")
                        Log.d("MainActivity", "工作完成: $result")
                    }
                    WorkInfo.State.FAILED -> {
                        Log.d("MainActivity", "工作失败")
                    }
                    WorkInfo.State.RUNNING -> {
                        Log.d("MainActivity", "工作运行中")
                    }
                    else -> {
                        Log.d("MainActivity", "工作状态: ${workInfo.state}")
                    }
                }
            }
        }
}

private fun createConstraints(): Constraints {
    return Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED) // 需要网络连接
        .setRequiresBatteryNotLow(true) // 电量不低
        .setRequiresStorageNotLow(true) // 存储空间不低
        .build()
}
```

### 调度周期性任务

```kotlin
fun schedulePeriodicWork() {
    // 创建周期性工作请求
    val periodicWorkRequest = PeriodicWorkRequestBuilder<DataSyncWorker>(
        15, TimeUnit.MINUTES, // 重复间隔
        5, TimeUnit.MINUTES   // 灵活间隔
    )
        .setConstraints(createConstraints())
        .build()
    
    // 提交工作请求（替换已有的同名工作）
    WorkManager.getInstance(this)
        .enqueueUniquePeriodicWork(
            "periodic_sync",
            ExistingPeriodicWorkPolicy.REPLACE,
            periodicWorkRequest
        )
}
```

### 链式任务

```kotlin
fun scheduleChainedWork() {
    // 第一个任务：压缩图片
    val compressWorkRequest = OneTimeWorkRequestBuilder<CompressWorker>()
        .build()
    
    // 第二个任务：上传图片
    val uploadWorkRequest = OneTimeWorkRequestBuilder<UploadWorker>()
        .build()
    
    // 第三个任务：清理临时文件
    val cleanupWorkRequest = OneTimeWorkRequestBuilder<CleanupWorker>()
        .build()
    
    // 创建并提交工作链
    WorkManager.getInstance(this)
        .beginWith(compressWorkRequest) // 从压缩任务开始
        .then(uploadWorkRequest)        // 然后执行上传任务
        .then(cleanupWorkRequest)       // 最后执行清理任务
        .enqueue()
}
```

### 取消任务

```kotlin
// 通过ID取消
fun cancelWorkById(workId: UUID) {
    WorkManager.getInstance(this).cancelWorkById(workId)
}

// 通过标签取消
fun cancelWorkByTag(tag: String) {
    WorkManager.getInstance(this).cancelAllWorkByTag(tag)
}

// 取消所有未完成的工作
fun cancelAllWork() {
    WorkManager.getInstance(this).cancelAllWork()
}
```

## AlarmManager

AlarmManager允许在特定时间执行操作，即使应用未运行也能触发。但它不像WorkManager那样可靠，可能受到系统电池优化的影响。

```kotlin
fun scheduleAlarm() {
    val alarmManager = getSystemService(Context.ALARM_SERVICE) as AlarmManager
    val intent = Intent(this, AlarmReceiver::class.java)
    val pendingIntent = PendingIntent.getBroadcast(
        this,
        0,
        intent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )
    
    // 设置闹钟时间
    val triggerTime = System.currentTimeMillis() + 60 * 60 * 1000 // 1小时后
    
    // 根据Android版本选择不同的设置方法
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        // 允许在Doze模式下唤醒设备
        alarmManager.setExactAndAllowWhileIdle(
            AlarmManager.RTC_WAKEUP,
            triggerTime,
            pendingIntent
        )
    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
        // 精确闹钟
        alarmManager.setExact(
            AlarmManager.RTC_WAKEUP,
            triggerTime,
            pendingIntent
        )
    } else {
        // 旧版API
        alarmManager.set(
            AlarmManager.RTC_WAKEUP,
            triggerTime,
            pendingIntent
        )
    }
}

// 创建广播接收器处理闹钟事件
class AlarmReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // 处理闹钟事件
        Log.d("AlarmReceiver", "闹钟触发")
        
        // 可以启动Service执行任务
        val serviceIntent = Intent(context, MyService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(serviceIntent)
        } else {
            context.startService(serviceIntent)
        }
    }
}

// 在AndroidManifest.xml中注册广播接收器
// <receiver android:name=".AlarmReceiver" />
```

## 后台处理的最佳实践

1. **选择合适的API**：
   - 短时间任务（几秒到几分钟）：协程、RxJava
   - 需要在UI不可见时运行的任务：Service
   - 可延迟的任务（同步、备份等）：WorkManager
   - 精确定时的任务：AlarmManager

2. **电池优化**：
   - 避免频繁唤醒设备
   - 批量处理网络请求
   - 使用WorkManager的约束条件（如需要充电时、有Wi-Fi时）

3. **后台限制适应**：
   - Android 8.0+对后台Service有严格限制
   - 使用前台Service时显示有意义的通知
   - 考虑使用WorkManager替代Service进行后台处理

4. **资源管理**：
   - 及时释放资源（关闭数据库连接、网络连接等）
   - 取消不再需要的任务
   - 避免内存泄漏

5. **错误处理**：
   - 实现适当的重试机制
   - 记录错误并上报
   - 提供用户可见的错误反馈

## 总结

本文档介绍了Android中的各种后台处理技术，包括线程、Handler、协程、RxJava、Service和WorkManager等。不同的技术适用于不同的场景，开发者应根据应用需求选择合适的方案，并遵循最佳实践以提供良好的用户体验和优化电池使用。

## 下一步学习

- [通知与推送](notifications.md)
- [Jetpack组件](jetpack.md)
- [性能优化](performance.md)
