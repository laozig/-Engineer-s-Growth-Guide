# Android基础组件

Android应用由多个核心组件构成，这些组件是Android应用架构的基础。本文档将详细介绍Android的基础组件：Activity、Fragment、Service、BroadcastReceiver和ContentProvider。

## Activity

Activity是Android应用中与用户交互的入口点，代表应用中的一个屏幕。

### Activity生命周期

Activity生命周期由一系列回调方法组成，用于管理Activity的状态变化：

![Activity生命周期](https://developer.android.com/guide/components/images/activity_lifecycle.png)

主要生命周期方法：

```kotlin
class MainActivity : AppCompatActivity() {
    
    // 创建Activity时调用，用于初始化
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        Log.d("ActivityLifecycle", "onCreate")
    }
    
    // Activity变为可见时调用
    override fun onStart() {
        super.onStart()
        Log.d("ActivityLifecycle", "onStart")
    }
    
    // Activity获取焦点，可与用户交互
    override fun onResume() {
        super.onResume()
        Log.d("ActivityLifecycle", "onResume")
    }
    
    // Activity失去焦点，但仍可见
    override fun onPause() {
        super.onPause()
        Log.d("ActivityLifecycle", "onPause")
    }
    
    // Activity不再可见
    override fun onStop() {
        super.onStop()
        Log.d("ActivityLifecycle", "onStop")
    }
    
    // Activity被销毁前调用
    override fun onDestroy() {
        super.onDestroy()
        Log.d("ActivityLifecycle", "onDestroy")
    }
    
    // 系统销毁Activity后重新创建时恢复状态
    override fun onRestoreInstanceState(savedInstanceState: Bundle) {
        super.onRestoreInstanceState(savedInstanceState)
        Log.d("ActivityLifecycle", "onRestoreInstanceState")
    }
    
    // 保存Activity状态，在onStop之后调用
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        Log.d("ActivityLifecycle", "onSaveInstanceState")
    }
}
```

### Activity启动模式

Android提供了四种启动模式，通过在AndroidManifest.xml中设置或通过Intent标志控制：

1. **standard**：默认模式，每次启动都创建新实例
2. **singleTop**：如果Activity已在栈顶，则复用该实例
3. **singleTask**：确保系统中只有一个Activity实例，如果存在则清除其上所有Activity
4. **singleInstance**：类似singleTask，但Activity在独立的任务栈中

```xml
<activity
    android:name=".MainActivity"
    android:launchMode="singleTop">
</activity>
```

### Activity间通信

Activities之间可以通过Intent传递数据：

```kotlin
// 启动Activity
val intent = Intent(this, SecondActivity::class.java)
intent.putExtra("key", "value")
startActivity(intent)

// 启动Activity并等待结果
startActivityForResult(intent, REQUEST_CODE)

// 在目标Activity中接收数据
val value = intent.getStringExtra("key")

// 返回结果给上一个Activity
val resultIntent = Intent()
resultIntent.putExtra("result", "Success")
setResult(Activity.RESULT_OK, resultIntent)
finish()

// 在原Activity中接收结果
override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    super.onActivityResult(requestCode, resultCode, data)
    if (requestCode == REQUEST_CODE && resultCode == Activity.RESULT_OK) {
        val result = data?.getStringExtra("result")
    }
}
```

> 注：在较新的Android版本中，推荐使用ActivityResultLauncher替代startActivityForResult

## Fragment

Fragment表示Activity中的行为或用户界面部分，可以组合多个Fragment创建多窗格UI。

### Fragment生命周期

Fragment的生命周期与Activity类似，但有一些额外的回调方法：

![Fragment生命周期](https://developer.android.com/images/fragment_lifecycle.png)

```kotlin
class MainFragment : Fragment() {
    
    // 创建Fragment时调用
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
    }
    
    // 创建Fragment的视图
    override fun onCreateView(
        inflater: LayoutInflater, 
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_main, container, false)
    }
    
    // 视图创建完成后调用，可以安全访问视图
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
    }
    
    // Fragment与Activity关联
    override fun onAttach(context: Context) {
        super.onAttach(context)
    }
    
    // Fragment与Activity解除关联
    override fun onDetach() {
        super.onDetach()
    }
}
```

### Fragment管理

使用FragmentManager管理Fragment：

```kotlin
// 添加Fragment
supportFragmentManager.beginTransaction()
    .add(R.id.fragment_container, MainFragment())
    .commit()

// 替换Fragment
supportFragmentManager.beginTransaction()
    .replace(R.id.fragment_container, SecondFragment())
    .addToBackStack(null) // 允许返回上一个Fragment
    .commit()

// 移除Fragment
val fragment = supportFragmentManager.findFragmentById(R.id.fragment_container)
if (fragment != null) {
    supportFragmentManager.beginTransaction()
        .remove(fragment)
        .commit()
}
```

### Fragment通信

1. **通过接口通信**：

```kotlin
// 在Fragment中定义接口
class MainFragment : Fragment() {
    interface OnItemSelectedListener {
        fun onItemSelected(item: String)
    }
    
    private var listener: OnItemSelectedListener? = null
    
    override fun onAttach(context: Context) {
        super.onAttach(context)
        if (context is OnItemSelectedListener) {
            listener = context
        } else {
            throw RuntimeException("$context must implement OnItemSelectedListener")
        }
    }
    
    // 触发回调
    private fun selectItem(item: String) {
        listener?.onItemSelected(item)
    }
}

// 在Activity中实现接口
class MainActivity : AppCompatActivity(), MainFragment.OnItemSelectedListener {
    override fun onItemSelected(item: String) {
        // 处理选择的项目
    }
}
```

2. **通过ViewModel共享数据**：

```kotlin
// 创建ViewModel
class SharedViewModel : ViewModel() {
    val selected = MutableLiveData<String>()
    
    fun select(item: String) {
        selected.value = item
    }
}

// 在Fragment中使用
class MainFragment : Fragment() {
    private lateinit var viewModel: SharedViewModel
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        viewModel = ViewModelProvider(requireActivity()).get(SharedViewModel::class.java)
        
        // 更新数据
        button.setOnClickListener {
            viewModel.select("New Item")
        }
    }
}

// 在另一个Fragment中观察数据
class DetailFragment : Fragment() {
    private lateinit var viewModel: SharedViewModel
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        viewModel = ViewModelProvider(requireActivity()).get(SharedViewModel::class.java)
        
        // 观察数据变化
        viewModel.selected.observe(viewLifecycleOwner, Observer { item ->
            // 更新UI
        })
    }
}
```

## Service

Service是一个可以在后台执行长时间运行操作的应用组件，不提供用户界面。

### Service类型

1. **前台Service**：用户可见，显示通知，即使用户不与应用交互也会继续运行
2. **后台Service**：对用户不可见，执行用户不直接感知的操作
3. **绑定Service**：当其他组件（如Activity）绑定到Service时运行

### Service生命周期

![Service生命周期](https://developer.android.com/images/service_lifecycle.png)

```kotlin
class MyService : Service() {
    
    // Service创建时调用
    override fun onCreate() {
        super.onCreate()
    }
    
    // 每次通过startService()启动Service时调用
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 处理任务
        
        // 返回值决定系统如何在Service被杀死后重新创建它
        return START_STICKY
    }
    
    // 当组件通过bindService()绑定到Service时调用
    override fun onBind(intent: Intent): IBinder? {
        return null // 如果不支持绑定，返回null
    }
    
    // 当所有客户端都与Service解除绑定时调用
    override fun onUnbind(intent: Intent): Boolean {
        return super.onUnbind(intent)
    }
    
    // Service销毁时调用
    override fun onDestroy() {
        super.onDestroy()
    }
}
```

### 启动和绑定Service

```kotlin
// 启动Service
val intent = Intent(this, MyService::class.java)
startService(intent)

// 停止Service
stopService(intent)

// 绑定Service
val serviceConnection = object : ServiceConnection {
    override fun onServiceConnected(name: ComponentName, service: IBinder) {
        // 获取Service实例
        val binder = service as MyService.LocalBinder
        val myService = binder.getService()
    }
    
    override fun onServiceDisconnected(name: ComponentName) {
        // Service意外断开连接
    }
}

bindService(Intent(this, MyService::class.java), serviceConnection, Context.BIND_AUTO_CREATE)

// 解除绑定
unbindService(serviceConnection)
```

### 前台Service

Android 8.0（API级别26）及更高版本需要创建通知通道：

```kotlin
// 创建通知通道
private fun createNotificationChannel() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Foreground Service Channel",
            NotificationManager.IMPORTANCE_DEFAULT
        )
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(channel)
    }
}

// 启动前台Service
override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    createNotificationChannel()
    
    val notification = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("Service Running")
        .setContentText("Performing background task")
        .setSmallIcon(R.drawable.ic_notification)
        .build()
    
    startForeground(NOTIFICATION_ID, notification)
    
    // 执行任务
    
    return START_STICKY
}
```

## BroadcastReceiver

BroadcastReceiver允许应用接收系统或其他应用发送的广播消息。

### 注册BroadcastReceiver

1. **静态注册**（在AndroidManifest.xml中）：

```xml
<receiver android:name=".MyReceiver" android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
    </intent-filter>
</receiver>
```

2. **动态注册**（在代码中）：

```kotlin
val receiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // 处理广播
    }
}

val filter = IntentFilter().apply {
    addAction("com.example.MY_ACTION")
    addAction(Intent.ACTION_BATTERY_LOW)
}

registerReceiver(receiver, filter)

// 不再需要时注销
unregisterReceiver(receiver)
```

### 发送广播

```kotlin
// 发送普通广播
val intent = Intent("com.example.MY_ACTION")
intent.putExtra("key", "value")
sendBroadcast(intent)

// 发送有序广播
sendOrderedBroadcast(intent, null)

// 发送本地广播（仅在应用内接收）
LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
```

### 常见系统广播

- `ACTION_BOOT_COMPLETED`：系统启动完成
- `ACTION_POWER_CONNECTED`：设备连接到电源
- `ACTION_POWER_DISCONNECTED`：设备与电源断开
- `ACTION_BATTERY_LOW`：电池电量低
- `ACTION_PACKAGE_ADDED`：安装新应用
- `ACTION_PACKAGE_REMOVED`：卸载应用

## ContentProvider

ContentProvider管理应用的共享数据，允许不同应用之间安全地共享数据。

### 创建ContentProvider

```kotlin
class MyContentProvider : ContentProvider() {
    
    companion object {
        // 定义URI
        val AUTHORITY = "com.example.provider"
        val CONTENT_URI = Uri.parse("content://$AUTHORITY/items")
        
        // 定义列名
        val ID = "_id"
        val NAME = "name"
    }
    
    private lateinit var dbHelper: DatabaseHelper
    
    // 初始化ContentProvider
    override fun onCreate(): Boolean {
        dbHelper = DatabaseHelper(context!!)
        return true
    }
    
    // 查询数据
    override fun query(
        uri: Uri,
        projection: Array<String>?,
        selection: String?,
        selectionArgs: Array<String>?,
        sortOrder: String?
    ): Cursor? {
        val db = dbHelper.readableDatabase
        return db.query("items", projection, selection, selectionArgs, null, null, sortOrder)
    }
    
    // 获取MIME类型
    override fun getType(uri: Uri): String? {
        return "vnd.android.cursor.dir/vnd.example.items"
    }
    
    // 插入数据
    override fun insert(uri: Uri, values: ContentValues?): Uri? {
        val db = dbHelper.writableDatabase
        val id = db.insert("items", null, values)
        context?.contentResolver?.notifyChange(uri, null)
        return Uri.parse("$CONTENT_URI/$id")
    }
    
    // 删除数据
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<String>?): Int {
        val db = dbHelper.writableDatabase
        val count = db.delete("items", selection, selectionArgs)
        context?.contentResolver?.notifyChange(uri, null)
        return count
    }
    
    // 更新数据
    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<String>?
    ): Int {
        val db = dbHelper.writableDatabase
        val count = db.update("items", values, selection, selectionArgs)
        context?.contentResolver?.notifyChange(uri, null)
        return count
    }
}
```

### 在AndroidManifest.xml中注册ContentProvider

```xml
<provider
    android:name=".MyContentProvider"
    android:authorities="com.example.provider"
    android:exported="true"
    android:readPermission="com.example.READ_PERMISSION"
    android:writePermission="com.example.WRITE_PERMISSION" />
```

### 访问ContentProvider

```kotlin
// 查询数据
val cursor = contentResolver.query(
    MyContentProvider.CONTENT_URI,
    arrayOf(MyContentProvider.ID, MyContentProvider.NAME),
    null,
    null,
    null
)

cursor?.use {
    while (it.moveToNext()) {
        val id = it.getLong(it.getColumnIndex(MyContentProvider.ID))
        val name = it.getString(it.getColumnIndex(MyContentProvider.NAME))
        Log.d("ContentProvider", "ID: $id, Name: $name")
    }
}

// 插入数据
val values = ContentValues().apply {
    put(MyContentProvider.NAME, "New Item")
}
val uri = contentResolver.insert(MyContentProvider.CONTENT_URI, values)

// 更新数据
val updateValues = ContentValues().apply {
    put(MyContentProvider.NAME, "Updated Item")
}
val count = contentResolver.update(
    MyContentProvider.CONTENT_URI,
    updateValues,
    "${MyContentProvider.ID} = ?",
    arrayOf("1")
)

// 删除数据
val deleteCount = contentResolver.delete(
    MyContentProvider.CONTENT_URI,
    "${MyContentProvider.ID} = ?",
    arrayOf("1")
)
```

## Intent和IntentFilter

Intent是一个消息传递对象，用于在不同组件之间请求操作。

### Intent类型

1. **显式Intent**：直接指定目标组件的类名
2. **隐式Intent**：指定要执行的操作，由系统找到合适的组件

```kotlin
// 显式Intent
val explicitIntent = Intent(this, SecondActivity::class.java)
startActivity(explicitIntent)

// 隐式Intent
val implicitIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.example.com"))
startActivity(implicitIntent)

// 检查是否有应用能处理此Intent
if (implicitIntent.resolveActivity(packageManager) != null) {
    startActivity(implicitIntent)
}
```

### 常见Intent操作

- `ACTION_VIEW`：显示数据
- `ACTION_SEND`：共享数据
- `ACTION_DIAL`：拨打电话
- `ACTION_PICK`：从数据集中选择项目
- `ACTION_GET_CONTENT`：让用户选择数据

```kotlin
// 打开网页
val webIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://www.example.com"))
startActivity(webIntent)

// 拨打电话
val dialIntent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:1234567890"))
startActivity(dialIntent)

// 分享文本
val shareIntent = Intent().apply {
    action = Intent.ACTION_SEND
    putExtra(Intent.EXTRA_TEXT, "分享的文本内容")
    type = "text/plain"
}
startActivity(Intent.createChooser(shareIntent, "分享到"))
```

### IntentFilter

IntentFilter定义组件可以接收的Intent类型，通常在AndroidManifest.xml中声明：

```xml
<activity android:name=".BrowserActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="http" />
        <data android:scheme="https" />
    </intent-filter>
</activity>
```

## 总结

Android的基础组件是构建应用的核心要素：

- **Activity**：提供用户界面和交互
- **Fragment**：模块化UI组件，可重用和组合
- **Service**：执行后台任务
- **BroadcastReceiver**：响应系统和应用事件
- **ContentProvider**：管理和共享数据
- **Intent**：连接各组件的消息传递机制

掌握这些基础组件及其生命周期和使用模式，是开发高质量Android应用的基础。

## 下一步学习

- [UI开发基础](ui-basics.md)
- [数据存储与访问](data-storage.md)
- [Jetpack组件](jetpack.md) 