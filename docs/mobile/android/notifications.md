# Android通知与推送

通知是Android系统中向用户传递信息的重要方式，即使应用不在前台运行。本文档将详细介绍Android通知系统的使用以及Firebase Cloud Messaging (FCM)推送服务的集成。

## 通知基础

### 通知的组成部分

Android通知通常包含以下元素：

1. **小图标**：必需，显示在状态栏和通知抽屉中
2. **标题**：通知的主要内容标题
3. **文本**：通知的详细内容
4. **大图标**：可选，显示在通知详情中
5. **操作按钮**：可选，最多可添加3个
6. **时间戳**：通知发出的时间
7. **通知渠道**：Android 8.0+必需，用于分类通知

### 通知渠道(Notification Channels)

从Android 8.0(API 26)开始，所有通知必须分配到一个通知渠道，用户可以按渠道控制通知行为。

```kotlin
// 创建通知渠道
private fun createNotificationChannel() {
    // 仅在Android 8.0及以上版本需要创建通知渠道
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val channelId = "my_channel_id"
        val channelName = "My Channel"
        val channelDescription = "My Channel Description"
        val importance = NotificationManager.IMPORTANCE_DEFAULT
        
        val channel = NotificationChannel(channelId, channelName, importance).apply {
            description = channelDescription
            // 配置渠道属性
            enableLights(true)
            lightColor = Color.RED
            enableVibration(true)
            vibrationPattern = longArrayOf(100, 200, 300, 400, 500)
        }
        
        // 向系统注册通知渠道
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.createNotificationChannel(channel)
    }
}
```

在应用启动时（如在`onCreate()`方法中）调用此方法创建通知渠道。

### 发送基本通知

```kotlin
// 发送基本通知
fun sendBasicNotification() {
    val channelId = "my_channel_id"
    val notificationId = 1
    
    // 创建一个PendingIntent，用户点击通知时打开应用
    val intent = Intent(this, MainActivity::class.java)
    val pendingIntent = PendingIntent.getActivity(
        this, 0, intent, PendingIntent.FLAG_IMMUTABLE
    )
    
    // 构建通知
    val notification = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("通知标题")
        .setContentText("这是通知内容")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setContentIntent(pendingIntent)
        .setAutoCancel(true) // 点击后自动移除通知
        .build()
    
    // 发送通知
    val notificationManager = NotificationManagerCompat.from(this)
    
    // 检查通知权限（Android 13+需要请求权限）
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        if (notificationManager.areNotificationsEnabled() &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == 
            PackageManager.PERMISSION_GRANTED) {
            notificationManager.notify(notificationId, notification)
        } else {
            requestNotificationPermission()
        }
    } else {
        notificationManager.notify(notificationId, notification)
    }
}

// 请求通知权限（Android 13+）
private fun requestNotificationPermission() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.POST_NOTIFICATIONS),
            REQUEST_NOTIFICATION_PERMISSION
        )
    }
}

// 处理权限请求结果
override fun onRequestPermissionsResult(
    requestCode: Int,
    permissions: Array<out String>,
    grantResults: IntArray
) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    if (requestCode == REQUEST_NOTIFICATION_PERMISSION) {
        if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            // 权限已授予，可以发送通知
            sendBasicNotification()
        } else {
            // 权限被拒绝，提示用户或引导用户到设置中开启权限
            Toast.makeText(this, "需要通知权限才能发送通知", Toast.LENGTH_SHORT).show()
        }
    }
}
```

## 高级通知功能

### 添加操作按钮

```kotlin
fun sendNotificationWithActions() {
    val channelId = "my_channel_id"
    val notificationId = 2
    
    // 创建回复意图
    val replyIntent = Intent(this, NotificationActionReceiver::class.java).apply {
        action = "ACTION_REPLY"
    }
    val replyPendingIntent = PendingIntent.getBroadcast(
        this, 0, replyIntent, PendingIntent.FLAG_IMMUTABLE
    )
    
    // 创建删除意图
    val deleteIntent = Intent(this, NotificationActionReceiver::class.java).apply {
        action = "ACTION_DELETE"
    }
    val deletePendingIntent = PendingIntent.getBroadcast(
        this, 1, deleteIntent, PendingIntent.FLAG_IMMUTABLE
    )
    
    // 构建带操作按钮的通知
    val notification = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("带操作的通知")
        .setContentText("点击按钮执行操作")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .addAction(R.drawable.ic_reply, "回复", replyPendingIntent)
        .addAction(R.drawable.ic_delete, "删除", deletePendingIntent)
        .setAutoCancel(true)
        .build()
    
    // 发送通知
    val notificationManager = NotificationManagerCompat.from(this)
    if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
        notificationManager.notify(notificationId, notification)
    }
}
```

创建处理通知操作的BroadcastReceiver：

```kotlin
class NotificationActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            "ACTION_REPLY" -> {
                // 处理回复操作
                Toast.makeText(context, "回复操作被点击", Toast.LENGTH_SHORT).show()
            }
            "ACTION_DELETE" -> {
                // 处理删除操作
                Toast.makeText(context, "删除操作被点击", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
```

在AndroidManifest.xml中注册BroadcastReceiver：

```xml
<receiver android:name=".NotificationActionReceiver" android:exported="false" />
```

### 直接回复功能

```kotlin
fun sendNotificationWithDirectReply() {
    val channelId = "my_channel_id"
    val notificationId = 3
    
    // 创建回复意图
    val replyIntent = Intent(this, DirectReplyReceiver::class.java)
    val replyPendingIntent = PendingIntent.getBroadcast(
        this, 0, replyIntent, PendingIntent.FLAG_MUTABLE
    )
    
    // 创建回复操作
    val remoteInput = RemoteInput.Builder("key_text_reply")
        .setLabel("输入回复...")
        .build()
    
    val replyAction = NotificationCompat.Action.Builder(
        R.drawable.ic_reply,
        "回复",
        replyPendingIntent
    ).addRemoteInput(remoteInput).build()
    
    // 构建带直接回复的通知
    val notification = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("直接回复通知")
        .setContentText("可以直接回复的通知")
        .setPriority(NotificationCompat.PRIORITY_HIGH)
        .addAction(replyAction)
        .build()
    
    // 发送通知
    val notificationManager = NotificationManagerCompat.from(this)
    if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
        notificationManager.notify(notificationId, notification)
    }
}
```

创建处理直接回复的BroadcastReceiver：

```kotlin
class DirectReplyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val remoteInput = RemoteInput.getResultsFromIntent(intent)
        if (remoteInput != null) {
            val replyText = remoteInput.getCharSequence("key_text_reply")
            
            // 处理回复文本
            if (replyText != null) {
                // 更新通知，显示已回复
                val notificationId = 3
                val repliedNotification = NotificationCompat.Builder(context, "my_channel_id")
                    .setSmallIcon(R.drawable.ic_notification)
                    .setContentTitle("回复已发送")
                    .setContentText("你的回复: $replyText")
                    .build()
                
                val notificationManager = NotificationManagerCompat.from(context)
                if (ActivityCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                    notificationManager.notify(notificationId, repliedNotification)
                }
                
                // 执行其他操作，如发送消息到服务器
            }
        }
    }
}
```

在AndroidManifest.xml中注册BroadcastReceiver：

```xml
<receiver android:name=".DirectReplyReceiver" android:exported="false" />
```

### 大文本和大图片通知

```kotlin
// 发送大文本通知
fun sendBigTextNotification() {
    val channelId = "my_channel_id"
    val notificationId = 4
    
    val longText = "这是一个长文本通知，可以显示多行文本内容。" +
            "当通知展开时，用户可以看到完整的文本内容。" +
            "这对于显示邮件或消息内容非常有用。"
    
    val notification = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("大文本通知")
        .setContentText("展开查看更多内容...")
        .setStyle(NotificationCompat.BigTextStyle().bigText(longText))
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .build()
    
    val notificationManager = NotificationManagerCompat.from(this)
    if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
        notificationManager.notify(notificationId, notification)
    }
}

// 发送大图片通知
fun sendBigPictureNotification() {
    val channelId = "my_channel_id"
    val notificationId = 5
    
    // 加载大图片
    val bitmap = BitmapFactory.decodeResource(resources, R.drawable.notification_image)
    
    val notification = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("大图片通知")
        .setContentText("展开查看图片")
        .setLargeIcon(bitmap)
        .setStyle(NotificationCompat.BigPictureStyle()
            .bigPicture(bitmap)
            .bigLargeIcon(null)) // 展开时隐藏大图标
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .build()
    
    val notificationManager = NotificationManagerCompat.from(this)
    if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
        notificationManager.notify(notificationId, notification)
    }
}
```

### 进度条通知

```kotlin
fun showProgressNotification() {
    val channelId = "my_channel_id"
    val notificationId = 6
    val notificationManager = NotificationManagerCompat.from(this)
    
    // 创建通知构建器
    val builder = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_download)
        .setContentTitle("下载中")
        .setContentText("下载进度...")
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true) // 通知不可滑动删除
    
    // 模拟下载进度
    val maxProgress = 100
    
    // 启动协程模拟下载进度
    CoroutineScope(Dispatchers.IO).launch {
        for (progress in 0..maxProgress) {
            // 更新进度条
            builder.setProgress(maxProgress, progress, false)
            builder.setContentText("下载进度: $progress%")
            
            // 更新通知
            if (ActivityCompat.checkSelfPermission(this@YourActivity, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                notificationManager.notify(notificationId, builder.build())
            }
            
            delay(100) // 模拟下载延迟
        }
        
        // 下载完成，更新通知
        builder.setContentTitle("下载完成")
            .setContentText("文件已下载完成")
            .setProgress(0, 0, false)
            .setOngoing(false)
        
        if (ActivityCompat.checkSelfPermission(this@YourActivity, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            notificationManager.notify(notificationId, builder.build())
        }
    }
}
```

### 通知分组

```kotlin
fun sendGroupedNotifications() {
    val channelId = "my_channel_id"
    val groupKey = "message_group"
    
    // 创建第一条通知
    val notification1 = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("消息1")
        .setContentText("来自张三的消息")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setGroup(groupKey)
        .build()
    
    // 创建第二条通知
    val notification2 = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("消息2")
        .setContentText("来自李四的消息")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setGroup(groupKey)
        .build()
    
    // 创建第三条通知
    val notification3 = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("消息3")
        .setContentText("来自王五的消息")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setGroup(groupKey)
        .build()
    
    // 创建摘要通知
    val summaryNotification = NotificationCompat.Builder(this, channelId)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle("3条新消息")
        .setPriority(NotificationCompat.PRIORITY_DEFAULT)
        .setGroup(groupKey)
        .setGroupSummary(true)
        .build()
    
    // 发送所有通知
    val notificationManager = NotificationManagerCompat.from(this)
    if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
        notificationManager.notify(1001, notification1)
        notificationManager.notify(1002, notification2)
        notificationManager.notify(1003, notification3)
        notificationManager.notify(1000, summaryNotification)
    }
}
```

## Firebase Cloud Messaging (FCM)

Firebase Cloud Messaging是Google提供的跨平台消息传递解决方案，允许你向用户设备发送通知和数据消息。

### 集成FCM

1. 在项目级build.gradle中添加Google服务插件：

```gradle
buildscript {
    dependencies {
        classpath 'com.google.gms:google-services:4.3.15'
    }
}
```

2. 在应用级build.gradle中应用插件并添加依赖：

```gradle
plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
    id 'com.google.gms.google-services'
}

dependencies {
    implementation platform('com.google.firebase:firebase-bom:32.2.0')
    implementation 'com.google.firebase:firebase-messaging-ktx'
    implementation 'com.google.firebase:firebase-analytics-ktx'
}
```

3. 从Firebase控制台下载google-services.json文件并放入app目录

4. 创建FCM服务：

```kotlin
class MyFirebaseMessagingService : FirebaseMessagingService() {
    
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        // 将新令牌发送到你的服务器
        sendRegistrationToServer(token)
    }
    
    private fun sendRegistrationToServer(token: String) {
        // 实现将FCM令牌发送到你的后端服务器的逻辑
        Log.d("FCM", "FCM令牌: $token")
    }
    
    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        super.onMessageReceived(remoteMessage)
        
        // 检查消息是否包含通知负载
        remoteMessage.notification?.let { notification ->
            val title = notification.title ?: "通知"
            val body = notification.body ?: "新消息"
            sendNotification(title, body)
        }
        
        // 检查消息是否包含数据负载
        remoteMessage.data.isNotEmpty().let {
            // 处理数据消息
            val messageData = remoteMessage.data
            Log.d("FCM", "数据消息: $messageData")
            
            // 如果需要，也可以从数据中创建通知
            if (messageData.containsKey("title") && messageData.containsKey("body")) {
                sendNotification(messageData["title"]!!, messageData["body"]!!)
            }
        }
    }
    
    private fun sendNotification(title: String, messageBody: String) {
        val channelId = "fcm_channel"
        
        // 创建通知渠道（Android 8.0+）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "FCM通知",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
        
        // 创建点击通知时打开应用的意图
        val intent = Intent(this, MainActivity::class.java)
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE
        )
        
        // 构建通知
        val notificationBuilder = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(messageBody)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
        
        // 显示通知
        val notificationManager = NotificationManagerCompat.from(this)
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
            notificationManager.notify(0, notificationBuilder.build())
        }
    }
}
```

5. 在AndroidManifest.xml中注册服务：

```xml
<service
    android:name=".MyFirebaseMessagingService"
    android:exported="false">
    <intent-filter>
        <action android:name="com.google.firebase.MESSAGING_EVENT" />
    </intent-filter>
</service>
```

### 获取FCM令牌

```kotlin
fun getFcmToken() {
    FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
        if (!task.isSuccessful) {
            Log.w("FCM", "获取FCM令牌失败", task.exception)
            return@addOnCompleteListener
        }
        
        // 获取新令牌
        val token = task.result
        Log.d("FCM", "FCM令牌: $token")
        
        // 发送令牌到服务器
        sendTokenToServer(token)
    }
}

private fun sendTokenToServer(token: String) {
    // 实现将令牌发送到你的后端服务器的逻辑
}
```

### 订阅主题

FCM允许应用订阅特定主题，以接收发送到该主题的消息：

```kotlin
fun subscribeToTopic(topic: String) {
    FirebaseMessaging.getInstance().subscribeToTopic(topic)
        .addOnCompleteListener { task ->
            if (task.isSuccessful) {
                Log.d("FCM", "成功订阅主题: $topic")
            } else {
                Log.e("FCM", "订阅主题失败: $topic", task.exception)
            }
        }
}

fun unsubscribeFromTopic(topic: String) {
    FirebaseMessaging.getInstance().unsubscribeFromTopic(topic)
        .addOnCompleteListener { task ->
            if (task.isSuccessful) {
                Log.d("FCM", "成功取消订阅主题: $topic")
            } else {
                Log.e("FCM", "取消订阅主题失败: $topic", task.exception)
            }
        }
}
```

### 处理通知点击

当用户点击FCM通知时，可以传递数据到启动的Activity：

```kotlin
// 在MainActivity的onCreate中处理通知点击
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    
    // 处理从通知启动
    intent.extras?.let {
        for (key in it.keySet()) {
            val value = intent.extras?.get(key)
            Log.d("NotificationData", "Key: $key Value: $value")
        }
        
        // 处理特定数据
        if (it.containsKey("message_id")) {
            val messageId = it.getString("message_id")
            // 打开相应的消息详情页面
            openMessageDetails(messageId)
        }
    }
}

private fun openMessageDetails(messageId: String?) {
    // 实现打开消息详情的逻辑
}
```

## 通知最佳实践

1. **尊重用户注意力**：
   - 只发送重要且相关的通知
   - 避免频繁发送通知造成打扰

2. **使用适当的优先级**：
   - 高优先级：需要立即注意的重要信息
   - 默认优先级：一般信息
   - 低优先级：不需要立即注意的信息

3. **提供清晰的通知渠道**：
   - 创建有意义的通知渠道分类
   - 为每个渠道提供清晰的描述

4. **个性化通知内容**：
   - 根据用户偏好定制通知内容
   - 使用用户名或相关上下文使通知更相关

5. **提供有用的操作**：
   - 添加直接操作按钮减少用户步骤
   - 确保操作明确且有用

6. **处理通知权限**：
   - 在适当时机请求通知权限
   - 解释为什么应用需要发送通知
   - 提供在设置中启用通知的引导

7. **测试各种Android版本**：
   - 确保通知在不同Android版本上正常工作
   - 适应不同版本的API变化

## 常见问题与解决方案

### 通知不显示

1. 检查通知权限是否已授予
2. 确认通知渠道已正确创建
3. 验证通知管理器代码无误
4. 检查设备是否处于"勿扰模式"

### FCM消息未收到

1. 确认google-services.json文件正确配置
2. 验证FCM服务是否正确注册在Manifest中
3. 检查网络连接状态
4. 查看Firebase控制台中的消息发送状态

### 通知样式问题

1. 确保提供了正确大小的图标
2. 验证通知构建器参数设置正确
3. 检查设备制造商的系统定制是否影响通知显示

## 总结

通知是与用户保持联系的重要方式，而Firebase Cloud Messaging提供了强大的推送功能。通过合理使用通知渠道、优先级和丰富的通知样式，可以提供良好的用户体验。记住始终尊重用户的注意力，只发送真正重要和相关的通知。

## 相关资源

- [Android通知官方文档](https://developer.android.com/guide/topics/ui/notifiers/notifications)
- [Firebase Cloud Messaging文档](https://firebase.google.com/docs/cloud-messaging)
- [通知兼容性库](https://developer.android.com/jetpack/androidx/releases/core)
- [通知设计最佳实践](https://material.io/design/platform-guidance/android-notifications.html)
