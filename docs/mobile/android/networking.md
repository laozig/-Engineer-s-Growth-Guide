# Android网络编程

网络通信是现代移动应用的核心功能之一。本文档将介绍Android中的网络编程技术，从基础的HTTP请求到高级的WebSocket和gRPC。

## 网络权限

在进行网络操作前，需要在AndroidManifest.xml中添加网络权限：

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

## 检查网络连接状态

在执行网络操作前，应该先检查网络是否可用：

```kotlin
fun isNetworkAvailable(context: Context): Boolean {
    val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val network = connectivityManager.activeNetwork ?: return false
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    } else {
        val networkInfo = connectivityManager.activeNetworkInfo ?: return false
        return networkInfo.isConnected
    }
}
```

## HTTP请求

### HttpURLConnection

Android内置的基础HTTP客户端：

```kotlin
fun makeHttpRequest(urlString: String): String {
    var connection: HttpURLConnection? = null
    var reader: BufferedReader? = null
    val stringBuilder = StringBuilder()
    
    try {
        val url = URL(urlString)
        connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.connectTimeout = 15000
        connection.readTimeout = 15000
        connection.connect()
        
        val inputStream = connection.inputStream
        reader = BufferedReader(InputStreamReader(inputStream))
        
        var line: String?
        while (reader.readLine().also { line = it } != null) {
            stringBuilder.append(line).append("\n")
        }
    } catch (e: Exception) {
        e.printStackTrace()
    } finally {
        connection?.disconnect()
        reader?.close()
    }
    
    return stringBuilder.toString()
}

// 使用协程执行网络请求
suspend fun fetchData(url: String): String = withContext(Dispatchers.IO) {
    makeHttpRequest(url)
}
```

### OkHttp

Square公司开发的高效HTTP客户端：

1. 添加依赖：

```gradle
dependencies {
    implementation 'com.squareup.okhttp3:okhttp:4.10.0'
}
```

2. 基本使用：

```kotlin
// 创建OkHttpClient实例
val client = OkHttpClient.Builder()
    .connectTimeout(15, TimeUnit.SECONDS)
    .readTimeout(15, TimeUnit.SECONDS)
    .build()

// 同步GET请求
fun makeGetRequest(url: String): String {
    val request = Request.Builder()
        .url(url)
        .build()
    
    client.newCall(request).execute().use { response ->
        if (!response.isSuccessful) throw IOException("Unexpected code $response")
        return response.body?.string() ?: ""
    }
}

// 异步GET请求
fun makeAsyncGetRequest(url: String, callback: (String?, Exception?) -> Unit) {
    val request = Request.Builder()
        .url(url)
        .build()
    
    client.newCall(request).enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
            callback(null, e)
        }
        
        override fun onResponse(call: Call, response: Response) {
            if (!response.isSuccessful) {
                callback(null, IOException("Unexpected code $response"))
            } else {
                callback(response.body?.string(), null)
            }
        }
    })
}

// POST请求
fun makePostRequest(url: String, jsonBody: String): String {
    val mediaType = "application/json; charset=utf-8".toMediaType()
    val requestBody = jsonBody.toRequestBody(mediaType)
    
    val request = Request.Builder()
        .url(url)
        .post(requestBody)
        .build()
    
    client.newCall(request).execute().use { response ->
        if (!response.isSuccessful) throw IOException("Unexpected code $response")
        return response.body?.string() ?: ""
    }
}

// 使用协程
suspend fun fetchDataWithOkHttp(url: String): String = withContext(Dispatchers.IO) {
    makeGetRequest(url)
}
```

### Retrofit

基于OkHttp的声明式REST API客户端：

1. 添加依赖：

```gradle
dependencies {
    implementation 'com.squareup.retrofit2:retrofit:2.9.0'
    implementation 'com.squareup.retrofit2:converter-gson:2.9.0'
}
```

2. 定义API接口：

```kotlin
interface ApiService {
    @GET("users/{user}")
    suspend fun getUser(@Path("user") user: String): User
    
    @GET("users")
    suspend fun getUsers(@Query("page") page: Int): List<User>
    
    @POST("users")
    suspend fun createUser(@Body user: User): User
    
    @FormUrlEncoded
    @POST("login")
    suspend fun login(
        @Field("username") username: String,
        @Field("password") password: String
    ): LoginResponse
    
    @Multipart
    @POST("upload")
    suspend fun uploadFile(
        @Part("description") description: RequestBody,
        @Part file: MultipartBody.Part
    ): UploadResponse
}

// 数据模型
data class User(
    val id: Int,
    val name: String,
    val email: String
)

data class LoginResponse(
    val token: String,
    val user: User
)

data class UploadResponse(
    val success: Boolean,
    val fileUrl: String
)
```

3. 创建Retrofit实例：

```kotlin
val retrofit = Retrofit.Builder()
    .baseUrl("https://api.example.com/")
    .addConverterFactory(GsonConverterFactory.create())
    .build()

val apiService = retrofit.create(ApiService::class.java)
```

4. 使用API：

```kotlin
// 在ViewModel中使用
class UserViewModel : ViewModel() {
    private val _user = MutableLiveData<User>()
    val user: LiveData<User> = _user
    
    fun loadUser(username: String) {
        viewModelScope.launch {
            try {
                val result = apiService.getUser(username)
                _user.value = result
            } catch (e: Exception) {
                // 处理错误
            }
        }
    }
}
```

### Ktor Client

Kotlin多平台网络客户端：

1. 添加依赖：

```gradle
dependencies {
    implementation "io.ktor:ktor-client-android:2.3.0"
    implementation "io.ktor:ktor-client-content-negotiation:2.3.0"
    implementation "io.ktor:ktor-serialization-gson:2.3.0"
}
```

2. 基本使用：

```kotlin
// 创建客户端
val client = HttpClient(Android) {
    install(ContentNegotiation) {
        gson()
    }
    install(Logging) {
        level = LogLevel.ALL
    }
    defaultRequest {
        contentType(ContentType.Application.Json)
        accept(ContentType.Application.Json)
    }
}

// 定义数据模型
@Serializable
data class User(val id: Int, val name: String, val email: String)

// GET请求
suspend fun getUser(id: Int): User {
    return client.get("https://api.example.com/users/$id").body()
}

// POST请求
suspend fun createUser(user: User): User {
    return client.post("https://api.example.com/users") {
        setBody(user)
    }.body()
}

// 下载文件
suspend fun downloadFile(url: String, file: File) {
    client.get(url).bodyAsChannel().copyAndClose(file.writeChannel())
}
```

## 图片加载

### Glide

高效的图片加载库：

1. 添加依赖：

```gradle
dependencies {
    implementation 'com.github.bumptech.glide:glide:4.15.1'
    kapt 'com.github.bumptech.glide:compiler:4.15.1'
}
```

2. 基本使用：

```kotlin
// 加载图片
Glide.with(context)
    .load("https://example.com/image.jpg")
    .placeholder(R.drawable.placeholder)
    .error(R.drawable.error)
    .into(imageView)

// 加载圆形图片
Glide.with(context)
    .load("https://example.com/avatar.jpg")
    .circleCrop()
    .into(imageView)

// 加载缩略图
Glide.with(context)
    .load("https://example.com/large_image.jpg")
    .thumbnail(0.1f)
    .into(imageView)

// 预加载
Glide.with(context)
    .load("https://example.com/image.jpg")
    .preload()

// 自定义配置
val options = RequestOptions()
    .placeholder(R.drawable.placeholder)
    .diskCacheStrategy(DiskCacheStrategy.ALL)
    .priority(Priority.HIGH)

Glide.with(context)
    .load("https://example.com/image.jpg")
    .apply(options)
    .into(imageView)
```

### Coil

Kotlin优先的图片加载库：

1. 添加依赖：

```gradle
dependencies {
    implementation "io.coil-kt:coil:2.4.0"
}
```

2. 基本使用：

```kotlin
// 加载图片
imageView.load("https://example.com/image.jpg") {
    placeholder(R.drawable.placeholder)
    error(R.drawable.error)
    crossfade(true)
}

// 加载圆形图片
imageView.load("https://example.com/avatar.jpg") {
    transformations(CircleCropTransformation())
}

// 预加载
val request = ImageRequest.Builder(context)
    .data("https://example.com/image.jpg")
    .build()
val disposable = context.imageLoader.enqueue(request)
```

## WebSocket

用于实时通信的双向连接：

### OkHttp WebSocket

```kotlin
// 创建WebSocket客户端
val client = OkHttpClient.Builder()
    .pingInterval(30, TimeUnit.SECONDS)
    .build()

// 创建请求
val request = Request.Builder()
    .url("wss://echo.websocket.org")
    .build()

// WebSocket监听器
val listener = object : WebSocketListener() {
    override fun onOpen(webSocket: WebSocket, response: Response) {
        // 连接建立
        webSocket.send("Hello, WebSocket!")
    }
    
    override fun onMessage(webSocket: WebSocket, text: String) {
        // 接收文本消息
        println("Received message: $text")
    }
    
    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
        // 接收二进制消息
        println("Received bytes: ${bytes.hex()}")
    }
    
    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        // 连接关闭中
        webSocket.close(1000, null)
        println("Closing: $code / $reason")
    }
    
    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        // 连接失败
        println("Error: ${t.message}")
    }
}

// 建立连接
val webSocket = client.newWebSocket(request, listener)

// 发送消息
webSocket.send("Hello")

// 关闭连接
webSocket.close(1000, "Goodbye")
```

## 下载管理

### DownloadManager

Android系统提供的下载服务：

```kotlin
fun downloadFile(url: String, title: String, description: String): Long {
    val request = DownloadManager.Request(Uri.parse(url))
        .setTitle(title)
        .setDescription(description)
        .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
        .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "file.pdf")
        .setAllowedOverMetered(true)
        .setAllowedOverRoaming(false)
    
    val downloadManager = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
    return downloadManager.enqueue(request)
}

// 监听下载完成
val downloadCompleteReceiver = object : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val downloadId = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1)
        if (downloadId != -1L) {
            // 下载完成
        }
    }
}

// 注册广播接收器
context.registerReceiver(
    downloadCompleteReceiver,
    IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE)
)

// 查询下载状态
fun checkDownloadStatus(downloadId: Long) {
    val downloadManager = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
    val query = DownloadManager.Query().setFilterById(downloadId)
    val cursor = downloadManager.query(query)
    
    if (cursor.moveToFirst()) {
        val columnIndex = cursor.getColumnIndex(DownloadManager.COLUMN_STATUS)
        val status = cursor.getInt(columnIndex)
        
        when (status) {
            DownloadManager.STATUS_SUCCESSFUL -> {
                // 下载成功
                val uriIndex = cursor.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI)
                val uri = cursor.getString(uriIndex)
                println("Download successful: $uri")
            }
            DownloadManager.STATUS_FAILED -> {
                // 下载失败
                val reasonIndex = cursor.getColumnIndex(DownloadManager.COLUMN_REASON)
                val reason = cursor.getInt(reasonIndex)
                println("Download failed: $reason")
            }
            DownloadManager.STATUS_PAUSED -> {
                // 下载暂停
            }
            DownloadManager.STATUS_PENDING -> {
                // 下载等待中
            }
            DownloadManager.STATUS_RUNNING -> {
                // 下载中
            }
        }
    }
    cursor.close()
}
```

## 网络安全配置

从Android 9.0(API 28)开始，默认情况下应用无法使用明文HTTP通信，需要配置网络安全：

1. 创建网络安全配置文件 `res/xml/network_security_config.xml`：

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- 允许明文通信的域名 -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">example.com</domain>
    </domain-config>
    
    <!-- 自定义信任的CA证书 -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="@raw/debug_cas"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

2. 在AndroidManifest.xml中引用配置：

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ... >
</application>
```

## 总结

本文档介绍了Android网络编程的多种技术和库：

- **HttpURLConnection**：Android内置的基础HTTP客户端
- **OkHttp**：高效的HTTP客户端
- **Retrofit**：声明式REST API客户端
- **Ktor Client**：Kotlin多平台网络客户端
- **Glide/Coil**：图片加载库
- **WebSocket**：实时双向通信
- **DownloadManager**：系统下载服务

选择合适的网络技术取决于应用的需求、复杂度和性能要求。

## 下一步学习

- [后台处理](background-processing.md)
- [数据存储与访问](data-storage.md)
- [Jetpack组件](jetpack.md)
