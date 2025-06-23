# 社交媒体客户端开发

本指南将引导你完成一个功能丰富的Android社交媒体客户端的开发，涵盖从架构设计到核心功能实现的完整流程。

## 应用概述

该社交媒体应用旨在提供一个现代化的社交平台，具备以下核心功能：
- 用户注册、登录与个人资料管理
- 发布、浏览、点赞和评论动态
- 关注/取关用户，构建社交关系
- 实时消息推送通知
- 基于RESTful API与后端服务进行数据交互

## 技术栈

- **语言**: Kotlin
- **架构**: MVVM (Model-View-ViewModel) / MVI (Model-View-Intent)
- **UI**: Jetpack Compose for modern, declarative UI
- **异步处理**: Kotlin Coroutines & Flow
- **网络请求**: Retrofit & OkHttp
- **JSON解析**: Moshi / Kotlinx Serialization
- **依赖注入**: Hilt / Koin
- **数据持久化**: Room (用于缓存) / DataStore (用于偏好设置)
- **图片加载**: Coil / Glide
- **导航**: Jetpack Navigation for Compose
- **实时通信**: WebSocket / Firebase Cloud Messaging (FCM)

## 开发步骤

### 1. 项目架构设计

采用分层架构，将代码按职责分离：
- **Data Layer**: 负责数据获取和管理，包括网络请求、本地缓存和数据转换。
- **Domain Layer**: 包含核心业务逻辑，通常以Use Cases的形式存在。
- **UI Layer**: 负责展示数据和处理用户交互。

```
app/
|-- data/
|   |-- remote/ (Retrofit API接口)
|   |-- local/  (Room数据库)
|   |-- repository/ (仓库实现)
|-- domain/
|   |-- model/ (领域模型)
|   |-- usecase/ (业务用例)
|-- ui/
|   |-- theme/
|   |-- screens/ (各个功能模块的Compose屏幕)
|   |   |-- auth/ (登录/注册)
|   |   |-- feed/ (动态流)
|   |   |-- profile/ (个人资料)
|-- di/ (依赖注入模块)
```

### 2. 用户认证模块

#### API定义

使用Retrofit定义用户认证相关的API接口。

```kotlin
// auth/AuthService.kt
interface AuthService {
    @POST("api/auth/register")
    suspend fun register(@Body request: RegisterRequest): Response<AuthResponse>

    @POST("api/auth/login")
    suspend fun login(@Body request: LoginRequest): Response<AuthResponse>

    @GET("api/user/profile")
    suspend fun getProfile(): Response<UserProfile>
}
```

#### 数据仓库

`AuthRepository` 负责处理认证逻辑，例如保存Token。

```kotlin
// auth/AuthRepository.kt
class AuthRepository @Inject constructor(
    private val authService: AuthService,
    private val tokenManager: TokenManager // 使用DataStore管理Token
) {
    suspend fun login(credentials: LoginRequest): Result<Unit> {
        return try {
            val response = authService.login(credentials)
            if (response.isSuccessful && response.body() != null) {
                tokenManager.saveToken(response.body()!!.token)
                Result.success(Unit)
            } else {
                Result.failure(Exception("登录失败"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

#### ViewModel与UI

使用`ViewModel`处理UI事件，并驱动UI状态更新。

```kotlin
// auth/LoginViewModel.kt
@HiltViewModel
class LoginViewModel @Inject constructor(
    private val authRepository: AuthRepository
) : ViewModel() {
    // ... 使用StateFlow管理UI状态
}

// auth/LoginScreen.kt
@Composable
fun LoginScreen(viewModel: LoginViewModel = hiltViewModel()) {
    // ... Compose UI布局，包含输入框和按钮
    // ... 调用viewModel的方法处理登录逻辑
}
```

### 3. 动态(Feed)模块

#### 数据模型

```kotlin
// feed/Post.kt
data class Post(
    val id: String,
    val author: User,
    val content: String,
    val imageUrl: String?,
    val timestamp: Long,
    val likeCount: Int,
    val isLikedByUser: Boolean
)
```

#### Paging 3实现无限滚动

使用Paging 3库从API加载分页数据，实现动态列表的无限滚动。

```kotlin
// feed/FeedPagingSource.kt
class FeedPagingSource(
    private val feedService: FeedService
) : PagingSource<Int, Post>() {
    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, Post> {
        val page = params.key ?: 1
        return try {
            val response = feedService.getFeed(page = page, limit = params.loadSize)
            LoadResult.Page(
                data = response.posts,
                prevKey = if (page == 1) null else page - 1,
                nextKey = if (response.posts.isEmpty()) null else page + 1
            )
        } catch (e: Exception) {
            LoadResult.Error(e)
        }
    }
    // ...
}
```

#### UI实现

使用`LazyColumn`和`collectAsLazyPagingItems`在Compose中展示分页数据。

```kotlin
// feed/FeedScreen.kt
@Composable
fun FeedScreen(viewModel: FeedViewModel = hiltViewModel()) {
    val lazyPagingItems = viewModel.feedPager.collectAsLazyPagingItems()

    LazyColumn {
        items(
            count = lazyPagingItems.itemCount,
            key = lazyPagingItems.itemKey { it.id }
        ) { index ->
            val post = lazyPagingItems[index]
            if (post != null) {
                PostItem(post = post)
            }
        }
    }
}
```

### 4. 实时通知

使用Firebase Cloud Messaging (FCM)接收来自后端的推送通知。

#### `FirebaseMessagingService`

创建一个服务来处理接收到的消息。

```kotlin
// push/MyFirebaseMessagingService.kt
class MyFirebaseMessagingService : FirebaseMessagingService() {
    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        // ... 解析通知内容
        // ... 构建并显示系统通知
    }

    override fun onNewToken(token: String) {
        // ... 将新的FCM Token发送到后端服务器
    }
}
```

### 5. 个人资料模块

该模块允许用户查看和编辑自己的个人资料。

- **UI**: 使用`TextField`展示和编辑用户信息，如用户名、简介等。
- **数据流**:
  1. `ProfileViewModel`从`UserRepository`加载用户数据。
  2. 用户在UI上修改信息。
  3. `ViewModel`调用`UserRepository`的更新方法，通过API将更改提交到后端。

## 结论

通过本指南，我们构建了一个功能较为完善的社交媒体应用。开发者可以基于此架构，进一步扩展功能，如实现即时聊天、话题标签、内容搜索等，从而打造一个功能更全面的社交平台。 