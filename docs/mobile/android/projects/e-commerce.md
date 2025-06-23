# 电商应用客户端开发

本指南将带你从零开始构建一个功能完善的Android电商应用客户端，覆盖从架构设计到核心功能模块的完整开发流程。

## 应用概述

此电商应用旨在提供一个完整的移动购物体验，核心功能包括：
- 商品浏览：按分类查看商品，搜索商品。
- 商品详情：查看商品的详细信息、图片和价格。
- 购物车：添加、移除商品，修改商品数量。
- 用户认证：支持用户登录注册，管理个人信息。
- 结账流程：填写收货地址，选择支付方式，创建订单。
- 订单管理：查看历史订单状态。

## 技术栈

- **语言**: Kotlin
- **架构**: MVVM (Model-View-ViewModel)
- **UI**: Jetpack Compose
- **异步处理**: Kotlin Coroutines & Flow
- **网络请求**: Retrofit & OkHttp
- **依赖注入**: Hilt
- **数据持久化**: Room (用于购物车和数据缓存)
- **导航**: Jetpack Navigation for Compose
- **图片加载**: Coil
- **分页加载**: Paging 3

## 开发步骤

### 1. 整体架构

应用采用分层架构，确保代码的模块化和可维护性。

```
app/
|-- data/
|   |-- remote/ (Retrofit API)
|   |-- local/  (Room DAO)
|   |-- model/  (DTOs)
|   |-- repository/ (仓库实现)
|-- domain/
|   |-- model/ (业务模型)
|   |-- usecase/ (业务逻辑)
|-- ui/
|   |-- navigation/ (导航图)
|   |-- screens/
|   |   |-- products/ (商品列表/详情)
|   |   |-- cart/     (购物车)
|   |   |-- checkout/ (结账)
|   |   |-- orders/   (订单历史)
|-- di/ (Hilt依赖注入模块)
```

### 2. 商品浏览模块

#### API定义

使用Retrofit定义获取商品列表和详情的API。

```kotlin
// products/ProductService.kt
interface ProductService {
    @GET("api/products")
    suspend fun getProducts(
        @Query("page") page: Int,
        @Query("pageSize") pageSize: Int,
        @Query("category") category: String?
    ): Response<ProductListResponse>

    @GET("api/products/{id}")
    suspend fun getProductDetails(@Path("id") productId: String): Response<Product>
}
```

#### 分页加载

使用Paging 3实现商品列表的无限滚动加载。

```kotlin
// products/ProductsPagingSource.kt
class ProductsPagingSource(
    private val productService: ProductService,
    private val category: String?
) : PagingSource<Int, Product>() {
    override suspend fun load(params: LoadParams<Int>): LoadResult<Int, Product> {
        val page = params.key ?: 1
        return try {
            val response = productService.getProducts(page, params.loadSize, category)
            LoadResult.Page(
                data = response.body()?.products ?: emptyList(),
                prevKey = if (page == 1) null else page - 1,
                nextKey = if (response.body()?.products.isNullOrEmpty()) null else page + 1
            )
        } catch (e: Exception) {
            LoadResult.Error(e)
        }
    }
}
```

### 3. 购物车模块 (本地持久化)

使用Room数据库在本地设备上存储购物车信息。

#### Room实体和DAO

```kotlin
// cart/CartItem.kt
@Entity(tableName = "cart_items")
data class CartItem(
    @PrimaryKey val productId: String,
    val productName: String,
    val price: Double,
    var quantity: Int
)

// cart/CartDao.kt
@Dao
interface CartDao {
    @Query("SELECT * FROM cart_items")
    fun getCartItems(): Flow<List<CartItem>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun addItem(item: CartItem)

    @Update
    suspend fun updateItem(item: CartItem)

    @Query("DELETE FROM cart_items WHERE productId = :productId")
    suspend fun removeItem(productId: String)

    @Query("DELETE FROM cart_items")
    suspend fun clearCart()
}
```

#### ViewModel与UI

`CartViewModel`通过`CartRepository`与数据库交互，并向UI暴露购物车状态。

```kotlin
// cart/CartViewModel.kt
@HiltViewModel
class CartViewModel @Inject constructor(
    private val cartRepository: CartRepository
) : ViewModel() {
    val cartItems = cartRepository.getCartItems().stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )
    // ... add, remove, update aync functions
}

// cart/CartScreen.kt
@Composable
fun CartScreen(viewModel: CartViewModel = hiltViewModel()) {
    val cartItems by viewModel.cartItems.collectAsState()
    // ... 使用LazyColumn展示cartItems
}
```

### 4. 结账流程

#### API定义

定义创建订单的API。

```kotlin
// checkout/OrderService.kt
interface OrderService {
    @POST("api/orders")
    suspend fun createOrder(@Body orderRequest: OrderRequest): Response<OrderConfirmation>
}
```

#### 结账状态管理

`CheckoutViewModel`负责管理结账流程中的所有状态，包括收货地址、支付信息和最终的订单提交。

```kotlin
// checkout/CheckoutViewModel.kt
@HiltViewModel
class CheckoutViewModel @Inject constructor(
    private val orderRepository: OrderRepository,
    private val cartRepository: CartRepository
) : ViewModel() {
    // ... 管理地址、支付方式等状态
    
    fun placeOrder() {
        viewModelScope.launch {
            // 1. 从cartRepository获取当前购物车商品
            // 2. 构建OrderRequest对象
            // 3. 调用orderRepository.createOrder
            // 4. 处理成功或失败的结果
            // 5. 清空购物车
        }
    }
}
```

### 5. 订单历史

`OrderHistoryScreen`将调用`OrderRepository`获取历史订单列表并展示。

## 结论

本指南概述了构建一个Android电商应用的核心步骤和技术选型。基于此架构，可以轻松扩展更多高级功能，如商品评价、优惠券系统、以及更复杂的支付集成方案，从而打造一个功能全面的电商平台。 