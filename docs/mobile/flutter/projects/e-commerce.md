# Flutter电商应用开发指南

## 目录

- [项目概述](#项目概述)
- [技术栈选择](#技术栈选择)
- [项目结构](#项目结构)
- [用户认证模块](#用户认证模块)
- [商品展示模块](#商品展示模块)
- [购物车模块](#购物车模块)
- [订单管理模块](#订单管理模块)
- [支付集成](#支付集成)
- [个人中心模块](#个人中心模块)
- [性能优化](#性能优化)
- [部署与发布](#部署与发布)

## 项目概述

本指南将详细介绍如何使用Flutter构建一个功能完善的电商应用。该应用将具备以下主要功能：

- 用户注册与登录
- 商品分类与搜索
- 商品详情展示
- 购物车管理
- 订单创建与跟踪
- 支付功能集成
- 个人中心与设置
- 收货地址管理
- 优惠券与促销

## 技术栈选择

### 前端技术

- **Flutter SDK**: 跨平台UI框架
- **GetX/Provider**: 状态管理
- **Dio**: 网络请求
- **Hive/Shared Preferences**: 本地存储
- **Firebase**: 认证与云服务
- **Flutter Secure Storage**: 敏感数据存储

### 后端技术

- **RESTful API**: 与服务器通信
- **WebSockets**: 实时通知与更新
- **支付网关**: 如支付宝、微信支付SDK

## 项目结构

采用基于模块(Module-first)的项目结构:

```
lib/
├── main.dart                 # 应用入口文件
├── app.dart                  # 应用根组件
├── config/                   # 配置文件
│   ├── app_config.dart       # 应用配置
│   ├── theme.dart            # 主题配置
│   └── routes.dart           # 路由配置
├── core/                     # 核心模块
│   ├── api/                  # API客户端
│   ├── errors/               # 错误处理
│   ├── localization/         # 国际化
│   ├── utils/                # 工具类
│   └── widgets/              # 共享组件
└── modules/                  # 功能模块
    ├── auth/                 # 认证模块
    ├── product/              # 商品模块
    ├── cart/                 # 购物车模块
    ├── order/                # 订单模块
    ├── payment/              # 支付模块
    └── profile/              # 个人中心模块
```

每个功能模块目录包含:

```
modules/product/
├── data/                     # 数据层
│   ├── models/               # 数据模型
│   ├── datasources/          # 数据源
│   └── repositories/         # 仓库实现
├── domain/                   # 领域层
│   ├── entities/             # 实体
│   ├── repositories/         # 仓库接口
│   └── usecases/             # 用例
└── presentation/             # 表现层
    ├── pages/                # 页面
    ├── widgets/              # 组件
    ├── controllers/          # 控制器
    └── bindings/             # 依赖绑定
```

## 用户认证模块

### 数据模型

创建用户认证相关的数据模型:

```dart
// lib/modules/auth/data/models/user_model.dart
class UserModel {
  final String id;
  final String username;
  final String email;
  final String? phone;
  final String? avatar;
  final DateTime createdAt;
  final bool isEmailVerified;

  UserModel({
    required this.id,
    required this.username,
    required this.email,
    this.phone,
    this.avatar,
    required this.createdAt,
    this.isEmailVerified = false,
  });

  factory UserModel.fromJson(Map<String, dynamic> json) {
    return UserModel(
      id: json['id'],
      username: json['username'],
      email: json['email'],
      phone: json['phone'],
      avatar: json['avatar'],
      createdAt: DateTime.parse(json['created_at']),
      isEmailVerified: json['is_email_verified'] ?? false,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'username': username,
      'email': email,
      'phone': phone,
      'avatar': avatar,
      'created_at': createdAt.toIso8601String(),
      'is_email_verified': isEmailVerified,
    };
  }
}
```

### 认证仓库

定义认证仓库接口和实现:

```dart
// lib/modules/auth/domain/repositories/auth_repository.dart
abstract class AuthRepository {
  Future<UserModel> signIn(String email, String password);
  Future<UserModel> signUp(String username, String email, String password);
  Future<void> signOut();
  Future<UserModel?> getCurrentUser();
  Future<void> resetPassword(String email);
  Future<void> updateProfile(UserModel user);
}

// lib/modules/auth/data/repositories/auth_repository_impl.dart
class AuthRepositoryImpl implements AuthRepository {
  final ApiClient _apiClient;
  final SecureStorage _secureStorage;

  AuthRepositoryImpl(this._apiClient, this._secureStorage);

  @override
  Future<UserModel> signIn(String email, String password) async {
    try {
      final response = await _apiClient.post('/auth/login', data: {
        'email': email,
        'password': password,
      });
      
      final userData = response.data['user'];
      final token = response.data['token'];
      
      // 保存token
      await _secureStorage.write(key: 'auth_token', value: token);
      
      return UserModel.fromJson(userData);
    } catch (e) {
      throw AuthException('登录失败: $e');
    }
  }

  @override
  Future<UserModel> signUp(String username, String email, String password) async {
    try {
      final response = await _apiClient.post('/auth/register', data: {
        'username': username,
        'email': email,
        'password': password,
      });
      
      final userData = response.data['user'];
      final token = response.data['token'];
      
      // 保存token
      await _secureStorage.write(key: 'auth_token', value: token);
      
      return UserModel.fromJson(userData);
    } catch (e) {
      throw AuthException('注册失败: $e');
    }
  }

  @override
  Future<void> signOut() async {
    await _secureStorage.delete(key: 'auth_token');
  }

  @override
  Future<UserModel?> getCurrentUser() async {
    try {
      final token = await _secureStorage.read(key: 'auth_token');
      if (token == null) return null;
      
      final response = await _apiClient.get('/auth/me');
      return UserModel.fromJson(response.data['user']);
    } catch (e) {
      await _secureStorage.delete(key: 'auth_token');
      return null;
    }
  }

  @override
  Future<void> resetPassword(String email) async {
    try {
      await _apiClient.post('/auth/reset-password', data: {
        'email': email,
      });
    } catch (e) {
      throw AuthException('重置密码失败: $e');
    }
  }

  @override
  Future<void> updateProfile(UserModel user) async {
    try {
      await _apiClient.put('/auth/profile', data: user.toJson());
    } catch (e) {
      throw AuthException('更新个人资料失败: $e');
    }
  }
}
```

### 状态管理

使用GetX管理认证状态:

```dart
// lib/modules/auth/presentation/controllers/auth_controller.dart
class AuthController extends GetxController {
  final AuthRepository _authRepository;
  
  AuthController(this._authRepository);
  
  final Rx<UserModel?> _user = Rx<UserModel?>(null);
  final RxBool _isLoading = false.obs;
  final RxString _error = ''.obs;
  
  UserModel? get user => _user.value;
  bool get isLoading => _isLoading.value;
  String get error => _error.value;
  bool get isAuthenticated => _user.value != null;
  
  @override
  void onInit() {
    super.onInit();
    _loadCurrentUser();
  }
  
  Future<void> _loadCurrentUser() async {
    _isLoading.value = true;
    _error.value = '';
    
    try {
      _user.value = await _authRepository.getCurrentUser();
    } catch (e) {
      _error.value = e.toString();
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<bool> signIn(String email, String password) async {
    _isLoading.value = true;
    _error.value = '';
    
    try {
      _user.value = await _authRepository.signIn(email, password);
      return true;
    } catch (e) {
      _error.value = e.toString();
      return false;
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<bool> signUp(String username, String email, String password) async {
    _isLoading.value = true;
    _error.value = '';
    
    try {
      _user.value = await _authRepository.signUp(username, email, password);
      return true;
    } catch (e) {
      _error.value = e.toString();
      return false;
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<void> signOut() async {
    await _authRepository.signOut();
    _user.value = null;
  }
  
  Future<bool> resetPassword(String email) async {
    _isLoading.value = true;
    _error.value = '';
    
    try {
      await _authRepository.resetPassword(email);
      return true;
    } catch (e) {
      _error.value = e.toString();
      return false;
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<bool> updateProfile(UserModel user) async {
    _isLoading.value = true;
    _error.value = '';
    
    try {
      await _authRepository.updateProfile(user);
      _user.value = user;
      return true;
    } catch (e) {
      _error.value = e.toString();
      return false;
    } finally {
      _isLoading.value = false;
    }
  }
}
```

### 登录页面

创建登录界面:

```dart
// lib/modules/auth/presentation/pages/login_page.dart
class LoginPage extends StatelessWidget {
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  
  @override
  Widget build(BuildContext context) {
    final authController = Get.find<AuthController>();
    
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Form(
            key: _formKey,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  '欢迎回来',
                  style: Theme.of(context).textTheme.headlineMedium,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 32),
                TextFormField(
                  controller: _emailController,
                  decoration: InputDecoration(
                    labelText: '邮箱',
                    prefixIcon: Icon(Icons.email),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  validator: (value) {
                    if (value == null || !value.contains('@')) {
                      return '请输入有效的邮箱地址';
                    }
                    return null;
                  },
                  keyboardType: TextInputType.emailAddress,
                ),
                const SizedBox(height: 16),
                TextFormField(
                  controller: _passwordController,
                  decoration: InputDecoration(
                    labelText: '密码',
                    prefixIcon: Icon(Icons.lock),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  validator: (value) {
                    if (value == null || value.length < 6) {
                      return '密码至少需要6个字符';
                    }
                    return null;
                  },
                  obscureText: true,
                ),
                const SizedBox(height: 8),
                Align(
                  alignment: Alignment.centerRight,
                  child: TextButton(
                    onPressed: () => Get.toNamed('/auth/forgot-password'),
                    child: Text('忘记密码?'),
                  ),
                ),
                const SizedBox(height: 16),
                Obx(() {
                  if (authController.error.isNotEmpty) {
                    return Padding(
                      padding: const EdgeInsets.only(bottom: 16),
                      child: Text(
                        authController.error,
                        style: TextStyle(color: Colors.red),
                        textAlign: TextAlign.center,
                      ),
                    );
                  }
                  return SizedBox.shrink();
                }),
                Obx(() => ElevatedButton(
                  onPressed: authController.isLoading
                      ? null
                      : () async {
                          if (_formKey.currentState!.validate()) {
                            final success = await authController.signIn(
                              _emailController.text.trim(),
                              _passwordController.text,
                            );
                            
                            if (success) {
                              Get.offAllNamed('/home');
                            }
                          }
                        },
                  child: authController.isLoading
                      ? SizedBox(
                          height: 20,
                          width: 20,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            color: Colors.white,
                          ),
                        )
                      : Text('登录'),
                  style: ElevatedButton.styleFrom(
                    padding: EdgeInsets.symmetric(vertical: 16),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                )),
                const SizedBox(height: 16),
                Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text('没有账号?'),
                    TextButton(
                      onPressed: () => Get.toNamed('/auth/register'),
                      child: Text('立即注册'),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
```

## 商品展示模块

### 商品数据模型

```dart
// lib/modules/product/data/models/product_model.dart
class ProductModel {
  final String id;
  final String name;
  final String description;
  final double price;
  final double? originalPrice;
  final List<String> images;
  final String category;
  final Map<String, dynamic>? attributes;
  final int stock;
  final double rating;
  final int reviewCount;
  final bool isFavorite;

  ProductModel({
    required this.id,
    required this.name,
    required this.description,
    required this.price,
    this.originalPrice,
    required this.images,
    required this.category,
    this.attributes,
    required this.stock,
    required this.rating,
    required this.reviewCount,
    this.isFavorite = false,
  });

  factory ProductModel.fromJson(Map<String, dynamic> json) {
    return ProductModel(
      id: json['id'],
      name: json['name'],
      description: json['description'],
      price: json['price'].toDouble(),
      originalPrice: json['original_price']?.toDouble(),
      images: List<String>.from(json['images']),
      category: json['category'],
      attributes: json['attributes'],
      stock: json['stock'],
      rating: json['rating'].toDouble(),
      reviewCount: json['review_count'],
      isFavorite: json['is_favorite'] ?? false,
    );
  }
}

// lib/modules/product/data/models/category_model.dart
class CategoryModel {
  final String id;
  final String name;
  final String? image;
  final int productCount;

  CategoryModel({
    required this.id,
    required this.name,
    this.image,
    required this.productCount,
  });

  factory CategoryModel.fromJson(Map<String, dynamic> json) {
    return CategoryModel(
      id: json['id'],
      name: json['name'],
      image: json['image'],
      productCount: json['product_count'],
    );
  }
}

// lib/modules/product/data/models/review_model.dart
class ReviewModel {
  final String id;
  final String userId;
  final String username;
  final String? userAvatar;
  final String productId;
  final double rating;
  final String comment;
  final List<String>? images;
  final DateTime createdAt;

  ReviewModel({
    required this.id,
    required this.userId,
    required this.username,
    this.userAvatar,
    required this.productId,
    required this.rating,
    required this.comment,
    this.images,
    required this.createdAt,
  });

  factory ReviewModel.fromJson(Map<String, dynamic> json) {
    return ReviewModel(
      id: json['id'],
      userId: json['user_id'],
      username: json['username'],
      userAvatar: json['user_avatar'],
      productId: json['product_id'],
      rating: json['rating'].toDouble(),
      comment: json['comment'],
      images: json['images'] != null ? List<String>.from(json['images']) : null,
      createdAt: DateTime.parse(json['created_at']),
    );
  }
}
```

### 商品仓库

```dart
// lib/modules/product/domain/repositories/product_repository.dart
abstract class ProductRepository {
  Future<List<CategoryModel>> getCategories();
  Future<List<ProductModel>> getProducts({
    String? categoryId,
    String? query,
    String? sort,
    int page = 1,
    int limit = 10,
  });
  Future<ProductModel> getProductDetails(String productId);
  Future<List<ReviewModel>> getProductReviews(String productId);
  Future<List<ProductModel>> getFavoriteProducts();
  Future<void> addToFavorites(String productId);
  Future<void> removeFromFavorites(String productId);
}

// lib/modules/product/data/repositories/product_repository_impl.dart
class ProductRepositoryImpl implements ProductRepository {
  final ApiClient _apiClient;

  ProductRepositoryImpl(this._apiClient);

  @override
  Future<List<CategoryModel>> getCategories() async {
    try {
      final response = await _apiClient.get('/categories');
      final List<dynamic> categoriesData = response.data['categories'];
      return categoriesData.map((json) => CategoryModel.fromJson(json)).toList();
    } catch (e) {
      throw ProductException('获取分类失败: $e');
    }
  }

  @override
  Future<List<ProductModel>> getProducts({
    String? categoryId,
    String? query,
    String? sort,
    int page = 1,
    int limit = 10,
  }) async {
    try {
      final Map<String, dynamic> queryParams = {
        'page': page,
        'limit': limit,
      };
      
      if (categoryId != null) queryParams['category_id'] = categoryId;
      if (query != null) queryParams['query'] = query;
      if (sort != null) queryParams['sort'] = sort;
      
      final response = await _apiClient.get(
        '/products',
        queryParameters: queryParams,
      );
      
      final List<dynamic> productsData = response.data['products'];
      return productsData.map((json) => ProductModel.fromJson(json)).toList();
    } catch (e) {
      throw ProductException('获取商品列表失败: $e');
    }
  }

  @override
  Future<ProductModel> getProductDetails(String productId) async {
    try {
      final response = await _apiClient.get('/products/$productId');
      return ProductModel.fromJson(response.data['product']);
    } catch (e) {
      throw ProductException('获取商品详情失败: $e');
    }
  }

  @override
  Future<List<ReviewModel>> getProductReviews(String productId) async {
    try {
      final response = await _apiClient.get('/products/$productId/reviews');
      final List<dynamic> reviewsData = response.data['reviews'];
      return reviewsData.map((json) => ReviewModel.fromJson(json)).toList();
    } catch (e) {
      throw ProductException('获取商品评价失败: $e');
    }
  }

  @override
  Future<List<ProductModel>> getFavoriteProducts() async {
    try {
      final response = await _apiClient.get('/users/favorites');
      final List<dynamic> productsData = response.data['products'];
      return productsData.map((json) => ProductModel.fromJson(json)).toList();
    } catch (e) {
      throw ProductException('获取收藏商品失败: $e');
    }
  }

  @override
  Future<void> addToFavorites(String productId) async {
    try {
      await _apiClient.post('/users/favorites', data: {
        'product_id': productId,
      });
    } catch (e) {
      throw ProductException('添加收藏失败: $e');
    }
  }

  @override
  Future<void> removeFromFavorites(String productId) async {
    try {
      await _apiClient.delete('/users/favorites/$productId');
    } catch (e) {
      throw ProductException('取消收藏失败: $e');
    }
  }
}
```

### 商品控制器

使用GetX管理商品状态:

```dart
// lib/modules/product/presentation/controllers/product_controller.dart
class ProductController extends GetxController {
  final ProductRepository _productRepository;
  
  ProductController(this._productRepository);
  
  final RxList<CategoryModel> _categories = <CategoryModel>[].obs;
  final RxList<ProductModel> _products = <ProductModel>[].obs;
  final Rx<ProductModel?> _selectedProduct = Rx<ProductModel?>(null);
  final RxList<ReviewModel> _reviews = <ReviewModel>[].obs;
  final RxBool _isLoading = false.obs;
  final RxString _error = ''.obs;
  final RxInt _currentPage = 1.obs;
  final RxBool _hasMoreData = true.obs;
  
  List<CategoryModel> get categories => _categories;
  List<ProductModel> get products => _products;
  ProductModel? get selectedProduct => _selectedProduct.value;
  List<ReviewModel> get reviews => _reviews;
  bool get isLoading => _isLoading.value;
  String get error => _error.value;
  bool get hasMoreData => _hasMoreData.value;
  
  @override
  void onInit() {
    super.onInit();
    fetchCategories();
    fetchProducts();
  }
  
  Future<void> fetchCategories() async {
    try {
      _isLoading.value = true;
      _categories.value = await _productRepository.getCategories();
    } catch (e) {
      _error.value = e.toString();
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<void> fetchProducts({
    String? categoryId,
    String? query,
    String? sort,
    bool refresh = false,
  }) async {
    try {
      if (refresh) {
        _currentPage.value = 1;
        _hasMoreData.value = true;
      }
      
      if (_isLoading.value || (!_hasMoreData.value && !refresh)) return;
      
      _isLoading.value = true;
      _error.value = '';
      
      final newProducts = await _productRepository.getProducts(
        categoryId: categoryId,
        query: query,
        sort: sort,
        page: _currentPage.value,
      );
      
      if (refresh) {
        _products.value = newProducts;
      } else {
        _products.addAll(newProducts);
      }
      
      _currentPage.value++;
      _hasMoreData.value = newProducts.length == 10; // 假设每页10条数据
    } catch (e) {
      _error.value = e.toString();
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<void> fetchProductDetails(String productId) async {
    try {
      _isLoading.value = true;
      _error.value = '';
      
      _selectedProduct.value = await _productRepository.getProductDetails(productId);
      _reviews.value = await _productRepository.getProductReviews(productId);
    } catch (e) {
      _error.value = e.toString();
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<void> toggleFavorite(String productId) async {
    try {
      final product = _products.firstWhere((p) => p.id == productId);
      final isFavorite = product.isFavorite;
      
      // 乐观更新UI
      _products.value = _products.map((p) {
        if (p.id == productId) {
          return ProductModel(
            id: p.id,
            name: p.name,
            description: p.description,
            price: p.price,
            originalPrice: p.originalPrice,
            images: p.images,
            category: p.category,
            attributes: p.attributes,
            stock: p.stock,
            rating: p.rating,
            reviewCount: p.reviewCount,
            isFavorite: !isFavorite,
          );
        }
        return p;
      }).toList();
      
      // 更新选中的商品
      if (_selectedProduct.value?.id == productId) {
        _selectedProduct.value = ProductModel(
          id: _selectedProduct.value!.id,
          name: _selectedProduct.value!.name,
          description: _selectedProduct.value!.description,
          price: _selectedProduct.value!.price,
          originalPrice: _selectedProduct.value!.originalPrice,
          images: _selectedProduct.value!.images,
          category: _selectedProduct.value!.category,
          attributes: _selectedProduct.value!.attributes,
          stock: _selectedProduct.value!.stock,
          rating: _selectedProduct.value!.rating,
          reviewCount: _selectedProduct.value!.reviewCount,
          isFavorite: !isFavorite,
        );
      }
      
      // 调用API
      if (isFavorite) {
        await _productRepository.removeFromFavorites(productId);
      } else {
        await _productRepository.addToFavorites(productId);
      }
    } catch (e) {
      _error.value = e.toString();
      // 如果API调用失败，恢复原状态
      await fetchProducts(refresh: true);
    }
  }
}
```

### 商品列表页面

```dart
// lib/modules/product/presentation/pages/product_list_page.dart
class ProductListPage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final productController = Get.find<ProductController>();
    
    return Scaffold(
      appBar: AppBar(
        title: Text('商品列表'),
        actions: [
          IconButton(
            icon: Icon(Icons.search),
            onPressed: () => Get.toNamed('/products/search'),
          ),
          IconButton(
            icon: Icon(Icons.favorite_border),
            onPressed: () => Get.toNamed('/products/favorites'),
          ),
        ],
      ),
      body: Column(
        children: [
          // 分类横向列表
          Obx(() {
            if (productController.categories.isEmpty) {
              return SizedBox(
                height: 100,
                child: Center(
                  child: productController.isLoading
                      ? CircularProgressIndicator()
                      : Text('暂无分类'),
                ),
              );
            }
            
            return Container(
              height: 100,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                itemCount: productController.categories.length,
                itemBuilder: (context, index) {
                  final category = productController.categories[index];
                  return GestureDetector(
                    onTap: () => Get.toNamed(
                      '/products/category/${category.id}',
                      arguments: {'categoryName': category.name},
                    ),
                    child: Container(
                      width: 80,
                      margin: EdgeInsets.only(right: 12),
                      child: Column(
                        children: [
                          CircleAvatar(
                            radius: 30,
                            backgroundImage: category.image != null
                                ? NetworkImage(category.image!)
                                : null,
                            child: category.image == null
                                ? Icon(Icons.category)
                                : null,
                          ),
                          SizedBox(height: 4),
                          Text(
                            category.name,
                            textAlign: TextAlign.center,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  );
                },
              ),
            );
          }),
          
          // 商品网格列表
          Expanded(
            child: Obx(() {
              if (productController.isLoading && productController.products.isEmpty) {
                return Center(child: CircularProgressIndicator());
              }
              
              if (productController.products.isEmpty && !productController.isLoading) {
                return Center(child: Text('暂无商品'));
              }
              
              return RefreshIndicator(
                onRefresh: () => productController.fetchProducts(refresh: true),
                child: GridView.builder(
                  padding: EdgeInsets.all(16),
                  gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 2,
                    childAspectRatio: 0.7,
                    crossAxisSpacing: 16,
                    mainAxisSpacing: 16,
                  ),
                  itemCount: productController.products.length + 
                      (productController.hasMoreData ? 1 : 0),
                  itemBuilder: (context, index) {
                    if (index >= productController.products.length) {
                      productController.fetchProducts();
                      return Center(child: CircularProgressIndicator());
                    }
                    
                    final product = productController.products[index];
                    return ProductCard(product: product);
                  },
                ),
              );
            }),
          ),
        ],
      ),
    );
  }
}

// lib/modules/product/presentation/widgets/product_card.dart
class ProductCard extends StatelessWidget {
  final ProductModel product;
  
  const ProductCard({Key? key, required this.product}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    final productController = Get.find<ProductController>();
    
    return GestureDetector(
      onTap: () => Get.toNamed('/products/${product.id}'),
      child: Card(
        elevation: 2,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 商品图片
            ClipRRect(
              borderRadius: BorderRadius.vertical(top: Radius.circular(12)),
              child: AspectRatio(
                aspectRatio: 1,
                child: Image.network(
                  product.images.first,
                  fit: BoxFit.cover,
                ),
              ),
            ),
            
            Padding(
              padding: const EdgeInsets.all(8.0),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 商品名称
                  Text(
                    product.name,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  SizedBox(height: 4),
                  
                  // 价格信息
                  Row(
                    children: [
                      Text(
                        '¥${product.price.toStringAsFixed(2)}',
                        style: TextStyle(
                          color: Colors.red,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      if (product.originalPrice != null)
                        Padding(
                          padding: const EdgeInsets.only(left: 4),
                          child: Text(
                            '¥${product.originalPrice!.toStringAsFixed(2)}',
                            style: TextStyle(
                              decoration: TextDecoration.lineThrough,
                              color: Colors.grey,
                              fontSize: 12,
                            ),
                          ),
                        ),
                    ],
                  ),
                  
                  // 评分和收藏
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Row(
                        children: [
                          Icon(
                            Icons.star,
                            size: 16,
                            color: Colors.amber,
                          ),
                          SizedBox(width: 2),
                          Text(
                            product.rating.toString(),
                            style: TextStyle(fontSize: 12),
                          ),
                        ],
                      ),
                      IconButton(
                        icon: Icon(
                          product.isFavorite
                              ? Icons.favorite
                              : Icons.favorite_border,
                          color: product.isFavorite ? Colors.red : null,
                          size: 20,
                        ),
                        onPressed: () => 
                            productController.toggleFavorite(product.id),
                        padding: EdgeInsets.zero,
                        constraints: BoxConstraints(),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
```

## 购物车模块

### 购物车数据模型

```dart
// lib/modules/cart/data/models/cart_item_model.dart
class CartItemModel {
  final String id;
  final String productId;
  final String productName;
  final String productImage;
  final double price;
  final int quantity;
  final Map<String, dynamic>? attributes;
  final int stock;

  CartItemModel({
    required this.id,
    required this.productId,
    required this.productName,
    required this.productImage,
    required this.price,
    required this.quantity,
    this.attributes,
    required this.stock,
  });

  double get totalPrice => price * quantity;

  factory CartItemModel.fromJson(Map<String, dynamic> json) {
    return CartItemModel(
      id: json['id'],
      productId: json['product_id'],
      productName: json['product_name'],
      productImage: json['product_image'],
      price: json['price'].toDouble(),
      quantity: json['quantity'],
      attributes: json['attributes'],
      stock: json['stock'],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'product_id': productId,
      'product_name': productName,
      'product_image': productImage,
      'price': price,
      'quantity': quantity,
      'attributes': attributes,
      'stock': stock,
    };
  }

  CartItemModel copyWith({
    String? id,
    String? productId,
    String? productName,
    String? productImage,
    double? price,
    int? quantity,
    Map<String, dynamic>? attributes,
    int? stock,
  }) {
    return CartItemModel(
      id: id ?? this.id,
      productId: productId ?? this.productId,
      productName: productName ?? this.productName,
      productImage: productImage ?? this.productImage,
      price: price ?? this.price,
      quantity: quantity ?? this.quantity,
      attributes: attributes ?? this.attributes,
      stock: stock ?? this.stock,
    );
  }
}
```

### 购物车仓库

```dart
// lib/modules/cart/domain/repositories/cart_repository.dart
abstract class CartRepository {
  Future<List<CartItemModel>> getCartItems();
  Future<void> addToCart(String productId, int quantity, Map<String, dynamic>? attributes);
  Future<void> updateCartItem(String cartItemId, int quantity);
  Future<void> removeCartItem(String cartItemId);
  Future<void> clearCart();
}

// lib/modules/cart/data/repositories/cart_repository_impl.dart
class CartRepositoryImpl implements CartRepository {
  final ApiClient _apiClient;

  CartRepositoryImpl(this._apiClient);

  @override
  Future<List<CartItemModel>> getCartItems() async {
    try {
      final response = await _apiClient.get('/cart');
      final List<dynamic> itemsData = response.data['items'];
      return itemsData.map((json) => CartItemModel.fromJson(json)).toList();
    } catch (e) {
      throw CartException('获取购物车失败: $e');
    }
  }

  @override
  Future<void> addToCart(String productId, int quantity, Map<String, dynamic>? attributes) async {
    try {
      await _apiClient.post('/cart', data: {
        'product_id': productId,
        'quantity': quantity,
        'attributes': attributes,
      });
    } catch (e) {
      throw CartException('添加到购物车失败: $e');
    }
  }

  @override
  Future<void> updateCartItem(String cartItemId, int quantity) async {
    try {
      await _apiClient.put('/cart/$cartItemId', data: {
        'quantity': quantity,
      });
    } catch (e) {
      throw CartException('更新购物车失败: $e');
    }
  }

  @override
  Future<void> removeCartItem(String cartItemId) async {
    try {
      await _apiClient.delete('/cart/$cartItemId');
    } catch (e) {
      throw CartException('从购物车移除失败: $e');
    }
  }

  @override
  Future<void> clearCart() async {
    try {
      await _apiClient.delete('/cart');
    } catch (e) {
      throw CartException('清空购物车失败: $e');
    }
  }
}
```

### 购物车控制器

```dart
// lib/modules/cart/presentation/controllers/cart_controller.dart
class CartController extends GetxController {
  final CartRepository _cartRepository;
  
  CartController(this._cartRepository);
  
  final RxList<CartItemModel> _cartItems = <CartItemModel>[].obs;
  final RxBool _isLoading = false.obs;
  final RxString _error = ''.obs;
  final RxMap<String, bool> _itemLoading = <String, bool>{}.obs;
  
  List<CartItemModel> get cartItems => _cartItems;
  bool get isLoading => _isLoading.value;
  String get error => _error.value;
  
  bool isItemLoading(String itemId) => _itemLoading[itemId] ?? false;
  
  double get totalPrice => _cartItems.fold(
    0, (sum, item) => sum + item.totalPrice);
  
  int get itemCount => _cartItems.fold(
    0, (sum, item) => sum + item.quantity);
  
  @override
  void onInit() {
    super.onInit();
    fetchCartItems();
  }
  
  Future<void> fetchCartItems() async {
    try {
      _isLoading.value = true;
      _error.value = '';
      
      _cartItems.value = await _cartRepository.getCartItems();
    } catch (e) {
      _error.value = e.toString();
    } finally {
      _isLoading.value = false;
    }
  }
  
  Future<bool> addToCart(String productId, int quantity, Map<String, dynamic>? attributes) async {
    try {
      _itemLoading[productId] = true;
      
      await _cartRepository.addToCart(productId, quantity, attributes);
      await fetchCartItems();
      
      return true;
    } catch (e) {
      _error.value = e.toString();
      return false;
    } finally {
      _itemLoading.remove(productId);
    }
  }
  
  Future<bool> updateCartItem(String itemId, int quantity) async {
    try {
      _itemLoading[itemId] = true;
      
      // 乐观更新UI
      final index = _cartItems.indexWhere((item) => item.id == itemId);
      if (index != -1) {
        final updatedItem = _cartItems[index].copyWith(quantity: quantity);
        _cartItems[index] = updatedItem;
      }
      
      await _cartRepository.updateCartItem(itemId, quantity);
      await fetchCartItems();
      
      return true;
    } catch (e) {
      _error.value = e.toString();
      await fetchCartItems(); // 恢复原状态
      return false;
    } finally {
      _itemLoading.remove(itemId);
    }
  }
  
  Future<bool> removeCartItem(String itemId) async {
    try {
      _itemLoading[itemId] = true;
      
      // 乐观更新UI
      _cartItems.removeWhere((item) => item.id == itemId);
      
      await _cartRepository.removeCartItem(itemId);
      
      return true;
    } catch (e) {
      _error.value = e.toString();
      await fetchCartItems(); // 恢复原状态
      return false;
    } finally {
      _itemLoading.remove(itemId);
    }
  }
  
  Future<bool> clearCart() async {
    try {
      _isLoading.value = true;
      
      await _cartRepository.clearCart();
      _cartItems.clear();
      
      return true;
    } catch (e) {
      _error.value = e.toString();
      await fetchCartItems();
      return false;
    } finally {
      _isLoading.value = false;
    }
  }
}
```

### 购物车页面

```dart
// lib/modules/cart/presentation/pages/cart_page.dart
class CartPage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final cartController = Get.find<CartController>();
    
    return Scaffold(
      appBar: AppBar(
        title: Text('购物车'),
        actions: [
          TextButton(
            onPressed: cartController.cartItems.isEmpty
                ? null
                : () => _showClearCartDialog(context),
            child: Text('清空'),
            style: TextButton.styleFrom(
              foregroundColor: Colors.red,
            ),
          ),
        ],
      ),
      body: Obx(() {
        if (cartController.isLoading && cartController.cartItems.isEmpty) {
          return Center(child: CircularProgressIndicator());
        }
        
        if (cartController.cartItems.isEmpty && !cartController.isLoading) {
          return Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.shopping_cart_outlined, size: 80, color: Colors.grey),
                SizedBox(height: 16),
                Text('购物车是空的'),
                SizedBox(height: 24),
                ElevatedButton(
                  onPressed: () => Get.offAllNamed('/home'),
                  child: Text('去购物'),
                  style: ElevatedButton.styleFrom(
                    padding: EdgeInsets.symmetric(horizontal: 32, vertical: 12),
                  ),
                ),
              ],
            ),
          );
        }
        
        return Column(
          children: [
            Expanded(
              child: ListView.builder(
                padding: EdgeInsets.all(16),
                itemCount: cartController.cartItems.length,
                itemBuilder: (context, index) {
                  final item = cartController.cartItems[index];
                  return CartItemCard(item: item);
                },
              ),
            ),
            
            // 底部结算栏
            Container(
              padding: EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                boxShadow: [
                  BoxShadow(
                    color: Colors.black12,
                    blurRadius: 4,
                    offset: Offset(0, -2),
                  ),
                ],
              ),
              child: Row(
                children: [
                  Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        '总计: ¥${cartController.totalPrice.toStringAsFixed(2)}',
                        style: TextStyle(
                          fontWeight: FontWeight.bold,
                          fontSize: 16,
                        ),
                      ),
                      Text(
                        '共${cartController.itemCount}件商品',
                        style: TextStyle(
                          color: Colors.grey,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                  Spacer(),
                  ElevatedButton(
                    onPressed: cartController.cartItems.isEmpty
                        ? null
                        : () => Get.toNamed('/checkout'),
                    child: Text('结算'),
                    style: ElevatedButton.styleFrom(
                      padding: EdgeInsets.symmetric(horizontal: 32, vertical: 12),
                    ),
                  ),
                ],
              ),
            ),
          ],
        );
      }),
    );
  }
  
  void _showClearCartDialog(BuildContext context) {
    final cartController = Get.find<CartController>();
    
    Get.dialog(
      AlertDialog(
        title: Text('清空购物车'),
        content: Text('确定要清空购物车吗？此操作不可撤销。'),
        actions: [
          TextButton(
            onPressed: () => Get.back(),
            child: Text('取消'),
          ),
          TextButton(
            onPressed: () async {
              Get.back();
              await cartController.clearCart();
            },
            child: Text('确定'),
            style: TextButton.styleFrom(
              foregroundColor: Colors.red,
            ),
          ),
        ],
      ),
    );
  }
}

// lib/modules/cart/presentation/widgets/cart_item_card.dart
class CartItemCard extends StatelessWidget {
  final CartItemModel item;
  
  const CartItemCard({Key? key, required this.item}) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    final cartController = Get.find<CartController>();
    
    return Card(
      margin: EdgeInsets.only(bottom: 16),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
      ),
      child: Padding(
        padding: const EdgeInsets.all(12.0),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 商品图片
            ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: Image.network(
                item.productImage,
                width: 80,
                height: 80,
                fit: BoxFit.cover,
              ),
            ),
            SizedBox(width: 12),
            
            // 商品信息
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    item.productName,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  SizedBox(height: 4),
                  
                  // 商品属性
                  if (item.attributes != null && item.attributes!.isNotEmpty)
                    Text(
                      item.attributes!.entries
                          .map((e) => '${e.key}: ${e.value}')
                          .join(', '),
                      style: TextStyle(
                        color: Colors.grey,
                        fontSize: 12,
                      ),
                    ),
                  
                  SizedBox(height: 8),
                  
                  // 价格和数量控制
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceBetween,
                    children: [
                      Text(
                        '¥${item.price.toStringAsFixed(2)}',
                        style: TextStyle(
                          color: Colors.red,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      
                      // 数量控制器
                      Row(
                        children: [
                          IconButton(
                            icon: Icon(Icons.remove),
                            onPressed: item.quantity <= 1
                                ? null
                                : () => cartController.updateCartItem(
                                    item.id, item.quantity - 1),
                            padding: EdgeInsets.zero,
                            constraints: BoxConstraints(),
                            iconSize: 18,
                          ),
                          SizedBox(width: 8),
                          Text(
                            item.quantity.toString(),
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                          SizedBox(width: 8),
                          IconButton(
                            icon: Icon(Icons.add),
                            onPressed: item.quantity >= item.stock
                                ? null
                                : () => cartController.updateCartItem(
                                    item.id, item.quantity + 1),
                            padding: EdgeInsets.zero,
                            constraints: BoxConstraints(),
                            iconSize: 18,
                          ),
                        ],
                      ),
                    ],
                  ),
                ],
              ),
            ),
            
            // 删除按钮
            IconButton(
              icon: Icon(Icons.delete_outline),
              onPressed: () => cartController.removeCartItem(item.id),
              color: Colors.red,
              padding: EdgeInsets.zero,
              constraints: BoxConstraints(),
            ),
          ],
        ),
      ),
    );
  }
}
```

## 订单管理模块

### 订单数据模型

```dart
// lib/modules/order/data/models/order_model.dart
class OrderModel {
  final String id;
  final String status;
  final double totalAmount;
  final int itemCount;
  final DateTime createdAt;
  final String? trackingNumber;
  final AddressModel shippingAddress;
  final List<OrderItemModel> items;
  final PaymentInfoModel paymentInfo;

  OrderModel({
    required this.id,
    required this.status,
    required this.totalAmount,
    required this.itemCount,
    required this.createdAt,
    this.trackingNumber,
    required this.shippingAddress,
    required this.items,
    required this.paymentInfo,
  });

  factory OrderModel.fromJson(Map<String, dynamic> json) {
    return OrderModel(
      id: json['id'],
      status: json['status'],
      totalAmount: json['total_amount'].toDouble(),
      itemCount: json['item_count'],
      createdAt: DateTime.parse(json['created_at']),
      trackingNumber: json['tracking_number'],
      shippingAddress: AddressModel.fromJson(json['shipping_address']),
      items: (json['items'] as List)
          .map((item) => OrderItemModel.fromJson(item))
          .toList(),
      paymentInfo: PaymentInfoModel.fromJson(json['payment_info']),
    );
  }
}

// lib/modules/order/data/models/order_item_model.dart
class OrderItemModel {
  final String id;
  final String productId;
  final String productName;
  final String productImage;
  final double price;
  final int quantity;
  final Map<String, dynamic>? attributes;

  OrderItemModel({
    required this.id,
    required this.productId,
    required this.productName,
    required this.productImage,
    required this.price,
    required this.quantity,
    this.attributes,
  });

  factory OrderItemModel.fromJson(Map<String, dynamic> json) {
    return OrderItemModel(
      id: json['id'],
      productId: json['product_id'],
      productName: json['product_name'],
      productImage: json['product_image'],
      price: json['price'].toDouble(),
      quantity: json['quantity'],
      attributes: json['attributes'],
    );
  }
}

// lib/modules/order/data/models/address_model.dart
class AddressModel {
  final String id;
  final String name;
  final String phone;
  final String province;
  final String city;
  final String district;
  final String detailAddress;
  final bool isDefault;

  AddressModel({
    required this.id,
    required this.name,
    required this.phone,
    required this.province,
    required this.city,
    required this.district,
    required this.detailAddress,
    this.isDefault = false,
  });

  factory AddressModel.fromJson(Map<String, dynamic> json) {
    return AddressModel(
      id: json['id'],
      name: json['name'],
      phone: json['phone'],
      province: json['province'],
      city: json['city'],
      district: json['district'],
      detailAddress: json['detail_address'],
      isDefault: json['is_default'] ?? false,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'id': id,
      'name': name,
      'phone': phone,
      'province': province,
      'city': city,
      'district': district,
      'detail_address': detailAddress,
      'is_default': isDefault,
    };
  }

  String get fullAddress => '$province $city $district $detailAddress';
}

// lib/modules/order/data/models/payment_info_model.dart
class PaymentInfoModel {
  final String method;
  final String status;
  final DateTime? paidAt;
  final String? transactionId;

  PaymentInfoModel({
    required this.method,
    required this.status,
    this.paidAt,
    this.transactionId,
  });

  factory PaymentInfoModel.fromJson(Map<String, dynamic> json) {
    return PaymentInfoModel(
      method: json['method'],
      status: json['status'],
      paidAt: json['paid_at'] != null ? DateTime.parse(json['paid_at']) : null,
      transactionId: json['transaction_id'],
    );
  }
}
```

### 订单仓库

```dart
// lib/modules/order/domain/repositories/order_repository.dart
abstract class OrderRepository {
  Future<List<OrderModel>> getOrders({String? status});
  Future<OrderModel> getOrderDetails(String orderId);
  Future<OrderModel> createOrder(String addressId, String paymentMethod);
  Future<void> cancelOrder(String orderId);
}

// lib/modules/order/data/repositories/order_repository_impl.dart
class OrderRepositoryImpl implements OrderRepository {
  final ApiClient _apiClient;

  OrderRepositoryImpl(this._apiClient);

  @override
  Future<List<OrderModel>> getOrders({String? status}) async {
    try {
      final queryParams = <String, dynamic>{};
      if (status != null) queryParams['status'] = status;
      
      final response = await _apiClient.get('/orders', queryParameters: queryParams);
      final List<dynamic> ordersData = response.data['orders'];
      return ordersData.map((json) => OrderModel.fromJson(json)).toList();
    } catch (e) {
      throw OrderException('获取订单列表失败: $e');
    }
  }

  @override
  Future<OrderModel> getOrderDetails(String orderId) async {
    try {
      final response = await _apiClient.get('/orders/$orderId');
      return OrderModel.fromJson(response.data['order']);
    } catch (e) {
      throw OrderException('获取订单详情失败: $e');
    }
  }

  @override
  Future<OrderModel> createOrder(String addressId, String paymentMethod) async {
    try {
      final response = await _apiClient.post('/orders', data: {
        'address_id': addressId,
        'payment_method': paymentMethod,
      });
      return OrderModel.fromJson(response.data['order']);
    } catch (e) {
      throw OrderException('创建订单失败: $e');
    }
  }

  @override
  Future<void> cancelOrder(String orderId) async {
    try {
      await _apiClient.post('/orders/$orderId/cancel');
    } catch (e) {
      throw OrderException('取消订单失败: $e');
    }
  }
}
```

## 支付集成

### 支付服务

```dart
// lib/modules/payment/domain/services/payment_service.dart
abstract class PaymentService {
  Future<bool> processPayment(String orderId, String method, double amount);
  Future<Map<String, dynamic>> getPaymentParams(String orderId, String method);
}

// lib/modules/payment/data/services/payment_service_impl.dart
class PaymentServiceImpl implements PaymentService {
  final ApiClient _apiClient;

  PaymentServiceImpl(this._apiClient);

  @override
  Future<bool> processPayment(String orderId, String method, double amount) async {
    try {
      // 获取支付参数
      final params = await getPaymentParams(orderId, method);
      
      // 根据不同支付方式调用对应SDK
      switch (method) {
        case 'alipay':
          return await _processAlipay(params);
        case 'wechat':
          return await _processWechat(params);
        default:
          throw PaymentException('不支持的支付方式');
      }
    } catch (e) {
      throw PaymentException('支付处理失败: $e');
    }
  }

  @override
  Future<Map<String, dynamic>> getPaymentParams(String orderId, String method) async {
    try {
      final response = await _apiClient.post('/payments/prepare', data: {
        'order_id': orderId,
        'method': method,
      });
      return response.data['params'];
    } catch (e) {
      throw PaymentException('获取支付参数失败: $e');
    }
  }

  Future<bool> _processAlipay(Map<String, dynamic> params) async {
    try {
      // 调用支付宝SDK
      // final result = await FlutterAlipay.pay(params['orderInfo']);
      // return result['resultStatus'] == '9000';
      
      // 模拟支付成功
      await Future.delayed(Duration(seconds: 2));
      return true;
    } catch (e) {
      throw PaymentException('支付宝支付失败: $e');
    }
  }

  Future<bool> _processWechat(Map<String, dynamic> params) async {
    try {
      // 调用微信支付SDK
      // final result = await FlutterWechatPay.pay(params);
      // return result['errCode'] == 0;
      
      // 模拟支付成功
      await Future.delayed(Duration(seconds: 2));
      return true;
    } catch (e) {
      throw PaymentException('微信支付失败: $e');
    }
  }
}
```

## 个人中心模块

### 地址管理

```dart
// lib/modules/profile/domain/repositories/address_repository.dart
abstract class AddressRepository {
  Future<List<AddressModel>> getAddresses();
  Future<AddressModel> createAddress(AddressModel address);
  Future<AddressModel> updateAddress(AddressModel address);
  Future<void> deleteAddress(String addressId);
  Future<void> setDefaultAddress(String addressId);
}

// lib/modules/profile/data/repositories/address_repository_impl.dart
class AddressRepositoryImpl implements AddressRepository {
  final ApiClient _apiClient;

  AddressRepositoryImpl(this._apiClient);

  @override
  Future<List<AddressModel>> getAddresses() async {
    try {
      final response = await _apiClient.get('/addresses');
      final List<dynamic> addressesData = response.data['addresses'];
      return addressesData.map((json) => AddressModel.fromJson(json)).toList();
    } catch (e) {
      throw AddressException('获取地址列表失败: $e');
    }
  }

  @override
  Future<AddressModel> createAddress(AddressModel address) async {
    try {
      final response = await _apiClient.post('/addresses', data: address.toJson());
      return AddressModel.fromJson(response.data['address']);
    } catch (e) {
      throw AddressException('创建地址失败: $e');
    }
  }

  @override
  Future<AddressModel> updateAddress(AddressModel address) async {
    try {
      final response = await _apiClient.put('/addresses/${address.id}', data: address.toJson());
      return AddressModel.fromJson(response.data['address']);
    } catch (e) {
      throw AddressException('更新地址失败: $e');
    }
  }

  @override
  Future<void> deleteAddress(String addressId) async {
    try {
      await _apiClient.delete('/addresses/$addressId');
    } catch (e) {
      throw AddressException('删除地址失败: $e');
    }
  }

  @override
  Future<void> setDefaultAddress(String addressId) async {
    try {
      await _apiClient.post('/addresses/$addressId/default');
    } catch (e) {
      throw AddressException('设置默认地址失败: $e');
    }
  }
}
```

## 性能优化

### 图片优化

```dart
// lib/core/widgets/optimized_image.dart
class OptimizedImage extends StatelessWidget {
  final String imageUrl;
  final double? width;
  final double? height;
  final BoxFit fit;
  
  const OptimizedImage({
    Key? key,
    required this.imageUrl,
    this.width,
    this.height,
    this.fit = BoxFit.cover,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    return CachedNetworkImage(
      imageUrl: imageUrl,
      width: width,
      height: height,
      fit: fit,
      placeholder: (context, url) => Container(
        color: Colors.grey[200],
        child: Center(
          child: SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              valueColor: AlwaysStoppedAnimation<Color>(Colors.grey),
            ),
          ),
        ),
      ),
      errorWidget: (context, url, error) => Container(
        color: Colors.grey[200],
        child: Icon(Icons.error, color: Colors.red),
      ),
      memCacheWidth: width?.toInt(),
      memCacheHeight: height?.toInt(),
    );
  }
}
```

### 无限滚动优化

```dart
// lib/core/widgets/infinite_scroll_list.dart
class InfiniteScrollList<T> extends StatelessWidget {
  final List<T> items;
  final bool isLoading;
  final bool hasMoreData;
  final Function() onLoadMore;
  final Widget Function(BuildContext, T) itemBuilder;
  final Widget? emptyWidget;
  final EdgeInsetsGeometry? padding;
  
  const InfiniteScrollList({
    Key? key,
    required this.items,
    required this.isLoading,
    required this.hasMoreData,
    required this.onLoadMore,
    required this.itemBuilder,
    this.emptyWidget,
    this.padding,
  }) : super(key: key);
  
  @override
  Widget build(BuildContext context) {
    if (items.isEmpty && !isLoading) {
      return emptyWidget ?? Center(child: Text('暂无数据'));
    }
    
    return ListView.builder(
      padding: padding,
      itemCount: items.length + (hasMoreData || isLoading ? 1 : 0),
      itemBuilder: (context, index) {
        if (index >= items.length) {
          if (!isLoading) {
            // 触发加载更多
            WidgetsBinding.instance.addPostFrameCallback((_) {
              onLoadMore();
            });
          }
          
          return Container(
            padding: EdgeInsets.symmetric(vertical: 16),
            alignment: Alignment.center,
            child: CircularProgressIndicator(),
          );
        }
        
        return itemBuilder(context, items[index]);
      },
    );
  }
}
```

## 部署与发布

参考[Flutter发布与部署](../publishing.md)文档，了解如何将电商应用发布到应用商店。

---

通过本指南，你应该能够构建一个功能完善的Flutter电商应用。记住，一个成功的电商应用不仅需要良好的用户体验，还需要安全可靠的后端支持和支付系统。祝你的电商应用开发顺利！
