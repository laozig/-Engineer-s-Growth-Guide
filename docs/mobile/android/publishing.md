# Android应用发布与上架

将Android应用发布到Google Play商店或其他应用市场是开发过程的最后一步，也是让用户能够下载和使用你的应用的关键环节。本文档将介绍Android应用的签名、发布准备、上架流程以及发布后的维护工作。

## 应用签名

### 签名密钥的生成与管理

Android应用需要使用密钥对进行签名，以验证应用的身份和完整性。

#### 生成签名密钥

使用Android Studio生成签名密钥：

1. 选择菜单：Build > Generate Signed Bundle/APK
2. 选择Android App Bundle或APK
3. 点击"Create new..."按钮创建新的密钥库
4. 填写密钥库信息：
   - 密钥库路径（保存位置）
   - 密钥库密码
   - 密钥别名
   - 密钥密码
   - 有效期（建议25年以上）
   - 证书信息（姓名、组织等）

也可以使用命令行工具keytool生成密钥：

```bash
keytool -genkey -v -keystore my-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias my-alias
```

#### 密钥管理最佳实践

1. **安全存储密钥库文件**：
   - 不要将密钥库文件添加到版本控制系统
   - 将密钥库文件保存在安全的离线位置
   - 创建密钥库文件的备份

2. **使用强密码**：
   - 为密钥库和密钥使用强密码
   - 不要在代码或构建文件中硬编码密码

3. **记录密钥信息**：
   - 记录密钥库路径、别名和密码
   - 记录密钥的SHA-1和SHA-256指纹

获取密钥指纹：

```bash
keytool -list -v -keystore my-release-key.jks -alias my-alias
```

### 应用签名配置

在build.gradle文件中配置签名信息：

```gradle
android {
    // ...
    
    signingConfigs {
        release {
            // 从环境变量或属性文件中读取签名信息
            storeFile file(System.getenv("KEYSTORE_PATH") ?: "path/to/keystore.jks")
            storePassword System.getenv("KEYSTORE_PASSWORD") ?: getLocalProperty("keystore.password")
            keyAlias System.getenv("KEY_ALIAS") ?: getLocalProperty("key.alias")
            keyPassword System.getenv("KEY_PASSWORD") ?: getLocalProperty("key.password")
        }
        
        debug {
            // 调试签名配置
            storeFile file("debug.keystore")
            storePassword "android"
            keyAlias "androiddebugkey"
            keyPassword "android"
        }
    }
    
    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
        
        debug {
            signingConfig signingConfigs.debug
        }
    }
}

// 从local.properties文件读取属性的辅助函数
def getLocalProperty(String key) {
    Properties properties = new Properties()
    properties.load(project.rootProject.file('local.properties').newDataInputStream())
    return properties.getProperty(key)
}
```

### 应用签名方案

Android支持两种签名方案：

1. **v1签名方案**：基于JAR签名
2. **v2签名方案**：APK签名方案v2（Android 7.0引入）
3. **v3签名方案**：APK签名方案v3（Android 9.0引入）
4. **v4签名方案**：APK签名方案v4（Android 11引入）

在build.gradle中配置签名方案：

```gradle
android {
    // ...
    
    signingConfigs {
        release {
            // ...
            v1SigningEnabled true
            v2SigningEnabled true
            v3SigningEnabled true
            v4SigningEnabled true
        }
    }
}
```

## 应用打包

### 生成发布版本

#### 使用Android Studio生成

1. 选择菜单：Build > Generate Signed Bundle/APK
2. 选择Android App Bundle或APK
3. 选择签名配置
4. 选择构建类型（release）
5. 点击"Finish"开始构建

#### 使用命令行生成

```bash
# 生成AAB（Android App Bundle）
./gradlew bundleRelease

# 生成APK
./gradlew assembleRelease
```

### Android App Bundle (AAB) vs APK

Android App Bundle是Google Play推荐的发布格式，相比传统APK有以下优势：

1. **更小的下载大小**：用户只下载其设备所需的代码和资源
2. **动态功能模块**：支持按需下载功能模块
3. **简化版本管理**：一个AAB可以生成多个针对不同设备的优化APK

AAB的工作流程：

1. 开发者上传AAB到Google Play
2. Google Play为每个用户设备生成优化的APK
3. 用户下载针对其设备优化的APK

### 配置App Bundle

在build.gradle中配置App Bundle：

```gradle
android {
    // ...
    
    bundle {
        language {
            // 指定包含的语言资源
            enableSplit = true
            includeSplits = ["en", "zh"]
        }
        
        density {
            // 指定包含的屏幕密度资源
            enableSplit = true
        }
        
        abi {
            // 指定包含的ABI
            enableSplit = true
        }
        
        // 配置动态功能模块的交付选项
        dynamicFeatures = [":feature_module1", ":feature_module2"]
    }
}
```

### 测试发布版本

在发布前测试签名版本：

1. **安装测试**：
   ```bash
   adb install app/build/outputs/bundle/release/app-release.aab
   ```

2. **使用bundletool测试AAB**：
   ```bash
   # 从AAB生成一组APK
   java -jar bundletool.jar build-apks --bundle=app-release.aab --output=app-release.apks --ks=keystore.jks --ks-pass=pass:password --ks-key-alias=alias --key-pass=pass:password
   
   # 安装适合设备的APK
   java -jar bundletool.jar install-apks --apks=app-release.apks
   ```

3. **测试签名**：
   ```bash
   # 验证APK签名
   jarsigner -verify -verbose -certs app-release.apk
   ```

## Google Play发布流程

### 创建开发者账号

1. 访问[Google Play Console](https://play.google.com/console)
2. 支付$25的一次性注册费
3. 完成账号设置和验证

### 准备发布材料

#### 应用图标和图形资产

1. **应用图标**：
   - 512x512像素的高分辨率图标
   - 遵循[Material Design图标指南](https://material.io/design/iconography/product-icons.html)

2. **特色图片**：
   - 1024x500像素的特色图片
   - 展示应用的主要功能和品牌

3. **截图**：
   - 为不同设备类型（手机、平板、电视等）提供截图
   - 每种设备类型至少2张截图，最多8张
   - 手机截图分辨率：1080x1920像素（16:9）

4. **宣传视频**（可选）：
   - YouTube链接
   - 30秒到2分钟的长度
   - 展示应用的核心功能

#### 应用描述和元数据

1. **应用名称**：最多50个字符
2. **简短描述**：最多80个字符
3. **完整描述**：最多4000个字符
4. **应用类别**：选择最适合的类别和子类别
5. **内容分级**：完成内容分级问卷
6. **联系信息**：
   - 电子邮件地址
   - 网站
   - 隐私政策URL（必需）

### 上传和配置应用

1. 在Google Play Console中创建新应用
2. 填写应用详情和上传图形资产
3. 设置内容分级
4. 配置定价和分发：
   - 免费或付费
   - 选择发布国家/地区
   - 设置Android版本要求
   - 设置设备要求
5. 上传AAB或APK文件
6. 设置发布轨道：
   - 内部测试
   - 封闭测试
   - 开放测试
   - 生产发布

### 应用内购买和订阅

如果应用包含应用内购买或订阅：

1. 在Google Play Console中设置支付资料
2. 创建应用内商品：
   - 一次性购买
   - 订阅
   - 订阅优惠
3. 在应用中集成Google Play结算库：

```gradle
dependencies {
    implementation 'com.android.billingclient:billing:5.0.0'
}
```

```kotlin
// 初始化结算客户端
private lateinit var billingClient: BillingClient

fun initBilling() {
    billingClient = BillingClient.newBuilder(context)
        .setListener(purchasesUpdatedListener)
        .enablePendingPurchases()
        .build()
    
    billingClient.startConnection(object : BillingClientStateListener {
        override fun onBillingSetupFinished(billingResult: BillingResult) {
            if (billingResult.responseCode == BillingClient.BillingResponseCode.OK) {
                // 结算服务已连接，可以查询商品和购买
                querySkuDetails()
            }
        }
        
        override fun onBillingServiceDisconnected() {
            // 结算服务断开连接，尝试重新连接
            retryBillingConnection()
        }
    })
}

// 查询商品详情
fun querySkuDetails() {
    val skuList = ArrayList<String>()
    skuList.add("premium_upgrade")
    skuList.add("monthly_subscription")
    
    val params = SkuDetailsParams.newBuilder()
        .setSkusList(skuList)
        .setType(BillingClient.SkuType.INAPP) // 或 BillingClient.SkuType.SUBS 用于订阅
        .build()
    
    billingClient.querySkuDetailsAsync(params) { billingResult, skuDetailsList ->
        if (billingResult.responseCode == BillingClient.BillingResponseCode.OK && skuDetailsList != null) {
            for (skuDetails in skuDetailsList) {
                // 处理商品详情
            }
        }
    }
}

// 启动购买流程
fun launchBillingFlow(skuDetails: SkuDetails) {
    val flowParams = BillingFlowParams.newBuilder()
        .setSkuDetails(skuDetails)
        .build()
    
    billingClient.launchBillingFlow(activity, flowParams)
}

// 处理购买更新
private val purchasesUpdatedListener = PurchasesUpdatedListener { billingResult, purchases ->
    if (billingResult.responseCode == BillingClient.BillingResponseCode.OK && purchases != null) {
        for (purchase in purchases) {
            handlePurchase(purchase)
        }
    }
}

// 处理购买
private fun handlePurchase(purchase: Purchase) {
    if (purchase.purchaseState == Purchase.PurchaseState.PURCHASED) {
        // 验证购买
        verifyPurchase(purchase)
        
        // 确认购买
        if (!purchase.isAcknowledged) {
            val acknowledgePurchaseParams = AcknowledgePurchaseParams.newBuilder()
                .setPurchaseToken(purchase.purchaseToken)
                .build()
            
            billingClient.acknowledgePurchase(acknowledgePurchaseParams) { billingResult ->
                if (billingResult.responseCode == BillingClient.BillingResponseCode.OK) {
                    // 购买已确认
                }
            }
        }
    }
}

// 验证购买（应在服务器端进行）
private fun verifyPurchase(purchase: Purchase) {
    // 将购买信息发送到服务器进行验证
}
```

### 发布审核和上线

1. 提交应用进行审核
2. Google Play团队审核应用（通常需要几小时到几天）
3. 审核通过后，应用将发布到选定的轨道
4. 监控应用状态和用户反馈

## 应用版本管理

### 版本号和版本名称

在build.gradle中设置版本信息：

```gradle
android {
    defaultConfig {
        // 版本号（内部版本标识）
        versionCode 10
        
        // 版本名称（用户可见的版本标识）
        versionName "1.2.3"
    }
}
```

版本号和版本名称的最佳实践：

1. **版本号（versionCode）**：
   - 每次发布递增
   - 可以使用构建时间或CI/CD系统生成

2. **版本名称（versionName）**：
   - 遵循语义化版本（[SemVer](https://semver.org/)）
   - 格式：主版本.次版本.修订版本（例如：1.2.3）
   - 主版本：不兼容的API变更
   - 次版本：向后兼容的功能新增
   - 修订版本：向后兼容的问题修复

### 分阶段发布

Google Play支持分阶段发布，可以逐步向用户推出更新：

1. 在Google Play Console中选择"发布管理" > "国家/地区发布"
2. 选择"创建新版本"
3. 配置分阶段发布选项：
   - 按百分比：例如先发布给5%的用户，然后20%，最后100%
   - 按国家/地区：先在特定国家/地区发布

### 应用更新策略

1. **增量更新**：
   - Google Play自动提供增量更新
   - 用户只需下载应用变更部分

2. **应用内更新**：
   使用Google Play Core库实现应用内更新：

```gradle
dependencies {
    implementation 'com.google.android.play:core:1.10.3'
}
```

```kotlin
// 检查更新
val appUpdateManager = AppUpdateManagerFactory.create(context)
val appUpdateInfoTask = appUpdateManager.appUpdateInfo

appUpdateInfoTask.addOnSuccessListener { appUpdateInfo ->
    if (appUpdateInfo.updateAvailability() == UpdateAvailability.UPDATE_AVAILABLE
        && appUpdateInfo.isUpdateTypeAllowed(AppUpdateType.FLEXIBLE)) {
        
        // 请求灵活更新
        appUpdateManager.startUpdateFlowForResult(
            appUpdateInfo,
            AppUpdateType.FLEXIBLE,
            activity,
            REQUEST_CODE_UPDATE
        )
    }
}

// 监听更新状态
val listener = InstallStateUpdatedListener { state ->
    if (state.installStatus() == InstallStatus.DOWNLOADED) {
        // 更新已下载，提示用户完成安装
        showCompleteUpdateNotification()
    }
}

appUpdateManager.registerListener(listener)

// 完成更新
fun completeUpdate() {
    appUpdateManager.completeUpdate()
}
```

## 应用上架其他应用市场

除了Google Play，还可以将应用发布到其他应用市场：

### 亚马逊应用商店

1. 注册[亚马逊开发者账号](https://developer.amazon.com/)
2. 创建应用并上传APK
3. 填写应用信息和资产
4. 提交审核

### 华为应用市场

1. 注册[华为开发者联盟](https://developer.huawei.com/)账号
2. 创建应用并上传APK
3. 填写应用信息和资产
4. 提交审核

### 小米应用商店

1. 注册[小米开放平台](https://dev.mi.com/)账号
2. 创建应用并上传APK
3. 填写应用信息和资产
4. 提交审核

### 三星Galaxy Store

1. 注册[三星开发者账号](https://developer.samsung.com/)
2. 创建应用并上传APK
3. 填写应用信息和资产
4. 提交审核

## 应用发布后的维护

### 监控应用性能和崩溃

使用Firebase Crashlytics监控应用崩溃：

```gradle
dependencies {
    implementation platform('com.google.firebase:firebase-bom:30.0.0')
    implementation 'com.google.firebase:firebase-crashlytics'
    implementation 'com.google.firebase:firebase-analytics'
}
```

```kotlin
// 记录自定义错误
try {
    // 可能抛出异常的代码
} catch (e: Exception) {
    FirebaseCrashlytics.getInstance().recordException(e)
}

// 记录自定义键值对
FirebaseCrashlytics.getInstance().setCustomKey("user_id", userId)
```

### 用户反馈和评价管理

1. **应用内反馈**：
   - 提供应用内反馈渠道
   - 使用Google Play应用内评价API：

```gradle
dependencies {
    implementation 'com.google.android.play:core:1.10.3'
}
```

```kotlin
// 请求应用内评价
val reviewManager = ReviewManagerFactory.create(context)
val request = reviewManager.requestReviewFlow()

request.addOnCompleteListener { task ->
    if (task.isSuccessful) {
        val reviewInfo = task.result
        
        // 启动评价流程
        reviewManager.launchReviewFlow(activity, reviewInfo).addOnCompleteListener {
            // 评价流程完成
        }
    }
}
```

2. **回复用户评论**：
   - 在Google Play Console中回复用户评论
   - 使用Google Play Developer API自动回复评论

### 应用分析与优化

使用Firebase Analytics跟踪用户行为：

```kotlin
// 记录自定义事件
val bundle = Bundle()
bundle.putString("item_id", "item_123")
bundle.putString("item_name", "Premium Feature")
FirebaseAnalytics.getInstance(context).logEvent("select_content", bundle)
```

使用Google Play Console分析工具：
1. **获取用户**：安装来源、转化率
2. **用户参与度**：活跃用户、使用时长
3. **盈利能力**：收入、ARPU（每用户平均收入）
4. **技术性能**：ANR率、崩溃率、启动时间

### 持续集成和持续部署(CI/CD)

使用GitHub Actions自动构建和发布：

```yaml
# .github/workflows/android.yml
name: Android CI/CD

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2
    
    - name: Set up JDK
      uses: actions/setup-java@v2
      with:
        java-version: '11'
        distribution: 'adopt'
    
    - name: Grant execute permission for gradlew
      run: chmod +x gradlew
    
    - name: Build with Gradle
      run: ./gradlew build
    
    - name: Run tests
      run: ./gradlew test
    
    - name: Build Release AAB
      run: ./gradlew bundleRelease
    
    - name: Sign AAB
      uses: r0adkll/sign-android-release@v1
      with:
        releaseDirectory: app/build/outputs/bundle/release
        signingKeyBase64: ${{ secrets.SIGNING_KEY }}
        alias: ${{ secrets.KEY_ALIAS }}
        keyStorePassword: ${{ secrets.KEY_STORE_PASSWORD }}
        keyPassword: ${{ secrets.KEY_PASSWORD }}
    
    - name: Upload to Google Play
      uses: r0adkll/upload-google-play@v1
      with:
        serviceAccountJsonPlainText: ${{ secrets.SERVICE_ACCOUNT_JSON }}
        packageName: com.example.app
        releaseFiles: app/build/outputs/bundle/release/app-release.aab
        track: internal
        status: completed
```

## 总结

Android应用的发布是一个多步骤的过程，包括应用签名、打包、准备发布材料、上传到应用市场以及发布后的维护。通过遵循本文档中的最佳实践，开发者可以顺利地将应用发布到Google Play和其他应用市场，并有效地管理应用的生命周期。

记住，应用发布不是终点，而是一个持续的过程。定期更新应用、响应用户反馈、监控应用性能，是保持应用成功的关键。

## 相关资源

- [Google Play Console帮助中心](https://support.google.com/googleplay/android-developer)
- [应用签名](https://developer.android.com/studio/publish/app-signing)
- [Android App Bundle](https://developer.android.com/guide/app-bundle)
- [Google Play结算库](https://developer.android.com/google/play/billing)
- [应用内更新API](https://developer.android.com/guide/playcore/in-app-updates)
- [Firebase Crashlytics](https://firebase.google.com/docs/crashlytics)
- [应用内评价API](https://developer.android.com/guide/playcore/in-app-review)
