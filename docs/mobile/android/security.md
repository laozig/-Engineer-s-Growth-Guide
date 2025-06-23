# Android应用安全

应用安全是Android开发中至关重要的一环，涉及保护用户数据、防止未授权访问、抵御恶意攻击等方面。本文档将介绍Android应用安全的最佳实践，包括数据加密、安全存储、网络安全、代码保护等内容。

## 数据加密

### 加密算法选择

在Android中，可以使用以下加密算法和技术：

1. **对称加密**：AES (Advanced Encryption Standard)
2. **非对称加密**：RSA (Rivest-Shamir-Adleman)
3. **哈希函数**：SHA-256, SHA-512
4. **密钥派生函数**：PBKDF2, Scrypt, Bcrypt

### 使用Android Keystore系统

Android Keystore系统提供了一种安全存储密钥的方式，密钥材料不会暴露给应用程序。

```kotlin
// 生成密钥并存储在Android Keystore中
fun generateKey(alias: String): SecretKey {
    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val keyGenParameterSpec = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setUserAuthenticationRequired(false) // 设置为true需要用户认证
        .setRandomizedEncryptionRequired(true)
        .build()
    
    keyGenerator.init(keyGenParameterSpec)
    return keyGenerator.generateKey()
}

// 使用存储在Keystore中的密钥加密数据
fun encryptData(alias: String, data: ByteArray): ByteArray {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)
    
    val secretKey = keyStore.getKey(alias, null) as SecretKey
    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey)
    
    val iv = cipher.iv
    val encryptedData = cipher.doFinal(data)
    
    // 将IV和加密数据合并
    return iv + encryptedData
}

// 使用存储在Keystore中的密钥解密数据
fun decryptData(alias: String, encryptedData: ByteArray): ByteArray {
    val keyStore = KeyStore.getInstance("AndroidKeyStore")
    keyStore.load(null)
    
    val secretKey = keyStore.getKey(alias, null) as SecretKey
    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    
    // 从加密数据中提取IV（前16字节）
    val iv = encryptedData.copyOfRange(0, 16)
    val actualEncryptedData = encryptedData.copyOfRange(16, encryptedData.size)
    
    val ivSpec = IvParameterSpec(iv)
    cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
    
    return cipher.doFinal(actualEncryptedData)
}
```

### 使用加密库

对于复杂的加密需求，可以使用成熟的第三方库，如Tink或者Bouncy Castle：

```gradle
dependencies {
    // Google Tink
    implementation 'com.google.crypto.tink:tink-android:1.6.1'
}
```

```kotlin
// 使用Tink进行加密
fun initTink() {
    TinkConfig.register()
}

fun encryptWithTink(keysetHandle: KeysetHandle, data: ByteArray): ByteArray {
    val aead = keysetHandle.getPrimitive(Aead::class.java)
    return aead.encrypt(data, null) // 第二个参数是关联数据（可选）
}

fun decryptWithTink(keysetHandle: KeysetHandle, encryptedData: ByteArray): ByteArray {
    val aead = keysetHandle.getPrimitive(Aead::class.java)
    return aead.decrypt(encryptedData, null)
}

// 生成新的密钥集
fun generateKeysetHandle(): KeysetHandle {
    return KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM)
}

// 保存密钥集到加密的文件
fun saveKeysetHandle(keysetHandle: KeysetHandle, fileName: String) {
    val androidKeysetManager = AndroidKeysetManager.Builder()
        .withSharedPref(context, "tink_keyset", fileName)
        .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
        .withMasterKeyUri("android-keystore://tink_master_key")
        .build()
    
    androidKeysetManager.keysetHandle = keysetHandle
}

// 从加密的文件加载密钥集
fun loadKeysetHandle(fileName: String): KeysetHandle {
    return AndroidKeysetManager.Builder()
        .withSharedPref(context, "tink_keyset", fileName)
        .withKeyTemplate(AeadKeyTemplates.AES256_GCM)
        .withMasterKeyUri("android-keystore://tink_master_key")
        .build()
        .keysetHandle
}
```

## 安全存储

### SharedPreferences加密

默认的SharedPreferences不加密存储数据，可以使用EncryptedSharedPreferences进行加密：

```kotlin
// 创建加密的SharedPreferences
fun createEncryptedSharedPreferences(fileName: String): SharedPreferences {
    val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    
    return EncryptedSharedPreferences.create(
        fileName,
        masterKeyAlias,
        applicationContext,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
}

// 使用加密的SharedPreferences
val encryptedSharedPreferences = createEncryptedSharedPreferences("secure_prefs")

// 存储敏感数据
encryptedSharedPreferences.edit()
    .putString("api_key", "secret_api_key")
    .putString("auth_token", "user_auth_token")
    .apply()

// 读取敏感数据
val apiKey = encryptedSharedPreferences.getString("api_key", null)
val authToken = encryptedSharedPreferences.getString("auth_token", null)
```

### 加密数据库

使用SQLCipher加密SQLite数据库：

```gradle
dependencies {
    implementation "net.zetetic:android-database-sqlcipher:4.5.0"
    implementation "androidx.sqlite:sqlite:2.2.0"
}
```

```kotlin
// 创建加密数据库
fun createEncryptedDatabase(context: Context, name: String, password: String): SQLiteDatabase {
    return SQLiteDatabase.openOrCreateDatabase(
        context.getDatabasePath(name),
        password,
        null,
        null
    )
}

// 使用Room与SQLCipher
@Database(entities = [User::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
    
    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null
        
        fun getDatabase(context: Context, passphrase: ByteArray): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "app_database"
                )
                .openHelperFactory(SupportFactory(passphrase))
                .build()
                INSTANCE = instance
                instance
            }
        }
    }
}

// 使用示例
val passphrase = SQLiteDatabase.getBytes("strong_password".toCharArray())
val database = AppDatabase.getDatabase(context, passphrase)
```

### 安全文件存储

```kotlin
// 使用加密文件存储敏感数据
fun saveEncryptedFile(fileName: String, data: ByteArray) {
    val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    
    val fileEncryptionParams = EncryptedFile.FileEncryptionParams.Builder()
        .setEncryptionScheme(EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
        .build()
    
    val file = File(applicationContext.filesDir, fileName)
    
    val encryptedFile = EncryptedFile.Builder(
        file,
        applicationContext,
        masterKeyAlias,
        fileEncryptionParams
    ).build()
    
    encryptedFile.openFileOutput().use { outputStream ->
        outputStream.write(data)
    }
}

// 读取加密文件
fun readEncryptedFile(fileName: String): ByteArray {
    val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
    
    val fileEncryptionParams = EncryptedFile.FileEncryptionParams.Builder()
        .setEncryptionScheme(EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
        .build()
    
    val file = File(applicationContext.filesDir, fileName)
    
    val encryptedFile = EncryptedFile.Builder(
        file,
        applicationContext,
        masterKeyAlias,
        fileEncryptionParams
    ).build()
    
    return encryptedFile.openFileInput().use { inputStream ->
        inputStream.readBytes()
    }
}
```

## 网络安全

### 配置网络安全

在Android 9 (API 28)及以上版本，应用默认只允许HTTPS连接。可以通过网络安全配置文件自定义网络安全策略：

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- 默认配置 -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <!-- 信任系统证书 -->
            <certificates src="system" />
            <!-- 信任用户证书（仅在调试模式下） -->
            <certificates src="user" debuggable="true" />
        </trust-anchors>
    </base-config>
    
    <!-- 特定域名配置 -->
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set expiration="2022-01-01">
            <!-- 证书固定 -->
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
            <pin digest="SHA-256">fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

在AndroidManifest.xml中引用配置文件：

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
</application>
```

### 证书固定

在OkHttp中实现证书固定：

```kotlin
// 配置OkHttp证书固定
val certificatePinner = CertificatePinner.Builder()
    .add("api.example.com", "sha256/7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=")
    .add("api.example.com", "sha256/fwza0LRMXouZHRC8Ei+4PyuldPDcf3UKgO/04cDM1oE=")
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

### 安全的API通信

```kotlin
// 添加认证拦截器
class AuthInterceptor(private val tokenProvider: () -> String) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        
        val authenticatedRequest = originalRequest.newBuilder()
            .header("Authorization", "Bearer ${tokenProvider()}")
            .build()
        
        return chain.proceed(authenticatedRequest)
    }
}

// 配置安全的Retrofit客户端
val tokenProvider = { secureStorage.getToken() }

val okHttpClient = OkHttpClient.Builder()
    .addInterceptor(AuthInterceptor(tokenProvider))
    .certificatePinner(certificatePinner)
    .build()

val retrofit = Retrofit.Builder()
    .baseUrl("https://api.example.com/")
    .client(okHttpClient)
    .addConverterFactory(GsonConverterFactory.create())
    .build()
```

## 代码保护

### ProGuard/R8混淆

ProGuard/R8是Android构建工具链中的代码压缩、优化和混淆工具。配置混淆规则：

```gradle
// build.gradle
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}
```

在proguard-rules.pro文件中添加规则：

```
# 保留应用程序入口点
-keep class com.example.app.MainActivity { *; }

# 保留所有模型类
-keep class com.example.app.data.model.** { *; }

# 保留Retrofit服务接口
-keep,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}

# 保留自定义View
-keep public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# 保留枚举类
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# 保留序列化相关
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# 保留Parcelable实现
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# 移除日志语句
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}
```

### 防止应用被调试

在AndroidManifest.xml中禁用调试：

```xml
<application
    android:debuggable="false"
    ...>
</application>
```

在代码中检测调试状态：

```kotlin
fun isBeingDebugged(): Boolean {
    return Debug.isDebuggerConnected() || Debug.waitingForDebugger()
}

// 在关键功能中检查调试状态
fun performSensitiveOperation() {
    if (isBeingDebugged() && !BuildConfig.DEBUG) {
        // 可能正在被攻击，采取措施
        return
    }
    
    // 执行敏感操作
}
```

### 防止Root检测

```kotlin
fun isDeviceRooted(): Boolean {
    // 检查常见的Root管理应用
    val rootApps = arrayOf(
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.topjohnwu.magisk"
    )
    
    val packageManager = context.packageManager
    for (app in rootApps) {
        try {
            packageManager.getPackageInfo(app, 0)
            return true
        } catch (e: PackageManager.NameNotFoundException) {
            // 应用未安装，继续检查
        }
    }
    
    // 检查su二进制文件
    val suPaths = arrayOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/system/app/Superuser.apk"
    )
    
    for (path in suPaths) {
        if (File(path).exists()) {
            return true
        }
    }
    
    // 尝试执行su命令
    try {
        Runtime.getRuntime().exec("su")
        return true
    } catch (e: Exception) {
        // 无法执行su命令
    }
    
    return false
}
```

### 防止应用被篡改

```kotlin
fun verifyAppSignature(): Boolean {
    try {
        val packageInfo = packageManager.getPackageInfo(
            packageName,
            PackageManager.GET_SIGNATURES
        )
        
        for (signature in packageInfo.signatures) {
            val signatureBytes = signature.toByteArray()
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(signatureBytes)
            val hexString = digest.joinToString("") { "%02x".format(it) }
            
            // 检查签名是否匹配预期值
            val expectedSignature = "your_app_signature_hash_here"
            return hexString == expectedSignature
        }
    } catch (e: Exception) {
        // 处理异常
    }
    
    return false
}
```

## 用户认证与授权

### 生物识别认证

使用BiometricPrompt进行生物识别认证：

```kotlin
// 创建生物识别提示
fun showBiometricPrompt(
    onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    onError: (Int, CharSequence) -> Unit
) {
    val executor = ContextCompat.getMainExecutor(this)
    
    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            onSuccess(result)
        }
        
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            onError(errorCode, errString)
        }
    }
    
    val biometricPrompt = BiometricPrompt(this, executor, callback)
    
    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("生物识别登录")
        .setSubtitle("使用您的指纹解锁应用")
        .setNegativeButtonText("取消")
        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()
    
    biometricPrompt.authenticate(promptInfo)
}

// 使用生物识别解密数据
fun decryptWithBiometric(
    encryptedData: ByteArray,
    initializationVector: ByteArray,
    cryptoObject: BiometricPrompt.CryptoObject
): ByteArray {
    val cipher = cryptoObject.cipher ?: throw IllegalStateException("Cipher is null")
    return cipher.doFinal(encryptedData)
}
```

### 安全的密码存储

使用安全的哈希算法存储密码：

```kotlin
// 使用BCrypt哈希密码
fun hashPassword(password: String): String {
    return BCrypt.hashpw(password, BCrypt.gensalt())
}

// 验证密码
fun verifyPassword(password: String, hashedPassword: String): Boolean {
    return BCrypt.checkpw(password, hashedPassword)
}
```

## 安全编码实践

### 输入验证

```kotlin
// 验证用户输入
fun validateUserInput(input: String): Boolean {
    // 检查长度
    if (input.length < 3 || input.length > 50) {
        return false
    }
    
    // 检查是否包含特殊字符
    val pattern = Pattern.compile("[A-Za-z0-9_]+")
    val matcher = pattern.matcher(input)
    
    return matcher.matches()
}

// 防止SQL注入
fun safeQueryUser(username: String): User? {
    // 使用参数化查询
    val query = "SELECT * FROM users WHERE username = ?"
    val cursor = database.rawQuery(query, arrayOf(username))
    
    // 处理结果
    // ...
    
    return user
}
```

### 敏感数据处理

```kotlin
// 使用SecureString存储敏感字符串
class SecureString(private val value: CharArray) : AutoCloseable {
    fun access(): CharArray {
        return value.clone()
    }
    
    override fun close() {
        // 清除内存中的敏感数据
        for (i in value.indices) {
            value[i] = '\u0000'
        }
    }
}

// 使用示例
fun processPassword() {
    SecureString("sensitive_password".toCharArray()).use { securePassword ->
        val password = securePassword.access()
        // 使用密码
        // ...
        // 使用完毕后清除
        password.fill('\u0000')
    }
    // 离开作用域后，securePassword会自动清除
}
```

## 安全审计与测试

### 使用安全扫描工具

1. **MobSF (Mobile Security Framework)**：开源的移动应用安全测试框架
2. **OWASP ZAP**：开源的Web应用安全扫描器
3. **Android Lint**：检测代码中的安全问题

### 安全测试清单

1. **静态分析**：
   - 检查代码中的安全漏洞
   - 审查敏感数据处理方式
   - 验证加密算法的正确使用

2. **动态分析**：
   - 使用代理工具监控网络通信
   - 检查运行时的数据存储安全性
   - 测试认证和授权机制

3. **渗透测试**：
   - 尝试绕过认证机制
   - 测试输入验证和注入攻击
   - 检查会话管理安全性

## 常见安全问题与解决方案

### 不安全的数据存储

**问题**：在设备上以明文形式存储敏感数据。

**解决方案**：
- 使用EncryptedSharedPreferences存储小型敏感数据
- 使用SQLCipher加密数据库
- 使用EncryptedFile加密文件
- 不要在日志中记录敏感信息

### 不安全的通信

**问题**：使用HTTP而非HTTPS，或未正确验证服务器证书。

**解决方案**：
- 强制使用HTTPS
- 实施证书固定
- 配置网络安全策略

### 不足的认证和授权

**问题**：弱密码策略，会话管理不当。

**解决方案**：
- 实施强密码策略
- 使用安全的会话管理
- 实施多因素认证
- 使用OAuth 2.0等标准协议

### 代码注入

**问题**：SQL注入、命令注入等。

**解决方案**：
- 使用参数化查询
- 验证和清理所有用户输入
- 避免动态SQL和命令执行

## 总结

Android应用安全是一个多层面的挑战，需要从数据存储、网络通信、代码保护、用户认证等多个方面入手。通过遵循本文档中的最佳实践，开发者可以显著提高应用的安全性，保护用户数据和隐私。

记住，安全不是一次性的工作，而是一个持续的过程。随着新威胁的出现和Android平台的演进，应用的安全措施也需要不断更新和加强。

## 相关资源

- [Android安全最佳实践](https://developer.android.com/topic/security/best-practices)
- [Android密钥库系统](https://developer.android.com/training/articles/keystore)
- [Android网络安全配置](https://developer.android.com/training/articles/security-config)
- [OWASP移动安全测试指南](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android应用安全检查表](https://github.com/OWASP/owasp-mstg/tree/master/Checklists)
