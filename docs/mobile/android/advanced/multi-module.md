# 多模块架构

随着应用功能的增多和团队规模的扩大，单体应用（所有代码都在一个`app`模块中）会变得越来越难以维护。多模块架构是将一个应用拆分成多个独立的、可独立构建的模块的实践。

## 1. 为什么使用多模块架构？

- **更快的构建速度**：Gradle可以并行构建未改动的模块，并缓存构建结果，从而显著减少增量构建时间。
- **强制关注点分离**：清晰的模块边界强制实现了代码的逻辑分离，提高了代码的可读性和可维护性。
- **改善代码所有权**：可以为不同的团队分配不同功能模块的所有权，减少代码冲突。
- **促进代码复用**：通用的功能（如网络、数据库、UI组件）可以被封装在独立的库模块中，被其他功能模块复用。
- **启用动态交付**：多模块是实现Play Feature Delivery（动态功能模块）的基础。

## 2. 模块划分策略

如何划分模块是实施多模块架构的关键。常见的策略有两种：

### 按层划分 (Layer-based)

这种策略将应用按架构分层（如`ui`, `domain`, `data`）来创建模块。

```
:app (应用主模块, 整合所有模块)
|
+--- :feature_a (功能A的UI层)
|
+--- :feature_b (功能B的UI层)
|
+--- :domain (包含业务逻辑/用例)
|
+--- :data (包含数据仓库、网络和数据库)
```

**优点**：严格遵循分层架构。
**缺点**：不同功能模块之间的界限可能变得模糊，可能导致高耦合。

### 按功能划分 (Feature-based)

这种策略将每个独立的功能封装成一个模块。这是目前更推荐的方式。

```
:app
|
+--- :feature_a (包含功能A的UI, ViewModel, 和相关逻辑)
|       |
|       +--- :core:ui
|       |
|       +--- :core:data
|
+--- :feature_b (包含功能B的UI, ViewModel, 和相关逻辑)
|       |
|       +--- :core:ui
|       |
|       +--- :core:data
|
+--- :core:ui (通用的UI组件, 主题, 资源)
|
+--- :core:data (数据层, 仓库, API, 数据库)
|
+--- :core:common (通用工具类, 扩展函数等)
```

**优点**：
- **高内聚，低耦合**：每个功能模块都是自包含的。
- **可扩展性强**：添加新功能只需创建一个新模块。
- **适合动态交付**。

## 3. 模块类型

- **`com.android.application` (`:app`)**: 应用的主入口模块，通常只包含用于整合其他模块的代码。
- **`com.android.library` (`:feature_x`, `:core_x`)**: Android库模块，可以包含代码和资源。大多数模块都应该是这种类型。
- **`org.jetbrains.kotlin.jvm`**: 纯Kotlin/Java模块，不依赖Android SDK。非常适合放置`domain`层或纯粹的业务逻辑。

## 4. 模块间的依赖关系

模块间的依赖关系应该是单向的。一个常见的规则是：

**功能模块 (`:feature`) 应该依赖核心模块 (`:core`)，但核心模块不应该知道任何关于功能模块的信息。功能模块之间通常不直接相互依赖。**

```groovy
// :feature_a/build.gradle
dependencies {
    // 依赖app模块会造成循环依赖，是错误的
    // implementation project(':app') // 错误！

    // 正确的依赖关系
    implementation project(':core:ui')
    implementation project(':core:data')
}

// :app/build.gradle
dependencies {
    implementation project(':feature_a')
    implementation project(':feature_b')
}
```

## 5. 管理Gradle脚本

在多模块项目中，管理大量的`build.gradle`文件会变得很麻烦。可以使用以下技巧来简化：
- **Convention Plugins**: 创建自定义的Gradle插件来共享构建配置（如Android通用配置、依赖版本等）。
- **版本目录 (`libs.versions.toml`)**: 使用Gradle的Version Catalog功能来集中管理所有依赖库及其版本。

### `libs.versions.toml` 示例

```toml
# libs.versions.toml
[versions]
kotlin = "1.8.0"
appcompat = "1.6.1"

[libraries]
kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
appcompat = { module = "androidx.appcompat:appcompat", version.ref = "appcompat" }

[bundles]
android-ui = ["appcompat", ...]
```

在`build.gradle`中使用：
```groovy
dependencies {
    implementation libs.kotlin.stdlib
    implementation libs.appcompat
}
```

## 结论

多模块架构是构建大型、可维护Android应用的基石。通过按功能划分模块，并建立清晰的依赖规则，可以显著提高开发效率和应用质量。虽然初期设置会增加一些复杂性，但长远来看，其带来的好处是巨大的。 