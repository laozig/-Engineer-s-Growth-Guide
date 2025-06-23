# Material Design实现

Material Design是Google推出的设计语言，旨在为Android、iOS、Web等平台提供一致的用户体验。本文档将介绍如何在Android应用中实现Material Design。

## 配置Material Design

### 添加依赖

在app级build.gradle文件中添加Material Components依赖：

```gradle
dependencies {
    implementation 'com.google.android.material:material:1.9.0'
}
```

### 应用Material主题

在res/values/themes.xml文件中应用Material主题：

```xml
<resources>
    <!-- 基础应用主题 -->
    <style name="Theme.MyApp" parent="Theme.MaterialComponents.DayNight.DarkActionBar">
        <!-- 主要品牌颜色 -->
        <item name="colorPrimary">@color/primary</item>
        <!-- 深色的主要品牌颜色，用于状态栏等 -->
        <item name="colorPrimaryDark">@color/primary_dark</item>
        <!-- 强调色，用于控件的选中状态等 -->
        <item name="colorAccent">@color/accent</item>
        <!-- 次要品牌颜色 -->
        <item name="colorSecondary">@color/secondary</item>
        <!-- 表面颜色，如卡片、对话框等 -->
        <item name="colorSurface">@color/surface</item>
        <!-- 背景颜色 -->
        <item name="android:colorBackground">@color/background</item>
        <!-- 错误颜色 -->
        <item name="colorError">@color/error</item>
        
        <!-- 文字颜色 -->
        <item name="android:textColorPrimary">@color/text_primary</item>
        <item name="android:textColorSecondary">@color/text_secondary</item>
        
        <!-- 形状样式 -->
        <item name="shapeAppearanceSmallComponent">@style/ShapeAppearance.MyApp.SmallComponent</item>
        <item name="shapeAppearanceMediumComponent">@style/ShapeAppearance.MyApp.MediumComponent</item>
        <item name="shapeAppearanceLargeComponent">@style/ShapeAppearance.MyApp.LargeComponent</item>
    </style>
    
    <!-- 无ActionBar的主题 -->
    <style name="Theme.MyApp.NoActionBar">
        <item name="windowActionBar">false</item>
        <item name="windowNoTitle">true</item>
    </style>
</resources>
```

在res/values/colors.xml中定义颜色：

```xml
<resources>
    <color name="primary">#6200EE</color>
    <color name="primary_dark">#3700B3</color>
    <color name="accent">#03DAC5</color>
    <color name="secondary">#03DAC6</color>
    <color name="background">#FFFFFF</color>
    <color name="surface">#FFFFFF</color>
    <color name="error">#B00020</color>
    <color name="text_primary">#DE000000</color> <!-- 87% 黑色 -->
    <color name="text_secondary">#99000000</color> <!-- 60% 黑色 -->
</resources>
```

在res/values/shape.xml中定义形状样式：

```xml
<resources>
    <!-- 小组件形状样式（如按钮） -->
    <style name="ShapeAppearance.MyApp.SmallComponent" parent="ShapeAppearance.MaterialComponents.SmallComponent">
        <item name="cornerFamily">rounded</item>
        <item name="cornerSize">4dp</item>
    </style>
    
    <!-- 中等组件形状样式（如卡片） -->
    <style name="ShapeAppearance.MyApp.MediumComponent" parent="ShapeAppearance.MaterialComponents.MediumComponent">
        <item name="cornerFamily">rounded</item>
        <item name="cornerSize">8dp</item>
    </style>
    
    <!-- 大组件形状样式（如底部表单） -->
    <style name="ShapeAppearance.MyApp.LargeComponent" parent="ShapeAppearance.MaterialComponents.LargeComponent">
        <item name="cornerFamily">rounded</item>
        <item name="cornerSize">12dp</item>
    </style>
</resources>
```

## Material组件

### AppBar和Toolbar

AppBar（顶部应用栏）是应用的主要标识符：

```xml
<androidx.coordinatorlayout.widget.CoordinatorLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <com.google.android.material.appbar.AppBarLayout
        android:layout_width="match_parent"
        android:layout_height="wrap_content">

        <androidx.appcompat.widget.Toolbar
            android:id="@+id/toolbar"
            android:layout_width="match_parent"
            android:layout_height="?attr/actionBarSize"
            app:title="应用标题"
            app:subtitle="副标题"
            app:menu="@menu/top_app_bar" />

    </com.google.android.material.appbar.AppBarLayout>

    <!-- 主要内容 -->
    <androidx.core.widget.NestedScrollView
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        app:layout_behavior="@string/appbar_scrolling_view_behavior">
        
        <!-- 内容 -->
        
    </androidx.core.widget.NestedScrollView>

</androidx.coordinatorlayout.widget.CoordinatorLayout>
```

在Activity中设置Toolbar：

```kotlin
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    
    val toolbar = findViewById<Toolbar>(R.id.toolbar)
    setSupportActionBar(toolbar)
}
```

### 可折叠的AppBar

```xml
<androidx.coordinatorlayout.widget.CoordinatorLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <com.google.android.material.appbar.AppBarLayout
        android:layout_width="match_parent"
        android:layout_height="180dp">

        <com.google.android.material.appbar.CollapsingToolbarLayout
            android:layout_width="match_parent"
            android:layout_height="match_parent"
            app:title="可折叠标题"
            app:expandedTitleMarginStart="16dp"
            app:expandedTitleMarginBottom="16dp"
            app:contentScrim="?attr/colorPrimary"
            app:layout_scrollFlags="scroll|exitUntilCollapsed">

            <ImageView
                android:layout_width="match_parent"
                android:layout_height="match_parent"
                android:src="@drawable/header_image"
                android:scaleType="centerCrop"
                app:layout_collapseMode="parallax" />

            <androidx.appcompat.widget.Toolbar
                android:id="@+id/toolbar"
                android:layout_width="match_parent"
                android:layout_height="?attr/actionBarSize"
                app:layout_collapseMode="pin" />

        </com.google.android.material.appbar.CollapsingToolbarLayout>

    </com.google.android.material.appbar.AppBarLayout>

    <androidx.core.widget.NestedScrollView
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        app:layout_behavior="@string/appbar_scrolling_view_behavior">
        
        <!-- 内容 -->
        
    </androidx.core.widget.NestedScrollView>

</androidx.coordinatorlayout.widget.CoordinatorLayout>
```

### 底部导航栏

```xml
<androidx.coordinatorlayout.widget.CoordinatorLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <!-- 主要内容 -->
    <androidx.fragment.app.FragmentContainerView
        android:id="@+id/nav_host_fragment"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        app:layout_behavior="@string/appbar_scrolling_view_behavior" />

    <com.google.android.material.bottomnavigation.BottomNavigationView
        android:id="@+id/bottom_navigation"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:layout_gravity="bottom"
        app:menu="@menu/bottom_navigation_menu" />

</androidx.coordinatorlayout.widget.CoordinatorLayout>
```

menu/bottom_navigation_menu.xml：

```xml
<menu xmlns:android="http://schemas.android.com/apk/res/android">
    <item
        android:id="@+id/page_1"
        android:enabled="true"
        android:icon="@drawable/ic_home"
        android:title="首页"/>
    <item
        android:id="@+id/page_2"
        android:enabled="true"
        android:icon="@drawable/ic_search"
        android:title="搜索"/>
    <item
        android:id="@+id/page_3"
        android:enabled="true"
        android:icon="@drawable/ic_notifications"
        android:title="通知"/>
    <item
        android:id="@+id/page_4"
        android:enabled="true"
        android:icon="@drawable/ic_account"
        android:title="我的"/>
</menu>
```

在Activity中设置底部导航：

```kotlin
val bottomNavigation = findViewById<BottomNavigationView>(R.id.bottom_navigation)
bottomNavigation.setOnItemSelectedListener { item ->
    when(item.itemId) {
        R.id.page_1 -> {
            // 导航到首页
            true
        }
        R.id.page_2 -> {
            // 导航到搜索页
            true
        }
        R.id.page_3 -> {
            // 导航到通知页
            true
        }
        R.id.page_4 -> {
            // 导航到个人页
            true
        }
        else -> false
    }
}
```

### 浮动操作按钮(FAB)

```xml
<androidx.coordinatorlayout.widget.CoordinatorLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <!-- 主要内容 -->

    <com.google.android.material.floatingactionbutton.FloatingActionButton
        android:id="@+id/fab"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="bottom|end"
        android:layout_margin="16dp"
        android:contentDescription="添加"
        app:srcCompat="@drawable/ic_add" />

</androidx.coordinatorlayout.widget.CoordinatorLayout>
```

在Activity中设置FAB点击事件：

```kotlin
val fab = findViewById<FloatingActionButton>(R.id.fab)
fab.setOnClickListener {
    // 处理点击事件
    Snackbar.make(it, "添加新项目", Snackbar.LENGTH_SHORT).show()
}
```

### 卡片视图

```xml
<com.google.android.material.card.MaterialCardView
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:layout_margin="8dp"
    app:cardElevation="4dp"
    app:cardCornerRadius="8dp">

    <LinearLayout
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:orientation="vertical"
        android:padding="16dp">

        <TextView
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:text="卡片标题"
            android:textAppearance="?attr/textAppearanceHeadline6" />

        <TextView
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:layout_marginTop="8dp"
            android:text="卡片内容描述，可以包含多行文本。"
            android:textAppearance="?attr/textAppearanceBody2" />

        <LinearLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:layout_marginTop="16dp"
            android:orientation="horizontal">

            <com.google.android.material.button.MaterialButton
                style="?attr/borderlessButtonStyle"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="操作1" />

            <com.google.android.material.button.MaterialButton
                style="?attr/borderlessButtonStyle"
                android:layout_width="wrap_content"
                android:layout_height="wrap_content"
                android:text="操作2" />

        </LinearLayout>

    </LinearLayout>

</com.google.android.material.card.MaterialCardView>
```

### 文本输入框

```xml
<com.google.android.material.textfield.TextInputLayout
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:hint="用户名"
    style="@style/Widget.MaterialComponents.TextInputLayout.OutlinedBox">

    <com.google.android.material.textfield.TextInputEditText
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />

</com.google.android.material.textfield.TextInputLayout>

<com.google.android.material.textfield.TextInputLayout
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:layout_marginTop="8dp"
    android:hint="密码"
    app:endIconMode="password_toggle"
    style="@style/Widget.MaterialComponents.TextInputLayout.OutlinedBox">

    <com.google.android.material.textfield.TextInputEditText
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:inputType="textPassword" />

</com.google.android.material.textfield.TextInputLayout>
```

### 按钮

```xml
<!-- 填充按钮（主要操作） -->
<com.google.android.material.button.MaterialButton
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="确认" />

<!-- 轮廓按钮（次要操作） -->
<com.google.android.material.button.MaterialButton
    style="@style/Widget.MaterialComponents.Button.OutlinedButton"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="取消" />

<!-- 文本按钮（次要操作） -->
<com.google.android.material.button.MaterialButton
    style="@style/Widget.MaterialComponents.Button.TextButton"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="跳过" />

<!-- 图标按钮 -->
<com.google.android.material.button.MaterialButton
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="收藏"
    app:icon="@drawable/ic_favorite"
    app:iconGravity="start" />
```

### 选择控件

```xml
<!-- 复选框 -->
<com.google.android.material.checkbox.MaterialCheckBox
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="同意条款" />

<!-- 单选按钮 -->
<com.google.android.material.radiobutton.MaterialRadioButton
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="选项1" />

<!-- 开关 -->
<com.google.android.material.switchmaterial.SwitchMaterial
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="开启通知" />
```

### 滑块

```xml
<com.google.android.material.slider.Slider
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:valueFrom="0.0"
    android:valueTo="100.0"
    android:stepSize="1.0"
    android:value="50.0" />
```

### 标签

```xml
<com.google.android.material.chip.ChipGroup
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    app:singleSelection="true">

    <com.google.android.material.chip.Chip
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="标签1"
        style="@style/Widget.MaterialComponents.Chip.Choice" />

    <com.google.android.material.chip.Chip
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="标签2"
        style="@style/Widget.MaterialComponents.Chip.Choice" />

    <com.google.android.material.chip.Chip
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="标签3"
        style="@style/Widget.MaterialComponents.Chip.Choice" />

</com.google.android.material.chip.ChipGroup>
```

### 底部表单

```xml
<androidx.coordinatorlayout.widget.CoordinatorLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <!-- 主要内容 -->

    <com.google.android.material.bottomsheet.BottomSheetBehavior
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        app:behavior_peekHeight="56dp"
        app:behavior_hideable="false">

        <LinearLayout
            android:layout_width="match_parent"
            android:layout_height="wrap_content"
            android:orientation="vertical"
            android:background="@color/surface">

            <TextView
                android:layout_width="match_parent"
                android:layout_height="56dp"
                android:gravity="center_vertical"
                android:paddingStart="16dp"
                android:paddingEnd="16dp"
                android:text="底部表单标题"
                android:textAppearance="?attr/textAppearanceHeadline6" />

            <!-- 底部表单内容 -->
            <LinearLayout
                android:layout_width="match_parent"
                android:layout_height="wrap_content"
                android:orientation="vertical"
                android:padding="16dp">

                <!-- 内容 -->

            </LinearLayout>

        </LinearLayout>

    </com.google.android.material.bottomsheet.BottomSheetBehavior>

</androidx.coordinatorlayout.widget.CoordinatorLayout>
```

### 对话框

```kotlin
MaterialAlertDialogBuilder(context)
    .setTitle("对话框标题")
    .setMessage("这是一个Material Design风格的对话框。")
    .setPositiveButton("确定") { dialog, which ->
        // 确定按钮点击处理
    }
    .setNegativeButton("取消") { dialog, which ->
        // 取消按钮点击处理
    }
    .show()
```

### 菜单

```xml
<com.google.android.material.navigation.NavigationView
    android:id="@+id/nav_view"
    android:layout_width="wrap_content"
    android:layout_height="match_parent"
    android:layout_gravity="start"
    app:headerLayout="@layout/nav_header"
    app:menu="@menu/drawer_menu" />
```

menu/drawer_menu.xml：

```xml
<menu xmlns:android="http://schemas.android.com/apk/res/android">
    <group android:checkableBehavior="single">
        <item
            android:id="@+id/nav_home"
            android:icon="@drawable/ic_home"
            android:title="首页" />
        <item
            android:id="@+id/nav_gallery"
            android:icon="@drawable/ic_gallery"
            android:title="相册" />
        <item
            android:id="@+id/nav_settings"
            android:icon="@drawable/ic_settings"
            android:title="设置" />
    </group>
    <item android:title="其他">
        <menu>
            <item
                android:id="@+id/nav_share"
                android:icon="@drawable/ic_share"
                android:title="分享" />
            <item
                android:id="@+id/nav_feedback"
                android:icon="@drawable/ic_feedback"
                android:title="反馈" />
        </menu>
    </item>
</menu>
```

## 动画与过渡

### 共享元素过渡

在Activity A中：

```kotlin
val intent = Intent(this, DetailActivity::class.java)
val options = ActivityOptionsCompat.makeSceneTransitionAnimation(
    this,
    imageView,
    "shared_image"
)
startActivity(intent, options.toBundle())
```

在Activity B中：

```xml
<ImageView
    android:id="@+id/detail_image"
    android:layout_width="match_parent"
    android:layout_height="300dp"
    android:transitionName="shared_image" />
```

### Material Motion

添加依赖：

```gradle
dependencies {
    implementation 'com.google.android.material:material:1.9.0'
}
```

在主题中启用过渡：

```xml
<style name="Theme.MyApp" parent="Theme.MaterialComponents.DayNight.DarkActionBar">
    <!-- 启用内容过渡 -->
    <item name="android:windowActivityTransitions">true</item>
    <item name="android:windowEnterTransition">@transition/explode</item>
    <item name="android:windowExitTransition">@transition/explode</item>
</style>
```

创建过渡资源：

```xml
<!-- res/transition/explode.xml -->
<explode xmlns:android="http://schemas.android.com/apk/res/android"
    android:duration="300" />
```

## 深色主题

在res/values-night/themes.xml中定义深色主题：

```xml
<resources>
    <style name="Theme.MyApp" parent="Theme.MaterialComponents.DayNight.DarkActionBar">
        <item name="colorPrimary">@color/primary_dark_theme</item>
        <item name="colorPrimaryDark">@color/primary_dark_dark_theme</item>
        <item name="colorAccent">@color/accent_dark_theme</item>
        <item name="colorSecondary">@color/secondary_dark_theme</item>
        <item name="colorSurface">@color/surface_dark_theme</item>
        <item name="android:colorBackground">@color/background_dark_theme</item>
        <item name="colorError">@color/error_dark_theme</item>
        
        <item name="android:textColorPrimary">@color/text_primary_dark_theme</item>
        <item name="android:textColorSecondary">@color/text_secondary_dark_theme</item>
    </style>
</resources>
```

在res/values-night/colors.xml中定义深色主题颜色：

```xml
<resources>
    <color name="primary_dark_theme">#BB86FC</color>
    <color name="primary_dark_dark_theme">#9965F4</color>
    <color name="accent_dark_theme">#03DAC6</color>
    <color name="secondary_dark_theme">#03DAC6</color>
    <color name="background_dark_theme">#121212</color>
    <color name="surface_dark_theme">#121212</color>
    <color name="error_dark_theme">#CF6679</color>
    <color name="text_primary_dark_theme">#DEFFFFFF</color> <!-- 87% 白色 -->
    <color name="text_secondary_dark_theme">#99FFFFFF</color> <!-- 60% 白色 -->
</resources>
```

## 最佳实践

1. **一致性**：在整个应用中保持一致的设计语言
2. **响应性**：提供即时的视觉反馈
3. **层次感**：使用阴影和高度来表示UI元素的层次关系
4. **有意义的动画**：使用动画来引导用户注意力和理解界面变化
5. **适应不同屏幕**：确保UI在不同尺寸的设备上都能良好显示
6. **深色主题支持**：提供深色主题以减少电池消耗和眼睛疲劳
7. **可访问性**：确保应用对所有用户都可用，包括有视觉、听觉或运动障碍的用户

## 总结

本文档介绍了如何在Android应用中实现Material Design，包括主题配置、常用组件、动画过渡和深色主题支持。通过遵循Material Design指南，可以创建具有一致性、美观且用户友好的应用界面。

## 下一步学习

- [数据存储与访问](data-storage.md)
- [网络编程](networking.md)
- [Jetpack组件](jetpack.md)
