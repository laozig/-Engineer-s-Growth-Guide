# Android UI开发基础

Android应用的用户界面由视图和布局组成。本文档将介绍Android UI开发的基础知识，包括常用布局、视图组件、资源管理和样式主题等。

## 视图层次结构

Android UI由View和ViewGroup对象组成，形成树状层次结构：

- **View**：UI的基本构建块，如按钮、文本框等
- **ViewGroup**：容器，用于存放其他View或ViewGroup，如布局容器

## 常用布局类型

Android提供了多种布局容器，用于组织UI元素：

### LinearLayout

线性布局按水平或垂直方向依次排列子视图：

```xml
<LinearLayout
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:orientation="vertical">
    
    <TextView
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:text="标题" />
        
    <Button
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="按钮" />
        
</LinearLayout>
```

关键属性：
- `android:orientation`：`horizontal`(水平)或`vertical`(垂直)
- `android:gravity`：子视图在布局内的对齐方式
- `android:layout_weight`：子视图占用剩余空间的比例

### RelativeLayout

相对布局允许子视图相对于父布局或其他子视图定位：

```xml
<RelativeLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent">
    
    <TextView
        android:id="@+id/title"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_centerHorizontal="true"
        android:text="标题" />
        
    <Button
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_below="@id/title"
        android:layout_alignParentRight="true"
        android:text="按钮" />
        
</RelativeLayout>
```

关键属性：
- `android:layout_alignParentXxx`：相对于父布局的位置
- `android:layout_toLeftOf`、`android:layout_below`等：相对于其他视图的位置
- `android:layout_centerInParent`：在父布局中居中

### ConstraintLayout

约束布局是一个更灵活的布局，是现代Android应用的推荐布局：

```xml
<androidx.constraintlayout.widget.ConstraintLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent">
    
    <TextView
        android:id="@+id/title"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        android:text="标题" />
        
    <Button
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        app:layout_constraintTop_toBottomOf="@id/title"
        app:layout_constraintEnd_toEndOf="parent"
        android:text="按钮" />
        
</androidx.constraintlayout.widget.ConstraintLayout>
```

关键属性：
- `app:layout_constraintXxx_toYyyOf`：设置约束关系
- `app:layout_constraintHorizontal_bias`：水平偏移比例
- `app:layout_constraintDimensionRatio`：设置宽高比

## 常用UI组件

### TextView

显示文本：

```xml
<TextView
    android:id="@+id/text_view"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="Hello World"
    android:textSize="18sp"
    android:textColor="#000000"
    android:textStyle="bold"
    android:ellipsize="end"
    android:maxLines="2" />
```

### Button

按钮控件：

```xml
<Button
    android:id="@+id/button"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:text="点击"
    android:onClick="onButtonClick" />
```

在Activity中处理点击事件：

```kotlin
fun onButtonClick(view: View) {
    // 处理点击事件
    Toast.makeText(this, "按钮被点击", Toast.LENGTH_SHORT).show()
}
```

### EditText

输入框：

```xml
<EditText
    android:id="@+id/edit_text"
    android:layout_width="match_parent"
    android:layout_height="wrap_content"
    android:hint="请输入文本"
    android:inputType="text" />
```

常用的inputType值：
- `text`：普通文本
- `textPassword`：密码
- `number`：数字
- `phone`：电话号码
- `textEmailAddress`：电子邮件

### ImageView

显示图像：

```xml
<ImageView
    android:id="@+id/image_view"
    android:layout_width="200dp"
    android:layout_height="200dp"
    android:src="@drawable/image"
    android:scaleType="centerCrop"
    android:contentDescription="图片描述" />
```

## 资源管理

Android使用资源系统管理应用的非代码资源，如布局、字符串、图像等。

### 资源目录结构

资源通常位于`app/src/main/res/`目录下：

- `drawable/`：图像资源
- `layout/`：布局文件
- `values/`：值资源（字符串、颜色、尺寸等）
- `mipmap/`：应用图标
- `raw/`：原始文件

### 资源限定符

可以使用限定符为不同配置提供备用资源：

- 语言：`values-zh/`（中文）
- 屏幕尺寸：`layout-large/`（大屏幕）
- 屏幕方向：`layout-land/`（横屏）
- 像素密度：`drawable-hdpi/`（高密度屏幕）

### 访问资源

在XML中访问资源：

```xml
<!-- 引用字符串资源 -->
<TextView
    android:text="@string/app_name" />
    
<!-- 引用颜色资源 -->
<View
    android:background="@color/colorPrimary" />
```

在代码中访问资源：

```kotlin
// 获取字符串
val appName = getString(R.string.app_name)

// 获取颜色
val color = ContextCompat.getColor(this, R.color.colorPrimary)
```

## 样式和主题

样式是应用于单个View的属性集合，而主题是应用于整个Activity或应用的样式：

```xml
<!-- styles.xml -->
<resources>
    <!-- 基础应用主题 -->
    <style name="AppTheme" parent="Theme.MaterialComponents.Light.DarkActionBar">
        <item name="colorPrimary">@color/colorPrimary</item>
        <item name="colorPrimaryDark">@color/colorPrimaryDark</item>
        <item name="colorAccent">@color/colorAccent</item>
    </style>
    
    <!-- 文本样式 -->
    <style name="TextStyle">
        <item name="android:textColor">@color/textColorPrimary</item>
        <item name="android:textSize">16sp</item>
    </style>
</resources>
```

## 总结

本文档介绍了Android UI开发的基础知识，包括布局类型、常用UI组件、资源管理和样式主题。掌握这些基础知识对于构建高质量的Android应用界面至关重要。

## 下一步学习

- [Material Design实现](material-design.md)
- [数据存储与访问](data-storage.md)
