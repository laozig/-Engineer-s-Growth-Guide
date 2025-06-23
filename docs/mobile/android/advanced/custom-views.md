# 创建自定义视图 (Custom Views)

在Android开发中，自定义视图允许你创建完全符合应用需求的UI组件。本指南将介绍如何创建自定义视图，包括绘制、尺寸测量和处理用户交互。

## 1. 为什么需要自定义视图？

- **性能优化**：将多个标准视图组合成一个复杂的视图，可以减少视图层级，提高渲染性能。
- **独特的UI/UX**：实现标准SDK未提供的独特视觉效果和交互行为。
- **代码复用**：将通用UI模式封装成可重用的组件。

## 2. 创建自定义视图的步骤

创建一个自定义视图通常涉及以下步骤：

1.  **继承`View`类**：创建一个新类，继承自`android.view.View`或其子类（如`TextView`, `ImageView`）。
2.  **定义自定义属性**：在`attrs.xml`中为你的视图定义可以在XML布局中使用的属性。
3.  **获取属性**：在视图的构造函数中，读取在XML中设置的属性值。
4.  **测量尺寸 (`onMeasure`)**：确定视图及其内容的大小。
5.  **布局 (`onLayout`)**：为视图中的每个子视图（如果是一个ViewGroup）分配大小和位置。
6.  **绘制视图 (`onDraw`)**：使用`Canvas`和`Paint`对象在屏幕上绘制视图。
7.  **处理用户交互**：重写`onTouchEvent`等方法来响应用户输入。

## 3. 示例：创建一个简单的圆形视图

下面我们来创建一个名为`CircleView`的自定义视图，它会绘制一个带可配置颜色的实心圆。

### 步骤 1: 继承`View`并添加构造函数

```kotlin
// CircleView.kt
class CircleView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private var circleColor = Color.RED

    // ... 后续步骤在这里添加 ...
}
```
*   `@JvmOverloads`注解让Kotlin编译器生成重载的构造函数，这样在Java和XML中都可以方便地使用。

### 步骤 2: 定义自定义属性

在`res/values/attrs.xml`文件中定义`circleColor`属性。

```xml
<!-- res/values/attrs.xml -->
<resources>
    <declare-styleable name="CircleView">
        <attr name="circleColor" format="color" />
    </declare-styleable>
</resources>
```

### 步骤 3: 在构造函数中获取属性

使用`obtainStyledAttributes`来获取XML布局中设置的属性值。

```kotlin
// 在CircleView的构造函数下方添加init块
init {
    attrs?.let {
        val typedArray = context.obtainStyledAttributes(it, R.styleable.CircleView, 0, 0)
        circleColor = typedArray.getColor(R.styleable.CircleView_circleColor, Color.RED)
        typedArray.recycle() // 回收TypedArray以供重用
    }
    paint.color = circleColor
}
```

### 步骤 4: 测量尺寸 (`onMeasure`)

`onMeasure`方法决定了视图的大小。你需要根据父视图提供的约束来计算期望的尺寸。

```kotlin
override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
    // 简单起见，我们取建议的最小宽度和高度中的较小值作为直径
    val desiredWidth = suggestedMinimumWidth + paddingLeft + paddingRight
    val desiredHeight = suggestedMinimumHeight + paddingTop + paddingBottom
    
    val size = 200 // 默认大小
    val width = resolveSize(size, widthMeasureSpec)
    val height = resolveSize(size, heightMeasureSpec)
    
    setMeasuredDimension(width, height)
}
```
* `resolveSize()`是一个辅助方法，它会根据`MeasureSpec`返回一个合适的尺寸。

### 步骤 5: 绘制视图 (`onDraw`)

`onDraw`方法负责实际的绘制工作。

```kotlin
override fun onDraw(canvas: Canvas) {
    super.onDraw(canvas)

    // 获取视图的中心点和半径
    val cx = width / 2f
    val cy = height / 2f
    val radius = (min(width, height) / 2f) - (paint.strokeWidth / 2)
    
    // 绘制圆形
    canvas.drawCircle(cx, cy, radius, paint)
}
```

### 步骤 6: 在XML布局中使用

现在你可以在XML布局文件中像使用标准视图一样使用`CircleView`。

```xml
<!-- activity_main.xml -->
<com.example.myapp.CircleView
    android:layout_width="100dp"
    android:layout_height="100dp"
    app:circleColor="@color/blue" />
```
* 确保在根布局中添加`xmlns:app="http://schemas.android.com/apk/res-auto"`。

## 4. 处理用户交互

要让自定义视图响应触摸事件，可以重写`onTouchEvent`方法。

```kotlin
override fun onTouchEvent(event: MotionEvent): Boolean {
    return when (event.action) {
        MotionEvent.ACTION_DOWN -> {
            // 用户按下时，改变颜色
            paint.color = if (paint.color == circleColor) Color.GREEN else circleColor
            invalidate() // 请求重绘视图
            true // 返回true表示我们处理了此事件
        }
        else -> super.onTouchEvent(event)
    }
}
```
*   调用`invalidate()`会通知系统视图需要重绘，最终会触发`onDraw`的调用。

## 结论

创建自定义视图是Android开发中的一项强大技能。通过掌握`onMeasure`、`onDraw`和`onTouchEvent`等核心方法，你可以构建出任何需要的UI组件，从而极大地提升应用的用户体验和独特性。 