# Jetpack Compose UI开发

Jetpack Compose是Android现代化的声明式UI工具包。它简化并加速了UI开发，让你用更少的代码、更强大的工具创建美观、响应迅速的应用。

## 1. 声明式UI编程思想

与传统的命令式UI（如XML布局）不同，Compose采用声明式方法。你只需描述你想要的UI状态，Compose会负责在状态变化时自动更新UI。

- **命令式**: "找到这个TextView，然后设置它的文本。"
- **声明式**: "当数据显示时，这里应该有一个文本，它的内容是[数据]。"

## 2. 核心概念

### 可组合函数 (`@Composable`)

在Compose中，UI元素是由可组合函数（用`@Composable`注解标记的函数）构建的。这些函数是Compose UI的基本构建块。

```kotlin
@Composable
fun Greeting(name: String) {
    Text(text = "Hello $name!")
}
```
- 可组合函数只能在其他可组合函数中调用。
- 函数名以大写字母开头。

### 状态管理

Compose的核心思想是UI = f(state)。当状态改变时，UI会自动更新。

#### 使用`remember`和`mutableStateOf`

`mutableStateOf`会创建一个可观察的`State`对象，当它的值改变时，所有读取该值的可组合函数都会被重组（recomposed）。`remember`则用于在重组过程中保持状态。

```kotlin
@Composable
fun Counter() {
    // remember将state保存在组合中
    val count = remember { mutableStateOf(0) }

    Button(onClick = { count.value++ }) {
        Text(text = "Count: ${count.value}")
    }
}
```

#### 状态提升 (State Hoisting)

为了使组件更具可重用性和可测试性，通常采用"状态提升"模式。即将状态从子组件中移出到父组件中，通过回调函数来修改状态。

```kotlin
@Composable
fun Counter(count: Int, onIncrement: () -> Unit) {
    Button(onClick = onIncrement) {
        Text(text = "Count: $count")
    }
}

@Composable
fun CounterScreen() {
    val count = remember { mutableStateOf(0) }
    Counter(count = count.value, onIncrement = { count.value++ })
}
```

## 3. 布局

Compose提供了一系列开箱即用的布局组件。

- **`Column`**: 垂直排列子组件。
- **`Row`**: 水平排列子组件。
- **`Box`**: 像`FrameLayout`一样，将子组件堆叠起来。
- **`ConstraintLayout`**: 用于创建复杂的扁平化布局。

```kotlin
@Composable
fun ArtistCard() {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Image(
            painter = painterResource(id = R.drawable.artist_avatar),
            contentDescription = "Artist Avatar",
            modifier = Modifier.size(48.dp)
        )
        Spacer(modifier = Modifier.width(8.dp))
        Column {
            Text("Alfred Sisley", fontWeight = FontWeight.Bold)
            Text("3 minutes ago", style = MaterialTheme.typography.body2)
        }
    }
}
```

### `Modifier`

`Modifier`是Compose中一个非常重要的概念。它允许你装饰或给可组合函数添加行为，如设置大小、边距、内边距、背景颜色和点击事件等。

```kotlin
Text(
    text = "Hello Compose",
    modifier = Modifier
        .padding(16.dp) // 外边距
        .background(Color.Blue) // 背景色
        .clickable { /* ... */ } // 点击事件
)
```

## 4. 列表

使用`LazyColumn`和`LazyRow`可以高效地显示大量可滚动的项目列表，它们只组合和布局当前可见的项目。

```kotlin
@Composable
fun MessageList(messages: List<String>) {
    LazyColumn {
        items(messages) { message ->
            Text(text = message)
        }
    }
}
```

## 5. 与传统View系统互操作

Compose可以与现有的Android View系统无缝集成。

### 在XML布局中使用Compose

使用`ComposeView`可以在XML布局中嵌入Compose UI。

```xml
<!-- activity_main.xml -->
<LinearLayout ...>
    <TextView ... />
    <androidx.compose.ui.platform.ComposeView
        android:id="@+id/compose_view"
        android:layout_width="match_parent"
        android:layout_height="wrap_content" />
</LinearLayout>
```

```kotlin
// 在Activity或Fragment中
findViewById<ComposeView>(R.id.compose_view).setContent {
    MaterialTheme {
        Greeting("Android")
    }
}
```

### 在Compose中使用XML布局

使用`AndroidView`可组合函数可以在Compose中嵌入传统的Android View。

```kotlin
@Composable
fun CustomCalendarView() {
    AndroidView(
        factory = { context ->
            // 创建一个传统的CalendarView
            CalendarView(context)
        },
        update = { view ->
            // 当状态改变时更新View
            // view.date = ...
        }
    )
}
```

## 结论

Jetpack Compose代表了Android UI开发的未来。它的声明式方法、强大的状态管理和与现有代码的互操作性，使其成为构建现代化Android应用的理想选择。通过掌握其核心概念，开发者可以更高效地创建出美观且高性能的用户界面。 