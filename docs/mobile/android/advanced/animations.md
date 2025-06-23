# Android中的动画与过渡

Android框架提供了多种强大的API来为应用添加动画效果，从简单的视图动画到复杂的属性动画和过渡效果。本指南将介绍Android中实现动画的主要技术。

## 1. 动画类型

Android中的动画主要分为三类：

- **属性动画 (Property Animation)**: 最灵活、功能最强大的动画系统。它可以对任何对象的任何属性（不限于View）进行动画处理。这是官方推荐的首选方案。
- **视图动画 (View Animation)**: 只能用于`View`对象，支持补间动画（位置、大小、旋转、透明度）。实现简单，但功能受限。
- **可绘制对象动画 (Drawable Animation)**: 用于实现逐帧动画，类似于播放GIF图片。

## 2. 属性动画 (Property Animation)

属性动画系统通过在指定时间内修改对象的属性值来创建动画。

### 使用`ValueAnimator`

`ValueAnimator`是属性动画的核心计时引擎，它不直接操作对象，而是计算动画过程中的值。

```kotlin
val animator = ValueAnimator.ofFloat(0f, 1f) // 从0到1
animator.duration = 1000 // 动画时长1秒

animator.addUpdateListener { animation ->
    val animatedValue = animation.animatedValue as Float
    myView.alpha = animatedValue // 手动更新视图属性
}
animator.start()
```

### 使用`ObjectAnimator`

`ObjectAnimator`是`ValueAnimator`的子类，它允许你直接对目标对象的属性进行动画处理，更易于使用。

```kotlin
// 将myView的alpha属性从1f变为0f
ObjectAnimator.ofFloat(myView, "alpha", 1f, 0f).apply {
    duration = 500
    start()
}

// 同时执行多个动画
val scaleX = ObjectAnimator.ofFloat(myView, "scaleX", 1f, 2f)
val scaleY = ObjectAnimator.ofFloat(myView, "scaleY", 1f, 2f)
AnimatorSet().apply {
    playTogether(scaleX, scaleY)
    duration = 1000
    start()
}
```
*   要使`ObjectAnimator`正常工作，目标属性必须有对应的setter方法（例如，`setAlpha()`）。

### 在XML中定义属性动画

你也可以在`res/animator/`目录下的XML文件中声明属性动画。

```xml
<!-- res/animator/scale_anim.xml -->
<objectAnimator
    xmlns:android="http://schemas.android.com/apk/res/android"
    android:propertyName="scaleX"
    android:valueType="floatType"
    android:valueFrom="1.0"
    android:valueTo="2.0"
    android:duration="1000" />
```

```kotlin
// 加载并启动XML动画
val animator = AnimatorInflater.loadAnimator(context, R.animator.scale_anim)
animator.setTarget(myView)
animator.start()
```

## 3. MotionLayout

`MotionLayout`是`ConstraintLayout`的子类，专门用于管理运动和控件动画。它允许你通过XML来描述复杂的过渡动画，而无需编写复杂的动画代码。

### 使用`MotionLayout`的步骤

1.  **添加依赖**：确保项目中已添加`ConstraintLayout`的最新依赖。
2.  **创建`MotionLayout`布局**：将你的`ConstraintLayout`布局转换为`MotionLayout`。
3.  **创建`MotionScene`**：在`res/xml/`目录下创建一个`MotionScene`文件。
4.  **定义`ConstraintSet`**：在`MotionScene`中定义动画的起始和结束状态（`ConstraintSet`）。
5.  **定义`Transition`**：在`MotionScene`中定义一个`Transition`，连接起始和结束`ConstraintSet`，并配置触发器（如点击或滑动）。

### `MotionScene`示例

```xml
<!-- res/xml/my_scene.xml -->
<MotionScene xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:motion="http://schemas.android.com/apk/res-auto">

    <Transition
        motion:constraintSetEnd="@+id/end"
        motion:constraintSetStart="@+id/start"
        motion:duration="1000">
        <OnClick
            motion:targetId="@+id/my_view"
            motion:clickAction="toggle" />
    </Transition>

    <ConstraintSet android:id="@+id/start">
        <Constraint
            android:id="@+id/my_view"
            android:layout_width="64dp"
            android:layout_height="64dp"
            motion:layout_constraintStart_toStartOf="parent"
            motion:layout_constraintTop_toTopOf="parent" />
    </ConstraintSet>

    <ConstraintSet android:id="@+id/end">
        <Constraint
            android:id="@+id/my_view"
            android:layout_width="64dp"
            android:layout_height="64dp"
            motion:layout_constraintEnd_toEndOf="parent"
            motion:layout_constraintBottom_toBottomOf="parent" />
    </ConstraintSet>

</MotionScene>
```

在`MotionLayout`布局中引用此`MotionScene`：

```xml
<androidx.constraintlayout.motion.widget.MotionLayout
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    motion:layoutDescription="@xml/my_scene">
    
    <!-- 这里放置你的视图 -->
    <View
        android:id="@+id/my_view"
        android:background="@color/blue" />
        
</androidx.constraintlayout.motion.widget.MotionLayout>
```

## 4. Activity/Fragment之间的过渡

`Material Motion`系统提供了一套预设的过渡动画，用于在Activity和Fragment之间创建连贯的导航体验。

- **`MaterialElevationScale`**: 用于进出视图的缩放动画。
- **`MaterialSharedAxis`**: 用于在具有导航关系的屏幕之间切换（如上一步/下一步）。
- **`MaterialFadeThrough`**: 用于在不相关的UI元素之间切换。

### Fragment过渡示例

```kotlin
// 在退出和进入的Fragment中设置过渡动画
override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    exitTransition = MaterialSharedAxis(MaterialSharedAxis.Z, true)
    reenterTransition = MaterialSharedAxis(MaterialSharedAxis.Z, false)

    enterTransition = MaterialSharedAxis(MaterialSharedAxis.Z, true)
    returnTransition = MaterialSharedAxis(MaterialSharedAxis.Z, false)
}
```

## 结论

Android的动画系统非常强大和灵活。对于大多数场景，推荐使用**属性动画**。对于复杂的UI编排和手势驱动的动画，**`MotionLayout`**是最佳选择。同时，善用`Material Motion`可以轻松创建符合Material Design规范的过渡效果。 