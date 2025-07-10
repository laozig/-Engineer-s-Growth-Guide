# 动画效果

动画是现代移动应用程序中不可或缺的元素，它们能够提升用户体验、引导用户注意力并赋予应用生动的特性。Flutter提供了丰富而强大的动画系统，使开发者能够创建从简单过渡到复杂交互动画的各种效果。本文档将介绍Flutter中的动画基础知识、常用动画类型及其实现方法。

## 动画基础

在Flutter中，动画系统建立在以下几个核心概念之上：

### Animation对象

`Animation`是Flutter动画系统的核心，它是一个抽象类，包含当前值和状态（如完成、正向、反向等）。最常用的Animation子类是`Animation<double>`，它生成介于0.0和1.0之间的值。

### AnimationController

`AnimationController`是一种特殊的Animation对象，用于控制动画的播放、暂停、重复等。它需要一个`vsync`参数来防止屏幕外动画消耗不必要的资源。

```dart
class _MyAnimationState extends State<MyAnimation> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  
  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this, // 需要一个TickerProvider，通常是当前状态对象
    );
    
    // 启动动画
    _controller.forward();
  }
  
  @override
  void dispose() {
    _controller.dispose(); // 不要忘记释放资源
    super.dispose();
  }
  
  // ...
}
```

### Tween

`Tween`（补间）定义了动画的起始和结束值，它将`AnimationController`生成的0.0到1.0值映射到我们需要的范围。

```dart
final animation = Tween<double>(
  begin: 0,
  end: 300,
).animate(_controller);
```

Flutter提供了多种Tween子类，用于不同类型的值：

- `ColorTween`: 在两个颜色之间进行插值
- `SizeTween`: 在两个Size之间进行插值
- `RectTween`: 在两个Rect之间进行插值
- `IntTween`: 在两个整数之间进行插值

### 动画监听

要在动画值变化时更新界面，可以使用以下方法：

1. **AnimatedBuilder**: 封装了重建逻辑的Widget
2. **addListener回调**: 手动触发重建
3. **AnimatedWidget**: 封装动画逻辑的抽象类

#### 使用AnimatedBuilder

```dart
AnimatedBuilder(
  animation: _animation,
  builder: (context, child) {
    return Container(
      height: _animation.value,
      width: _animation.value,
      child: child,
    );
  },
  child: FlutterLogo(size: 100), // 这个部分不会在动画过程中重建
)
```

#### 使用addListener

```dart
@override
void initState() {
  super.initState();
  _controller = AnimationController(
    duration: const Duration(seconds: 2),
    vsync: this,
  );
  
  _animation = Tween<double>(begin: 0, end: 300).animate(_controller)
    ..addListener(() {
      setState(() {
        // 动画值变化时触发重建
      });
    });
  
  _controller.forward();
}

@override
Widget build(BuildContext context) {
  return Container(
    width: _animation.value,
    height: _animation.value,
    color: Colors.blue,
  );
}
```

#### 使用AnimatedWidget

```dart
class AnimatedLogo extends AnimatedWidget {
  const AnimatedLogo({Key? key, required Animation<double> animation})
      : super(key: key, listenable: animation);

  @override
  Widget build(BuildContext context) {
    final animation = listenable as Animation<double>;
    return Container(
      height: animation.value,
      width: animation.value,
      child: FlutterLogo(),
    );
  }
}

// 使用方式
AnimatedLogo(animation: _animation)
```

### 曲线

`Curve`用于定义动画的进度曲线，使动画更自然。Flutter提供了多种预设曲线：

```dart
final animation = Tween<double>(
  begin: 0,
  end: 300,
).animate(
  CurvedAnimation(
    parent: _controller,
    curve: Curves.elasticOut, // 弹性曲线
  ),
);
```

常用的曲线包括：
- `Curves.linear`: 线性
- `Curves.easeIn`: 缓入
- `Curves.easeOut`: 缓出
- `Curves.easeInOut`: 缓入缓出
- `Curves.elasticIn`: 弹性缓入
- `Curves.elasticOut`: 弹性缓出
- `Curves.bounceIn`: 弹跳缓入
- `Curves.bounceOut`: 弹跳缓出

## 隐式动画

隐式动画是Flutter提供的一组封装好的Widget，只需设置起始和结束状态，Flutter会自动处理中间的过渡动画。这种方式简单易用，适合大多数基础场景。

### 常用隐式动画Widget

#### AnimatedContainer

`AnimatedContainer`可以在其属性（如大小、颜色、对齐方式等）更改时自动生成动画效果。

```dart
class _AnimatedContainerExample extends State<AnimatedContainerExample> {
  bool _isExpanded = false;
  
  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () {
        setState(() {
          _isExpanded = !_isExpanded;
        });
      },
      child: AnimatedContainer(
        duration: Duration(milliseconds: 300),
        curve: Curves.easeInOut,
        width: _isExpanded ? 200.0 : 100.0,
        height: _isExpanded ? 200.0 : 100.0,
        color: _isExpanded ? Colors.blue : Colors.red,
        alignment: _isExpanded ? Alignment.center : Alignment.topLeft,
        child: FlutterLogo(size: 50),
      ),
    );
  }
}
```

#### AnimatedOpacity

`AnimatedOpacity`可以为Widget的透明度变化添加动画效果。

```dart
AnimatedOpacity(
  opacity: _visible ? 1.0 : 0.0,
  duration: Duration(milliseconds: 500),
  child: Container(
    width: 200,
    height: 200,
    color: Colors.blue,
    child: FlutterLogo(size: 100),
  ),
)
```

#### AnimatedPositioned

`AnimatedPositioned`可以为Stack中子Widget的位置变化添加动画效果。

```dart
Stack(
  children: [
    AnimatedPositioned(
      duration: Duration(milliseconds: 500),
      left: _left,
      top: _top,
      child: Container(
        width: 100,
        height: 100,
        color: Colors.red,
      ),
    ),
  ],
)
```

#### TweenAnimationBuilder

`TweenAnimationBuilder`是一个更通用的隐式动画Widget，可以为任何值创建补间动画。

```dart
TweenAnimationBuilder<double>(
  tween: Tween<double>(begin: 0, end: _targetValue),
  duration: Duration(milliseconds: 500),
  builder: (BuildContext context, double value, Widget? child) {
    return Transform.rotate(
      angle: value,
      child: child,
    );
  },
  child: FlutterLogo(size: 100), // 不会在动画过程中重建
)
```

### 其他常用隐式动画Widget

- `AnimatedAlign`: 动画化对齐方式变化
- `AnimatedPadding`: 动画化内边距变化
- `AnimatedPhysicalModel`: 动画化物理属性变化
- `AnimatedDefaultTextStyle`: 动画化文本样式变化
- `AnimatedCrossFade`: 在两个子Widget之间交叉淡入淡出

## Hero动画

Hero动画（又称共享元素过渡）用于在不同页面之间创建连接两个Widget的视觉效果，使其看起来是同一个Widget在两个位置之间移动。这在页面导航时特别有用，能为用户提供更流畅的体验。

### 基本实现

实现Hero动画需要在起始和目标页面中使用相同tag的`Hero`Widget来包裹共享元素。

```dart
// 第一个页面中
GestureDetector(
  onTap: () {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (context) => DetailPage()),
    );
  },
  child: Hero(
    tag: 'imageHero', // 唯一标识符
    child: Image.network(
      'https://picsum.photos/250?image=9',
      width: 100,
      height: 100,
    ),
  ),
)

// 第二个页面中
class DetailPage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('详情页')),
      body: Center(
        child: Hero(
          tag: 'imageHero', // 相同的标识符
          child: Image.network('https://picsum.photos/250?image=9'),
        ),
      ),
    );
  }
}
```

### 自定义Hero动画

可以通过`HeroController`和`CreateRectTween`自定义Hero动画的路径和行为：

```dart
Navigator(
  observers: [
    HeroController(
      createRectTween: (begin, end) {
        // 自定义路径计算
        return RectTween(begin: begin, end: end);
      },
    ),
  ],
  // ...
)
```

### 最佳实践

1. 为每个Hero提供唯一的tag
2. 尽可能确保起始和目标Hero有相似的尺寸和外观
3. 避免过多的Hero动画同时播放，以防性能问题
4. 考虑使用`flightShuttleBuilder`来自定义过渡时的外观

```dart
Hero(
  tag: 'imageHero',
  flightShuttleBuilder: (
    BuildContext flightContext,
    Animation<double> animation,
    HeroFlightDirection flightDirection,
    BuildContext fromHeroContext,
    BuildContext toHeroContext,
  ) {
    // 自定义过渡外观
    return RotationTransition(
      turns: animation,
      child: toHeroContext.widget,
    );
  },
  child: Image.network('https://picsum.photos/250?image=9'),
)
```

## 交互动画

交互动画是对用户输入直接做出响应的动画，如拖拽、手势等。Flutter提供了多种方式来实现这类动画。

### GestureDetector和动画

可以使用`GestureDetector`检测用户手势，然后基于这些手势控制动画：

```dart
class _DraggableCardState extends State<DraggableCard> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<Alignment> _animation;
  Alignment _dragAlignment = Alignment.center;
  
  @override
  void initState() {
    super.initState();
    _controller = AnimationController(vsync: this, duration: Duration(seconds: 1));
    _animation = _controller.drive(
      AlignmentTween(
        begin: _dragAlignment,
        end: Alignment.center,
      ),
    );
    
    _controller.addListener(() {
      setState(() {
        _dragAlignment = _animation.value;
      });
    });
  }
  
  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    var size = MediaQuery.of(context).size;
    return GestureDetector(
      onPanDown: (details) {
        _controller.stop();
      },
      onPanUpdate: (details) {
        setState(() {
          _dragAlignment += Alignment(
            details.delta.dx / (size.width / 2),
            details.delta.dy / (size.height / 2),
          );
        });
      },
      onPanEnd: (details) {
        _controller.reset();
        _animation = _controller.drive(
          AlignmentTween(
            begin: _dragAlignment,
            end: Alignment.center,
          ),
        );
        _controller.forward();
      },
      child: Align(
        alignment: _dragAlignment,
        child: Card(
          child: widget.child,
        ),
      ),
    );
  }
}
```

### AnimatedBuilder结合手势

结合`AnimatedBuilder`和手势识别可以创建更复杂的交互动画：

```dart
class _AnimatedFlipCardState extends State<AnimatedFlipCard> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _frontScale;
  late Animation<double> _backScale;
  
  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(milliseconds: 500),
      vsync: this,
    );
    
    _frontScale = TweenSequence(
      <TweenSequenceItem<double>>[
        TweenSequenceItem<double>(
          tween: Tween<double>(begin: 1.0, end: 0.0)
            .chain(CurveTween(curve: Curves.easeOut)),
          weight: 50.0,
        ),
        TweenSequenceItem<double>(
          tween: ConstantTween<double>(0.0),
          weight: 50.0,
        ),
      ],
    ).animate(_controller);
    
    _backScale = TweenSequence(
      <TweenSequenceItem<double>>[
        TweenSequenceItem<double>(
          tween: ConstantTween<double>(0.0),
          weight: 50.0,
        ),
        TweenSequenceItem<double>(
          tween: Tween<double>(begin: 0.0, end: 1.0)
            .chain(CurveTween(curve: Curves.easeOut)),
          weight: 50.0,
        ),
      ],
    ).animate(_controller);
  }
  
  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }
  
  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () {
        if (_controller.status == AnimationStatus.dismissed) {
          _controller.forward();
        } else {
          _controller.reverse();
        }
      },
      child: Stack(
        children: <Widget>[
          AnimatedBuilder(
            animation: _controller,
            builder: (BuildContext context, Widget? child) {
              return Transform(
                transform: Matrix4.identity()
                  ..setEntry(3, 2, 0.001)
                  ..rotateY(pi * _controller.value),
                alignment: Alignment.center,
                child: _controller.value <= 0.5
                    ? Transform.scale(
                        scale: _frontScale.value,
                        child: widget.frontWidget,
                      )
                    : Transform.scale(
                        scale: _backScale.value,
                        child: Transform(
                          transform: Matrix4.identity()..rotateY(pi),
                          alignment: Alignment.center,
                          child: widget.backWidget,
                        ),
                      ),
              );
            },
          ),
        ],
      ),
    );
  }
}
```

### 物理模拟动画

Flutter提供了模拟物理行为的动画类，如弹簧、摩擦等：

#### SpringSimulation

```dart
// 创建一个弹簧动画
final SpringDescription _springDescription = SpringDescription(
  mass: 1,      // 质量
  stiffness: 500, // 刚度
  damping: 20,  // 阻尼
);

final simulation = SpringSimulation(
  _springDescription,
  0.0,  // 起始位置
  1.0,  // 目标位置
  0.0,  // 初始速度
);

// 使用弹簧动画控制器
_controller.animateWith(simulation);
```

#### FrictionSimulation

```dart
// 创建一个摩擦动画
final simulation = FrictionSimulation(
  0.5,   // 摩擦系数
  0.0,   // 起始位置
  10.0,  // 初始速度
);

// 使用摩擦动画控制器
_controller.animateWith(simulation);
```

### 自定义交互动画

对于更复杂的交互需求，可以结合`CustomPainter`和动画控制器来创建完全自定义的动画：

```dart
class WaveAnimation extends StatefulWidget {
  @override
  _WaveAnimationState createState() => _WaveAnimationState();
}

class _WaveAnimationState extends State<WaveAnimation>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Container(
          height: 200,
          width: double.infinity,
          child: CustomPaint(
            painter: WavePainter(_controller),
          ),
        ),
      ),
    );
  }
}

class WavePainter extends CustomPainter {
  final Animation<double> _animation;

  WavePainter(this._animation) : super(repaint: _animation);

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.blue
      ..style = PaintingStyle.fill;

    final path = Path();
    final height = size.height;
    final width = size.width;

    path.moveTo(0, height / 2);

    for (double i = 0; i < width; i++) {
      path.lineTo(
        i,
        height / 2 + sin((i / width * 2 * pi) + (_animation.value * 2 * pi)) * 20,
      );
    }

    path.lineTo(width, height);
    path.lineTo(0, height);
    path.close();

    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(WavePainter oldDelegate) => true;
}
```

## 动画性能优化

创建流畅的动画体验需要注意以下几点：

1. **使用RepaintBoundary**: 对于复杂的动画，使用`RepaintBoundary`隔离动画区域，减少重绘范围：

```dart
RepaintBoundary(
  child: AnimatedWidget(...),
)
```

2. **减少动画中的构建开销**: 尽可能使用`child`参数传递不需要重建的Widget：

```dart
AnimatedBuilder(
  animation: _animation,
  builder: (context, child) {
    return Transform.rotate(
      angle: _animation.value,
      child: child, // 不会在每帧中重建
    );
  },
  child: ComplexWidget(), // 只构建一次
)
```

3. **使用AnimatedWidget而非setState**: 对于简单的动画，`AnimatedWidget`比手动调用`setState`更高效。

4. **选择合适的动画方案**: 
   - 简单场景使用隐式动画
   - 复杂交互使用显式动画
   - 考虑使用`Lottie`等库处理复杂动画

5. **使用工具分析性能**:
   - Flutter DevTools
   - Performance Overlay

## 示例应用

下面是一个结合多种动画技术的示例应用：

```dart
import 'package:flutter/material.dart';
import 'dart:math' as math;

void main() => runApp(AnimationDemoApp());

class AnimationDemoApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter 动画演示',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: AnimationDemoHome(),
    );
  }
}

class AnimationDemoHome extends StatefulWidget {
  @override
  _AnimationDemoHomeState createState() => _AnimationDemoHomeState();
}

class _AnimationDemoHomeState extends State<AnimationDemoHome> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Flutter动画示例')),
      body: ListView(
        children: <Widget>[
          _buildSection('基础动画', BasicAnimationDemo()),
          _buildSection('隐式动画', ImplicitAnimationDemo()),
          _buildSection('Hero动画', HeroAnimationDemo()),
          _buildSection('交互动画', InteractiveAnimationDemo()),
        ],
      ),
    );
  }

  Widget _buildSection(String title, Widget demo) {
    return Card(
      margin: EdgeInsets.all(8.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Padding(
            padding: EdgeInsets.all(8.0),
            child: Text(
              title,
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
          ),
          Container(
            height: 200,
            child: Center(child: demo),
          ),
        ],
      ),
    );
  }
}

// 基础动画示例
class BasicAnimationDemo extends StatefulWidget {
  @override
  _BasicAnimationDemoState createState() => _BasicAnimationDemoState();
}

class _BasicAnimationDemoState extends State<BasicAnimationDemo>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      duration: const Duration(seconds: 2),
      vsync: this,
    )..repeat(reverse: true);
    
    _animation = CurvedAnimation(
      parent: _controller,
      curve: Curves.elasticOut,
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animation,
      builder: (_, __) {
        return Transform.scale(
          scale: 0.5 + _animation.value * 0.5,
          child: FlutterLogo(size: 100),
        );
      },
    );
  }
}

// 隐式动画示例
class ImplicitAnimationDemo extends StatefulWidget {
  @override
  _ImplicitAnimationDemoState createState() => _ImplicitAnimationDemoState();
}

class _ImplicitAnimationDemoState extends State<ImplicitAnimationDemo> {
  bool _isExpanded = false;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () {
        setState(() {
          _isExpanded = !_isExpanded;
        });
      },
      child: AnimatedContainer(
        duration: Duration(milliseconds: 500),
        curve: Curves.easeInOut,
        width: _isExpanded ? 150.0 : 100.0,
        height: _isExpanded ? 150.0 : 100.0,
        decoration: BoxDecoration(
          color: _isExpanded ? Colors.blue : Colors.red,
          borderRadius: BorderRadius.circular(_isExpanded ? 75.0 : 0.0),
        ),
        child: Center(
          child: Text(
            '点击我',
            style: TextStyle(color: Colors.white),
          ),
        ),
      ),
    );
  }
}

// Hero动画示例
class HeroAnimationDemo extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () {
        Navigator.push(
          context,
          MaterialPageRoute(builder: (_) => HeroDetailPage()),
        );
      },
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: <Widget>[
          Hero(
            tag: 'logoHero',
            child: FlutterLogo(size: 50.0),
          ),
          SizedBox(width: 16.0),
          Text('点击查看Hero动画'),
        ],
      ),
    );
  }
}

class HeroDetailPage extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: Text('Hero详情页')),
      body: Center(
        child: Hero(
          tag: 'logoHero',
          child: FlutterLogo(size: 200.0),
        ),
      ),
    );
  }
}

// 交互动画示例
class InteractiveAnimationDemo extends StatefulWidget {
  @override
  _InteractiveAnimationDemoState createState() => _InteractiveAnimationDemoState();
}

class _InteractiveAnimationDemoState extends State<InteractiveAnimationDemo>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  double _dragPosition = 0.5;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: <Widget>[
        Text('拖动下方的滑块：'),
        SizedBox(height: 16.0),
        GestureDetector(
          onHorizontalDragUpdate: (details) {
            setState(() {
              _dragPosition += details.delta.dx / 200;
              _dragPosition = math.max(0, math.min(1, _dragPosition));
              _controller.value = _dragPosition;
            });
          },
          child: Container(
            width: 200,
            height: 30,
            decoration: BoxDecoration(
              color: Colors.grey[300],
              borderRadius: BorderRadius.circular(15),
            ),
            child: Stack(
              children: <Widget>[
                Positioned(
                  left: _dragPosition * 170,
                  child: Container(
                    width: 30,
                    height: 30,
                    decoration: BoxDecoration(
                      color: Colors.blue,
                      shape: BoxShape.circle,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
        SizedBox(height: 20),
        AnimatedBuilder(
          animation: _controller,
          builder: (_, __) {
            return Transform.rotate(
              angle: _controller.value * 2 * math.pi,
              child: FlutterLogo(size: 50),
            );
          },
        ),
      ],
    );
  }
}
```

## 总结

Flutter的动画系统丰富且强大，通过本文档介绍的基础动画、隐式动画、Hero动画和交互动画，开发者可以为应用添加生动的视觉效果，提升用户体验。在实现动画时，应注意选择合适的动画类型，并考虑性能优化，以保证应用流畅运行。

## 下一步

- 学习[自定义绘制](custom-painting.md)来创建更复杂的视觉效果
- 探索[Lottie动画](https://pub.dev/packages/lottie)库来实现高质量预设动画
- 了解[Rive动画](https://rive.app/)与Flutter的集成