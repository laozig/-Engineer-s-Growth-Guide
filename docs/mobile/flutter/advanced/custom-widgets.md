# Flutter 自定义 Widget - 创建可复用组件

自定义 Widget 是 Flutter 开发中的核心概念，能够帮助开发者创建可复用、可维护的组件，提高开发效率并保持应用的一致性。本文将深入探讨如何在 Flutter 中创建和使用自定义 Widget。

## 目录

- [基础概念](#基础概念)
- [StatelessWidget vs StatefulWidget](#statelesswidget-vs-statefulwidget)
- [创建基础自定义 Widget](#创建基础自定义-widget)
- [组合 Widget](#组合-widget)
- [可配置的 Widget](#可配置的-widget)
- [自定义画布绘制](#自定义画布绘制)
- [自定义布局 Widget](#自定义布局-widget)
- [可重用组件库](#可重用组件库)
- [性能优化](#性能优化)
- [最佳实践](#最佳实践)

## 基础概念

在 Flutter 中，一切皆为 Widget。自定义 Widget 是通过组合或扩展现有 Widget，或者从零开始创建新的 Widget 来实现的。

### Widget 的生命周期

Widget 本身是不可变的配置描述，真正的 UI 渲染是通过 Element 树来完成的：

1. Widget 被创建并添加到 Widget 树
2. Flutter 框架将 Widget 转换为 Element
3. Element 创建或更新 RenderObject
4. RenderObject 负责布局和绘制

## StatelessWidget vs StatefulWidget

选择正确的 Widget 类型是创建自定义 Widget 的第一步：

### StatelessWidget

```dart
class CustomButton extends StatelessWidget {
  final String text;
  final VoidCallback onPressed;
  final Color color;

  const CustomButton({
    Key? key,
    required this.text,
    required this.onPressed,
    this.color = Colors.blue,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      onPressed: onPressed,
      style: ElevatedButton.styleFrom(
        backgroundColor: color,
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
      ),
      child: Text(
        text,
        style: const TextStyle(fontSize: 16),
      ),
    );
  }
}
```

### StatefulWidget

```dart
class ExpandableCard extends StatefulWidget {
  final String title;
  final Widget content;
  final bool initiallyExpanded;

  const ExpandableCard({
    Key? key,
    required this.title,
    required this.content,
    this.initiallyExpanded = false,
  }) : super(key: key);

  @override
  State<ExpandableCard> createState() => _ExpandableCardState();
}

class _ExpandableCardState extends State<ExpandableCard> {
  late bool _isExpanded;

  @override
  void initState() {
    super.initState();
    _isExpanded = widget.initiallyExpanded;
  }

  @override
  Widget build(BuildContext context) {
    return Card(
      margin: const EdgeInsets.all(8.0),
      child: Column(
        children: [
          ListTile(
            title: Text(widget.title),
            trailing: Icon(_isExpanded ? Icons.expand_less : Icons.expand_more),
            onTap: () {
              setState(() {
                _isExpanded = !_isExpanded;
              });
            },
          ),
          if (_isExpanded)
            Padding(
              padding: const EdgeInsets.all(16.0),
              child: widget.content,
            ),
        ],
      ),
    );
  }
}
```

## 创建基础自定义 Widget

### 封装常用样式

```dart
class PrimaryText extends StatelessWidget {
  final String text;
  final double fontSize;
  final FontWeight fontWeight;
  final Color color;
  final TextAlign textAlign;
  final int? maxLines;
  final TextOverflow overflow;

  const PrimaryText(
    this.text, {
    Key? key,
    this.fontSize = 16,
    this.fontWeight = FontWeight.normal,
    this.color = Colors.black87,
    this.textAlign = TextAlign.left,
    this.maxLines,
    this.overflow = TextOverflow.ellipsis,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Text(
      text,
      style: TextStyle(
        fontSize: fontSize,
        fontWeight: fontWeight,
        color: color,
      ),
      textAlign: textAlign,
      maxLines: maxLines,
      overflow: maxLines != null ? overflow : null,
    );
  }
}
```

### 使用示例

```dart
PrimaryText(
  '这是一个标题',
  fontSize: 20,
  fontWeight: FontWeight.bold,
),
PrimaryText(
  '这是正文内容，可能会很长很长很长很长很长很长很长很长很长很长',
  maxLines: 2,
),
```

## 组合 Widget

组合多个 Widget 创建更复杂的可复用组件：

```dart
class ProfileCard extends StatelessWidget {
  final String name;
  final String role;
  final String avatarUrl;
  final VoidCallback onTap;

  const ProfileCard({
    Key? key,
    required this.name,
    required this.role,
    required this.avatarUrl,
    required this.onTap,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 2,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Row(
            children: [
              CircleAvatar(
                radius: 30,
                backgroundImage: NetworkImage(avatarUrl),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      name,
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      role,
                      style: TextStyle(
                        fontSize: 14,
                        color: Colors.grey[600],
                      ),
                    ),
                  ],
                ),
              ),
              const Icon(Icons.chevron_right),
            ],
          ),
        ),
      ),
    );
  }
}
```

## 可配置的 Widget

创建高度可定制的 Widget，适应不同场景：

```dart
class ActionCard extends StatelessWidget {
  final String title;
  final String? subtitle;
  final IconData icon;
  final Color iconColor;
  final Color backgroundColor;
  final VoidCallback onTap;
  final List<Widget>? actions;
  final EdgeInsets padding;
  final double borderRadius;

  const ActionCard({
    Key? key,
    required this.title,
    this.subtitle,
    required this.icon,
    this.iconColor = Colors.blue,
    this.backgroundColor = Colors.white,
    required this.onTap,
    this.actions,
    this.padding = const EdgeInsets.all(16.0),
    this.borderRadius = 8.0,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Card(
      color: backgroundColor,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(borderRadius),
      ),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(borderRadius),
        child: Padding(
          padding: padding,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(
                    icon,
                    color: iconColor,
                    size: 24,
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          title,
                          style: const TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        if (subtitle != null)
                          Padding(
                            padding: const EdgeInsets.only(top: 4),
                            child: Text(
                              subtitle!,
                              style: TextStyle(
                                fontSize: 14,
                                color: Colors.grey[600],
                              ),
                            ),
                          ),
                      ],
                    ),
                  ),
                ],
              ),
              if (actions != null)
                Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.end,
                    children: actions!,
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
```

## 自定义画布绘制

使用 `CustomPainter` 创建自定义图形：

```dart
class CircularProgressPainter extends CustomPainter {
  final double progress;
  final Color progressColor;
  final Color backgroundColor;
  final double strokeWidth;

  CircularProgressPainter({
    required this.progress,
    this.progressColor = Colors.blue,
    this.backgroundColor = Colors.grey,
    this.strokeWidth = 10.0,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = min(size.width, size.height) / 2 - strokeWidth / 2;

    // 绘制背景圆环
    final backgroundPaint = Paint()
      ..color = backgroundColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth;

    canvas.drawCircle(center, radius, backgroundPaint);

    // 绘制进度圆弧
    final progressPaint = Paint()
      ..color = progressColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      -pi / 2, // 从顶部开始
      2 * pi * progress, // 进度对应的弧度
      false,
      progressPaint,
    );
  }

  @override
  bool shouldRepaint(CircularProgressPainter oldDelegate) {
    return oldDelegate.progress != progress ||
        oldDelegate.progressColor != progressColor ||
        oldDelegate.backgroundColor != backgroundColor ||
        oldDelegate.strokeWidth != strokeWidth;
  }
}

class CircularProgressIndicator extends StatelessWidget {
  final double progress;
  final double size;
  final Color progressColor;
  final Color backgroundColor;
  final double strokeWidth;
  final Widget? child;

  const CircularProgressIndicator({
    Key? key,
    required this.progress,
    this.size = 100.0,
    this.progressColor = Colors.blue,
    this.backgroundColor = Colors.grey,
    this.strokeWidth = 10.0,
    this.child,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        alignment: Alignment.center,
        children: [
          CustomPaint(
            size: Size(size, size),
            painter: CircularProgressPainter(
              progress: progress,
              progressColor: progressColor,
              backgroundColor: backgroundColor,
              strokeWidth: strokeWidth,
            ),
          ),
          if (child != null) child!,
        ],
      ),
    );
  }
}
```

使用示例：

```dart
CircularProgressIndicator(
  progress: 0.75,
  size: 120,
  progressColor: Colors.green,
  child: Text(
    '75%',
    style: TextStyle(
      fontSize: 20,
      fontWeight: FontWeight.bold,
    ),
  ),
)
```

## 自定义布局 Widget

使用 `CustomMultiChildLayout` 实现自定义布局：

```dart
class ChatBubbleLayoutDelegate extends MultiChildLayoutDelegate {
  final bool isMe;
  final Size avatarSize;
  final EdgeInsets padding;

  ChatBubbleLayoutDelegate({
    required this.isMe,
    this.avatarSize = const Size(40, 40),
    this.padding = const EdgeInsets.all(8),
  });

  @override
  void performLayout(Size size) {
    // 布局头像
    final avatarConstraints = BoxConstraints.tight(avatarSize);
    final avatarSize = layoutChild('avatar', avatarConstraints);
    
    // 确定头像位置
    final avatarOffset = isMe
        ? Offset(size.width - avatarSize.width - padding.right, padding.top)
        : Offset(padding.left, padding.top);
    positionChild('avatar', avatarOffset);

    // 布局气泡内容
    final contentWidth = size.width - avatarSize.width - padding.left - padding.right - 16;
    final contentConstraints = BoxConstraints(
      maxWidth: contentWidth,
      minWidth: 0,
      maxHeight: size.height - padding.vertical,
      minHeight: 0,
    );
    
    final contentSize = layoutChild('content', contentConstraints);
    
    // 确定气泡内容位置
    final contentOffset = isMe
        ? Offset(size.width - contentSize.width - avatarSize.width - padding.right - 8, padding.top)
        : Offset(avatarSize.width + padding.left + 8, padding.top);
    positionChild('content', contentOffset);
  }

  @override
  bool shouldRelayout(ChatBubbleLayoutDelegate oldDelegate) {
    return oldDelegate.isMe != isMe ||
        oldDelegate.avatarSize != avatarSize ||
        oldDelegate.padding != padding;
  }
}

class ChatBubble extends StatelessWidget {
  final Widget content;
  final String avatarUrl;
  final bool isMe;

  const ChatBubble({
    Key? key,
    required this.content,
    required this.avatarUrl,
    required this.isMe,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return CustomMultiChildLayout(
      delegate: ChatBubbleLayoutDelegate(isMe: isMe),
      children: [
        LayoutId(
          id: 'avatar',
          child: CircleAvatar(
            backgroundImage: NetworkImage(avatarUrl),
          ),
        ),
        LayoutId(
          id: 'content',
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: isMe ? Colors.blue[100] : Colors.grey[200],
              borderRadius: BorderRadius.circular(16),
            ),
            child: content,
          ),
        ),
      ],
    );
  }
}
```

## 可重用组件库

创建组件库，统一管理自定义 Widget：

```dart
// lib/widgets/buttons/primary_button.dart
class PrimaryButton extends StatelessWidget {
  // 实现...
}

// lib/widgets/buttons/secondary_button.dart
class SecondaryButton extends StatelessWidget {
  // 实现...
}

// lib/widgets/cards/info_card.dart
class InfoCard extends StatelessWidget {
  // 实现...
}

// lib/widgets/index.dart
export 'buttons/primary_button.dart';
export 'buttons/secondary_button.dart';
export 'cards/info_card.dart';
// 其他导出...
```

使用组件库：

```dart
import 'package:my_app/widgets/index.dart';

class MyScreen extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        children: [
          InfoCard(
            title: '标题',
            description: '描述',
          ),
          PrimaryButton(
            text: '确认',
            onPressed: () {},
          ),
        ],
      ),
    );
  }
}
```

## 性能优化

### const 构造函数

```dart
class IconText extends StatelessWidget {
  final IconData icon;
  final String text;
  final double spacing;

  // 使用 const 构造函数
  const IconText({
    Key? key,
    required this.icon,
    required this.text,
    this.spacing = 8.0,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon),
        SizedBox(width: spacing),
        Text(text),
      ],
    );
  }
}
```

### 避免不必要的重建

```dart
// 不好的做法
class CounterDisplay extends StatelessWidget {
  final int count;
  final VoidCallback onIncrement;

  const CounterDisplay({
    Key? key,
    required this.count,
    required this.onIncrement,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Text('Count: $count'),
        ElevatedButton(
          onPressed: onIncrement,
          child: const Text('+'),
        ),
      ],
    );
  }
}

// 好的做法：拆分 Widget
class CounterDisplay extends StatelessWidget {
  final int count;

  const CounterDisplay({Key? key, required this.count}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Text('Count: $count');
  }
}

class IncrementButton extends StatelessWidget {
  final VoidCallback onIncrement;

  const IncrementButton({Key? key, required this.onIncrement}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return ElevatedButton(
      onPressed: onIncrement,
      child: const Text('+'),
    );
  }
}
```

## 最佳实践

1. **单一职责原则**：每个 Widget 只负责一个功能
2. **参数合理默认值**：提供合理的默认值，减少必需参数
3. **文档注释**：为自定义 Widget 添加详细文档
4. **组件测试**：为自定义 Widget 编写测试用例
5. **主题适配**：使用 Theme.of(context) 获取主题数据
6. **响应式设计**：使用 MediaQuery 适配不同屏幕尺寸
7. **无障碍支持**：添加语义标签和适当的对比度

### 主题适配示例

```dart
class ThemedButton extends StatelessWidget {
  final String text;
  final VoidCallback onPressed;
  final bool isPrimary;

  const ThemedButton({
    Key? key,
    required this.text,
    required this.onPressed,
    this.isPrimary = true,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    
    return ElevatedButton(
      onPressed: onPressed,
      style: ElevatedButton.styleFrom(
        backgroundColor: isPrimary ? theme.colorScheme.primary : theme.colorScheme.secondary,
        foregroundColor: isPrimary ? theme.colorScheme.onPrimary : theme.colorScheme.onSecondary,
        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
      ),
      child: Text(text),
    );
  }
}
```

### 响应式设计示例

```dart
class ResponsiveCard extends StatelessWidget {
  final String title;
  final String description;
  final Widget image;

  const ResponsiveCard({
    Key? key,
    required this.title,
    required this.description,
    required this.image,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final isSmallScreen = size.width < 600;

    return Card(
      child: isSmallScreen
          ? Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                AspectRatio(
                  aspectRatio: 16 / 9,
                  child: image,
                ),
                Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: const TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(description),
                    ],
                  ),
                ),
              ],
            )
          : Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(
                  width: 200,
                  child: AspectRatio(
                    aspectRatio: 1,
                    child: image,
                  ),
                ),
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.all(16.0),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          title,
                          style: const TextStyle(
                            fontSize: 20,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 12),
                        Text(description),
                      ],
                    ),
                  ),
                ),
              ],
            ),
    );
  }
}
```

通过遵循这些最佳实践和示例，您可以创建出高质量、可复用的 Flutter 自定义 Widget，提高开发效率并保持应用的一致性。
