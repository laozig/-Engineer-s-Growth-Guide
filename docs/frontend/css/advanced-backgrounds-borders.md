# 高级背景与边框效果

CSS 不仅仅是布局和颜色，它还提供了许多强大的属性来创建复杂的背景和边框效果，让视觉设计更上一层楼。

## 1. 多重背景 (Multiple Backgrounds)

ackground-image 属性允许你为一个元素指定多个背景图像，用逗号分隔。第一个图像在最顶层，后面的依次在下面。

`css
.element {
  background-image: url('image1.png'), url('image2.jpg');
  background-position: right bottom, left top;
  background-repeat: no-repeat, repeat;
  background-color: #cccccc; /* 作为底层颜色 */
}
`
你也可以为每个背景图像分别设置 ackground-position, ackground-repeat, ackground-size 等属性，同样用逗号分隔。

## 2. ackground-clip

ackground-clip 属性定义了背景的绘制区域。

- **order-box (默认)**: 背景延伸到边框的外边缘。
- **padding-box**: 背景延伸到内边距的外边缘，不会绘制到边框下面。
- **content-box**: 背景只在内容区域内绘制。
- **	ext**: 背景被裁剪为前景文本的形状。这是创建 **渐变文字** 效果的关键。

### 渐变文字效果示例
`css
.gradient-text {
  /* 1. 设置一个渐变背景 */
  background-image: linear-gradient(45deg, #f3ec78, #af4261);

  /* 2. 将背景裁剪为文字形状 */
  background-clip: text;
  -webkit-background-clip: text; /* 兼容性 */

  /* 3. 将文字颜色设为透明，以显示下面的背景 */
  color: transparent;
}
`

## 3. ackground-origin

ackground-origin 属性定义了 ackground-position 属性的原点。它的值与 ackground-clip 类似：
- padding-box (默认)
- order-box
- content-box

例如，如果你希望 ackground-position: top left 是从内容区的左上角开始，而不是内边距区的左上角，你可以设置 ackground-origin: content-box。

## 4. ackground-size

除了常见的 cover 和 contain，ackground-size 也可以接受精确的长度或百分比值。
- ackground-size: 50% 100%; (宽度为容器的50%，高度为100%)
- ackground-size: 300px 150px; (具体的像素值)

## 5. 边框 (Borders)

### order-radius
除了为所有角设置一个值，order-radius 还可以为每个角设置不同的水平和垂直半径，用 / 分隔。
order-radius: <水平半径> / <垂直半径>
这可以让你创建出椭圆形的角，甚至是更复杂的形状。

`css
/* 创建一个类似叶子的形状 */
.leaf {
  border-radius: 50% 0; 
}

/* 为四个角分别设置复杂的半径 */
.complex-shape {
  border-radius: 10px 5% / 20px 25em 30px 35em;
}
`

### order-image
这是一个强大的复合属性，允许你使用图像作为元素的边框。它包含以下子属性：

- **order-image-source**: 边框图像的路径 (url(...))。
- **order-image-slice**: 定义如何切割源图像。它会从图像的四个边缘向内切割，形成九宫格区域：四个角、四条边和中间部分。
- **order-image-width**: 定义边框图像的宽度。
- **order-image-outset**: 定义边框图像超出边框盒的距离。
- **order-image-repeat**: 定义如何填充四条边的区域。
  - stretch (默认): 拉伸。
  - epeat: 重复平铺。
  - ound: 重复平铺，并自动调整以使图像完整显示。
  - space: 重复平铺，并用空白填充间隙。

**示例**:
`css
.frame {
  border: 30px solid transparent;
  padding: 15px;
  border-image: url('border.png') 30 round; /* 简写 */
}
/*
  等同于:
  border-image-source: url('border.png');
  border-image-slice: 30;
  border-image-repeat: round;
*/
`
在这个例子中，浏览器会加载 order.png，从四个边缘向内切割 30px，将四个角放到元素的四个角，然后使用 ound 方式平铺四条边。

---
**下一章**: **[伪类与伪元素](pseudo-classes-elements.md)**
