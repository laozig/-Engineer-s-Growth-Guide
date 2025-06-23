# 响应式图片高级技巧：srcset, sizes 与 <picture>

在前面的章节中，我们使用 max-width: 100% 解决了图片的 **布局** 响应问题。但一个更严峻的 **性能** 问题依然存在：无论在大屏幕还是小屏幕上，用户加载的都是同一张高分辨率的大图。这对于使用移动网络、屏幕较小的用户来说，是极大的带宽和性能浪费。

本章将深入探讨解决这一问题的现代HTML技术：srcset、sizes 和 <picture> 元素。

## 1. 问题场景分类

响应式图片问题主要分为两大类：

1.  **分辨率切换 (Resolution Switching)**:
    - **场景**: 在不同尺寸的屏幕上，我们希望展示 **内容相同但分辨率不同** 的图片。小屏幕加载小图，大屏幕加载大图。
    - **解决方案**: <img> 标签的 srcset 和 sizes 属性。

2.  **艺术指导 (Art Direction)**:
    - **场景**: 我们希望在不同屏幕尺寸上展示 **完全不同构图或裁剪** 的图片。例如，桌面端显示一张包含人物和背景的全景图，而移动端则只显示人物的面部特写。
    - **解决方案**: <picture> 元素。

## 2. 分辨率切换：srcset 和 sizes

srcset 和 sizes 是 <img> 标签的两个属性，它们协同工作，让浏览器能够根据设备情况智能地选择最合适的图片进行加载。

### a. srcset: 提供图片资源列表

srcset 属性允许你提供一个以逗号分隔的图片URL列表，并为每个URL附加一个描述符，告诉浏览器该图片的具体信息。

描述符有两种类型：

- **x 描述符 (像素密度描述符)**:
  - 用于根据设备的 **像素密度 (DPR, Device Pixel Ratio)** 来切换图片。
  - 1x 对应 DPR 为 1 的标准屏幕。
  - 2x 对应 DPR 为 2 的 Retina 屏幕。

  `html
  <img srcset="image-1x.jpg 1x, 
               image-2x.jpg 2x"
       src="image-1x.jpg" alt="描述">
  `
  - **工作原理**: 浏览器检测到自己的DPR是2，就会选择加载 image-2x.jpg。
  - **缺点**: 它只考虑了像素密度，没有考虑图片的实际显示尺寸。在小尺寸的Retina屏幕上，可能仍然加载了不必要的大图。因此，它只适用于固定尺寸图片的场景。

- **w 描述符 (宽度描述符)**:
  - 这是 **更常用、更强大** 的方式。它告诉浏览器每张图片的 **真实宽度**（以像素为单位）。
  - **注意**: 它不是告诉浏览器在多宽的屏幕下用这张图，而只是陈述图片本身有多宽。

  `html
  <img srcset="image-small.jpg   480w,
               image-medium.jpg  800w,
               image-large.jpg  1600w"
       src="image-medium.jpg" alt="描述">
  `

### b. sizes: 告知浏览器图片的显示尺寸

仅仅提供图片宽度列表（w描述符）还不够，浏览器不知道这张图片在你的页面布局中究竟会显示多大。sizes 属性正是用来告诉浏览器这件事的。

sizes 属性包含一个以逗号分隔的媒体条件-长度列表。浏览器会从上到下检查，使用第一个匹配的媒体条件所对应的长度值。

`html
<img srcset="image-small.jpg   480w,
             image-medium.jpg  800w,
             image-large.jpg  1600w"
     sizes="(max-width: 600px) 90vw,
            (max-width: 900px) 50vw,
            800px"
     src="image-medium.jpg" alt="描述">
`

**sizes 属性解读**:
- (max-width: 600px) 90vw: 当视口宽度小于等于600px时，这张图片的显示宽度是视口宽度的90%。
- (max-width: 900px) 50vw: 当视口宽度小于等于900px时，这张图片的显示宽度是视口宽度的50%。
- 800px: 在以上条件都不满足的情况下（即视口宽度大于900px时），图片的默认显示宽度是800px。

### c. 浏览器如何决策？

1.  浏览器首先查看 sizes 属性，根据当前的视口宽度计算出图片 **即将要显示** 的CSS像素宽度。
    - 假设当前设备视口是 400px，它匹配了第一个条件 (max-width: 600px) 90vw，于是计算出图片的显示宽度是 400 * 0.9 = 360px。
2.  浏览器查看设备的DPR（假设是 2x）。
3.  浏览器将显示宽度乘以DPR，得到它所 **需要** 的图片的最小真实宽度：360px * 2 = 720px。
4.  浏览器查看 srcset 列表，寻找一个宽度最接近且不小于 720w 的图片。
    - 480w (太小)
    - 800w (完美，比720w大一点，最合适)
    - 1600w (太大，浪费)
5.  最终，浏览器决定加载 image-medium.jpg (800w)。

通过这种方式，srcset 和 sizes 实现了真正智能的、基于性能的图片选择。

## 3. 艺术指导：<picture> 元素

当你需要的不仅仅是分辨率切换，而是想在不同断点提供完全不同内容的图片时，就需要使用 <picture> 元素。

<picture> 元素本身不显示任何东西，它像一个包装器，内部包含一个或多个 <source> 元素和一个必需的 <img> 元素。

`html
<picture>
  <!-- 在大屏幕上，显示横向的全景图 -->
  <source media="(min-width: 1024px)" srcset="landscape.jpg">
  
  <!-- 在中等屏幕上，显示方形的裁剪图 -->
  <source media="(min-width: 768px)" srcset="square.jpg">
  
  <!-- 默认情况下，以及在小屏幕上，显示纵向的人物特写图 -->
  <!-- <img> 元素是必须的，作为最终的回退和图像内容的实际载体 -->
  <img src="portrait.jpg" alt="描述">
</picture>
`

**工作原理**:
1.  浏览器从上到下解析 <source> 元素。
2.  它会检查每个 <source> 的 media 属性，这与CSS媒体查询完全相同。
3.  一旦找到第一个匹配当前设备环境的 <source>，浏览器就会使用该 source 的 srcset 属性去加载图片，并 **忽略** 所有后续的 <source> 和 <img> 的 srcset。
4.  如果没有任何 <source> 匹配，或者浏览器不支持 <picture> 元素，它就会渲染 <img> 元素。<img> 在这里起到了 **回退（fallback）** 和 **内容载体** 的双重作用（lt 文本、class 等都写在 <img> 上）。

### 结合现代图片格式

<picture> 也是提供 WebP, AVIF 等现代图片格式并优雅降级的最佳方式。这时我们使用 <source> 的 	ype 属性。

`html
<picture>
  <source type="image/avif" srcset="image.avif">
  <source type="image/webp" srcset="image.webp">
  <img src="image.jpeg" alt="描述">
</picture>
`
浏览器会选择它支持的第一个 <source> 类型。一个支持AVIF的浏览器会加载 .avif 文件并停止解析，而一个只支持WebP的浏览器会跳过第一个，加载第二个。老旧的浏览器则会直接渲染 <img> 标签。

你甚至可以在同一个 <source> 上同时使用 media 和 	ype，并在 srcset 中提供多种分辨率，实现极其精细的控制。

---
**下一章**: **[优雅的响应式排版](responsive-typography.md)**
