# 图片与多媒体优化

图片和视频等多媒体资源通常占据网页总下载量的大部分，优化这些资源可以显著提升加载性能和用户体验。本文档介绍图片和多媒体资源的优化策略和最佳实践。

## 目录

- [图片格式选择](#图片格式选择)
- [图片大小优化](#图片大小优化)
- [响应式图片](#响应式图片)
- [图片延迟加载](#图片延迟加载)
- [视频优化](#视频优化)
- [音频优化](#音频优化)
- [SVG优化](#svg优化)
- [图标优化](#图标优化)
- [最佳实践](#最佳实践)

## 图片格式选择

为不同类型的图像选择最合适的格式：

### 现代图片格式

```html
<!-- 使用WebP格式，提供PNG回退 -->
<picture>
  <source srcset="image.webp" type="image/webp">
  <img src="image.png" alt="描述">
</picture>

<!-- 使用AVIF格式，提供WebP和JPEG回退 -->
<picture>
  <source srcset="image.avif" type="image/avif">
  <source srcset="image.webp" type="image/webp">
  <img src="image.jpg" alt="描述">
</picture>
```

### 格式对比

| 格式 | 最佳用途 | 优点 | 缺点 | 浏览器支持 |
|------|----------|------|------|------------|
| JPEG | 照片、复杂图像 | 高压缩率、广泛支持 | 有损、无透明度 | 所有浏览器 |
| PNG | 需要透明度的图像 | 无损、透明度支持 | 文件较大 | 所有浏览器 |
| WebP | 通用替代JPEG/PNG | 比JPEG小30%、支持透明度 | 旧浏览器不支持 | 现代浏览器 |
| AVIF | 下一代格式 | 比WebP小20%、高质量 | 较新、编码慢 | Chrome、Firefox |
| SVG | 图标、简单图形 | 可缩放、小文件 | 不适合照片 | 所有浏览器 |

## 图片大小优化

### 压缩工具

使用工具优化图片大小：

```bash
# 使用sharp库压缩图片
npm install sharp

# 使用imagemin压缩图片
npm install imagemin imagemin-mozjpeg imagemin-pngquant
```

```js
// 使用sharp压缩和转换图片
const sharp = require('sharp');

async function optimizeImage(input, output, options = {}) {
  try {
    const { width, height, quality = 80, format = 'webp' } = options;
    
    let transform = sharp(input);
    
    // 调整大小（如果指定）
    if (width || height) {
      transform = transform.resize({
        width,
        height,
        fit: 'cover',
        withoutEnlargement: true
      });
    }
    
    // 转换格式和质量
    switch (format) {
      case 'webp':
        transform = transform.webp({ quality });
        break;
      case 'avif':
        transform = transform.avif({ quality });
        break;
      case 'jpeg':
      case 'jpg':
        transform = transform.jpeg({ quality });
        break;
      case 'png':
        transform = transform.png({ quality });
        break;
    }
    
    // 输出
    await transform.toFile(output);
    console.log(`图片已优化并保存到 ${output}`);
  } catch (error) {
    console.error('图片优化失败:', error);
  }
}

// 使用示例
optimizeImage('input.jpg', 'output.webp', {
  width: 800,
  quality: 75,
  format: 'webp'
});
```

## 响应式图片

### srcset和sizes属性

为不同屏幕提供不同分辨率的图片：

```html
<!-- 根据设备像素比提供不同分辨率 -->
<img src="image-400.jpg"
     srcset="image-400.jpg 1x,
             image-800.jpg 2x,
             image-1200.jpg 3x"
     alt="响应式图片">

<!-- 根据视口宽度提供不同大小 -->
<img src="image-400.jpg"
     srcset="image-400.jpg 400w,
             image-800.jpg 800w,
             image-1200.jpg 1200w"
     sizes="(max-width: 600px) 100vw,
            (max-width: 1200px) 50vw,
            33vw"
     alt="响应式图片">
```

### picture元素

为不同场景提供不同图片：

```html
<picture>
  <!-- 移动设备竖屏 -->
  <source media="(max-width: 600px) and (orientation: portrait)"
          srcset="image-mobile-portrait.jpg">
          
  <!-- 移动设备横屏 -->
  <source media="(max-width: 600px) and (orientation: landscape)"
          srcset="image-mobile-landscape.jpg">
          
  <!-- 平板设备 -->
  <source media="(max-width: 1200px)"
          srcset="image-tablet.jpg">
          
  <!-- 默认图片 -->
  <img src="image-desktop.jpg" alt="响应式图片">
</picture>
```

## 图片延迟加载

### 原生延迟加载

使用浏览器原生的延迟加载功能：

```html
<!-- 使用loading="lazy"属性 -->
<img src="image.jpg" loading="lazy" alt="延迟加载图片">

<!-- 对iframe也有效 -->
<iframe src="video-player.html" loading="lazy"></iframe>
```

### Intersection Observer

使用Intersection Observer实现自定义延迟加载：

```js
document.addEventListener("DOMContentLoaded", function() {
  const lazyImages = document.querySelectorAll('img[data-src]');
  
  const imageObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        img.src = img.dataset.src;
        
        // 如果有srcset，也设置它
        if (img.dataset.srcset) {
          img.srcset = img.dataset.srcset;
        }
        
        img.classList.add('loaded');
        imageObserver.unobserve(img);
      }
    });
  }, {
    rootMargin: '50px 0px',
    threshold: 0.01
  });
  
  lazyImages.forEach(img => {
    imageObserver.observe(img);
  });
});
```

## 视频优化

### 视频格式选择

为不同浏览器提供多种格式：

```html
<video controls preload="metadata" poster="video-poster.jpg">
  <source src="video.webm" type="video/webm">
  <source src="video.mp4" type="video/mp4">
  您的浏览器不支持视频标签。
</video>
```

### 视频预加载策略

根据需要控制预加载行为：

```html
<!-- 不预加载，用户点击播放按钮时才加载 -->
<video controls preload="none" poster="video-poster.jpg">
  <source src="video.mp4" type="video/mp4">
</video>

<!-- 只预加载元数据（时长、尺寸等） -->
<video controls preload="metadata" poster="video-poster.jpg">
  <source src="video.mp4" type="video/mp4">
</video>

<!-- 自动预加载视频（谨慎使用） -->
<video controls preload="auto" poster="video-poster.jpg">
  <source src="video.mp4" type="video/mp4">
</video>
```

## SVG优化

### SVG压缩

使用SVGO优化SVG文件：

```bash
# 安装SVGO
npm install -g svgo

# 优化SVG
svgo icon.svg -o icon.min.svg
```

### 内联SVG

将SVG直接嵌入HTML减少HTTP请求：

```html
<style>
  .icon {
    width: 24px;
    height: 24px;
    fill: currentColor;
  }
</style>

<!-- 内联SVG图标 -->
<svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path d="M12 2L2 22h20L12 2z"/>
</svg>
```

## 图标优化

### 图标字体 vs SVG图标

比较两种常用的图标实现方式：

| 特性 | 图标字体 | SVG图标 |
|------|---------|--------|
| 文件大小 | 单个HTTP请求加载多个图标 | 可单独加载或内联 |
| 样式控制 | 有限（颜色、大小） | 完全控制（颜色、描边等） |
| 清晰度 | 可能在某些尺寸模糊 | 任何尺寸都清晰 |
| 可访问性 | 较差 | 较好 |

## 最佳实践

### 图片优化清单

1. **选择合适的格式**：使用WebP/AVIF替代JPEG/PNG，使用SVG替代位图图标
2. **正确调整尺寸**：避免加载过大的图片然后在客户端缩小
3. **使用响应式图片**：根据设备提供不同大小的图片
4. **压缩图片**：使用适当的压缩工具减小文件大小
5. **延迟加载**：对首屏以外的图片使用延迟加载
6. **使用CDN**：通过CDN分发图片资源
7. **设置合理的缓存**：为图片设置长期缓存头
8. **优化关键图片**：确保首屏关键图片优先加载
9. **提供占位符**：在图片加载前显示占位符或低质量预览
10. **避免图片尺寸变化**：预设图片尺寸避免布局偏移

## 参考资源

- [使用WebP图像 - web.dev](https://web.dev/serve-images-webp/)
- [响应式图片 - MDN](https://developer.mozilla.org/zh-CN/docs/Learn/HTML/Multimedia_and_embedding/Responsive_images)
- [图片延迟加载 - web.dev](https://web.dev/lazy-loading-images/)
- [视频和音频内容 - MDN](https://developer.mozilla.org/zh-CN/docs/Learn/HTML/Multimedia_and_embedding/Video_and_audio_content)
- [SVG优化指南 - web.dev](https://web.dev/optimize-svg/)