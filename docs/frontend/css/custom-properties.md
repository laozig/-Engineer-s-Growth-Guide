# CSS 变量 (自定义属性)

CSS 自定义属性 (Custom Properties)，通常被称为 CSS 变量，允许我们在 CSS 中声明和使用可复用的值。这极大地增强了 CSS 的动态性和可维护性，是现代 CSS 开发的利器。

## 1. 声明和使用变量

### 声明变量
变量的声明使用两个连字符 -- 开头，后跟变量名。它们必须在 CSS 选择器的大括号内声明。
将变量声明在 :root 伪类选择器中，可以使其成为全局变量，在整个文档中都可访问。

`css
:root {
  --primary-color: #3498db;
  --base-font-size: 16px;
  --main-spacing: 20px;
}
`

### 使用变量
使用 ar() 函数来获取变量的值。ar() 函数可以接受第二个参数，作为备用值 (fallback value)，当第一个参数的变量未定义时，将使用备用值。

`css
.button {
  background-color: var(--primary-color);
  color: white;
}

.container {
  padding: var(--main-spacing);
  font-size: var(--base-font-size, 1rem); /* 如果--base-font-size未定义，则使用1rem */
}
`

## 2. 作用域

CSS 变量遵循标准的层叠和继承规则，这意味着它们是有作用域的。
- 在 :root 中声明的变量是全局的。
- 在特定选择器（如 .dark-theme）中声明的变量是局部的，只在该选择器及其后代元素中生效。
- 如果局部变量与全局变量同名，局部变量会覆盖（遮蔽）全局变量。

这使得 CSS 变量在实现主题切换 (Theming) 时非常强大。

## 3. 使用场景

### 场景一：主题切换 (Theming)

这是 CSS 变量最经典的应用。我们可以为不同的主题（如暗色模式）定义一套不同的变量值。

`css
/* 默认 (亮色) 主题 */
:root {
  --background-color: #ffffff;
  --text-color: #333333;
  --primary-color: #007bff;
}

/* 暗色主题 */
.dark-theme {
  --background-color: #1a1a1a;
  --text-color: #f0f0f0;
  --primary-color: #58a6ff;
}

/* 应用样式的组件 */
body {
  background-color: var(--background-color);
  color: var(--text-color);
  transition: background-color 0.3s, color 0.3s;
}

a {
  color: var(--primary-color);
}
`
然后，只需用 JavaScript 给 <body> 或 <html> 元素添加/移除 .dark-theme 类，整个网站的颜色主题就会随之平滑地改变。

`javascript
document.body.classList.toggle('dark-theme');
`

### 场景二：维护一致的UI系统

在设计系统中，颜色、间距、字体大小等都应该是一致的。使用 CSS 变量可以将这些设计令牌 (Design Tokens) 集中管理。

`css
:root {
  /* Colors */
  --color-brand: #ff6347;
  --color-success: #2ecc71;
  
  /* Spacing */
  --space-sm: 8px;
  --space-md: 16px;
  --space-lg: 24px;

  /* Fonts */
  --font-size-body: 1rem;
  --font-size-heading: 1.5rem;
}

.card {
  padding: var(--space-md);
  border: 1px solid var(--color-brand);
}

.title {
  font-size: var(--font-size-heading);
  margin-bottom: var(--space-sm);
}
`
当需要调整设计系统的基础间距或主色调时，只需修改 :root 中的一个值即可，所有使用该变量的地方都会自动更新。

## 4. 与 JavaScript 交互

CSS 变量可以与 JavaScript 进行非常方便的交互。

### 读取变量
`javascript
const element = document.querySelector('.element');
const styles = getComputedStyle(element);
const primaryColor = styles.getPropertyValue('--primary-color'); // '#3498db'
`

### 设置变量
`javascript
const element = document.querySelector('.element');
// 设置或修改 .element 作用域内的 --primary-color 变量
element.style.setProperty('--primary-color', 'red'); 
`
这个特性非常有用，例如可以根据用户的输入动态改变颜色，或者根据鼠标位置实现一些炫酷的交互效果。

## CSS 变量 vs. Sass 变量

| 特性 | CSS 变量 (--var) | Sass 变量 ($var) |
| :--- | :--- | :--- |
| **处理时间** | **运行时** (浏览器处理) | **编译时** (Sass编译器处理) |
| **作用域** | 遵循DOM结构和CSS层叠规则 | 词法作用域（在代码块内） |
| **动态性** | **是**，可以在运行时通过JS修改 | **否**，编译后变为静态值 |
| **继承** | **是**，可以被后代元素继承 | **否** |

**结论**: Sass 变量非常适合用于那些在项目构建后就不会再改变的值（如媒体查询断点）。而 CSS 变量则非常适合用于需要在运行时动态改变的值（如主题颜色、响应用户交互等）。两者可以结合使用，各取所长。

---
**下一章**: **[高级背景与边框效果](advanced-backgrounds-borders.md)**
