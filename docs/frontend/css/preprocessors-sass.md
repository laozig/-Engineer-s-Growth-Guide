# CSS 预处理器：Sass/SCSS 入门

CSS 本身是一门相对简单的语言，但随着项目复杂度的增加，原生 CSS 在代码复用、逻辑组织和可维护性方面会显得力不从心。CSS 预处理器 (Preprocessor) 是一种脚本语言，它扩展了 CSS 的功能，让我们能以更像编程语言的方式来编写样式，最终再将其编译成普通的 CSS 文件。

Sass (Syntactically Awesome StyleSheets) 是最流行、最成熟的 CSS 预处理器之一。

## 1. Sass vs. SCSS

Sass 有两种语法格式：

1.  **Sass (旧语法)**:
    - 使用缩进而不是大括号来表示代码块。
    - 不使用分号。
    - 文件扩展名为 .sass。
    - 它的语法更简洁，但与原生 CSS 不兼容。

2.  **SCSS (Sassy CSS)**:
    - 使用与 CSS 完全相同的语法，即用大括号和分号。
    - 任何有效的 CSS 文件都是一个有效的 SCSS 文件。
    - 文件扩展名为 .scss。
    - **这是目前推荐和主流的语法**，因为它学习曲线平缓，且易于将现有 CSS 项目迁移过来。

**本指南将专注于 SCSS 语法。**

## 2. 核心功能

### 变量 (Variables)
允许你存储和复用值，如颜色、字体、间距等。使用 $ 符号来声明变量。

`scss
// 声明变量
$primary-color: #8a4baf;
$base-font-size: 16px;

// 使用变量
body {
  color: $primary-color;
  font-size: $base-font-size;
}
`
**与 CSS 变量的区别**: SCSS 变量在 **编译时** 被处理，编译后的 CSS 文件中不再存在变量，而是替换为具体的值。CSS 变量则是在 **运行时** 由浏览器处理。

### 嵌套 (Nesting)
允许你像 HTML 一样嵌套 CSS 规则，这使得样式表的结构更清晰，并减少了重复编写父选择器。

`scss
// SCSS
nav {
  height: 50px;
  background-color: #eee;

  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  li {
    display: inline-block;
  }

  a {
    display: block;
    padding: 0 15px;
    line-height: 50px;
    text-decoration: none;

    &:hover { // 使用 & 引用父选择器
      background-color: #ddd;
    }
  }
}
`
**编译后的 CSS**:
`css
nav { height: 50px; background-color: #eee; }
nav ul { list-style: none; margin: 0; padding: 0; }
nav li { display: inline-block; }
nav a { display: block; padding: 0 15px; line-height: 50px; text-decoration: none; }
nav a:hover { background-color: #ddd; }
`
**注意**: 应避免过度嵌套（建议不超过3-4层），否则会导致生成过高特异性的选择器，难以覆盖。

### 模块化 (@import 和 @use)

SCSS 允许你将样式表分割成多个小的、可维护的文件（称为 "partials"），然后在主文件中将它们导入。
- **Partials**: 局部文件，通常以下划线 _ 开头命名（如 _reset.scss, _variables.scss）。下划线告诉 Sass 这个文件只是一个模块，不应该被单独编译成 CSS 文件。
- **@import (旧)**: 这是传统的导入方式，但它会将所有变量和混合宏都变为全局的，容易引起命名冲突。
- **@use (新)**: 这是 Sass 团队现在推荐的模块系统（称为 "Sass Modules"）。它通过为每个导入的模块创建命名空间来解决全局冲突问题。

**使用 @use 的示例**:
`scss
// _variables.scss
$primary-color: #8a4baf;

// main.scss
@use 'variables'; // 导入模块

body {
  color: variables.$primary-color; // 通过命名空间使用变量
}
`

### 混合宏 (Mixins)
混合宏允许你定义一组可复用的 CSS 声明，并在需要的地方通过 @include 来调用。混合宏还可以接受参数。

`scss
// 定义一个混合宏
@mixin flex-center($direction: row) {
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: $direction;
}

.box {
  @include flex-center; // 调用混合宏
}

.container {
  @include flex-center(column); // 调用并传入参数
}
`

### 继承 (@extend)
允许一个选择器继承另一个选择器的所有样式。

`scss
.message {
  border: 1px solid #ccc;
  padding: 10px;
  color: #333;
}

.success-message {
  @extend .message;
  border-color: green;
}
`
**@mixin vs @extend**:
- 使用 @extend 会将选择器分组，生成更少的重复代码，但可能产生意想不到的副作用（如改变选择器顺序或位置）。
- 使用 @mixin 会生成更多的重复代码，但它更安全、更可预测，并且可以接受参数。
- **通常推荐优先使用 @mixin**，只在确定要建立清晰的语义关系时才使用 @extend。

### 内置函数
Sass 提供了丰富的内置函数来处理颜色、数字、字符串等，例如 darken(), lighten(), gba(), percentage()。

---
**下一章**: **[CSS性能优化](performance-optimization.md)**
