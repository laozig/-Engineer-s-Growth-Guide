# CSS 命名规范：BEM

随着项目变得越来越大、越来越复杂，维护一个清晰、可扩展且无冲突的 CSS 代码库就成了一个巨大的挑战。BEM 是一种流行的 CSS 命名方法论，它通过一套严格的命名规则，帮助我们构建出组件化、可复用且易于理解的样式表。

## 1. BEM 是什么？

BEM 代表 **块（Block）**、**元素（Element）** 和 **修饰符（Modifier）**。它是一种将用户界面划分为独立组件（块）的思维方式。

- **块 (Block)**: 一个独立的、可复用的界面组件。例如 header, menu, utton, search-form。
- **元素 (Element)**: 块的一部分，不能脱离块独立存在。它在语义上与块绑定。例如 menu__item, search-form__input。
- **修饰符 (Modifier)**: 用于定义块或元素的外观、状态或行为。例如 utton--primary, menu__item--disabled。

## 2. BEM 命名约定

BEM 的核心是其命名约定，它清晰地反映了每个类的作用和关系。

- **块 (Block)**: 使用小写单词，单词之间用单个连字符 - 分隔。
  - my-block
  - search-form

- **元素 (Element)**: 在块名后面跟上 **两个下划线 __**，再加上元素名。
  - my-block__element
  - search-form__input

- **修饰符 (Modifier)**: 在块名或元素名后面跟上 **两个连字符 --**，再加上修饰符名。
  - my-block--modifier
  - my-block__element--modifier

修饰符也可以是键值对的形式，用于表示更复杂的状态：
- my-block--theme-dark
- my-block--size-big

### 示例：一个搜索表单

**HTML 结构:**
`html
<form class="search-form search-form--focused">
  <input class="search-form__input" type="text" placeholder="Search...">
  <button class="search-form__button search-form__button--primary">
    Search
  </button>
</form>
`

**CSS/SCSS 结构:**
`css
/* Block */
.search-form {
  display: flex;
  border: 1px solid #ccc;
}

/* Modifier for Block */
.search-form--focused {
  border-color: blue;
}

/* Element */
.search-form__input {
  flex-grow: 1;
  border: none;
  padding: 10px;
}

/* Element */
.search-form__button {
  background-color: #eee;
  border: none;
  padding: 0 15px;
  cursor: pointer;
}

/* Modifier for Element */
.search-form__button--primary {
  background-color: blue;
  color: white;
}
`

## 3. BEM 的优点

1.  **高可读性和自解释性**:
    通过类名 menu__item--disabled，我们可以立即知道：这是一个 menu 组件里的 item 元素，并且它处于 disabled 状态。

2.  **模块化和组件化**:
    BEM 强制你从组件的角度思考 UI。每个块都是一个独立的单元，可以轻松地在项目中移动或复用。

3.  **避免样式冲突**:
    由于所有选择器都以块名开头，它们的作用域被有效地限制在了组件内部。这大大降低了样式冲突的风险，减少了对后代选择器 (.block p) 或高特异性选择器的依赖。

4.  **低特异性**:
    BEM 推荐只使用单个类选择器。这使得所有规则的特异性都保持在一个较低且一致的水平，从而更容易覆盖和扩展样式，也避免了 !important 的滥用。

## 4. BEM 与 SCSS 结合

BEM 与 CSS 预处理器（如 SCSS）是天作之合。SCSS 的嵌套和父选择器 & 可以让我们在编写 BEM 风格的样式时，结构更清晰，代码更少。

`scss
.search-form {
  display: flex;
  border: 1px solid #ccc;

  /* Modifier for Block */
  &--focused {
    border-color: blue;
  }

  /* Element */
  &__input {
    flex-grow: 1;
    border: none;
    padding: 10px;
  }

  /* Element */
  &__button {
    background-color: #eee;
    border: none;
    padding: 0 15px;
    cursor: pointer;

    /* Modifier for Element */
    &--primary {
      background-color: blue;
      color: white;
    }
  }
}
`
这种写法不仅减少了重复，而且在视觉上完美地映射了 BEM 的块、元素、修饰符结构。

---
**下一章**: **[CSS预处理器：Sass/SCSS入门](preprocessors-sass.md)**
