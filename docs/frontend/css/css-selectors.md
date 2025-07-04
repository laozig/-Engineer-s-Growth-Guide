﻿# CSS 选择器全解

CSS选择器是CSS的基石，它定义了样式规则将应用于哪些HTML元素。熟练掌握选择器是高效编写CSS的前提。

## 1. 基础选择器

| 类型 | 选择器 | 示例 | 描述 |
| :--- | :--- | :--- | :--- |
| **通用选择器** | * | * { color: #333; } | 匹配页面上所有元素。 |
| **类型选择器** | element | p { line-height: 1.5; } | 匹配所有指定类型的元素，如 <p>。 |
| **类选择器** | .classname | .btn { background: blue; } | 匹配所有 class 属性包含 classname 的元素。 |
| **ID选择器** | #idname | #header { position: fixed; } | 匹配 id 属性为 idname 的元素。**ID在页面中必须唯一。** |
| **属性选择器** | [attr], [attr=val] | [target="_blank"] | 匹配具有特定属性或属性值的元素。 |

### 属性选择器的变体

- [attr]：匹配所有带有 ttr 属性的元素。
- [attr=value]：匹配 ttr 属性值 **完全等于** alue 的元素。
- [attr~=value]：匹配 ttr 属性值包含 alue (以空格分隔的单词) 的元素。
- [attr|=value]：匹配 ttr 属性值以 alue 或 alue- 开头的元素。
- [attr^=value]：匹配 ttr 属性值以 alue **开头**的元素。
- [attr$=value]：匹配 ttr 属性值以 alue **结尾**的元素。
- [attr*=value]：匹配 ttr 属性值 **包含** alue 子字符串的元素。
- [attr operator value i]：(CSS4新增) i 修饰符使属性值在匹配时不区分大小写。

## 2. 组合选择器

组合选择器用于描述元素之间的关系。

| 类型 | 选择器 | 示例 | 描述 |
| :--- | :--- | :--- | :--- |
| **后代组合器** | A B (空格) | rticle p | 匹配所有被 A 元素包含的 B 元素 (不一定是直接子元素)。 |
| **子代组合器** | A > B | ul > li | 匹配所有作为 A 元素 **直接子元素** 的 B 元素。 |
| **相邻兄弟组合器**| A + B | h2 + p | 匹配所有紧跟在 A 元素 **之后** 的同级 B 元素。 |
| **通用兄弟组合器**| A ~ B | h2 ~ p | 匹配所有在 A 元素 **之后** 的同级 B 元素 (不一定紧邻)。 |
| **列组合器** | A || B (实验性) | colgroup || col| 匹配 A 范围内的 B 元素，常用于表格列。|

## 3. 伪类选择器

伪类选择器用于为元素的特定状态添加样式，如被鼠标悬停、链接被访问过等。

| 分类 | 选择器 | 描述 |
| :--- | :--- | :--- |
| **用户行为** | :hover, :active, :focus | 当用户鼠标悬停、激活或聚焦在元素上时。 |
| **链接状态** | :link, :visited | 匹配未被访问和已被访问的链接。 |
| **UI元素状态**| :enabled, :disabled, :checked, :indeterminate | 匹配表单元素的可用、禁用、选中等状态。 |
| **结构化** | :root, :empty | 匹配文档的根元素和没有子元素的元素。 |
| **
th-系列**| :nth-child(n), :nth-last-child(n), :nth-of-type(n) | 匹配同级元素中的特定位置。
 可以是数字、关键字(odd, even)或公式(2n+1)。|
| **only-系列**| :only-child, :only-of-type | 当元素是其父元素的唯一子元素或唯一类型的子元素时匹配。 |
| **逻辑组合** | :is(s1, s2), :where(s1, s2), :not(s) | :is 和 :where 匹配任何选择器列表中的一个，:not 排除匹配某个选择器的元素。 |

**:is() vs :where()**
- :is() 的特异性由其参数中特异性最高的选择器决定。
- :where() 的特异性始终为 0。这使得它在覆盖样式时非常有用。

## 4. 伪元素选择器

伪元素用于为元素的特定部分添加样式，例如在元素内容前后插入内容，或为文本的第一行/第一个字母设置样式。

| 选择器 | 描述 |
| :--- | :--- |
| ::before | 在元素内容的 **前面** 创建一个伪元素。 |
| ::after | 在元素内容的 **后面** 创建一个伪元素。 |
| ::first-line | 为元素的第一行文本应用样式。 |
| ::first-letter | 为元素的第一个字母应用样式。 |
| ::selection | 为用户高亮选中的内容应用样式。 |
| ::marker | 为列表项的标记（如 <li> 的点或数字）应用样式。 |
| ::placeholder | 为表单元素的占位文本应用样式。 |

**要点**:
- 伪元素 ::before 和 ::after 必须与 content 属性一起使用。
- 在旧版 CSS 中，伪元素使用单冒号 (:before)。现代 CSS 推荐使用双冒号 (::before) 以区分伪类和伪元素。

---
**下一章**: **[深入理解盒子模型](box-model.md)**
