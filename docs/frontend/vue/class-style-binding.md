# 7. Class 与 Style 绑定

数据绑定一个常见需求是操作元素的 class 列表和内联样式。因为 `class` 和 `style` 都是 attribute，我们可以用 `v-bind` 处理它们：只需要计算出表达式最终的字符串。不过，字符串拼接麻烦且易错。因此，Vue 专门为 `class` 和 `style` 的 `v-bind` 用法提供了特殊的功能增强。

## 绑定 HTML Class

### 绑定对象

我们可以给 `:class` (v-bind:class 的缩写) 传递一个对象来动态地切换 class：

```vue
<script setup>
import { ref, computed } from 'vue'

const isActive = ref(true)
const hasError = ref(false)

const classObject = computed(() => ({
  active: isActive.value,
  'text-danger': hasError.value
}))
</script>

<template>
  <div :class="classObject"></div>
</template>
```

上面的语法表示 `active` class 的存在与否将取决于数据 property `isActive` 的真假值。

### 绑定数组

我们也可以给 `:class` 绑定一个数组，以应用一个 class 列表：

```vue
<script setup>
import { ref } from 'vue'

const activeClass = ref('active')
const errorClass = ref('text-danger')
</script>

<template>
  <div :class="[activeClass, errorClass]"></div>
</template>
```

如果你也想在数组中有条件地渲染一个 class，你可以使用三元表达式：

```vue
<div :class="[isActive ? activeClass : '', errorClass]"></div>
```

### 在组件上使用

当你在一个单根组件上使用 `class` attribute 时，这些 class 将被添加到该组件的根元素上。

```vue
<!-- MyComponent.vue -->
<template>
  <p class="foo bar">Hi!</p>
</template>
```

```vue
<!-- App.vue -->
<MyComponent class="baz" />
```

渲染出的 HTML 将会是:
```html
<p class="foo bar baz">Hi!</p>
```

## 绑定内联样式

### 绑定对象

`:style` 支持绑定 JavaScript 对象值，对应的是 [HTML 元素的 `style` property](https://developer.mozilla.org/en-US/docs/Web/API/HTMLElement/style)。Vue 会自动为 camelCase 形式的 CSS property 添加前缀。

```vue
<script setup>
import { ref } from 'vue'

const activeColor = ref('red')
const fontSize = ref(30)
</script>

<template>
  <div :style="{ color: activeColor, fontSize: fontSize + 'px' }"></div>
</template>
```

直接绑定一个样式对象通常更好，这会让模板更清晰：

```vue
<script setup>
import { ref, computed } from 'vue'

const activeColor = ref('red')
const fontSize = ref(30)

const styleObject = computed(() => ({
  color: activeColor.value,
  'font-size': fontSize.value + 'px' // 也可以使用 kebab-case
}))
</script>

<template>
  <div :style="styleObject"></div>
</template>
```

### 绑定数组

我们还可以给 `:style` 绑定一个包含多个样式对象的数组。这些对象会被合并后应用到同一元素上：

```vue
<div :style="[baseStyles, overridingStyles]"></div>
```

### 自动添加前缀

当 `:style` 使用需要浏览器引擎前缀的 CSS property 时，例如 `transform`，Vue.js 会自动侦测并添加相应的前缀。 