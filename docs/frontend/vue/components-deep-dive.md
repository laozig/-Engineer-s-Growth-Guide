# 8. 组件深入：插槽、动态组件、异步组件

除了 Props 和事件，Vue 组件还有一些更高级的特性，可以帮助我们构建更灵活、更强大的应用程序，例如插槽、动态组件和异步组件。

## 插槽 (Slots)

插槽用于**内容分发**。它允许你在父组件中定义一块内容，然后将这块内容"插入"到子组件的指定位置。这使得子组件可以更加通用和可复用。

### 基础用法

在子组件中，使用 `<slot>` 标签作为内容的占位符。

```vue
<!-- components/FancyButton.vue -->
<template>
  <button class="fancy-btn">
    <slot></slot> <!-- 插槽出口 -->
  </button>
</template>
```

在父组件中，放置在 `<FancyButton>` 标签内的任何内容都将被视为插槽内容。

```vue
<!-- App.vue -->
<FancyButton>
  Click me! <!-- 插槽内容 -->
</FancyButton>
```

渲染出的 HTML 将是：
```html
<button class="fancy-btn">
  Click me!
</button>
```

### 具名插槽 (Named Slots)

有时我们需要多个插槽。`<slot>` 元素有一个特殊的 attribute `name`，可以用来定义具名插槽。

```vue
<!-- components/BaseLayout.vue -->
<template>
  <div class="container">
    <header>
      <slot name="header"></slot>
    </header>
    <main>
      <slot></slot> <!-- 默认插槽 -->
    </main>
    <footer>
      <slot name="footer"></slot>
    </footer>
  </div>
</template>
```

要为一个具名插槽提供内容，我们需要使用一个带 `v-slot` 指令的 `<template>` 元素，并以 `v-slot` 的参数的形式提供其名称。`v-slot` 有对应的缩写 `#`。

```vue
<!-- App.vue -->
<BaseLayout>
  <template #header>
    <h1>Here might be a page title</h1>
  </template>

  <template #default> <!-- 可简写为 <template> -->
    <p>A paragraph for the main content.</p>
    <p>And another one.</p>
  </template>

  <template #footer>
    <p>Here's some contact info</p>
  </template>
</BaseLayout>
```

### 作用域插槽 (Scoped Slots)

有时，让插槽内容能够访问子组件中才有的数据是很有用的。作用域插槽就是为此而生的。子组件可以将数据作为 attribute 绑定到 `<slot>` 元素上，父组件可以通过 `v-slot` 来接收这些数据。

```vue
<!-- components/MyComponent.vue -->
<script setup>
const message = 'hello'
</script>
<template>
  <slot :text="message" :count="1"></slot>
</template>
```

```vue
<!-- App.vue -->
<MyComponent v-slot="slotProps">
  {{ slotProps.text }} {{ slotProps.count }}
</MyComponent>
```

## 动态组件

动态组件允许你在多个组件之间动态切换，而无需使用 `v-if`/`v-else-if`。这通过 Vue 的 `<component>` 元素和特殊的 `is` attribute 来实现。

```vue
<script setup>
import { ref, shallowRef } from 'vue'
import Home from './Home.vue'
import Posts from './Posts.vue'
import Archive from './Archive.vue'

const currentTab = ref('Home')
const tabs = { Home, Posts, Archive }
// 使用 shallowRef 避免不必要的深度响应
const currentComponent = shallowRef(tabs[currentTab.value])

</script>

<template>
  <div class="demo">
    <button v-for="(_, tab) in tabs" @click="currentTab = tab">
      {{ tab }}
    </button>
    
    <!-- 在多个组件间动态切换 -->
    <component :is="tabs[currentTab]"></component>
  </div>
</template>
```

## 异步组件

在大型应用中，我们可能需要将应用分割成小一些的代码块，并且只在需要的时候才从服务器加载一个模块。为了简化这个过程，Vue 提供了 `defineAsyncComponent` 函数：

```js
import { defineAsyncComponent } from 'vue'

const AsyncComp = defineAsyncComponent(() => {
  return new Promise((resolve, reject) => {
    // ...从服务器获取组件
    resolve(/* 获取到的组件 */)
  })
})
// ... 像使用其他一般组件一样使用 `AsyncComp`
```

在实践中，异步组件经常与路由结合使用，例如 Vue Router 就内置了对异步组件的支持，可以实现路由级别的代码分割（懒加载）。 