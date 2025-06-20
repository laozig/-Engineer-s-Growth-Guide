# 3. 组件基础与 Props

组件是可复用的 Vue 实例，它们拥有自己的名称、状态和视图。通过将 UI 拆分为独立的、可复用的组件，我们可以构建出大型、可维护的应用程序。

## 单文件组件 (SFC)

在 Vue 中，我们通常使用一种类似于 HTML 文件格式的文件来定义一个组件，这种文件被称为**单文件组件 (Single-File Component)**，文件扩展名为 `.vue`。

一个 `.vue` 文件通常包含三个部分：
-   `<template>`: 组件的 HTML 模板。
-   `<script setup>`: 组件的逻辑，使用 Composition API。
-   `<style scoped>`: 组件的 CSS 样式，`scoped` attribute 可以确保样式只作用于当前组件。

```vue
<!-- components/MyComponent.vue -->
<script setup>
import { ref } from 'vue'
const greeting = ref('Hello from MyComponent!')
</script>

<template>
  <p class="greeting">{{ greeting }}</p>
</template>

<style scoped>
.greeting {
  color: red;
  font-weight: bold;
}
</style>
```

## 使用组件

要使用一个子组件，我们需要在父组件中导入它并注册。在 `<script setup>` 中，导入的组件可以直接在模板中使用。

```vue
<!-- App.vue -->
<script setup>
// 导入组件
import MyComponent from './components/MyComponent.vue'
</script>

<template>
  <h1>Here is my application</h1>
  <MyComponent />
  <MyComponent />
</template>
```

如上所示，组件可以被多次复用。每次使用 `<MyComponent />` 时，都会创建一个新的 `MyComponent` 实例。

## Props

Props 是一种将数据从父组件传递到子组件的机制。子组件需要显式地声明它所期望接收的 props。

### 声明 Props

在子组件中，使用 `defineProps`宏来声明 props。

```vue
<!-- components/BlogPost.vue -->
<script setup>
// 使用 defineProps 声明 props
const props = defineProps(['title', 'author'])
</script>

<template>
  <div class="blog-post">
    <h4>{{ title }}</h4>
    <p>By {{ author }}</p>
  </div>
</template>
```

### 传递 Props

父组件可以通过 attribute 的方式将数据传递给子组件。

```vue
<!-- App.vue -->
<script setup>
import BlogPost from './components/BlogPost.vue'
import { ref } from 'vue'

const posts = ref([
  { id: 1, title: 'My journey with Vue', author: 'John Doe' },
  { id: 2, title: 'Blogging with Vue', author: 'Jane Smith' },
  { id: 3, title: 'Why Vue is so fun', author: 'Steve White' }
])
</script>

<template>
  <h1>My Blog</h1>
  <BlogPost
    v-for="post in posts"
    :key="post.id"
    :title="post.title"
    :author="post.author"
  />
</template>
```

注意我们是如何使用 `v-bind` (缩写为 `:`) 来动态地传递 props 的。

### Prop 校验

为了使组件更健壮，我们可以为 props 定义校验规则，例如指定类型、是否必需、默认值等。

```vue
<script setup>
defineProps({
  // 类型检查
  title: String,
  
  // 多个可能的类型
  likes: [String, Number],

  // 必填的字符串
  author: {
    type: String,
    required: true
  },

  // 有默认值的数字
  commentIds: {
    type: Array,
    default: () => []
  },
  
  // 自定义校验函数
  status: {
    validator(value) {
      // The value must match one of these strings
      return ['published', 'draft', 'archived'].includes(value)
    }
  }
})
</script>
```

Props 是构建组件通信的基础。遵循**单向数据流**的原则——数据总是从父级流向子级——有助于我们构建可预测且易于理解的应用。 