# 12. 自定义指令

自定义指令是 Vue 提供的一种机制，用于直接操作 DOM 元素。当你需要进行底层 DOM 访问时，自定义指令是很有用的，这些操作通常是标准组件和内置指令所不能实现的。

## 自定义指令的注册

### 全局注册

你可以在应用层面注册一个全局自定义指令：

```js
// main.js
const app = createApp(App)

// 注册一个全局自定义指令 `v-focus`
app.directive('focus', {
  // 指令的生命周期钩子
  mounted(el) {
    // 当元素被插入到 DOM 中时，获取焦点
    el.focus()
  }
})
```

### 局部注册

在单个组件中，你可以使用 `directives` 选项来注册局部指令：

```vue
<script>
export default {
  directives: {
    focus: {
      mounted(el) {
        el.focus()
      }
    }
  }
}
</script>
```

在 `<script setup>` 中，你可以通过以 `v` 开头的变量名称来定义一个局部指令：

```vue
<script setup>
// 注册一个局部自定义指令，通过前缀 "v" 来定义
const vFocus = {
  mounted(el) {
    el.focus()
  }
}
</script>

<template>
  <input v-focus />
</template>
```

## 指令钩子函数

一个自定义指令被定义为一个包含钩子函数的对象。这些钩子函数会在特定的时机被调用：

```js
const myDirective = {
  // 在绑定元素的 attribute 前或事件监听器应用前调用
  created(el, binding, vnode, prevVnode) {},
  // 在元素被插入到 DOM 前调用
  beforeMount(el, binding, vnode, prevVnode) {},
  // 在绑定元素的父组件及自己的所有子节点都挂载完成后调用
  mounted(el, binding, vnode, prevVnode) {},
  // 在包含组件的 VNode 更新之前调用
  beforeUpdate(el, binding, vnode, prevVnode) {},
  // 在包含组件的 VNode 及其子 VNode 全部更新之后调用
  updated(el, binding, vnode, prevVnode) {},
  // 在绑定元素的父组件卸载之前调用
  beforeUnmount(el, binding, vnode, prevVnode) {},
  // 在绑定元素的父组件卸载之后调用
  unmounted(el, binding, vnode, prevVnode) {}
}
```

其中，`el` 是指令绑定的元素，`binding` 是一个包含有关指令详情的对象。

## 指令的参数、修饰符和值

自定义指令可以接收参数、修饰符和值，这些都可以通过 `binding` 对象访问：

```vue
<div v-example:foo.bar="baz"></div>
```

```js
const vExample = {
  mounted(el, binding) {
    console.log(binding.value) // "baz"
    console.log(binding.arg) // "foo"
    console.log(binding.modifiers) // { bar: true }
  }
}
```

## 简化形式

对于仅使用 `mounted` 和 `updated` 钩子函数且两者行为相同的指令，你可以提供一个函数来简化语法：

```js
app.directive('color', (el, binding) => {
  // 这会在 `mounted` 和 `updated` 时都调用
  el.style.color = binding.value
})
```

```vue
<div v-color="'red'">Text will be red</div>
```

## 实际应用

### 自动聚焦

一个经典的例子是 `v-focus` 指令，用于使元素在页面加载时自动获取焦点：

```js
app.directive('focus', {
  mounted(el) {
    el.focus()
  }
})
```

### 点击外部

一个检测点击元素外部的指令，通常用于下拉菜单或模态框：

```js
app.directive('click-outside', {
  mounted(el, binding) {
    el._clickOutsideHandler = (event) => {
      if (!(el === event.target || el.contains(event.target))) {
        binding.value(event)
      }
    }
    document.addEventListener('click', el._clickOutsideHandler)
  },
  unmounted(el) {
    document.removeEventListener('click', el._clickOutsideHandler)
  }
})
```

```vue
<div v-click-outside="closeDropdown">
  <!-- dropdown content -->
</div>
```

### 滚动指示器

一个滚动指示器指令，用于显示用户在页面上的滚动进度：

```js
app.directive('scroll-indicator', {
  mounted(el) {
    window.addEventListener('scroll', () => {
      const scrollTop = document.documentElement.scrollTop
      const scrollHeight = document.documentElement.scrollHeight
      const clientHeight = document.documentElement.clientHeight
      const scrollPercentage = (scrollTop / (scrollHeight - clientHeight)) * 100
      el.style.width = scrollPercentage + '%'
    })
  }
})
```

```vue
<div class="scroll-indicator-container">
  <div v-scroll-indicator class="scroll-indicator"></div>
</div>
```

## 组件 vs. 指令

自定义指令和组件都是抽象和复用代码的方式，但它们有不同的使用场景：

- **组件**是主要的代码重用和抽象单元，适用于创建独立的 UI 元素。
- **指令**主要用于直接 DOM 操作，通常是对现有元素添加底层行为。

当需要操作 DOM 并且这种操作不适合封装在组件中时，自定义指令是一个很好的选择。 