# 4. 事件处理与 v-model

处理用户交互是前端开发的核心任务之一。Vue 提供了 `v-on` 指令来监听 DOM 事件，并提供了 `v-model` 指令来实现表单输入的双向绑定。

## 监听事件

我们可以使用 `v-on` 指令 (通常缩写为 `@` 符号) 来监听 DOM 事件，并在触发时运行一些 JavaScript 代码。

### 内联事件处理器

```vue
<script setup>
import { ref } from 'vue'
const count = ref(0)
</script>

<template>
  <button @click="count++">Add 1</button>
  <p>Count is: {{ count }}</p>
</template>
```

### 方法事件处理器

对于更复杂的逻辑，`v-on` 也可以接受一个方法名。

```vue
<script setup>
import { ref } from 'vue'
const name = ref('Vue.js')

function greet(event) {
  alert(`Hello ${name.value}!`)
  // `event` 是 DOM 原生事件
  if (event) {
    alert(event.target.tagName)
  }
}
</script>

<template>
  <button @click="greet">Greet</button>
</template>
```

### 事件修饰符

Vue 为 `v-on` 提供了一些**事件修饰符**，用于处理常见的事件处理任务，例如 `event.preventDefault()` 或 `event.stopPropagation()`。

-   `.stop`: 调用 `event.stopPropagation()`。
-   `.prevent`: 调用 `event.preventDefault()`。
-   `.capture`: 添加事件侦听器时使用 capture 模式。
-   `.self`: 只当事件是从侦听器绑定的元素本身触发时才触发处理函数。
-   `.once`: 点击事件将只会触发一次。
-   `.passive`: `.`passive` 修饰符尤其能够提升移动端的性能。

```vue
<!-- 链式调用 -->
<a @click.stop.prevent="doThat"></a>

<!-- 只有修饰符 -->
<form @submit.prevent></form>
```

## `v-model` 与表单输入绑定

`v-model` 指令可以在表单的 `<input>`、`<textarea>` 及 `<select>` 元素上创建双向数据绑定。它会根据控件类型自动选取正确的方法来更新元素。

`v-model` 本质上是一个语法糖。它负责监听用户的输入事件来更新数据，并在数据改变时对表单元素进行更新。

### 文本输入

```vue
<script setup>
import { ref } from 'vue'
const message = ref('')
</script>

<template>
  <p>Message is: {{ message }}</p>
  <input v-model="message" placeholder="edit me" />
</template>
```

### 复选框

单个复选框，绑定到布尔值：

```vue
<input type="checkbox" id="checkbox" v-model="checked" />
<label for="checkbox">{{ checked }}</label>
```

多个复选框，绑定到同一个数组：

```vue
<input type="checkbox" id="jack" value="Jack" v-model="checkedNames">
<input type="checkbox" id="john" value="John" v-model="checkedNames">
```

### 单选按钮

```vue
<input type="radio" id="one" value="One" v-model="picked" />
<input type="radio" id="two" value="Two" v-model="picked" />
```

### 选择器

```vue
<select v-model="selected">
  <option disabled value="">Please select one</option>
  <option>A</option>
  <option>B</option>
  <option>C</option>
</select>
```

### `v-model` 修饰符

-   `.lazy`: 默认情况下，`v-model` 在每次 `input` 事件后同步数据。添加 `.lazy` 修饰符，从而转变为在 `change` 事件之后进行同步。
-   `.number`: 如果想自动将用户的输入值转为数值类型，可以给 `v-model` 添加 `.number` 修饰符。
-   `.trim`: 如果要自动过滤用户输入的首尾空白字符，可以给 `v-model` 添加 `.trim` 修饰符。

```vue
<input v-model.lazy="msg" />
<input v-model.number="age" />
<input v-model.trim="msg" />
``` 