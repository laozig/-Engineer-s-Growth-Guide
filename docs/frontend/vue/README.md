# Vue.js 应用开发指南

本指南旨在为开发者提供一个从入门到精通的Vue.js学习路径，全面覆盖Vue.js的核心概念、现代化的Composition API、庞大的生态系统以及企业级的最佳实践。

## 学习路径

### 第一部分：Vue.js 基础与核心概念

1.  [x] [Vue.js 简介与环境搭建](introduction-setup.md)
2.  [x] [模板语法与指令](template-syntax.md)
3.  [x] [组件基础与 Props](components-props.md)
4.  [x] [事件处理与v-model](event-handling-v-model.md)
5.  [x] [计算属性与侦听器](computed-properties-watchers.md)
6.  [x] [条件渲染与列表渲染](conditional-rendering-lists.md)
7.  [x] [Class 与 Style 绑定](class-style-binding.md)

### 第二部分：深入 Vue.js 组件

8.  [x] [组件深入：插槽、动态组件、异步组件](components-deep-dive.md)
9.  [x] [Composition API: `setup` 与响应式基础](composition-api-setup.md)
10. [x] [Composition API: 生命周期钩子](composition-api-lifecycle-hooks.md)
11. [x] [Composition API: 依赖注入](composition-api-dependency-injection.md)
12. [x] [自定义指令](custom-directives.md)

### 第三部分：Vue.js 生态系统与工具

13. [x] [路由管理: Vue Router](vue-router.md)
14. [x] [状态管理: Pinia](state-management-pinia.md)
15. [x] [状态管理: Vuex (传统方案)](state-management-vuex.md)
16. [x] [UI 组件库: Element Plus & Ant Design Vue](ui-component-libraries.md)
17. [x] [构建工具: Vite](build-tool-vite.md)
18. [x] [测试: Vitest & Vue Testing Library](testing-vue-apps.md)

### 第四部分：高级主题与最佳实践

19. [x] [性能优化](performance-optimization.md)
20. [x] [TypeScript 集成](typescript-integration.md)
21. [x] [服务端渲染 (SSR) 与 Nuxt.js](ssr-with-nuxtjs.md)
22. [x] [高级状态管理模式](advanced-state-management.md)

## Vue.js 学习路径图

```mermaid
graph TD
    A[开始 Vue.js 学习之旅] --> B[基础与核心概念]
    B --> B1[Vue.js 简介与环境搭建]
    B --> B2[模板语法与指令]
    B --> B3[组件基础与 Props]
    B --> B4[事件处理与v-model]
    B --> B5[计算属性与侦听器]
    B --> B6[条件渲染与列表渲染]
    B --> B7[Class 与 Style 绑定]
    
    A --> C[深入 Vue.js 组件]
    C --> C1[组件深入：插槽、动态组件、异步组件]
    C --> C2[Composition API: setup 与响应式基础]
    C --> C3[Composition API: 生命周期钩子]
    C --> C4[Composition API: 依赖注入]
    C --> C5[自定义指令]
    
    A --> D[Vue.js 生态系统与工具]
    D --> D1[路由管理: Vue Router]
    D --> D2[状态管理: Pinia]
    D --> D3[状态管理: Vuex]
    D --> D4[UI 组件库]
    D --> D5[构建工具: Vite]
    D --> D6[测试: Vitest & Vue Testing Library]
    
    A --> E[高级主题与最佳实践]
    E --> E1[性能优化]
    E --> E2[TypeScript 集成]
    E --> E3[服务端渲染 (SSR) 与 Nuxt.js]
    E --> E4[高级状态管理模式]
    
    style B1 fill:#d4f4dd
    style B2 fill:#d4f4dd
    style B3 fill:#d4f4dd
    style B4 fill:#d4f4dd
    style B5 fill:#d4f4dd
    style B6 fill:#d4f4dd
    style B7 fill:#d4f4dd
    
    style C1 fill:#d4f4dd
    style C2 fill:#d4f4dd
    style C3 fill:#d4f4dd
    style C4 fill:#d4f4dd
    style C5 fill:#d4f4dd
    
    style D1 fill:#d4f4dd
    style D2 fill:#d4f4dd
    style D3 fill:#d4f4dd
    style D4 fill:#d4f4dd
    style D5 fill:#d4f4dd
    style D6 fill:#d4f4dd
    
    style E1 fill:#d4f4dd
    style E2 fill:#d4f4dd
    style E3 fill:#d4f4dd
    style E4 fill:#d4f4dd
```

## 如何贡献

欢迎您通过提交Pull Request来改进本指南。详情请参阅 [CONTRIBUTING.md](../../../CONTRIBUTING.md)。 