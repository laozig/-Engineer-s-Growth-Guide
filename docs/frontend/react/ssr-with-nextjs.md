# 22. 服务端渲染 (SSR) 与 Next.js

标准的 React 应用（如使用 Create React App 创建的应用）是**客户端渲染 (Client-Side Rendering, CSR)** 的。这意味着浏览器会下载一个几乎为空的 HTML 文件，以及一个巨大的 JavaScript 包。然后，浏览器执行 JavaScript，React 代码运行，最终将内容渲染到页面上。

## CSR 的问题

- **SEO 不友好**: 搜索引擎的爬虫可能只会看到一个空白的 HTML 页面，因为它们可能不会等待 JavaScript 执行完毕。这对于需要被搜索引擎索引的公共页面（如博客、电商产品页）是致命的。
- **首屏加载性能差 (FCP/LCP)**: 用户需要等待整个 JavaScript 包下载并执行完毕后，才能看到有意义的内容。在网络状况不佳或设备性能较差的情况下，用户可能会在很长一段时间内看到白屏。

## 服务端渲染 (Server-Side Rendering, SSR)

SSR 解决了这些问题。在 SSR 模式下，当用户请求一个页面时，服务器会：
1.  在服务器端运行 React 代码。
2.  获取页面所需的数据。
3.  将 React 组件渲染成一个完整的 HTML 字符串。
4.  将这个包含所有内容的 HTML 直接发送给浏览器。

浏览器接收到 HTML 后可以立即渲染出完整的页面内容，大大提升了首屏加载速度 (FCP/LCP)。之后，浏览器再下载 JavaScript 包，并在后台"激活"(hydrate) 这个页面，使其成为一个可交互的单页面应用。

## Next.js: React 的生产级框架

从零开始配置一个支持 SSR、代码分割、路由和热重载的 React 应用是非常复杂的。**Next.js** 是一个基于 React 的开源框架，它为你提供了生产环境所需的所有功能，开箱即用。

Next.js 是目前实现 React SSR 和其他预渲染模式的**事实标准**。

### Next.js 的核心特性

- **多种渲染模式**: 支持 SSR、静态网站生成 (Static Site Generation, SSG)、增量静态再生 (Incremental Static Regeneration, ISR) 和 CSR。你可以为每个页面选择最适合的渲染策略。
- **文件系统路由**: `pages` 目录下的文件会自动成为应用的路由。例如 `pages/about.js` 会自动映射到 `/about` 路径。
- **内置优化**: 自动进行代码分割、图片优化、字体优化等。
- **API 路由**: 可以在 `pages/api` 目录下创建无服务器 (serverless) API 端点。
- **强大的数据获取方法**: 提供了 `getServerSideProps` (用于SSR) 和 `getStaticProps` (用于SSG) 等专用函数，用于在渲染前获取数据。

### 创建一个 Next.js 应用

创建 Next.js 项目最简单的方式是使用 `create-next-app`。
```bash
npx create-next-app@latest my-next-app
```

### Next.js 中的 SSR

在 Next.js 中，要为一个页面启用 SSR，你只需要从该页面文件（例如 `pages/posts/[id].js`）中导出一个名为 `getServerSideProps` 的 `async` 函数。

**示例：一个动态的博客文章页面**

假设我们有一个页面用于显示单篇博客文章，其内容需要从外部 API 获取。

```jsx
// pages/posts/[id].js

// 1. 页面组件
function Post({ post }) {
  // `post` prop 是由 getServerSideProps 提供的
  if (!post) {
    return <div>Post not found.</div>;
  }

  return (
    <div>
      <h1>{post.title}</h1>
      <p>{post.body}</p>
    </div>
  );
}

// 2. getServerSideProps 函数
// 这个函数只会在服务器端运行，永远不会在浏览器端运行。
export async function getServerSideProps(context) {
  // `context` 对象包含了请求相关的信息，如 params, req, res 等。
  const { params } = context;
  const { id } = params;

  try {
    // 从 API 获取数据
    const res = await fetch(`https://api.example.com/posts/${id}`);
    const post = await res.json();

    if (!post) {
      return { notFound: true }; // 返回 404 页面
    }

    // 将数据通过 props 传递给页面组件
    return {
      props: {
        post, // `post` 将作为 Post 组件的 prop
      },
    };
  } catch (error) {
    // 处理错误
    return {
      props: {
        post: null,
      },
    };
  }
}

export default Post;
```

**工作流程**:
1.  用户访问 `/posts/123`。
2.  Next.js 服务器捕获到这个请求，并调用 `pages/posts/[id].js` 文件中的 `getServerSideProps` 函数，同时将 `{ id: '123' }` 作为 `context.params` 传入。
3.  `getServerSideProps` 函数在**服务器端**执行 `fetch` 请求，获取到文章数据。
4.  函数返回一个包含 `props` 的对象。
5.  Next.js 在**服务器端**使用这些 `props` 来渲染 `Post` 组件，生成最终的 HTML。
6.  服务器将这个预渲染好的 HTML 发送给浏览器。
7.  浏览器立即显示页面内容。之后，React 会在客户端进行 "hydration"，让页面变得可交互。

## 静态网站生成 (SSG)

对于那些内容不经常变化的页面（如博客文章、文档、营销页面），在**构建时 (build time)** 就生成静态 HTML 文件是更好的选择。这就是 SSG。

在 Next.js 中，实现 SSG 需要使用 `getStaticProps` 和 `getStaticPaths` (对于动态路由)。SSG 生成的页面可以被部署到 CDN，访问速度极快。

## 结论

虽然客户端渲染 (CSR) 对于许多应用（特别是需要登录的后台应用）来说已经足够，但对于需要良好 SEO 和极致首屏性能的公开网站，**服务端渲染 (SSR)** 或 **静态网站生成 (SSG)** 是必不可少的。

**Next.js** 作为一个功能全面的 React 框架，极大地简化了 SSR 和 SSG 的实现。它通过提供文件系统路由、优化的数据获取方法和内置的性能优化，让开发者可以专注于业务逻辑，同时构建出高性能、对 SEO 友好的现代 Web 应用。对于任何严肃的、面向公众的 React 项目，Next.js 都应该是首选的技术方案。 