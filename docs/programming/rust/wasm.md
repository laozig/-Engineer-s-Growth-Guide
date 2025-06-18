# Rust 与 WebAssembly (Wasm)

WebAssembly (简称 Wasm) 是一种新兴的、可移植的、体积小且加载快的二进制指令格式，它可以在现代 Web 浏览器中以接近原生的速度运行。Rust 拥有一流的 WebAssembly 支持，被认为是编写 Wasm 的最佳语言之一。它允许开发者将性能密集型的计算任务从 JavaScript 转移到 Rust，从而显著提升 Web 应用的性能。

## 1. 为什么选择 Rust 开发 WebAssembly?

- **性能**: Rust 编译的 Wasm 模块运行速度非常快，接近原生性能，非常适合计算密集型任务，如图形渲染、游戏物理、数据分析等。
- **内存安全**: Rust 的编译时安全保证延续到了 Wasm，有助于编写更可靠、更安全的代码。
- **无运行时**: Rust 不需要垃圾回收器或庞大的运行时，这使得生成的 `.wasm` 文件体积非常小，加载速度快。
- **与 JavaScript 的互操作性**: `wasm-bindgen` 工具链使得在 Rust 和 JavaScript 之间传递复杂数据类型（如字符串、结构体、JS 对象）变得异常简单。
- **丰富的生态**: 社区提供了大量专门为 Wasm 优化的库，涵盖了从 WebGL 渲染到虚拟 DOM 操作的方方面面。

## 2. 核心工具链

- **`wasm-pack`**:
  - 这是官方推荐的用于构建、测试和发布 Rust-Wasm crate 的一站式工具。
  - 它会自动调用编译器 (`cargo build --target wasm32-unknown-unknown`)，然后运行 `wasm-bindgen`，并生成一个包含 `.wasm` 文件和相应 JavaScript "胶水"代码的 npm 包。

- **`wasm-bindgen`**:
  - 这是 Rust 与 JavaScript 之间实现无缝互操作的桥梁。
  - 它通过 `#[wasm_bindgen]` 宏来理解你想在两种语言之间共享的数据类型和函数。
  - 它不仅能让 JavaScript 调用 Rust 函数，还能让 Rust 调用 JavaScript 函数、操作 DOM、处理事件等。

- **`cargo-generate`**:
  - 一个用于从预定义模板快速创建新项目的工具。官方提供了 `wasm-pack` 项目模板。

## 3. 构建第一个 Rust-Wasm 项目

### 步骤 1: 安装工具

```bash
# 安装 wasm-pack
cargo install wasm-pack
# 安装项目模板工具
cargo install cargo-generate
```

### 步骤 2: 从模板创建项目

```bash
cargo generate --git https://github.com/rustwasm/wasm-pack-template
# 当提示项目名称时，输入 "wasm-game-of-life" 或你喜欢的名字
```

### 步骤 3: 探索代码 (`src/lib.rs`)

生成的项目中会有一个简单的示例。让我们看一个更有趣的例子：从 Rust 导出一个 `alert` 函数。

```rust
use wasm_bindgen::prelude::*;

// 从 JavaScript 的 `window` 对象中导入 `alert` 函数
#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

// 导出一个 `greet` 函数给 JavaScript 使用
#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}
```
- **`#[wasm_bindgen]`**: 这个宏是所有魔法的核心。
- **`extern "C"` 块**: 用于声明你想从 JavaScript 中导入的函数或类型。
- **`pub fn`**: 使用 `#[wasm_bindgen]` 标记的公共函数将被导出，可供 JavaScript 调用。

### 步骤 4: 构建 Wasm 模块

在项目根目录下运行 `wasm-pack`：

```bash
wasm-pack build
```

这会在项目下创建一个 `pkg` 目录，其结构如下：
```
pkg/
├── wasm_game_of_life_bg.wasm  # 编译后的 Wasm 二进制文件
├── wasm_game_of_life.js       # JS 胶水代码 (ES 模块)
├── wasm_game_of_life.d.ts     # TypeScript 类型定义
└── package.json               # npm 包定义文件
```

### 步骤 5: 在网页中使用

现在，你可以将这个 `pkg` 目录当作一个 npm 包来使用。

1.  在项目根目录下创建一个 `index.html` 文件：
    ```html
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>Hello wasm-pack!</title>
      </head>
      <body>
        <script type="module">
          import init, { greet } from './pkg/wasm_game_of_life.js';

          async function run() {
            // 初始化 Wasm 模块
            await init();
            // 调用导出的 Rust 函数
            greet("WebAssembly");
          }

          run();
        </script>
      </body>
    </html>
    ```

2.  启动一个本地 Web 服务器来托管这些文件（例如，使用 `miniserve` 或 `python -m http.server`）。

3.  在浏览器中打开页面，你应该会看到一个弹窗显示 "Hello, WebAssembly!"。

## 4. 与 JavaScript 的高级交互

`wasm-bindgen` 支持非常丰富的交互方式：

- **传递字符串、数字**: 如上例所示，非常直接。
- **传递结构体**:
  - 在 Rust 结构体上添加 `#[wasm_bindgen]`，它的字段可以被 JS 访问。
- **操作 DOM**:
  - `web-sys` crate 提供了对所有 Web API（如 `window`, `document`, `console`）的原始绑定。你可以用它来创建元素、附加事件监听器等。
- **处理 `JsValue`**:
  - `wasm_bindgen::JsValue` 类型代表了任意的 JavaScript 值，允许你处理动态数据或 JS 对象。
- **异步和 `Promise`**:
  - `wasm-bindgen-futures` crate 允许你在 Rust 的 `Future` 和 JavaScript 的 `Promise` 之间进行转换。

**`web-sys` 示例**:
```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn append_paragraph(text: &str) {
    let window = web_sys::window().expect("no global `window` exists");
    let document = window.document().expect("should have a document on window");
    let body = document.body().expect("document should have a body");

    let p = document.create_element("p").unwrap();
    p.set_inner_html(text);
    body.append_child(&p).unwrap();
}
```

## 5. 性能与优化

- **代码体积**:
  - 始终在 `release` 模式下构建 (`wasm-pack build --release`)。
  - 在 `Cargo.toml` 中开启链接时优化（LTO）和设置 `opt-level = "s"` 或 `opt-level = "z"` 可以进一步减小体积。
  - 使用 `wasm-opt` 工具（`wasm-pack` 可以自动调用）来对生成的 `.wasm` 文件进行后处理优化。
- **性能**:
  - 避免在 Rust 和 JavaScript 之间频繁地来回传递大量数据，因为每次跨越边界都有一定的开销。尽量将复杂的计算完整地保留在 Rust 端。

## 总结

Rust 和 WebAssembly 的结合为 Web 开发开辟了新的可能性。
- **`wasm-pack`** 和 **`wasm-bindgen`** 提供了世界级的工具链，简化了开发和集成流程。
- 你可以利用 Rust 的全部威力（性能、可靠性、生态系统）来构建以前在浏览器中难以实现的高性能组件。
- 从游戏、数据可视化到科学计算和媒体处理，Rust+Wasm 正在成为将桌面级应用体验带到 Web 的关键技术。 