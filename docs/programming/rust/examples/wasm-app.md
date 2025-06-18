# 示例项目：WebAssembly应用

WebAssembly (Wasm) 是一种可移植的二进制指令格式，可作为Web浏览器中JavaScript的高性能替代品。Rust对WebAssembly有一流的支持，允许开发者编写在浏览器中以接近原生速度运行的代码。

本示例将指导你创建一个简单的Rust项目，编译为WebAssembly，并在一个HTML页面中通过JavaScript调用它。

## 项目目标

1.  使用`wasm-pack`工具构建一个Rust库项目。
2.  编写一个Rust函数，并将其暴露给JavaScript。
3.  将Rust代码编译为WebAssembly模块。
4.  创建一个HTML页面，加载并与WebAssembly模块交互。

## 技术栈与工具

-   **Rust**: 核心编程语言。
-   **`wasm-pack`**: 用于构建、测试和发布Rust-Wasm项目的工具。
-   **`wasm-bindgen`**: Rust与JavaScript之间交互的桥梁，便于类型转换和函数调用。
-   **Web服务器**: 用于在本地提供HTML和Wasm文件服务（例如Python的`http.server`或Node.js的`serve`）。

## 环境准备

1.  **安装Rust**: 如果你还没有安装，请访问[rust-lang.org](https://www.rust-lang.org/)。
2.  **安装`wasm-pack`**:
    ```bash
    cargo install wasm-pack
    ```

## 项目初始化

使用`cargo`创建一个新的库项目，并进入该目录：
```bash
cargo new --lib wasm_example
cd wasm_example
```

## 编写Rust代码

### 1. 配置`Cargo.toml`

我们需要添加`wasm-bindgen`作为依赖项。同时，需要将crate类型设置为`cdylib`，这是生成WebAssembly模块所必需的。

`Cargo.toml`:
```toml
[package]
name = "wasm_example"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
wasm-bindgen = "0.2"
```

### 2. 创建一个可被JavaScript调用的函数

我们将编写一个简单的函数，它接收一个名字（字符串）并返回一句问候语。

`src/lib.rs`:
```rust
use wasm_bindgen::prelude::*;

// 当此模块被实例化时，这个函数将被调用。
// 我们可以用它来设置一些初始状态，例如设置panic hook。
#[wasm_bindgen(start)]
pub fn main_js() -> Result<(), JsValue> {
    // 在Wasm中发生panic时，提供更详细的错误信息到开发者控制台。
    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();
    Ok(())
}

// 导出一个函数到JavaScript。
#[wasm_bindgen]
pub fn greet(name: &str) -> String {
    format!("你好, {}! 👋 这条消息来自Rust + WebAssembly。", name)
}
```

-   `#[wasm_bindgen]`: 这个属性宏是`wasm-bindgen`的核心。它标记了希望在JavaScript和Rust之间传递的项。
-   `use wasm_bindgen::prelude::*;`: 导入所有常用的`wasm-bindgen`项。
-   `greet`函数接收一个字符串切片`&str`，并返回一个`String`。`wasm-bindgen`会自动处理这两种类型与JavaScript字符串之间的转换。
-   `#[wasm_bindgen(start)]`: 标记一个启动函数，它在Wasm模块加载后立即执行一次。我们通常用它来初始化一些东西，比如`console_error_panic_hook`，这个库可以在Rust代码panic时将错误信息打印到浏览器的开发者控制台，非常便于调试。为了使用它，还需要在`Cargo.toml`中添加：
    ```toml
    [dependencies]
    # ... wasm-bindgen
    console_error_panic_hook = { version = "0.1.6", optional = true }

    [features]
    default = ["console_error_panic_hook"]
    ```

## 编译为WebAssembly

现在，使用`wasm-pack`将Rust代码编译为WebAssembly。在项目根目录下运行：
```bash
wasm-pack build --target web
```

-   `wasm-pack build`: 执行编译过程。
-   `--target web`: 指定构建目标。`web`目标生成的代码可以直接在现代浏览器中使用ES模块导入。

执行成功后，你会在项目根目录下发现一个新的`pkg`目录。它的结构大致如下：
```
pkg/
├── wasm_example_bg.wasm      # 编译后的Wasm二进制文件
├── wasm_example.js           # JavaScript "胶水"代码，用于加载和调用Wasm
├── wasm_example.d.ts         # TypeScript类型定义
└── package.json              # npm包定义文件
```
`wasm_example.js`文件是关键，它封装了加载`.wasm`文件和调用导出函数的复杂性。

## 创建Web前端

现在，我们创建一个简单的HTML文件来使用我们刚刚生成的Wasm模块。

1.  在项目根目录下创建一个`index.html`文件。

`index.html`:
```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rust + Wasm 示例</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding-top: 50px; }
        input { padding: 8px; margin-right: 10px; }
        button { padding: 8px 12px; }
        p { margin-top: 20px; font-size: 1.2em; }
    </style>
</head>
<body>
    <h1>Rust WebAssembly 交互示例</h1>
    <input id="name-input" type="text" placeholder="输入你的名字" value="WebAssembly">
    <button id="greet-button">打招呼</button>
    <p id="greeting-output"></p>

    <script type="module">
        // 导入 `pkg/wasm_example.js` 中的所有内容，最重要的是默认导出的init函数
        import init, { greet } from './pkg/wasm_example.js';

        async function run() {
            // 初始化Wasm模块
            await init();

            const nameInput = document.getElementById('name-input');
            const greetButton = document.getElementById('greet-button');
            const greetingOutput = document.getElementById('greeting-output');

            greetButton.addEventListener('click', () => {
                const name = nameInput.value;
                if (name) {
                    // 调用从Rust导出的greet函数
                    const greeting = greet(name);
                    greetingOutput.textContent = greeting;
                }
            });

            // 页面加载时立即触发一次
            greetButton.click();
        }

        run();
    </script>
</body>
</html>
```

-   `<script type="module">`: 我们使用ES模块来导入JavaScript胶水代码。
-   `import init, { greet } from './pkg/wasm_example.js'`: 导入`init`函数（用于初始化Wasm）和我们自己定义的`greet`函数。
-   `await init()`: 在调用任何Wasm函数之前，必须先调用并等待`init()`函数完成。它负责加载和编译Wasm二进制文件。
-   之后，我们就可以像调用普通的JavaScript函数一样调用`greet(name)`。

## 运行Web应用

由于浏览器安全策略的限制（CORS），你不能直接通过`file://`协议打开`index.html`来加载Wasm模块。你需要一个本地Web服务器。

1.  **如果你安装了Python**:
    ```bash
    # 在项目根目录（与index.html同级）运行
    python -m http.server
    ```
2.  **如果你安装了Node.js**:
    你可以安装一个简单的服务器包`serve`：
    ```bash
    npm install -g serve
    serve .
    ```

启动服务器后，在浏览器中打开 `http://localhost:8000` (或服务器指定的其他端口)。你应该能看到一个输入框和一个按钮。点击按钮，就会调用Rust代码并显示返回的问候语。

## 总结

这个示例展示了使用Rust和`wasm-pack`创建一个简单的WebAssembly应用是多么直接。`wasm-bindgen`极大地简化了Rust和JavaScript之间的互操作性，让我们可以专注于业务逻辑，而不是复杂的底层细节。

从这里开始，你可以探索更复杂的功能，例如：
-   在Rust中直接操作DOM。
-   处理更复杂的数据结构。
-   利用Rust的性能优势进行计算密集型任务（如图像处理、物理模拟等）。
-   结合像`wgpu`这样的库在浏览器中进行图形渲染。 