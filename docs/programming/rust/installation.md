# Rust安装与环境配置

本文档介绍如何安装Rust编程语言及配置开发环境，包括工具链安装、编辑器设置和常用开发工具的使用说明。

## 目录

- [安装Rust](#安装Rust)
  - [在Windows上安装](#在Windows上安装)
  - [在macOS上安装](#在macOS上安装)
  - [在Linux上安装](#在Linux上安装)
- [验证安装](#验证安装)
- [更新与卸载](#更新与卸载)
- [配置开发环境](#配置开发环境)
  - [集成开发环境(IDE)](#集成开发环境IDE)
  - [命令行工具](#命令行工具)
- [Cargo包管理器](#Cargo包管理器)
- [第一个Rust程序](#第一个Rust程序)
- [常见问题解决](#常见问题解决)

## 安装Rust

Rust通过`rustup`工具进行安装，这是Rust的工具链安装器和版本管理工具。

### 在Windows上安装

1. 访问[rustup官网](https://rustup.rs/)下载并运行安装程序，或者使用PowerShell：

```powershell
# 下载并运行安装脚本
Invoke-WebRequest -Uri https://win.rustup.rs -OutFile rustup-init.exe
.\rustup-init.exe
```

2. 按照安装向导进行操作，选择默认安装选项即可。
3. 安装完成后，重启终端以使环境变量生效。

### 在macOS上安装

在macOS上，可以使用Terminal执行以下命令安装Rust：

```bash
# 下载并运行安装脚本
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

选择默认安装选项，安装过程将自动配置环境变量。

### 在Linux上安装

在大多数Linux发行版上，可以使用与macOS相同的方式安装：

```bash
# 下载并运行安装脚本
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

对于某些Linux发行版，可能需要额外安装C编译器和开发工具：

```bash
# Debian/Ubuntu
sudo apt install build-essential

# Fedora
sudo dnf install gcc

# Arch Linux
sudo pacman -S base-devel
```

## 验证安装

安装完成后，运行以下命令验证Rust是否安装成功：

```bash
# 检查Rust编译器版本
rustc --version

# 检查Cargo包管理器版本
cargo --version

# 检查Rustup版本
rustup --version
```

如果上述命令能够显示版本信息，则表示安装成功。

## 更新与卸载

### 更新Rust

Rust可以通过rustup工具进行更新：

```bash
# 更新Rust工具链
rustup update
```

### 卸载Rust

如需卸载Rust，可以使用：

```bash
# 卸载Rust工具链
rustup self uninstall
```

## 配置开发环境

### 集成开发环境(IDE)

#### Visual Studio Code (推荐)

1. 下载并安装[Visual Studio Code](https://code.visualstudio.com/)
2. 安装以下扩展：
   - `rust-analyzer`：提供代码补全、错误检查等功能
   - `CodeLLDB`：用于调试Rust应用
   - `crates`：用于管理依赖版本
   - `Even Better TOML`：提供Cargo.toml文件的支持

安装后配置：
- 打开VS Code设置
- 搜索"rust-analyzer"
- 根据需要调整配置项

#### JetBrains IntelliJ IDEA

1. 安装[IntelliJ IDEA](https://www.jetbrains.com/idea/)（社区版或旗舰版均可）
2. 安装"Rust"插件：
   - 打开设置->插件->市场
   - 搜索并安装"Rust"插件
   - 重启IDE

#### 其他编辑器

- **Vim/NeoVim**：安装rust.vim、vim-lsp等插件
- **Emacs**：安装rustic、lsp-mode等包
- **Sublime Text**：安装LSP和Rust-Enhanced插件

### 命令行工具

以下是一些有用的Rust命令行工具：

```bash
# 安装代码格式化工具
rustup component add rustfmt

# 安装代码分析工具
rustup component add clippy

# 安装文档工具，用于本地查看文档
rustup component add rust-docs

# 安装交叉编译目标（示例：针对Windows 64位）
rustup target add x86_64-pc-windows-msvc
```

## Cargo包管理器

Cargo是Rust的包管理器和构建工具，通常随Rust一同安装。以下是Cargo的常用命令：

```bash
# 创建新项目
cargo new hello_world

# 构建项目（开发模式）
cargo build

# 构建项目（发布模式，优化性能）
cargo build --release

# 运行项目
cargo run

# 检查代码是否能编译，但不生成可执行文件
cargo check

# 运行测试
cargo test

# 生成文档
cargo doc

# 发布库到crates.io
cargo publish
```

## 第一个Rust程序

安装完成后，让我们创建并运行一个简单的Rust程序：

1. 创建新项目：

```bash
cargo new hello_rust
cd hello_rust
```

2. Cargo会自动创建项目结构：

```
hello_rust/
├── Cargo.toml       # 项目配置文件
└── src/
    └── main.rs      # 主源代码文件
```

3. `main.rs`已经包含了一个简单的示例程序：

```rust
fn main() {
    println!("你好，世界！");
}
```

4. 运行程序：

```bash
cargo run
```

应该可以看到输出：`你好，世界！`

## 常见问题解决

### 安装过程中的网络问题

如果在中国大陆地区安装遇到网络问题，可以考虑使用镜像源：

```bash
# 设置环境变量
export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

# 然后再运行安装脚本
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

对于Cargo，可以配置`.cargo/config`文件：

```toml
[source.crates-io]
replace-with = 'ustc'

[source.ustc]
registry = "https://mirrors.ustc.edu.cn/crates.io-index"
```

### 权限问题

在Linux或macOS上，如果遇到权限问题：

```bash
# 确保安装目录有正确权限
chmod -R u+w $HOME/.cargo
chmod -R u+w $HOME/.rustup
```

### 缺少依赖

如果编译过程中提示缺少系统依赖：

```bash
# Debian/Ubuntu
sudo apt-get install pkg-config libssl-dev

# Fedora
sudo dnf install pkgconfig openssl-devel

# Arch Linux
sudo pacman -S pkg-config openssl
```

### 更新路径问题

如果命令未找到，可能需要手动添加路径：

```bash
# 将以下内容添加到~/.bashrc、~/.zshrc或其他shell配置文件
export PATH="$HOME/.cargo/bin:$PATH"

# 然后重新加载配置
source ~/.bashrc  # 或对应的配置文件
```

---

完成上述步骤后，您已成功安装并配置了Rust开发环境。接下来，您可以参考[基础语法](basics.md)文档开始学习Rust编程。 