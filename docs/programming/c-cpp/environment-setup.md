# C/C++ 环境搭建

要开始编写 C/C++ 代码，你首先需要一个**编译器**和一个**代码编辑器**。编译器是将你编写的源代码（`.c` 或 `.cpp` 文件）转换成计算机可以执行的机器码的工具。代码编辑器则提供了编写和组织代码的环境。

本指南将推荐使用 **Visual Studio Code (VS Code)** 作为代码编辑器，并介绍如何在 Windows、macOS 和 Linux 三大主流操作系统上安装编译器。

## 1. 安装 Visual Studio Code

VS Code 是一款免费、开源且功能强大的代码编辑器，它拥有庞大的扩展生态系统，对 C/C++ 的支持非常好。

1.  访问 [VS Code 官方网站](https://code.visualstudio.com/)。
2.  下载并安装适用于你操作系统的版本。

### 安装 C/C++ 扩展

安装 VS Code 后，你需要安装由微软官方提供的 C/C++ 扩展包，它提供了代码补全、调试、代码导航等核心功能。

1.  打开 VS Code。
2.  点击左侧活动栏的"扩展"图标（或按 `Ctrl+Shift+X`）。
3.  在搜索框中输入 `C/C++`。
4.  找到名为 **"C/C++ Extension Pack"** 的扩展，点击 **Install**。

## 2. 安装编译器

### 在 Windows 上

Windows 用户有两个主流选择：MinGW-w64 (GCC) 或 Microsoft Visual C++ (MSVC)。我们推荐 **MinGW-w64**，因为它提供了与 Linux 和 macOS 上一致的 GCC 工具链体验。

1.  **访问 MSYS2 网站**：访问 [MSYS2 官方网站](https://www.msys2.org/) 并下载安装程序。MSYS2 是一个软件分发和构建平台，可以方便地安装 MinGW-w64。
2.  **安装 MSYS2**：运行下载的安装程序，并遵循默认设置。
3.  **安装 MinGW-w64 工具链**：安装完成后，打开 MSYS2 终端（从开始菜单搜索 "MSYS2 MSYS"）。在终端中运行以下命令：
    ```bash
    pacman -Syu
    pacman -S --needed base-devel mingw-w64-ucrt-x86_64-toolchain
    ```
    在提示确认时，按 `Enter` 继续。
4.  **添加环境变量**：这是关键一步。你需要将编译器的 `bin` 目录添加到系统的 `PATH` 环境变量中。
    -   安装目录通常是 `C:\msys64`。
    -   需要添加的路径是 `C:\msys64\ucrt64\bin`。
    -   操作步骤：
        1.  在 Windows 搜索中输入"环境变量"并选择"编辑系统环境变量"。
        2.  点击"环境变量..."按钮。
        3.  在"系统变量"下找到 `Path` 变量，点击"编辑"。
        4.  点击"新建"，然后粘贴路径 `C:\msys64\ucrt64\bin`。
        5.  一路点击"确定"保存。
5.  **验证安装**：打开一个新的命令提示符 (CMD) 或 PowerShell 窗口（**必须是新的**），运行以下命令：
    ```bash
    gcc --version
    g++ --version
    gdb --version
    ```
    如果都能看到版本号信息，说明安装成功。

### 在 macOS 上

macOS 用户最简单的方式是安装 Xcode Command Line Tools，它包含了 Clang 编译器（一个与 GCC 高度兼容的现代编译器）。

1.  **打开终端** (Terminal)。
2.  运行以下命令：
    ```bash
    xcode-select --install
    ```
3.  会弹出一个对话框，提示你安装命令行工具。点击"安装"并同意许可协议。
4.  **验证安装**：安装完成后，在终端中运行：
    ```bash
    clang --version
    clang++ --version
    ```
    如果能看到版本信息，说明安装成功。

### 在 Linux 上

大多数 Linux 发行版（如 Ubuntu, Debian, Fedora）都可以通过包管理器轻松安装 GCC 工具链。

在基于 Debian/Ubuntu 的发行版上，可以安装 `build-essential` 包，它包含了 GCC/G++ 编译器、`make` 以及其他开发必需的工具。

1.  **打开终端**。
2.  运行以下命令：
    ```bash
    sudo apt update
    sudo apt install build-essential gdb
    ```
3.  **验证安装**：安装完成后，运行：
    ```bash
    gcc --version
    g++ --version
    gdb --version
    ```
    如果能看到版本信息，说明安装成功。

## 3. 在 VS Code 中配置编译任务

虽然你可以直接在终端使用 `gcc` 或 `g++` 命令来编译代码，但在 VS Code 中设置一个编译任务会更高效。VS Code 的 C/C++ 扩展可以自动为你完成这些配置。当你第一次打开一个 `.c` 或 `.cpp` 文件并尝试运行或调试时，它会自动检测你安装的编译器并生成一个 `.vscode/tasks.json` 文件，该文件定义了如何编译你的代码。

我们将在下一章编写第一个程序时详细体验这个流程。

---

环境搭建完成后，你已经准备好编写并运行你的第一个 C 程序了。让我们继续学习 [C 语言基础](c-basics.md)。 