# Python 开发环境的现代指南

搭建一个健壮、可复现且无冲突的开发环境，是每一位专业 Python 开发者的第一步。本指南将摒弃过时的方法，引导你采用业界公认的最佳实践。

## 1. 核心理念：版本管理与依赖隔离

在开始安装之前，必须理解两个核心概念：

-   **Python 版本管理**: 你的操作系统可能自带一个 Python（系统 Python），但你绝不应该直接用它来开发项目。系统 Python 服务于操作系统自身，直接修改它或安装包可能导致系统崩溃。此外，不同项目可能需要不同版本的 Python（如 3.9, 3.10, 3.11），因此你需要在它们之间轻松切换。
-   **项目依赖隔离**: 项目 A 可能需要 `requests` 的 2.25 版本，而项目 B 可能需要 2.28 版本。如果将它们都安装到全局环境中，必然会产生冲突。每个项目都应该拥有自己独立的、与外界隔离的包（依赖）集合。

**我们的目标**：为每个项目创建一个指定 Python 版本的、隔离的开发环境。

## 2. 推荐的工作流 (跨平台)

我们推荐使用 `pyenv` 管理 Python 版本，使用 `venv` 管理项目虚拟环境。这个流程适用于所有主流操作系统。

### 第一步：使用 `pyenv` 安装和管理 Python 解释器

`pyenv` 是一个强大的 Python 版本管理工具。它让你能够在同一台机器上安装任意多个 Python 版本，并为每个项目指定使用哪个版本。

#### (1) 安装 `pyenv`

-   **macOS / Linux**: 推荐使用官方的 `pyenv-installer`。
    ```bash
    curl https://pyenv.run | bash
    ```
    安装完成后，按照终端提示将 `pyenv` 初始化脚本添加到你的 shell 配置文件中（如 `.bashrc`, `.zshrc`）。

-   **Windows**: 使用 `pyenv-win`。可以通过 PowerShell 使用 `pip` 安装：
    ```powershell
    pip install pyenv-win --target $HOME/.pyenv
    ```
    然后按照 `pyenv-win` 的文档说明配置环境变量。

#### (2) 使用 `pyenv` 安装 Python
安装一个具体的 Python 版本，例如 3.11.5。

```bash
# 查看所有可安装的版本
pyenv install --list

# 安装指定的版本 (这可能需要一些时间，因为它会从源码编译)
pyenv install 3.11.5
```

#### (3) 使用 `pyenv` 切换 Python 版本
-   **设置全局默认版本**: `pyenv global 3.11.5`
-   **为当前目录或项目设置版本**: 进入你的项目文件夹，然后运行：
    ```bash
    pyenv local 3.11.5
    ```
    这会在当前目录创建一个 `.python-version` 文件。当你在此目录或其子目录中时，`pyenv` 会自动切换到 3.11.5 版本。

### 第二步：使用 `venv` 创建项目虚拟环境

现在我们已经有了特定版本的 Python，接下来要为项目创建一个隔离的沙箱。`venv` 是 Python 3 自带的官方标准库，用于创建虚拟环境。

#### (1) 创建虚拟环境
进入你的项目文件夹，确保 `pyenv` 已将 Python 版本设置为你想要的（例如，通过 `pyenv local`）。然后运行：

```bash
# 使用当前激活的 Python 版本创建一个名为 .venv 的虚拟环境
python -m venv .venv
```
**最佳实践**:
-   始终将虚拟环境命名为 `.venv`。
-   将 `.venv/` 添加到项目的 `.gitignore` 文件中，永远不要将虚拟环境提交到版本控制。

#### (2) 激活虚拟环境
创建后，你需要"激活"它，这会将你的 shell 会话切换到使用这个沙箱环境。

-   **macOS / Linux**:
    ```bash
    source .venv/bin/activate
    ```
-   **Windows (Command Prompt)**:
    ```bash
    .venv\Scripts\activate.bat
    ```
-   **Windows (PowerShell)**:
    ```powershell
    .venv\Scripts\Activate.ps1
    ```
激活后，你会发现终端提示符前面多了 `(.venv)` 的标识。现在，你使用 `python` 和 `pip` 命令都将是这个隔离环境中的版本。

### 第三步：使用 `pip` 管理项目依赖

在激活的虚拟环境中，你可以使用 `pip` 安装、更新和移除包，而不会影响全局或其他项目。

```bash
# 安装一个包
pip install requests

# 升级一个包
pip install --upgrade requests

# 查看已安装的包
pip list

# 生成依赖列表文件
pip freeze > requirements.txt

# 从文件安装依赖
pip install -r requirements.txt
```
*注意：虽然 `requirements.txt` 很常用，但现代 Python 项目正逐步转向使用 `pyproject.toml` 来统一管理依赖和项目元数据。我们将在后续章节深入探讨。*

## 3. (可选) 一体化工具：Poetry 和 PDM

对于更复杂的项目，你可能希望使用功能更强大的一体化工具。
-   **Poetry**: 一个广受欢迎的工具，它集成了依赖管理、虚拟环境创建、打包和发布功能。
-   **PDM**: 一个新兴的、支持最新 PEP 标准的包管理器，与 Poetry 类似但更加现代化。

这些工具通过一个 `pyproject.toml` 文件管理所有项目配置，可以自动化大部分上述流程。对于大型项目或团队协作，强烈推荐学习使用它们。

## 4. 编辑器配置：以 VS Code 为例

良好的编辑器集成是高效开发的关键。
1.  **安装扩展**: 在 VS Code 中，安装官方的 `Python` 扩展 (来自 Microsoft)。它会自动捆绑 `Pylance`，提供强大的代码补全和类型检查功能。
2.  **选择解释器**:
    -   打开你的项目文件夹。
    -   使用快捷键 `Ctrl+Shift+P` (或 `Cmd+Shift+P`) 打开命令面板。
    -   输入并选择 "Python: Select Interpreter"。
    -   VS Code 会自动检测到你的 `.venv` 虚拟环境。选择它。
    
现在，VS Code 的终端、代码运行和调试功能都会自动使用你为项目配置的隔离环境。

## 5. 传统安装方式 (备查)

以下是在没有 `pyenv` 的情况下，直接在操作系统上安装 Python 的传统方法。**除非你有特殊理由，否则不推荐这样做。**

### Windows
- **官方安装包**: 从 [python.org](https://www.python.org/downloads/windows/) 下载。**关键**：在安装第一步，务必勾选 "Add Python to PATH"。

### macOS
- **官方安装包**: 从 [python.org](https://www.python.org/downloads/macos/) 下载。
- **Homebrew**: `brew install python3`。

### Linux (Debian/Ubuntu)
- `sudo apt update && sudo apt install python3 python3-pip python3-venv` 