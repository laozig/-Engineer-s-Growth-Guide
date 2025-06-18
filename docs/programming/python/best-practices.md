# Python 最佳实践与代码风格

编写能够工作的代码只是第一步，而编写出清晰、高效、可维护且符合社区规范的代码，则是专业开发者的标志。本章将总结一系列 Python 开发的最佳实践。

## 1. 代码风格：遵循 PEP 8，使用自动化工具

-   **PEP 8**: 是 Python 官方的代码风格指南。遵循它是与社区保持一致的基础。核心要点包括：
    -   使用 4 个空格进行缩进。
    -   行长度建议不超过 79-99 个字符。
    -   使用空行来分隔函数和类，以及代码的逻辑部分。
    -   命名规范：
        -   `snake_case` (小写+下划线) 用于函数、方法、变量和模块。
        -   `PascalCase` (驼峰式) 用于类。
        -   `UPPERCASE_SNAKE_CASE` 用于常量。

-   **自动化工具**: 手动维护代码风格既繁琐又易出错。现代 Python 开发强烈依赖自动化工具：
    -   **Black**: 一个"不妥协"的代码格式化工具。它会以一种统一的风格自动重写你的代码。只需运行 `black .`，无需任何争论。
    -   **Ruff** / **Flake8**: 代码检查（Linting）工具。它们会检查代码中不符合 PEP 8 规范或可能存在逻辑错误的地方。Ruff 是一个用 Rust 编写的新工具，速度极快，可以替代 Flake8 和 isort。
    -   **isort**: 自动对你的 `import` 语句进行排序和分组。

**工作流**: 配置你的编辑器，在每次保存文件时自动运行 Black 和 isort/Ruff。

## 2. Python 之禅 (`import this`)

在 Python 解释器中输入 `import this`，你会看到指导 Python 设计的"Python 之禅"。以下是其中几条核心思想：
-   **优美胜于丑陋 (Beautiful is better than ugly)**: 追求代码的简洁与优雅。
-   **明确胜于隐晦 (Explicit is better than implicit)**: 代码的行为应该是清晰、无歧义的。
-   **简单胜于复杂 (Simple is better than complex)**: 优先选择简单的解决方案。
-   **可读性很重要 (Readability counts)**: 代码的读者比作者更重要，编写易于他人理解的代码。

## 3. 核心编码实践

### (1) 拥抱类型提示
自 Python 3.5 起，类型提示已成为语言的标准部分。
```python
def greet(name: str) -> str:
    return f"Hello, {name}"
```
**为什么使用类型提示？**
-   **可读性与文档**: 类型签名清晰地说明了函数期望的输入和输出。
-   **静态分析**: 工具如 `Mypy` 可以在不运行代码的情况下发现类型不匹配的错误。
-   **编辑器支持**: 编辑器（如 VS Code）会利用类型提示提供更智能的自动补全和错误检查。

### (2) 优先使用推导式
列表、字典和集合推导式是创建新集合的 Pythonic 方式，比传统的 `for` 循环更简洁、通常也更快。

```python
# 不推荐
squares = []
for i in range(10):
    squares.append(i * i)

# 推荐 (更 Pythonic)
squares = [i * i for i in range(10)]

# 字典推导式
square_map = {i: i * i for i in range(10)}
```

### (3) 使用 `with` 语句管理资源
对于文件、网络连接、数据库会话、锁等需要在使用后被明确关闭或释放的资源，应始终使用 `with` 语句。它能确保即使在代码块中发生异常，清理操作（如 `file.close()`）也一定会被执行。

```python
# 推荐
with open('my_file.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 不推荐 (容易忘记关闭或在异常时失败)
# f = open('my_file.txt', 'r')
# content = f.read()
# f.close()
```

### (4) 避免可变的默认参数
这是一个常见的陷阱。默认参数在函数定义时只被创建一次。

```python
# 错误的方式
def add_item_wrong(item, items=[]):
    items.append(item)
    return items

list1 = add_item_wrong(1) # [1]
list2 = add_item_wrong(2) # [1, 2] <- list1 和 list2 共享同一个列表！

# 正确的方式
def add_item_correct(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items
```

## 4. 项目结构与依赖管理

### (1) 标准项目布局
一个典型的 Python 项目结构如下：
```
my_project/
├── .venv/               # 虚拟环境目录 (应在 .gitignore 中)
├── src/                 # 源代码根目录 (可选，但推荐)
│   └── my_project/
│       ├── __init__.py
│       └── main.py
├── tests/               # 测试代码
│   └── test_main.py
├── docs/                # 文档
├── pyproject.toml       # 现代 Python 项目的配置文件
└── README.md
```

### (2) 依赖管理
-   **始终使用虚拟环境**: 使用 `venv` 为每个项目创建独立的 Python 环境，避免包版本冲突。
-   **`requirements.txt`**: 用于记录项目依赖的传统方式。
    -   `pip freeze > requirements.txt` 生成。
    -   `pip install -r requirements.txt` 安装。
-   **`pyproject.toml` (现代方式)**:
    -   这是一个统一的项目配置文件，用于取代 `setup.py`, `requirements.txt` 等。
    -   工具如 **Poetry** 或 **PDM** 使用此文件来管理依赖、项目元数据、构建和发布流程。
    -   **优点**: 能够区分生产依赖和开发依赖（如 `pytest`），并能锁定依赖版本以确保可复现的构建。

## 5. 文档与注释
-   **文档字符串 (Docstrings)**:
    -   为所有公共的模块、函数、类和方法编写文档字符串。
    -   它解释了"做什么"，而不是"怎么做"。
    -   遵循一种标准格式，如 Google Style 或 reStructuredText。
-   **代码注释**:
    -   注释应该解释代码中那些不明显的部分，即"为什么"这么做，而不是简单地复述代码"在做什么"。
    -   保持注释的更新。过时的注释比没有注释更糟糕。 