# 7. 文本编辑器 (Vim/Nano)

在命令行环境中，所有配置和脚本编写都是通过编辑纯文本文件完成的。因此，熟练使用一个命令行文本编辑器是 Linux 系统管理的基础技能。本章将介绍两个最流行和最常见的编辑器：`nano` 和 `vim`。

## Nano - 简单易用的编辑器

Nano 是一个对初学者非常友好的编辑器。它的界面直观，常用命令会直接显示在屏幕底部，无需记忆。

**启动 Nano**:
```bash
# 打开一个新文件或现有文件
nano filename.txt
```

**基本操作**:
- **直接输入**: 与普通记事本一样，直接输入文字即可。
- **光标移动**: 使用键盘上的箭头键 `↑`, `↓`, `←`, `→` 来移动光标。
- **保存文件**: 按 `Ctrl + O` (Write**O**ut)。它会提示你确认文件名，按 `Enter` 即可。
- **退出 Nano**: 按 `Ctrl + X` (E**x**it)。如果文件有未保存的修改，它会询问你是否要保存。按 `Y` (是)，然后按 `Enter` 确认文件名并保存退出；或者按 `N` (否) 放弃修改直接退出。
- **搜索文本**: 按 `Ctrl + W` (Where is)。输入要搜索的文本，按 `Enter`。
- **剪切和粘贴**:
  - `Alt + A` 设置选区的起点。
  - 移动光标来选择文本。
  - `Alt + 6` 复制选中的文本。
  - `Ctrl + K` 剪切当前行（或选中的文本）。
  - `Ctrl + U` 粘贴被剪切或复制的文本。

Nano 的优点是上手快，几乎没有学习曲线。对于快速修改配置文件等简单任务来说，它是一个绝佳的选择。

## Vim - 功能强大的模态编辑器

Vim (Vi IMproved) 是一个非常强大、高效且高度可配置的编辑器。它在有经验的开发者和系统管理员中非常受欢迎。Vim 的主要特点是其 **模态 (modal)** 操作，这意味着在不同的模式下，键盘按键有不同的功能。

**启动 Vim**:
```bash
# 打开一个新文件或现有文件
vim filename.txt
```

### Vim 的主要模式

1.  **普通模式 (Normal Mode)**:
    - 这是启动 Vim 后的默认模式。
    - 在这个模式下，你不能直接输入文本。所有的按键都被解释为命令（如移动光标、删除文本、复制粘贴等）。
    - 这是 Vim 的核心，大部分时间都应该待在这个模式下。
    - **如何进入**: 从任何其他模式按 `Esc` 键即可返回普通模式。

2.  **插入模式 (Insert Mode)**:
    - 在这个模式下，你可以像普通编辑器一样输入文本。
    - **如何进入**: 在普通模式下按以下任一键：
        - `i`: 在光标**前**插入 (insert)
        - `a`: 在光标**后**追加 (append)
        - `o`: 在当前行的**下方**打开一个新行并进入插入模式
        - `O`: 在当前行的**上方**打开一个新行并进入插入模式

3.  **命令模式 (Command-Line Mode)**:
    - 用于执行更复杂的操作，如保存、退出、搜索替换等。
    - **如何进入**: 在普通模式下按冒号 `:`。光标会跳到屏幕左下角。

### Vim 基础操作 (在普通模式下)

**移动光标**:
- 基本移动: `h` (左), `j` (下), `k` (上), `l` (右)  (避免使用箭头键，以养成高效习惯)
- 词间移动: `w` (跳到下一个词的开头), `b` (跳到上一个词的开头)
- 行内移动: `0` (跳到行首), `$` (跳到行尾)
- 翻页: `Ctrl + f` (向前翻页), `Ctrl + b` (向后翻页)
- 跳转到指定行: `[行号]G` (例如，`10G` 跳转到第10行)，`G` (跳转到文件末尾)，`gg` (跳转到文件开头)

**编辑文本**:
- **删除**:
  - `x`: 删除光标下的字符
  - `dw`: 删除从光标到词尾的内容
  - `dd`: 删除整行
- **复制 (Yank)**:
  - `yw`: 复制一个词
  - `yy`: 复制整行
- **粘贴 (Paste)**:
  - `p`: 在光标后粘贴
  - `P`: 在光标前粘贴
- **撤销与重做**:
  - `u`: 撤销上一步操作 (undo)
  - `Ctrl + r`: 重做被撤销的操作 (redo)

### 保存和退出 (在命令模式下)

首先按 `Esc` 确保在普通模式，然后按 `:` 进入命令模式。

- **`:w`**: 保存 (write) 文件。
- **`:q`**: 退出 (quit)。如果文件有未保存的修改，Vim 会阻止你退出。
- **`:wq`** 或 **`:x`**: 保存并退出。
- **`:q!`**: 强制退出，丢弃所有未保存的修改。
- **`:w <新文件名>`**: 另存为。

## Vim 还是 Nano?

- **Nano**: 当你需要快速、简单地编辑一个文件时，尤其是在你不熟悉的系统上，Nano 是一个安全可靠的选择。
- **Vim**: 当你需要进行大量文本编辑、编程或脚本开发时，学习 Vim 的投入是值得的。一旦你熟悉了 Vim 的操作方式，你的编辑效率将大大提高。

对于初学者，建议先从 Nano 开始，熟悉在命令行下编辑文件的感觉。然后，可以逐步学习 Vim，从掌握上述基本操作开始。许多系统管理员最终会同时使用这两种工具，根据任务的复杂性来选择合适的编辑器。 