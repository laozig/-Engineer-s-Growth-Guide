# 4. Linux 基本命令

命令行是与 Linux 系统交互的主要方式。掌握基本命令是高效使用 Linux 的基础。本章将介绍一些最常用和最重要的命令。

## Shell 提示符

当你打开一个终端时，你会看到一个 Shell 提示符，它通常看起来像这样：

```bash
username@hostname:~$
```

- **`username`**: 你当前的用户名。
- **`hostname`**: 你正在操作的计算机的主机名。
- **`:`**: 分隔符。
- **`~`**: 表示你当前的目录是你的主目录 (`/home/username`)。
- **`$`**: 提示符的结束。这表示你是一个普通用户。如果是 `root` 用户，提示符通常是 `#`。

## 获取帮助

在学习命令时，知道如何获取帮助至关重要。

### 1. `man` - (Manual) 查看手册页

`man` 命令用于显示一个命令的官方手册页（manual page）。这是最权威、最详细的帮助来源。

```bash
# 查看 ls 命令的手册页
man ls

# 查看 man 命令自身的手册页
man man
```

在 `man` 页面中，你可以使用以下按键进行导航：
- **`↓` / `↑` / `Enter`**: 向下/上滚动一行。
- **`Page Down` / `Page Up` / `Space`**: 向下/上翻一页。
- **`/` + `关键词` + `Enter`**: 向下搜索关键词。
- **`n`**: 跳转到下一个搜索结果。
- **`q`**: 退出 `man` 页面。

### 2. `--help` 选项

大多数命令都支持 `--help` 选项，它会显示一个简短的、总结性的用法信息。

```bash
# 获取 ls 命令的帮助信息
ls --help

# 获取 cd 命令的帮助信息 (注意：cd 是内建命令，可能需要用 help cd)
help cd
```

### 3. `info` 命令

`info` 命令提供了比 `man` 更结构化、更易于导航的文档（使用超链接）。但不是所有命令都有 info 页面。

```bash
# 查看 coreutils 的 info 页面
info coreutils
```

## 导航文件系统

这些命令用于在文件系统的目录之间移动。

### 1. `pwd` - (Print Working Directory) 显示当前目录

`pwd` 命令会打印出你当前所在位置的绝对路径。

```bash
pwd
# 输出示例: /home/username
```

### 2. `cd` - (Change Directory) 切换目录

`cd` 命令用于从一个目录移动到另一个目录。

```bash
# 切换到 /usr/bin 目录
cd /usr/bin

# 切换到你的主目录
cd ~
# 或者直接输入 cd，效果相同
cd

# 切换到上一级目录
cd ..

# 切换到根目录
cd /

# 切换到你之前所在的目录
cd -
```

### 3. `ls` - (List) 列出目录内容

`ls` 命令用于列出当前目录下的文件和子目录。

```bash
# 列出当前目录的内容
ls

# 列出 /etc 目录的内容
ls /etc
```

`ls` 有许多非常有用的选项：

- **`ls -l`**: (long) 使用长格式显示，提供更多细节，如权限、所有者、大小和修改时间。
- **`ls -a`**: (all) 显示所有文件，包括以 `.` 开头的隐藏文件。
- **`ls -h`**: (human-readable) 与 `-l` 结合使用，以人类可读的格式显示文件大小（例如 `4.0K`, `1.2M`）。
- **`ls -t`**: (time) 按修改时间排序，最新的排在最前面。
- **`ls -R`**: (recursive) 递归地列出所有子目录的内容。

这些选项可以组合使用：

```bash
# 以长格式、人类可读的方式，显示所有文件（包括隐藏文件）
ls -lah
```

## 查看文件内容

这些命令用于查看文本文件的内容。

### 1. `file` - 判断文件类型

`file` 命令可以探测并显示一个文件的类型。

```bash
file /etc/passwd
# 输出示例: /etc/passwd: ASCII text

file /bin/bash
# 输出示例: /bin/bash: ELF 64-bit LSB shared object, x86-64...
```

### 2. `cat` - (Concatenate) 连接并显示文件内容

`cat` 命令会读取一个或多个文件，并将它们的全部内容一次性打印到屏幕上。

```bash
# 显示单个文件的内容
cat /etc/hostname

# 同时显示多个文件的内容
cat file1.txt file2.txt
```

**警告**：不要用 `cat` 查看非常大的文件，因为它会用文件内容刷满你的屏幕。

### 3. `less` - 以可翻页的方式查看文件

`less` 是一个功能强大的分页器，它允许你交互式地向前或向后滚动浏览文件内容。这是查看大文件的首选方式。

```bash
less /var/log/syslog
```

`less` 中的导航键与 `man` 命令非常相似（`/` 搜索，`q` 退出等）。

### 4. `head` - 查看文件开头

`head` 命令默认显示文件的前 10 行。

```bash
# 显示文件的前 10 行
head /var/log/syslog

# 使用 -n 选项指定行数
head -n 20 /var/log/syslog
```

### 5. `tail` - 查看文件末尾

`tail` 命令默认显示文件的最后 10 行。这对于查看日志文件的最新条目非常有用。

```bash
# 显示文件的最后 10 行
tail /var/log/syslog

# 使用 -n 选项指定行数
tail -n 50 /var/log/syslog

# 使用 -f 选项 (follow)，可以持续监视文件的更新，实时显示新增内容
# 这对于实时监控日志文件非常有用。按 Ctrl+C 停止。
tail -f /var/log/syslog
```

通过组合使用这些基本命令，你已经可以开始在 Linux 系统中进行探索和基本的文件操作了。 