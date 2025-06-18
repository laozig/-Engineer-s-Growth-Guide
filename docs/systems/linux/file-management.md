# 5. 文件与目录管理

在上一章的基础上，本章将深入介绍如何在命令行中创建、复制、移动、重命名和删除文件与目录，以及如何有效地查找文件。

## 创建文件和目录

### 1. `touch` - 创建空文件或更新时间戳

`touch` 命令的主要用途是创建一个新的空文件，或者更新一个已存在文件的时间戳。

```bash
# 创建一个名为 my_file.txt 的空文件
touch my_file.txt

# 同时创建多个文件
touch file1.txt file2.txt file3.md

# 如果 a_file.txt 已存在，则更新它的访问和修改时间为当前时间
# 如果不存在，则创建一个空文件
touch a_file.txt
```

### 2. `mkdir` - (Make Directory) 创建目录

`mkdir` 命令用于创建一个新目录。

```bash
# 在当前位置创建一个名为 'my_documents' 的目录
mkdir my_documents

# 使用 -p (parents) 选项，可以一次性创建多层嵌套的目录
# 如果 'project' 和 'src' 目录不存在，它会自动创建
mkdir -p project/src/components
```

## 复制、移动和重命名

### 1. `cp` - (Copy) 复制文件和目录

`cp` 命令用于复制文件或目录。

**基本语法**: `cp [选项] <源文件> <目标文件>`

```bash
# 将 file1.txt 复制并命名为 file2.txt
cp file1.txt file2.txt

# 将 file1.txt 复制到 my_documents 目录中，文件名保持不变
cp file1.txt my_documents/

# 将 file1.txt 复制到 my_documents 目录中，并重命名为 report.txt
cp file1.txt my_documents/report.txt
```

要复制整个目录，必须使用 `-r` 或 `-R` (recursive) 选项。

```bash
# 递归地将 my_documents 目录及其所有内容复制到 backup 目录中
cp -r my_documents/ backup/
```

### 2. `mv` - (Move) 移动或重命名文件和目录

`mv` 命令有两个主要功能：移动文件/目录，或者重命名文件/目录。

**移动**:
```bash
# 将 report.txt 文件移动到 my_documents 目录
mv report.txt my_documents/

# 将多个文件移动到一个目录
mv file1.txt file2.txt my_documents/
```

**重命名**:
重命名的本质是将文件"移动"到同一个目录下，但使用一个新的名字。
```bash
# 将文件 old_name.txt 重命名为 new_name.txt
mv old_name.txt new_name.txt

# 将目录 my_docs 重命名为 documents
mv my_docs documents
```

## 删除文件和目录

**警告**：Linux 的命令行删除是**永久性的**！没有回收站。在使用 `rm` 命令时要格外小心。

### 1. `rm` - (Remove) 删除文件

`rm` 命令用于删除文件。

```bash
# 删除一个文件
rm file_to_delete.txt
```

要删除一个目录，你需要使用 `-r` (recursive) 选项来删除目录及其包含的所有内容。

```bash
# 递归删除一个目录和它里面的所有内容
rm -r directory_to_delete/
```

`rm` 命令的常用选项：
- **`-i` (interactive)**: 在删除每个文件前进行提示确认。
- **`-f` (force)**: 强制删除，忽略不存在的文件并且从不提示。**请谨慎使用！**

组合使用：
```bash
# 强制递归删除一个目录，不进行任何提示。这是一个非常危险的命令！
rm -rf some_directory/
```

### 2. `rmdir` - (Remove Directory) 删除空目录

`rmdir` 命令只能用于删除**空**目录。如果目录中含有任何文件或子目录，`rmdir` 将会报错。

```bash
# 如果 'empty_dir' 是空的，则删除它
rmdir empty_dir
```

## 使用通配符 (Wildcards)

通配符（也称为 globbing）是 Shell 的一个强大功能，它允许你使用特殊字符来匹配文件名。

- **`*` (星号)**: 匹配任意数量（包括零个）的任意字符。
  - `*.txt`: 匹配所有以 `.txt` 结尾的文件。
  - `report_*`: 匹配所有以 `report_` 开头的文件。

- **`?` (问号)**: 匹配任意单个字符。
  - `file?.txt`: 匹配 `file1.txt`, `fileA.txt`，但不匹配 `file10.txt`。

- **`[]` (方括号)**: 匹配方括号中指定的任意一个字符。
  - `[abc].log`: 匹配 `a.log`, `b.log`, `c.log`。
  - `[0-9].log`: 匹配 `0.log` 到 `9.log`。

**使用示例**:
```bash
# 复制所有 .txt 文件到一个目录
cp *.txt text_files/

# 移动所有以 'image' 开头，后跟一个数字，并以 '.jpg' 结尾的文件
mv image[0-9].jpg images/

# 删除所有 .tmp 文件
rm *.tmp
```

## 查找文件

### `find` - 在目录树中查找文件

`find` 是一个非常强大和灵活的命令，用于根据各种条件在文件系统中搜索文件和目录。

**基本语法**: `find <在何处查找> <基于什么查找> <做什么操作>`

**按名称查找**:
```bash
# 在当前目录 (.) 及其子目录中，查找名为 'myfile.txt' 的文件
find . -name "myfile.txt"

# -iname 选项可以忽略大小写
find . -iname "myfile.txt"

# 使用通配符查找所有 .log 文件
find /var/log -name "*.log"
```

**按类型查找**:
```bash
# 查找所有目录
find . -type d

# 查找所有文件
find . -type f
```

**按修改时间查找**:
```bash
# 查找最近 7 天内被修改过的文件
find . -mtime -7

# 查找超过 30 天未被修改过的文件
find . -mtime +30
```

**按大小查找**:
```bash
# 查找大于 100MB 的文件
find / -size +100M

# 查找小于 10KB 的文件
find . -size -10k
```

**组合条件并执行操作**:
`find` 的一个强大之处在于可以对找到的文件执行命令。

```bash
# 查找所有名为 '.swp' 的文件，并删除它们
# {} 是一个占位符，代表 find 命令找到的每个文件
# \; 是必需的，表示 -exec 命令的结束
find . -name "*.swp" -exec rm {} \;

# 查找所有属于用户 'john' 的文件，并将其所有权更改为 'jane'
find /home/john -user john -exec chown jane {} \;
``` 