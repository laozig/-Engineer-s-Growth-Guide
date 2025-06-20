# Shell 脚本编程

Shell 脚本是 Linux/Unix 系统中非常强大的工具，允许用户自动化日常任务、批处理命令和简化系统管理。本文将介绍 Bash（Bourne Again SHell）脚本编程的基础知识和常用技巧。

## 基础知识

### 创建和执行脚本

1. 创建脚本文件：
```bash
touch myscript.sh
```

2. 添加执行权限：
```bash
chmod +x myscript.sh
```

3. 编辑脚本，添加 shebang 行：
```bash
#!/bin/bash
echo "Hello, World!"
```

4. 执行脚本：
```bash
./myscript.sh
```

### 脚本结构

一个良好的 shell 脚本通常包含以下部分：

```bash
#!/bin/bash

# 脚本描述和版本信息
# 作者：xxx
# 日期：yyyy-mm-dd
# 版本：1.0
# 描述：这个脚本的用途

# 定义变量
LOG_FILE="/var/log/myscript.log"
MAX_RETRIES=5

# 定义函数
log_message() {
    echo "$(date): $1" >> "$LOG_FILE"
}

# 主程序逻辑
log_message "脚本开始执行"
# ...其他命令...
log_message "脚本执行完成"

exit 0  # 成功退出
```

## 变量

### 变量定义和使用

```bash
# 定义变量（注意等号两边不能有空格）
name="John"
age=30
current_date=$(date +%Y-%m-%d)

# 使用变量（使用$前缀）
echo "Name: $name"
echo "Age: $age"
echo "Today is $current_date"

# 变量作用域
local_var="仅在函数内可见"  # 局部变量，需要在函数内使用 local 关键字
global_var="全局可见"      # 全局变量
```

### 特殊变量

```bash
$0    # 脚本名称
$1    # 第一个参数
$2    # 第二个参数
$@    # 所有参数（作为独立的单词）
$*    # 所有参数（作为单个字符串）
$#    # 参数个数
$?    # 上一个命令的退出状态
$$    # 当前脚本的进程 ID
$!    # 最后一个后台进程的 ID
```

### 环境变量

```bash
echo "Home directory: $HOME"
echo "Current user: $USER"
echo "Shell path: $SHELL"
echo "PATH: $PATH"
```

## 控制结构

### 条件语句

```bash
# if-else 语句
if [ "$age" -ge 18 ]; then
    echo "成年人"
elif [ "$age" -ge 13 ]; then
    echo "青少年"
else
    echo "儿童"
fi

# case 语句
case "$fruit" in
    "apple")
        echo "这是一个苹果"
        ;;
    "banana"|"plantain")
        echo "这是一个香蕉"
        ;;
    *)
        echo "未知水果"
        ;;
esac
```

### 循环语句

```bash
# for 循环
for i in {1..5}; do
    echo "Count: $i"
done

# while 循环
count=1
while [ $count -le 5 ]; do
    echo "While count: $count"
    ((count++))
done

# until 循环
count=1
until [ $count -gt 5 ]; do
    echo "Until count: $count"
    ((count++))
done

# break 和 continue
for i in {1..10}; do
    if [ $i -eq 3 ]; then
        continue  # 跳过当前迭代
    fi
    if [ $i -eq 8 ]; then
        break     # 退出循环
    fi
    echo "Iteration: $i"
done
```

## 函数

### 定义和调用函数

```bash
# 定义函数
hello() {
    echo "Hello, $1!"
    return 0
}

# 调用函数
hello "World"

# 带参数和返回值的函数
calculate() {
    local result=$(($1 + $2))
    echo $result
    return 0
}

sum=$(calculate 5 3)
echo "Sum: $sum"
```

## 文件操作

### 文件测试

```bash
if [ -f "$file" ]; then
    echo "普通文件存在"
fi

if [ -d "$directory" ]; then
    echo "目录存在"
fi

if [ -r "$file" ]; then
    echo "文件可读"
fi

if [ -w "$file" ]; then
    echo "文件可写"
fi

if [ -x "$file" ]; then
    echo "文件可执行"
fi
```

### 读取文件

```bash
# 逐行读取文件
while IFS= read -r line; do
    echo "Line: $line"
done < input.txt

# 使用 cat 和管道
cat input.txt | while read line; do
    echo "Line: $line"
done
```

## 字符串操作

```bash
# 字符串长度
str="Hello, World!"
echo "Length: ${#str}"

# 子字符串提取
echo "Substring: ${str:7:5}"  # 从索引7开始，长度为5

# 字符串替换
echo "Replace: ${str/World/Universe}"  # 替换第一个匹配
echo "Replace all: ${str//l/L}"       # 替换所有匹配

# 字符串判断
if [[ "$str" == *"World"* ]]; then
    echo "包含 'World'"
fi

# 大小写转换
echo "Lowercase: ${str,,}"
echo "Uppercase: ${str^^}"
```

## 数组

```bash
# 定义数组
fruits=("apple" "banana" "cherry")

# 访问数组元素
echo "First fruit: ${fruits[0]}"

# 数组长度
echo "Number of fruits: ${#fruits[@]}"

# 遍历数组
for fruit in "${fruits[@]}"; do
    echo "Fruit: $fruit"
done

# 添加元素
fruits+=("orange")

# 删除元素
unset fruits[1]
```

## 错误处理

```bash
# 捕获错误
set -e  # 任何命令失败时脚本退出
set -u  # 使用未定义变量时脚本退出
set -o pipefail  # 管道中任何命令失败时整个管道命令失败

# 错误处理函数
handle_error() {
    echo "Error occurred at line $1"
    exit 1
}

# 设置错误处理
trap 'handle_error $LINENO' ERR

# 自定义错误消息
command_that_might_fail || { echo "Command failed"; exit 1; }
```

## 调试技巧

```bash
# 启用调试模式
set -x  # 打印每条命令及其参数
set -v  # 打印每条命令的输入

# 仅调试部分代码
set +x  # 关闭调试
critical_code_here
set -x  # 重新启用调试

# 使用 bash -x 执行脚本
# bash -x myscript.sh
```

## 实用示例

### 批量重命名文件

```bash
#!/bin/bash
# 将所有 .txt 文件重命名为 .bak
for file in *.txt; do
    mv "$file" "${file%.txt}.bak"
done
```

### 系统监控脚本

```bash
#!/bin/bash
# 简单的系统监控脚本

while true; do
    echo "===== 系统状态 $(date) ====="
    echo "CPU 使用率:"
    top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}'
    
    echo "内存使用率:"
    free -m | awk 'NR==2{printf "%.2f%%\n", $3*100/$2 }'
    
    echo "磁盘使用率:"
    df -h | grep '^/dev/' | awk '{print $1 ": " $5}'
    
    echo "--------------------------"
    sleep 5
done
```

### 备份脚本

```bash
#!/bin/bash
# 简单的备份脚本

src_dir="/path/to/source"
backup_dir="/path/to/backup"
date_str=$(date +%Y%m%d_%H%M%S)
backup_file="backup_$date_str.tar.gz"

# 创建备份目录（如果不存在）
mkdir -p "$backup_dir"

# 创建备份
echo "正在备份 $src_dir 到 $backup_dir/$backup_file..."
tar -czf "$backup_dir/$backup_file" -C "$(dirname "$src_dir")" "$(basename "$src_dir")"

# 验证备份是否成功
if [ $? -eq 0 ]; then
    echo "备份成功完成"
    # 保留最近的5个备份，删除旧的
    ls -t "$backup_dir"/backup_*.tar.gz | tail -n +6 | xargs -r rm
    echo "已清理旧备份文件"
else
    echo "备份失败"
    exit 1
fi
```

## 最佳实践

1. **总是使用 shebang 行**：`#!/bin/bash`
2. **添加注释**：解释复杂代码的功能和目的
3. **使用有意义的变量名**：提高代码可读性
4. **引用变量**：使用 `"$variable"` 而不是 `$variable`，防止变量包含空格时出错
5. **使用退出状态**：脚本成功时返回0，失败时返回非0值
6. **模块化代码**：将复杂逻辑拆分为函数
7. **防止常见错误**：使用 `set -e`, `set -u` 和 `set -o pipefail`
8. **安全删除**：使用 `rm -i` 或确认提示，防止意外删除

## 参考资源

- [GNU Bash 手册](https://www.gnu.org/software/bash/manual/)
- [Advanced Bash-Scripting Guide](https://tldp.org/LDP/abs/html/)
- [Bash Hackers Wiki](https://wiki.bash-hackers.org/) 