# 8. Shell 脚本编程

Shell 脚本是将一系列 Linux 命令按顺序组织在一个文本文件中，以便一次性执行。它是自动化日常任务、简化复杂操作和进行系统管理的基石。通过编写脚本，你可以将重复性的工作交给计算机完成。

本章将介绍 Bash (Bourne Again SHell) 脚本的基础知识，Bash 是绝大多数 Linux 发行版中默认的 Shell。

## 什么是 Shell 脚本？

- 一个包含 Shell 命令的纯文本文件。
- 它可以像普通程序一样被执行。
- 用于自动化，例如：
    - 自动备份文件。
    - 监控系统状态（如磁盘空间、内存使用）。
    - 批量处理文件（如重命名、转换格式）。
    - 简化自定义命令的执行。

## 创建第一个脚本

1.  **创建文件**: 使用文本编辑器（如 `nano` 或 `vim`）创建一个新文件，通常以 `.sh` 结尾（这不是必需的，但有助于识别）。
    ```bash
    nano my_script.sh
    ```

2.  **添加 Shebang**: 在脚本的第一行，添加 "shebang"。它告诉系统应该使用哪个解释器来执行这个脚本。对于 Bash 脚本，它总是：
    ```bash
    #!/bin/bash
    ```

3.  **添加命令**: 在 shebang 下方，添加你想要执行的命令。
    ```bash
    #!/bin/bash
    # 这是一个注释
    echo "Hello, World!"
    echo "当前日期是: $(date)"
    ```

4.  **授予执行权限**: 新创建的脚本文件默认没有执行权限。你需要使用 `chmod` 来添加它。
    ```bash
    chmod 755 my_script.sh
    # 或者
    chmod u+x my_script.sh
    ```

5.  **运行脚本**:
    ```bash
    # 如果你在脚本所在的目录，需要使用 ./ 来指定当前目录
    ./my_script.sh

    # 输出:
    # Hello, World!
    # 当前日期是: Tue Jul 16 14:20:00 UTC 2024
    ```

## 变量 (Variables)

在 Shell 脚本中，你可以定义变量来存储数据。

### 定义变量
- 语法: `VARIABLE_NAME="value"`
- **注意**:
    - 变量名、等号和值之间**不能有空格**。
    - 按照惯例，变量名通常使用大写字母。
    - 值如果包含空格，必须用引号引起来。

```bash
#!/bin/bash

GREETING="你好, Linux 世界"
USER_NAME="Alice"
```

### 使用变量
- 在变量名前加上美元符号 `$` 来引用它的值。
- 推荐将变量引用放在双引号中，以防止因变量值包含空格或特殊字符而引发问题。

```bash
#!/bin/bash

GREETING="你好, Linux 世界"
USER_NAME="Alice"

echo "$GREETING"
echo "欢迎, $USER_NAME"
echo "我正在使用 $SHELL" # $SHELL 是一个系统内置的环境变量
```

### 命令替换 (Command Substitution)
你可以将一个命令的输出结果赋值给一个变量。使用 `$(command)` 语法。

```bash
#!/bin/bash

CURRENT_DIR=$(pwd)
FILE_COUNT=$(ls -l | wc -l)

echo "你现在在 $CURRENT_DIR 目录."
echo "这个目录里有 $FILE_COUNT 个文件和子目录."
```

## 位置参数 (Positional Parameters)

脚本可以接收在运行时传递给它的参数。在脚本内部，这些参数通过特殊变量访问：
- `$0`: 脚本本身的名称。
- `$1`: 第一个参数。
- `$2`: 第二个参数，以此类推。
- `$#`: 传递给脚本的参数总数。
- `$@` 或 `$*`: 所有参数的列表。

**示例 (`greet_user.sh`)**:
```bash
#!/bin/bash

# 检查参数数量是否正确
if [ $# -ne 2 ]; then
    echo "用法: $0 <名字> <城市>"
    exit 1
fi

NAME=$1
CITY=$2

echo "你好, $NAME!"
echo "欢迎来到 $CITY."
```

**运行**:
```bash
./greet_user.sh Bob London
# 输出:
# 你好, Bob!
# 欢迎来到 London.
```

## 读取用户输入 (`read`)

`read` 命令用于在脚本运行时从用户那里获取输入，并将其存入一个变量。

```bash
#!/bin/bash

echo "请输入你的名字:"
read USER_NAME

echo "你好, $USER_NAME! 很高兴认识你。"
```

## 控制流

### `if-else` 语句
用于根据条件执行不同的代码块。

**基本结构**:
```bash
if [ condition ]; then
    # 如果条件为真，执行这里的命令
elif [ another_condition ]; then
    # 如果条件为假，但这个条件为真，执行这里的命令
else
    # 如果以上条件都为假，执行这里的命令
fi
```
- **注意**: `[` 和 `]` 与其中的条件之间必须有空格。

**文件和字符串比较**:
- `[ -f "$FILE" ]`: 如果文件存在且为普通文件，则为真。
- `[ -d "$DIR" ]`: 如果目录存在，则为真。
- `[ "$VAR1" == "$VAR2" ]`: 如果两个字符串相等，则为真。
- `[ -z "$VAR" ]`: 如果变量为空，则为真。

**数字比较**:
- `-eq` (等于), `-ne` (不等于), `-gt` (大于), `-lt` (小于), `-ge` (大于等于), `-le` (小于等于)。

```bash
#!/bin/bash

read -p "请输入你的年龄: " AGE

if [ "$AGE" -lt 18 ]; then
    echo "你还未成年。"
else
    echo "你已经是成年人了。"
fi
```

### `for` 循环
用于遍历一个列表。

```bash
#!/bin/bash

# 遍历一个字符串列表
for PLANET in Mercury Venus Earth Mars Jupiter
do
    echo "行星: $PLANET"
done

# C 语言风格的 for 循环
for (( i=1; i<=5; i++ ))
do
    echo "计数: $i"
done
```

### `while` 循环
当给定条件为真时，重复执行代码块。

```bash
#!/bin/bash

COUNTER=1
while [ $COUNTER -le 5 ]
do
    echo "当前数字: $COUNTER"
    # 使用 ((...)) 进行算术运算
    ((COUNTER++))
done
```

这是一个简单的起点。Shell 脚本可以变得非常复杂和强大，包括函数、数组、错误处理等高级特性，这些都可以在进阶学习中探索。 