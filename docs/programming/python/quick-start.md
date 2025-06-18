# Python 快速入门：从基础到现代特性

本指南旨在帮助你快速掌握 Python 编程的核心概念，不仅涵盖基础语法，更融入了现代 Python 开发的最佳实践，如 f-string 和类型提示，让你从一开始就编写出清晰、高效的代码。

## 1. 第一个 Python 程序

按照传统，我们从 "Hello, World!" 开始。创建一个名为 `hello.py` 的文件：

```python
print("Hello, Modern Python!")
```

在终端中运行它：
`python hello.py`

## 2. 基本语法与变量

### 代码缩进与注释
Python 使用 **4个空格** 的缩进来组织代码块，这是强制性的语法规则。

```python
# 这是一个单行注释
name = "Alice"
if name == "Alice":
    print(f"你好, {name}!")  # 正确的缩写
```

### 变量与现代 Python 赋值
变量无需预先声明类型。现代 Python 允许在赋值时使用类型提示，以增强代码可读性。

```python
# 类型提示 (Type Hints) 是可选的，但强烈推荐
user_name: str = "Bob"
user_age: int = 30
is_active: bool = True

# Python 3.8+ 的海象运算符 (Walrus Operator) 可以在表达式内部赋值
if (n := len(user_name)) > 3:
    print(f"用户名 '{user_name}' 的长度是 {n}，符合要求。")
```

## 3. 核心数据类型

### (1) 数字 (Number) 与字符串 (String)

#### 数字：整数、浮点数
```python
year: int = 2023
price: float = 99.9
```

#### 字符串与 f-string 格式化
字符串由单引号或双引号包围。**f-string** 是现代 Python 中最推荐的字符串格式化方法。

```python
# 使用 f-string，将变量直接嵌入字符串中
welcome_message: str = f"欢迎, {user_name}! 您的年龄是 {user_age}."
print(welcome_message)
# 输出: 欢迎, Bob! 您的年龄是 30.

# 常用字符串方法
print(welcome_message.upper()) # 转为大写
print(welcome_message.startswith("欢迎")) # 检查起始部分，返回 True
```

### (2) 列表 (List)：有序且可变
列表是 Python 中最常用的数据结构，它是一个有序的、可以随时修改的元素集合。

```python
# 推荐为列表中的元素类型添加提示
fruits: list[str] = ["苹果", "香蕉", "樱桃"]

# 访问与修改
print(f"第一个水果是: {fruits[0]}") # 访问第一个元素
fruits[1] = "蓝莓" # 修改第二个元素

# 添加与删除
fruits.append("橙子") # 在末尾添加
fruits.pop() # 移除并返回最后一个元素
print(f"更新后的水果列表: {fruits}")

# 列表推导式 (List Comprehension)：一种强大而简洁的创建列表的方式
squares: list[int] = [x * x for x in range(5)] # [0, 1, 4, 9, 16]
print(f"平方数列表: {squares}")
```

### (3) 元组 (Tuple)：有序且不可变
元组类似于列表，但一旦创建就**不能被修改**。这使得它非常适合用于存储那些不应改变的数据。

```python
# (纬度, 经度)
coordinate: tuple[float, float] = (39.9, 116.3)
print(f"坐标: 纬度 {coordinate[0]}, 经度 {coordinate[1]}")

# 尝试修改元组会引发错误
# coordinate[0] = 40.0 # 这行会产生 TypeError
```
**核心区别**: 列表是可变的 (mutable)，元组是不可变的 (immutable)。

### (4) 字典 (Dictionary)：无序的键值对集合
字典用于存储键值对 (key-value) 数据，通过唯一的键来快速查找对应的值。

```python
# 推荐为键和值的类型添加提示
user_profile: dict[str, any] = {
    "name": "Charlie",
    "age": 25,
    "is_premium": True
}

# 访问数据
print(f"{user_profile['name']} 是 premium 用户吗? {user_profile['is_premium']}")

# 添加或修改数据
user_profile["city"] = "北京" # 添加新键值对
user_profile["age"] = 26 # 更新值

# 使用 .get() 方法安全地访问可能不存在的键
country = user_profile.get("country", "未知") # 如果 "country" 不存在，返回默认值 "未知"
print(f"国家: {country}")
```

### (5) 集合 (Set)：无序且唯一的元素
集合用于存储不重复的元素，非常适合用于去重或进行成员资格测试。

```python
tags: set[str] = {"python", "web", "dev", "python"}
print(f"去重后的标签: {tags}") # 输出: {'web', 'dev', 'python'}

# 成员资格测试 (速度极快)
if "python" in tags:
    print("包含 'python' 标签")
```

## 4. 控制流

### (1) 条件语句 (if, elif, else)
```python
score: int = 85

if score >= 90:
    print("优秀")
elif score >= 80:
    print("良好")
elif score >= 60:
    print("及格")
else:
    print("需努力")
```

### (2) 循环 (for, while)

#### `for` 循环
常用于遍历序列（如列表、字符串）。

```python
for fruit in fruits:
    print(f"我喜欢吃 {fruit}")

# 使用 range() 生成数字序列
for i in range(3):
    print(f"循环次数: {i}")

# 同时获取索引和值
for index, fruit in enumerate(fruits):
    print(f"第 {index + 1} 个水果是 {fruit}")
```

#### `while` 循环
当某个条件为真时，持续执行。

```python
count = 3
while count > 0:
    print(f"倒计时: {count}")
    count -= 1
print("发射！")
```

## 5. 函数 (Function)

函数是组织好的、可重复使用的、用来实现单一相关功能的代码段。现代 Python 强烈推荐使用类型提示。

```python
def greet(name: str, greeting: str = "你好") -> str:
    """
    一个带类型提示和文档字符串 (docstring) 的函数。

    Args:
        name (str): 要问候的人的名字。
        greeting (str, optional): 使用的问候语. Defaults to "你好".

    Returns:
        str: 完整的问候信息。
    """
    return f"{greeting}, {name}!"

# 调用函数
message = greet("小明")
print(message)

message_en = greet("John", "Hello")
print(message_en)
```

## 6. 模块与异常处理

### 模块导入
从 Python 标准库或其他文件中导入功能。

```python
import math
from collections import Counter

print(f"圆周率约等于: {math.pi}")

word_counts = Counter("hello world")
print(f"字母 'l' 出现了 {word_counts['l']} 次")
```

### 异常处理 (try...except)
优雅地处理可能发生的错误。

```python
try:
    result = 10 / 0
except ZeroDivisionError:
    print("错误：不能除以零！")
finally:
    print("无论如何，最终都会执行此块。")
```

## 7. 综合示例：一个简单的待办事项列表

让我们把所有知识点串联起来，编写一个简单的命令行待办事项应用。

```python
# simple_todo.py
def show_tasks(tasks: list[str]) -> None:
    """显示所有待办事项。"""
    print("\n--- 待办事项 ---")
    if not tasks:
        print("列表为空！")
    for index, task in enumerate(tasks, start=1):
        print(f"{index}. {task}")
    print("----------------\n")

def add_task(tasks: list[str], new_task: str) -> None:
    """添加一个新的待办事项。"""
    tasks.append(new_task)
    print(f"已添加任务: '{new_task}'")

def main() -> None:
    """程序主函数。"""
    my_tasks: list[str] = []
    
    while True:
        print("操作: 1.显示任务 2.添加任务 3.退出")
        choice = input("请选择操作: ")
        
        if choice == '1':
            show_tasks(my_tasks)
        elif choice == '2':
            task_to_add = input("请输入要添加的任务: ")
            add_task(my_tasks, task_to_add)
        elif choice == '3':
            print("感谢使用，再见！")
            break
        else:
            print("无效输入，请重新选择。")

if __name__ == "__main__":
    main()
```
将以上代码保存为 `simple_todo.py` 并运行它，你就可以通过命令行与你的第一个 Python 应用交互了！ 