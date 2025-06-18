# Python 标准库：内置的瑞士军刀

Python 的一个巨大优势是其"内置电池"(batteries included)的哲学，即它自带一个庞大而功能丰富的标准库。这意味着在没有网络连接、无法安装第三方包的情况下，你依然能完成大量工作。本章将导览其中最常用、最有价值的部分。

## 1. 文件与路径操作：`os` 与现代的 `pathlib`

### `os` 模块：传统方式
`os` 模块提供了与操作系统交互的功能，其 `os.path` 子模块用于处理路径。

```python
import os

# 路径拼接 (跨平台)
file_path = os.path.join('data', 'raw', 'file.txt')
print(file_path) # 在 Windows 上输出: data\raw\file.txt

# 检查路径是否存在
if not os.path.exists('data/raw'):
    os.makedirs('data/raw') # 递归创建目录
```

### `pathlib` 模块：现代面向对象的方式 (推荐)
自 Python 3.4 起，`pathlib` 提供了面向对象的路径操作接口，更直观、更易用，是现代 Python 开发的首选。

```python
from pathlib import Path

# 创建 Path 对象
p = Path('data/raw')

# 路径拼接
file_path = p / 'file.txt' # 使用 / 操作符，非常直观
print(file_path)

# 创建目录
p.mkdir(parents=True, exist_ok=True) # 等同于 os.makedirs

# 读写文件
file_path.write_text('你好, pathlib!', encoding='utf-8')
content = file_path.read_text(encoding='utf-8')
print(content)

# 遍历文件
for py_file in Path('.').glob('*.py'):
    print(py_file.name)
```

## 2. 数据持久化与交换

### `json`：与 Web 世界无缝对接
`json` 模块用于在 Python 对象（主要是字典和列表）与 JSON 字符串之间进行转换。

```python
import json

# Python 字典
data = {
    'name': 'Alice',
    'age': 30,
    'is_student': False,
    'courses': ['Math', 'Science']
}

# 将 Python 字典编码为 JSON 字符串
json_string = json.dumps(data, indent=4, ensure_ascii=False)
print(json_string)

# 将 JSON 字符串解码为 Python 字典
parsed_data = json.loads(json_string)
print(parsed_data['name'])
```

### `pickle`：Python 对象的专属序列化
`pickle` 模块可以将几乎任何 Python 对象（包括自定义类的实例）序列化为字节流，以便存储或传输。

**安全警告**: `pickle` 并不安全，不要反序列化来自不可信来源的数据，因为它可能执行任意代码。

```python
import pickle

class MyObject:
    def __init__(self, value):
        self.value = value

# 创建一个对象
obj = MyObject(42)

# 序列化到文件
with open('data.pkl', 'wb') as f:
    pickle.dump(obj, f)

# 从文件反序列化
with open('data.pkl', 'rb') as f:
    loaded_obj = pickle.load(f)
    print(loaded_obj.value) # 输出: 42
```

## 3. 日期与时间：`datetime`

`datetime` 模块是处理日期和时间的标准工具。

```python
from datetime import datetime, timedelta, timezone

# 获取当前时间
now = datetime.now()
print(f"当前本地时间: {now}")

# 获取带时区的当前 UTC 时间
now_utc = datetime.now(timezone.utc)
print(f"当前 UTC 时间: {now_utc}")

# 创建一个 timedelta 对象表示时间差
one_day = timedelta(days=1)
yesterday = now - one_day
print(f"昨天是: {yesterday}")

# 格式化日期为字符串 (strftime)
print(now.strftime('%Y-%m-%d %H:%M:%S'))

# 从字符串解析日期 (strptime)
date_str = '2023-01-01 12:30:00'
dt_obj = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
print(f"解析后的日期对象: {dt_obj}")
```

## 4. 高级数据结构：`collections`

`collections` 模块提供了一系列标准数据类型（`dict`, `list`, `set`, `tuple`）的替代品。

-   `defaultdict`: 创建一个带有默认值的字典。当你访问一个不存在的键时，它会自动为你创建一个默认值，而不是抛出 `KeyError`。
-   `Counter`: 一个字典的子类，用于计数可哈希对象。
-   `deque`: 发音类似 "deck"，是一个双端队列，支持从两端快速地添加和弹出元素。

```python
from collections import defaultdict, Counter, deque

# defaultdict
dd = defaultdict(int) # 设置默认值为 int(), 即 0
dd['a'] += 1
print(dd['a']) # 输出: 1
print(dd['b']) # 输出: 0 (因为 'b' 不存在，自动创建并返回 0)

# Counter
word_counts = Counter("abracadabra")
print(word_counts) # Counter({'a': 5, 'b': 2, 'r': 2, 'c': 1, 'd': 1})
print(word_counts.most_common(2)) # [('a', 5), ('b', 2)]

# deque
d = deque(['a', 'b', 'c'])
d.appendleft('x') # 从左边添加
d.pop() # 从右边弹出
print(d) # deque(['x', 'a', 'b'])
```

## 5. 其他实用工具

### `random`：生成随机数
```python
import random

print(random.randint(1, 10)) # 生成一个 1 到 10 之间的整数
print(random.choice(['A', 'B', 'C'])) # 从序列中随机选择一个元素
my_list = [1, 2, 3, 4]
random.shuffle(my_list) # 原地打乱列表
print(my_list)
```

### `argparse`：创建命令行接口
`argparse` 模块可以让你轻松地为你的脚本编写用户友好的命令行接口。

```python
# a_script.py
import argparse

parser = argparse.ArgumentParser(description='一个简单的示例程序')
parser.add_argument('name', type=str, help='你的名字')
parser.add_argument('-c', '--count', type=int, default=1, help='重复次数')
args = parser.parse_args()

for _ in range(args.count):
    print(f"你好, {args.name}!")
```
在终端中运行:
`python a_script.py Alice --count 3`

### `http.server`：快速启动本地 Web 服务器
这是一个非常方便的工具，可以快速地在当前目录启动一个 Web 服务器来分享文件。
```bash
# 进入你想要分享的文件夹
# 然后运行以下命令
python -m http.server 8000
```
现在打开浏览器访问 `http://localhost:8000` 即可看到文件列表。 