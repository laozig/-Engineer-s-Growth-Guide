# Python 高级特性

当你掌握了 Python 的基础知识后，一系列高级特性将为你打开新世界的大门，让你的代码更高效、更简洁、也更具"Pythonic"风格。本章将深入探讨生成器、装饰器和上下文管理器等核心高级概念。

## 1. 迭代器 (Iterator) 与可迭代对象 (Iterable)

-   **可迭代对象 (Iterable)**: 任何你可以用 `for` 循环遍历的东西都是可迭代对象，例如列表、字符串、字典、文件等。其内部必须实现 `__iter__()` 方法。
-   **迭代器 (Iterator)**: 是一个表示数据流的对象。它实现了 `__next__()` 方法，该方法返回数据流中的下一个元素。当没有更多元素时，`__next__()` 会抛出 `StopIteration` 异常。

`for` 循环的本质就是：
1.  对一个可迭代对象调用 `iter()` 来获取其迭代器。
2.  不断调用这个迭代器的 `next()` 方法来获取每个元素。
3.  捕捉 `StopIteration` 异常并结束循环。

## 2. 生成器 (Generators): 优雅地创建迭代器

手动创建一个迭代器类通常很繁琐。Python 的生成器提供了一种极其简洁的方式来创建迭代器。

### (1) 生成器函数 (Generator Functions)
一个使用了 `yield` 关键字的函数就是一个生成器函数。它不会一次性返回所有结果，而是在每次被调用时"产出"一个值，并暂停执行，直到下一次被请求。

```python
import time

def countdown(n: int):
    """一个简单的倒计时生成器。"""
    print("开始倒计时！")
    while n > 0:
        yield n  # 使用 yield "产出"一个值
        n -= 1

# 创建一个生成器对象
c = countdown(3)

# 每次调用 next() 都会执行到下一个 yield
print(next(c)) # 输出: 开始倒计时！\n 3
print(next(c)) # 输出: 2
print(next(c)) # 输出: 1
# print(next(c)) # 再次调用会抛出 StopIteration

# 生成器本身就是迭代器，可以直接用于 for 循环
for i in countdown(3):
    print(i)
```
**优势**: 生成器是"懒加载"的，它只在需要时才计算和生成值，对于处理大数据集或无限序列（如网络数据流）时，内存效率极高。

### (2) 生成器表达式 (Generator Expressions)
类似于列表推导式，但使用圆括号 `()`。它创建的是一个生成器对象，而不是一个完整的列表，因此也具有极高的内存效率。

```python
# 列表推导式：立即在内存中创建一个包含一百万个元素的列表
list_comp = [i * i for i in range(1000000)]

# 生成器表达式：创建一个生成器对象，不占用大量初始内存
gen_exp = (i * i for i in range(1000000))

# 只有在你迭代它时，值才会被计算出来
print(sum(gen_exp)) # 计算一百万个平方数的和，内存占用很小
```

## 3. 装饰器 (Decorators): 在不修改代码的情况下增强函数

装饰器本质上是一个函数，它接收另一个函数作为参数，并返回一个新的、功能得到增强的函数。它是一种强大的元编程（metaprogramming）工具。

```python
import functools

def timer(func):
    """一个计算并打印函数执行时间的装饰器。"""
    @functools.wraps(func) # 保持原函数的元信息(如名称、文档字符串)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        value = func(*args, **kwargs) # 调用原始函数
        end_time = time.perf_counter()
        run_time = end_time - start_time
        print(f"函数 '{func.__name__}' 执行完毕，耗时 {run_time:.4f} 秒。")
        return value
    return wrapper

@timer  # @ 语法糖等价于 a_slow_function = timer(a_slow_function)
def a_slow_function(delay: float) -> None:
    """一个模拟耗时操作的函数。"""
    time.sleep(delay)

a_slow_function(1.5)
# 输出: 函数 'a_slow_function' 执行完毕，耗时 1.50XX 秒。
```
装饰器广泛应用于日志记录、性能测试、权限校验、缓存等场景。

## 4. 上下文管理器 (Context Managers) 与 `with` 语句

`with` 语句提供了一种优雅的方式来管理资源，确保资源（如文件、网络连接、数据库会话）在使用完毕后能够被正确地关闭或释放，即使在代码块中发生异常。

### (1) 基于类的上下文管理器
一个类如果实现了 `__enter__()` 和 `__exit__()` 方法，就可以用于 `with` 语句。

```python
class ManagedFile:
    def __init__(self, filename: str, mode: str):
        self.filename = filename
        self.mode = mode

    def __enter__(self):
        """进入 with 块时调用，返回值赋给 as 后面的变量。"""
        print(f"打开文件 {self.filename}")
        self.file = open(self.filename, self.mode, encoding='utf-8')
        return self.file

    def __exit__(self, exc_type, exc_val, exc_tb):
        """退出 with 块时调用，负责清理资源。"""
        if self.file:
            self.file.close()
        print(f"文件 {self.filename} 已关闭。")
        # 如果 __exit__ 返回 False 或 None，异常会正常抛出
        # 如果返回 True，异常会被抑制
        return False

with ManagedFile('hello.txt', 'w') as f:
    f.write('你好，上下文管理器！')
    # a = 1 / 0 # 即使这里有异常，__exit__ 依然会被调用
```

### (2) 基于生成器的上下文管理器
使用 `contextlib` 模块可以更简单地创建上下文管理器。

```python
from contextlib import contextmanager

@contextmanager
def managed_file_gen(filename: str, mode: str):
    f = open(filename, mode, encoding='utf-8')
    try:
        yield f # yield 之前是 __enter__ 的逻辑
    finally:
        f.close() # yield 之后是 __exit__ 的逻辑

with managed_file_gen('hello.txt', 'r') as f:
    print(f.read())
```

## 5. Lambda 函数
Lambda 函数是一种小型的、匿名的、单行函数。它通常在需要一个简单函数作为参数的地方使用。

```python
# 普通函数
def add(x, y):
    return x + y

# 等价的 Lambda 函数
add_lambda = lambda x, y: x + y

print(add_lambda(3, 5)) # 输出: 8

# Lambda 的常见用途：作为排序的 key
points = [(1, 2), (3, 1), (5, -4)]
points.sort(key=lambda p: p[1]) # 按每个元组的第二个元素排序
print(points) # 输出: [(5, -4), (3, 1), (1, 2)]
```
Lambda 对于需要一个快速、一次性的小函数的场景非常方便，但对于复杂的逻辑，应始终使用 `def` 定义的常规函数。 