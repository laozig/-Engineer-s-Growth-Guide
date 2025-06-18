# Python 并发：线程与进程

在 Python 中实现并发和并行有多种方式，最核心的两个模块是 `threading`（多线程）和 `multiprocessing`（多进程）。理解它们的区别和适用场景至关重要。

## 1. 核心概念：并发 vs. 并行

-   **并发 (Concurrency)**: 指的是系统能够**处理**多个任务的能力，但不一定**同时**执行它们。任务可以被交替执行，看起来像在同时运行。
    *   *比喻*: 一个咖啡师在两台咖啡机之间来回操作，先启动第一台，在它研磨咖啡豆时，去操作第二台。
-   **并行 (Parallelism)**: 指的是系统能够**同时**执行多个任务的能力，这需要多核处理器的支持。
    *   *比喻*: 两个咖啡师，每人操作一台咖啡机，同时制作两杯咖啡。

在 Python 中，`threading` 主要用于实现并发，而 `multiprocessing` 用于实现并行。

## 2. GIL：Python 线程的特殊限制

**全局解释器锁 (Global Interpreter Lock, GIL)** 是理解 Python 线程的关键。
-   **它是什么？** GIL 是 CPython 解释器中的一个互斥锁，它确保在任何时刻，只有一个线程在执行 Python 字节码。
-   **为什么存在？** 为了简化 CPython 的内存管理，防止多个线程同时访问 Python 对象，从而避免复杂的内存安全问题。
-   **后果是什么？** 这意味着即使在多核 CPU 上，Python 的多线程也无法实现 CPU 密集型任务的并行计算。一个计算密集的线程会一直持有 GIL，导致其他线程无法执行。

## 3. `threading` 模块：用于 I/O 密集型任务

尽管有 GIL 的限制，但多线程对于 I/O 密集型任务依然非常有效。

**为什么？** 因为当一个线程执行阻塞的 I/O 操作（如等待网络响应、读写文件）时，它会**释放 GIL**，允许其他线程运行。这实现了任务的并发执行。

### (1) 创建线程

```python
import threading
import time

def worker(name: str, delay: int):
    print(f"线程 {name}: 开始工作")
    time.sleep(delay) # 模拟 I/O 阻塞，此时会释放 GIL
    print(f"线程 {name}: 工作完成")

# 创建线程对象
thread1 = threading.Thread(target=worker, args=("A", 2))
thread2 = threading.Thread(target=worker, args=("B", 3))

# 启动线程
thread1.start()
thread2.start()

# 等待所有线程完成
thread1.join()
thread2.join()

print("所有线程均已完成。")
```

### (2) 线程安全与锁 (Lock)
当多个线程共享并修改同一个数据时，可能会发生**竞态条件 (Race Condition)**，导致数据不一致。

```python
# 非线程安全的例子
balance = 0
def change_balance(n):
    global balance
    # 读取、修改、写回不是原子操作
    local_copy = balance
    local_copy += n
    time.sleep(0.1) # 模拟操作耗时
    balance = local_copy

# 使用锁来保证线程安全
balance_safe = 0
lock = threading.Lock()
def change_balance_safe(n):
    global balance_safe
    with lock: # 使用 with 语句自动获取和释放锁
        local_copy = balance_safe
        local_copy += n
        time.sleep(0.1)
        balance_safe = local_copy

# 如果你用多线程同时调用 change_balance，结果将不可预测
# 而 change_balance_safe 的结果是正确的
```

## 4. `multiprocessing` 模块：用于 CPU 密集型任务

`multiprocessing` 模块通过创建全新的子进程来绕过 GIL，从而实现真正的并行计算。
-   每个进程都有自己独立的内存空间和 Python 解释器。
-   它可以充分利用多核 CPU 的计算能力。

### (1) 创建进程
`multiprocessing` 的 API 与 `threading` 非常相似。

```python
from multiprocessing import Process

def cpu_bound_task(n):
    """一个 CPU 密集型任务"""
    result = 0
    for i in range(n):
        result += i
    print(f"计算结果: {result}")

# 在 Windows 上，启动进程的代码必须放在 if __name__ == '__main__': 块中
if __name__ == '__main__':
    p1 = Process(target=cpu_bound_task, args=(10**7,))
    p2 = Process(target=cpu_bound_task, args=(10**7,))

    p1.start()
    p2.start()

    p1.join()
    p2.join()
    print("所有进程均已完成。")
```

### (2) 进程池 (`Pool`)
`Pool` 对象提供了一种便捷的方式来管理一个工作进程池，并将任务分发给它们。

```python
from multiprocessing import Pool

def square(x):
    return x * x

if __name__ == '__main__':
    numbers = [1, 2, 3, 4, 5, 6, 7, 8]
    # 创建一个包含 4 个工作进程的池
    with Pool(processes=4) as pool:
        # map 方法会将 numbers 列表中的每个元素分发给一个工作进程
        results = pool.map(square, numbers)
    
    print(results) # 输出: [1, 4, 9, 16, 25, 36, 49, 64]
```
`Pool` 会自动处理进程的创建、任务分配和结果收集，非常方便。

## 5. 如何选择：`threading` vs `multiprocessing` vs `asyncio`

| 模块 | 核心机制 | 适用场景 | 优点 | 缺点 |
| --- | --- | --- | --- | --- |
| **`threading`** | 并发 (Concurrency) | **I/O 密集型** (网络、磁盘) | 内存共享方便，启动开销小 | 受 GIL 限制，无法利用多核 CPU |
| **`multiprocessing`** | 并行 (Parallelism) | **CPU 密集型** (计算、处理) | 能充分利用多核 CPU，绕开 GIL | 启动开销大，进程间通信 (IPC) 复杂 |
| **`asyncio`** | 并发 (Concurrency) | **高并发 I/O 密集型** (上万连接) | 单线程，极高并发能力，开销极小 | 需要专门的异步库，代码有一定心智负担 |

**简单法则**:
-   你的任务是**计算密集型**的吗？用 `multiprocessing`。
-   你的任务是**I/O 密集型**且并发数不高吗？用 `threading`。
-   你的任务是**I/O 密集型**且需要极高的并发能力吗？用 `asyncio`。 