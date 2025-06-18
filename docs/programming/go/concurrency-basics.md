# Go语言并发编程基础

Go语言的一大特色是内置的并发支持，主要通过**goroutine**（轻量级线程）和**channel**（通道）实现。这种设计使得编写并发程序变得简单而强大。本文档将详细介绍Go语言并发编程的基础概念和实践。

## 目录
- [并发与并行](#并发与并行)
- [Goroutine基础](#goroutine基础)
- [Channel基础](#channel基础)
- [同步模式](#同步模式)
- [Select语句](#select语句)
- [并发模式](#并发模式)
- [并发安全](#并发安全)
- [Context包](#context包)
- [最佳实践](#最佳实践)

## 并发与并行

在深入Go的并发特性前，先了解并发和并行的区别：

- **并发(Concurrency)**：同一时间段内处理多个任务的能力，是一种程序设计方法
- **并行(Parallelism)**：同一时刻执行多个任务的能力，依赖于硬件多核心支持

Go的并发模型基于Tony Hoare的[通信顺序进程(CSP)](https://en.wikipedia.org/wiki/Communicating_sequential_processes)，强调"**通过通信共享内存，而不是通过共享内存通信**"。

## Goroutine基础

Goroutine是Go语言中最基本的并发执行单元，可以将其视为轻量级的线程。

### 创建Goroutine

使用`go`关键字启动一个goroutine：

```go
// 启动一个goroutine执行函数
go functionName(parameters)

// 启动一个goroutine执行匿名函数
go func() {
    // 函数体
}()
```

### 简单示例

```go
package main

import (
    "fmt"
    "time"
)

func sayHello(message string) {
    for i := 0; i < 5; i++ {
        fmt.Println(message)
        time.Sleep(100 * time.Millisecond)
    }
}

func main() {
    // 启动一个goroutine
    go sayHello("世界")
    
    // main goroutine继续执行
    sayHello("你好")
    
    // 注意: 如果main函数结束，所有的goroutine都会被强制终止
}
```

这个程序会打印交错的"世界"和"你好"，展示了goroutine的并发执行。

### Goroutine的特点

1. **轻量级**：相比操作系统线程，goroutine的创建和销毁开销很小（几KB内存）
2. **自动调度**：Go运行时会自动管理goroutine的调度，无需手动管理
3. **可伸缩**：一个程序可以同时运行成千上万个goroutine
4. **非抢占式**：goroutine的切换发生在函数调用点，而非随时被抢占

### 等待Goroutine完成

常见的等待goroutine完成的方法：

1. 使用`sync.WaitGroup`：

```go
package main

import (
    "fmt"
    "sync"
    "time"
)

func worker(id int, wg *sync.WaitGroup) {
    defer wg.Done() // 通知WaitGroup此goroutine已完成
    
    fmt.Printf("Worker %d 开始工作\n", id)
    time.Sleep(time.Second) // 模拟工作负载
    fmt.Printf("Worker %d 工作完成\n", id)
}

func main() {
    var wg sync.WaitGroup
    
    // 启动5个worker goroutines
    for i := 1; i <= 5; i++ {
        wg.Add(1) // 增加等待计数
        go worker(i, &wg)
    }
    
    // 等待所有worker完成
    wg.Wait()
    fmt.Println("所有worker已完成工作")
}
```

### Goroutine闭包陷阱

使用goroutine时，要注意闭包陷阱：

```go
func main() {
    // 错误用法
    for i := 0; i < 5; i++ {
        go func() {
            fmt.Println(i) // 可能会打印意外的值
        }()
    }
    time.Sleep(time.Second)
    
    // 正确用法1：将变量作为参数传递
    for i := 0; i < 5; i++ {
        go func(val int) {
            fmt.Println(val)
        }(i)
    }
    time.Sleep(time.Second)
    
    // 正确用法2：每次迭代创建新变量
    for i := 0; i < 5; i++ {
        i := i // 在循环内创建新变量（Go语言的奇特写法）
        go func() {
            fmt.Println(i)
        }()
    }
    time.Sleep(time.Second)
}
```

## Channel基础

Channel（通道）是goroutine之间的通信机制，用于在goroutine间安全地传递值。

### Channel类型

Channel是带有类型的管道，通过操作符`<-`发送或接收数据：

```go
ch <- v    // 发送值v到通道ch
v := <-ch  // 从通道ch接收值并赋给v
```

### 创建Channel

使用`make`函数创建通道：

```go
// 创建无缓冲通道
ch := make(chan Type)

// 创建带缓冲通道，缓冲区大小为capacity
ch := make(chan Type, capacity)
```

### 无缓冲Channel

无缓冲通道上的发送操作会阻塞，直到另一个goroutine执行对应的接收操作：

```go
package main

import (
    "fmt"
    "time"
)

func sender(ch chan string) {
    fmt.Println("发送者: 准备发送数据")
    ch <- "你好"
    fmt.Println("发送者: 数据已发送")
}

func main() {
    ch := make(chan string) // 无缓冲通道
    
    go sender(ch)
    
    // 给发送者一些时间开始发送
    time.Sleep(100 * time.Millisecond)
    
    fmt.Println("接收者: 准备接收数据")
    msg := <-ch
    fmt.Println("接收者: 收到数据:", msg)
}
```

输出结果：
```
发送者: 准备发送数据
接收者: 准备接收数据
接收者: 收到数据: 你好
发送者: 数据已发送
```

### 带缓冲Channel

带缓冲通道在缓冲区满时才会阻塞发送操作，在缓冲区空时才会阻塞接收操作：

```go
package main

import (
    "fmt"
    "time"
)

func main() {
    ch := make(chan string, 2) // 带2个缓冲区的通道
    
    ch <- "消息1" // 不会阻塞
    ch <- "消息2" // 不会阻塞
    
    // ch <- "消息3" // 会阻塞，因为缓冲区已满
    
    fmt.Println(<-ch) // 输出: 消息1
    fmt.Println(<-ch) // 输出: 消息2
}
```

### 关闭Channel

发送者可以关闭通道，表示不再发送值：

```go
close(ch)
```

接收者可以检测通道是否已关闭：

```go
v, ok := <-ch
// 如果ok为false，表示通道已关闭且没有更多值
```

### 遍历Channel

使用`for range`语法遍历通道，直到通道关闭：

```go
package main

import "fmt"

func fibonacci(n int, ch chan int) {
    x, y := 0, 1
    for i := 0; i < n; i++ {
        ch <- x
        x, y = y, x+y
    }
    close(ch)
}

func main() {
    ch := make(chan int, 10)
    go fibonacci(10, ch)
    
    // 使用for range遍历通道
    for num := range ch {
        fmt.Println(num)
    }
}
```

### Channel方向

可以限制通道的方向，增加程序的类型安全性：

```go
func send(ch chan<- int) {
    ch <- 42 // 只能发送到通道
    // <-ch     // 编译错误：不能从只发送通道接收
}

func receive(ch <-chan int) {
    v := <-ch // 只能从通道接收
    // ch <- 34 // 编译错误：不能向只接收通道发送
    fmt.Println(v)
}

func main() {
    ch := make(chan int)
    go send(ch)
    receive(ch)
}
```

### 使用Channel实现同步

Channel可以用于同步goroutine：

```go
package main

import (
    "fmt"
    "time"
)

func worker(done chan bool) {
    fmt.Println("工作中...")
    time.Sleep(time.Second)
    fmt.Println("工作完成")
    
    // 通知工作完成
    done <- true
}

func main() {
    done := make(chan bool)
    
    go worker(done)
    
    // 等待worker完成
    <-done // 阻塞直到接收到值
    
    fmt.Println("主程序继续执行")
}
```

## 同步模式

### sync包基础

`sync`包提供了基本的同步原语：

1. **WaitGroup**：等待一组goroutine完成
2. **Mutex**：互斥锁，保护共享资源
3. **RWMutex**：读写锁，允许多个读操作或一个写操作
4. **Once**：确保代码只执行一次
5. **Cond**：条件变量，用于等待和通知

#### Mutex示例

```go
package main

import (
    "fmt"
    "sync"
    "time"
)

type Counter struct {
    mu    sync.Mutex
    count int
}

func (c *Counter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.count++
}

func (c *Counter) Value() int {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.count
}

func main() {
    counter := Counter{}
    var wg sync.WaitGroup
    
    // 启动10个goroutine增加计数
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for j := 0; j < 1000; j++ {
                counter.Increment()
            }
        }()
    }
    
    wg.Wait()
    fmt.Println("计数:", counter.Value()) // 输出: 10000
}
```

#### RWMutex示例

```go
package main

import (
    "fmt"
    "sync"
    "time"
)

type Resource struct {
    mu    sync.RWMutex
    value int
}

func (r *Resource) SetValue(v int) {
    r.mu.Lock() // 写锁
    defer r.mu.Unlock()
    
    r.value = v
    time.Sleep(50 * time.Millisecond) // 模拟写操作耗时
}

func (r *Resource) GetValue() int {
    r.mu.RLock() // 读锁
    defer r.mu.RUnlock()
    
    time.Sleep(10 * time.Millisecond) // 模拟读操作耗时
    return r.value
}

func main() {
    resource := Resource{}
    var wg sync.WaitGroup
    
    // 启动5个读goroutine
    for i := 0; i < 5; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            for j := 0; j < 3; j++ {
                fmt.Printf("读取者 %d: 值 = %d\n", id, resource.GetValue())
                time.Sleep(100 * time.Millisecond)
            }
        }(i)
    }
    
    // 启动2个写goroutine
    for i := 0; i < 2; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            for j := 0; j < 3; j++ {
                newValue := id*100 + j
                resource.SetValue(newValue)
                fmt.Printf("写入者 %d: 设置值 = %d\n", id, newValue)
                time.Sleep(200 * time.Millisecond)
            }
        }(i)
    }
    
    wg.Wait()
}
```

#### sync.Once示例

```go
package main

import (
    "fmt"
    "sync"
)

func main() {
    var once sync.Once
    var wg sync.WaitGroup
    
    for i := 0; i < 10; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            
            // 此初始化代码只会执行一次
            once.Do(func() {
                fmt.Println("初始化 - 只执行一次！")
            })
            
            fmt.Printf("Goroutine %d 运行\n", id)
        }(i)
    }
    
    wg.Wait()
}
```

## Select语句

Select语句用于在多个通道操作中进行选择，类似于switch语句，但用于通道：

```go
package main

import (
    "fmt"
    "time"
)

func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)
    
    go func() {
        time.Sleep(1 * time.Second)
        ch1 <- "消息1"
    }()
    
    go func() {
        time.Sleep(2 * time.Second)
        ch2 <- "消息2"
    }()
    
    for i := 0; i < 2; i++ {
        select {
        case msg1 := <-ch1:
            fmt.Println("收到消息1:", msg1)
        case msg2 := <-ch2:
            fmt.Println("收到消息2:", msg2)
        }
    }
}
```

## 并发模式

### 并发模式示例

```go
package main

import (
    "fmt"
    "time"
)

func worker(id int) {
    fmt.Printf("Worker %d 开始工作\n", id)
    time.Sleep(time.Second)
    fmt.Printf("Worker %d 工作完成\n", id)
}

func main() {
    for i := 1; i <= 5; i++ {
        go worker(i)
    }
    
    // 等待所有goroutine完成
    time.Sleep(5 * time.Second)
}
```

## 并发安全

### 并发安全示例

```go
package main

import (
    "fmt"
    "sync"
)

var counter int
var mu sync.Mutex

func increment() {
    mu.Lock()
    defer mu.Unlock()
    counter++
}

func main() {
    var wg sync.WaitGroup
    
    for i := 0; i < 1000; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            increment()
        }()
    }
    
    wg.Wait()
    fmt.Println("最终计数:", counter)
}
```

## Context包

Context包用于在goroutine之间传递上下文信息，特别是在并发环境中。

### Context示例

```go
package main

import (
    "context"
    "fmt"
    "time"
)

func worker(ctx context.Context, id int) {
    fmt.Printf("Worker %d 开始工作\n", id)
    select {
    case <-ctx.Done():
        fmt.Printf("Worker %d 被取消\n", id)
        return
    case <-time.After(time.Second):
        fmt.Printf("Worker %d 工作完成\n", id)
    }
}

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    
    for i := 1; i <= 5; i++ {
        go worker(ctx, i)
    }
    
    // 等待一段时间后取消所有goroutine
    time.Sleep(3 * time.Second)
    cancel()
    
    // 等待所有goroutine完成
    time.Sleep(time.Second)
}
```

## 最佳实践

### 最佳实践示例

```go
package main

import (
    "fmt"
    "sync"
)

func main() {
    var wg sync.WaitGroup
    
    for i := 1; i <= 5; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            fmt.Printf("Worker %d 开始工作\n", id)
            // 模拟工作负载
            time.Sleep(time.Second)
            fmt.Printf("Worker %d 工作完成\n", id)
        }(i)
    }
    
    wg.Wait()
    fmt.Println("所有worker已完成工作")
}
``` 