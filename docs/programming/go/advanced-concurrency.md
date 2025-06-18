# Go语言高级并发模式

在掌握了Goroutine和Channel的基础之后，我们可以探索一些更高级的并发模式，这些模式能够帮助我们构建更复杂、健壮和高效的并发程序。同时，深入理解`sync`包和`context`包也是Go并发编程的进阶必备技能。

## 1. 核心并发模式

### 1.1 流水线 (Pipeline)
流水线模式将一个任务分解为多个阶段，每个阶段由一个Goroutine处理，并通过Channel连接起来。一个阶段的输出是下一个阶段的输入。

**特点:**
- **解耦**: 每个阶段只关注自己的任务。
- **并行**: 不同阶段可以并行处理不同的数据。
- **可扩展**: 可以方便地增加或移除阶段。

**示例:** 一个生成数字、计算平方、打印结果的流水线。
```go
package main

import "fmt"

// 1. 生成整数
func generator(done <-chan struct{}, nums ...int) <-chan int {
    out := make(chan int)
    go func() {
        defer close(out)
        for _, n := range nums {
            select {
            case out <- n:
            case <-done:
                return
            }
        }
    }()
    return out
}

// 2. 计算平方
func square(done <-chan struct{}, in <-chan int) <-chan int {
    out := make(chan int)
    go func() {
        defer close(out)
        for n := range in {
            select {
            case out <- n * n:
            case <-done:
                return
            }
        }
    }()
    return out
}

func main() {
    done := make(chan struct{})
    defer close(done)

    in := generator(done, 2, 3)
    ch := square(done, in)

    // 从流水线消费结果
    for ret := range ch {
        fmt.Println(ret) // 4, 9
    }
}
```

### 1.2 扇出、扇入 (Fan-out, Fan-in)

- **扇出 (Fan-out)**: 同一个Channel的数据被多个Goroutine处理，以实现并行化。
- **扇入 (Fan-in)**: 将多个Channel的数据合并到一个Channel中。

这两种模式通常结合使用，例如，一个任务分发给多个worker（扇出），然后将所有worker的结果汇总（扇入）。

**示例:**
```go
package main

import (
    "fmt"
    "sync"
)

// ... (使用上面的generator和square函数) ...

// fanIn合并多个channel的结果
func fanIn(done <-chan struct{}, channels ...<-chan int) <-chan int {
    var wg sync.WaitGroup
    out := make(chan int)

    output := func(c <-chan int) {
        defer wg.Done()
        for n := range c {
            select {
            case out <- n:
            case <-done:
                return
            }
        }
    }

    wg.Add(len(channels))
    for _, c := range channels {
        go output(c)
    }

    go func() {
        wg.Wait()
        close(out)
    }()
    return out
}

func main() {
    done := make(chan struct{})
    defer close(done)

    in := generator(done, 2, 3, 4, 5)

    // 扇出: 启动两个goroutine来处理数据
    c1 := square(done, in)
    c2 := square(done, in)

    // 扇入: 将两个channel的结果合并
    out := fanIn(done, c1, c2)

    for ret := range out {
        fmt.Println(ret)
    }
}
```

### 1.3 工作池 (Worker Pools)
当需要处理大量任务，但又不希望无限创建Goroutine时（以避免耗尽系统资源），可以使用工作池模式。该模式会启动固定数量的worker Goroutine，从任务Channel接收任务并执行。

**示例:**
```go
package main

import (
    "fmt"
    "time"
)

func worker(id int, jobs <-chan int, results chan<- int) {
    for j := range jobs {
        fmt.Printf("worker %d started job %d\n", id, j)
        time.Sleep(time.Second) // 模拟耗时任务
        fmt.Printf("worker %d finished job %d\n", id, j)
        results <- j * 2
    }
}

func main() {
    const numJobs = 5
    jobs := make(chan int, numJobs)
    results := make(chan int, numJobs)

    // 启动3个worker
    for w := 1; w <= 3; w++ {
        go worker(w, jobs, results)
    }

    // 发送5个任务
    for j := 1; j <= numJobs; j++ {
        jobs <- j
    }
    close(jobs)

    // 收集结果
    for a := 1; a <= numJobs; a++ {
        <-results
    }
}
```

## 2. Context包的使用

`context`包用于在Goroutine之间传递请求作用域的数据、取消信号（cancellation）和超时（timeout）。它对于控制需要跨越多个API调用和Goroutine的复杂操作至关重要。

### 主要功能
- **取消操作**: 当一个操作不再需要时，可以通过`context`通知所有相关的Goroutine停止工作，释放资源。
- **超时控制**: 可以设置一个操作的最长执行时间。
- **传递请求域的值**: 可以在Goroutine之间安全地传递键值对数据。

### 示例: 使用`context`控制超时
```go
package main

import (
    "context"
    "fmt"
    "time"
)

func longRunningTask(ctx context.Context, results chan<- string) {
    select {
    case <-time.After(5 * time.Second): // 模拟一个耗时5秒的任务
        results <- "task completed"
    case <-ctx.Done(): // context被取消或超时
        results <- ctx.Err().Error()
    }
}

func main() {
    // 创建一个超时时间为3秒的context
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()

    results := make(chan string, 1)
    go longRunningTask(ctx, results)

    // 等待结果
    res := <-results
    fmt.Println(res) // 输出: context deadline exceeded
}
```

## 3. `sync`包深入

### `sync.WaitGroup`
用于等待一组Goroutine执行完毕。主Goroutine调用`Add`设置需要等待的Goroutine数量，每个Goroutine在结束时调用`Done`，主Goroutine通过`Wait`等待所有Goroutine完成。

### `sync.Once`
保证某个函数在程序运行期间只被执行一次，常用于初始化单例或全局资源。

### `sync.Pool`
用于缓存和复用临时对象，以减少内存分配和GC压力。`sync.Pool`是并发安全的。

**示例:**
```go
var bufferPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, 4096)
    },
}

func main() {
    buf := bufferPool.Get().([]byte) // 获取一个buffer
    // ... 使用buffer ...
    bufferPool.Put(buf) // 将buffer放回池中
}
```

### `sync.RWMutex` (读写锁)
相比于`sync.Mutex`（互斥锁），`RWMutex`更高效，因为它允许多个读操作同时进行，但写操作是互斥的。适用于读多写少的场景。

## 4. 原子操作 (`sync/atomic`)

`atomic`包提供了底层的原子内存操作，对于实现无锁（lock-free）的并发算法非常有用。它可以保证对一个变量的读、写、修改等操作是不可中断的，避免了竞态条件。

**常用函数:**
- `atomic.AddInt64(&counter, 1)`: 原子地增加
- `atomic.LoadInt64(&counter)`: 原子地读取
- `atomic.StoreInt64(&counter, 10)`: 原子地写入
- `atomic.CompareAndSwapInt64(&val, old, new)`: 比较并交换 (CAS)

## 5. 常见并发问题

- **竞态条件 (Race Condition)**: 多个Goroutine在没有同步的情况下访问和修改共享资源，导致结果不可预测。
  - **检测**: 使用`go test -race`或`go run -race`来检测竞态条件。
- **死锁 (Deadlock)**: 两个或多个Goroutine相互等待对方释放锁，导致所有Goroutine都无法继续执行。
  - **预防**:
    - 保持一致的锁获取顺序。
    - 使用`context`设置超时。
    - 避免在持有锁时调用外部或未知的代码。

</rewritten_file>