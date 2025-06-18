# Go语言系统工具开发

Go语言非常适合用于开发系统工具、命令行（CLI）应用和后台服务。它的跨平台编译能力、生成静态二进制文件的特性、以及强大的并发和网络库，使得分发和运行Go编写的工具变得异常简单。

## 1. 为什么用Go开发系统工具？

- **跨平台编译**: 可以轻松地将一份代码编译到Windows, macOS, Linux等不同平台，无需修改。
- **静态二进制文件**: 编译结果是单个可执行文件，不依赖任何外部库。用户只需下载一个文件即可运行，极大简化了分发和部署。
- **高性能**: Go的性能足以胜任文件处理、网络通信、数据转换等常见系统任务。
- **并发支持**: Goroutine使得并行处理任务（如并发处理多个文件）变得轻而易举。
- **强大的标准库**: `os`, `io`, `flag`, `net`等标准库提供了开发系统工具所需的大部分功能。

## 2. 命令行参数处理

### 2.1 标准库`flag`
`flag`包提供了基础的命令行参数解析功能。

```go
package main

import (
    "flag"
    "fmt"
)

func main() {
    // 定义一个字符串标志 -name，默认值为"World"，用法说明为"Your name"
    name := flag.String("name", "World", "Your name")
    // 定义一个整数标志 -age
    age := flag.Int("age", 25, "Your age")
    
    // 解析命令行参数
    flag.Parse()
    
    fmt.Printf("Hello, %s! You are %d years old.\n", *name, *age)
    // 打印非标志参数
    fmt.Println("Other args:", flag.Args())
}
// 运行: go run main.go -name=Alice -age=30 other_arg
```

### 2.2 使用`Cobra`构建现代CLI
对于复杂的CLI应用（如`git`, `docker`, `kubectl`），通常需要子命令、嵌套标志等高级功能。`Cobra`是一个非常流行的库，专门用于构建这类应用。

**核心概念:**
- **`Command`**: 代表一个命令或子命令。
- **`Persistent Flags`**: 对该命令及其所有子命令都有效的标志。
- **`Local Flags`**: 只对该命令有效的标志。

**Cobra示例:**
```go
// main.go
package main
import "path/to/your/cmd" // 导入cobra命令包
func main() {
    cmd.Execute()
}

// cmd/root.go
package cmd
import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
    Use:   "my-cli",
    Short: "A brief description of your application",
    Run: func(cmd *cobra.Command, args []string) {
        // 根命令的执行逻辑
    },
}

// 子命令
var helloCmd = &cobra.Command{
    Use:   "hello",
    Short: "Prints a hello message",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("Hello, from subcommand!")
    },
}

func init() {
    // 添加子命令
    rootCmd.AddCommand(helloCmd)
    // 添加标志
    rootCmd.PersistentFlags().StringP("author", "a", "Your Name", "Author name for copyright attribution")
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

## 3. 与操作系统交互

### `os`包
- `os.Args`: 获取原始的命令行参数（包括程序名）。
- `os.Getenv`, `os.Setenv`: 读写环境变量。
- `os.Exit`: 退出程序并返回状态码。
- 文件操作: `os.Create`, `os.Open`, `os.Stat`, `os.Remove`, `os.MkdirAll`等。

### `os/exec`包
用于运行外部命令。
```go
import (
    "os/exec"
    "log"
)

func runCommand() {
    cmd := exec.Command("ls", "-l", "/tmp")
    
    // 获取命令输出
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Fatalf("cmd.Run() failed with %s\n", err)
    }
    fmt.Printf("Output:\n%s\n", string(output))
}
```

## 4. 处理操作系统信号

系统工具通常需要能响应操作系统信号（如`Ctrl+C`，即`SIGINT`）以实现优雅退出。

```go
import (
    "os"
    "os/signal"
    "syscall"
)

func waitForSignal() {
    // 创建一个channel来接收信号
    sigs := make(chan os.Signal, 1)
    
    // 注册我们关心的信号
    signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
    
    // 阻塞等待信号
    <-sigs
    fmt.Println("\nSignal received, shutting down gracefully...")
    // 在这里执行清理工作
}
```

## 5. 并发应用示例

假设我们要编写一个工具来计算多个文件中的总行数，我们可以使用goroutine来并行处理。

```go
package main

import (
    "bufio"
    "fmt"
    "os"
    "sync"
)

func countLines(filename string, wg *sync.WaitGroup, countChan chan<- int) {
    defer wg.Done()

    file, err := os.Open(filename)
    if err != nil {
        fmt.Fprintf(os.Stderr, "error opening file %s: %v\n", filename, err)
        return
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    lineCount := 0
    for scanner.Scan() {
        lineCount++
    }
    countChan <- lineCount
}

func main() {
    filenames := os.Args[1:] // 从命令行获取文件名
    if len(filenames) == 0 {
        fmt.Println("Usage: go run main.go <file1> <file2> ...")
        return
    }

    var wg sync.WaitGroup
    countChan := make(chan int, len(filenames))

    for _, filename := range filenames {
        wg.Add(1)
        go countLines(filename, &wg, countChan)
    }

    wg.Wait()
    close(countChan)

    totalLines := 0
    for count := range countChan {
        totalLines += count
    }

    fmt.Printf("Total lines: %d\n", totalLines)
}
```
这个示例为每个文件启动一个goroutine，并使用`WaitGroup`来等待所有goroutine完成，最后通过channel汇总结果。 