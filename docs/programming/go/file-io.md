# Go语言文件操作与I/O

Go语言提供了丰富的文件和I/O操作功能，通过标准库中的包如`os`、`io`、`bufio`、`ioutil`等实现对文件及其他I/O源的操作。本文档详细介绍Go语言中文件操作和I/O的常用方法和最佳实践。

## 目录
- [文件基础操作](#文件基础操作)
- [读取文件](#读取文件)
- [写入文件](#写入文件)
- [缓冲I/O](#缓冲io)
- [目录操作](#目录操作)
- [路径处理](#路径处理)
- [临时文件](#临时文件)
- [I/O接口](#io接口)
- [常见I/O模式](#常见io模式)
- [性能优化](#性能优化)

## 文件基础操作

### 打开和关闭文件

使用`os.Open`函数打开文件：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    // 打开文件
    file, err := os.Open("example.txt")
    if err != nil {
        fmt.Println("打开文件错误:", err)
        return
    }
    
    // 确保在函数结束时关闭文件
    defer file.Close()
    
    // 使用文件...
    fmt.Println("文件打开成功")
}
```

使用`os.OpenFile`可以更精细地控制打开文件的模式：

```go
file, err := os.OpenFile(
    "example.txt",
    os.O_RDWR|os.O_CREATE|os.O_APPEND, // 打开模式
    0644,                             // 权限
)
```

常用的文件打开模式：

- `os.O_RDONLY`: 只读模式
- `os.O_WRONLY`: 只写模式
- `os.O_RDWR`: 读写模式
- `os.O_CREATE`: 如果文件不存在则创建
- `os.O_APPEND`: 写入数据时追加到文件末尾
- `os.O_EXCL`: 与O_CREATE一起使用，确保创建一个新文件
- `os.O_TRUNC`: 打开文件时清空文件内容

### 创建文件

使用`os.Create`函数创建文件：

```go
func main() {
    // 创建文件（如果存在则截断）
    file, err := os.Create("newfile.txt")
    if err != nil {
        fmt.Println("创建文件错误:", err)
        return
    }
    defer file.Close()
    
    fmt.Println("文件创建成功")
}
```

### 获取文件信息

使用`os.Stat`函数获取文件信息：

```go
func main() {
    fileInfo, err := os.Stat("example.txt")
    if err != nil {
        if os.IsNotExist(err) {
            fmt.Println("文件不存在")
        } else {
            fmt.Println("获取文件信息错误:", err)
        }
        return
    }
    
    fmt.Printf("文件名: %s\n", fileInfo.Name())
    fmt.Printf("大小: %d字节\n", fileInfo.Size())
    fmt.Printf("权限: %v\n", fileInfo.Mode())
    fmt.Printf("修改时间: %v\n", fileInfo.ModTime())
    fmt.Printf("是目录: %t\n", fileInfo.IsDir())
}
```

### 删除文件

使用`os.Remove`函数删除文件：

```go
func main() {
    err := os.Remove("toDelete.txt")
    if err != nil {
        fmt.Println("删除文件错误:", err)
        return
    }
    
    fmt.Println("文件删除成功")
}
```

### 重命名或移动文件

使用`os.Rename`函数重命名或移动文件：

```go
func main() {
    // 重命名文件
    err := os.Rename("oldname.txt", "newname.txt")
    if err != nil {
        fmt.Println("重命名文件错误:", err)
        return
    }
    
    fmt.Println("文件重命名成功")
    
    // 移动文件
    err = os.Rename("file.txt", "subfolder/file.txt")
    if err != nil {
        fmt.Println("移动文件错误:", err)
        return
    }
    
    fmt.Println("文件移动成功")
}
```

### 修改文件权限

使用`os.Chmod`函数修改文件权限：

```go
func main() {
    // 修改文件权限
    err := os.Chmod("example.txt", 0644) // rw-r--r--权限
    if err != nil {
        fmt.Println("修改权限错误:", err)
        return
    }
    
    fmt.Println("文件权限修改成功")
}
```

## 读取文件

### 读取整个文件内容

使用`os.ReadFile`函数读取整个文件（Go 1.16+）：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    data, err := os.ReadFile("example.txt")
    if err != nil {
        fmt.Println("读取文件错误:", err)
        return
    }
    
    content := string(data)
    fmt.Println("文件内容:")
    fmt.Println(content)
}
```

在Go 1.16之前，可以使用`ioutil.ReadFile`：

```go
import (
    "fmt"
    "io/ioutil" // Go 1.16+中已弃用，新代码应使用os和io包
)

func main() {
    data, err := ioutil.ReadFile("example.txt")
    if err != nil {
        fmt.Println("读取文件错误:", err)
        return
    }
    
    content := string(data)
    fmt.Println(content)
}
```

### 按块读取文件

使用`Read`方法按块读取文件：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    file, err := os.Open("example.txt")
    if err != nil {
        fmt.Println("打开文件错误:", err)
        return
    }
    defer file.Close()
    
    // 创建缓冲区
    buffer := make([]byte, 1024)
    
    for {
        // 读取块
        bytesRead, err := file.Read(buffer)
        if err != nil {
            if err.Error() == "EOF" {
                break // 已到达文件末尾
            }
            fmt.Println("读取文件错误:", err)
            return
        }
        
        // 处理读取的数据块
        fmt.Printf("读取了 %d 字节:\n", bytesRead)
        fmt.Println(string(buffer[:bytesRead]))
        
        if bytesRead < len(buffer) {
            // 不足一个缓冲区，表示已到达文件末尾
            break
        }
    }
}
```

### 按行读取文件

使用`bufio.Scanner`按行读取文件：

```go
package main

import (
    "bufio"
    "fmt"
    "os"
)

func main() {
    file, err := os.Open("example.txt")
    if err != nil {
        fmt.Println("打开文件错误:", err)
        return
    }
    defer file.Close()
    
    scanner := bufio.NewScanner(file)
    lineCount := 0
    
    // 逐行扫描
    for scanner.Scan() {
        lineCount++
        line := scanner.Text()
        fmt.Printf("第%d行: %s\n", lineCount, line)
    }
    
    // 检查扫描过程中是否有错误
    if err := scanner.Err(); err != nil {
        fmt.Println("扫描错误:", err)
    }
}
```

### 随机访问文件

使用`Seek`方法随机访问文件的不同位置：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    file, err := os.Open("example.txt")
    if err != nil {
        fmt.Println("打开文件错误:", err)
        return
    }
    defer file.Close()
    
    // 获取文件大小
    fileInfo, err := file.Stat()
    if err != nil {
        fmt.Println("获取文件信息错误:", err)
        return
    }
    size := fileInfo.Size()
    
    // 读取文件第10个字节
    pos := int64(10)
    if pos < size {
        _, err = file.Seek(pos, 0) // 0表示从文件开始位置计算偏移量
        if err != nil {
            fmt.Println("设置文件指针位置错误:", err)
            return
        }
        
        buffer := make([]byte, 1)
        _, err = file.Read(buffer)
        if err != nil {
            fmt.Println("读取错误:", err)
            return
        }
        
        fmt.Printf("第%d个字节是: %c\n", pos+1, buffer[0])
    }
    
    // 读取文件最后10个字节
    if size > 10 {
        _, err = file.Seek(-10, 2) // 2表示从文件末尾计算偏移量
        if err != nil {
            fmt.Println("设置文件指针位置错误:", err)
            return
        }
        
        buffer := make([]byte, 10)
        _, err = file.Read(buffer)
        if err != nil {
            fmt.Println("读取错误:", err)
            return
        }
        
        fmt.Printf("最后10个字节: %s\n", string(buffer))
    }
}
```

`Seek`方法的第二个参数指定偏移量的参考位置：
- `0`: 从文件开头计算偏移量(os.SEEK_SET)
- `1`: 从当前位置计算偏移量(os.SEEK_CUR)
- `2`: 从文件末尾计算偏移量(os.SEEK_END)

## 写入文件

### 写入整个文件

使用`os.WriteFile`函数写入整个文件（Go 1.16+）：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    content := []byte("这是要写入文件的内容\n第二行内容\n")
    
    err := os.WriteFile("output.txt", content, 0644)
    if err != nil {
        fmt.Println("写入文件错误:", err)
        return
    }
    
    fmt.Println("文件写入成功")
}
```

在Go 1.16之前，可以使用`ioutil.WriteFile`：

```go
import (
    "fmt"
    "io/ioutil" // Go 1.16+中已弃用
)

func main() {
    content := []byte("这是要写入文件的内容\n")
    
    err := ioutil.WriteFile("output.txt", content, 0644)
    if err != nil {
        fmt.Println("写入文件错误:", err)
        return
    }
    
    fmt.Println("文件写入成功")
}
```

### 按块写入文件

使用`Write`方法按块写入文件：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    file, err := os.Create("output.txt")
    if err != nil {
        fmt.Println("创建文件错误:", err)
        return
    }
    defer file.Close()
    
    // 写入第一块数据
    data1 := []byte("这是第一块数据\n")
    bytesWritten, err := file.Write(data1)
    if err != nil {
        fmt.Println("写入错误:", err)
        return
    }
    fmt.Printf("写入了 %d 字节\n", bytesWritten)
    
    // 写入第二块数据
    data2 := []byte("这是第二块数据\n")
    bytesWritten, err = file.Write(data2)
    if err != nil {
        fmt.Println("写入错误:", err)
        return
    }
    fmt.Printf("写入了 %d 字节\n", bytesWritten)
    
    fmt.Println("文件写入完成")
}
```

### 按字符串写入文件

使用`WriteString`方法写入字符串：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    file, err := os.Create("output.txt")
    if err != nil {
        fmt.Println("创建文件错误:", err)
        return
    }
    defer file.Close()
    
    // 写入字符串
    bytesWritten, err := file.WriteString("这是一个字符串\n")
    if err != nil {
        fmt.Println("写入错误:", err)
        return
    }
    fmt.Printf("写入了 %d 字节\n", bytesWritten)
    
    file.WriteString("这是第二行\n")
    file.WriteString("这是第三行\n")
    
    fmt.Println("文件写入完成")
}
```

### 追加内容到文件

使用适当的打开模式追加内容到文件：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    // 以追加模式打开文件
    file, err := os.OpenFile("output.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
    if err != nil {
        fmt.Println("打开文件错误:", err)
        return
    }
    defer file.Close()
    
    // 追加内容
    content := []byte("\n这是追加的内容\n")
    _, err = file.Write(content)
    if err != nil {
        fmt.Println("追加内容错误:", err)
        return
    }
    
    fmt.Println("内容追加成功")
}
```

### 覆盖文件的特定部分

使用`WriteAt`方法在文件的特定位置写入内容：

```go
package main

import (
    "fmt"
    "os"
)

func main() {
    // 打开文件用于读写
    file, err := os.OpenFile("example.txt", os.O_RDWR, 0644)
    if err != nil {
        fmt.Println("打开文件错误:", err)
        return
    }
    defer file.Close()
    
    // 在文件偏移量为10的位置写入数据
    newData := []byte("替换的文本")
    _, err = file.WriteAt(newData, 10)
    if err != nil {
        fmt.Println("写入错误:", err)
        return
    }
    
    fmt.Println("在指定位置写入成功")
}
``` 