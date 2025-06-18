# Go语言测试与性能分析

Go语言内置了强大的测试工具链，支持单元测试、基准测试、性能分析等多种功能。通过`go test`命令，开发者可以轻松地编写和执行测试，确保代码质量和性能。

## 1. 测试基础

### 测试文件命名
测试文件必须以`_test.go`结尾，且与被测试的源文件在同一个包（`package`）内。例如，`main.go`的测试文件应为`main_test.go`。

### `go test`命令
`go test`是执行测试的主要命令。它会自动扫描当前目录下所有`_test.go`文件，并执行其中的测试函数。
- `go test`: 运行当前目录下的所有测试。
- `go test -v`: 显示详细的测试过程和结果。
- `go test ./...`: 运行当前目录及其所有子目录下的测试。

## 2. 单元测试 (Unit Testing)

单元测试用于验证代码中最小的可测试单元（通常是函数或方法）是否按预期工作。

### 测试函数格式
- 函数名必须以`Test`开头，例如`TestMyFunction`。
- 参数必须是`*testing.T`类型。
- 测试函数所在的`_test.go`文件需要和被测试代码在同一个包。

**示例:**
假设我们有一个`add.go`文件：
```go
package main

func Add(a, b int) int {
    return a + b
}
```

对应的测试文件`add_test.go`：
```go
package main

import "testing"

func TestAdd(t *testing.T) {
    sum := Add(1, 2)
    if sum != 3 {
        t.Errorf("Add(1, 2) = %d; want 3", sum)
    }
}
```
使用`t.Errorf`、`t.Fatalf`或`t.Logf`等方法来报告测试结果。

## 3. 基准测试 (Benchmark Testing)

基准测试用于衡量特定代码段的性能。

### 基准函数格式
- 函数名必须以`Benchmark`开头，例如`BenchmarkMyFunction`。
- 参数必须是`*testing.B`类型。
- 测试代码需要放在一个`for`循环中，循环次数由`b.N`决定。

**示例:**
```go
package main

import "testing"

func BenchmarkAdd(b *testing.B) {
    for i := 0; i < b.N; i++ {
        Add(1, 2)
    }
}
```

运行基准测试：
```bash
go test -bench=.
```
- `-bench=.`：运行当前目录下的所有基准测试。
- `-benchmem`：显示内存分配信息。

## 4. 示例测试 (Example Tests)

示例测试既是文档也是可运行的测试。它们会出现在Godoc生成的文档中，并且`go test`会验证示例的输出是否正确。

### 示例函数格式
- 函数名以`Example`开头。
- 函数体中包含一段示例代码，并通过注释`// Output:`来指定期望的输出。

**示例:**
```go
package main

import "fmt"

func ExampleAdd() {
    sum := Add(1, 2)
    fmt.Println(sum)
    // Output: 3
}
```

## 5. 子测试 (Subtests)

子测试允许你在一个测试函数内创建一组独立的测试用例，从而更好地组织测试代码。

**示例:**
```go
package main

import "testing"

func TestAddGroup(t *testing.T) {
    testCases := []struct {
        name string
        a, b int
        want int
    }{
        {"positive numbers", 1, 2, 3},
        {"negative numbers", -1, -2, -3},
        {"mixed numbers", 1, -2, -1},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            got := Add(tc.a, tc.b)
            if got != tc.want {
                t.Errorf("Add() = %d; want %d", got, tc.want)
            }
        })
    }
}
```

## 6. 测试覆盖率 (Test Coverage)

测试覆盖率是衡量测试代码覆盖了多少业务代码的指标。

运行并生成覆盖率报告：
```bash
# 生成覆盖率文件
go test -coverprofile=coverage.out

# 在浏览器中查看报告
go tool cover -html=coverage.out
```

## 7. 性能剖析 (Profiling)

Go工具链还支持生成CPU和内存的性能剖析文件。

### CPU剖析
```bash
go test -cpuprofile=cpu.prof -bench=.
go tool pprof cpu.prof
```

### 内存剖析
```bash
go test -memprofile=mem.prof -bench=.
go tool pprof mem.prof
```
`pprof`工具可以用于分析性能瓶颈，支持命令行交互和Web UI (`-http=:8080`)。

## 8. 常用测试框架

虽然Go的原生测试工具很强大，但社区也提供了一些优秀的第三方库来简化测试编写。

- **[Testify](https://github.com/stretchr/testify)**: 一个非常流行的断言和Mocking库。
  - `assert`: 提供丰富的断言函数，如`assert.Equal(t, 10, result)`。
  - `require`: 与`assert`类似，但在失败时会立即停止测试（调用`t.FailNow()`）。
  - `mock`: 提供创建测试桩（Mock）对象的功能。
  - `suite`: 允许将测试组织成结构化的测试套件。

**使用`testify/assert`的示例:**
```go
package main

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestAddWithAssert(t *testing.T) {
    sum := Add(1, 2)
    assert.Equal(t, 3, sum, "they should be equal")
}
```
在项目中引入`testify`：
```bash
go get github.com/stretchr/testify
``` 