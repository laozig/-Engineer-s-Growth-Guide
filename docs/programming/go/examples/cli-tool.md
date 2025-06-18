# 示例项目：命令行工具 (CLI)

这个示例将演示如何使用[Cobra库](https://github.com/spf13/cobra)来构建一个命令行工具，该工具可以与我们之前创建的[RESTful API服务](./rest-api.md)进行交互。

## 功能
我们将创建一个名为`task-cli`的工具，它有三个子命令：

- `task-cli list`: 从API获取并显示所有任务。
- `task-cli add <title>`: 向API添加一个新任务。
- `task-cli complete <id>`: 将指定ID的任务标记为已完成。

## 项目结构
一个典型的Cobra项目结构如下：
```
task-cli/
├── go.mod
├── main.go
└── cmd/
    ├── root.go
    ├── list.go
    ├── add.go
    └── complete.go
```

## 代码实现

### `main.go`
这是程序的入口，它只调用`cmd`包的`Execute`函数。
```go
package main

import "task-cli/cmd"

func main() {
	cmd.Execute()
}
```

### `cmd/root.go`
`root.go`定义了根命令，并作为所有其他子命令的父级。
```go
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// apiURL是API服务器的地址，可以通过标志来设置
var apiURL string

var rootCmd = &cobra.Command{
	Use:   "task-cli",
	Short: "A simple CLI to interact with the Task API",
	Long:  `task-cli is a command-line interface for a simple task management service.`,
}

func init() {
	// 添加一个持久标志，使其对所有子命令都可用
	rootCmd.PersistentFlags().StringVarP(&apiURL, "api-url", "a", "http://localhost:8080", "URL of the Task API server")
}

// Execute 执行根命令
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
```

### `cmd/list.go`
```go
package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/spf13/cobra"
)

type Task struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Completed bool   `json:"completed"`
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tasks",
	Run: func(cmd *cobra.Command, args []string) {
		resp, err := http.Get(apiURL + "/tasks")
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer resp.Body.Close()

		body, _ := ioutil.ReadAll(resp.Body)
		var tasks []Task
		json.Unmarshal(body, &tasks)

		fmt.Println("Tasks:")
		for _, task := range tasks {
			status := " "
			if task.Completed {
				status = "✔"
			}
			fmt.Printf("[%s] %d: %s\n", status, task.ID, task.Title)
		}
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}
```

### `cmd/add.go`
```go
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add [title]",
	Short: "Add a new task",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		title := strings.Join(args, " ")
		taskData, _ := json.Marshal(map[string]string{"title": title})

		resp, err := http.Post(apiURL+"/tasks", "application/json", bytes.NewBuffer(taskData))
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer resp.Body.Close()

		fmt.Println("New task added successfully.")
	},
}

func init() {
	rootCmd.AddCommand(addCmd)
}
```

### `cmd/complete.go`
```go
package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
)

var completeCmd = &cobra.Command{
	Use:   "complete [id]",
	Short: "Mark a task as completed",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		taskID := args[0]
		taskData, _ := json.Marshal(map[string]bool{"completed": true})

		req, _ := http.NewRequest(http.MethodPut, apiURL+"/tasks/"+taskID, bytes.NewBuffer(taskData))
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			fmt.Printf("Task %s marked as completed.\n", taskID)
		} else {
			fmt.Printf("Failed to complete task %s. Status: %s\n", taskID, resp.Status)
		}
	},
}

func init() {
	rootCmd.AddCommand(completeCmd)
}
```

## 如何运行
1.  确保之前的[RESTful API服务](./rest-api.md)正在运行。
2.  创建上述的项目结构和文件。
3.  初始化Go模块并获取`Cobra`依赖:
    ```bash
    go mod init task-cli
    go get github.com/spf13/cobra
    ```
4.  构建并运行CLI:
    - `go run main.go list`
    - `go run main.go add "My new CLI task"`
    - `go run main.go complete 3`
    
    或者安装到`$GOPATH/bin`:
    ```bash
    go install
    task-cli list
    ```
