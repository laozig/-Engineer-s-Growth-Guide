# 示例项目：RESTful API服务

这个示例将演示如何使用[Gin框架](https://github.com/gin-gonic/gin)构建一个功能完备的RESTful API服务。我们将创建一个简单的待办事项（Task）管理API，所有数据将存储在内存中。

## 功能
API将提供对`Task`资源的CRUD（创建、读取、更新、删除）操作：

- `GET /tasks`: 获取所有任务列表。
- `POST /tasks`: 创建一个新任务。
- `GET /tasks/:id`: 根据ID获取单个任务。
- `PUT /tasks/:id`: 根据ID更新一个任务。
- `DELETE /tasks/:id`: 根据ID删除一个任务。

## 项目结构
```
go-rest-api/
└── main.go
```

## 代码实现 (`main.go`)
我们将使用`Gin`来处理路由和JSON绑定，使用`sync.RWMutex`来保证对内存中任务列表的并发访问安全。

```go
package main

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
)

// Task 定义了待办事项的数据结构
type Task struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	Completed bool   `json:"completed"`
}

// 使用内存存储，并用读写锁保证并发安全
var (
	tasks      = make(map[int]Task)
	nextTaskID = 1
	mu         sync.RWMutex
)

// listTasksHandler 获取所有任务
func listTasksHandler(c *gin.Context) {
	mu.RLock() // 使用读锁，允许多个goroutine同时读取
	defer mu.RUnlock()

	// 将map转换为slice以便返回
	var taskList []Task
	for _, task := range tasks {
		taskList = append(taskList, task)
	}
	c.JSON(http.StatusOK, taskList)
}

// createTaskHandler 创建一个新任务
func createTaskHandler(c *gin.Context) {
	var newTask struct {
		Title string `json:"title" binding:"required"`
	}

	if err := c.ShouldBindJSON(&newTask); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title is required"})
		return
	}

	mu.Lock() // 使用写锁，独占访问
	defer mu.Unlock()

	task := Task{
		ID:        nextTaskID,
		Title:     newTask.Title,
		Completed: false,
	}
	tasks[task.ID] = task
	nextTaskID++

	c.JSON(http.StatusCreated, task)
}

// getTaskHandler 根据ID获取单个任务
func getTaskHandler(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	task, exists := tasks[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	c.JSON(http.StatusOK, task)
}

// updateTaskHandler 更新一个任务
func updateTaskHandler(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var updatedTaskBody struct {
		Title     string `json:"title"`
		Completed *bool  `json:"completed"` // 使用指针来区分"未提供"和"false"
	}

	if err := c.ShouldBindJSON(&updatedTaskBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	task, exists := tasks[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}

	if updatedTaskBody.Title != "" {
		task.Title = updatedTaskBody.Title
	}
	if updatedTaskBody.Completed != nil {
		task.Completed = *updatedTaskBody.Completed
	}
	tasks[id] = task

	c.JSON(http.StatusOK, task)
}

// deleteTaskHandler 删除一个任务
func deleteTaskHandler(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := tasks[id]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Task not found"})
		return
	}
	delete(tasks, id)

	c.JSON(http.StatusNoContent, nil)
}

func main() {
	// 初始化一些数据
	tasks[nextTaskID] = Task{ID: nextTaskID, Title: "Learn Go", Completed: false}
	nextTaskID++
	tasks[nextTaskID] = Task{ID: nextTaskID, Title: "Build a REST API", Completed: false}
	nextTaskID++

	r := gin.Default()

	// 定义API路由
	r.GET("/tasks", listTasksHandler)
	r.POST("/tasks", createTaskHandler)
	r.GET("/tasks/:id", getTaskHandler)
	r.PUT("/tasks/:id", updateTaskHandler)
	r.DELETE("/tasks/:id", deleteTaskHandler)

	// 启动服务器
	r.Run(":8080")
}
```

## 如何运行
1.  在一个新目录中创建`main.go`文件并拷贝上面的代码。
2.  初始化Go模块并获取`Gin`依赖:
    ```bash
    go mod init go-rest-api
    go get github.com/gin-gonic/gin
    ```
3.  运行服务器:
    ```bash
    go run main.go
    ```

## 使用`curl`与API交互
- **获取所有任务**:
  ```bash
  curl http://localhost:8080/tasks
  ```
- **创建新任务**:
  ```bash
  curl -X POST http://localhost:8080/tasks -H "Content-Type: application/json" -d '{"title": "Write documentation"}'
  ```
- **获取ID为1的任务**:
  ```bash
  curl http://localhost:8080/tasks/1
  ```
- **更新ID为1的任务 (标记为完成)**:
  ```bash
  curl -X PUT http://localhost:8080/tasks/1 -H "Content-Type: application/json" -d '{"completed": true}'
  ```
- **删除ID为2的任务**:
  ```bash
  curl -X DELETE http://localhost:8080/tasks/2
  ``` 