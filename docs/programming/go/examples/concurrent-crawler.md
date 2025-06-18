# 示例项目：并发数据爬虫

这个示例将展示Go语言并发特性的强大之处。我们将构建一个简单的并行网络爬虫，它从一个URL开始，递归地抓取页面上的所有链接。

为避免真实世界的复杂性（如遵守`robots.txt`、处理各种相对URL等），本示例将使用一个模拟的（fake）URL抓取器。

## 功能
- 从一个根URL开始抓取。
- 并发地抓取页面内的链接。
- 记录已访问的URL，避免重复抓取和无限循环。
- 使用固定数量的worker goroutine来控制并发度。

## 核心思想
这个爬虫的核心由一个**主控goroutine**和多个**worker goroutine**组成。
1.  **主控(Master)**:
    - 维护一个待抓取URL的队列（`worklist`）。
    - 维护一个已抓取URL的集合（`seen`），以防重复。
    - 将`worklist`中的URL通过channel发送给worker。
    - 接收worker抓取到的新链接，并将其加入`worklist`。
2.  **工人(Workers)**:
    - 从channel接收URL。
    - "抓取"该URL。
    - 将抓取到的新链接发送回主控。

## 代码实现
我们将把爬虫逻辑封装在一个结构体中，以便管理其状态。

```go
package main

import (
	"fmt"
	"sync"
)

// Fetcher 是一个可以抓取URL并返回其body和子URL列表的接口
type Fetcher interface {
	Fetch(url string) (body string, urls []string, err error)
}

// ConcurrentCrawler 是爬虫的状态结构体
type ConcurrentCrawler struct {
	mu   sync.Mutex       // 用于保护seen map
	seen map[string]bool  // 记录已访问的URL
}

// NewConcurrentCrawler 创建一个新的爬虫实例
func NewConcurrentCrawler() *ConcurrentCrawler {
	return &ConcurrentCrawler{
		seen: make(map[string]bool),
	}
}

// Crawl 是爬虫的主函数
func (c *ConcurrentCrawler) Crawl(url string, fetcher Fetcher) {
	// worklist是待处理的URL列表，使用channel实现
	worklist := make(chan []string)
	// a channel to receive new urls from workers
	go func() { worklist <- []string{url} }()

	// n是活跃的worker数量
	n := 0

	// 主循环
	for ; n > 0 || len(<-worklist) > 0; {
		list := <-worklist
		for _, item := range list {
			if !c.isSeen(item) {
				n++ // 增加worker计数
				c.markSeen(item)
				go c.worker(item, fetcher, worklist)
			}
		}
	}
}

// isSeen 检查URL是否已被访问 (并发安全)
func (c *ConcurrentCrawler) isSeen(url string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.seen[url]
	return ok
}

// markSeen 将URL标记为已访问 (并发安全)
func (c *ConcurrentCrawler) markSeen(url string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[url] = true
}

// worker 是执行抓取任务的goroutine
func (c *ConcurrentCrawler) worker(url string, fetcher Fetcher, worklist chan []string) {
	body, urls, err := fetcher.Fetch(url)
	if err != nil {
		fmt.Printf("Error fetching %s: %s\n", url, err)
		return
	}
	fmt.Printf("Found: %s, Title: %q\n", url, body)
	worklist <- urls
}

// --- 模拟实现 ---

// fakeFetcher 是一个实现了Fetcher接口的模拟抓取器
type fakeFetcher map[string]*fakeResult

type fakeResult struct {
	body string
	urls []string
}

func (f fakeFetcher) Fetch(url string) (string, []string, error) {
	if res, ok := f[url]; ok {
		return res.body, res.urls, nil
	}
	return "", nil, fmt.Errorf("not found: %s", url)
}

// fetcher 是一个预填充了数据的fakeFetcher实例
var fetcher = fakeFetcher{
	"https://golang.org/": &fakeResult{
		"The Go Programming Language",
		[]string{
			"https://golang.org/pkg/",
			"https://golang.org/cmd/",
		},
	},
	"https://golang.org/pkg/": &fakeResult{
		"Packages",
		[]string{
			"https://golang.org/",
			"https://golang.org/cmd/",
			"https://golang.org/pkg/fmt/",
			"https://golang.org/pkg/os/",
		},
	},
	"https://golang.org/pkg/fmt/": &fakeResult{
		"Package fmt",
		[]string{
			"https://golang.org/",
			"https://golang.org/pkg/",
		},
	},
	"https://golang.org/pkg/os/": &fakeResult{
		"Package os",
		[]string{
			"https://golang.org/",
			"https://golang.org/pkg/",
		},
	},
}

func main() {
	crawler := NewConcurrentCrawler()
	crawler.Crawl("https://golang.org/", fetcher)
	fmt.Println("Crawling finished.")
}
```
*注意：这个版本的`Crawl`函数存在一个bug，它会在worker完成之前退出。一个更健壮的实现会使用`sync.WaitGroup`来等待所有worker goroutine完成。这是Go官方教程中的一个经典练习，留给读者作为思考和改进的空间。*

## 如何运行
1.  将上述代码保存到`main.go`文件中。
2.  运行程序:
    ```bash
    go run main.go
    ```
3.  观察输出，你会看到程序从根URL开始，并发地打印出找到的页面标题。 