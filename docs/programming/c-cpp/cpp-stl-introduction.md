# C++: STL 简介

**标准模板库 (Standard Template Library, STL)** 是 C++ 标准库的核心组成部分，也是 C++ 最强大、最受欢迎的特性之一。它是一个基于**泛型编程**思想的、经过高度优化和严格测试的通用数据结构与算法库。

使用 STL 可以极大地提高开发效率和代码质量，让你不必再"重复造轮子"，而是可以专注于解决实际的业务问题。

## STL 的三大核心组件

STL 的设计理念是将**数据**（存储在容器中）与对数据的**操作**（由算法实现）分离开来。而连接这两者的桥梁，就是**迭代器**。

![STL Components](https://i.imgur.com/3wS4y0g.png)

### 1. 容器 (Containers)

容器是用于存储和组织数据的类模板。它们是各种常见数据结构的实现。STL 容器可以分为几类：

- **顺序容器 (Sequence Containers)**: 元素按线性顺序排列。
    - `std::vector`: 动态数组。在末尾添加/删除元素非常快。支持快速随机访问。
    - `std::list`: 双向链表。在任何位置插入/删除元素都很快，但不支持快速随机访问。
    - `std::deque`: 双端队列 (double-ended queue)。类似于 `vector`，但在开头和末尾添加/删除元素都很快。
    - `std::array` (C++11): 固定大小的数组，是对 C 风格数组的封装，更安全。
    - `std::forward_list` (C++11): 单向链表。

- **关联容器 (Associative Containers)**: 元素根据键值自动排序。插入和查找效率很高（通常是对数时间复杂度）。
    - `std::set`: 存储唯一的、已排序的元素。
    - `std::map`: 存储键-值对 (`key-value`)，键是唯一的且已排序。
    - `std::multiset`: 类似于 `set`，但允许存储重复的键。
    - `std::multimap`: 类似于 `map`，但允许存储重复的键。

- **无序关联容器 (Unordered Associative Containers)** (C++11): 基于哈希表实现，元素不排序。插入和查找的平均时间复杂度是常数时间，非常快。
    - `std::unordered_set`
    - `std::unordered_map`
    - `std::unordered_multiset`
    - `std::unordered_multimap`

- **容器适配器 (Container Adaptors)**: 它们不是独立的容器，而是对其他容器（如 `vector`, `deque`）的接口进行封装，以提供特定的行为。
    - `std::stack`: 栈 (后进先出, LIFO)。
    - `std::queue`: 队列 (先进先出, FIFO)。
    - `std::priority_queue`: 优先队列，最大的元素总是在队首。

### 2. 算法 (Algorithms)

算法是独立于任何特定容器的、可重用的函数模板。它们用于处理容器中的元素序列。STL 提供了大量算法，都在 `<algorithm>` 头文件中。

**常见的算法类别:**
- **非修改性算法**: 不会改变容器中的元素。
    - `find`: 查找某个值的元素。
    - `count`: 统计某个值的出现次数。
    - `for_each`: 对序列中的每个元素执行一个操作。
    - `equal`: 比较两个序列是否相等。
- **修改性算法**: 会改变容器中的元素。
    - `sort`: 对序列进行排序。
    - `copy`: 复制一个序列到另一个位置。
    - `remove`: "移除"序列中等于特定值的元素（实际是将其移动到末尾）。
    - `reverse`: 反转序列。
    - `transform`: 对序列中的每个元素应用一个操作，并将结果存到另一个序列。
- **排序和搜索算法**:
    - `sort`, `stable_sort`, `partial_sort`
    - `binary_search`: 在已排序的序列中进行二分查找。
    - `lower_bound`, `upper_bound`

### 3. 迭代器 (Iterators)

迭代器是 STL 的核心和粘合剂。它是一种行为类似于指针的对象，用于**遍历**容器中的元素，并作为**连接容器和算法的桥梁**。

每个容器都提供自己的迭代器类型。算法不直接操作容器，而是通过迭代器来操作一个由开始和结束位置定义的**元素范围 `[begin, end)`**。

**迭代器的主要优点:**
- **统一接口**: 无论底层是数组 (`vector`) 还是链表 (`list`)，算法都可以用同样的方式（通过迭代器）来遍历它们。`sort(my_vector.begin(), my_vector.end())` 和 `sort(my_list.begin(), my_list.end())`（虽然 `list` 有自己的 `sort` 成员函数）在调用形式上是统一的。
- **灵活性**: 算法可以操作容器的任何子序列，例如 `sort(my_vector.begin() + 1, my_vector.begin() + 5)` 只对部分元素排序。

**示例：使用迭代器和算法**
```cpp
#include <iostream>
#include <vector>
#include <algorithm>

int main() {
    // 1. 创建一个容器
    std::vector<int> numbers = {30, 10, 50, 20, 40};

    // 2. 使用迭代器和算法
    // std::vector<int>::iterator 是迭代器类型
    // .begin() 返回指向第一个元素的迭代器
    // .end() 返回指向"末尾之后"位置的迭代器
    std::sort(numbers.begin(), numbers.end());

    // 3. 使用迭代器遍历并打印结果
    std::cout << "Sorted numbers: ";
    for (std::vector<int>::iterator it = numbers.begin(); it != numbers.end(); ++it) {
        std::cout << *it << " "; // 使用 * 解引用迭代器来获取元素值
    }
    std::cout << std::endl;

    // C++11 之后，可以使用更简洁的范围 for 循环
    std::cout << "Sorted numbers (range-based): ";
    for (int num : numbers) {
        std::cout << num << " ";
    }
    std::cout << std::endl;

    return 0;
}
```

---

理解了容器、算法和迭代器这三大组件如何协同工作，你就掌握了使用 STL 的基本思想。接下来，我们将深入探讨一些最常用的 [STL 容器](cpp-stl-containers.md)。 