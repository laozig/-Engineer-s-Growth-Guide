# C++ STL 容器 (Containers)

C++ 标准模板库 (STL) 的核心是**容器**（Containers）。容器是用于存储和组织数据的类模板。它们是高度优化的数据结构，为开发者提供了常见数据结构的现成实现。

## 容器的特点

- **类模板**: 容器是类模板，意味着它们可以存储任何数据类型（只要该类型支持必要的操作，如复制或移动）。
- **内存管理**: 容器自动处理内存分配和释放，极大地简化了资源管理，减少了内存泄漏的风险。
- **丰富的接口**: 提供了一套统一、丰富的成员函数来访问和操作元素，如添加、删除、查找、遍历等。
- **与算法分离**: 容器的设计与算法（Algorithms）分离，通过迭代器（Iterators）作为桥梁，使得任何算法都可以应用于任何兼容的容器。

## 容器的分类

STL 容器主要分为三类：序列容器、关联容器和无序关联容器。

---

### 1. 序列容器 (Sequence Containers)

序列容器维护元素的顺序，元素的位置与插入时的位置相关。

#### a. `std::vector`
- **特点**: 动态数组。在内存中连续存储元素，支持快速随机访问。当空间不足时，会自动分配更大的内存块并移动元素。
- **优势**: 随机访问速度最快（O(1)）。
- **劣势**: 在中间插入或删除元素较慢（O(n)），因为需要移动后续元素。
- **常用场景**: 需要频繁随机访问元素，且主要在末尾添加/删除元素的场景。

```cpp
#include <iostream>
#include <vector>

int main() {
    std::vector<int> vec;
    vec.push_back(10); // 末尾添加元素
    vec.push_back(20);
    vec.push_back(30);

    std::cout << "Second element: " << vec[1] << std::endl; // 随机访问

    for (int val : vec) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
    // 输出: 10 20 30 
    return 0;
}
```

#### b. `std::deque` (双端队列)
- **特点**: "double-ended queue"。在内存中分块存储，允许在序列的头部和尾部进行快速的插入和删除操作。
- **优势**: O(1) 复杂度的头/尾插入和删除。仍然支持较快的随机访问。
- **劣势**: 内存非连续，随机访问比 `vector` 稍慢，内存占用也稍高。
- **常用场景**: 需要频繁地在集合的两端进行添加/删除操作。

```cpp
#include <iostream>
#include <deque>

int main() {
    std::deque<int> dq;
    dq.push_back(10);  // 尾部添加
    dq.push_front(5);  // 头部添加
    dq.push_back(20);

    std::cout << "First element: " << dq.front() << std::endl;
    std::cout << "Last element: " << dq.back() << std::endl;

    dq.pop_front(); // 头部删除
    
    for (int val : dq) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
    // 输出: 10 20
    return 0;
}
```

#### c. `std::list` (双向链表)
- **特点**: 由节点组成的双向链表，每个节点存储一个元素和指向前驱/后继节点的指针。
- **优势**: 在任意位置插入或删除元素都非常快（O(1)），只要有指向该位置的迭代器。
- **劣势**: 不支持随机访问（访问第 n 个元素需要遍历，O(n)）。每个元素都有额外的指针开销。
- **常用场景**: 需要在集合中间进行大量插入和删除操作的场景。

```cpp
#include <iostream>
#include <list>

int main() {
    std::list<int> myList;
    myList.push_back(10);
    myList.push_back(30);
    
    auto it = myList.begin();
    it++; // 移动到 30 的位置
    myList.insert(it, 20); // 在 30 前面插入 20

    for (int val : myList) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
    // 输出: 10 20 30
    return 0;
}
```

---

### 2. 关联容器 (Associative Containers)

关联容器根据键（Key）来排序和存储元素，允许快速查找（通常是对数时间复杂度）。

#### a. `std::set`
- **特点**: 存储**唯一**且**有序**的元素集合。内部通常由红黑树实现。
- **优势**: 快速查找、插入、删除（O(log n)）。自动去重和排序。
- **常用场景**: 需要存储不重复的元素，并希望它们始终保持有序。

```cpp
#include <iostream>
#include <set>

int main() {
    std::set<int> mySet;
    mySet.insert(30);
    mySet.insert(10);
    mySet.insert(20);
    mySet.insert(10); // 重复元素，将被忽略

    // 查找元素
    if (mySet.find(20) != mySet.end()) {
        std::cout << "Found 20!" << std::endl;
    }

    // 遍历时自动有序
    for (int val : mySet) {
        std::cout << val << " ";
    }
    std::cout << std::endl;
    // 输出: 10 20 30
    return 0;
}
```

#### b. `std::map`
- **特点**: 存储**键-值对**（Key-Value Pair），其中键是唯一的且有序的。同样基于红黑树。
- **优势**: 通过键进行快速的查找、插入、删除（O(log n)）。
- **常用场景**: 需要建立键到值的映射关系，例如字典、索引等。

```cpp
#include <iostream>
#include <map>
#include <string>

int main() {
    std::map<std::string, int> ageMap;
    ageMap["Alice"] = 30;
    ageMap["Bob"] = 25;
    ageMap.insert(std::make_pair("Charlie", 35));

    std::cout << "Bob's age is: " << ageMap["Bob"] << std::endl;

    // 遍历时按键排序
    for (const auto& pair : ageMap) {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }
    return 0;
}
```

> `std::multiset` 和 `std::multimap` 是 `set` 和 `map` 的变体，它们允许存储重复的键。

---

### 3. 无序关联容器 (Unordered Associative Containers)

自 C++11 起引入，这些容器使用哈希表（Hash Table）实现，提供平均情况下的常数时间复杂度的查找、插入和删除。

#### a. `std::unordered_set`
- **特点**: 存储唯一的元素，但元素是**无序**的。
- **优势**: 平均查找、插入、删除速度极快（O(1)）。
- **劣势**: 最坏情况下性能可能降至O(n)。元素不排序，需要提供哈希函数。
- **常用场景**: 当只需要快速查找、去重，而不需要元素有序时，是 `set` 的高性能替代品。

#### b. `std::unordered_map`
- **特点**: 存储键-值对，键是唯一的，但集合是**无序**的。
- **优势**: 通过键进行平均 O(1) 复杂度的查找、插入、删除。
- **劣势**: 同 `unordered_set`，最坏情况性能可能不佳。
- **常用场景**: 当需要高性能的键值映射（如缓存、哈希索引），且不关心顺序时，是 `map` 的首选。

```cpp
#include <iostream>
#include <unordered_map>
#include <string>

int main() {
    std::unordered_map<std::string, int> cityPopulation;
    cityPopulation["New York"] = 8400000;
    cityPopulation["Tokyo"] = 14000000;
    
    std::cout << "Population of Tokyo: " << cityPopulation["Tokyo"] << std::endl;
    
    // 遍历顺序不确定
    for (const auto& pair : cityPopulation) {
        std::cout << pair.first << ": " << pair.second << std::endl;
    }
    return 0;
}
```

## 如何选择容器？

选择正确的容器对于程序性能至关重要。可以遵循以下思路：

1.  **需要键值映射吗？**
    - 是 -> 使用 `map` 或 `unordered_map`。
    - **需要按键排序吗？**
        - 是 -> `std::map`
        - 否 -> `std::unordered_map` (性能更高)

2.  **只需要存储值吗？**
    - 是 ->
    - **需要排序和去重吗？**
        - 是 -> `std::set`
        - **只需要去重，不需要排序？**
            - 是 -> `std::unordered_set` (性能更高)
    - **都不需要？**
        - 那么使用序列容器。
        - **需要频繁在任意位置插入/删除？** -> `std::list`
        - **需要在头/尾频繁插入/删除？** -> `std::deque`
        - **主要是随机访问和尾部操作？** -> `std::vector` (默认首选)

通常来说，`std::vector` 是最常用的默认序列容器，而 `std::unordered_map` 是最常用的默认关联容器（如果不需要排序）。 