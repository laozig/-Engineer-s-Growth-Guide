# C++ STL 迭代器与算法

如果说容器（Containers）是 STL 的骨架，那么**迭代器**（Iterators）和**算法**（Algorithms）就是其血肉和灵魂。它们共同构成了一套强大且解耦的工具集，让 C++ 开发者能够编写出高效、泛型且可读性强的代码。

## 1. 迭代器 (Iterators)

迭代器是一种行为类似指针的对象，它是容器与算法之间的桥梁。它指向容器中的某个元素，并提供了一套统一的接口来遍历容器中的元素，而无需暴露容器的内部实现细节。

### 迭代器的核心思想

- **抽象访问**: 无论底层是 `vector`（连续内存）、`list`（链表）还是 `map`（树状结构），迭代器都提供了相似的访问方式（如 `*it` 解引用、`++it` 移动到下一个）。
- **统一接口**: 算法不需要为每种容器都写一个特定版本，它们只需要操作迭代器即可。只要容器提供了符合规范的迭代器，算法就能在其上工作。

### 迭代器的分类

根据提供的能力，迭代器被分为五个类别：

1.  **输入迭代器 (Input Iterator)**: 最基本的迭代器，只能向前单步移动，只能读元素，且只能遍历一遍。
2.  **输出迭代器 (Output Iterator)**: 只能向前单步移动，只能写元素，且只能遍历一遍。
3.  **前向迭代器 (Forward Iterator)**: 结合了输入和输出迭代器的能力，可以多次读写同一个元素，并且可以保存副本。
4.  **双向迭代器 (Bidirectional Iterator)**: 在前向迭代器的基础上，增加了向后移动的能力（`--it`）。`std::list`, `std::set`, `std::map` 提供此类迭代器。
5.  **随机访问迭代器 (Random-Access Iterator)**: 最强大的迭代器，在双向迭代器的基础上，增加了算术运算能力（如 `it + n`, `it - n`, `it[n]`, `it1 - it2`）。`std::vector`, `std::deque` 提供此类迭代器。

```cpp
#include <iostream>
#include <vector>
#include <list>

int main() {
    std::vector<int> vec = {1, 2, 3, 4, 5};

    // 使用随机访问迭代器
    std::vector<int>::iterator vec_it = vec.begin(); // 指向第一个元素
    vec_it += 2; // 移动到第三个元素
    std::cout << "Vector's 3rd element: " << *vec_it << std::endl; // 输出 3

    std::list<int> myList = {10, 20, 30};
    
    // 使用双向迭代器
    std::list<int>::iterator list_it = myList.begin();
    ++list_it; // 移动到第二个元素 (20)
    --list_it; // 移回第一个元素 (10)
    std::cout << "List's current element: " << *list_it << std::endl; // 输出 10
    
    return 0;
}
```

---

## 2. 算法 (Algorithms)

STL 在 `<algorithm>` 头文件中提供了大量基于迭代器的、功能强大的函数模板。这些算法本身不操作容器，而是操作由迭代器指定的元素范围，通常是 `[first, last)`，这是一个左闭右开的区间。

### 算法的特点

- **泛型**: 它们是函数模板，可以用于任何支持所需迭代器类型的容器。
- **高效**: 算法都经过了高度优化，并针对不同类型的迭代器提供了最高效的实现版本。
- **解耦**: 算法与数据结构（容器）分离，提高了代码的复用性和灵活性。

### 常用算法示例

#### a. 非修改性算法 (Non-modifying algorithms)

这类算法只读取容器中的元素，不进行修改。

- **`for_each`**: 对范围内的每个元素执行一个函数。
- **`find`**: 在范围内查找一个值，返回指向第一个匹配元素的迭代器。
- **`count`**: 统计范围内某个值出现的次数。
- **`equal`**: 比较两个范围是否相等。

```cpp
#include <iostream>
#include <vector>
#include <algorithm>

void print_val(int val) {
    std::cout << val << " ";
}

int main() {
    std::vector<int> vec = {10, 20, 30, 40, 20};

    // 使用 for_each 打印元素
    std::for_each(vec.begin(), vec.end(), print_val); // 输出: 10 20 30 40 20
    std::cout << std::endl;

    // 使用 find 查找元素
    auto it = std::find(vec.begin(), vec.end(), 30);
    if (it != vec.end()) {
        std::cout << "Found 30 at index: " << std::distance(vec.begin(), it) << std::endl;
    }

    // 使用 count 统计元素
    int num_20s = std::count(vec.begin(), vec.end(), 20);
    std::cout << "The number 20 appears " << num_20s << " times." << std::endl;

    return 0;
}
```

#### b. 修改性算法 (Modifying algorithms)

这类算法会修改范围内的元素。

- **`sort`**: 对范围内的元素进行排序（要求随机访问迭代器）。
- **`reverse`**: 翻转范围内的元素顺序。
- **`copy`**: 将一个范围的元素复制到另一个位置。
- **`remove`**: "移除"范围内的特定值。注意它只将被移除元素之后的内容前移覆盖，并返回一个新的逻辑终点，并不实际缩减容器大小。
- **`unique`**: "移除"连续的重复元素，返回逻辑终点。

```cpp
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric> // For std::iota

int main() {
    std::vector<int> vec = {5, 2, 8, 1, 9, 9, 3};

    // 排序
    std::sort(vec.begin(), vec.end());
    std::cout << "Sorted: ";
    for(int v : vec) std::cout << v << " "; // 1 2 3 5 8 9 9
    std::cout << std::endl;

    // 翻转
    std::reverse(vec.begin(), vec.end());
    std::cout << "Reversed: ";
    for(int v : vec) std::cout << v << " "; // 9 9 8 5 3 2 1
    std::cout << std::endl;

    // 使用 remove-erase idiom 删除所有 9
    // std::remove 将所有不等于 9 的元素移动到容器前端，并返回新的逻辑末尾
    auto new_end = std::remove(vec.begin(), vec.end(), 9);
    // vec.erase 删除从 new_end 到物理末尾的所有元素
    vec.erase(new_end, vec.end());
    std::cout << "After removing 9s: ";
    for(int v : vec) std::cout << v << " "; // 8 5 3 2 1
    std::cout << std::endl;

    return 0;
}
```
**`remove-erase` Idiom**: 这是 C++ 中一个非常重要的模式。由于算法不能修改容器的大小，`std::remove` 只是移动元素。我们必须配合容器自身的 `erase` 成员函数来真正地从物理上删除这些元素。

## 总结

迭代器和算法的组合是 STL 设计哲学的精髓。通过理解和善用它们，你可以：

- 编写出不依赖于特定数据结构的通用代码。
- 利用标准库提供的高效、可靠的实现，避免重复造轮子。
- 以一种声明式的方式来表达你的意图（例如，调用 `std::sort` 而不是自己实现排序循环），使代码更清晰、更易于维护。 