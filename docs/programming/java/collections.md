# Java 集合框架 (Collections Framework)

Java 集合框架提供了一套性能优良、使用方便的接口和类，用于存储和操作数据集合。它是 Java 开发中不可或缺的一部分。

## 核心接口

集合框架主要由以下几个核心接口构成：

-   `Collection`: 集合层次结构的根接口，代表一组对象，即元素（elements）。
    -   `List`: 有序集合，允许重复元素。可以通过索引访问。
    -   `Set`: 不允许重复元素的集合。
    -   `Queue`: 通常用于持有待处理元素的集合，一般以 FIFO（先进先出）方式排序。
-   `Map`: 存储键值对（key-value pairs）的对象。键不能重复。

---

### 1. `List` 接口

`List` 是一个有序的集合，也称为序列。它允许存储重复的元素，并能通过整数索引（位置）来精确控制每个元素的插入和访问。

#### 主要实现类

-   **`ArrayList`**:
    -   基于动态数组实现。
    -   **优点**: 随机访问速度快（通过索引 get 和 set）。
    -   **缺点**: 在中间位置插入和删除元素较慢，因为需要移动后续元素。
    -   **线程不安全**。

-   **`LinkedList`**:
    -   基于双向链表实现。
    -   **优点**: 在任意位置插入和删除元素速度快。
    -   **缺点**: 随机访问速度慢，需要从头或尾遍历到指定位置。
    -   **线程不安全**。

-   **`Vector`**:
    -   与 `ArrayList` 类似，但它是**线程安全**的。
    -   由于同步开销，性能通常低于 `ArrayList`，已不推荐使用。

**代码示例 (`ArrayList`)**

```java
import java.util.ArrayList;
import java.util.List;

public class ListExample {
    public static void main(String[] args) {
        List<String> fruits = new ArrayList<>();

        // 添加元素
        fruits.add("Apple");
        fruits.add("Banana");
        fruits.add("Cherry");

        // 访问元素
        System.out.println("Element at index 1: " + fruits.get(1)); // Banana

        // 遍历列表
        for (String fruit : fruits) {
            System.out.println(fruit);
        }

        // 删除元素
        fruits.remove("Banana");
        System.out.println("List after removing Banana: " + fruits);
    }
}
```

---

### 2. `Set` 接口

`Set` 是一个不包含重复元素的集合。它主要用于存储唯一的元素。

#### 主要实现类

-   **`HashSet`**:
    -   基于哈希表（`HashMap` 的实例）实现。
    -   **不保证**元素的顺序。
    -   允许 `null` 值。
    -   **线程不安全**。

-   **`LinkedHashSet`**:
    -   `HashSet` 的子类，使用链表维护了元素的插入顺序。
    -   **优点**: 迭代访问时，元素按插入顺序排序。
    -   **线程不安全**。

-   **`TreeSet`**:
    -   基于红黑树（一种自平衡二叉查找树）实现。
    -   元素按其**自然顺序**进行排序，或者根据创建 `Set` 时提供的 `Comparator` 进行排序。
    -   **不允许** `null` 值（除非自定义比较器）。
    -   **线程不安全**。

**代码示例 (`HashSet`)**

```java
import java.util.HashSet;
import java.util.Set;

public class SetExample {
    public static void main(String[] args) {
        Set<String> uniqueNames = new HashSet<>();

        uniqueNames.add("Alice");
        uniqueNames.add("Bob");
        uniqueNames.add("Charlie");
        uniqueNames.add("Alice"); // 尝试添加重复元素，将被忽略

        System.out.println("Set contains: " + uniqueNames);
        System.out.println("Does set contain Bob? " + uniqueNames.contains("Bob")); // true
    }
}
```

---

### 3. `Map` 接口

`Map` 用于存储键值对。每个键最多只能映射到一个值。

#### 主要实现类

-   **`HashMap`**:
    -   基于哈希表实现。
    -   **不保证**映射的顺序。
    -   允许 `null` 键和 `null` 值。
    -   **线程不安全**。

-   **`LinkedHashMap`**:
    -   `HashMap` 的子类，使用链表维护了键值对的插入顺序。
    -   **优点**: 迭代访问时，键值对按插入顺序排序。
    -   **线程不安全**。

-   **`TreeMap`**:
    -   基于红黑树实现。
    -   键按其**自然顺序**进行排序，或者根据创建 `Map` 时提供的 `Comparator` 进行排序。
    -   **不允许** `null` 键。
    -   **线程不安全**。

-   **`Hashtable`**:
    -   与 `HashMap` 类似，但它是**线程安全**的。
    -   **不允许** `null` 键或 `null` 值。
    -   由于同步开销，性能通常低于 `HashMap`，已不推荐使用。

**代码示例 (`HashMap`)**

```java
import java.util.HashMap;
import java.util.Map;

public class MapExample {
    public static void main(String[] args) {
        Map<String, Integer> studentScores = new HashMap<>();

        // 添加键值对
        studentScores.put("Alice", 95);
        studentScores.put("Bob", 88);
        studentScores.put("Charlie", 92);

        // 获取值
        System.out.println("Bob's score: " + studentScores.get("Bob")); // 88

        // 遍历 Map
        for (Map.Entry<String, Integer> entry : studentScores.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }

        // 检查键是否存在
        System.out.println("Is there a score for David? " + studentScores.containsKey("David")); // false
    }
}
```

## `Collections` 工具类

Java 提供了一个名为 `Collections` 的工具类（注意末尾的 `s`），它包含各种静态方法，可用于操作或返回集合。

-   **排序**: `Collections.sort(list)`
-   **查找**: `Collections.binarySearch(list, key)`
-   **反转**: `Collections.reverse(list)`
-   **打乱**: `Collections.shuffle(list)`
-   **同步包装**: `Collections.synchronizedList(list)` 将 `ArrayList` 包装成线程安全的 `List`。
