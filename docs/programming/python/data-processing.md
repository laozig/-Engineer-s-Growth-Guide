# Python 数据处理与分析

Python 在数据科学、机器学习和数据分析领域的统治地位，主要归功于其强大的第三方库生态系统。本章将重点介绍两个最核心的库：NumPy 和 Pandas。

## 1. NumPy：科学计算的基石

NumPy (Numerical Python) 是 Python 科学计算的基础包。它提供了一个核心的数据结构 `ndarray` (N-dimensional array)，以及用于高效操作这些数组的函数。

### (1) `ndarray`：为何不用 Python 列表？
`ndarray` 相比 Python 的原生 `list`，具有以下绝对优势：
-   **性能**: NumPy 数组的操作由预编译的 C 代码执行，速度远超 Python 循环。
-   **内存效率**: 数组在内存中是连续存储的，比离散存储的列表更紧凑。
-   **便利性**: 支持大量的向量化操作和数学函数，代码更简洁。

### (2) 创建 NumPy 数组

```python
import numpy as np

# 从 Python 列表创建
my_list = [1, 2, 3, 4, 5]
arr = np.array(my_list)
print(f"一维数组: {arr}")

# 创建特定形状和值的数组
zeros = np.zeros((2, 3)) # 创建一个 2x3 的全零数组
ones = np.ones(5) # 创建一个长度为 5 的全一数组
num_range = np.arange(0, 10, 2) # 类似 range()，创建等差数组
print(num_range) # 输出: [0 2 4 6 8]
```

### (3) 向量化操作
这是 NumPy 最强大的特性之一。你可以对整个数组执行操作，而无需编写显式的循环。

```python
# 数组与标量的运算
result = arr * 2 + 1
print(f"向量化运算: {result}") # 输出: [ 3  5  7  9 11]

# 数组与数组的运算
arr2 = np.array([10, 20, 30, 40, 50])
sum_arr = arr + arr2
print(f"数组相加: {sum_arr}") # 输出: [11 22 33 44 55]

# 通用函数 (ufunc)
print(np.sqrt(arr)) # 计算数组中每个元素的平方根
```

### (4) 索引、切片与聚合

NumPy 的索引和切片与列表类似，但扩展到了多维。

```python
# 创建一个二维数组
matrix = np.array([[1, 2, 3], [4, 5, 6], [7, 8, 9]])

# 索引: 获取第 2 行，第 1 列的元素 (从0开始)
print(matrix[1, 0]) # 输出: 4

# 切片: 获取前两行
print(matrix[:2, :])

# 聚合操作
print(f"所有元素的和: {matrix.sum()}")
print(f"每列的平均值: {matrix.mean(axis=0)}") # axis=0 表示沿列操作
print(f"每行的最大值: {matrix.max(axis=1)}") # axis=1 表示沿行操作
```

## 2. Pandas：强大的数据分析工具

如果说 NumPy 是基石，那么 Pandas 就是建立在这块基石上的数据分析大厦。Pandas 提供了 `Series` 和 `DataFrame` 两种核心数据结构，让处理表格化数据变得异常轻松。

### (1) `Series` 和 `DataFrame`
-   **`Series`**: 一个带索引的一维数组，可以看作是字典的增强版或带标签的一列数据。
-   **`DataFrame`**: 一个二维的、带行列索引的表格型数据结构，是 Pandas 的核心。你可以把它想象成一个电子表格或 SQL 表。

### (2) 数据读写
Pandas 支持从多种格式的文件中读取数据，最常用的是 CSV。

```python
import pandas as pd

# 创建一个 DataFrame
data = {
    'Name': ['Alice', 'Bob', 'Charlie', 'David'],
    'Age': [25, 30, 35, 40],
    'City': ['New York', 'Los Angeles', 'Chicago', 'Houston']
}
df = pd.DataFrame(data)

# 将 DataFrame 写入 CSV 文件
df.to_csv('users.csv', index=False) # index=False 表示不将 DataFrame 的索引写入文件

# 从 CSV 文件读取数据
df_from_csv = pd.read_csv('users.csv')
print(df_from_csv)
```

### (3) 数据查看与选择

```python
# 查看前几行
print(df.head())

# 查看基本信息 (数据类型、非空值数量)
df.info()

# 查看描述性统计
print(df.describe())

# 选择一列 (返回一个 Series)
ages = df['Age']
print(ages)

# 选择多列
subset = df[['Name', 'City']]
print(subset)

# 使用 .loc 按标签选择 (行, 列)
print(df.loc[0]) # 选择第一行
print(df.loc[0, 'Name']) # 选择第一行的 'Name' 列

# 使用 .iloc 按整数位置选择
print(df.iloc[1:3, :]) # 选择第 2 到 3 行的所有列

# 布尔索引：最强大的筛选方式
young_users = df[df['Age'] < 35]
print(young_users)
```

### (4) 数据清洗与处理
```python
# 假设我们有一些缺失数据
df.loc[3, 'City'] = np.nan

# 检查缺失值
print(df.isnull().sum())

# 删除包含缺失值的行
df_cleaned = df.dropna()

# 填充缺失值
df_filled = df.fillna({'City': 'Unknown'})

# 应用函数
df['Age_in_5_years'] = df['Age'].apply(lambda x: x + 5)
print(df)
```

### (5) 分组与聚合 (`groupby`)
`groupby` 操作是数据分析的核心，它遵循"分割-应用-合并"(Split-Apply-Combine) 的模式。

```python
# 添加一列用于分组
df['Category'] = ['A', 'B', 'A', 'B']

# 按 'Category' 分组，并计算每个组的平均年龄
avg_age_by_category = df.groupby('Category')['Age'].mean()
print(avg_age_by_category)
# Category
# A    30.0
# B    35.0
# Name: Age, dtype: float64
```

Pandas 的功能远不止于此，它还包括时间序列分析、数据合并、透视表等高级功能，是任何想用 Python 做数据工作的人都必须掌握的工具。 