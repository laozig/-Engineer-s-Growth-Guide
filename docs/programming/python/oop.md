# Python 面向对象编程 (OOP)

面向对象编程（Object-Oriented Programming, OOP）是一种强大的编程范式，它将数据和操作数据的函数（方法）捆绑在一起，形成"对象"。本章将介绍 Python 中 OOP 的核心概念和现代实践。

## 1. 类 (Class) 与对象 (Object)

-   **类 (Class)**: 一个创建对象的蓝图或模板。它定义了对象的共同属性和行为。
-   **对象 (Object)**: 类的一个具体实例。每个对象都有自己独立的数据（属性），但共享类中定义的方法。

```python
# 定义一个"汽车"类
class Car:
    # __init__ 是一个特殊的"魔法方法"，称为构造函数
    # 它在创建新对象时被自动调用
    def __init__(self, brand: str, model: str, year: int):
        # 这些是实例属性 (Instance Attributes)
        self.brand = brand
        self.model = model
        self.year = year
        self.is_running = False

    # 这是一个实例方法 (Instance Method)
    def start_engine(self) -> None:
        """启动汽车引擎。"""
        if not self.is_running:
            self.is_running = True
            print(f"{self.year} 年款的 {self.brand} {self.model} 引擎已启动。")
        else:
            print("引擎已经在运行了。")

# 创建两个 Car 类的对象（实例）
my_car = Car("特斯拉", "Model 3", 2022)
friends_car = Car("比亚迪", "汉", 2023)

# 调用对象的方法
my_car.start_engine()
friends_car.start_engine()

# 访问对象的属性
print(f"我的车是 {my_car.brand} 品牌的。")
```

## 2. OOP 的四大支柱

### (1) 封装 (Encapsulation)
封装是将数据（属性）和操作数据的方法捆绑在一起的做法，并限制对内部状态的直接访问。Python 没有真正的私有变量，但使用约定：
-   `_single_underscore`: 提示这是一个内部变量，不应在外部直接修改。
-   `__double_underscore`: 会触发"名称改写 (Name Mangling)"，使其更难从外部访问。

```python
class BankAccount:
    def __init__(self, owner: str, balance: float):
        self.owner = owner
        self._balance = balance # 内部变量

    def deposit(self, amount: float) -> None:
        self._balance += amount

    def get_balance(self) -> float:
        # 提供一个公共方法来访问内部数据
        return self._balance
```

### (2) 继承 (Inheritance)
继承允许我们创建一个新类（子类），它会继承一个现有类（父类）的所有属性和方法。这促进了代码重用。

```python
# ElectricCar 是 Car 的子类
class ElectricCar(Car):
    def __init__(self, brand: str, model: str, year: int, battery_kwh: int):
        # super() 用于调用父类的 __init__ 方法，避免重复代码
        super().__init__(brand, model, year)
        self.battery_kwh = battery_kwh

    def charge(self) -> None:
        """为电动车充电。"""
        print(f"正在为 {self.model} 充电，电池容量: {self.battery_kwh} kWh。")

my_tesla = ElectricCar("特斯拉", "Model Y", 2023, 75)
my_tesla.start_engine() # 继承自父类 Car 的方法
my_tesla.charge() # 子类自己的方法
```

### (3) 多态 (Polymorphism)
多态意味着"多种形态"。它允许我们以统一的方式处理不同类的对象。只要这些对象实现了共同的接口（方法），我们就可以用同样的方式调用它们。

```python
def start_any_car(car: Car) -> None:
    # 这个函数可以接受任何 Car 或其子类的对象
    car.start_engine()

start_any_car(my_car)
start_any_car(my_tesla)
```

### (4) 抽象 (Abstraction)
抽象是隐藏复杂实现细节，只向用户展示必要功能的过程。在 Python 中，这通常通过抽象基类 (Abstract Base Classes, ABC) 实现。

## 3. 魔法方法 (Magic Methods)
魔法方法是以双下划线开头和结尾的特殊方法，它们能让你自定义对象的行为。

-   `__str__(self)`: 当你 `print(obj)` 或 `str(obj)` 时调用，应返回一个对用户友好的字符串。
-   `__repr__(self)`: 当你直接在解释器中输入对象名或 `repr(obj)` 时调用，应返回一个明确的、能让开发者重建该对象的字符串表示。

```python
class Book:
    def __init__(self, title: str, author: str):
        self.title = title
        self.author = author

    def __str__(self) -> str:
        return f"《{self.title}》 by {self.author}"

    def __repr__(self) -> str:
        return f"Book(title='{self.title}', author='{self.author}')"

book = Book("三体", "刘慈欣")
print(book) # 调用 __str__
# 输出: 《三体》 by 刘慈欣

print(repr(book)) # 调用 __repr__
# 输出: Book(title='三体', author='刘慈欣')
```

## 4. 现代 OOP 特性

### (1) `@property` 装饰器
用于创建"只读"属性，将一个方法伪装成一个属性来访问。

```python
class Circle:
    def __init__(self, radius: float):
        self._radius = radius

    @property
    def diameter(self) -> float:
        """直径是半径的两倍。"""
        return self._radius * 2

c = Circle(5)
print(c.diameter) # 像访问属性一样访问，无需括号
# c.diameter = 12 # 会报错，因为我们没有定义 setter
```

### (2) `@staticmethod` 和 `@classmethod`

-   `@staticmethod`: 静态方法。它不接收 `self` 或 `cls` 参数，与类的实例完全独立。它只是一个逻辑上属于这个类的函数。
-   `@classmethod`: 类方法。它接收的第一个参数是类本身（通常命名为 `cls`），而不是实例。常用于创建工厂方法。

```python
class Pizza:
    def __init__(self, ingredients: list[str]):
        self.ingredients = ingredients

    @classmethod
    def margherita(cls):
        """一个创建玛格丽特披萨的工厂方法。"""
        return cls(['番茄', '马苏里拉奶酪'])

    @staticmethod
    def is_vegetarian(ingredients: list[str]) -> bool:
        """检查配料是否为素食。"""
        return '肉' not in ingredients

# 使用类方法创建实例
margherita_pizza = Pizza.margherita()
print(margherita_pizza.ingredients)

# 使用静态方法
print(Pizza.is_vegetarian(['番茄', '蘑菇'])) # True
```

### (3) 数据类 (Dataclasses)
对于主要用于存储数据的类，Python 3.7+ 的 `@dataclass` 装饰器可以自动为你生成 `__init__`, `__repr__`, `__eq__` 等魔法方法，大大减少样板代码。

```python
from dataclasses import dataclass

@dataclass
class Person:
    name: str
    age: int
    city: str = "未知" # 可以有默认值

# 无需编写 __init__，直接创建实例
p1 = Person("张三", 28)
p2 = Person("张三", 28)

print(p1) # 自动生成了友好的 __repr__
print(p1 == p2) # 自动生成了 __eq__，返回 True
```
使用 `@dataclass` 是现代 Python 中创建简单数据容器类的首选方式。 