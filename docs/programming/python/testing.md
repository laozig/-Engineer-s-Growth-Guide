# Python 测试之道

在专业的软件开发中，编写测试与编写功能代码同等重要。测试能够确保代码的正确性、防止回归（即修复一个 bug 导致另一个 bug 出现）、促进重构，并作为一种形式的文档。

## 1. 测试金字塔

测试金字塔是一个经典的隐喻，描述了不同类型测试的数量和范围：
-   **单元测试 (Unit Tests)**: 构成金字塔的坚实基础。它们数量最多，用于测试程序中最小的可测试单元（如一个函数或一个类），速度快且独立于外部依赖。
-   **集成测试 (Integration Tests)**: 位于中间层。它们测试多个单元如何协同工作，例如测试你的应用是否能正确地与数据库或外部 API 交互。
-   **端到端测试 (E2E Tests)**: 位于顶层。它们数量最少，模拟真实用户的完整操作流程来测试整个系统，例如通过浏览器自动化测试一个 Web 应用的注册、登录、购物流程。

## 2. 单元测试：`pytest` (现代标准)

虽然 Python 内置了 `unittest` 模块，但社区广泛采用 `pytest` 作为事实上的标准测试框架。

**为什么选择 `pytest`?**
-   **简洁**: 测试用例就是普通的函数，无需继承类。
-   **强大的断言**: 直接使用 Python 的 `assert` 关键字，无需记忆 `assertEqual`, `assertTrue` 等方法。
-   **优雅的 Fixture 模型**: 用于管理测试的依赖、状态和初始化/清理工作。
-   **丰富的插件生态**: 拥有海量的插件，如 `pytest-cov` (测试覆盖率), `pytest-django` 等。

### (1) 编写第一个 `pytest` 测试
假设我们有一个简单的计算函数保存在 `calculations.py`:
```python
# calculations.py
def add(a, b):
    return a + b

def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b
```

测试代码通常放在一个名为 `test_` 开头的文件夹或文件中，例如 `test_calculations.py`:
```python
# test_calculations.py
import pytest
from calculations import add, divide

# 一个简单的测试函数
def test_add():
    assert add(2, 3) == 5
    assert add(-1, 1) == 0

# 测试函数名以 test_ 开头
def test_divide():
    assert divide(10, 2) == 5

# 测试异常情况
def test_divide_by_zero():
    with pytest.raises(ValueError):
        divide(10, 0)
```
在终端中，进入项目目录并运行 `pytest` 命令，它会自动发现并执行所有测试。

### (2) Fixtures: 管理测试依赖
Fixture 是 `pytest` 的核心特性，用于提供测试所需的数据、对象或状态。

```python
# conftest.py 是一个特殊的文件，用于存放全局的 fixture
import pytest

@pytest.fixture
def sample_user_data():
    """一个提供示例用户数据的 fixture。"""
    return {"name": "Alice", "email": "alice@example.com"}

# test_users.py
def test_user_creation(sample_user_data):
    # pytest 会自动将 fixture 的返回值作为参数传入
    assert sample_user_data["name"] == "Alice"
```

### (3) 参数化测试
使用 `@pytest.mark.parametrize` 可以用不同的输入多次运行同一个测试。

```python
# test_calculations.py
@pytest.mark.parametrize("a, b, expected", [
    (2, 3, 5),
    (-1, -1, -2),
    (0, 0, 0)
])
def test_add_parametrized(a, b, expected):
    assert add(a, b) == expected
```

## 3. Mocking：隔离测试单元

在单元测试中，我们希望将被测单元与其依赖（如数据库、API）隔离开。**Mocking** 就是用一个"伪造"的对象来替换真实依赖的过程。Python 的标准库 `unittest.mock` 提供了强大的 Mock 功能，并与 `pytest` 无缝集成。

### `@patch` 装饰器
`@patch` 可以临时替换一个模块中的对象。

假设我们有这样一个函数，它依赖 `requests` 库：
```python
# api_client.py
import requests

def get_user_from_api(user_id: int):
    response = requests.get(f"https://api.example.com/users/{user_id}")
    if response.status_code == 200:
        return response.json()
    return None
```

我们可以像这样测试它，而无需真正地发出网络请求：
```python
# test_api_client.py
from unittest.mock import patch
from api_client import get_user_from_api

@patch('api_client.requests.get') # 指定要 mock 的对象路径
def test_get_user_from_api_success(mock_get):
    # 配置 mock 对象的行为
    mock_response = mock_get.return_value
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": 1, "name": "Test User"}

    # 调用函数
    user = get_user_from_api(1)

    # 断言
    assert user["name"] == "Test User"
    mock_get.assert_called_once_with("https://api.example.com/users/1") # 验证 mock 是否被正确调用
```

## 4. 集成与端到端测试

-   **集成测试**: 你会连接到一个真实的（但通常是测试专用的）数据库或服务。`pytest` 的 fixture 是管理这些资源的绝佳工具。例如，你可以创建一个 fixture 来初始化数据库并在测试结束后清空它。对于 Web 框架，`pytest-flask` 或 FastAPI 的 `TestClient` 可以在不启动真实服务器的情况下测试应用的路由和逻辑。
-   **端到端测试**: 通常使用专门的浏览器自动化框架。
    -   **Playwright**: 一个现代的、功能强大的浏览器自动化库，由微软开发，支持所有现代浏览器。
    -   **Selenium**: 一个历史悠久且非常流行的浏览器自动化框架。

## 5. 测试最佳实践
-   **快 (Fast)**: 测试应该运行得很快，这样你才会经常运行它们。
-   **独立 (Independent)**: 测试之间不应有依赖或顺序关系。
-   **可重复 (Repeatable)**: 无论运行多少次，测试都应该产生相同的结果。
-   **自我验证 (Self-Validating)**: 测试应该有明确的成功或失败的断言。
-   **及时 (Timely)**: 测试应该与功能代码一起编写，或者稍微提前（测试驱动开发, TDD）。 