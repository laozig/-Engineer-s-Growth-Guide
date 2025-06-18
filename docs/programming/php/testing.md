# PHP 测试 (PHPUnit)

自动化测试是专业软件开发的基石。它能确保你的代码按预期工作，防止在修改或添加新功能时引入新的错误（即"回归"），并让你能自信地进行代码重构。

在PHP生态系统中，**PHPUnit** 是事实上的标准测试框架。本指南将介绍PHPUnit的基础知识。

## 为什么需要测试？

-   **提高代码质量**: 编写测试会迫使你思考代码的各种边界情况。
-   **防止回归**: 每当你修改代码后，运行测试套件可以立即发现是否破坏了现有功能。
-   **充当文档**: 写得好的测试可以作为代码使用方式的示例。
-   **促进良好设计**: 可测试的代码通常是松耦合、模块化的代码。
-   **放心重构**: 有了测试的保护，你可以大胆地改进和重构代码，而不用担心会破坏某些东西。

## 安装 PHPUnit

将PHPUnit作为项目的**开发依赖**添加到`composer.json`中是最推荐的方式。
```bash
composer require --dev phpunit/phpunit
```
安装后，你可以通过`vendor/bin/phpunit`来运行它。

## 编写第一个测试

假设我们有一个简单的计算器类需要测试。

**`src/Calculator.php`:**
```php
<?php
namespace App;

class Calculator {
    public function add(float $a, float $b): float {
        return $a + $b;
    }
}
?>
```

现在，我们为这个类创建一个测试用例。
-   测试文件通常放在一个独立的`tests`目录中。
-   测试文件名应对应被测试的类，并以`Test.php`结尾。
-   测试类应继承自 `PHPUnit\Framework\TestCase`。
-   测试方法必须是`public`的，并且通常以`test`开头。

**`tests/CalculatorTest.php`:**
```php
<?php
// tests/CalculatorTest.php

use PHPUnit\Framework\TestCase;
use App\Calculator; // 引入要测试的类

class CalculatorTest extends TestCase {
    
    // 测试 add 方法
    public function testAdd() {
        // 1. 准备 (Arrange)
        $calculator = new Calculator();
        $a = 5;
        $b = 3;
        $expectedResult = 8;

        // 2. 执行 (Act)
        $actualResult = $calculator->add($a, $b);

        // 3. 断言 (Assert)
        $this->assertEquals($expectedResult, $actualResult, "5 + 3 应该等于 8");
    }
}
?>
```
这个测试遵循了经典的"Arrange-Act-Assert"（准备-执行-断言）模式。

## 断言 (Assertions)

断言是测试的核心。它用于验证一个条件是否为真。如果断言失败，PHPUnit会标记这个测试为失败。PHPUnit提供了大量的断言方法。

### 常用断言方法

-   **`assertEquals($expected, $actual)`**: 断言两个变量的值相等（使用`==`比较）。
-   **`assertSame($expected, $actual)`**: 断言两个变量的类型和值都相等（使用`===`比较）。
-   **`assertTrue($condition)`**: 断言一个条件为真。
-   **`assertFalse($condition)`**: 断言一个条件为假。
-   **`assertCount(int $expectedCount, $haystack)`**: 断言一个数组或可数对象的元素数量。
-   **`assertInstanceOf(string $expected, $actual)`**: 断言一个对象是某个类的实例。
-   **`assertNull($variable)`**: 断言一个变量是`null`。
-   **`assertStringContainsString(string $needle, string $haystack)`**: 断言一个字符串包含另一个字符串。
-   **`assertEmpty($variable)`**: 断言一个变量是空的。

**更多示例:**
```php
<?php
use PHPUnit\Framework\TestCase;

class MoreAssertionsTest extends TestCase
{
    public function testArrayCount() {
        $myArray = [1, 2, 3];
        $this->assertCount(3, $myArray);
    }

    public function testInstanceOf() {
        $exception = new \InvalidArgumentException();
        $this->assertInstanceOf(\Exception::class, $exception);
    }
}
?>
```

## 运行测试

在项目的根目录下，从命令行运行PHPUnit。
```bash
# 运行所有在 phpunit.xml (配置文件) 中定义的测试
./vendor/bin/phpunit

# 运行指定目录下的所有测试
./vendor/bin/phpunit tests

# 运行指定的测试文件
./vendor/bin/phpunit tests/CalculatorTest.php
```
如果所有测试都通过，你会看到一个绿色的成功提示。如果任何测试失败，PHPUnit会详细报告哪个测试的哪个断言失败了。

## 配置文件 (`phpunit.xml`)

你可以在项目根目录创建一个`phpunit.xml`文件来配置PHPUnit的行为，例如指定测试目录、设置颜色、引导文件等。

一个基本的`phpunit.xml`文件：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="https://schema.phpunit.de/9.5/phpunit.xsd"
         bootstrap="vendor/autoload.php"
         colors="true">
    <testsuites>
        <testsuite name="Project Test Suite">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
</phpunit>
```
-   **`bootstrap`**: 指定在运行测试前需要包含的文件，通常是Composer的自动加载文件。
-   **`colors`**: 在终端输出中启用颜色。
-   **`<directory>`**: 定义了测试文件所在的目录。

## 测试替身 (Test Doubles): Stubs & Mocks

当被测试的代码依赖于其他复杂的组件（如数据库连接、API客户端）时，直接在测试中使用这些真实组件会使测试变得缓慢、不稳定且难以设置。

**测试替身**是一种用一个可控的替代品来替换真实依赖的技术。
-   **桩 (Stub)**: 一个返回预设好的数据的测试替身。你可以用它来模拟数据库查询结果或API响应，而无需真正地连接数据库或发送HTTP请求。
-   **模拟对象 (Mock)**: 一个更复杂的测试替身，你可以对它的行为进行预期。例如，你可以断言"这个对象的某个方法必须被调用恰好一次，并且带有指定的参数"。

创建Stubs和Mocks是PHPUnit的一个高级功能，但对于测试复杂的应用至关重要。

```php
<?php
use PHPUnit\Framework\TestCase;

class StubTest extends TestCase
{
    public function testStub()
    {
        // 为 SomeClass 类创建一个桩件
        $stub = $this->createStub(SomeClass::class);

        // 配置桩件
        $stub->method('doSomething')
             ->willReturn('foo');

        // 调用桩件的方法会返回 'foo'
        $this->assertEquals('foo', $stub->doSomething());
    }
}
```

学习编写自动化测试是提升PHP开发技能的重要一步，它能帮助你构建更可靠、更易于维护的应用程序。 