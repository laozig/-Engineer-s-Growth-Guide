# PHP 面向对象编程 (OOP)

面向对象编程 (Object-Oriented Programming, OOP) 是一种编程范式，它使用"对象"来设计软件。对象可以包含数据（属性）和代码（方法）。PHP 5 引入了完整的对象模型，使其成为一门强大的面向对象语言。

## 类和对象 (Classes and Objects)

-   **类 (Class)**: 是创建对象的模板或蓝图。它定义了对象的属性和方法。
-   **对象 (Object)**: 是类的实例。

```php
<?php
// 定义一个类
class Car {
    // 属性 (Properties)
    public $color = 'red';
    public $brand = 'Volvo';

    // 方法 (Methods)
    public function startEngine() {
        return "Engine started!";
    }
}

// 创建一个对象 (类的实例)
$myCar = new Car();

// 访问对象的属性
echo $myCar->brand; // 输出: Volvo

// 调用对象的方法
echo $myCar->startEngine(); // 输出: Engine started!
?>
```

## 构造函数和析构函数

-   **`__construct()`**: 构造函数。当使用 `new` 关键字创建对象时，该方法会自动被调用。常用于初始化对象的属性。
-   **`__destruct()`**: 析构函数。当对象被销毁或脚本执行结束时，该方法会自动被调用。

```php
<?php
class Fruit {
    public $name;
    public $color;

    function __construct($name, $color) {
        $this->name = $name;
        $this->color = $color;
        echo "A new fruit '{$this->name}' is created.<br>";
    }

    function __destruct() {
        echo "The fruit '{$this->name}' is destroyed.<br>";
    }
}

$apple = new Fruit("Apple", "red");
// 脚本结束时，会自动输出 "The fruit 'Apple' is destroyed."
?>
```

## 访问控制 (Access Modifiers)

访问控制修饰符定义了属性和方法的可见性。
-   **`public`**: 可以在任何地方访问（类内部、子类、类外部）。
-   **`protected`**: 只能在类自身及其子类（继承的类）中访问。
-   **`private`**: 只能在定义它的类内部访问。

```php
<?php
class MyClass {
    public $publicVar = "Public";
    protected $protectedVar = "Protected";
    private $privateVar = "Private";

    function printHello() {
        echo $this->publicVar . "<br>";
        echo $this->protectedVar . "<br>";
        echo $this->privateVar . "<br>";
    }
}

$obj = new MyClass();
$obj->printHello(); // 输出 Public, Protected, Private
echo $obj->publicVar; // 正常工作
// echo $obj->protectedVar; // 致命错误
// echo $obj->privateVar; // 致命错误
?>
```

## 继承 (Inheritance)

继承允许一个类（子类）继承另一个类（父类）的公共和受保护的属性与方法。使用 `extends` 关键字。
```php
<?php
class Animal {
    public function eat() {
        echo "This animal eats food.<br>";
    }
}

class Dog extends Animal { // Dog 继承自 Animal
    public function bark() {
        echo "Woof woof!<br>";
    }
}

$myDog = new Dog();
$myDog->eat();  // 调用从父类继承的方法
$myDog->bark(); // 调用自己的方法
?>
```

## 常量 (Constants)

类常量使用 `const` 关键字定义。它的值一旦被设定就不能更改。访问类常量使用作用域解析操作符 `::`。
```php
<?php
class Greeting {
    const MESSAGE = "欢迎来到PHP OOP的世界!";
}

echo Greeting::MESSAGE; // 输出: 欢迎来到PHP OOP的世界!
?>
```

## 抽象类 (Abstract Classes)

-   抽象类是不能被实例化的类。它至少包含一个抽象方法。
-   抽象方法只声明了方法的名称和参数，没有具体的实现。
-   继承抽象类的子类必须实现父类中所有的抽象方法。

```php
<?php
abstract class Vehicle {
    abstract public function getNumberOfWheels(): int;
}

class Motorcycle extends Vehicle {
    public function getNumberOfWheels(): int {
        return 2;
    }
}

$moto = new Motorcycle();
echo $moto->getNumberOfWheels(); // 输出: 2
?>
```

## 接口 (Interfaces)

接口定义了类必须实现的一组方法，但它不提供这些方法的具体实现。一个类可以实现多个接口。
```php
<?php
interface Logger {
    public function log(string $message);
}

class FileLogger implements Logger {
    public function log(string $message) {
        echo "Logging to file: $message";
    }
}

class DatabaseLogger implements Logger {
    public function log(string $message) {
        echo "Logging to database: $message";
    }
}
?>
```

## Trait (特质)

Trait 是一种为类提供代码复用的机制。它旨在解决单继承语言（如PHP）的局限性。一个类可以使用 `use` 关键字来包含一个或多个trait。
```php
<?php
trait Sharable {
    public function share(string $item) {
        echo "Sharing " . $item;
    }
}

class Post {
    use Sharable;
}

class Photo {
    use Sharable;
}

$post = new Post();
$post->share("My new blog post"); // 输出: Sharing My new blog post
?>
```

## 静态属性和静态方法 (Static Properties & Methods)

-   静态成员属于类本身，而不是类的某个实例。
-   可以使用 `static` 关键字声明。
-   通过类名和 `::` 操作符直接访问，无需创建对象。

```php
<?php
class WebUtils {
    public static $pi = 3.14159;

    public static function getHostName() {
        return "example.com";
    }
}

echo WebUtils::$pi; // 输出: 3.14159
echo WebUtils::getHostName(); // 输出: example.com
?>
```

## `final` 关键字

-   如果用 `final` 关键字修饰一个类，那么这个类就不能被继承。
-   如果用 `final` 关键字修饰一个方法，那么这个方法就不能在子类中被重写 (override)。

```php
<?php
class BaseClass {
    public function test() {
        echo "BaseClass::test() called<br>";
    }

    final public function testFinal() {
        echo "BaseClass::testFinal() called<br>";
    }
}

class ChildClass extends BaseClass {
    public function test() { // 重写父类方法
        echo "ChildClass::test() called<br>";
    }
    // public function testFinal() {} // 会产生致命错误
}
?>
```
面向对象编程是构建可维护、可扩展和可重用的大型应用程序的基础。 