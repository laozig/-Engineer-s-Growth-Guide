# PHP 依赖管理 (Composer)

Composer是PHP世界中用于依赖管理的标准工具。它允许你声明项目所依赖的库，并会为你管理（安装/更新）这些库。Composer是现代PHP开发不可或缺的一部分。

## 什么是依赖管理？

几乎所有的项目都会依赖于第三方的库（packages）来完成某些功能，例如日志记录、HTTP请求、数据库操作等。这些库就是"依赖"。
依赖管理器负责：
-   解析和下载项目所需的所有库。
-   处理库之间的依赖关系（例如，库A可能依赖于库B）。
-   提供自动加载机制，让你能轻松地在项目中使用这些库的类。

## 安装 Composer

在[安装与环境配置](installation.md)章节中我们已经简要介绍过。这里重申一下，安装Composer的最佳方式是通过官方网站 [getcomposer.org](https://getcomposer.org/) 的指引。

安装完成后，你应该能够在一个终端或命令行窗口中运行 `composer` 命令。
```bash
composer --version
# Composer version 2.x.x ...
```

## 核心文件: `composer.json`

每个使用Composer的项目根目录下都有一个`composer.json`文件。这个JSON文件描述了你的项目及其依赖。

一个基本的`composer.json`文件结构如下：
```json
{
    "name": "my-vendor/my-project",
    "description": "一个示例Composer项目",
    "type": "project",
    "require": {
        "php": ">=8.0",
        "monolog/monolog": "2.3.*"
    },
    "require-dev": {
        "phpunit/phpunit": "^9.5"
    },
    "autoload": {
        "psr-4": {
            "MyProject\\": "src/"
        }
    }
}
```

-   **`name`**: 包的名称，格式为 `vendor/project`。
-   **`description`**: 项目的简短描述。
-   **`require`**: **生产环境**需要的依赖列表。
    -   `"monolog/monolog": "2.3.*"` 表示项目需要`monolog`库的`2.3`系列中的任何版本（如`2.3.0`, `2.3.5`）。
-   **`require-dev`**: **开发环境**需要的依赖列表，例如测试框架。这些包在生产环境部署时可以被忽略。
-   **`autoload`**: 定义自动加载规则。

## 基本命令

### `composer install`
当你从一个已有的项目开始（例如，从Git克隆下来）时，该项目会包含一个`composer.json`和一个`composer.lock`文件。
运行`composer install`命令，它会：
1.  检查是否存在`composer.lock`文件。
2.  如果存在，它会下载并安装`composer.lock`文件中指定的**确切版本**的依赖。这确保了团队中每个成员都使用完全相同的依赖版本。
3.  如果不存在`composer.lock`，它会读取`composer.json`，计算依赖，安装最新符合要求的版本，并创建一个新的`composer.lock`文件。

```bash
# 在包含 composer.json 的项目根目录下运行
composer install

# 在生产环境中，使用 --no-dev 可以忽略 require-dev 中的包
composer install --no-dev --optimize-autoloader
```

### `composer update`
这个命令会读取`composer.json`文件，忽略`composer.lock`，并安装**符合版本约束的最新版本**的依赖。然后，它会用新的版本信息更新`composer.lock`文件。
```bash
# 更新所有依赖
composer update

# 只更新指定的包
composer update monolog/monolog
```
**警告**: 在团队协作中，随意运行`composer update`可能会引入未经测试的新版本依赖，导致潜在的兼容性问题。通常只在需要升级依赖时才执行此命令。

### `composer require`
这是向项目中添加新依赖的最简单方法。它会自动修改`composer.json`，然后安装该依赖。
```bash
# 添加一个新的生产依赖
composer require psr/log:^1.1

# 添加一个新的开发依赖
composer require --dev fakerphp/faker
```

## 自动加载 (Autoloading)

Composer最强大的功能之一是它生成的自动加载文件。你不再需要手动编写一长串的`require_once`语句。

### `vendor/autoload.php`
当你运行`composer install`或`composer update`后，Composer会在项目根目录下创建一个`vendor`目录，里面存放着所有下载的库，以及一个`autoload.php`文件。

你只需要在你的PHP应用入口文件（例如`index.php`）的顶部包含这个文件，就可以开始使用所有已安装库的类，以及你自己项目中定义的类。
```php
<?php
// index.php

// 包含Composer的自动加载文件
require_once __DIR__ . '/vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use MyProject\MyClass;

// 使用下载的库
$log = new Logger('name');
$log->pushHandler(new StreamHandler('app.log', Logger::WARNING));
$log->warning('这是一个警告日志。');

// 使用你自己项目中的类
$myObject = new MyClass();
$myObject->doSomething();
?>
```

### PSR-4 自动加载
PSR-4是PHP社区推荐的一种自动加载标准。它规定了命名空间和文件路径之间的映射关系。

在`composer.json`中配置`autoload`部分：
```json
"autoload": {
    "psr-4": {
        "MyProject\\": "src/"
    }
}
```
这告诉Composer：
-   所有以`MyProject\`开头的命名空间...
-   ...对应的文件都可以在`src/`目录下找到。

例如，当你尝试使用`new MyProject\Controllers\HomeController()`时，Composer的自动加载器会自动查找并包含`src/Controllers/HomeController.php`这个文件。

配置完`autoload`后，你需要运行以下命令来重新生成自动加载文件：
```bash
composer dump-autoload
```

## Packagist

[Packagist](https://packagist.org/)是Composer的主要包存储库。你可以在这里找到几乎所有可用的开源PHP库。当你运行`composer require monolog/monolog`时，Composer就是在Packagist上搜索这个包。 