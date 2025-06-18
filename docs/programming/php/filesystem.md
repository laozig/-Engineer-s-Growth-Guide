# PHP 文件系统操作

PHP提供了一套强大而丰富的函数来与服务器上的文件系统进行交互。这包括读取、写入、创建和删除文件及目录。

## 检查文件和目录

在对文件或目录进行操作之前，检查它们是否存在以及是否具有正确的权限是一种好习惯。

-   **`file_exists(string $filename): bool`**: 检查文件或目录是否存在。
-   **`is_file(string $filename): bool`**: 判断给定文件名是否为一个正常的文件。
-   **`is_dir(string $filename): bool`**: 判断给定文件名是否为一个目录。
-   **`is_readable(string $filename): bool`**: 判断文件或目录是否存在且可读。
-   **`is_writable(string $filename): bool`**: 判断文件或目录是否存在且可写。
-   **`filesize(string $filename): int|false`**: 获取文件大小（以字节为单位）。

```php
<?php
$file = 'my_file.txt';

if (file_exists($file)) {
    echo "文件 $file 存在。<br>";
    if (is_readable($file) && is_writable($file)) {
        echo "文件可读可写。<br>";
        echo "文件大小: " . filesize($file) . " 字节。<br>";
    }
} else {
    echo "文件 $file 不存在。<br>";
}
?>
```

## 读取文件

### 1. `file_get_contents()` - 简单快捷

这是将整个文件读入一个字符串的最简单方法。
```php
<?php
$file = 'readme.txt';

if (file_exists($file) && is_readable($file)) {
    $content = file_get_contents($file);
    // 使用 nl2br 将换行符转换为 <br> 标签以便在HTML中显示
    echo nl2br($content);
}
?>
```
**注意**: 此函数会将整个文件加载到内存中，对于非常大的文件可能会消耗大量内存。

### 2. `fopen()`, `fread()`, `fclose()` - 更灵活的控制

对于大文件或需要更精细控制（例如，一次只读取一部分）的情况，可以使用这组函数。

1.  **`fopen(string $filename, string $mode)`**: 打开文件，返回一个文件指针（资源）。`$mode`参数指定了打开文件的模式（`r`=只读, `w`=只写, `a`=追加等）。
2.  **`fread(resource $handle, int $length)`**: 从文件指针中读取指定长度的字节。
3.  **`fclose(resource $handle)`**: 关闭一个已打开的文件指针。

```php
<?php
$file = 'readme.txt';
$handle = fopen($file, 'r'); // 以只读模式打开文件

if ($handle) {
    // 读取整个文件
    $content = fread($handle, filesize($file));
    echo nl2br($content);
    
    // 关闭文件句柄
    fclose($handle);
}
?>
```

### 3.逐行读取文件

-   **`fgets(resource $handle): string|false`**: 从文件指针中读取一行。
-   **`feof(resource $handle): bool`**: 测试文件指针是否到了文件结束的位置。

```php
<?php
$file = 'readme.txt';
$handle = fopen($file, 'r');

if ($handle) {
    while (!feof($handle)) {
        $line = fgets($handle);
        echo $line . "<br>";
    }
    fclose($handle);
}
?>
```

## 写入文件

### 1. `file_put_contents()` - 简单快捷

这是将一个字符串写入文件的最简单方法。如果文件不存在，它会尝试创建该文件。
```php
<?php
$file = 'log.txt';
$content = "这是一个新的日志条目。\n";

// 写入文件，如果文件已存在则会覆盖
file_put_contents($file, $content);

// 追加内容到文件末尾
$new_content = "这是追加的日志条目。\n";
file_put_contents($file, $new_content, FILE_APPEND);
?>
```

### 2. `fopen()`, `fwrite()`, `fclose()`

与读取文件类似，这组函数提供了更底层的控制。

```php
<?php
$file = 'app.log';
// 以追加模式打开文件。如果文件不存在，会尝试创建它。
$handle = fopen($file, 'a');

if ($handle) {
    $log_entry = date('Y-m-d H:i:s') . " - 用户登录。\n";
    fwrite($handle, $log_entry);
    fclose($handle);
    echo "日志已写入。";
}
?>
```

## 目录操作

### 1. 创建和删除目录
-   **`mkdir(string $pathname, int $mode = 0777, bool $recursive = false): bool`**: 创建目录。
-   **`rmdir(string $dirname): bool`**: 删除一个**空**目录。

```php
<?php
$dir = 'my_new_directory';

// 创建目录
if (!file_exists($dir)) {
    mkdir($dir, 0755, true); // 0755是常用的权限模式, true表示可以递归创建
    echo "目录 $dir 创建成功。<br>";
}

// 删除目录 (注意: 目录必须是空的)
if (file_exists($dir) && is_dir($dir)) {
    // rmdir($dir);
    // echo "目录 $dir 删除成功。<br>";
}
?>
```

### 2. 读取目录内容
-   **`scandir(string $directory): array|false`**: 列出指定路径中的文件和目录，返回一个数组。

```php
<?php
$dir = './'; // 当前目录
$files = scandir($dir);

echo "<pre>";
print_r($files);
echo "</pre>";

// 遍历并排除 . 和 ..
foreach ($files as $file) {
    if ($file !== '.' && $file !== '..') {
        echo $file . "<br>";
    }
}
?>
```
`scandir()`返回的结果中会包含 `.` (当前目录) 和 `..` (上级目录)。

## 其他有用的文件函数

-   **`copy(string $source, string $dest): bool`**: 拷贝文件。
-   **`rename(string $oldname, string $newname): bool`**: 重命名或移动文件/目录。
-   **`unlink(string $filename): bool`**: 删除文件。
-   **`pathinfo(string $path, int $flags = PATHINFO_ALL): array|string`**: 返回文件路径的信息，如目录名、基本名、扩展名。

```php
<?php
$path = '/var/www/html/index.php';
$info = pathinfo($path);

echo "目录名: " . $info['dirname'] . "<br>";   // /var/www/html
echo "基本名: " . $info['basename'] . "<br>";  // index.php
echo "扩展名: " . $info['extension'] . "<br>"; // php
echo "文件名: " . $info['filename'] . "<br>";   // index
?>
```
通过这些函数，PHP可以完成几乎所有你需要的文件系统管理任务。 