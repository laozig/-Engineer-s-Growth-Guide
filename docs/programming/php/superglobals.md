# PHP 超全局变量 (Superglobals)

超全局变量是PHP中一些内置的、始终可用的变量。这意味着它们在任何作用域（函数、类或文件）中都可以直接访问，无需使用 `global` 关键字。

这些变量为我们提供了大量关于脚本运行环境、用户请求和服务器状态的信息。

## `$GLOBALS`
`$GLOBALS` 是一个包含了所有全局变量的关联数组。数组的键是全局变量的名称。它是在函数或方法内部访问全局变量的另一种方式。
```php
<?php
$x = 75;
$y = 25;
 
function addition() {
    $GLOBALS['z'] = $GLOBALS['x'] + $GLOBALS['y'];
}
 
addition();
echo $z; // 输出: 100
?>
```

## `$_SERVER`
`$_SERVER` 是一个包含了诸如头信息(header)、路径(path)和脚本位置(script locations)等信息的数组。此数组中的项目由Web服务器创建。

### 常用键名:
-   **`$_SERVER['PHP_SELF']`**: 返回当前执行脚本的文件名。
-   **`$_SERVER['SERVER_NAME']`**: 返回当前运行脚本所在的服务器的主机名。
-   **`$_SERVER['HTTP_HOST']`**: 返回来自当前请求的`Host`头的内容。
-   **`$_SERVER['HTTP_USER_AGENT']`**: 返回客户端浏览器的用户代理信息。
-   **`$_SERVER['SCRIPT_NAME']`**: 返回当前脚本的路径。
-   **`$_SERVER['REQUEST_METHOD']`**: 返回访问页面所使用的请求方法（如 `GET`, `POST`）。
-   **`$_SERVER['REMOTE_ADDR']`**: 返回浏览当前页面的用户的IP地址。

```php
<?php
echo 'PHP_SELF: ' . $_SERVER['PHP_SELF'] . "<br>";
echo 'SERVER_NAME: ' . $_SERVER['SERVER_NAME'] . "<br>";
echo 'REQUEST_METHOD: ' . $_SERVER['REQUEST_METHOD'] . "<br>";
?>
```

## `$_REQUEST`
`$_REQUEST` 是一个关联数组，默认情况下包含了 `$_GET`、`$_POST` 和 `$_COOKIE` 的内容。它用于收集通过GET和POST方法发送的表单数据。

**注意**: 由于其来源不明确（可能来自GET、POST或COOKIE），并且可能导致安全问题，**通常不建议在生产代码中使用 `$_REQUEST`**。最好直接使用更具体的 `$_GET` 或 `$_POST`。

```php
// 假设请求URL为: /info.php?name=John&age=30
// 或者通过POST表单提交了 name 和 age
echo "你好, " . $_REQUEST['name']; // 输出: 你好, John
```

## `$_POST`
`$_POST` 是一个关联数组，用于收集通过HTTP POST方法发送的表单数据。当用户提交一个`method="post"`的HTML表单时，表单中的数据可以在 `$_POST` 数组中找到。

**HTML 表单 (`my_form.html`):**
```html
<form action="welcome.php" method="post">
  名字: <input type="text" name="name"><br>
  邮箱: <input type="text" name="email"><br>
  <input type="submit">
</form>
```

**PHP 脚本 (`welcome.php`):**
```php
<?php
// 检查数据是否存在，避免未定义索引的警告
if (isset($_POST['name']) && isset($_POST['email'])) {
    echo "欢迎 " . $_POST['name'] . "<br>";
    echo "你的邮箱是: " . $_POST['email'];
}
?>
```

## `$_GET`
`$_GET` 是一个关联数组，用于收集URL查询字符串中的数据，或者通过`method="get"`的HTML表单提交的数据。

**请求URL:** `http://example.com/user.php?id=123&lang=en`

**PHP 脚本 (`user.php`):**
```php
<?php
if (isset($_GET['id'])) {
    echo "正在请求用户 ID: " . $_GET['id'];
}
?>
```
GET方法不应用于发送敏感信息（如密码），因为数据在URL中是可见的。

## `$_FILES`
`$_FILES` 是一个关联数组，包含了通过HTTP POST方法上传到当前脚本的文件的信息。

假设HTML表单中有一个 `<input type="file" name="uploaded_file">`。

当文件被上传后，`$_FILES['uploaded_file']`会是一个包含以下键的数组：
-   **`name`**: 上传文件的原始文件名。
-   **`type`**: 文件的MIME类型。
-   **`size`**: 文件的大小（字节）。
-   **`tmp_name`**: 文件被上传后在服务器端的临时文件名。
-   **`error`**: 上传文件过程中的错误代码。

```php
<?php
if ($_FILES['uploaded_file']['error'] == UPLOAD_ERR_OK) {
    $tmp_name = $_FILES['uploaded_file']['tmp_name'];
    $name = basename($_FILES['uploaded_file']['name']);
    move_uploaded_file($tmp_name, "uploads/$name");
    echo "文件上传成功!";
}
?>
```

## `$_ENV`
`$_ENV` 是一个关联数组，包含了通过环境方法传递给当前脚本的变量。这些变量通常在shell环境或`.env`文件中定义。

## `$_COOKIE`
`$_COOKIE` 是一个关联数组，包含了通过HTTP Cookie传递给当前脚本的变量。你可以用`setcookie()`函数来设置cookie。

**设置Cookie:**
```php
<?php
$cookie_name = "user";
$cookie_value = "John Doe";
// cookie将在1小时后过期 (3600秒)
setcookie($cookie_name, $cookie_value, time() + 3600, "/"); 
?>
```

**读取Cookie:**
```php
<?php
if(isset($_COOKIE['user'])) {
    echo "欢迎回来, " . $_COOKIE['user'];
} else {
    echo "欢迎, 新访客!";
}
?>
```

## `$_SESSION`
`$_SESSION` 是一个关联数组，包含了会话变量。会话（Session）是一种在服务器上存储用户信息的方式，以便在跨多个页面时使用。
在使用`$_SESSION`之前，必须先调用`session_start()`函数。

**启动会话并设置变量:**
```php
<?php
// 启动会话
session_start();

// 设置会话变量
$_SESSION["favcolor"] = "green";
$_SESSION["favanimal"] = "cat";
echo "会话变量已设置。";
?>
```

**访问会话变量:**
```php
<?php
session_start();

if (isset($_SESSION["favcolor"])) {
    echo "最喜欢的颜色是 " . $_SESSION["favcolor"] . ".";
}
?>
```
与Cookie不同，会话数据存储在服务器上，只有一个唯一的会话ID存储在客户端的Cookie中。 