# PHP 会话 (Session) 与 Cookie

HTTP协议是无状态的，这意味着Web服务器不会记录关于用户访问的任何信息。为了在多个页面之间保持用户的状态（例如，用户是否已登录），Web开发者需要使用特定的技术，其中最主要的就是Cookie和Session。

## Cookie

Cookie是存储在用户计算机上的小文本文件。当浏览器从服务器请求一个页面时，属于该服务器的cookie也会被一同发送。这使得服务器能够识别用户。

### 如何创建Cookie？

使用 `setcookie()` 函数来创建cookie。这个函数**必须**在任何HTML标签之前调用。
**语法:**
`setcookie(name, value, expire, path, domain, secure, httponly)`

-   `name`: cookie的名称。
-   `value`: cookie的值。
-   `expire`: cookie的过期时间戳。通常使用 `time()` 函数加上秒数来设置，例如 `time() + 3600` 表示1小时后过期。如果设置为0或省略，cookie将在浏览器关闭时失效。
-   `path`: cookie在服务器上的有效路径。`/` 表示在整个域名内有效。

**示例:**
```php
<?php
$cookie_name = "user";
$cookie_value = "Alex Porter";
// 设置一个有效期为1小时的cookie
setcookie($cookie_name, $cookie_value, time() + (86400 * 30), "/"); // 86400 = 1 day
?>
<!DOCTYPE html>
<html>
<body>

<?php
if(!isset($_COOKIE[$cookie_name])) {
    echo "Cookie named '" . $cookie_name . "' is not set!";
} else {
    echo "Cookie '" . $cookie_name . "' is set!<br>";
    echo "Value is: " . $_COOKIE[$cookie_name];
}
?>

</body>
</html>
```

### 如何读取Cookie？

使用 `$_COOKIE` 超全局变量来读取cookie的值。

### 如何删除Cookie？

要删除一个cookie，你需要再次调用`setcookie()`，但将过期时间设置为一个过去的时间点。
```php
<?php
// 将过期日期设置为一小时前
setcookie("user", "", time() - 3600);
?>
```

### Cookie的优缺点

-   **优点**: 简单易用，数据存储在客户端，不占用服务器资源。
-   **缺点**:
    -   **不安全**: 数据以明文形式存储在用户本地，不应存储敏感信息。
    -   **大小限制**: 大多数浏览器限制cookie大小约为4KB。
    -   **用户可禁用**: 用户可以在浏览器设置中禁用cookie。

## 会话 (Session)

会话是一种在服务器端存储用户信息的方式。与cookie不同，会话数据不会存储在用户的计算机上，只有一个唯一的会话ID（通常是一个随机字符串）会通过cookie发送给客户端。

### 如何开始一个PHP会话？

在访问任何会话数据之前，必须先调用 `session_start()` 函数。这个函数会检查是否存在会话ID，如果不存在则创建一个新的，并启动会话。
`session_start()` **必须**是你脚本中的第一个语句。

### 存储和访问会话数据

使用 `$_SESSION` 超全局数组来存储和访问会话数据。

**`session_start_page.php`:**
```php
<?php
// 启动会话
session_start();
?>
<!DOCTYPE html>
<html>
<body>

<?php
// 设置会话变量
$_SESSION["favcolor"] = "green";
$_SESSION["favanimal"] = "cat";
echo "Session variables are set.";
?>

<a href="session_get_page.php">Go to next page to get session data</a>

</body>
</html>
```

**`session_get_page.php`:**
```php
<?php
// 必须先启动会话
session_start();
?>
<!DOCTYPE html>
<html>
<body>

<?php
// 打印会话变量
print_r($_SESSION);

echo "<br>Favorite color is " . $_SESSION["favcolor"] . ".<br>";
echo "Favorite animal is " . $_SESSION["favanimal"] . ".";
?>

</body>
</html>
```

### 修改和删除会话变量

-   **修改**: 像普通数组一样直接覆盖即可。
    `$_SESSION["favcolor"] = "yellow";`
-   **删除部分**: 使用 `unset()` 函数。
    `unset($_SESSION["favcolor"]);`

### 销毁会话

如果你想彻底清除所有会话数据，可以使用以下两个函数：
1.  **`session_unset()`**: 释放所有的会话变量。
2.  **`session_destroy()`**: 销毁会话。这会删除服务器上存储的会话文件。

```php
<?php
session_start();

// 移除所有会话变量
session_unset();

// 销毁会话
session_destroy();

echo "All session variables are now removed, and the session is destroyed."
?>
```

## Cookie vs. Session

| 特性 | Cookie | Session |
| :--- | :--- | :--- |
| **存储位置** | 客户端（浏览器） | 服务器端 |
| **安全性** | 较低（明文存储） | 较高（数据不在客户端暴露） |
| **数据大小** | 小（约4KB） | 较大（受服务器内存限制） |
| **生命周期** | 可长时间保持 | 浏览器关闭后通常会失效 |
| **依赖关系** | Session依赖Cookie来存储Session ID | Cookie是独立的 |

**何时使用？**
-   **Cookie**: 用于存储非敏感信息，如用户偏好（主题颜色、语言选择）、"记住我"功能。
-   **Session**: 用于存储敏感信息，如用户登录状态、用户ID、购物车内容等。

在现代Web应用中，Session是实现用户认证和状态管理的首选方法。 