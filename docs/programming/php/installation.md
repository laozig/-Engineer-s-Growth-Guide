# PHP 安装与环境配置

搭建一个稳定、高效的PHP开发环境是开始PHP编程的第一步。本指南将介绍如何在主流操作系统（Windows, macOS, Linux）上安装PHP、配置Web服务器以及安装Composer依赖管理器。

## 目录
1.  [Windows环境配置](#windows环境配置)
    -   使用XAMPP/WampServer集成包
    -   手动安装PHP
2.  [macOS环境配置](#macOS环境配置)
    -   使用Homebrew
3.  [Linux环境配置 (Ubuntu/Debian)](#linux环境配置-ubuntudebian)
    -   使用APT包管理器
4.  [安装Composer（所有平台）](#安装composer所有平台)
5.  [配置Web服务器 (Nginx)](#配置web服务器-nginx)
6.  [验证安装](#验证安装)

---

## Windows环境配置

在Windows上安装PHP，最简单的方式是使用集成了Apache、PHP和MySQL的软件包，如XAMPP或WampServer。

### 使用XAMPP/WampServer集成包

1.  **下载**:
    -   访问 [XAMPP 官方网站](https://www.apachefriends.org/index.html) 或 [WampServer 官方网站](https://www.wampserver.com/en/)。
    -   根据你的系统（32位或64位）下载最新版本的安装程序。

2.  **安装**:
    -   运行下载的`.exe`文件。
    -   遵循安装向导的指示。建议不要安装在`C:\Program Files`目录下，以避免权限问题，可以选择`C:\xampp`或`D:\wamp`等路径。
    -   安装完成后，启动XAMPP或WampServer的控制面板。

3.  **启动服务**:
    -   在控制面板中，启动Apache Web服务器和MySQL数据库服务。
    -   打开浏览器，访问 `http://localhost`。如果你看到XAMPP或WampServer的欢迎页面，说明Apache运行正常。

4.  **将PHP添加到系统PATH**:
    -   找到PHP的安装路径，例如 `C:\xampp\php`。
    -   右键点击"此电脑" -> "属性" -> "高级系统设置" -> "环境变量"。
    -   在"系统变量"中找到`Path`，点击"编辑"。
    -   新建一个条目，并将PHP的路径粘贴进去。
    -   这样，你就可以在任何命令行窗口中使用`php`命令。

### 手动安装PHP

如果你想拥有更多控制权，可以选择手动安装。
1.  访问 [PHP for Windows 官网](https://windows.php.net/download/)。
2.  下载最新的 **"VS16 x64 Thread Safe"** ZIP压缩包。
3.  在`C:\`根目录下创建一个`php`文件夹，并将压缩包内容解压到此。
4.  将`php.ini-development`文件复制并重命名为`php.ini`。
5.  按照上述方法，将`C:\php`添加到系统环境变量`Path`中。

---

## macOS环境配置

在macOS上，推荐使用 [Homebrew](https://brew.sh/) 包管理器来安装PHP。

1.  **安装Homebrew**:
    如果你没有安装Homebrew，请打开终端并运行以下命令：
    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```

2.  **安装PHP**:
    使用Homebrew安装最新版本的PHP：
    ```bash
    brew install php
    ```

3.  **启动PHP内置服务器**:
    Homebrew安装的PHP自带一个开发服务器。你可以通过以下命令启动它：
    ```bash
    php -S localhost:8000
    ```

---

## Linux环境配置 (Ubuntu/Debian)

在基于Debian的Linux发行版（如Ubuntu）上，可以使用`apt`包管理器。

1.  **更新包列表**:
    ```bash
    sudo apt update
    ```

2.  **安装PHP及常用扩展**:
    ```bash
    sudo apt install php php-cli php-fpm php-mysql php-json php-gd php-curl
    ```
    -   `php-fpm` (FastCGI Process Manager) 是一个常用的PHP-FPM实现，常与Nginx配合使用。
    -   其他`php-*`包是常用的PHP扩展。

---

## 安装Composer（所有平台）

[Composer](https://getcomposer.org/) 是PHP的依赖管理器，是现代PHP开发不可或缺的工具。

1.  **下载并安装Composer**:
    打开终端或命令行，执行以下命令：
    ```bash
    php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
    php composer-setup.php
    php -r "unlink('composer-setup.php');"
    ```
    这会在当前目录下生成一个`composer.phar`文件。

2.  **全局安装 (推荐)**:
    为了能在任何地方使用`composer`命令，你需要将`composer.phar`移动到一个位于系统PATH中的目录。

    -   **Linux/macOS**:
        ```bash
        sudo mv composer.phar /usr/local/bin/composer
        ```
    -   **Windows**:
        -   在`C:\`下创建一个`bin`目录，例如`C:\bin`。
        -   将`composer.phar`移动到该目录。
        -   将`C:\bin`添加到系统环境变量`Path`中。
        -   创建一个名为`composer.bat`的文件，内容为：`@php "%~dp0composer.phar" %*`。

3.  **验证安装**:
    运行`composer --version`，如果看到版本信息，说明安装成功。

---

## 配置Web服务器 (Nginx)

虽然PHP有内置服务器可用于开发，但在生产环境或需要更复杂配置时，通常会使用Nginx或Apache。以下是Nginx的基本配置示例。

1.  **安装Nginx**:
    -   **Linux (Ubuntu)**: `sudo apt install nginx`
    -   **macOS**: `brew install nginx`
    -   **Windows**: 从 [Nginx官网](http://nginx.org/en/download.html) 下载并解压。

2.  **配置Nginx与PHP-FPM**:
    创建一个新的Nginx站点配置文件，例如 `/etc/nginx/sites-available/default` (Linux) 或 `/usr/local/etc/nginx/servers/` (macOS)。

    ```nginx
    server {
        listen 80;
        server_name your_domain.com www.your_domain.com; # 替换为你的域名或localhost
        root /var/www/html; # 你的项目根目录

        index index.php index.html index.htm;

        location / {
            try_files $uri $uri/ /index.php?$query_string;
        }

        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            # 在Linux上通常是 /var/run/php/php8.2-fpm.sock (版本号可能不同)
            # 在macOS上通常是 /usr/local/var/run/php-fpm.sock
            fastcgi_pass unix:/var/run/php/php-fpm.sock; 
        }

        location ~ /\.ht {
            deny all;
        }
    }
    ```
    -   确保`fastcgi_pass`指令指向正确的PHP-FPM套接字文件。
    -   重启Nginx服务以使配置生效：`sudo systemctl restart nginx` (Linux)。

---

## 验证安装

1.  **命令行验证**:
    打开终端或CMD，运行：
    ```bash
    php -v
    ```
    如果显示PHP版本信息，说明PHP CLI已正确安装。

2.  **Web服务器验证**:
    -   在你的Web服务器根目录（例如 `/var/www/html` 或 `C:\xampp\htdocs`）创建一个名为 `info.php` 的文件。
    -   文件内容如下：
        ```php
        <?php
        phpinfo();
        ?>
        ```
    -   在浏览器中访问 `http://localhost/info.php`。
    -   如果你看到一个包含PHP配置详情的页面，说明Web服务器和PHP已成功集成。

完成以上步骤后，你就拥有了一个功能齐全的PHP开发环境，可以开始你的PHP编程之旅了。 