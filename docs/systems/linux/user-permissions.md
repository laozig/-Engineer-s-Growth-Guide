# 6. 用户与权限管理

Linux 是一个多用户操作系统，这意味着多个用户可以同时登录和使用系统。因此，拥有一套健全的权限管理机制来保护用户文件和系统安全至关重要。本章将介绍 Linux 的用户、用户组和文件权限模型。

## 用户 (Users) 和用户组 (Groups)

### 1. 用户 (Users)
- **超级用户 (root)**: 系统中拥有最高权限的用户，其用户名为 `root`。它可以访问系统上的任何文件，执行任何命令。
- **普通用户 (Regular Users)**: 权限受限的用户，通常只能在自己的主目录 (`/home/username`) 中创建和修改文件。
- **系统用户 (System Users)**: 用于运行特定服务或进程的用户，例如 `www-data` 用户用于运行 Apache Web 服务器。这些用户通常不允许登录。

### 2. 用户组 (Groups)
- 用户组是用户的集合。
- 权限可以被授予整个用户组，该组内的所有用户将继承这些权限。
- 一个用户可以属于多个组，但有一个是其**主组 (primary group)**，通常在创建用户时一同创建。

### 相关文件
- `/etc/passwd`: 存储用户账户信息（用户名、用户ID(UID)、主组ID(GID)、主目录、登录Shell）。
- `/etc/shadow`: 存储用户的加密密码和密码策略。只有 `root` 用户可读。
- `/etc/group`: 存储用户组信息（组名、组ID(GID)、组成员）。

## 文件权限

使用 `ls -l` 命令可以查看文件或目录的详细信息，其中第一列就是权限信息。

```bash
ls -l /etc/passwd
# 输出示例:
# -rw-r--r-- 1 root root 2345 Jul 15 10:00 /etc/passwd
```

让我们来解析 `_rw_r__r__` 这 10 个字符：

**第 1 位: 文件类型**
- `-`: 普通文件
- `d`: 目录
- `l`: 符号链接
- `c`: 字符设备文件
- `b`: 块设备文件

**第 2-4 位: 文件所有者 (User) 的权限**
**第 5-7 位: 文件所属组 (Group) 的权限**
**第 8-10 位: 其他用户 (Others) 的权限**

每一组权限由三个字符组成：`r`, `w`, `x`。

- **`r` (Read)**: 读权限
  - 对文件: 可以读取文件的内容。
  - 对目录: 可以列出目录中的文件和子目录 (`ls`)。
- **`w` (Write)**: 写权限
  - 对文件: 可以修改或删除文件的内容。
  - 对目录: 可以在目录中创建、删除或重命名文件。**这是一个非常重要的权限！**
- **`x` (Execute)**: 执行权限
  - 对文件: 可以作为程序来执行。
  - 对目录: 可以进入该目录 (`cd`)。

**示例解析**: `-rw-r--r--`
- `_`: 这是一个普通文件。
- `rw_`: 所有者 `root` 具有**读**和**写**权限。
- `r__`: 所属组 `root` 的成员只有**读**权限。
- `r__`: 其他任何用户也只有**读**权限。

## 修改权限 (`chmod`)

`chmod` (change mode) 命令用于修改文件或目录的权限。它有两种模式：符号模式和八进制模式。

### 1. 符号模式 (Symbolic Mode)

语法: `chmod [who][operator][permission] file`
- **who (谁)**:
  - `u`: 用户 (user/owner)
  - `g`: 组 (group)
  - `o`: 其他人 (others)
  - `a`: 所有人 (all)，相当于 `ugo`
- **operator (操作)**:
  - `+`: 添加权限
  - `-`: 移除权限
  - `=`: 设置精确的权限
- **permission (权限)**: `r`, `w`, `x`

```bash
# 为文件 'script.sh' 的所有者添加执行权限
chmod u+x script.sh

# 为组和其他人移除写权限
chmod go-w confidential.txt

# 为所有人添加读权限
chmod a+r public_info.txt

# 将权限精确设置为: user 可读写，group 可读，others 无权限
chmod u=rw,g=r,o= private.dat
```

### 2. 八进制模式 (Octal/Numeric Mode)

这是更常用、更快捷的方式。每个权限用一个数字表示：
- `r` = 4
- `w` = 2
- `x` = 1
- `-` = 0

将每组（user, group, others）的权限数字相加：
- `rwx` = 4+2+1 = 7
- `rw-` = 4+2+0 = 6
- `r-x` = 4+0+1 = 5
- `r--` = 4+0+0 = 4

```bash
# 设置 script.sh 的权限为 rwxr-xr-x (所有者可读写执行，组和其他人可读执行)
chmod 755 script.sh

# 设置 confidential.txt 的权限为 rw------- (只有所有者可读写)
chmod 600 confidential.txt

# 设置 public_dir 目录的权限为 rwxr-xr-x
chmod 755 public_dir

# 设置一个共享目录，组内成员可以读写
# drwxrwx---
chmod 770 shared_folder
```

要递归地修改目录及其下所有内容的权限，使用 `-R` 选项。
```bash
chmod -R 755 my_project/
```

## 修改所有权

### 1. `chown` - (Change Owner) 修改所有者

`chown` 命令用于修改文件或目录的所有者和所属组。

```bash
# 将文件 'data.txt' 的所有者更改为 'jane'
chown jane data.txt

# 同时更改所有者为 'jane'，所属组为 'developers'
chown jane:developers report.docx

# 递归地更改目录的所有权
chown -R john:employees project_files/
```

### 2. `chgrp` - (Change Group) 修改所属组

`chgrp` 命令专门用于修改文件的所属组。

```bash
# 将 'script.sh' 的所属组更改为 'admins'
chgrp admins script.sh
```

## 用户和组管理命令

这些命令通常需要 `root` 权限（使用 `sudo`）。

- **`useradd`**: 添加新用户
  ```bash
  # 创建一个新用户 'bob'，并为其创建主目录
  sudo useradd -m bob
  ```
- **`passwd`**: 设置或修改用户密码
  ```bash
  # 为用户 'bob' 设置密码 (会提示输入新密码)
  sudo passwd bob
  ```
- **`usermod`**: 修改用户属性
  ```bash
  # 将用户 'bob' 添加到 'developers' 组
  sudo usermod -aG developers bob
  # 更改 'bob' 的登录 Shell 为 zsh
  sudo usermod -s /bin/zsh bob
  ```
- **`userdel`**: 删除用户
  ```bash
  # 删除用户 'bob'，但不删除其主目录
  sudo userdel bob
  # 删除用户 'bob' 并移除其主目录
  sudo userdel -r bob
  ```
- **`groupadd`**: 添加新用户组
  ```bash
  sudo groupadd editors
  ```
- **`groupdel`**: 删除用户组
  ```bash
  sudo groupdel editors
  ```

## 使用 `sudo`

`sudo` (superuser do) 是一个命令，它允许被授权的普通用户以超级用户或其他用户的身份执行命令。这是在现代 Linux 系统中进行系统管理的首选方式，而不是直接使用 `root` 登录。

- **配置**: `sudo` 的规则定义在 `/etc/sudoers` 文件中。**永远不要直接编辑这个文件！** 应该使用 `visudo` 命令，它会在保存时检查语法错误，防止你把自己锁在系统之外。
- **使用**: 在需要管理员权限的命令前加上 `sudo`。

```bash
# 安装一个软件包
sudo apt-get install nginx

# 编辑一个系统配置文件
sudo nano /etc/hosts

# 以 root 用户身份启动一个新的 Shell
sudo -i
``` 