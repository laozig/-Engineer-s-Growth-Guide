# Linux 用户权限管理

Linux 是一个多用户操作系统，具有强大的权限管理机制，确保系统资源能够被合理分配和保护。本文将介绍 Linux 中的用户、组管理以及文件权限系统。

## 用户和组管理

### 用户管理

Linux 系统中每个用户都有一个唯一的用户 ID (UID) 和一个主要组 ID (GID)。

#### 用户类型
1. **root 用户** - UID 为 0，拥有系统的完全控制权
2. **系统用户** - 为系统服务运行而创建的用户，通常不用于登录
3. **普通用户** - 正常登录系统的用户账户

#### 用户管理命令

```bash
# 创建新用户
sudo useradd -m -s /bin/bash username

# 带有更多选项的用户创建
sudo useradd -m -s /bin/bash -c "Full Name" -G wheel,developers username

# 修改现有用户
sudo usermod -aG sudo username  # 将用户添加到 sudo 组

# 删除用户
sudo userdel username           # 保留家目录
sudo userdel -r username        # 同时删除家目录

# 设置/修改密码
sudo passwd username

# 切换用户
su - username

# 查看当前用户信息
id
whoami

# 查看所有用户
cat /etc/passwd
```

#### 用户配置文件
- `/etc/passwd` - 存储用户账户信息
- `/etc/shadow` - 存储加密的用户密码
- `/etc/login.defs` - 用户创建的默认设置

### 组管理

组是用户的集合，用于简化权限管理。

#### 组类型
1. **主要组（Primary Group）** - 用户创建文件时默认分配的组
2. **附加组（Supplementary Groups）** - 用户可以同时属于多个附加组

#### 组管理命令

```bash
# 创建新组
sudo groupadd groupname

# 修改组
sudo groupmod -n new_name old_name

# 删除组
sudo groupdel groupname

# 将用户添加到组
sudo gpasswd -a username groupname

# 从组中删除用户
sudo gpasswd -d username groupname

# 查看所有组
cat /etc/group

# 查看用户所属的组
groups username
```

#### 组配置文件
- `/etc/group` - 存储组信息
- `/etc/gshadow` - 存储组密码信息

## 文件权限

Linux 中的文件权限系统是基于用户、组和其他人（world）三个级别的权限设置。

### 基本权限

每个文件或目录有三种基本权限类型：

1. **读（r）** - 读取文件内容或列出目录内容
2. **写（w）** - 修改文件内容或在目录中创建/删除文件
3. **执行（x）** - 执行文件（如脚本、程序）或进入目录

### 查看文件权限

使用 `ls -l` 命令可以查看文件的详细权限信息：

```bash
$ ls -l file.txt
-rw-r--r-- 1 user group 4096 Aug 10 12:34 file.txt
```

权限表示解析：
- 第1位：文件类型（`-`表示普通文件，`d`表示目录，`l`表示符号链接等）
- 第2-4位：所有者权限（`rw-`表示可读、可写、不可执行）
- 第5-7位：所属组权限（`r--`表示仅可读）
- 第8-10位：其他用户权限（`r--`表示仅可读）

### 修改文件权限

#### 使用符号模式

```bash
# 格式：chmod [用户类型][操作符][权限] 文件/目录
# 用户类型：u(用户)、g(组)、o(其他)、a(所有)
# 操作符：+(添加)、-(删除)、=(设置)
# 权限：r(读)、w(写)、x(执行)

# 为所有者添加执行权限
chmod u+x script.sh

# 为所有者和组添加写权限
chmod ug+w file.txt

# 为所有人移除写权限
chmod a-w important.txt

# 设置精确权限
chmod u=rwx,g=rx,o=r file.txt
```

#### 使用数字模式

数字权限使用八进制数字表示：
- 读(r) = 4
- 写(w) = 2
- 执行(x) = 1

将所需权限的数值相加，得到每个级别（用户、组、其他）的权限数字。

```bash
# 设置权限为：用户(rwx=7)、组(r-x=5)、其他(r--=4)
chmod 754 file.txt

# 常用组合：
chmod 755 script.sh  # rwxr-xr-x（可执行脚本）
chmod 644 file.txt   # rw-r--r--（普通文件）
chmod 600 id_rsa     # rw-------（私钥）
chmod 777 temp.txt   # rwxrwxrwx（完全访问，不安全）
```

### 目录权限的特殊性

对于目录，权限具有不同的含义：
- 读权限(r)：允许列出目录内容
- 写权限(w)：允许在目录中创建、删除或重命名文件
- 执行权限(x)：允许进入目录或访问其中的文件

### 默认权限和 umask

新创建的文件和目录的默认权限由系统的 umask 值决定：
- 文件的最大默认权限为 666 (rw-rw-rw-)
- 目录的最大默认权限为 777 (rwxrwxrwx)
- umask 值从这些最大值中减去

```bash
# 查看当前 umask 值
umask

# 设置新的 umask 值（会话期间有效）
umask 022  # 文件将是 644，目录将是 755
```

## 特殊权限

除了基本的读、写、执行权限外，Linux 还提供了三种特殊权限：

### SetUID (SUID)

- 当应用于可执行文件时，允许用户以文件所有者的权限执行该文件
- 数字表示：4000
- 符号表示：s 替代所有者的 x 位置

```bash
# 设置 SUID
chmod u+s file
chmod 4755 file  # rwsr-xr-x
```

### SetGID (SGID)

- 应用于可执行文件：允许用户以文件所属组的权限执行文件
- 应用于目录：在该目录中创建的新文件会继承目录的组所有权
- 数字表示：2000
- 符号表示：s 替代组的 x 位置

```bash
# 设置 SGID
chmod g+s file_or_directory
chmod 2755 file  # rwxr-sr-x
```

### Sticky Bit

- 主要用于共享目录，防止用户删除其他用户的文件
- 数字表示：1000
- 符号表示：t 替代其他用户的 x 位置

```bash
# 设置 Sticky Bit
chmod +t directory
chmod 1777 directory  # rwxrwxrwt
```

### 组合特殊权限

```bash
# 设置 SUID、SGID 和 Sticky Bit
chmod 7777 file  # rwsrwsrwt
```

## 访问控制列表 (ACL)

当基本权限系统不够灵活时，可以使用 ACL 进行更精细的权限控制。

### 安装 ACL 工具

```bash
# Debian/Ubuntu
sudo apt install acl

# CentOS/RHEL
sudo yum install acl
```

### 使用 ACL

```bash
# 查看文件的 ACL
getfacl file.txt

# 为用户设置 ACL
setfacl -m u:username:rwx file.txt

# 为组设置 ACL
setfacl -m g:groupname:rx file.txt

# 设置默认 ACL（应用于目录中创建的新文件）
setfacl -d -m u:username:rwx directory

# 删除特定用户的 ACL
setfacl -x u:username file.txt

# 删除所有 ACL
setfacl -b file.txt
```

## chown 和 chgrp 命令

### 更改文件所有者和组

```bash
# 更改文件所有者
sudo chown username file.txt

# 更改文件所有者和组
sudo chown username:groupname file.txt

# 仅更改组
sudo chgrp groupname file.txt

# 递归更改目录及其内容的所有权
sudo chown -R username:groupname directory/
```

## sudo 和提升权限

sudo 允许授权用户以超级用户或其他用户的身份执行命令。

### 配置 sudo

sudo 的配置在 `/etc/sudoers` 文件中，应使用 `visudo` 命令编辑：

```bash
sudo visudo
```

### sudo 配置示例

```
# 用户规则
username ALL=(ALL) ALL  # 允许用户执行任何命令，需要密码

# 组规则（%表示组）
%wheel ALL=(ALL) ALL    # 允许 wheel 组的所有成员执行任何命令

# 免密码执行
username ALL=(ALL) NOPASSWD: ALL

# 限制特定命令
username ALL=(ALL) /bin/ls, /usr/bin/apt
```

### 使用 sudo

```bash
# 以 root 身份执行命令
sudo command

# 以特定用户身份执行命令
sudo -u username command

# 切换到 root shell
sudo -i
sudo su -

# 查看 sudo 权限
sudo -l
```

## 安全最佳实践

1. **最小权限原则**：只给用户完成任务所需的最小权限
2. **避免使用 root 账户**：使用 sudo 执行需要特权的任务
3. **定期审计**：检查系统用户和权限
4. **谨慎使用特殊权限**：尤其是 SUID 和 SGID
5. **密码策略**：强制使用强密码，定期更换
6. **安全的 umask**：使用较严格的 umask（如 027）
7. **文件权限审计**：定期检查关键文件和目录的权限

## 常见问题

### 1. 权限拒绝

```bash
-bash: ./script.sh: Permission denied
```

解决方法：
```bash
chmod +x script.sh
```

### 2. 目录遍历权限

要访问 `/path/to/file.txt`，需要：
- 对 `/`, `/path`, `/path/to` 有执行权限 (x)
- 对 `file.txt` 有适当的权限

### 3. 共享目录设置

创建多用户共享目录：
```bash
# 创建组
sudo groupadd shared_group

# 创建目录
sudo mkdir /shared

# 设置所有权
sudo chown root:shared_group /shared

# 设置权限（包括 SGID 和 Sticky Bit）
sudo chmod 2775 /shared  # rwxrwsr-x

# 将用户添加到组
sudo usermod -aG shared_group user1
sudo usermod -aG shared_group user2
```

## 参考资源

- [Linux 权限管理详解](https://www.linuxfoundation.org/blog/blog/classic-sysadmin-understanding-linux-file-permissions)
- [Linux 用户和组管理指南](https://www.redhat.com/sysadmin/linux-user-group-management)
- [sudo 官方文档](https://www.sudo.ws/docs/man/sudoers.man/) 