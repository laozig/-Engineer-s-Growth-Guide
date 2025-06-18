# 12. 服务管理 (systemd)

在 Linux 系统中，服务（也称为守护进程, daemons）是在后台运行、等待执行任务或响应请求的程序。例如，Web 服务器 (`nginx`)、数据库 (`mysqld`) 和 SSH 服务 (`sshd`) 都是以服务的形式运行的。

现代 Linux 系统大多使用 `systemd` 作为其初始化系统 (init system) 和服务管理器。`systemd` 负责在系统启动时启动所有必要的服务，并在系统运行期间对它们进行管理。

## 什么是 systemd?

- **初始化系统**: 它是内核加载后启动的第一个进程 (PID 1)，负责初始化系统并启动所有其他进程。
- **服务管理器**: 它提供了统一的工具来控制、启动、停止、重启和查看服务的状态。
- **系统管理套件**: `systemd` 还包含了日志管理 (`journald`)、网络管理 (`networkd`)、定时任务 (`timers`) 等多种功能。

## 使用 `systemctl` 管理服务

`systemctl` 是与 `systemd` 交互的核心命令。它用于管理服务单元 (service units)。所有这些命令都需要管理员权限 (`sudo`)。

**基本语法**: `sudo systemctl <command> <service_name>`

(我们将以 `nginx` Web 服务器为例，你可以用 `sshd`, `cron` 等任何服务名代替)

### 1. 启动和停止服务
- **`start`**: 启动一个服务。
  ```bash
  sudo systemctl start nginx
  ```
- **`stop`**: 停止一个服务。
  ```bash
  sudo systemctl stop nginx
  ```
- **`restart`**: 重启一个服务（先执行 stop 再执行 start）。
  ```bash
  sudo systemctl restart nginx
  ```
- **`reload`**: 让服务重新加载其配置文件，而无需中断服务。这比 `restart` 更平滑。并非所有服务都支持此操作。
  ```bash
  sudo systemctl reload nginx
  ```

### 2. 设置开机自启
- **`enable`**: 设置服务在系统启动时自动运行。这会创建一个符号链接到相应的 `.target` 目录。
  ```bash
  sudo systemctl enable nginx
  ```
- **`disable`**: 取消服务的开机自启。
  ```bash
  sudo systemctl disable nginx
  ```

### 3. 查看服务状态
- **`status`**: 这是最重要的诊断命令之一。它显示服务是否正在运行、是否开机自启，并会附上最近的几条日志。
  ```bash
  systemctl status nginx

  # 输出示例:
  # ● nginx.service - A high performance web server and a reverse proxy server
  #      Loaded: loaded (/lib/systemd/system/nginx.service; enabled; vendor preset: enabled)
  #      Active: active (running) since Tue 2024-07-16 15:00:00 UTC; 10min ago
  #        Docs: man:nginx(8)
  #    Main PID: 1234 (nginx)
  #       Tasks: 2 (limit: 4662)
  #      Memory: 4.6M
  #         CPU: 15ms
  #      CGroup: /system.slice/nginx.service
  #              ├─1234 /usr/sbin/nginx -g daemon on; master_process on;
  #              └─1235 /usr/sbin/nginx -g daemon on; master_process on;
  ```
  - **Loaded**: `enabled` 表示已设为开机自启。
  - **Active**: `active (running)` 表示服务当前正在运行。如果是 `inactive (dead)` 则表示已停止。`failed` 则表示启动失败。

- **`is-active`**: 快速检查服务是否正在运行。
  ```bash
  systemctl is-active nginx
  # 输出: active
  ```
- **`is-enabled`**: 快速检查服务是否开机自启。
  ```bash
  systemctl is-enabled nginx
  # 输出: enabled
  ```

## 理解 systemd 单元 (Units)

`systemd` 管理的对象被称为"单元 (Unit)"。单元有多种类型，由其文件扩展名定义，例如：
- **`.service`**: 系统服务，这是最常见的单元类型。
- **`.socket`**: 用于套接字激活。`systemd` 可以监听一个网络套接字，当有连接请求时，才启动相应的 `.service`。
- **`.target`**: 用于对单元进行分组。Targets 类似于传统的运行级别 (runlevels)，例如 `multi-user.target` 包含了所有在多用户命令行模式下需要启动的服务。`graphical.target` 则在 `multi-user.target` 的基础上添加了图形界面相关的服务。
- **`.timer`**: 用于定时任务，是 `cron` 的一个强大替代品。你可以创建一个 `.timer` 单元来定义何时运行，并关联一个 `.service` 单元来定义要做什么。

**列出单元文件**:
```bash
# 列出所有已安装的服务单元
systemctl list-unit-files --type=service

# 列出所有正在运行的单元
systemctl list-units
```

单元配置文件通常位于：
- `/lib/systemd/system/`: 由软件包管理器安装的默认单元文件。
- `/etc/systemd/system/`: 系统管理员创建或修改的单元文件。此处的配置会覆盖 `/lib/systemd/system/` 中的同名文件。

## 使用 `journalctl` 查看日志

`systemd` 有自己的日志系统 `journald`，它以二进制格式收集和存储所有系统日志，包括内核日志、服务日志等。`journalctl` 是查询这些日志的工具。

- **查看所有日志 (从旧到新)**:
  ```bash
  journalctl
  ```
- **反向查看日志 (从新到旧)**:
  ```bash
  journalctl -r
  ```
- **实时监控日志**:
  ```bash
  journalctl -f
  ```
- **查看特定服务的日志**:
  这是排查服务问题的关键命令。
  ```bash
  journalctl -u nginx.service
  ```
- **按时间过滤**:
  ```bash
  # 查看今天的日志
  journalctl --since "today"

  # 查看过去一小时的日志
  journalctl --since "1 hour ago"
  ```
- **显示内核日志**:
  类似于 `dmesg` 命令。
  ```bash
  journalctl -k
  ```

通过组合使用 `systemctl` 和 `journalctl`，你可以有效地管理和诊断现代 Linux 系统上的几乎所有后台服务。 