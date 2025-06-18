# 17. 日志管理

日志是记录系统、服务和应用程序运行过程中发生的事件的文本文件。它们对于监控系统状态、诊断问题、审计安全事件和理解系统行为至关重要。有效的日志管理是任何一位系统管理员的核心职责。

## 核心日志管理系统

现代 Linux 系统通常结合使用两种主要的日志记录机制：`journald` 和 `rsyslog`。

### 1. `journald` (由 systemd 提供)

`journald` 是 `systemd` 的一个组件，它以结构化的、带索引的二进制格式从所有来源（内核、系统服务、应用程序等）收集日志数据。

**`journalctl` 进阶用法**

我们在"服务管理"一章中已经介绍了 `journalctl` 的基本用法，这里是一些更高级的查询技巧：

- **按优先级过滤**:
  `journalctl` 使用标准的 syslog 消息级别。
  - `0`: emerg (紧急)
  - `1`: alert (警报)
  - `2`: crit (严重)
  - `3`: err (错误)
  - `4`: warning (警告)
  - `5`: notice (通知)
  - `6`: info (信息)
  - `7`: debug (调试)

  ```bash
  # 只显示错误及更高级别的日志
  sudo journalctl -p err

  # 显示从 warning 到 critical 级别的日志
  sudo journalctl -p warning..crit
  ```

- **查看特定可执行文件的日志**:
  ```bash
  sudo journalctl /usr/sbin/nginx
  ```

- **查看特定进程的日志**:
  ```bash
  sudo journalctl _PID=1234
  ```

- **查看特定用户的日志**:
  ```bash
  sudo journalctl _UID=1000
  ```

- **控制输出格式**:
  ```bash
  # 以 JSON 格式输出，便于机器解析
  sudo journalctl -o json-pretty
  ```

- **管理日志存储**:
  `journald` 的日志默认存储在 `/run/log/journal/` (非持久化) 或 `/var/log/journal/` (持久化)。你可以通过编辑 `/etc/systemd/journald.conf` 来配置其行为。
  ```bash
  # 查看当前磁盘使用量
  sudo journalctl --disk-usage

  # 限制日志大小为 500M
  sudo journalctl --vacuum-size=500M

  # 只保留过去两周的日志
  sudo journalctl --vacuum-time=2weeks
  ```

### 2. `rsyslog` (传统的 syslog 实现)

`rsyslog` 是一个非常强大和高度可配置的传统日志记录系统。在许多系统中，`journald` 会将其接收到的日志转发给 `rsyslog`，由 `rsyslog` 将它们以纯文本格式写入到 `/var/log` 目录下的各种文件中。

- **配置文件**: `/etc/rsyslog.conf` 和 `/etc/rsyslog.d/` 目录下的文件定义了日志处理规则。
- **规则格式**: `facility.priority action`
  - **Facility (来源设施)**: 内核 (`kern`), 用户进程 (`user`), 邮件 (`mail`), 认证 (`authpriv`) 等。
  - **Priority (优先级)**: `info`, `notice`, `warn`, `err`, `crit` 等。
  - **Action (动作)**: 要将日志消息发送到哪里，通常是一个文件路径。

**`/etc/rsyslog.conf` 规则示例**:
```
# 将所有 info 或更高级别的消息记录到 /var/log/messages，但邮件、认证和cron除外
*.info;mail.none;authpriv.none;cron.none                /var/log/messages

# 将所有认证相关的消息记录到 /var/log/secure
authpriv.*                                              /var/log/secure

# 将所有邮件相关的消息记录到 /var/log/maillog
mail.*                                                  -/var/log/maillog
```
前面的 `-` 表示异步写入，可以提高性能。

## `logrotate` - 日志轮转

日志文件会随着时间的推移不断增长，如果不加以管理，它们会耗尽所有磁盘空间。`logrotate` 是一个用于自动轮转、压缩、删除和邮寄日志文件的工具。

- **主配置文件**: `/etc/logrotate.conf`
- **应用特定配置**: `/etc/logrotate.d/` 目录下的文件。软件包通常会在这里为自己的日志文件放置一个配置文件。

**`/etc/logrotate.d/nginx` 示例**:
```
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 nginx adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 `cat /var/run/nginx.pid`
        fi
    endscript
}
```
- `daily`: 每天轮转一次。
- `rotate 14`: 保留 14 份旧的日志文件。
- `compress`: 使用 gzip 压缩旧的日志文件。
- `delaycompress`: 推迟到下一次轮转时再压缩，确保当前日志周期内程序可以继续写入旧文件。
- `missingok`: 如果日志文件不存在，不要报错。
- `notifempty`: 如果日志文件为空，则不进行轮转。
- `create`: 创建新的空日志文件，并设置权限和所有权。
- `postrotate`/`endscript`: 在轮转完成后执行的脚本（这里是通知 nginx 重新打开其日志文件）。

## 常见的日志文件位置 (`/var/log`)

- `/var/log/syslog` 或 `/var/log/messages`: 全局系统日志，记录了从系统启动到关闭的大部分事件。
- `/var/log/auth.log` 或 `/var/log/secure`: 用户登录和认证相关的日志。
- `/var/log/kern.log`: 内核日志。
- `/var/log/dmesg`: 系统启动信息。
- `/var/log/boot.log`: 系统启动过程的日志。
- `/var/log/apt/` (Debian/Ubuntu) 或 `/var/log/dnf.log` (Fedora/CentOS): 软件包管理器相关的日志。
- `/var/log/nginx/`, `/var/log/httpd/`: Web 服务器日志。

熟练地查看和分析日志是系统管理员排查问题的核心能力。了解 `journalctl`, `rsyslog` 和 `logrotate` 的协同工作方式，将使你能够有效地管理任何 Linux 系统的日志。 