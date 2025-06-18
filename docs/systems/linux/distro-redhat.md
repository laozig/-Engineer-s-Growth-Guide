# 21. 常见发行版: RHEL, Fedora, 和 CentOS/Rocky Linux

Red Hat (红帽) 及其相关社区发行版构成了 Linux 世界中另一大重要的生态系统，广泛应用于企业和服务器环境。

## 家族关系

理解这个家族中各个成员的角色和关系至关重要：

- **Fedora**:
  - **角色**: 上游的、前沿的社区发行版。
  - **特点**: 由社区支持，并得到 Red Hat 的赞助。它是一个快速迭代的发行版，通常每 6 个月发布一个新版本。Fedora 是新技术和新想法的试验场，许多在 Fedora 中经过测试和稳定的特性，最终会被整合到 Red Hat Enterprise Linux (RHEL) 中。它非常适合希望体验最新 Linux 技术的开发者和桌面用户。

- **Red Hat Enterprise Linux (RHEL)**:
  - **角色**: 商业化的、面向企业客户的旗舰产品。
  - **特点**: 基于 Fedora 的一个稳定版本构建。RHEL 以其稳定性、安全性和长期的商业支持（通常长达10年）而闻名。它是需要最高级别可靠性和认证的生产环境（如大型企业、数据中心）的标准。使用 RHEL 需要购买订阅。

- **CentOS / Rocky Linux / AlmaLinux**:
  - **角色**: RHEL 的社区重建版。
  - **历史**: 过去，CentOS 是 RHEL 的下游重建版，目标是与 RHEL 100% 二进制兼容，并免费提供给用户。它成为了许多不需要商业支持但又希望获得 RHEL 稳定性的用户的首选。
  - **现状**: 2020年，CentOS 项目转变为 **CentOS Stream**，其定位从 RHEL 的下游转变为 RHEL 的**上游**（介于 Fedora 和 RHEL 之间）。为了填补 CentOS 留下的空白，原 CentOS 创始人发起了 **Rocky Linux** 项目，另一个社区项目 **AlmaLinux** 也应运而生。这两个发行版都旨在成为 RHEL 的下游重建版，继续扮演传统 CentOS 的角色。

**关系流**: `Fedora` -> `CentOS Stream` -> `RHEL` -> `Rocky Linux / AlmaLinux`

## 核心包管理工具

这个家族使用 RPM (RPM Package Manager) 作为底层包格式，并使用 DNF 或 YUM 作为高级包管理工具。

### `dnf` (Dandified YUM)

DNF 是现代 Fedora、RHEL 8+ 和 CentOS 8+ 中的默认包管理器。它是 YUM 的下一代版本，提供了更好的性能和更可靠的依赖解析。其命令与 `yum` 基本兼容。

```bash
# 更新所有已安装的软件包
sudo dnf update

# 安装一个新软件包
sudo dnf install nginx

# 移除一个软件包
sudo dnf remove nginx

# 搜索一个软件包
dnf search "web server"

# 显示软件包的详细信息
dnf info nginx

# 列出所有已安装的软件包
dnf list installed

# 查看哪个软件包提供了某个文件
dnf provides /etc/nginx/nginx.conf
```

### `yum` (Yellowdog Updater, Modified)
在 RHEL 7 和 CentOS 7 及更早版本中，`yum` 是主要的包管理工具。在较新的系统中，`yum` 命令通常是一个指向 `dnf` 的符号链接，以保持向后兼容。

## `rpm` (RPM Package Manager)

`rpm` 是底层的包管理实用程序，直接与 RPM 数据库和 `.rpm` 文件交互。与 `dpkg` 类似，它不自动处理依赖关系。

```bash
# 查询系统上是否安装了某个包
rpm -q nginx

# 列出某个已安装软件包中的所有文件
rpm -ql nginx

# 验证一个软件包的文件是否被修改过
rpm -V nginx

# 从一个 .rpm 文件中提取信息
rpm -qpi my-package-1.0.0.el8.x86_64.rpm

# 安装一个本地的 .rpm 文件 (不解决依赖)
sudo rpm -ivh my-package-1.0.0.el8.x86_64.rpm
```

## 系统特性

### 网络配置 (`nmcli`)
RHEL 及其衍生版使用 `NetworkManager` 作为标准的网络配置服务。`nmcli` 是其功能强大的命令行客户端。

```bash
# 查看所有网络设备的状态
nmcli device status

# 查看所有活动的网络连接
nmcli connection show

# 启动一个网络连接
sudo nmcli connection up 'Wired connection 1'

# 关闭一个网络连接
sudo nmcli connection down 'Wired connection 1'

# 修改一个连接，将其IP地址设为静态
sudo nmcli connection modify 'Wired connection 1' ipv4.method manual ipv4.addresses 192.168.1.101/24 ipv4.gateway 192.168.1.1
```

### 防火墙 (`firewalld`)
`firewalld` 是这个生态系统中默认的防火墙管理工具。我们在"系统安全"一章中已经详细介绍过。

### 安全 (`SELinux`)
SELinux 是 RHEL 家族安全模型的核心组成部分。它在默认情况下以 `enforcing` 模式启用，为系统提供了强大的强制访问控制。

## 总结
- **Fedora** 是创新的先锋，适合那些希望走在技术前沿的用户。
- **RHEL** 是企业级的黄金标准，提供无与伦比的稳定性和支持。
- **Rocky Linux / AlmaLinux** 继承了传统 CentOS 的衣钵，为社区提供了免费的、与 RHEL 兼容的稳定服务器平台。
- 整个生态系统共享 `dnf`/`yum` 和 `rpm` 作为包管理基础，并深度集成了 `NetworkManager`, `firewalld`, 和 `SELinux`，构成了一个健壮而安全的服务器环境。 