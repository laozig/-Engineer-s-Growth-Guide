# 20. 常见发行版: Debian 与 Ubuntu

Debian 和 Ubuntu 是世界上最流行和最有影响力的两个 Linux 发行版。Ubuntu 基于 Debian 构建，两者共享大量的底层工具和设计哲学，但也存在关键差异。

## 1. Debian

Debian 项目始于 1993 年，是现存最古老的 Linux 发行版之一。它完全由一个充满激情的志愿者社区维护，并以其对自由软件的坚定承诺、可靠性和稳定性而闻名。

### Debian 的哲学
- **《Debian 社会契约》**: 定义了项目的核心价值观，其中最重要的是承诺 Debian 将始终保持 100% 的自由软件。
- **稳定性优先**: Debian 的 `stable` (稳定版) 以其极其稳定而著称，这得益于其漫长而严格的测试周期。这使得 Debian 成为服务器的绝佳选择。

### Debian 的版本
Debian 同时维护着至少三个版本：
- **`stable` (稳定版)**: 当前的官方发行版。软件包版本可能不是最新的，但都经过了广泛的测试，非常可靠。
- **`testing` (测试版)**: 下一个稳定版的候选版本。包含了比 `stable`更新的软件包，但尚未被认为可以正式发布。许多桌面用户偏爱此版本，以在稳定性和新特性之间取得平衡。
- **`unstable` (不稳定版, 代号 "Sid")**: 软件包的滚动开发版本。新包会先进入 `unstable`，经过一段时间的测试后，才会迁移到 `testing`。

## 2. Ubuntu

Ubuntu 由 Canonical 公司于 2004 年首次发布。它的目标是为桌面用户和开发者提供一个易于使用、功能全面且始终保持最新的 Linux 系统。

### Ubuntu 与 Debian 的关系
- **基于 Debian**: Ubuntu 的每个版本都基于 Debian `unstable` 的一个快照构建。它从 Debian 导入了大量的软件包，并在此基础上进行修改和添加自己的特性。
- **易用性**: Ubuntu 投入了大量精力来改善用户体验，例如开发了友好的安装程序、默认配置和图形化管理工具。
- **发布周期**: Ubuntu 有一个可预测的、固定的发布周期。
  - **标准版**: 每六个月发布一次（4月和10月）。
  - **LTS (长期支持) 版**: 每两年发布一次（在偶数年的4月）。LTS 版本是企业和大规模部署的首选，因为它们提供长达 5 年的免费安全更新和支持。

## 核心包管理工具

Debian 和 Ubuntu 都使用 APT (Advanced Package Tool) 包管理系统。

### `apt` (推荐)
`apt` 是一个功能丰富的命令行工具，它结合了 `apt-get` 和 `apt-cache` 中最常用的功能，并提供了更友好的输出格式和进度条。

```bash
# 更新可用软件包列表
sudo apt update

# 升级所有已安装的软件包
sudo apt upgrade

# 安装一个新软件包
sudo apt install nginx

# 移除一个软件包
sudo apt remove nginx

# 移除软件包及其配置文件
sudo apt purge nginx

# 自动移除不再需要的依赖包
sudo apt autoremove

# 搜索一个软件包
apt search "web server"

# 显示软件包的详细信息
apt show nginx
```

### `apt-get` 与 `apt-cache`
在 `apt` 命令出现之前，这些是主要的交互工具。
- `apt-get`: 用于安装、升级和移除软件包 (`install`, `upgrade`, `remove`, `purge`)。
- `apt-cache`: 用于查询和搜索软件包 (`search`, `show`, `policy`)。
虽然现在推荐使用 `apt`，但了解它们对于阅读旧的文档和脚本仍然很有用。

## `dpkg` (Debian Package Manager)

`dpkg` 是 APT 系统底层的包管理工具。它直接处理 `.deb` 文件。通常你不会直接使用 `dpkg` 来从仓库安装软件（因为它不处理依赖关系），但它对于手动安装本地的 `.deb` 文件或检查已安装的软件包很有用。

```bash
# 安装一个本地的 .deb 文件
# 注意：这不会自动安装依赖！
sudo dpkg -i my-package_1.0.0_amd64.deb

# 列出系统上所有与 "nginx" 相关的包
dpkg -l | grep nginx

# 查看哪个软件包拥有 /etc/nginx/nginx.conf 文件
dpkg -S /etc/nginx/nginx.conf

# 移除一个软件包（不处理依赖）
sudo dpkg -r nginx
```

## 网络配置

- **传统方式**: 传统的 Debian/Ubuntu 系统使用 `/etc/network/interfaces` 文件来静态配置网络。
- **Netplan (Ubuntu)**: 从 Ubuntu 17.10 开始，默认使用 Netplan 进行网络配置。Netplan 使用 YAML 文件来描述网络接口，然后它会为后端（如 `systemd-networkd` 或 `NetworkManager`）生成相应的配置文件。
  - 配置文件位于 `/etc/netplan/`。
  - 使用 `sudo netplan apply` 来应用配置。

**Netplan 配置示例 (`/etc/netplan/01-netcfg.yaml`)**:
```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      dhcp4: true
    enp0s8:
      dhcp4: no
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
```

## 总结
- **Debian** 是一个稳定、可靠、由社区驱动的通用操作系统，是许多其他发行版（包括 Ubuntu）的基石。
- **Ubuntu** 在 Debian 的基础上，专注于为桌面和云端用户提供一个更现代、更易用的体验，并拥有强大的商业支持。
- 两者共享强大的 `apt` 和 `dpkg` 包管理系统，使得软件管理变得非常高效。 