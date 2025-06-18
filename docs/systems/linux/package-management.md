# 9. 软件包管理

软件包管理器是 Linux 系统中用于自动化安装、升级、配置和删除软件包的工具集。它极大地简化了软件管理，解决了依赖关系问题，并确保了系统上软件来源的一致性和安全性。

几乎每个 Linux 发行版都有自己的包管理器。本章将介绍几个最主流的包管理系统。所有这些命令通常都需要管理员权限（使用 `sudo`）。

## 1. Debian, Ubuntu 及其衍生版: APT

APT (Advanced Package Tool) 是 Debian 系列发行版（包括 Ubuntu, Mint 等）使用的包管理系统。现代的 `apt` 命令整合了传统 `apt-get` 和 `apt-cache` 的功能，并提供了更友好的用户界面。

### 常用 `apt` 命令

- **更新软件包列表**:
  在安装或升级任何软件之前，你都应该先运行此命令。它会从配置的软件源（在 `/etc/apt/sources.list` 中定义）下载最新的软件包信息，但不会实际升级任何软件。
  ```bash
  sudo apt update
  ```

- **升级已安装的软件包**:
  将系统上所有已安装的软件包升级到最新版本。
  ```bash
  sudo apt upgrade
  ```

- **安装新软件包**:
  ```bash
  sudo apt install nginx
  ```

- **卸载软件包**:
  - `remove`: 只卸载软件包本身，但保留其配置文件。
  ```bash
  sudo apt remove nginx
  ```
  - `purge`: 卸载软件包及其所有配置文件。
  ```bash
  sudo apt purge nginx
  ```

- **搜索软件包**:
  在所有可用软件包的名称和描述中搜索关键词。
  ```bash
  apt search "web server"
  ```

- **查看软件包信息**:
  显示软件包的详细信息，如版本、依赖关系、大小和描述。
  ```bash
  apt show nginx
  ```

- **清理系统**:
  `autoremove` 用于删除为满足其他软件包的依赖关系而自动安装，但现在已不再需要的软件包。
  ```bash
  sudo apt autoremove
  ```

## 2. Red Hat, Fedora, CentOS: YUM 和 DNF

YUM (Yellowdog Updater, Modified) 是 Red Hat 系列发行版（RHEL, CentOS）中历史悠久的包管理器。DNF (Dandified YUM) 是 YUM 的下一代版本，自 Fedora 22 和 RHEL 8 起成为默认包管理器。DNF 解决了 YUM 的一些性能和依赖解析问题，其命令基本与 YUM 兼容。

### 常用 `dnf` / `yum` 命令

(在现代系统中推荐使用 `dnf`。如果系统较旧，可以将 `dnf` 替换为 `yum`)

- **升级所有软件包**:
  与 `apt` 不同，`update` 或 `upgrade` 都会实际升级软件包。
  ```bash
  sudo dnf upgrade
  # 或者
  sudo yum update
  ```

- **安装新软件包**:
  ```bash
  sudo dnf install httpd
  ```

- **卸载软件包**:
  ```bash
  sudo dnf remove httpd
  ```

- **搜索软件包**:
  ```bash
  dnf search "web server"
  ```

- **查看软件包信息**:
  ```bash
  dnf info httpd
  ```

- **查看软件包依赖**:
  ```bash
  dnf deplist httpd
  ```

- **列出已安装的软件包**:
  ```bash
  dnf list installed
  ```

- **清理系统**:
  删除不再需要的依赖包。
  ```bash
  sudo dnf autoremove
  ```

## 3. Arch Linux: Pacman

Pacman 是 Arch Linux 及其衍生版（如 Manjaro）的包管理器。它以其简洁、快速和强大的依赖解析能力而闻名。Pacman 的命令选项与其他包管理器有很大不同，通常是单个大写字母。

### 常用 `pacman` 命令

- **同步并升级系统**:
  `-S` 表示同步 (sync)，`-y` 表示更新本地包数据库，`-u` 表示升级 (upgrade) 过时的包。这三个通常一起使用。
  ```bash
  sudo pacman -Syu
  ```

- **安装新软件包**:
  ```bash
  # 从官方源安装
  sudo pacman -S nginx
  # 从本地文件安装（例如从 AUR 手动构建的包）
  sudo pacman -U package-name.pkg.tar.zst
  ```

- **卸载软件包**:
  - `-R`: 移除软件包，但保留其依赖。
  ```bash
  sudo pacman -R nginx
  ```
  - `-Rs`: 移除软件包及其不再被任何其他已安装软件包所需要的依赖。
  ```bash
  sudo pacman -Rs nginx
  ```
  - `-Rsn`: 移除软件包、其依赖和所有系统级的配置文件。
  ```bash
  sudo pacman -Rsn nginx
  ```

- **搜索软件包**:
  在远程仓库中搜索。
  ```bash
  pacman -Ss "web server"
  ```
  在已安装的包中搜索。
  ```bash
  pacman -Qs "web server"
  ```

- **查看软件包信息**:
  `-i` 显示详细信息，`-l` 显示包内文件列表。
  ```bash
  pacman -Si nginx  # 查看远程仓库中的包信息
  pacman -Qi nginx  # 查看已安装的包信息
  pacman -Ql nginx  # 列出 nginx 包安装的文件
  ```

- **清理系统**:
  清理未被安装的软件包的缓存 (`/var/cache/pacman/pkg/`)。
  ```bash
  # 只清理未安装的包
  sudo pacman -Sc
  # 清理所有缓存，这会释放大量空间
  sudo pacman -Scc
  ```

## 总结

| 任务 | `apt` (Debian/Ubuntu) | `dnf`/`yum` (Fedora/CentOS) | `pacman` (Arch) |
| :--- | :--- | :--- | :--- |
| **更新包列表** | `sudo apt update` | (集成在升级命令中) | `sudo pacman -Sy` |
| **升级系统** | `sudo apt upgrade` | `sudo dnf upgrade` | `sudo pacman -Syu` |
| **安装包** | `sudo apt install <pkg>` | `sudo dnf install <pkg>` | `sudo pacman -S <pkg>` |
| **卸载包** | `sudo apt remove <pkg>` | `sudo dnf remove <pkg>` | `sudo pacman -R <pkg>` |
| **卸载包+依赖**| `sudo apt autoremove` | `sudo dnf autoremove` | `sudo pacman -Rs <pkg>` |
| **搜索包** | `apt search <term>` | `dnf search <term>` | `pacman -Ss <term>` |
| **包信息** | `apt show <pkg>` | `dnf info <pkg>` | `pacman -Si <pkg>` |

</rewritten_file> 