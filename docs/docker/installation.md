# 2. 安装 Docker

在本章中，我们将在几个主流的操作系统上安装 Docker。Docker 官方提供了对 Linux、Windows 和 macOS 的良好支持。

## 准备工作

在开始安装之前，请确保你的系统满足基本要求：
- **64位操作系统**: Docker 需要 64 位的 CPU 架构。
- **虚拟化支持**: 对于 Windows 和 macOS，需要在 BIOS/UEFI 中启用硬件虚拟化技术 (Intel VT-x 或 AMD-V)。

## 在 Linux 上安装

在 Linux 上，我们通常安装 **Docker Engine**，这是 Docker 的核心运行时。官方推荐使用 Docker 的官方 `apt` 或 `yum`/`dnf` 仓库进行安装，以确保你获取的是最新版本。

### 在 Ubuntu 上安装
这是最常见的 Linux 安装场景之一。

**1. 卸载旧版本 (如果存在)**
```bash
sudo apt-get remove docker docker-engine docker.io containerd runc
```

**2. 设置 Docker 的 APT 仓库**
```bash
# 更新 apt 包索引并安装依赖
sudo apt-get update
sudo apt-get install \
    ca-certificates \
    curl \
    gnupg

# 添加 Docker 的官方 GPG 密钥
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# 设置仓库源
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

**3. 安装 Docker Engine**
```bash
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
`docker-ce` 是社区版 (Community Edition)，免费使用。

**4. (推荐) 创建 `docker` 组以管理 Docker**
默认情况下，`docker` 命令需要 `sudo` 权限。为了避免每次都输入 `sudo`，你可以将当前用户添加到 `docker` 用户组。
```bash
# 创建 docker 组 (如果它还不存在)
sudo groupadd docker

# 将你的用户添加到 docker 组
sudo usermod -aG docker $USER

# 激活组更改 (你需要注销并重新登录才能生效)
newgrp docker
```
**警告**: 将用户添加到 `docker` 组授予的权限等同于 `root` 权限。请了解其安全影响。

### 在 CentOS / Fedora / RHEL 上安装
对于基于 RPM 的发行版，过程类似，只是使用的是 `dnf` (或 `yum`)。
```bash
# 卸载旧版本
sudo dnf remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-engine

# 设置仓库
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# 安装 Docker Engine
sudo dnf install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
之后同样需要启动 Docker 服务并设置用户组。

## 在 Windows 上安装

在 Windows 上，我们安装 **Docker Desktop for Windows**。它是一个图形化的应用程序，捆绑了 Docker Engine、命令行工具、Docker Compose 等。

**核心依赖: WSL 2 (Windows Subsystem for Linux 2)**
- Docker Desktop for Windows 不再使用旧的 Hyper-V 后端，而是利用 WSL 2 在 Windows 内部运行一个真正的 Linux 内核。
- 这带来了巨大的性能提升和 100% 的 Linux 容器兼容性。

**安装步骤**:
1.  **确保你的 Windows 系统支持 WSL 2**:
    - 你需要 Windows 10 版本 2004 或更高版本，或者 Windows 11。
    - 在 BIOS 中启用虚拟化。
2.  **安装 WSL**: 打开 PowerShell (以管理员身份) 并运行：
    ```powershell
    wsl --install
    ```
    这会自动安装 WSL 和默认的 Ubuntu 发行版。
3.  **下载并安装 Docker Desktop**:
    - 访问 [Docker 官方网站](https://www.docker.com/products/docker-desktop/)。
    - 下载适用于 Windows 的安装程序。
    - 双击 `.exe` 文件并按照图形界面提示进行安装。在安装过程中，确保勾选了 "Use WSL 2 instead of Hyper-V"。
4.  **启动 Docker Desktop**: 安装完成后，从开始菜单启动 Docker Desktop。第一次启动可能需要一些时间来配置 WSL 2 集成。

## 在 macOS 上安装

与 Windows 类似，在 macOS 上我们安装 **Docker Desktop for Mac**。

**安装步骤**:
1.  **下载 Docker Desktop**:
    - 访问 [Docker 官方网站](https://www.docker.com/products/docker-desktop/)。
    - 根据你的 Mac 芯片类型，下载适用于 **Apple Silicon (M1/M2/M3)** 或 **Intel Chip** 的安装程序。
2.  **安装**:
    - 双击下载的 `.dmg` 文件。
    - 将 Docker 图标拖动到 "Applications" 文件夹中。
3.  **启动 Docker Desktop**: 从 "Applications" 文件夹中启动 Docker。你可能需要授权其一些系统权限。

## 安装后验证

无论在哪种操作系统上安装，最后的验证步骤都是相同的。打开你的终端 (Terminal, PowerShell, or CMD) 并运行以下命令：

**1. 检查 Docker 版本**
```bash
docker --version
```
你应该会看到 Docker 的版本信息，例如 `Docker version 24.0.5, build 24.0.5-0ubuntu1~22.04.1`。

**2. 运行 "Hello World" 容器**
这是测试 Docker 是否能正常拉取镜像并运行容器的最终方法。
```bash
docker run hello-world
```
如果一切正常，你会看到一条欢迎信息，其中解释了这条命令执行的步骤：
1.  Docker 客户端联系了 Docker 守护进程。
2.  守护进程在本地没有找到 "hello-world" 镜像。
3.  守护进程从 Docker Hub 拉取了 "hello-world" 镜像。
4.  守护进程从该镜像创建了一个新容器。
5.  守护进程运行了容器，容器输出了欢迎信息，然后退出。

看到这条消息，就意味着你的 Docker 环境已经准备就绪！ 