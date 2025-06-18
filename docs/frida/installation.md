# Frida 安装指南

本文档提供了在不同操作系统上安装和配置Frida的详细说明。

## 目录
- [系统要求](#系统要求)
- [Windows安装](#windows安装)
- [macOS安装](#macos安装)
- [Linux安装](#linux安装)
- [Android设置](#android设置)
- [iOS设置](#ios设置)
- [故障排除](#故障排除)

## 系统要求

使用Frida前，请确保您的系统满足以下要求：

- Python 3.6+（推荐使用最新版本）
- pip（Python包管理器）
- 对于Android设备：Android 5.0+，需要启用USB调试或root权限
- 对于iOS设备：越狱设备或使用开发者证书的设备

## Windows安装

### 安装Python和Frida

1. 首先，从[Python官网](https://www.python.org/downloads/windows/)下载并安装Python（确保勾选"Add Python to PATH"选项）。

2. 打开命令提示符(CMD)或PowerShell，运行以下命令安装Frida：

   ```powershell
   pip install frida-tools
   ```

3. 验证安装是否成功：

   ```powershell
   frida --version
   ```

### 针对Windows目标程序

如果您想要分析Windows应用程序，通常不需要额外设置，只需使用以下命令列出可用进程：

```powershell
frida-ps
```

## macOS安装

1. 安装Homebrew（如果尚未安装）：

   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
   ```

2. 安装Python：

   ```bash
   brew install python
   ```

3. 安装Frida：

   ```bash
   pip3 install frida-tools
   ```

4. 验证安装：

   ```bash
   frida --version
   ```

## Linux安装

对于大多数Linux发行版：

1. 安装Python和pip：

   ```bash
   # Debian/Ubuntu
   sudo apt update
   sudo apt install python3 python3-pip
   
   # Fedora
   sudo dnf install python3 python3-pip
   
   # Arch Linux
   sudo pacman -S python python-pip
   ```

2. 安装Frida：

   ```bash
   pip3 install frida-tools
   ```

3. 验证安装：

   ```bash
   frida --version
   ```

## Android设置

要在Android设备上使用Frida，需要在Android设备上设置frida-server：

1. 确保您的Android设备已启用USB调试并已连接到计算机。

2. 确定您的设备架构：

   ```bash
   adb shell getprop ro.product.cpu.abi
   ```

3. 根据设备架构从[Frida GitHub发布页面](https://github.com/frida/frida/releases)下载适当版本的frida-server。

4. 将frida-server推送到Android设备：

   ```bash
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   ```

5. 在Android设备上运行frida-server：

   ```bash
   adb shell "/data/local/tmp/frida-server &"
   ```

6. 在您的电脑上验证连接：

   ```bash
   frida-ps -U
   ```

   此命令应列出您Android设备上运行的所有进程。

## iOS设置

### 对于越狱设备

1. 在iOS设备上添加Frida库源：

   打开Cydia，添加以下源：`https://build.frida.re`

2. 安装Frida包：

   在Cydia中搜索并安装"Frida"。

3. 在电脑上安装frida-tools：

   ```bash
   pip install frida-tools
   ```

4. 验证连接：

   ```bash
   frida-ps -U
   ```

### 对于非越狱设备

需要使用开发者证书重新签名应用程序并注入Frida库：

1. 安装必要工具：

   ```bash
   pip install frida-tools
   npm install -g applesign
   ```

2. 下载目标应用的IPA文件。

3. 使用frida-ios-dump等工具重新签名并注入Frida：
   具体步骤请参考[frida-ios-dump文档](https://github.com/AloneMonkey/frida-ios-dump)。

## 故障排除

### 常见问题

1. **"frida-server is not running"错误**
   - 确保frida-server在目标设备上运行
   - 检查USB连接
   - 确认设备架构与frida-server版本匹配

2. **"Failed to enumerate processes"错误**
   - 检查设备连接
   - 确认frida-server版本与frida-tools版本兼容

3. **Windows环境变量问题**
   - 确保Python和pip已添加到PATH环境变量中

### 版本兼容性

始终确保您的frida-tools和frida-server版本兼容。通常，它们应该是相同版本。您可以使用以下命令查看frida-tools版本：

```bash
pip show frida-tools
```

### 更新Frida

定期更新Frida以获取最新功能和bug修复：

```bash
pip install --upgrade frida-tools
```

同时，记得更新设备上的frida-server版本。

---

如果您在安装或设置过程中遇到任何问题，请查看[官方文档](https://frida.re/docs/installation/)或在[GitHub Issues](https://github.com/frida/frida/issues)中寻求帮助。 