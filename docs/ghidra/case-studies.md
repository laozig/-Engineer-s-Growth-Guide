# Ghidra 实战案例研究

本文档通过四个详细的实际案例展示如何使用Ghidra进行不同类型的软件分析，从基础入门到高级应用，覆盖多种常见分析场景。

## 案例一：恶意软件分析

### 目标：分析Windows恶意软件样本

#### 恶意软件背景

样本是一个疑似窃取凭证的Windows恶意软件，具有以下特性：
- 文件大小：324KB
- 格式：Windows PE可执行文件
- 混淆级别：中等
- 可能行为：数据窃取、持久化安装

#### 分析步骤

##### 1. 初始设置与导入

1. 创建隔离项目
   ```
   项目名称：MalwareAnalysis_Sample1
   项目类型：非共享项目
   ```

2. 导入PE文件
   ```
   文件 > 导入文件 > 选择恶意样本
   语言：x86:LE:32:default
   分析选项：启用基本分析
   ```

3. 初始分析配置
   - 启用字符串搜索
   - 启用函数识别
   - 启用引用识别
   - 禁用耗时分析器

##### 2. 识别反分析技术

1. 检查导入表
   ```
   IsDebuggerPresent, GetTickCount, QueryPerformanceCounter
   ```
   这些API通常用于反调试和虚拟机检测

2. 分析可疑代码段
   ```c
   // 反调试代码示例
   if (IsDebuggerPresent()) {
       ExitProcess(0);
   }
   
   // 时间检测（沙箱逃避）
   DWORD start_time = GetTickCount();
   Sleep(2000);
   if (GetTickCount() - start_time < 1500) {
       return FALSE; // 虚拟环境检测
   }
   ```

3. 发现字符串解密例程
   - 找到包含大量赋值操作的函数
   - 识别出XOR解密循环
   - 编写脚本解密所有字符串

##### 3. 关键功能分析

1. 入口点分析
   ```
   入口点地址：0x00401290
   初始化函数：sub_401320
   主要处理函数：sub_402510
   ```

2. 网络通信分析
   - 发现使用WinINet API
   - 提取硬编码URL和地址
   - 分析通信协议和数据格式

3. 持久化机制
   ```c
   // 注册表持久化示例
   HKEY hKey;
   RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
   RegSetValueEx(hKey, "SystemService", 0, REG_SZ, (BYTE*)filepath, strlen(filepath));
   RegCloseKey(hKey);
   ```

##### 4. 数据窃取功能

1. 浏览器凭证窃取
   - 分析访问Chrome、Firefox配置文件的代码
   - 识别SQLite数据库访问逻辑
   - 追踪凭证提取和处理流程

2. 键盘钩子分析
   ```c
   // 键盘钩子安装简化代码
   HHOOK hook = SetWindowsHookEx(
       WH_KEYBOARD_LL,
       KeyboardProc,
       GetModuleHandle(NULL),
       0
   );
   ```

3. 凭证处理与泄露
   - 字符串处理和格式化
   - 数据加密（使用RC4算法）
   - 网络传输方法

##### 5. 分析结论

对该恶意软件的分析揭示：
- 通过注册表实现持久化
- 使用基本反调试和沙箱检测技术
- 窃取多个浏览器的存储凭证
- 使用键盘记录器捕获额外凭证
- 加密数据并发送到远程C2服务器

### 分析技术与Ghidra特性

1. **使用的Ghidra功能**
   - 自动分析引擎识别基本功能结构
   - 反编译器揭示高级代码逻辑
   - 字符串搜索定位关键内容
   - 交叉引用跟踪关键API使用
   - 数据类型重构（用于网络数据包）

2. **关键分析技巧**
   - 使用函数调用图识别代码结构
   - 通过内存引用识别配置数据
   - 使用批注记录分析发现
   - 编写Python脚本解密字符串

## 案例二：固件分析与漏洞研究

### 目标：分析IoT设备固件并识别安全漏洞

#### 固件背景

- 设备：网络连接智能家居控制器
- 架构：ARM Cortex-M4
- 固件大小：4.2MB
- 文件格式：原始二进制镜像

#### 分析步骤

##### 1. 固件提取与导入

1. 获取原始固件
   ```
   binwalk -e firmware.bin
   ```

2. 在Ghidra中导入
   ```
   语言：ARM:LE:32:v7
   基址：0x08000000（Flash起始地址）
   ```

3. 扫描引导加载程序和主固件边界
   - 识别向量表位置
   - 定位引导加载程序
   - 标记固件区段

##### 2. 识别系统组件

1. 定位操作系统代码
   ```
   FreeRTOS关键函数：
   - xTaskCreate
   - vTaskDelay
   - xQueueReceive
   ```

2. 识别驱动程序和硬件接口
   - UART驱动
   - 网络控制器
   - Flash存储接口

3. 映射任务和线程
   ```c
   // 任务创建示例
   xTaskCreate(
       NetworkTask,        // 任务函数
       "NET",              // 任务名称
       256,                // 栈大小
       NULL,               // 参数
       2,                  // 优先级
       &xNetTaskHandle     // 任务句柄
   );
   ```

##### 3. 网络协议分析

1. 识别网络协议处理器
   - TCP/IP栈定位
   - HTTP请求处理函数
   - WebSocket实现

2. 认证机制分析
   ```c
   // 简化的认证验证函数
   int verify_auth_token(char *token) {
       // 硬编码比较 - 安全漏洞
       if (strcmp(token, "admin_secure_token123") == 0) {
           return 1;
       }
       return 0;
   }
   ```

3. 命令处理功能
   - 识别命令解析器
   - 权限检查逻辑
   - 命令执行流程

##### 4. 漏洞识别

1. 缓冲区溢出漏洞
   ```c
   // 有漏洞的代码
   void process_request(char *input) {
       char buffer[64];
       strcpy(buffer, input); // 无边界检查
       // 处理buffer内容
   }
   ```

2. 硬编码凭证
   - 发现多个硬编码密码和密钥
   - 标识使用这些凭证的功能

3. 命令注入漏洞
   ```c
   // 简化的命令处理函数
   void execute_command(char *cmd) {
       char command[128];
       sprintf(command, "system %s", cmd); // 命令注入
       system(command);
   }
   ```

##### 5. 漏洞验证与影响

1. 缓冲区溢出
   - 可利用输入大于64字节触发
   - 可能导致代码执行
   - 影响设备控制流程

2. 硬编码凭证
   - 允许绕过认证
   - 可远程访问管理接口
   - 可获取完全设备控制权

3. 命令注入
   - 可通过网络接口触发
   - 允许执行任意系统命令
   - 可完全控制设备

##### 6. 分析结论

- 发现三个严重安全漏洞
- 所有漏洞都可远程利用
- 推荐缓解措施包括输入验证、移除硬编码凭证、实现命令参数过滤

### 分析技术与Ghidra特性

1. **使用的Ghidra功能**
   - 内存映射工具定位固件段
   - 自动识别常见库函数
   - 数据类型恢复用于协议解析
   - 反编译揭示漏洞代码模式

2. **关键分析技巧**
   - 使用批处理分析大型固件
   - 创建自定义ARM处理器定义
   - 使用引用跟踪定位关键函数
   - 应用数据流分析识别漏洞

## 案例三：专有算法提取分析

### 目标：逆向工程专有加密算法

#### 目标软件背景

- 商业数据保护应用程序
- 使用自定义加密算法
- 平台：Windows 64位
- 目标：提取核心加密算法进行安全评估

#### 分析步骤

##### 1. 定位加密组件

1. 导入目标DLL
   ```
   语言：x86:LE:64:default
   分析选项：默认分析，启用高级指令模式
   ```

2. 搜索加密指标
   - 常见加密常量（如S-box值）
   - 数学位运算指令集中区域
   - 熵计算和操作

3. 通过API调用定位
   ```c
   // 通过Windows加密API调用找到加密实现
   CryptGenRandom(hProv, 16, iv);  // 生成初始化向量
   // 自定义加密函数可能在附近
   custom_encrypt(data, len, key, iv);
   ```

##### 2. 分析核心加密算法

1. 识别算法结构
   - 确定块大小（128位）
   - 识别轮函数模式
   - 分析密钥扩展例程

2. 密钥处理分析
   ```c
   // 密钥扩展示例
   void expand_key(uint8_t *key, uint32_t *round_keys) {
       // 初始赋值
       memcpy(round_keys, key, 16);
       
       // 轮密钥生成
       for (int i = 4; i < 44; i++) {
           uint32_t temp = round_keys[i-1];
           if (i % 4 == 0) {
               // 常见的密钥调度操作
               temp = SubWord(RotWord(temp)) ^ Rcon[i/4];
           }
           round_keys[i] = round_keys[i-4] ^ temp;
       }
   }
   ```

3. 轮函数分析
   - 替换操作（类似S-box）
   - 置换或移位操作
   - 线性混合层（如MixColumns）

##### 3. 算法特性识别

1. 使用的操作类型
   - 字节替换表（自定义S-box）
   - 位移和循环移位
   - XOR操作
   - 表格查询优化

2. 与已知算法比较
   - 结构类似AES但修改了S-box
   - 轮数增加到16轮
   - 添加额外的混淆步骤

3. 算法弱点分析
   - 密钥扩展可能不均匀
   - 发现S-box存在线性特性
   - 轮函数缺乏足够非线性

##### 4. 算法实现提取

1. 重建核心算法结构
   ```c
   // 简化的算法结构
   void custom_encrypt(uint8_t *data, uint8_t *key) {
       uint32_t round_keys[60];
       expand_key(key, round_keys);
       
       // 初始轮密钥加
       add_round_key(data, round_keys);
       
       // 主要加密轮
       for (int round = 1; round < 16; round++) {
           sub_bytes(data);
           shift_rows(data);
           mix_columns(data);
           add_round_key(data, round_keys + round * 4);
       }
       
       // 最后一轮(无mix_columns)
       sub_bytes(data);
       shift_rows(data);
       add_round_key(data, round_keys + 16 * 4);
   }
   ```

2. 构建S-box和常量表
   - 提取替换表
   - 记录任何特殊常量
   - 记录密钥扩展常量

##### 5. 评估算法安全性

1. 分析加密强度
   - 与标准算法比较
   - 评估可能的攻击向量
   - 估计密钥空间和复杂性

2. 识别潜在弱点
   - 轮密钥生成中的问题
   - 非线性层的弱点
   - 可能的侧信道攻击点

3. 安全建议
   - 使用标准加密算法替代
   - 如需保留，建议改进的方向
   - 加强密钥管理方面

##### 6. 分析结论

- 算法是AES的修改变种
- 安全性低于标准AES
- 密钥扩展存在线性问题
- 建议迁移到标准加密算法

### 分析技术与Ghidra特性

1. **使用的Ghidra功能**
   - 字节模式搜索识别加密表
   - 函数图可视化算法结构
   - 高级数据流分析跟踪密钥使用
   - 自定义Ghidra脚本提取S-box

2. **关键分析技巧**
   - 跟踪数据变换识别轮函数
   - 使用表格视图重构S-box
   - 应用数学知识评估密码学强度
   - 使用反汇编-反编译比较分析优化代码

## 案例四：软件保护机制分析

### 目标：分析并绕过商业软件的授权保护

#### 目标软件背景

- 商业CAD软件试用版
- 实现：C++，Win64平台
- 保护：自定义授权检查和混淆
- 目标：理解授权机制（仅用于教育研究）

#### 分析步骤

##### 1. 初始调查

1. 导入主程序
   ```
   语言：x86:LE:64:default
   导入选项：默认
   分析选项：启用高级分析
   ```

2. 识别保护组件
   - 许可证相关字符串
   - 加密API使用
   - 可疑的反调试代码
   - 网络通信用于在线验证

3. 定位关键检查点
   ```c
   // 简化的启动序列
   int main() {
       initialize_app();
       if (!check_license()) {         // 关键检查点
           show_trial_restrictions();
       } else {
           enable_full_features();
       }
       run_main_loop();
       return 0;
   }
   ```

##### 2. 反调试与混淆分析

1. 识别反调试技术
   ```c
   // 反调试检查示例
   bool is_debugger_present() {
       int isDebuggerPresent = 0;
       
       // 直接API检查
       if (IsDebuggerPresent()) return true;
       
       // PEB检查
       __asm {
           mov eax, fs:[30h]
           mov eax, [eax+2]
           mov isDebuggerPresent, eax
       }
       
       return isDebuggerPresent != 0;
   }
   ```

2. 分析代码混淆
   - 虚假控制流
   - 不透明谓词
   - 自修改代码
   - 花指令分析

3. 分析字符串与常量混淆
   - 识别字符串解密例程
   - 定位运行时计算常量
   - 提取混淆的API调用

##### 3. 许可证验证逻辑

1. 分析许可文件格式
   - 定位许可证加载函数
   - 确定文件格式和字段
   - 识别签名或验证方法

2. 理解密钥验证
   ```c
   // 简化的许可证验证
   bool validate_license_key(const char* key) {
       uint8_t hash[32];
       char user_name[64];
       char expiry_date[16];
       
       // 从密钥中提取信息
       extract_license_info(key, user_name, expiry_date);
       
       // 验证哈希
       compute_hash(user_name, expiry_date, hash);
       if (!verify_signature(hash, key + 128)) {
           return false;
       }
       
       // 检查过期
       time_t now = time(NULL);
       time_t expires = parse_date(expiry_date);
       
       return now < expires;
   }
   ```

3. 分析在线验证机制
   - 识别网络请求格式
   - 确定服务器响应处理
   - 分析本地与远程验证交互

##### 4. 保护机制分析

1. 识别试用限制实现
   ```c
   // 试用限制检查示例
   bool is_feature_available(int feature_id) {
       if (g_license_type == LICENSE_FULL) {
           return true;
       } else if (g_license_type == LICENSE_TRIAL) {
           // 特定功能限制
           if (feature_id >= 100 && feature_id <= 200) {
               return false;  // 高级功能在试用版中禁用
           }
           // 使用次数限制
           if (g_usage_count > MAX_TRIAL_USAGE) {
               return false;
           }
           // 时间限制
           if (time(NULL) > g_install_time + TRIAL_PERIOD) {
               return false;
           }
       }
       return true;
   }
   ```

2. 分析完整性检查
   - 代码区域校验和
   - 资源文件验证
   - 运行时自检技术

3. 理解防篡改保护
   - 识别内存监控点
   - 分析代码校验和机制
   - 查看自我修复能力

##### 5. 分析结论

- 软件使用多层保护机制
- 许可证采用RSA签名验证
- 反调试技术基于PEB检查和时间检测
- 试用限制通过功能禁用和时间限制实施
- 存在关键的安全设计缺陷，如本地时间依赖

### 分析技术与Ghidra特性

1. **使用的Ghidra功能**
   - 反编译器处理高度优化的C++代码
   - 脚本API解密混淆字符串
   - 函数图分析复杂控制流
   - 字节搜索定位加密常量

2. **关键分析技巧**
   - 创建自定义数据类型表示许可证结构
   - 使用书签标记关键验证点
   - 应用反混淆技术识别真实控制流
   - 跟踪数据流识别关键算法组件 