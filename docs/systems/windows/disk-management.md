# 6. 磁盘管理

有效的磁盘管理是确保系统性能、数据完整性和存储空间可用性的关键。本章将介绍 Windows 中用于管理物理磁盘、分区和卷的核心工具和概念。

---

### 6.1 核心概念

-   **物理磁盘 (Physical Disk)**: 指计算机中实际的硬件驱动器，如 HDD (硬盘驱动器) 或 SSD (固态驱动器)。

-   **分区 (Partition)**: 是在物理磁盘上划分出的一个逻辑区域。一块物理磁盘可以被划分为一个或多个分区。

-   **卷 (Volume)**: 是一个应用了文件系统（如 NTFS）并被分配了驱动器号（如 `C:`）的分区，使其能够被操作系统用来存储文件。在简单场景下，"分区"和"卷"可以互换使用。

-   **分区样式 (Partition Style)**:
    -   **MBR (Master Boot Record)**:
        -   传统的分区样式，兼容性好。
        -   **限制**: 最多只支持 4 个主分区（或 3 个主分区 + 1 个扩展分区），且不支持容量超过 2TB 的磁盘。
    -   **GPT (GUID Partition Table)**:
        -   现代的分区样式，是 UEFI 启动模式的标配。
        -   **优势**: 支持最多 128 个主分区，支持的磁盘容量远超现有硬盘大小 (ZB 级别)。
        -   现代操作系统（Windows 10/11, Server 2016+）都应优先使用 GPT。

-   **磁盘类型**:
    -   **基本磁盘 (Basic Disk)**: 默认的磁盘类型，使用固定的分区表。简单、可靠，适用于大多数场景。
    -   **动态磁盘 (Dynamic Disk)**:
        -   提供一些基本磁盘不具备的高级功能，如创建跨区卷、带区卷、镜像卷等。
        -   在现代 Windows 中，其功能已基本被**存储空间 (Storage Spaces)** 技术所取代。除非有特定旧版需求，否则不建议使用。

---

### 6.2 GUI 工具：磁盘管理器

磁盘管理器 (`diskmgmt.msc`) 是最常用的磁盘管理图形工具。

**访问方式**:
1.  按 `Win + R`，输入 `diskmgmt.msc` 并回车。
2.  通过 `计算机管理 -> 存储 -> 磁盘管理`。

#### 常见操作

-   **初始化新磁盘**:
    1.  当你向系统中添加一块全新的、未格式化的磁盘时，磁盘管理器会提示你必须先**初始化**该磁盘。
    2.  你需要选择分区样式（**推荐选择 GPT**）。
    3.  初始化后，磁盘状态会显示为"联机 (Online)"和"未分配 (Unallocated)"。

-   **创建新卷 (分区)**:
    1.  在"未分配"空间上右键，选择 `新建简单卷 (New Simple Volume)`。
    2.  **卷大小**: 指定分区的大小。
    3.  **分配驱动器号**: 为卷分配一个盘符（如 `D:`）。
    4.  **格式化**:
        -   **文件系统**: 选择 `NTFS` (默认且推荐)。
        -   **分配单元大小**: 保持 `默认` 即可。
        -   **卷标**: 为你的驱动器起一个有意义的名称（如 `Data`）。
        -   **执行快速格式化**: 勾选此项会大大加快格式化速度。

-   **扩展卷**:
    -   如果一个卷后面紧随着**未分配的空间**，你可以扩展该卷。
    -   右键点击要扩展的卷，选择 `扩展卷 (Extend Volume)`，并按照向导操作。

-   **压缩卷**:
    -   如果一个卷有未使用的空间，你可以将其压缩出来，形成一块新的"未分配"空间，用于创建新分区。
    -   右键点击要压缩的卷，选择 `压缩卷 (Shrink Volume)`。

-   **更改驱动器号和路径**:
    -   右键点击一个卷，选择 `更改驱动器号和路径 (Change Drive Letter and Paths)`。你可以更改其盘符，或将其**装载 (Mount)** 到一个空的 NTFS 文件夹中（例如，将 D 盘装载到 `C:\Mount\Data`）。

---

### 6.3 命令行工具

#### DiskPart

`diskpart` 是一个强大的、交互式的命令行工具，用于高级磁盘管理。**操作具有破坏性，请谨慎使用。**

**使用流程**:
1.  以管理员身份打开 CMD 或 PowerShell。
2.  输入 `diskpart` 进入其交互环境。

**常用命令**:

| 命令 | 描述 |
| :--- | :--- |
| `list disk` | 列出系统中的所有物理磁盘。 |
| `select disk <编号>` | 选择要操作的磁盘，例如 `select disk 1`。 |
| `clean` | **[危险]** 清除所选磁盘上的所有分区和格式化信息。 |
| `convert gpt` | 将所选的空磁盘转换为 GPT 分区样式。 |
| `create partition primary` | 在所选磁盘上创建一个主分区（会使用所有可用空间）。 |
| `list partition` | 列出所选磁盘上的分区。 |
| `select partition <编号>` | 选择要操作的分区。 |
| `format fs=ntfs quick` | 将所选分区快速格式化为 NTFS。 |
| `assign letter=<盘符>` | 为所选分区分配一个驱动器号，例如 `assign letter=D`。 |
| `active` | 将所选分区标记为活动分区（仅用于 MBR 启动盘）。 |
| `exit` | 退出 diskpart。 |

*示例：将一块新磁盘 (disk 1) 初始化为 GPT 并创建、格式化一个卷*
```
diskpart
list disk
select disk 1
clean
convert gpt
create partition primary
format fs=ntfs quick
assign letter=E
exit
```

#### PowerShell

PowerShell 也提供了丰富的 cmdlet 来管理磁盘，通常比 `diskpart` 更安全、更易于在脚本中使用。

-   **查看磁盘和分区**:
    ```powershell
    # 获取所有物理磁盘
    Get-Disk

    # 获取所有分区/卷
    Get-Partition
    Get-Volume
    ```

-   **初始化新磁盘并创建卷**:
    ```powershell
    # 初始化磁盘 1 为 GPT 并分配盘符
    Initialize-Disk -Number 1 -PartitionStyle GPT -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize | Format-Volume -FileSystem NTFS -NewFileSystemLabel "NewData"
    ```
    这个命令完美地展示了 PowerShell 的对象管道能力：`Initialize-Disk` 的输出对象被直接传递给 `New-Partition`，后者的输出又被传递给 `Format-Volume`。

-   **调整分区大小**:
    ```powershell
    # 将 D 盘大小调整为 500GB
    Resize-Partition -DriveLetter "D" -Size 500GB
    ```

---

### 6.4 存储空间 (Storage Spaces)

这是 Windows Server 和 Windows 10/11 Pro 中提供的现代存储虚拟化技术，它允许你将多个物理磁盘（不限大小、接口）组合成一个**存储池 (Storage Pool)**，然后从池中创建具有高级弹性和性能特性的**存储空间 (虚拟磁盘)**。

-   **简单 (Simple)**: 将多个磁盘条带化以提高性能，但不提供冗余。一个磁盘故障会导致所有数据丢失。
-   **镜像 (Mirror)**: 将数据写入两个（双向镜像）或三个（三向镜像）磁盘，提供数据冗余。性能良好。
-   **奇偶校验 (Parity)**: 使用奇偶校验信息进行条带化，提供类似 RAID-5 的冗余，空间效率高于镜像，但写入性能较低。

存储空间是替代传统动态磁盘和硬件 RAID 的一种灵活、经济的方案。管理主要通过 `控制面板 -> 存储空间` 或 PowerShell 的 `Storage` 模块进行。 