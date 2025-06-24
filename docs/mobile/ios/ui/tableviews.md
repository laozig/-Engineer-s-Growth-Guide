# iOS 表格视图

表格视图（UITableView）是 iOS 应用程序中最常用和最强大的 UI 组件之一，用于展示和管理列表形式的数据。从简单的设置菜单到复杂的社交媒体信息流，表格视图几乎无处不在。本文将详细介绍 `UITableView` 的使用方法、自定义技巧以及常见的最佳实践。

## 目录

- [表格视图基础](#表格视图基础)
- [数据源与委托](#数据源与委托)
- [单元格重用机制](#单元格重用机制)
- [自定义单元格](#自定义单元格)
- [表头和表尾](#表头和表尾)
- [分组表格](#分组表格)
- [表格编辑](#表格编辑)
- [表格性能优化](#表格性能优化)
- [自适应布局](#自适应布局)
- [动态单元格高度](#动态单元格高度)
- [搜索与过滤](#搜索与过滤)
- [分页加载](#分页加载)
- [表格动画](#表格动画)
- [实践示例](#实践示例)
- [常见问题与解决方案](#常见问题与解决方案)

## 表格视图基础

### 什么是表格视图？

`UITableView` 是一个高度专门化的视图，用于展示垂直滚动的数据列表。它由多个行（rows）组成，每行显示为一个单元格（cell）。表格视图可以进一步划分为不同的段（sections），每段可以有自己的表头和表尾。

表格视图的主要特点：

- 垂直滚动的列表界面
- 高效的内存管理（通过单元格重用）
- 内置的编辑、删除和重新排序功能
- 支持分组和索引
- 高度可定制的外观和行为

### 表格视图样式

`UITableView` 提供两种基本样式：

1. **普通样式（Plain）**：单元格从屏幕边缘延伸，适合连续数据列表
2. **分组样式（Grouped）**：单元格显示在独立的组中，适合逻辑分组的数据

iOS 13 后新增：
3. **插入分组样式（Inset Grouped）**：类似于分组样式，但组与屏幕边缘有间距

```swift
// 创建普通样式的表格视图
let plainTableView = UITableView(frame: view.bounds, style: .plain)

// 创建分组样式的表格视图
let groupedTableView = UITableView(frame: view.bounds, style: .grouped)

// 创建插入分组样式的表格视图 (iOS 13+)
let insetGroupedTableView = UITableView(frame: view.bounds, style: .insetGrouped)
```

### 基本表格视图设置

下面是创建和配置表格视图的基本步骤：

```swift
import UIKit

class SimpleTableViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    
    let tableView = UITableView()
    let cellIdentifier = "SimpleCell"
    let data = ["项目 1", "项目 2", "项目 3", "项目 4", "项目 5"]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 设置表格视图
        tableView.frame = view.bounds
        tableView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(tableView)
        
        // 设置数据源和委托
        tableView.dataSource = self
        tableView.delegate = self
        
        // 注册单元格
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: cellIdentifier)
    }
    
    // MARK: - UITableViewDataSource
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return data.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier, for: indexPath)
        cell.textLabel?.text = data[indexPath.row]
        return cell
    }
    
    // MARK: - UITableViewDelegate
    
    func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        print("选中了: \(data[indexPath.row])")
    }
}
```

### 表格视图的主要属性

表格视图有许多属性可以控制其外观和行为：

```swift
// 基本外观
tableView.backgroundColor = .white
tableView.separatorColor = .lightGray
tableView.separatorStyle = .singleLine
tableView.separatorInset = UIEdgeInsets(top: 0, left: 15, bottom: 0, right: 15)

// 行为
tableView.allowsSelection = true // 允许选择行
tableView.allowsMultipleSelection = false // 禁止多选
tableView.isEditing = false // 编辑模式
tableView.showsVerticalScrollIndicator = true // 显示滚动指示器

// 表头表尾
tableView.tableHeaderView = headerView
tableView.tableFooterView = footerView

// 性能相关
tableView.rowHeight = 44 // 默认行高
tableView.estimatedRowHeight = 44 // 估算行高，提升性能
tableView.sectionHeaderHeight = 28 // 段头高度
tableView.estimatedSectionHeaderHeight = 28 // 估算段头高度
```

### 索引路径 (IndexPath)

在表格视图中，使用 `IndexPath` 来唯一标识一个单元格的位置。它包含两个主要属性：

- **section**：单元格所在的段（索引从 0 开始）
- **row**：单元格在其段中的行号（索引从 0 开始）

```swift
// 创建索引路径
let indexPath = IndexPath(row: 2, section: 0)

// 获取指定位置的单元格
let cell = tableView.cellForRow(at: indexPath)

// 滚动到指定位置
tableView.scrollToRow(at: indexPath, at: .middle, animated: true)
```

## 数据源与委托

表格视图使用两个主要协议来管理其数据和行为：

### UITableViewDataSource

数据源协议负责提供表格视图的数据内容，包括：

- 每个段中的行数
- 每行的单元格内容
- 段的标题
- 编辑操作（插入、删除）

```swift
// 必需方法

// 返回指定段中的行数
func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
    return data[section].count
}

// 配置并返回指定位置的单元格
func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
    let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier, for: indexPath)
    let item = data[indexPath.section][indexPath.row]
    cell.textLabel?.text = item.title
    cell.detailTextLabel?.text = item.subtitle
    cell.imageView?.image = item.image
    return cell
}

// 可选方法

// 返回段数（默认为1）
func numberOfSections(in tableView: UITableView) -> Int {
    return data.count
}

// 返回段标题
func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
    return sectionTitles[section]
}

// 返回段尾标题
func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
    return sectionFooters[section]
}

// 单元格编辑（删除/插入）
func tableView(_ tableView: UITableView, commit editingStyle: UITableViewCell.EditingStyle, forRowAt indexPath: IndexPath) {
    if editingStyle == .delete {
        // 处理删除操作
        data[indexPath.section].remove(at: indexPath.row)
        tableView.deleteRows(at: [indexPath], with: .fade)
    } else if editingStyle == .insert {
        // 处理插入操作
        data[indexPath.section].insert(newItem, at: indexPath.row)
        tableView.insertRows(at: [indexPath], with: .automatic)
    }
}

// 行是否可移动
func tableView(_ tableView: UITableView, canMoveRowAt indexPath: IndexPath) -> Bool {
    return true
}

// 处理行移动
func tableView(_ tableView: UITableView, moveRowAt sourceIndexPath: IndexPath, to destinationIndexPath: IndexPath) {
    let movedItem = data[sourceIndexPath.section][sourceIndexPath.row]
    data[sourceIndexPath.section].remove(at: sourceIndexPath.row)
    data[destinationIndexPath.section].insert(movedItem, at: destinationIndexPath.row)
}
```

### UITableViewDelegate

委托协议处理表格视图的外观和用户交互，包括：

- 行高和段头/尾高度
- 行选择和高亮
- 辅助操作（如滑动删除）
- 自定义段头/尾视图

```swift
// 行高
func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
    return 60
}

// 估算行高（提高性能）
func tableView(_ tableView: UITableView, estimatedHeightForRowAt indexPath: IndexPath) -> CGFloat {
    return 60
}

// 段头高度
func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
    return 40
}

// 段尾高度
func tableView(_ tableView: UITableView, heightForFooterInSection section: Int) -> CGFloat {
    return 30
}

// 自定义段头视图
func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
    let headerView = UIView(frame: CGRect(x: 0, y: 0, width: tableView.bounds.width, height: 40))
    headerView.backgroundColor = .lightGray
    
    let label = UILabel(frame: CGRect(x: 15, y: 0, width: tableView.bounds.width - 30, height: 40))
    label.text = sectionTitles[section]
    label.font = UIFont.boldSystemFont(ofSize: 16)
    headerView.addSubview(label)
    
    return headerView
}

// 自定义段尾视图
func tableView(_ tableView: UITableView, viewForFooterInSection section: Int) -> UIView? {
    // 类似于段头视图的实现
    return footerView
}

// 选中行
func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
    tableView.deselectRow(at: indexPath, animated: true)
    
    let selectedItem = data[indexPath.section][indexPath.row]
    print("选中了: \(selectedItem)")
    
    // 导航到详情页面
    let detailVC = DetailViewController(item: selectedItem)
    navigationController?.pushViewController(detailVC, animated: true)
}

// 行将要显示
func tableView(_ tableView: UITableView, willDisplay cell: UITableViewCell, forRowAt indexPath: IndexPath) {
    // 可以在这里设置单元格的其他属性或添加动画
    cell.alpha = 0
    UIView.animate(withDuration: 0.3) {
        cell.alpha = 1
    }
}

// 配置滑动操作
func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
    // 创建删除操作
    let deleteAction = UIContextualAction(style: .destructive, title: "删除") { (action, view, completion) in
        self.data[indexPath.section].remove(at: indexPath.row)
        tableView.deleteRows(at: [indexPath], with: .fade)
        completion(true)
    }
    
    // 创建其他操作
    let editAction = UIContextualAction(style: .normal, title: "编辑") { (action, view, completion) in
        // 处理编辑操作
        completion(true)
    }
    editAction.backgroundColor = .blue
    
    // 配置滑动操作
    let configuration = UISwipeActionsConfiguration(actions: [deleteAction, editAction])
    return configuration
}
```

### 数据驱动的表格视图

建立一个良好的数据模型是实现高效表格视图的关键。下面是一个简单的数据驱动示例：

```swift
// 数据模型
struct Item {
    let title: String
    let subtitle: String
    let image: UIImage?
}

class SectionModel {
    var title: String
    var items: [Item]
    
    init(title: String, items: [Item]) {
        self.title = title
        self.items = items
    }
}

class TableViewModel {
    var sections: [SectionModel] = []
    
    func numberOfSections() -> Int {
        return sections.count
    }
    
    func numberOfRows(in section: Int) -> Int {
        return sections[section].items.count
    }
    
    func item(at indexPath: IndexPath) -> Item {
        return sections[indexPath.section].items[indexPath.row]
    }
    
    func titleForSection(_ section: Int) -> String {
        return sections[section].title
    }
    
    func addItem(_ item: Item, to sectionIndex: Int) {
        sections[sectionIndex].items.append(item)
    }
    
    func removeItem(at indexPath: IndexPath) {
        sections[indexPath.section].items.remove(at: indexPath.row)
    }
}

// 在视图控制器中使用
class DataDrivenTableViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    
    let tableView = UITableView(frame: .zero, style: .grouped)
    let cellIdentifier = "ItemCell"
    let viewModel = TableViewModel()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 设置表格视图
        view.addSubview(tableView)
        tableView.frame = view.bounds
        tableView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        
        tableView.dataSource = self
        tableView.delegate = self
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: cellIdentifier)
        
        // 准备数据
        setupData()
    }
    
    func setupData() {
        // 创建示例数据
        let section1Items = [
            Item(title: "项目 1", subtitle: "描述 1", image: UIImage(named: "icon1")),
            Item(title: "项目 2", subtitle: "描述 2", image: UIImage(named: "icon2"))
        ]
        let section1 = SectionModel(title: "第一组", items: section1Items)
        
        let section2Items = [
            Item(title: "项目 3", subtitle: "描述 3", image: UIImage(named: "icon3")),
            Item(title: "项目 4", subtitle: "描述 4", image: UIImage(named: "icon4"))
        ]
        let section2 = SectionModel(title: "第二组", items: section2Items)
        
        viewModel.sections = [section1, section2]
    }
    
    // MARK: - UITableViewDataSource
    
    func numberOfSections(in tableView: UITableView) -> Int {
        return viewModel.numberOfSections()
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return viewModel.numberOfRows(in: section)
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier, for: indexPath)
        
        let item = viewModel.item(at: indexPath)
        cell.textLabel?.text = item.title
        cell.detailTextLabel?.text = item.subtitle
        cell.imageView?.image = item.image
        
        return cell
    }
    
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return viewModel.titleForSection(section)
    }
} 
```

## 单元格重用机制

### 重用的重要性

表格视图的核心优化机制是单元格重用。当用户滚动表格时，只有屏幕上可见的单元格会被加载到内存中，而不是创建整个表格的所有单元格。当单元格滚出屏幕时，它会被放入重用队列中，准备被新显示的行重新利用。

这种机制能够显著提高性能并降低内存使用：

- 避免为每一行创建新的单元格实例
- 减少内存占用和垃圾回收
- 提高滚动性能

### 单元格注册

在使用重用机制前，必须先注册单元格类型：

```swift
// 注册系统提供的单元格
tableView.register(UITableViewCell.self, forCellReuseIdentifier: "BasicCell")

// 注册自定义单元格类
tableView.register(CustomTableViewCell.self, forCellReuseIdentifier: "CustomCell")

// 从 Nib 文件注册单元格
tableView.register(UINib(nibName: "CustomCell", bundle: nil), forCellReuseIdentifier: "NibCell")
```

### 获取重用单元格

在 `cellForRowAt` 方法中，使用 `dequeueReusableCell(withIdentifier:for:)` 方法从重用队列中获取单元格：

```swift
func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
    // 从重用队列获取单元格
    let cell = tableView.dequeueReusableCell(withIdentifier: "CustomCell", for: indexPath) as! CustomTableViewCell
    
    // 配置单元格内容
    let item = data[indexPath.row]
    cell.configure(with: item)
    
    return cell
}
```

### 单元格重用的最佳实践

1. **始终使用重用机制**：即使只有几行数据，也应该使用重用机制，这是好习惯
2. **清理重用单元格**：在配置单元格前重置其所有状态，避免残留之前行的数据
3. **轻量级单元格**：保持单元格设计简单，避免过多的子视图和复杂层级
4. **异步加载内容**：在后台线程加载图片等资源，避免阻塞主线程
5. **使用适当的标识符**：为不同类型的单元格使用不同的重用标识符

```swift
func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
    let item = data[indexPath.row]
    
    // 根据内容类型选择不同的单元格类型
    let identifier = item.hasImage ? "ImageCell" : "TextCell"
    let cell = tableView.dequeueReusableCell(withIdentifier: identifier, for: indexPath)
    
    // 清理旧状态
    cell.imageView?.image = nil
    cell.accessoryView = nil
    
    // 配置新内容
    cell.textLabel?.text = item.title
    
    if item.hasImage {
        // 异步加载图片
        DispatchQueue.global().async {
            if let image = self.loadImage(for: item) {
                DispatchQueue.main.async {
                    // 确保单元格仍然被用于显示同一行
                    if let visibleCell = tableView.cellForRow(at: indexPath) {
                        visibleCell.imageView?.image = image
                        visibleCell.setNeedsLayout()
                    }
                }
            }
        }
    }
    
    return cell
}
```

### 常见陷阱与解决方法

**问题：滚动时单元格内容闪烁或重置**

解决方案：确保在重用队列获取单元格后正确重置所有状态，避免使用 `cellForRow(at:)` 方法获取不在屏幕上的单元格。

**问题：选择状态在滚动时丢失**

解决方案：跟踪选中的索引路径，并在 `cellForRowAt` 中设置单元格选中状态。

**问题：滚动性能差**

解决方案：使用 `estimatedRowHeight`，减少 `cellForRowAt` 中的工作量，确保图片和内容在后台线程异步加载。

## 自定义单元格

虽然系统提供的 `UITableViewCell` 样式可以满足简单需求，但大多数应用需要自定义单元格以展示特定布局和内容。

### 系统提供的单元格样式

`UITableViewCell` 提供四种内置样式：

1. **Default**：左侧图片、主标题
2. **Subtitle**：左侧图片、主标题、副标题
3. **Value1**：左侧主标题、右侧副标题（灰色）
4. **Value2**：左侧副标题（蓝色）、右侧主标题

```swift
// 使用默认样式
let cell1 = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
cell1.textLabel?.text = "主标题"
cell1.imageView?.image = UIImage(named: "icon")

// 使用 Subtitle 样式
let cell2 = UITableViewCell(style: .subtitle, reuseIdentifier: "SubtitleCell")
cell2.textLabel?.text = "主标题"
cell2.detailTextLabel?.text = "副标题"
cell2.imageView?.image = UIImage(named: "icon")
```

### 子类化 UITableViewCell

通过子类化 `UITableViewCell` 可以创建完全自定义的单元格：

```swift
class CustomTableViewCell: UITableViewCell {
    
    // 自定义UI元素
    let customImageView = UIImageView()
    let titleLabel = UILabel()
    let subtitleLabel = UILabel()
    let actionButton = UIButton(type: .system)
    
    // 可选：声明回调闭包
    var buttonTapHandler: (() -> Void)?
    
    // 必需：重写初始化方法
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupViews()
    }
    
    // 设置视图层次和约束
    private func setupViews() {
        // 添加子视图
        contentView.addSubview(customImageView)
        contentView.addSubview(titleLabel)
        contentView.addSubview(subtitleLabel)
        contentView.addSubview(actionButton)
        
        // 禁用自动转换约束
        customImageView.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        subtitleLabel.translatesAutoresizingMaskIntoConstraints = false
        actionButton.translatesAutoresizingMaskIntoConstraints = false
        
        // 配置视图属性
        customImageView.contentMode = .scaleAspectFill
        customImageView.clipsToBounds = true
        customImageView.layer.cornerRadius = 20
        
        titleLabel.font = UIFont.boldSystemFont(ofSize: 16)
        
        subtitleLabel.font = UIFont.systemFont(ofSize: 14)
        subtitleLabel.textColor = .gray
        subtitleLabel.numberOfLines = 2
        
        actionButton.setTitle("操作", for: .normal)
        actionButton.addTarget(self, action: #selector(buttonTapped), for: .touchUpInside)
        
        // 设置自动布局约束
        NSLayoutConstraint.activate([
            customImageView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 15),
            customImageView.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            customImageView.widthAnchor.constraint(equalToConstant: 40),
            customImageView.heightAnchor.constraint(equalToConstant: 40),
            
            titleLabel.leadingAnchor.constraint(equalTo: customImageView.trailingAnchor, constant: 12),
            titleLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 10),
            titleLabel.trailingAnchor.constraint(equalTo: actionButton.leadingAnchor, constant: -10),
            
            subtitleLabel.leadingAnchor.constraint(equalTo: titleLabel.leadingAnchor),
            subtitleLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 4),
            subtitleLabel.trailingAnchor.constraint(equalTo: titleLabel.trailingAnchor),
            subtitleLabel.bottomAnchor.constraint(lessThanOrEqualTo: contentView.bottomAnchor, constant: -10),
            
            actionButton.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -15),
            actionButton.centerYAnchor.constraint(equalTo: contentView.centerYAnchor),
            actionButton.widthAnchor.constraint(greaterThanOrEqualToConstant: 60)
        ])
    }
    
    // 按钮点击处理方法
    @objc private func buttonTapped() {
        buttonTapHandler?()
    }
    
    // 配置单元格内容的方法
    func configure(with model: CellModel) {
        titleLabel.text = model.title
        subtitleLabel.text = model.subtitle
        customImageView.image = model.image
        
        // 如果需要，可以配置按钮
        if let buttonTitle = model.buttonTitle {
            actionButton.setTitle(buttonTitle, for: .normal)
            actionButton.isHidden = false
        } else {
            actionButton.isHidden = true
        }
    }
    
    // 单元格准备重用前清理
    override func prepareForReuse() {
        super.prepareForReuse()
        
        // 重置所有状态
        customImageView.image = nil
        titleLabel.text = nil
        subtitleLabel.text = nil
        actionButton.isHidden = true
        buttonTapHandler = nil
    }
}

// 单元格数据模型
struct CellModel {
    let title: String
    let subtitle: String
    let image: UIImage?
    let buttonTitle: String?
    
    init(title: String, subtitle: String, image: UIImage? = nil, buttonTitle: String? = nil) {
        self.title = title
        self.subtitle = subtitle
        self.image = image
        self.buttonTitle = buttonTitle
    }
}
```

### 使用 XIB 创建自定义单元格

除了代码创建外，还可以使用 Interface Builder 创建自定义单元格：

1. **创建 XIB 文件**：File > New > File > User Interface > View，命名为 `CustomTableViewCell.xib`
2. **设置单元格类**：在 Identity Inspector 中设置 Class 为 `CustomTableViewCell`
3. **添加和配置 UI 元素**：拖放并设置约束
4. **创建 Outlet 连接**：将 UI 元素与自定义类中的属性连接

```swift
class CustomTableViewCell: UITableViewCell {
    
    @IBOutlet weak var customImageView: UIImageView!
    @IBOutlet weak var titleLabel: UILabel!
    @IBOutlet weak var subtitleLabel: UILabel!
    @IBOutlet weak var actionButton: UIButton!
    
    var buttonTapHandler: (() -> Void)?
    
    override func awakeFromNib() {
        super.awakeFromNib()
        // 在这里进行额外的设置，如果需要
        customImageView.layer.cornerRadius = 20
        customImageView.clipsToBounds = true
        
        actionButton.addTarget(self, action: #selector(buttonTapped), for: .touchUpInside)
    }
    
    @objc private func buttonTapped() {
        buttonTapHandler?()
    }
    
    func configure(with model: CellModel) {
        titleLabel.text = model.title
        subtitleLabel.text = model.subtitle
        customImageView.image = model.image
        
        if let buttonTitle = model.buttonTitle {
            actionButton.setTitle(buttonTitle, for: .normal)
            actionButton.isHidden = false
        } else {
            actionButton.isHidden = true
        }
    }
    
    override func prepareForReuse() {
        super.prepareForReuse()
        
        customImageView.image = nil
        titleLabel.text = nil
        subtitleLabel.text = nil
        actionButton.isHidden = true
        buttonTapHandler = nil
    }
}
```

在视图控制器中注册和使用这个自定义单元格：

```swift
// 在 viewDidLoad 中注册 XIB 单元格
tableView.register(UINib(nibName: "CustomTableViewCell", bundle: nil), forCellReuseIdentifier: "CustomCell")

// 在 cellForRowAt 中使用
func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
    let cell = tableView.dequeueReusableCell(withIdentifier: "CustomCell", for: indexPath) as! CustomTableViewCell
    
    let model = dataArray[indexPath.row]
    cell.configure(with: model)
    
    // 设置按钮点击处理
    cell.buttonTapHandler = { [weak self] in
        self?.handleButtonTap(for: indexPath)
    }
    
    return cell
}

func handleButtonTap(for indexPath: IndexPath) {
    print("按钮被点击，位置：\(indexPath)")
    // 处理按钮点击操作
}
```

### 使用 Swift UI 组件作为单元格

iOS 13 及以上版本支持在 UIKit 项目中使用 SwiftUI 视图作为表格单元格：

```swift
import SwiftUI

// 创建 SwiftUI 视图
struct CustomCellView: View {
    var title: String
    var subtitle: String
    var imageName: String?
    
    var body: some View {
        HStack(spacing: 12) {
            if let imageName = imageName, let image = UIImage(named: imageName) {
                Image(uiImage: image)
                    .resizable()
                    .aspectRatio(contentMode: .fill)
                    .frame(width: 40, height: 40)
                    .clipShape(Circle())
            }
            
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.headline)
                
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundColor(.gray)
                    .lineLimit(2)
            }
            
            Spacer()
            
            Button("操作") {
                // 处理操作
            }
            .foregroundColor(.blue)
            .padding(.horizontal, 10)
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 15)
    }
}

// 在 UIKit 中使用 SwiftUI 视图
class SwiftUITableViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    
    let tableView = UITableView()
    let data: [(title: String, subtitle: String, imageName: String?)] = [
        ("标题 1", "副标题 1", "image1"),
        ("标题 2", "副标题 2", "image2"),
        ("标题 3", "副标题 3", nil)
    ]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.addSubview(tableView)
        tableView.frame = view.bounds
        tableView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        
        tableView.dataSource = self
        tableView.delegate = self
        
        // 注册自定义单元格
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
    }
    
    // MARK: - UITableViewDataSource
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return data.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
        
        // 移除旧的托管控制器
        cell.contentView.subviews.forEach { $0.removeFromSuperview() }
        
        // 创建 SwiftUI 视图
        let item = data[indexPath.row]
        let swiftUIView = CustomCellView(
            title: item.title,
            subtitle: item.subtitle,
            imageName: item.imageName
        )
        
        // 将 SwiftUI 视图嵌入到 UIKit 单元格
        let hostingController = UIHostingController(rootView: swiftUIView)
        hostingController.view.backgroundColor = .clear
        
        // 添加托管控制器视图到单元格
        cell.contentView.addSubview(hostingController.view)
        hostingController.view.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            hostingController.view.leadingAnchor.constraint(equalTo: cell.contentView.leadingAnchor),
            hostingController.view.trailingAnchor.constraint(equalTo: cell.contentView.trailingAnchor),
            hostingController.view.topAnchor.constraint(equalTo: cell.contentView.topAnchor),
            hostingController.view.bottomAnchor.constraint(equalTo: cell.contentView.bottomAnchor)
        ])
        
        // 保留对托管控制器的引用
        addChild(hostingController)
        hostingController.didMove(toParent: self)
        
        return cell
    }
    
    func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        return UITableView.automaticDimension
    }
    
    func tableView(_ tableView: UITableView, estimatedHeightForRowAt indexPath: IndexPath) -> CGFloat {
        return 60
    }
} 
```

## 表头和表尾

表格视图可以包含表头和表尾视图，用于展示额外信息或提供补充功能。

### 整个表格的表头和表尾

使用 `tableHeaderView` 和 `tableFooterView` 属性可以为整个表格设置表头和表尾视图：

```swift
// 创建表头视图
let headerView = UIView(frame: CGRect(x: 0, y: 0, width: tableView.bounds.width, height: 100))
headerView.backgroundColor = .systemGroupedBackground
    
// 添加标题
let titleLabel = UILabel(frame: CGRect(x: 15, y: 30, width: tableView.bounds.width - 30, height: 40))
titleLabel.text = "我的列表"
titleLabel.font = UIFont.boldSystemFont(ofSize: 22)
headerView.addSubview(titleLabel)
    
// 设置表头
tableView.tableHeaderView = headerView

// 创建表尾视图
let footerView = UIView(frame: CGRect(x: 0, y: 0, width: tableView.bounds.width, height: 80))
footerView.backgroundColor = .systemGroupedBackground
    
// 添加按钮
let addButton = UIButton(type: .system)
addButton.frame = CGRect(x: 20, y: 20, width: tableView.bounds.width - 40, height: 40)
addButton.setTitle("添加新项目", for: .normal)
addButton.backgroundColor = .systemBlue
addButton.setTitleColor(.white, for: .normal)
addButton.layer.cornerRadius = 8
addButton.addTarget(self, action: #selector(addNewItem), for: .touchUpInside)
footerView.addSubview(addButton)
    
// 设置表尾
tableView.tableFooterView = footerView
```

### 段头和段尾

对于分组的表格，可以为每个段提供自定义的段头和段尾：

#### 通过委托方法设置段头段尾视图

```swift
// 段头视图
func tableView(_ tableView: UITableView, viewForHeaderInSection section: Int) -> UIView? {
    let headerView = UIView(frame: CGRect(x: 0, y: 0, width: tableView.bounds.width, height: 50))
    headerView.backgroundColor = .systemGray6
    
    let titleLabel = UILabel(frame: CGRect(x: 15, y: 0, width: tableView.bounds.width - 30, height: 50))
    titleLabel.text = sections[section].title
    titleLabel.font = UIFont.boldSystemFont(ofSize: 16)
    headerView.addSubview(titleLabel)
    
    // 添加按钮或其他控件
    let button = UIButton(type: .system)
    button.frame = CGRect(x: tableView.bounds.width - 80, y: 10, width: 60, height: 30)
    button.setTitle("更多", for: .normal)
    button.tag = section  // 存储段索引
    button.addTarget(self, action: #selector(headerButtonTapped(_:)), for: .touchUpInside)
    headerView.addSubview(button)
    
    return headerView
}

// 段尾视图
func tableView(_ tableView: UITableView, viewForFooterInSection section: Int) -> UIView? {
    let footerView = UIView(frame: CGRect(x: 0, y: 0, width: tableView.bounds.width, height: 30))
    footerView.backgroundColor = .systemGray6
    
    let label = UILabel(frame: CGRect(x: 15, y: 0, width: tableView.bounds.width - 30, height: 30))
    label.text = "共 \(sections[section].items.count) 项"
    label.font = UIFont.systemFont(ofSize: 12)
    label.textColor = .gray
    footerView.addSubview(label)
    
    return footerView
}

// 设置段头高度
func tableView(_ tableView: UITableView, heightForHeaderInSection section: Int) -> CGFloat {
    return 50
}

// 设置段尾高度
func tableView(_ tableView: UITableView, heightForFooterInSection section: Int) -> CGFloat {
    return 30
}

// 段头按钮点击处理
@objc func headerButtonTapped(_ sender: UIButton) {
    let section = sender.tag
    print("点击了第 \(section) 段的更多按钮")
    // 执行相应的操作
}
```

#### 使用简单标题

如果只需要简单的文本标题，可以使用以下方法：

```swift
// 段头标题
func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
    return sections[section].title
}

// 段尾标题
func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
    return "共 \(sections[section].items.count) 项"
}
```

### 粘性段头

iOS 表格视图默认支持粘性段头（悬停在屏幕顶部）。如果要禁用此功能，可以实现：

```swift
// 关闭粘性段头
if #available(iOS 15.0, *) {
    tableView.sectionHeaderTopPadding = 0
}

// 完全禁用粘性段头
func scrollViewDidScroll(_ scrollView: UIScrollView) {
    if let visibleSectionHeaders = tableView.visibleSectionHeaders {
        for headerView in visibleSectionHeaders {
            if let rect = tableView.rectForHeader(inSection: headerView.section) {
                headerView.frame.origin.y = rect.origin.y
            }
        }
    }
}
```

## 分组表格

表格视图可以将数据分为多个逻辑组，以提高可读性和组织性。

### 分组样式

创建表格视图时可以指定其样式：

```swift
// 普通样式（无视觉分组）
let plainTableView = UITableView(frame: view.bounds, style: .plain)

// 分组样式（每组有明显的视觉分隔）
let groupedTableView = UITableView(frame: view.bounds, style: .grouped)

// 插入分组样式（iOS 13+，组与屏幕边缘有间距）
if #available(iOS 13.0, *) {
    let insetGroupedTableView = UITableView(frame: view.bounds, style: .insetGrouped)
}
```

### 实现分组数据模型

分组表格需要一个二维数据结构：

```swift
// 定义段模型
struct Section {
    let title: String
    let footer: String?
    var items: [Item]
}

// 定义项目模型
struct Item {
    let title: String
    let subtitle: String?
    let image: UIImage?
}

// 在视图控制器中使用
class GroupedTableViewController: UIViewController, UITableViewDataSource, UITableViewDelegate {
    
    let tableView = UITableView(frame: .zero, style: .grouped)
    let cellIdentifier = "GroupedCell"
    
    // 分组数据
    var sections: [Section] = [
        Section(
            title: "水果",
            footer: "各种新鲜水果",
            items: [
                Item(title: "苹果", subtitle: "红富士", image: UIImage(named: "apple")),
                Item(title: "香蕉", subtitle: "进口", image: UIImage(named: "banana")),
                Item(title: "橙子", subtitle: "赣南脐橙", image: UIImage(named: "orange"))
            ]
        ),
        Section(
            title: "蔬菜",
            footer: "当季蔬菜",
            items: [
                Item(title: "西红柿", subtitle: "大棚", image: UIImage(named: "tomato")),
                Item(title: "黄瓜", subtitle: "本地", image: UIImage(named: "cucumber"))
            ]
        )
    ]
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.addSubview(tableView)
        tableView.frame = view.bounds
        tableView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        
        tableView.dataSource = self
        tableView.delegate = self
        
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: cellIdentifier)
    }
    
    // MARK: - UITableViewDataSource
    
    func numberOfSections(in tableView: UITableView) -> Int {
        return sections.count
    }
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return sections[section].items.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: cellIdentifier, for: indexPath)
        
        let item = sections[indexPath.section].items[indexPath.row]
        cell.textLabel?.text = item.title
        cell.detailTextLabel?.text = item.subtitle
        cell.imageView?.image = item.image
        
        return cell
    }
    
    func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        return sections[section].title
    }
    
    func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        return sections[section].footer
    }
}
```

### 索引列表

对于包含大量数据的表格，可以添加索引列表以便快速导航：

```swift
// 返回索引标题数组
func sectionIndexTitles(for tableView: UITableView) -> [String]? {
    // 返回段标题的首字母
    return sections.map { String($0.title.prefix(1)) }
}

// 可选：将索引映射到段索引
func tableView(_ tableView: UITableView, sectionForSectionIndexTitle title: String, at index: Int) -> Int {
    // 查找匹配的段
    for (i, section) in sections.enumerated() {
        if section.title.hasPrefix(title) {
            return i
        }
    }
    return 0
}
```

对于通讯录类应用，常用 A-Z 索引：

```swift
func sectionIndexTitles(for tableView: UITableView) -> [String]? {
    return ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
            "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "#"]
}
```

## 表格编辑

表格视图支持多种编辑操作，包括插入、删除和重新排序行。

### 启用编辑模式

有两种方式进入编辑模式：

```swift
// 方式1：设置表格视图的编辑状态
tableView.isEditing = true  // 进入编辑模式
tableView.isEditing = false // 退出编辑模式

// 方式2：使用动画切换
tableView.setEditing(true, animated: true)  // 进入编辑模式
tableView.setEditing(false, animated: true) // 退出编辑模式

// 常见用法：在导航栏添加编辑按钮
navigationItem.rightBarButtonItem = editButtonItem
```

### 删除行

实现以下方法允许删除行：

```swift
// 1. 指定行是否可编辑
func tableView(_ tableView: UITableView, canEditRowAt indexPath: IndexPath) -> Bool {
    // 允许编辑所有行，或者根据条件决定
    return true
}

// 2. 处理编辑操作
func tableView(_ tableView: UITableView, commit editingStyle: UITableViewCell.EditingStyle, forRowAt indexPath: IndexPath) {
    if editingStyle == .delete {
        // 更新数据源
        let section = indexPath.section
        sections[section].items.remove(at: indexPath.row)
        
        // 更新表格视图
        tableView.deleteRows(at: [indexPath], with: .fade)
        
        // 如果段中没有项目了，可以选择删除整个段
        if sections[section].items.isEmpty {
            sections.remove(at: section)
            tableView.deleteSections(IndexSet(integer: section), with: .fade)
        }
    }
}
```

### 插入行

```swift
// 在编辑操作方法中处理插入
func tableView(_ tableView: UITableView, commit editingStyle: UITableViewCell.EditingStyle, forRowAt indexPath: IndexPath) {
    if editingStyle == .delete {
        // 删除行的代码
    } else if editingStyle == .insert {
        // 创建新项目
        let newItem = Item(title: "新项目", subtitle: "详情", image: nil)
        
        // 更新数据源
        sections[indexPath.section].items.insert(newItem, at: indexPath.row)
        
        // 更新表格视图
        tableView.insertRows(at: [indexPath], with: .automatic)
    }
}

// 指定某些行显示"添加"按钮
func tableView(_ tableView: UITableView, editingStyleForRowAt indexPath: IndexPath) -> UITableViewCell.EditingStyle {
    // 例如，每个段的最后一行显示添加按钮
    if indexPath.row == sections[indexPath.section].items.count - 1 {
        return .insert
    } else {
        return .delete
    }
}
```

### 移动行

允许用户通过拖动重新排序行：

```swift
// 1. 指定行是否可移动
func tableView(_ tableView: UITableView, canMoveRowAt indexPath: IndexPath) -> Bool {
    return true  // 所有行都可移动
}

// 2. 处理移动操作
func tableView(_ tableView: UITableView, moveRowAt sourceIndexPath: IndexPath, to destinationIndexPath: IndexPath) {
    // 从数据源中移除项目
    let movedItem = sections[sourceIndexPath.section].items[sourceIndexPath.row]
    sections[sourceIndexPath.section].items.remove(at: sourceIndexPath.row)
    
    // 将项目插入到新位置
    sections[destinationIndexPath.section].items.insert(movedItem, at: destinationIndexPath.row)
}

// 3. 可选：限制移动范围
func tableView(_ tableView: UITableView, targetIndexPathForMoveFromRowAt sourceIndexPath: IndexPath, toProposedIndexPath proposedDestinationIndexPath: IndexPath) -> IndexPath {
    // 例如，限制行只能在同一段内移动
    if sourceIndexPath.section != proposedDestinationIndexPath.section {
        // 如果尝试移动到其他段，返回源段中最接近的位置
        let row = min(sections[sourceIndexPath.section].items.count - 1, proposedDestinationIndexPath.row)
        return IndexPath(row: row, section: sourceIndexPath.section)
    }
    return proposedDestinationIndexPath
}
```

### 自定义滑动操作

iOS 提供了可自定义的滑动操作，替代传统的删除操作：

```swift
// 左侧滑动操作（iOS 11+）
func tableView(_ tableView: UITableView, leadingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
    // 创建收藏操作
    let favoriteAction = UIContextualAction(style: .normal, title: "收藏") { (action, view, completion) in
        // 处理收藏操作
        self.sections[indexPath.section].items[indexPath.row].isFavorite.toggle()
        completion(true)
    }
    favoriteAction.backgroundColor = .systemYellow
    
    // 创建其他操作
    let shareAction = UIContextualAction(style: .normal, title: "共享") { (action, view, completion) in
        // 处理共享操作
        completion(true)
    }
    shareAction.backgroundColor = .systemGreen
    
    // 返回滑动配置
    return UISwipeActionsConfiguration(actions: [favoriteAction, shareAction])
}

// 右侧滑动操作（iOS 11+）
func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
    // 创建删除操作
    let deleteAction = UIContextualAction(style: .destructive, title: "删除") { (action, view, completion) in
        // 处理删除操作
        self.sections[indexPath.section].items.remove(at: indexPath.row)
        tableView.deleteRows(at: [indexPath], with: .automatic)
        completion(true)
    }
    
    // 创建存档操作
    let archiveAction = UIContextualAction(style: .normal, title: "存档") { (action, view, completion) in
        // 处理存档操作
        completion(true)
    }
    archiveAction.backgroundColor = .systemGray
    
    // 返回滑动配置
    let configuration = UISwipeActionsConfiguration(actions: [deleteAction, archiveAction])
    configuration.performsFirstActionWithFullSwipe = true  // 全滑动执行第一个操作
    
    return configuration
}
```

### 批量编辑

iOS 表格视图支持多选操作：

```swift
// 启用多选模式
tableView.allowsMultipleSelectionDuringEditing = true
tableView.setEditing(true, animated: true)

// 处理选中的行
@objc func deleteSelectedRows() {
    guard let selectedRows = tableView.indexPathsForSelectedRows else {
        return
    }
    
    // 按段和行从大到小排序，避免删除时索引错误
    let sortedRows = selectedRows.sorted { 
        if $0.section != $1.section {
            return $0.section > $1.section
        }
        return $0.row > $1.row
    }
    
    // 删除选中的行
    for indexPath in sortedRows {
        sections[indexPath.section].items.remove(at: indexPath.row)
    }
    
    // 更新表格视图
    tableView.beginUpdates()
    tableView.deleteRows(at: sortedRows, with: .automatic)
    tableView.endUpdates()
    
    // 检查是否有空段，如果有则删除
    let emptySections = sections.enumerated().filter { $0.element.items.isEmpty }.map { $0.offset }
    let sortedSections = emptySections.sorted(by: >)
    
    for section in sortedSections {
        sections.remove(at: section)
    }
    
    if !sortedSections.isEmpty {
        tableView.deleteSections(IndexSet(sortedSections), with: .automatic)
    }
    
    // 退出编辑模式
    tableView.setEditing(false, animated: true)
}

// 在导航栏添加按钮
func setupToolbar() {
    navigationItem.rightBarButtonItem = editButtonItem
    
    // 创建工具栏按钮
    let deleteButton = UIBarButtonItem(title: "删除所选", style: .plain, target: self, action: #selector(deleteSelectedRows))
    let flexSpace = UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil)
    toolbarItems = [flexSpace, deleteButton, flexSpace]
    
    // 显示工具栏
    navigationController?.setToolbarHidden(false, animated: true)
}

// 响应编辑模式变化
override func setEditing(_ editing: Bool, animated: Bool) {
    super.setEditing(editing, animated: animated)
    tableView.setEditing(editing, animated: animated)
    
    // 更新工具栏可见性
    navigationController?.setToolbarHidden(!editing, animated: true)
}
```

## 表格性能优化

处理大量数据的表格视图可能会面临性能挑战。以下是提高表格性能的关键策略：

### 估算行高

使用估算行高可以显著提高表格的初始加载速度：

```swift
// 设置估算行高
tableView.estimatedRowHeight = 60
tableView.estimatedSectionHeaderHeight = 40
tableView.estimatedSectionFooterHeight = 30

// 使用自动维度
tableView.rowHeight = UITableView.automaticDimension
tableView.sectionHeaderHeight = UITableView.automaticDimension
tableView.sectionFooterHeight = UITableView.automaticDimension
```

### 异步加载内容

在后台线程加载图片和数据，避免阻塞主线程：

```swift
func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
    let cell = tableView.dequeueReusableCell(withIdentifier: cellID, for: indexPath) as! CustomCell
    
    // 配置基本文本
    let item = items[indexPath.row]
    cell.titleLabel.text = item.title
    cell.subtitleLabel.text = item.subtitle
    
    // 清除旧图片
    cell.customImageView.image = nil
    
    // 标记当前请求的索引路径
    let currentIndexPath = indexPath
    
    // 异步加载图片
    DispatchQueue.global().async {
        if let imageData = try? Data(contentsOf: item.imageURL) {
            let image = UIImage(data: imageData)
            
            // 切换回主线程更新 UI
            DispatchQueue.main.async {
                // 确保单元格仍然被用于显示同一行
                if let cell = tableView.cellForRow(at: currentIndexPath) as? CustomCell {
                    cell.customImageView.image = image
                }
            }
        }
    }
    
    return cell
}
```

### 预取内容

iOS 10+ 引入了预取 API，可以在行即将显示前预加载内容：

```swift
// 在视图控制器中启用预取
override func viewDidLoad() {
    super.viewDidLoad()
    
    // 设置表格视图
    tableView.prefetchDataSource = self
}

// 实现 UITableViewDataSourcePrefetching 协议
extension TableViewController: UITableViewDataSourcePrefetching {
    
    func tableView(_ tableView: UITableView, prefetchRowsAt indexPaths: [IndexPath]) {
        // 开始预加载指定行的数据
        for indexPath in indexPaths {
            let item = items[indexPath.row]
            ImagePrefetcher.shared.prefetchImage(at: item.imageURL)
        }
    }
    
    func tableView(_ tableView: UITableView, cancelPrefetchingForRowsAt indexPaths: [IndexPath]) {
        // 取消不再需要的预加载操作
        for indexPath in indexPaths {
            let item = items[indexPath.row]
            ImagePrefetcher.shared.cancelPrefetching(for: item.imageURL)
        }
    }
}

// 简单的图片预取器示例
class ImagePrefetcher {
    static let shared = ImagePrefetcher()
    private var prefetchTasks: [URL: URLSessionDataTask] = [:]
    private let imageCache = NSCache<NSURL, UIImage>()
    
    func prefetchImage(at url: URL) {
        // 如果已经在缓存中，则不需要预取
        if imageCache.object(forKey: url as NSURL) != nil {
            return
        }
        
        // 如果已经在预取中，则不需要重复预取
        if prefetchTasks[url] != nil {
            return
        }
        
        // 创建预取任务
        let task = URLSession.shared.dataTask(with: url) { [weak self] data, response, error in
            defer { self?.prefetchTasks[url] = nil }
            
            if let data = data, let image = UIImage(data: data) {
                self?.imageCache.setObject(image, forKey: url as NSURL)
            }
        }
        
        prefetchTasks[url] = task
        task.resume()
    }
    
    func cancelPrefetching(for url: URL) {
        prefetchTasks[url]?.cancel()
        prefetchTasks[url] = nil
    }
    
    func cachedImage(for url: URL) -> UIImage? {
        return imageCache.object(forKey: url as NSURL)
    }
}
```

### 内容预排版

使用预计算的单元格高度和缓存的布局信息：

```swift
// 存储预计算的高度
private var cachedHeights: [IndexPath: CGFloat] = [:]

// 计算并缓存单元格高度
func calculateHeightForCell(at indexPath: IndexPath, width: CGFloat) -> CGFloat {
    // 检查缓存
    if let cachedHeight = cachedHeights[indexPath] {
        return cachedHeight
    }
    
    // 获取数据
    let item = items[indexPath.row]
    
    // 创建临时标签计算高度
    let titleLabel = UILabel()
    titleLabel.font = UIFont.boldSystemFont(ofSize: 16)
    titleLabel.text = item.title
    
    let subtitleLabel = UILabel()
    subtitleLabel.font = UIFont.systemFont(ofSize: 14)
    subtitleLabel.numberOfLines = 0
    subtitleLabel.text = item.subtitle
    
    // 计算所需高度
    let titleHeight = titleLabel.sizeThatFits(CGSize(width: width - 30, height: .greatestFiniteMagnitude)).height
    let subtitleHeight = subtitleLabel.sizeThatFits(CGSize(width: width - 30, height: .greatestFiniteMagnitude)).height
    
    // 计算总高度（包括间距和内边距）
    let totalHeight = 20 + titleHeight + 8 + subtitleHeight + 20
    
    // 缓存高度
    cachedHeights[indexPath] = totalHeight
    
    return totalHeight
}

// 在 tableView(_:heightForRowAt:) 中使用
func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
    return calculateHeightForCell(at: indexPath, width: tableView.bounds.width)
}

// 在数据更新时清除缓存
func updateData(newItems: [Item]) {
    items = newItems
    cachedHeights.removeAll()
    tableView.reloadData()
}
```

### 轻量级单元格

保持单元格设计简单，减少子视图数量和层级深度：

```swift
class LightweightCell: UITableViewCell {
    
    // 使用少量子视图
    let containerView = UIView()
    let titleLabel = UILabel()
    let iconImageView = UIImageView()
    
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupViews()
    }
    
    private func setupViews() {
        // 添加容器视图而不是多个单独视图
        contentView.addSubview(containerView)
        containerView.translatesAutoresizingMaskIntoConstraints = false
        
        // 添加子视图到容器
        containerView.addSubview(titleLabel)
        containerView.addSubview(iconImageView)
        
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        iconImageView.translatesAutoresizingMaskIntoConstraints = false
        
        // 设置约束
        NSLayoutConstraint.activate([
            containerView.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 8),
            containerView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 15),
            containerView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -15),
            containerView.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -8),
            
            iconImageView.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
            iconImageView.centerYAnchor.constraint(equalTo: containerView.centerYAnchor),
            iconImageView.widthAnchor.constraint(equalToConstant: 30),
            iconImageView.heightAnchor.constraint(equalToConstant: 30),
            
            titleLabel.leadingAnchor.constraint(equalTo: iconImageView.trailingAnchor, constant: 12),
            titleLabel.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),
            titleLabel.centerYAnchor.constraint(equalTo: containerView.centerYAnchor)
        ])
        
        // 使用不透明视图减少合成操作
        containerView.isOpaque = true
        titleLabel.isOpaque = true
        iconImageView.isOpaque = true
        contentView.isOpaque = true
        backgroundColor = .white
    }
    
    // 避免不必要的布局计算
    override func prepareForReuse() {
        super.prepareForReuse()
        titleLabel.text = nil
        iconImageView.image = nil
    }
    
    // 避免不必要的约束计算
    override func layoutSubviews() {
        super.layoutSubviews()
        // 在这里进行简单的手动布局可以替代自动布局约束
        // 只有在需要复杂布局时才使用自动布局
    }
}
```

### 避免透明度和模糊效果

透明度和模糊效果会增加渲染负担：

```swift
// 不推荐：使用透明度和阴影
cell.contentView.alpha = 0.9
cell.layer.shadowOpacity = 0.3
cell.layer.shadowOffset = CGSize(width: 0, height: 2)
cell.layer.shadowRadius = 3

// 推荐：使用不透明视图和简单边框
cell.contentView.alpha = 1.0
cell.contentView.layer.borderWidth = 1
cell.contentView.layer.borderColor = UIColor.lightGray.cgColor
```

### 分批更新表格

处理大规模更新时，分批次更新表格以避免界面卡顿：

```swift
func updateTableWithLargeDataSet(newItems: [Item]) {
    // 分批次处理大量数据
    let batchSize = 50
    var updatedItems: [Item] = []
    
    // 分批次添加数据并更新表格
    for i in 0..<newItems.count {
        updatedItems.append(newItems[i])
        
        // 每达到批次大小或最后一个项目时更新表格
        if (i + 1) % batchSize == 0 || i == newItems.count - 1 {
            // 记录当前批次
            let currentBatch = updatedItems
            
            // 在主线程更新 UI
            DispatchQueue.main.async {
                // 更新数据源
                self.items.append(contentsOf: currentBatch)
                
                // 创建要插入的索引路径
                let startIndex = self.items.count - currentBatch.count
                let endIndex = self.items.count - 1
                let indexPaths = (startIndex...endIndex).map { IndexPath(row: $0, section: 0) }
                
                // 执行批量更新
                self.tableView.beginUpdates()
                self.tableView.insertRows(at: indexPaths, with: .automatic)
                self.tableView.endUpdates()
            }
            
            // 清空临时数组准备下一批
            updatedItems.removeAll()
        }
    }
}
```

## 自适应布局

现代 iOS 应用需要适应不同屏幕尺寸和方向。表格视图可以轻松实现自适应布局。

### 自动调整单元格尺寸

使用自动调整大小配置表格视图：

```swift
// 设置表格视图适应父视图
tableView.translatesAutoresizingMaskIntoConstraints = false
NSLayoutConstraint.activate([
    tableView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
    tableView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
    tableView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
    tableView.bottomAnchor.constraint(equalTo: view.bottomAnchor)
])

// 或使用自动调整掩码
tableView.frame = view.bounds
tableView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
```

### 适应不同设备和方向

根据设备尺寸和方向调整表格布局：

```swift
override func viewWillTransition(to size: CGSize, with coordinator: UIViewControllerTransitionCoordinator) {
    super.viewWillTransition(to: size, with: coordinator)
    
    coordinator.animate(alongsideTransition: { _ in
        // 在旋转过程中更新表格
        self.updateTableForNewSize(size)
    })
}

func updateTableForNewSize(_ size: CGSize) {
    // 清除高度缓存
    self.cachedHeights.removeAll()
    
    // 根据设备尺寸调整布局
    let isPortrait = size.height > size.width
    
    if UIDevice.current.userInterfaceIdiom == .pad {
        // iPad 特定布局
        if isPortrait {
            // iPad 竖屏布局
            tableView.separatorInset = UIEdgeInsets(top: 0, left: 20, bottom: 0, right: 20)
        } else {
            // iPad 横屏布局
            tableView.separatorInset = UIEdgeInsets(top: 0, left: 50, bottom: 0, right: 50)
        }
    } else {
        // iPhone 特定布局
        if isPortrait {
            // iPhone 竖屏布局
            tableView.separatorInset = UIEdgeInsets(top: 0, left: 15, bottom: 0, right: 15)
        } else {
            // iPhone 横屏布局
            tableView.separatorInset = UIEdgeInsets(top: 0, left: 20, bottom: 0, right: 20)
        }
    }
    
    // 重新加载表格视图以应用新的布局
    tableView.reloadData()
}

// 动态调整单元格内容
func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
    let cell = tableView.dequeueReusableCell(withIdentifier: cellID, for: indexPath) as! AdaptiveCell
    
    // 配置单元格
    cell.configure(with: items[indexPath.row])
    
    // 根据设备特性调整布局
    let isPortrait = view.bounds.height > view.bounds.width
    let isPad = UIDevice.current.userInterfaceIdiom == .pad
    
    if isPad {
        // iPad 特定布局
        cell.titleLabel.font = UIFont.boldSystemFont(ofSize: isPortrait ? 18 : 20)
        cell.contentInsets = isPortrait ? UIEdgeInsets(top: 15, left: 20, bottom: 15, right: 20) : 
                                         UIEdgeInsets(top: 20, left: 50, bottom: 20, right: 50)
    } else {
        // iPhone 特定布局
        cell.titleLabel.font = UIFont.boldSystemFont(ofSize: isPortrait ? 16 : 17)
        cell.contentInsets = isPortrait ? UIEdgeInsets(top: 10, left: 15, bottom: 10, right: 15) : 
                                         UIEdgeInsets(top: 12, left: 20, bottom: 12, right: 20)
    }
    
    return cell
}
```

### 特定屏幕大小配置

针对不同屏幕尺寸自定义表格视图：

```swift
// 在视图加载时应用设备特定配置
override func viewDidLoad() {
    super.viewDidLoad()
    
    setupTableView()
    applyDeviceSpecificSettings()
}

func applyDeviceSpecificSettings() {
    let screenWidth = UIScreen.main.bounds.width
    
    // 根据屏幕宽度调整表格配置
    if screenWidth >= 834 {  // iPad Pro 尺寸
        // 大屏幕 iPad 配置
        tableView.rowHeight = 80
        tableView.separatorInset = UIEdgeInsets(top: 0, left: 30, bottom: 0, right: 30)
        tableView.contentInset = UIEdgeInsets(top: 20, left: 0, bottom: 20, right: 0)
    } else if screenWidth >= 768 {  // 普通 iPad 尺寸
        // 标准 iPad 配置
        tableView.rowHeight = 70
        tableView.separatorInset = UIEdgeInsets(top: 0, left: 20, bottom: 0, right: 20)
        tableView.contentInset = UIEdgeInsets(top: 15, left: 0, bottom: 15, right: 0)
    } else if screenWidth >= 414 {  // 大屏幕 iPhone (Plus/Max)
        // 大屏幕 iPhone 配置
        tableView.rowHeight = 60
        tableView.separatorInset = UIEdgeInsets(top: 0, left: 15, bottom: 0, right: 15)
        tableView.contentInset = UIEdgeInsets(top: 10, left: 0, bottom: 10, right: 0)
    } else {  // 普通 iPhone
        // 标准 iPhone 配置
        tableView.rowHeight = 55
        tableView.separatorInset = UIEdgeInsets(top: 0, left: 15, bottom: 0, right: 15)
        tableView.contentInset = UIEdgeInsets(top: 8, left: 0, bottom: 8, right: 0)
    }
}
```

## 动态单元格高度

根据内容自动调整单元格高度可以提升用户体验。

### 自动维度

使用 Auto Layout 和自动维度实现动态高度：

```swift
// 在 viewDidLoad 中设置
override func viewDidLoad() {
    super.viewDidLoad()
    
    // 启用自动维度
    tableView.rowHeight = UITableView.automaticDimension
    tableView.estimatedRowHeight = 60
}

// 自定义单元格中的约束设置
class DynamicHeightCell: UITableViewCell {
    
    let titleLabel = UILabel()
    let contentLabel = UILabel()
    
    override init(style: UITableViewCell.CellStyle, reuseIdentifier: String?) {
        super.init(style: style, reuseIdentifier: reuseIdentifier)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupViews()
    }
    
    private func setupViews() {
        contentView.addSubview(titleLabel)
        contentView.addSubview(contentLabel)
        
        // 配置标签
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.font = UIFont.boldSystemFont(ofSize: 17)
        titleLabel.numberOfLines = 0  // 允许多行
        
        contentLabel.translatesAutoresizingMaskIntoConstraints = false
        contentLabel.font = UIFont.systemFont(ofSize: 15)
        contentLabel.numberOfLines = 0  // 允许多行
        contentLabel.textColor = .darkGray
        
        // 设置关键的自动布局约束
        NSLayoutConstraint.activate([
            // 标题标签约束
            titleLabel.topAnchor.constraint(equalTo: contentView.topAnchor, constant: 12),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            
            // 内容标签约束
            contentLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 8),
            contentLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 16),
            contentLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -16),
            contentLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -12)
        ])
    }
    
    func configure(with model: CellModel) {
        titleLabel.text = model.title
        contentLabel.text = model.content
    }
}
```

### 手动计算高度

对于复杂布局或旧版设备，可能需要手动计算高度：

```swift
// 手动提供行高
func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
    let item = items[indexPath.row]
    
    // 计算文本高度
    let titleFont = UIFont.boldSystemFont(ofSize: 17)
    let contentFont = UIFont.systemFont(ofSize: 15)
    
    let titleWidth = tableView.bounds.width - 32  // 减去左右边距
    let contentWidth = tableView.bounds.width - 32
    
    let titleHeight = calculateTextHeight(text: item.title, font: titleFont, width: titleWidth)
    let contentHeight = calculateTextHeight(text: item.content, font: contentFont, width: contentWidth)
    
    // 计算总高度（包括内边距和间距）
    let totalHeight = 12 + titleHeight + 8 + contentHeight + 12
    
    return totalHeight
}

// 计算文本高度的辅助方法
func calculateTextHeight(text: String, font: UIFont, width: CGFloat) -> CGFloat {
    let constraintRect = CGSize(width: width, height: .greatestFiniteMagnitude)
    let boundingBox = text.boundingRect(
        with: constraintRect,
        options: .usesLineFragmentOrigin,
        attributes: [.font: font],
        context: nil
    )
    
    return ceil(boundingBox.height)
}
```

### 缓存行高

对于大型表格，缓存行高可以提高性能：

```swift
// 缓存行高
private var cachedHeights: [Int: CGFloat] = [:]

func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
    // 检查缓存
    if let height = cachedHeights[indexPath.row] {
        return height
    }
    
    // 计算高度
    let item = items[indexPath.row]
    let titleFont = UIFont.boldSystemFont(ofSize: 17)
    let contentFont = UIFont.systemFont(ofSize: 15)
    let width = tableView.bounds.width - 32
    
    let titleHeight = calculateTextHeight(text: item.title, font: titleFont, width: width)
    let contentHeight = calculateTextHeight(text: item.content, font: contentFont, width: width)
    
    let totalHeight = 12 + titleHeight + 8 + contentHeight + 12
    
    // 缓存结果
    cachedHeights[indexPath.row] = totalHeight
    
    return totalHeight
}

// 在数据更改时清除缓存
func updateData() {
    cachedHeights.removeAll()
    tableView.reloadData()
}

// 处理旋转和尺寸变化
override func viewWillTransition(to size: CGSize, with coordinator: UIViewControllerTransitionCoordinator) {
    super.viewWillTransition(to: size, with: coordinator)
    
    // 清除缓存，因为宽度改变会影响高度计算
    cachedHeights.removeAll()
}
```

### 自定义动态高度单元格

使用原型单元格来计算高度：

```swift
class TableWithPrototypeCell: UIViewController, UITableViewDataSource, UITableViewDelegate {
    
    let tableView = UITableView()
    let cellID = "DynamicCell"
    var items: [CellModel] = []
    
    // 用于计算高度的原型单元格
    private let prototypeCellForHeightCalculation: DynamicHeightCell
    
    init() {
        // 初始化原型单元格
        prototypeCellForHeightCalculation = DynamicHeightCell(style: .default, reuseIdentifier: "PrototypeCell")
        super.init(nibName: nil, bundle: nil)
    }
    
    required init?(coder: NSCoder) {
        prototypeCellForHeightCalculation = DynamicHeightCell(style: .default, reuseIdentifier: "PrototypeCell")
        super.init(coder: coder)
    }
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.addSubview(tableView)
        tableView.frame = view.bounds
        tableView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        
        tableView.dataSource = self
        tableView.delegate = self
        
        tableView.register(DynamicHeightCell.self, forCellReuseIdentifier: cellID)
    }
    
    // 使用原型单元格计算高度
    func tableView(_ tableView: UITableView, heightForRowAt indexPath: IndexPath) -> CGFloat {
        let item = items[indexPath.row]
        
        // 配置原型单元格
        prototypeCellForHeightCalculation.configure(with: item)
        
        // 设置原型单元格宽度
        prototypeCellForHeightCalculation.bounds = CGRect(
            x: 0, y: 0, 
            width: tableView.bounds.width, 
            height: UITableView.automaticDimension
        )
        
        // 强制布局以确保所有约束已应用
        prototypeCellForHeightCalculation.layoutIfNeeded()
        
        // 计算并返回高度
        let height = prototypeCellForHeightCalculation.contentView.systemLayoutSizeFitting(
            CGSize(width: tableView.bounds.width, height: UIView.layoutFittingCompressedSize.height),
            withHorizontalFittingPriority: .required,
            verticalFittingPriority: .fittingSizeLevel
        ).height
        
        return height + 1  // 加1像素用于分隔线
    }
    
    // MARK: - UITableViewDataSource
    
    func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return items.count
    }
    
    func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: cellID, for: indexPath) as! DynamicHeightCell
        
        let item = items[indexPath.row]
        cell.configure(with: item)
        
        return cell
    }
}