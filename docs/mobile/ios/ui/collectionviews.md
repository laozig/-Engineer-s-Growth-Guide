# 集合视图

集合视图（UICollectionView）是 iOS 中一个强大而灵活的 UI 组件，用于以网格、流式布局或自定义布局的方式展示数据项集合。相比表格视图（UITableView），集合视图提供了更多的布局自由度和定制能力。

## 目录

- [集合视图基础](#集合视图基础)
- [数据源与委托](#数据源与委托)
- [布局系统](#布局系统)
- [自定义单元格](#自定义单元格)
- [补充视图](#补充视图)
- [交互与选择](#交互与选择)
- [性能优化](#性能优化)
- [动画与转场](#动画与转场)
- [实践示例](#实践示例)
- [常见问题](#常见问题)

## 集合视图基础

### 什么是集合视图

集合视图是一个用于展示有序数据集合的视图，其中的每个项目用单元格（cell）表示。集合视图的主要特点包括：

- 高度可定制的布局方式（网格、流式、自定义等）
- 支持水平和垂直滚动
- 单元格和补充视图（装饰视图、页眉、页脚）
- 内置的选择、高亮和编辑功能
- 丰富的动画效果

### 创建集合视图

```swift
// 创建基本的集合视图
let layout = UICollectionViewFlowLayout()
layout.itemSize = CGSize(width: 100, height: 100)
layout.minimumLineSpacing = 10
layout.minimumInteritemSpacing = 10
layout.scrollDirection = .vertical

let collectionView = UICollectionView(frame: view.bounds, collectionViewLayout: layout)
collectionView.backgroundColor = .white
view.addSubview(collectionView)

// 设置数据源和委托
collectionView.dataSource = self
collectionView.delegate = self

// 注册单元格和补充视图
collectionView.register(MyCollectionViewCell.self, forCellWithReuseIdentifier: "Cell")
collectionView.register(
    MyHeaderView.self,
    forSupplementaryViewOfKind: UICollectionView.elementKindSectionHeader,
    withReuseIdentifier: "Header"
)
```

## 数据源与委托

### UICollectionViewDataSource

数据源协议负责提供集合视图需要显示的数据：

```swift
// 实现 UICollectionViewDataSource 协议
extension ViewController: UICollectionViewDataSource {
    // 返回分区数量
    func numberOfSections(in collectionView: UICollectionView) -> Int {
        return 3
    }
    
    // 返回每个分区的项目数量
    func collectionView(_ collectionView: UICollectionView, numberOfItemsInSection section: Int) -> Int {
        return itemsArray[section].count
    }
    
    // 配置并返回单元格
    func collectionView(_ collectionView: UICollectionView, cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
        let cell = collectionView.dequeueReusableCell(withReuseIdentifier: "Cell", for: indexPath) as! MyCollectionViewCell
        
        let item = itemsArray[indexPath.section][indexPath.item]
        cell.configure(with: item)
        
        return cell
    }
    
    // 配置并返回补充视图（页眉、页脚等）
    func collectionView(_ collectionView: UICollectionView, viewForSupplementaryElementOfKind kind: String, at indexPath: IndexPath) -> UICollectionReusableView {
        if kind == UICollectionView.elementKindSectionHeader {
            let headerView = collectionView.dequeueReusableSupplementaryView(
                ofKind: kind,
                withReuseIdentifier: "Header",
                for: indexPath
            ) as! MyHeaderView
            
            headerView.titleLabel.text = "Section \(indexPath.section)"
            return headerView
        }
        
        return UICollectionReusableView()
    }
}
```

### UICollectionViewDelegate

委托协议处理与集合视图的交互事件：

```swift
// 实现 UICollectionViewDelegate 协议
extension ViewController: UICollectionViewDelegate {
    // 单元格被选中
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        print("选中了第 \(indexPath.section) 分区的第 \(indexPath.item) 个项目")
        
        // 执行相应操作，如导航到详情页面
        let item = itemsArray[indexPath.section][indexPath.item]
        showDetailViewController(for: item)
    }
    
    // 单元格将要显示
    func collectionView(_ collectionView: UICollectionView, willDisplay cell: UICollectionViewCell, forItemAt indexPath: IndexPath) {
        // 可以添加显示动画
        cell.alpha = 0
        UIView.animate(withDuration: 0.3) {
            cell.alpha = 1
        }
    }
    
    // 高亮状态改变
    func collectionView(_ collectionView: UICollectionView, didHighlightItemAt indexPath: IndexPath) {
        if let cell = collectionView.cellForItem(at: indexPath) {
            UIView.animate(withDuration: 0.2) {
                cell.transform = CGAffineTransform(scaleX: 0.95, y: 0.95)
            }
        }
    }
    
    func collectionView(_ collectionView: UICollectionView, didUnhighlightItemAt indexPath: IndexPath) {
        if let cell = collectionView.cellForItem(at: indexPath) {
            UIView.animate(withDuration: 0.2) {
                cell.transform = .identity
            }
        }
    }
}
```

### UICollectionViewDelegateFlowLayout

当使用 `UICollectionViewFlowLayout` 时，这个委托协议允许自定义布局属性：

```swift
// 实现 UICollectionViewDelegateFlowLayout 协议
extension ViewController: UICollectionViewDelegateFlowLayout {
    // 项目尺寸
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, sizeForItemAt indexPath: IndexPath) -> CGSize {
        // 可以根据内容或索引路径返回不同尺寸
        let screenWidth = collectionView.bounds.width
        let itemWidth = (screenWidth - 30) / 2 // 两列布局，左右和中间各 10 点间距
        return CGSize(width: itemWidth, height: itemWidth)
    }
    
    // 分区内边距
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, insetForSectionAt section: Int) -> UIEdgeInsets {
        return UIEdgeInsets(top: 10, left: 10, bottom: 10, right: 10)
    }
    
    // 行间距
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, minimumLineSpacingForSectionAt section: Int) -> CGFloat {
        return 10
    }
    
    // 项目间距
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, minimumInteritemSpacingForSectionAt section: Int) -> CGFloat {
        return 10
    }
    
    // 页眉尺寸
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, referenceSizeForHeaderInSection section: Int) -> CGSize {
        return CGSize(width: collectionView.bounds.width, height: 50)
    }
    
    // 页脚尺寸
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, referenceSizeForFooterInSection section: Int) -> CGSize {
        return CGSize(width: collectionView.bounds.width, height: 30)
    }
}
```

## 布局系统

### UICollectionViewFlowLayout

流式布局是最常用的集合视图布局，它按行或列排列项目：

```swift
let flowLayout = UICollectionViewFlowLayout()

// 基本配置
flowLayout.scrollDirection = .vertical // 滚动方向（.vertical 或 .horizontal）
flowLayout.itemSize = CGSize(width: 100, height: 100) // 项目尺寸
flowLayout.minimumLineSpacing = 10 // 行间距
flowLayout.minimumInteritemSpacing = 8 // 项目间距
flowLayout.sectionInset = UIEdgeInsets(top: 10, left: 10, bottom: 10, right: 10) // 分区内边距

// 页眉页脚尺寸
flowLayout.headerReferenceSize = CGSize(width: collectionView.bounds.width, height: 50)
flowLayout.footerReferenceSize = CGSize(width: collectionView.bounds.width, height: 30)

// 应用布局
collectionView.collectionViewLayout = flowLayout
```

### 自定义布局

通过子类化 `UICollectionViewLayout` 可以创建完全自定义的布局：

```swift
class CircularLayout: UICollectionViewLayout {
    private var center: CGPoint = .zero
    private var radius: CGFloat = 200
    
    override func prepare() {
        super.prepare()
        center = CGPoint(x: collectionView!.bounds.midX, y: collectionView!.bounds.midY)
    }
    
    override var collectionViewContentSize: CGSize {
        return collectionView!.bounds.size
    }
    
    override func layoutAttributesForElements(in rect: CGRect) -> [UICollectionViewLayoutAttributes]? {
        guard let collectionView = collectionView else { return nil }
        
        var attributesArray: [UICollectionViewLayoutAttributes] = []
        let itemCount = collectionView.numberOfItems(inSection: 0)
        
        for item in 0..<itemCount {
            let indexPath = IndexPath(item: item, section: 0)
            if let attributes = layoutAttributesForItem(at: indexPath) {
                attributesArray.append(attributes)
            }
        }
        
        return attributesArray
    }
    
    override func layoutAttributesForItem(at indexPath: IndexPath) -> UICollectionViewLayoutAttributes? {
        let attributes = UICollectionViewLayoutAttributes(forCellWith: indexPath)
        
        // 计算圆形布局中的位置
        let itemCount = collectionView!.numberOfItems(inSection: 0)
        let angle = 2 * CGFloat.pi * CGFloat(indexPath.item) / CGFloat(itemCount)
        
        // 项目大小
        attributes.size = CGSize(width: 80, height: 80)
        
        // 项目位置（圆形排列）
        let x = center.x + radius * cos(angle)
        let y = center.y + radius * sin(angle)
        attributes.center = CGPoint(x: x, y: y)
        
        return attributes
    }
}

// 使用自定义布局
let circularLayout = CircularLayout()
collectionView.collectionViewLayout = circularLayout
```

### 组合布局（iOS 13+）

`UICollectionViewCompositionalLayout` 允许创建复杂的混合布局：

```swift
// 创建组合布局
let layout = UICollectionViewCompositionalLayout { (sectionIndex, environment) -> NSCollectionLayoutSection? in
    // 根据分区返回不同的布局
    switch sectionIndex {
    case 0:
        // 水平滚动的大型项目
        return self.createFeaturedSection()
    case 1:
        // 网格布局
        return self.createGridSection()
    case 2:
        // 水平列表
        return self.createHorizontalListSection()
    default:
        return self.createListSection()
    }
}

collectionView.collectionViewLayout = layout

// 特色横幅分区
private func createFeaturedSection() -> NSCollectionLayoutSection {
    // 项目
    let itemSize = NSCollectionLayoutSize(
        widthDimension: .fractionalWidth(1.0),
        heightDimension: .fractionalHeight(1.0)
    )
    let item = NSCollectionLayoutItem(layoutSize: itemSize)
    
    // 组
    let groupSize = NSCollectionLayoutSize(
        widthDimension: .fractionalWidth(0.9),
        heightDimension: .absolute(200)
    )
    let group = NSCollectionLayoutGroup.horizontal(layoutSize: groupSize, subitems: [item])
    
    // 分区
    let section = NSCollectionLayoutSection(group: group)
    section.orthogonalScrollingBehavior = .groupPaging
    section.interGroupSpacing = 10
    section.contentInsets = NSDirectionalEdgeInsets(top: 10, leading: 10, bottom: 10, trailing: 10)
    
    return section
}

// 网格分区
private func createGridSection() -> NSCollectionLayoutSection {
    // 项目
    let itemSize = NSCollectionLayoutSize(
        widthDimension: .fractionalWidth(0.5),
        heightDimension: .fractionalHeight(1.0)
    )
    let item = NSCollectionLayoutItem(layoutSize: itemSize)
    item.contentInsets = NSDirectionalEdgeInsets(top: 5, leading: 5, bottom: 5, trailing: 5)
    
    // 组
    let groupSize = NSCollectionLayoutSize(
        widthDimension: .fractionalWidth(1.0),
        heightDimension: .absolute(120)
    )
    let group = NSCollectionLayoutGroup.horizontal(layoutSize: groupSize, subitems: [item])
    
    // 分区
    let section = NSCollectionLayoutSection(group: group)
    section.contentInsets = NSDirectionalEdgeInsets(top: 10, leading: 10, bottom: 10, trailing: 10)
    
    // 页眉
    let headerSize = NSCollectionLayoutSize(
        widthDimension: .fractionalWidth(1.0),
        heightDimension: .absolute(44)
    )
    let header = NSCollectionLayoutBoundarySupplementaryItem(
        layoutSize: headerSize,
        elementKind: UICollectionView.elementKindSectionHeader,
        alignment: .top
    )
    section.boundarySupplementaryItems = [header]
    
    return section
}
```

## 自定义单元格

### 代码创建单元格

```swift
class PhotoCell: UICollectionViewCell {
    let imageView = UIImageView()
    let titleLabel = UILabel()
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupViews()
    }
    
    private func setupViews() {
        // 配置容器视图
        contentView.backgroundColor = .white
        contentView.layer.cornerRadius = 8
        contentView.layer.masksToBounds = true
        
        // 配置图像视图
        imageView.contentMode = .scaleAspectFill
        imageView.clipsToBounds = true
        contentView.addSubview(imageView)
        
        // 配置标题标签
        titleLabel.font = UIFont.systemFont(ofSize: 14, weight: .medium)
        titleLabel.textColor = .darkGray
        titleLabel.textAlignment = .center
        contentView.addSubview(titleLabel)
        
        // 设置约束
        imageView.translatesAutoresizingMaskIntoConstraints = false
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            imageView.topAnchor.constraint(equalTo: contentView.topAnchor),
            imageView.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            imageView.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            imageView.heightAnchor.constraint(equalTo: contentView.heightAnchor, multiplier: 0.8),
            
            titleLabel.topAnchor.constraint(equalTo: imageView.bottomAnchor, constant: 4),
            titleLabel.leadingAnchor.constraint(equalTo: contentView.leadingAnchor, constant: 4),
            titleLabel.trailingAnchor.constraint(equalTo: contentView.trailingAnchor, constant: -4),
            titleLabel.bottomAnchor.constraint(equalTo: contentView.bottomAnchor, constant: -4)
        ])
    }
    
    func configure(with photo: Photo) {
        imageView.image = photo.image
        titleLabel.text = photo.title
    }
    
    override func prepareForReuse() {
        super.prepareForReuse()
        // 重置单元格状态
        imageView.image = nil
        titleLabel.text = nil
    }
}
```

### Xib 创建单元格

1. 创建 Xib 文件和对应的类
2. 在 Xib 中设计单元格
3. 连接 IBOutlet
4. 注册和使用单元格

```swift
// 注册 Xib 单元格
collectionView.register(
    UINib(nibName: "PhotoCell", bundle: nil),
    forCellWithReuseIdentifier: "PhotoCell"
)

// 使用 Xib 单元格
func collectionView(_ collectionView: UICollectionView, cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
    let cell = collectionView.dequeueReusableCell(withReuseIdentifier: "PhotoCell", for: indexPath) as! PhotoCell
    cell.configure(with: photos[indexPath.item])
    return cell
}
```

## 补充视图

### 页眉和页脚

```swift
// 页眉类
class SectionHeaderView: UICollectionReusableView {
    let titleLabel = UILabel()
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupViews()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupViews()
    }
    
    private func setupViews() {
        backgroundColor = .systemGray6
        
        titleLabel.font = UIFont.systemFont(ofSize: 18, weight: .bold)
        titleLabel.textColor = .darkText
        addSubview(titleLabel)
        
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            titleLabel.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 15),
            titleLabel.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -15),
            titleLabel.centerYAnchor.constraint(equalTo: centerYAnchor)
        ])
    }
}

// 注册补充视图
collectionView.register(
    SectionHeaderView.self,
    forSupplementaryViewOfKind: UICollectionView.elementKindSectionHeader,
    withReuseIdentifier: "SectionHeader"
)

// 提供补充视图
func collectionView(_ collectionView: UICollectionView, viewForSupplementaryElementOfKind kind: String, at indexPath: IndexPath) -> UICollectionReusableView {
    if kind == UICollectionView.elementKindSectionHeader {
        let headerView = collectionView.dequeueReusableSupplementaryView(
            ofKind: kind,
            withReuseIdentifier: "SectionHeader",
            for: indexPath
        ) as! SectionHeaderView
        
        headerView.titleLabel.text = sectionTitles[indexPath.section]
        return headerView
    }
    
    return UICollectionReusableView()
}
```

### 装饰视图

装饰视图是布局的一部分，不与特定的数据项关联：

```swift
// 自定义布局中添加装饰视图
class CustomLayout: UICollectionViewLayout {
    // 装饰视图的布局属性
    override func layoutAttributesForElements(in rect: CGRect) -> [UICollectionViewLayoutAttributes]? {
        var allAttributes = super.layoutAttributesForElements(in: rect) ?? []
        
        // 添加分区背景装饰视图
        let sectionsInRect = NSIndexSet(
            indexesIn: NSRange(location: 0, length: collectionView!.numberOfSections)
        )
        
        sectionsInRect.forEach { section in
            let indexPath = IndexPath(item: 0, section: section)
            if let attributes = layoutAttributesForDecorationView(
                ofKind: "SectionBackground",
                at: indexPath
            ) {
                allAttributes.append(attributes)
            }
        }
        
        return allAttributes
    }
    
    // 装饰视图的布局属性
    override func layoutAttributesForDecorationView(
        ofKind elementKind: String,
        at indexPath: IndexPath
    ) -> UICollectionViewLayoutAttributes? {
        let attributes = UICollectionViewLayoutAttributes(
            forDecorationViewOfKind: elementKind,
            with: indexPath
        )
        
        // 设置装饰视图的位置和大小
        // ...
        
        return attributes
    }
    
    // 注册装饰视图
    override func register(nib: UINib?, forDecorationViewOfKind elementKind: String) {
        super.register(nib, forDecorationViewOfKind: elementKind)
    }
    
    override func register(
        _ viewClass: AnyClass?,
        forDecorationViewOfKind elementKind: String
    ) {
        super.register(viewClass, forDecorationViewOfKind: elementKind)
    }
}
```

## 交互与选择

### 单选与多选

```swift
// 配置选择模式
collectionView.allowsSelection = true
collectionView.allowsMultipleSelection = false // 设置为 true 允许多选

// 处理选择事件
func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
    let selectedItem = items[indexPath.item]
    // 处理选择逻辑
}

func collectionView(_ collectionView: UICollectionView, didDeselectItemAt indexPath: IndexPath) {
    // 处理取消选择逻辑
}

// 获取所有选中的项目
let selectedIndexPaths = collectionView.indexPathsForSelectedItems
```

### 长按手势

```swift
// 添加长按手势
func setupLongPressGesture() {
    let longPressGesture = UILongPressGestureRecognizer(
        target: self,
        action: #selector(handleLongPress)
    )
    longPressGesture.minimumPressDuration = 0.5
    collectionView.addGestureRecognizer(longPressGesture)
}

// 处理长按事件
@objc func handleLongPress(_ gesture: UILongPressGestureRecognizer) {
    let location = gesture.location(in: collectionView)
    
    switch gesture.state {
    case .began:
        if let indexPath = collectionView.indexPathForItem(at: location) {
            // 开始拖动
            collectionView.beginInteractiveMovementForItem(at: indexPath)
        }
    case .changed:
        // 更新位置
        collectionView.updateInteractiveMovementTargetPosition(location)
    case .ended:
        // 结束拖动
        collectionView.endInteractiveMovement()
    default:
        // 取消拖动
        collectionView.cancelInteractiveMovement()
    }
}

// 实现移动逻辑
func collectionView(
    _ collectionView: UICollectionView,
    moveItemAt sourceIndexPath: IndexPath,
    to destinationIndexPath: IndexPath
) {
    // 更新数据源
    let movedItem = items.remove(at: sourceIndexPath.item)
    items.insert(movedItem, at: destinationIndexPath.item)
}
```

## 性能优化

### 单元格重用

确保正确实现单元格重用机制：

```swift
// 在 prepareForReuse 中重置单元格状态
override func prepareForReuse() {
    super.prepareForReuse()
    imageView.image = nil
    titleLabel.text = nil
    activityIndicator.stopAnimating()
}

// 异步加载图像
func configureWithImage(url: URL) {
    // 显示加载指示器
    activityIndicator.startAnimating()
    
    // 异步加载图像
    DispatchQueue.global().async { [weak self] in
        guard let self = self else { return }
        
        if let data = try? Data(contentsOf: url),
           let image = UIImage(data: data) {
            
            DispatchQueue.main.async {
                // 确保单元格仍然显示相同的内容
                if self.imageUrl == url {
                    self.imageView.image = image
                    self.activityIndicator.stopAnimating()
                }
            }
        }
    }
}
```

### 预取 API

使用预取 API 提前加载内容：

```swift
// 实现预取数据源协议
extension ViewController: UICollectionViewDataSourcePrefetching {
    func collectionView(_ collectionView: UICollectionView, prefetchItemsAt indexPaths: [IndexPath]) {
        // 预取图像或数据
        for indexPath in indexPaths {
            let imageUrl = imageUrls[indexPath.item]
            ImagePrefetcher.shared.prefetchImage(at: imageUrl)
        }
    }
    
    func collectionView(_ collectionView: UICollectionView, cancelPrefetchingForItemsAt indexPaths: [IndexPath]) {
        // 取消预取
        for indexPath in indexPaths {
            let imageUrl = imageUrls[indexPath.item]
            ImagePrefetcher.shared.cancelPrefetching(for: imageUrl)
        }
    }
}

// 设置预取数据源
collectionView.prefetchDataSource = self
```

### 估算尺寸

使用估算尺寸提高滚动性能：

```swift
// 对于 UICollectionViewFlowLayout
let layout = UICollectionViewFlowLayout()
layout.estimatedItemSize = CGSize(width: 100, height: 100) // 估算尺寸
layout.itemSize = UICollectionViewFlowLayout.automaticSize // 自动计算实际尺寸

// 或者通过委托方法提供估算尺寸
func collectionView(
    _ collectionView: UICollectionView,
    layout collectionViewLayout: UICollectionViewLayout,
    estimatedSizeForItemAt indexPath: IndexPath
) -> CGSize {
    return CGSize(width: 100, height: 100)
}
```

## 动画与转场

### 批量更新

使用批量更新 API 执行多个更改：

```swift
// 批量更新
func updateData(newItems: [Item]) {
    collectionView.performBatchUpdates {
        // 删除项目
        let itemsToRemove = calculateItemsToRemove(newItems: newItems)
        collectionView.deleteItems(at: itemsToRemove)
        
        // 插入项目
        let itemsToInsert = calculateItemsToInsert(newItems: newItems)
        collectionView.insertItems(at: itemsToInsert)
        
        // 移动项目
        let itemsToMove = calculateItemsToMove(newItems: newItems)
        for move in itemsToMove {
            collectionView.moveItem(at: move.from, to: move.to)
        }
        
        // 更新数据源
        self.items = newItems
    } completion: { finished in
        if finished {
            // 批量更新完成后的操作
        }
    }
}
```

### 自定义转场动画

```swift
// 使用 UICollectionViewTransitionLayout 自定义转场
func collectionView(
    _ collectionView: UICollectionView,
    transitionLayoutForOldLayout fromLayout: UICollectionViewLayout,
    newLayout toLayout: UICollectionViewLayout
) -> UICollectionViewTransitionLayout {
    let customTransition = CustomTransitionLayout(
        currentLayout: fromLayout,
        nextLayout: toLayout
    )
    return customTransition
}

// 自定义转场布局
class CustomTransitionLayout: UICollectionViewTransitionLayout {
    override func updateValue(
        _ value: CGFloat,
        forAnimatedKey key: String
    ) {
        super.updateValue(value, forAnimatedKey: key)
        // 根据转场进度更新布局
        invalidateLayout()
    }
    
    override func layoutAttributesForElements(
        in rect: CGRect
    ) -> [UICollectionViewLayoutAttributes]? {
        // 混合起始布局和目标布局的属性
        let fromAttributes = super.layoutAttributesForElements(in: rect) ?? []
        // 自定义转场效果
        return fromAttributes
    }
}
```

## 实践示例

### 照片库应用示例

```swift
class PhotoGalleryViewController: UIViewController {
    private var collectionView: UICollectionView!
    private var photos: [Photo] = []
    
    override func viewDidLoad() {
        super.viewDidLoad()
        setupCollectionView()
        loadPhotos()
    }
    
    private func setupCollectionView() {
        // 创建布局
        let layout = UICollectionViewFlowLayout()
        layout.scrollDirection = .vertical
        layout.minimumLineSpacing = 1
        layout.minimumInteritemSpacing = 1
        
        // 创建集合视图
        collectionView = UICollectionView(frame: view.bounds, collectionViewLayout: layout)
        collectionView.backgroundColor = .white
        collectionView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(collectionView)
        
        // 设置委托
        collectionView.dataSource = self
        collectionView.delegate = self
        
        // 注册单元格
        collectionView.register(PhotoCell.self, forCellWithReuseIdentifier: "PhotoCell")
    }
    
    private func loadPhotos() {
        // 从服务器或本地加载照片
        PhotoService.shared.fetchPhotos { [weak self] result in
            switch result {
            case .success(let photos):
                self?.photos = photos
                self?.collectionView.reloadData()
            case .failure(let error):
                self?.showError(error)
            }
        }
    }
}

// MARK: - UICollectionViewDataSource
extension PhotoGalleryViewController: UICollectionViewDataSource {
    func collectionView(_ collectionView: UICollectionView, numberOfItemsInSection section: Int) -> Int {
        return photos.count
    }
    
    func collectionView(_ collectionView: UICollectionView, cellForItemAt indexPath: IndexPath) -> UICollectionViewCell {
        let cell = collectionView.dequeueReusableCell(withReuseIdentifier: "PhotoCell", for: indexPath) as! PhotoCell
        cell.configure(with: photos[indexPath.item])
        return cell
    }
}

// MARK: - UICollectionViewDelegateFlowLayout
extension PhotoGalleryViewController: UICollectionViewDelegateFlowLayout {
    func collectionView(_ collectionView: UICollectionView, layout collectionViewLayout: UICollectionViewLayout, sizeForItemAt indexPath: IndexPath) -> CGSize {
        let width = (collectionView.bounds.width - 2) / 3 // 3列布局
        return CGSize(width: width, height: width)
    }
    
    func collectionView(_ collectionView: UICollectionView, didSelectItemAt indexPath: IndexPath) {
        let photo = photos[indexPath.item]
        let detailVC = PhotoDetailViewController(photo: photo)
        navigationController?.pushViewController(detailVC, animated: true)
    }
}
```

## 常见问题

### 布局问题

1. **单元格尺寸不正确**
   - 确保正确实现了 `UICollectionViewDelegateFlowLayout` 方法
   - 检查约束和自动布局设置

2. **分组不均匀**
   - 检查内边距和间距设置
   - 考虑使用自定义布局

### 性能问题

1. **滚动卡顿**
   - 使用估算尺寸
   - 实现单元格重用机制
   - 异步加载内容
   - 避免复杂的单元格布局

2. **内存使用过高**
   - 缓存图像尺寸
   - 定期清理缓存
   - 延迟加载屏幕外的内容

### 其他常见问题

1. **单元格选择状态不保持**
   - 在 `cellForItemAt` 中手动维护选择状态

2. **补充视图不显示**
   - 确保在数据源方法中提供了补充视图
   - 检查布局中的页眉/页脚尺寸设置 