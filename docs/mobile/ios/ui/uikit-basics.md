# UIKit 基础

UIKit 是 iOS 应用程序开发的核心框架，提供了构建和管理应用程序的图形界面、事件处理和应用程序基础结构所需的基础设施。本文将介绍 UIKit 的基本概念、常用视图和控制器。

## 目录

- [UIKit 框架概述](#uikit-框架概述)
- [视图基础](#视图基础)
- [常用 UI 控件](#常用-ui-控件)
- [视图控制器](#视图控制器)
- [导航与过渡](#导航与过渡)
- [用户交互与手势](#用户交互与手势)
- [自定义视图](#自定义视图)
- [实践建议](#实践建议)

## UIKit 框架概述

### 什么是 UIKit

UIKit 是 iOS 和 tvOS 应用程序用户界面、事件处理和应用程序基础结构的核心框架。它提供了窗口和视图架构、用于显示界面的基础设施，以及处理用户交互所需的事件控制系统。

UIKit 的主要功能包括：

- 管理视图和视图层次结构
- 处理用户输入和事件
- 管理应用程序生命周期
- 控制设备屏幕上的内容显示
- 支持多任务、打印和动画
- 辅助功能支持
- 用户通知处理

### UIKit 架构

UIKit 采用面向对象的架构，基于以下关键概念：

1. **MVC (Model-View-Controller)** 设计模式：
   - **Model**：应用程序的数据和业务逻辑
   - **View**：用户界面元素
   - **Controller**：协调模型和视图之间的交互

2. **委托模式 (Delegation)**：通过协议定义的对象间通信方式，使对象可以将特定任务委托给其他对象。

3. **目标-动作机制 (Target-Action)**：控件（如按钮）将操作消息发送到指定的目标对象。

4. **通知系统 (Notification)**：允许对象在发生特定事件时广播信息。

### UIKit 主要类层次结构

```
NSObject
  └── UIResponder (能响应和处理事件)
       ├── UIView (视图基类)
       │    ├── UIControl (控件基类)
       │    │    ├── UIButton
       │    │    ├── UITextField
       │    │    └── ...
       │    ├── UILabel
       │    ├── UIImageView
       │    └── ...
       ├── UIViewController (视图控制器基类)
       │    ├── UINavigationController
       │    ├── UITabBarController
       │    └── ...
       └── UIApplication (应用程序单例)
```

## 视图基础

### UIView 简介

`UIView` 是 UIKit 中所有视图的基类，负责在屏幕上绘制内容、处理触摸事件和管理子视图。每个 `UIView` 对象定义了屏幕上的一个矩形区域。

主要特性：

- **渲染内容**：在分配的矩形区域中绘制内容
- **布局管理**：管理子视图的位置和大小
- **事件处理**：接收和处理触摸事件
- **动画支持**：提供动画更改视图属性的能力

### 视图层次结构

iOS 应用中的界面由视图层次结构组成，这是一个树状结构，每个视图可以包含多个子视图：

```
UIWindow
  └── RootViewController.view
       ├── SubviewA
       │    ├── SubviewA1
       │    └── SubviewA2
       └── SubviewB
            └── SubviewB1
```

- **父视图 (Superview)**：包含其他视图的视图
- **子视图 (Subview)**：被其他视图包含的视图
- **同级视图 (Sibling views)**：共享相同父视图的视图

### 视图的基本属性

```swift
// 创建视图
let view = UIView(frame: CGRect(x: 50, y: 100, width: 200, height: 150))

// 设置基本属性
view.backgroundColor = .blue // 背景色
view.alpha = 0.8            // 透明度 (0-1)
view.isHidden = false       // 是否隐藏
view.tag = 100              // 标签值，用于标识视图
view.clipsToBounds = true   // 是否裁剪超出边界的内容

// 设置圆角
view.layer.cornerRadius = 10
```

### 视图的框架和边界

`UIView` 有两个表示其位置和大小的关键属性：

- **frame**：在父视图坐标系中的位置和大小
- **bounds**：在自身坐标系中的位置和大小
- **center**：在父视图坐标系中的中心点

```swift
// 使用 frame 设置视图位置和大小
view.frame = CGRect(x: 50, y: 100, width: 200, height: 150)

// 使用 bounds 设置视图的内部坐标系统
view.bounds = CGRect(x: 0, y: 0, width: 200, height: 150)

// 使用 center 设置视图中心点
view.center = CGPoint(x: 150, y: 200)
```

### 视图层次管理

```swift
// 添加子视图
parentView.addSubview(childView)

// 插入子视图到特定索引
parentView.insertSubview(childView, at: 2)

// 将子视图移到最前面
parentView.bringSubviewToFront(childView)

// 将子视图移到最后面
parentView.sendSubviewToBack(childView)

// 从父视图中移除
childView.removeFromSuperview()

// 获取子视图数量
let count = parentView.subviews.count

// 遍历所有子视图
for subview in parentView.subviews {
    print(subview)
}
```

### 坐标系转换

在复杂的视图层次中，经常需要在不同视图的坐标系之间转换点或矩形：

```swift
// 将点从一个视图的坐标系转换到另一个视图的坐标系
let pointInViewA = CGPoint(x: 10, y: 20)
let pointInViewB = viewA.convert(pointInViewA, to: viewB)

// 将矩形从一个视图的坐标系转换到另一个视图的坐标系
let rectInViewA = CGRect(x: 10, y: 20, width: 100, height: 50)
let rectInViewB = viewA.convert(rectInViewA, to: viewB)
```

### 布局系统

UIKit 提供两种主要的布局系统：

1. **Frame-based 布局**：通过直接设置视图的 frame 属性手动定位

2. **Auto Layout**：基于约束的自适应布局系统

```swift
// 使用 Auto Layout 创建约束
let leadingConstraint = childView.leadingAnchor.constraint(equalTo: parentView.leadingAnchor, constant: 20)
let topConstraint = childView.topAnchor.constraint(equalTo: parentView.topAnchor, constant: 20)
let widthConstraint = childView.widthAnchor.constraint(equalToConstant: 100)
let heightConstraint = childView.heightAnchor.constraint(equalToConstant: 50)

// 激活约束
NSLayoutConstraint.activate([
    leadingConstraint,
    topConstraint,
    widthConstraint,
    heightConstraint
])
```

## 常用 UI 控件

### UILabel

`UILabel` 用于显示一行或多行文本。

```swift
// 创建标签
let label = UILabel(frame: CGRect(x: 20, y: 100, width: 200, height: 40))

// 设置文本和属性
label.text = "Hello, UIKit!"
label.font = UIFont.systemFont(ofSize: 18, weight: .medium)
label.textColor = .darkGray
label.textAlignment = .center
label.numberOfLines = 2 // 0 表示不限制行数
label.lineBreakMode = .byTruncatingTail

// 添加到视图
view.addSubview(label)
```

### UIButton

`UIButton` 是用户可以点击以触发操作的控件。

```swift
// 创建按钮
let button = UIButton(type: .system)
button.frame = CGRect(x: 20, y: 150, width: 200, height: 40)

// 设置标题和图像
button.setTitle("点击我", for: .normal)
button.setTitleColor(.blue, for: .normal)
button.setTitleColor(.lightGray, for: .highlighted)
button.setImage(UIImage(named: "icon"), for: .normal)

// 设置背景色和圆角
button.backgroundColor = .white
button.layer.cornerRadius = 8
button.layer.borderWidth = 1
button.layer.borderColor = UIColor.blue.cgColor

// 添加事件处理
button.addTarget(self, action: #selector(buttonTapped), for: .touchUpInside)

// 事件处理方法
@objc func buttonTapped() {
    print("按钮被点击了")
}

// 添加到视图
view.addSubview(button)
```

### UITextField

`UITextField` 用于接收单行文本输入。

```swift
// 创建文本字段
let textField = UITextField(frame: CGRect(x: 20, y: 200, width: 200, height: 40))

// 设置外观
textField.placeholder = "请输入用户名"
textField.borderStyle = .roundedRect
textField.clearButtonMode = .whileEditing
textField.returnKeyType = .done
textField.keyboardType = .default
textField.isSecureTextEntry = false // 用于密码输入

// 设置委托
textField.delegate = self

// 添加到视图
view.addSubview(textField)
```

实现 `UITextFieldDelegate`：

```swift
// 文本字段委托方法
extension ViewController: UITextFieldDelegate {
    // 当用户点击 return 键时调用
    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        textField.resignFirstResponder() // 隐藏键盘
        return true
    }
    
    // 当文本将要改变时调用
    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        // 限制输入长度不超过 10 个字符
        let currentText = textField.text ?? ""
        guard let stringRange = Range(range, in: currentText) else { return false }
        let updatedText = currentText.replacingCharacters(in: stringRange, with: string)
        return updatedText.count <= 10
    }
}
```

### UITextView

`UITextView` 用于显示或编辑多行文本。

```swift
// 创建文本视图
let textView = UITextView(frame: CGRect(x: 20, y: 250, width: 200, height: 100))

// 设置外观和内容
textView.text = "这是一个多行文本编辑区域，可以输入大段文字。"
textView.font = UIFont.systemFont(ofSize: 14)
textView.textColor = .darkGray
textView.backgroundColor = .lightGray.withAlphaComponent(0.1)
textView.layer.cornerRadius = 5
textView.layer.borderWidth = 1
textView.layer.borderColor = UIColor.lightGray.cgColor
textView.isEditable = true
textView.isScrollEnabled = true

// 设置委托
textView.delegate = self

// 添加到视图
view.addSubview(textView)
```

### UIImageView

`UIImageView` 用于显示图像。

```swift
// 创建图像视图
let imageView = UIImageView(frame: CGRect(x: 20, y: 360, width: 200, height: 150))

// 设置图像
imageView.image = UIImage(named: "sample")
imageView.contentMode = .scaleAspectFit // 保持宽高比缩放
imageView.clipsToBounds = true // 裁剪超出边界的内容

// 启用用户交互（默认为 false）
imageView.isUserInteractionEnabled = true

// 添加到视图
view.addSubview(imageView)
```

### UISwitch

`UISwitch` 是一个开关控件，用于二元选择。

```swift
// 创建开关
let switchControl = UISwitch(frame: CGRect(x: 20, y: 520, width: 0, height: 0))

// 设置状态和颜色
switchControl.isOn = true
switchControl.onTintColor = .green
switchControl.thumbTintColor = .white

// 添加事件处理
switchControl.addTarget(self, action: #selector(switchValueChanged), for: .valueChanged)

// 事件处理方法
@objc func switchValueChanged(_ sender: UISwitch) {
    print("开关状态: \(sender.isOn)")
}

// 添加到视图
view.addSubview(switchControl)
```

### UISlider

`UISlider` 用于从连续值范围中选择值。

```swift
// 创建滑块
let slider = UISlider(frame: CGRect(x: 20, y: 560, width: 200, height: 20))

// 设置值范围和初始值
slider.minimumValue = 0
slider.maximumValue = 100
slider.value = 50

// 设置外观
slider.minimumTrackTintColor = .blue // 已滑过部分的颜色
slider.maximumTrackTintColor = .lightGray // 未滑过部分的颜色
slider.thumbTintColor = .white // 滑块颜色

// 添加事件处理
slider.addTarget(self, action: #selector(sliderValueChanged), for: .valueChanged)

// 事件处理方法
@objc func sliderValueChanged(_ sender: UISlider) {
    print("滑块值: \(sender.value)")
}

// 添加到视图
view.addSubview(slider)
```

### UISegmentedControl

`UISegmentedControl` 是一组互斥的按钮，用于显示离散的选择。

```swift
// 创建分段控件
let segmentedControl = UISegmentedControl(items: ["选项 1", "选项 2", "选项 3"])
segmentedControl.frame = CGRect(x: 20, y: 600, width: 200, height: 30)

// 设置初始选中项
segmentedControl.selectedSegmentIndex = 0

// 添加事件处理
segmentedControl.addTarget(self, action: #selector(segmentChanged), for: .valueChanged)

// 事件处理方法
@objc func segmentChanged(_ sender: UISegmentedControl) {
    print("选中的索引: \(sender.selectedSegmentIndex)")
}

// 添加到视图
view.addSubview(segmentedControl)
```

### UIActivityIndicatorView

`UIActivityIndicatorView` 显示任务正在进行中的旋转指示器。

```swift
// 创建活动指示器
let activityIndicator = UIActivityIndicatorView(style: .medium)
activityIndicator.center = CGPoint(x: 120, y: 650)

// 开始动画
activityIndicator.startAnimating()

// 如果需要隐藏停止时的指示器
activityIndicator.hidesWhenStopped = true

// 停止动画
// activityIndicator.stopAnimating()

// 添加到视图
view.addSubview(activityIndicator)
```

### UIProgressView

`UIProgressView` 显示任务完成的进度。

```swift
// 创建进度条
let progressView = UIProgressView(progressViewStyle: .default)
progressView.frame = CGRect(x: 20, y: 680, width: 200, height: 10)

// 设置进度和颜色
progressView.progress = 0.7 // 进度值范围 0.0 - 1.0
progressView.progressTintColor = .blue // 已完成部分的颜色
progressView.trackTintColor = .lightGray // 未完成部分的颜色

// 添加到视图
view.addSubview(progressView)
```

### UIAlertController

`UIAlertController` 用于显示警告或操作表。

```swift
// 创建警告框
let alertController = UIAlertController(
    title: "警告",
    message: "这是一个警告消息",
    preferredStyle: .alert
)

// 添加按钮
let cancelAction = UIAlertAction(title: "取消", style: .cancel) { _ in
    print("用户点击了取消")
}

let okAction = UIAlertAction(title: "确定", style: .default) { _ in
    print("用户点击了确定")
}

alertController.addAction(cancelAction)
alertController.addAction(okAction)

// 显示警告框
present(alertController, animated: true)
```

### UIPickerView

`UIPickerView` 显示一个或多个选择轮，用于选择值。

```swift
// 创建选择器视图
let pickerView = UIPickerView(frame: CGRect(x: 20, y: 700, width: 200, height: 150))

// 设置委托和数据源
pickerView.delegate = self
pickerView.dataSource = self

// 添加到视图
view.addSubview(pickerView)
```

实现 `UIPickerViewDelegate` 和 `UIPickerViewDataSource`：

```swift
// 选择器视图委托和数据源方法
extension ViewController: UIPickerViewDelegate, UIPickerViewDataSource {
    // 列数
    func numberOfComponents(in pickerView: UIPickerView) -> Int {
        return 1
    }
    
    // 每列的行数
    func pickerView(_ pickerView: UIPickerView, numberOfRowsInComponent component: Int) -> Int {
        return 10 // 示例数据
    }
    
    // 每行的标题
    func pickerView(_ pickerView: UIPickerView, titleForRow row: Int, forComponent component: Int) -> String? {
        return "选项 \(row + 1)"
    }
    
    // 选中某一行时的回调
    func pickerView(_ pickerView: UIPickerView, didSelectRow row: Int, inComponent component: Int) {
        print("选中了第 \(row + 1) 项")
    }
}
```

## 视图控制器

视图控制器是 iOS 应用程序的基本组织单元，负责管理视图层次结构、响应用户交互以及与应用程序的其他部分协调。

### UIViewController 简介

`UIViewController` 是所有视图控制器的基类，提供以下主要功能：

- 管理视图层次结构
- 响应视图的生命周期事件
- 处理布局和旋转
- 管理内存警告
- 协调与其他视图控制器的过渡

### 视图控制器的生命周期

视图控制器有一个明确定义的生命周期，包括以下主要事件：

1. **init/awakeFromNib**: 初始化阶段
2. **loadView**: 创建控制器的视图
3. **viewDidLoad**: 视图已加载到内存
4. **viewWillAppear**: 视图即将出现在屏幕上
5. **viewDidAppear**: 视图已出现在屏幕上
6. **viewWillDisappear**: 视图即将从屏幕上消失
7. **viewDidDisappear**: 视图已从屏幕上消失
8. **deinit**: 视图控制器即将被释放

生命周期方法示例：

```swift
class MyViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // 视图已加载到内存中，进行一次性设置
        print("视图已加载")
        setupUI()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // 视图即将显示，执行每次显示前的准备工作
        print("视图即将出现")
        refreshData()
    }
    
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        // 视图已显示，执行需要视图可见的操作
        print("视图已出现")
        startAnimations()
    }
    
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        // 视图即将消失，执行清理工作
        print("视图即将消失")
        pauseAnimations()
    }
    
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        // 视图已消失，执行额外清理
        print("视图已消失")
        clearTempData()
    }
    
    // 布局相关事件
    override func viewWillLayoutSubviews() {
        super.viewWillLayoutSubviews()
        // 子视图即将布局
        print("子视图即将布局")
    }
    
    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        // 子视图已完成布局
        print("子视图已布局完成")
    }
    
    // 视图尺寸变化
    override func viewWillTransition(to size: CGSize, with coordinator: UIViewControllerTransitionCoordinator) {
        super.viewWillTransition(to: size, with: coordinator)
        print("视图尺寸将变化为: \(size)")
    }
    
    // 内存警告
    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        print("接收到内存警告")
        // 释放非必要资源
    }
    
    // 辅助方法
    private func setupUI() {
        // 设置UI组件
    }
    
    private func refreshData() {
        // 刷新数据
    }
    
    private func startAnimations() {
        // 开始动画
    }
    
    private func pauseAnimations() {
        // 暂停动画
    }
    
    private func clearTempData() {
        // 清理临时数据
    }
}
```

### 创建视图控制器

有两种主要方式创建视图控制器：

1. **代码创建**：

```swift
// 创建视图控制器
let viewController = MyViewController()

// 设置属性
viewController.title = "我的视图"
viewController.modalPresentationStyle = .fullScreen

// 显示视图控制器
present(viewController, animated: true)
```

2. **从故事板加载**：

```swift
// 从主故事板加载
let storyboard = UIStoryboard(name: "Main", bundle: nil)
let viewController = storyboard.instantiateViewController(withIdentifier: "MyViewController") as! MyViewController

// 显示视图控制器
navigationController?.pushViewController(viewController, animated: true)
```

### 容器视图控制器

容器视图控制器用于管理其他视图控制器，形成视图控制器的层次结构。最常见的容器视图控制器包括：

#### UINavigationController

导航控制器管理视图控制器栈，提供在层次结构中导航的方法。

```swift
// 创建导航控制器
let rootViewController = MainViewController()
let navigationController = UINavigationController(rootViewController: rootViewController)

// 导航操作
navigationController.pushViewController(DetailViewController(), animated: true)
navigationController.popViewController(animated: true)
navigationController.popToRootViewController(animated: true)
```

#### UITabBarController

标签栏控制器管理一组可切换的视图控制器。

```swift
// 创建标签栏控制器
let tabBarController = UITabBarController()

// 创建视图控制器
let homeVC = HomeViewController()
homeVC.tabBarItem = UITabBarItem(tabBarSystemItem: .featured, tag: 0)

let searchVC = SearchViewController()
searchVC.tabBarItem = UITabBarItem(tabBarSystemItem: .search, tag: 1)

let profileVC = ProfileViewController()
profileVC.tabBarItem = UITabBarItem(title: "个人", image: UIImage(named: "profile"), tag: 2)

// 设置视图控制器数组
tabBarController.viewControllers = [homeVC, searchVC, profileVC]
```

#### UISplitViewController

分屏视图控制器在大屏幕设备上管理主-从界面。

```swift
// 创建分屏视图控制器
let masterVC = MasterViewController()
let detailVC = DetailViewController()
let splitViewController = UISplitViewController()

// 设置视图控制器
splitViewController.viewControllers = [
    UINavigationController(rootViewController: masterVC),
    UINavigationController(rootViewController: detailVC)
]
```

#### UIPageViewController

页面视图控制器管理页面之间的导航。

```swift
// 创建页面视图控制器
let pageViewController = UIPageViewController(
    transitionStyle: .scroll,
    navigationOrientation: .horizontal
)

// 设置数据源和委托
pageViewController.dataSource = self
pageViewController.delegate = self

// 设置初始页面
let initialVC = ContentViewController(pageIndex: 0)
pageViewController.setViewControllers([initialVC], direction: .forward, animated: false)
```

### 模态呈现

模态呈现是一种临时中断当前视图控制器流程的方式，强制用户完成某个任务或关注特定内容。

```swift
// 基本模态呈现
let viewController = ModalViewController()
present(viewController, animated: true)

// 设置呈现样式
viewController.modalPresentationStyle = .formSheet // 表单样式
viewController.modalTransitionStyle = .coverVertical // 覆盖过渡

// 关闭模态视图
dismiss(animated: true)
```

常用的模态呈现样式包括：

- `.fullScreen`: 全屏覆盖
- `.pageSheet`: 页面样式，适合 iPad
- `.formSheet`: 表单样式，居中显示
- `.popover`: 弹出窗口样式，通常用于 iPad
- `.automatic`: 根据环境自动选择样式
- `.custom`: 自定义呈现样式

## 导航与过渡

iOS 应用程序通常使用多种导航模式来组织内容和允许用户在不同屏幕之间移动。

### 导航控制器

导航控制器 (`UINavigationController`) 提供基于栈的导航模型，常用于分层内容。

```swift
// 设置导航栏外观
navigationController?.navigationBar.barTintColor = .white
navigationController?.navigationBar.tintColor = .blue
navigationController?.navigationBar.titleTextAttributes = [
    .foregroundColor: UIColor.darkGray,
    .font: UIFont.boldSystemFont(ofSize: 18)
]

// 设置当前视图控制器导航项
title = "主页"
navigationItem.rightBarButtonItem = UIBarButtonItem(
    barButtonSystemItem: .add,
    target: self,
    action: #selector(addButtonTapped)
)

// 显示和隐藏导航栏
navigationController?.setNavigationBarHidden(true, animated: true)
```

### 标签栏导航

标签栏控制器 (`UITabBarController`) 允许用户在应用程序的主要功能之间快速切换。

```swift
// 设置标签栏外观
tabBarController?.tabBar.tintColor = .blue
tabBarController?.tabBar.barTintColor = .white

// 自定义标签栏项
let tabItem = tabBarController?.tabBar.items?[0]
tabItem?.badgeValue = "5" // 显示角标
```

### 页面控制器

页面视图控制器 (`UIPageViewController`) 用于在相关内容页面之间滑动。

实现 `UIPageViewControllerDataSource`：

```swift
extension MainViewController: UIPageViewControllerDataSource {
    
    func pageViewController(_ pageViewController: UIPageViewController, viewControllerBefore viewController: UIViewController) -> UIViewController? {
        guard let contentVC = viewController as? ContentViewController else { return nil }
        let index = contentVC.pageIndex
        
        if index == 0 {
            return nil // 已经是第一页
        }
        
        // 返回前一页
        return ContentViewController(pageIndex: index - 1)
    }
    
    func pageViewController(_ pageViewController: UIPageViewController, viewControllerAfter viewController: UIViewController) -> UIViewController? {
        guard let contentVC = viewController as? ContentViewController else { return nil }
        let index = contentVC.pageIndex
        
        if index == totalPages - 1 {
            return nil // 已经是最后一页
        }
        
        // 返回后一页
        return ContentViewController(pageIndex: index + 1)
    }
}
```

### 自定义过渡动画

自定义过渡动画可以增强用户体验，使应用程序更具吸引力。

```swift
// 创建自定义过渡动画控制器
class FadeAnimationController: NSObject, UIViewControllerAnimatedTransitioning {
    
    func transitionDuration(using transitionContext: UIViewControllerContextTransitioning?) -> TimeInterval {
        return 0.5
    }
    
    func animateTransition(using transitionContext: UIViewControllerContextTransitioning) {
        guard let toVC = transitionContext.viewController(forKey: .to) else { return }
        let containerView = transitionContext.containerView
        
        toVC.view.alpha = 0.0
        containerView.addSubview(toVC.view)
        
        UIView.animate(withDuration: transitionDuration(using: transitionContext), animations: {
            toVC.view.alpha = 1.0
        }, completion: { finished in
            transitionContext.completeTransition(!transitionContext.transitionWasCancelled)
        })
    }
}

// 使用自定义动画控制器
class CustomTransitionDelegate: NSObject, UIViewControllerTransitioningDelegate {
    
    func animationController(forPresented presented: UIViewController, presenting: UIViewController, source: UIViewController) -> UIViewControllerAnimatedTransitioning? {
        return FadeAnimationController()
    }
    
    func animationController(forDismissed dismissed: UIViewController) -> UIViewControllerAnimatedTransitioning? {
        return FadeAnimationController()
    }
}

// 在视图控制器中使用
let transitionDelegate = CustomTransitionDelegate()
let modalVC = ModalViewController()
modalVC.transitioningDelegate = transitionDelegate
modalVC.modalPresentationStyle = .custom
present(modalVC, animated: true) 
```

## 用户交互与手势

UIKit 提供了丰富的机制来处理各种用户交互，包括触摸事件和手势识别。

### 响应者链

iOS 应用中的事件处理基于响应者链（Responder Chain）机制，它定义了事件如何从一个视图传递到另一个视图，直到被处理。

1. 首先，系统将事件发送到第一响应者（通常是用户触摸的视图）
2. 如果第一响应者不处理事件，事件会沿着响应者链向上传递
3. 链条通常遵循以下路径：触摸的视图 → 父视图 → 视图控制器 → 窗口 → 应用对象

```swift
// 响应触摸事件的基本方法
override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
    super.touchesBegan(touches, with: event)
    
    guard let touch = touches.first else { return }
    let location = touch.location(in: self)
    print("触摸开始于点: \(location)")
}

override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
    super.touchesMoved(touches, with: event)
    
    guard let touch = touches.first else { return }
    let location = touch.location(in: self)
    print("触摸移动到点: \(location)")
}

override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
    super.touchesEnded(touches, with: event)
    
    guard let touch = touches.first else { return }
    let location = touch.location(in: self)
    print("触摸结束于点: \(location)")
}

override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
    super.touchesCancelled(touches, with: event)
    print("触摸被取消")
}
```

### 手势识别器

手势识别器 (`UIGestureRecognizer`) 简化了复杂手势的处理，UIKit 提供了几种内置的手势识别器：

#### 点击手势

```swift
// 创建点击手势
let tapGesture = UITapGestureRecognizer(target: self, action: #selector(handleTap(_:)))
tapGesture.numberOfTapsRequired = 2 // 双击
tapGesture.numberOfTouchesRequired = 1 // 单指

// 添加到视图
imageView.addGestureRecognizer(tapGesture)
imageView.isUserInteractionEnabled = true // 确保视图可以交互

// 处理手势
@objc func handleTap(_ gesture: UITapGestureRecognizer) {
    let location = gesture.location(in: view)
    print("点击位置: \(location)")
    
    // 执行操作，如放大图片
    UIView.animate(withDuration: 0.3) {
        self.imageView.transform = CGAffineTransform(scaleX: 1.2, y: 1.2)
    }
}
```

#### 长按手势

```swift
// 创建长按手势
let longPressGesture = UILongPressGestureRecognizer(target: self, action: #selector(handleLongPress(_:)))
longPressGesture.minimumPressDuration = 1.0 // 1秒长按

// 添加到视图
view.addGestureRecognizer(longPressGesture)

// 处理手势
@objc func handleLongPress(_ gesture: UILongPressGestureRecognizer) {
    if gesture.state == .began {
        print("长按开始")
        // 显示上下文菜单
        showContextMenu(at: gesture.location(in: view))
    }
}
```

#### 滑动手势

```swift
// 创建滑动手势
let swipeGesture = UISwipeGestureRecognizer(target: self, action: #selector(handleSwipe(_:)))
swipeGesture.direction = .left // 设置滑动方向

// 添加到视图
view.addGestureRecognizer(swipeGesture)

// 处理手势
@objc func handleSwipe(_ gesture: UISwipeGestureRecognizer) {
    print("检测到滑动，方向: \(gesture.direction)")
    
    // 根据滑动方向执行不同操作
    switch gesture.direction {
    case .left:
        showNextItem()
    case .right:
        showPreviousItem()
    default:
        break
    }
}
```

#### 拖动手势

```swift
// 创建拖动手势
let panGesture = UIPanGestureRecognizer(target: self, action: #selector(handlePan(_:)))

// 添加到视图
draggableView.addGestureRecognizer(panGesture)

// 处理手势
@objc func handlePan(_ gesture: UIPanGestureRecognizer) {
    let translation = gesture.translation(in: view)
    
    // 更新视图位置
    if let dragView = gesture.view {
        dragView.center = CGPoint(
            x: dragView.center.x + translation.x,
            y: dragView.center.y + translation.y
        )
    }
    
    // 重置转换，避免累积
    gesture.setTranslation(.zero, in: view)
    
    // 手势状态处理
    switch gesture.state {
    case .began:
        print("拖动开始")
    case .changed:
        print("拖动中")
    case .ended:
        print("拖动结束")
    default:
        break
    }
}
```

#### 捏合手势

```swift
// 创建捏合手势
let pinchGesture = UIPinchGestureRecognizer(target: self, action: #selector(handlePinch(_:)))

// 添加到视图
imageView.addGestureRecognizer(pinchGesture)

// 处理手势
@objc func handlePinch(_ gesture: UIPinchGestureRecognizer) {
    // 缩放视图
    if let view = gesture.view {
        view.transform = view.transform.scaledBy(x: gesture.scale, y: gesture.scale)
        gesture.scale = 1.0 // 重置缩放比例，避免累积
    }
}
```

#### 旋转手势

```swift
// 创建旋转手势
let rotationGesture = UIRotationGestureRecognizer(target: self, action: #selector(handleRotation(_:)))

// 添加到视图
imageView.addGestureRecognizer(rotationGesture)

// 处理手势
@objc func handleRotation(_ gesture: UIRotationGestureRecognizer) {
    // 旋转视图
    if let view = gesture.view {
        view.transform = view.transform.rotated(by: gesture.rotation)
        gesture.rotation = 0 // 重置旋转角度，避免累积
    }
}
```

### 组合手势

有时需要组合多个手势同时工作，如缩放和旋转：

```swift
// 允许多个手势同时识别
pinchGesture.delegate = self
rotationGesture.delegate = self

// 实现手势识别器委托
extension ViewController: UIGestureRecognizerDelegate {
    // 允许手势同时识别
    func gestureRecognizer(_ gestureRecognizer: UIGestureRecognizer, shouldRecognizeSimultaneouslyWith otherGestureRecognizer: UIGestureRecognizer) -> Bool {
        // 允许捏合和旋转手势同时工作
        if (gestureRecognizer is UIPinchGestureRecognizer && otherGestureRecognizer is UIRotationGestureRecognizer) ||
           (gestureRecognizer is UIRotationGestureRecognizer && otherGestureRecognizer is UIPinchGestureRecognizer) {
            return true
        }
        return false
    }
}
```

## 自定义视图

创建自定义视图是 iOS 开发中的常见任务，它允许开发者创建可重用的 UI 组件。

### 基本自定义视图

最简单的自定义视图是继承 `UIView` 并重写必要的方法：

```swift
class CircleView: UIView {
    
    var circleColor: UIColor = .blue {
        didSet {
            setNeedsDisplay() // 属性变化时重绘
        }
    }
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        commonInit()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        commonInit()
    }
    
    private func commonInit() {
        backgroundColor = .clear
    }
    
    // 自定义绘制
    override func draw(_ rect: CGRect) {
        guard let context = UIGraphicsGetCurrentContext() else { return }
        
        // 计算圆心和半径
        let center = CGPoint(x: bounds.midX, y: bounds.midY)
        let radius = min(bounds.width, bounds.height) / 2 - 2
        
        // 绘制圆形
        context.setFillColor(circleColor.cgColor)
        context.addArc(center: center, radius: radius, startAngle: 0, endAngle: .pi * 2, clockwise: true)
        context.fillPath()
    }
}

// 使用自定义视图
let circleView = CircleView(frame: CGRect(x: 100, y: 100, width: 100, height: 100))
circleView.circleColor = .red
view.addSubview(circleView)
```

### 创建自定义 UIControl

自定义控件通常继承 `UIControl`，以支持目标-动作机制：

```swift
class RatingControl: UIControl {
    
    private var ratingButtons = [UIButton]()
    private let starCount = 5
    private let spacing: CGFloat = 5
    private let starSize: CGFloat = 30
    
    var rating = 0 {
        didSet {
            updateButtonSelectionStates()
            sendActions(for: .valueChanged)
        }
    }
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupButtons()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupButtons()
    }
    
    private func setupButtons() {
        // 清除现有按钮
        for button in ratingButtons {
            removeArrangedSubview(button)
        }
        ratingButtons.removeAll()
        
        // 加载按钮图像
        let emptyStarImage = UIImage(systemName: "star")
        let filledStarImage = UIImage(systemName: "star.fill")
        
        // 创建评分按钮
        for index in 0..<starCount {
            let button = UIButton()
            button.setImage(emptyStarImage, for: .normal)
            button.setImage(filledStarImage, for: .selected)
            button.tag = index
            
            // 添加动作
            button.addTarget(self, action: #selector(ratingButtonTapped), for: .touchUpInside)
            
            // 添加到视图和数组
            addSubview(button)
            ratingButtons.append(button)
        }
        
        updateButtonSelectionStates()
    }
    
    override func layoutSubviews() {
        super.layoutSubviews()
        
        // 设置按钮位置
        let buttonWidth = starSize
        let buttonHeight = starSize
        
        var buttonFrame = CGRect(x: 0, y: 0, width: buttonWidth, height: buttonHeight)
        
        for (index, button) in ratingButtons.enumerated() {
            buttonFrame.origin.x = CGFloat(index) * (buttonWidth + spacing)
            button.frame = buttonFrame
        }
    }
    
    override var intrinsicContentSize: CGSize {
        let buttonsTotalWidth = CGFloat(starCount) * starSize
        let buttonsSpacingWidth = CGFloat(starCount - 1) * spacing
        let width = buttonsTotalWidth + buttonsSpacingWidth
        return CGSize(width: width, height: starSize)
    }
    
    @objc private func ratingButtonTapped(_ sender: UIButton) {
        rating = sender.tag + 1
    }
    
    private func updateButtonSelectionStates() {
        for (index, button) in ratingButtons.enumerated() {
            button.isSelected = index < rating
        }
    }
    
    private func removeArrangedSubview(_ button: UIButton) {
        button.removeFromSuperview()
    }
}

// 使用自定义控件
let ratingControl = RatingControl()
ratingControl.center = view.center
ratingControl.addTarget(self, action: #selector(ratingChanged), for: .valueChanged)
view.addSubview(ratingControl)

@objc func ratingChanged(_ sender: RatingControl) {
    print("评分: \(sender.rating)")
}
```

### 使用 XIB 创建自定义视图

使用 XIB 文件可以更直观地设计自定义视图：

1. 创建一个新的 Swift 文件和对应的 XIB 文件
2. 在 XIB 中设计视图
3. 将 XIB 中的视图连接到 Swift 类

```swift
class CustomCardView: UIView {
    
    @IBOutlet weak var titleLabel: UILabel!
    @IBOutlet weak var descriptionLabel: UILabel!
    @IBOutlet weak var imageView: UIImageView!
    @IBOutlet private weak var contentView: UIView!
    
    var title: String? {
        didSet {
            titleLabel.text = title
        }
    }
    
    var descriptionText: String? {
        didSet {
            descriptionLabel.text = descriptionText
        }
    }
    
    var image: UIImage? {
        didSet {
            imageView.image = image
        }
    }
    
    override init(frame: CGRect) {
        super.init(frame: frame)
        setupFromNib()
    }
    
    required init?(coder: NSCoder) {
        super.init(coder: coder)
        setupFromNib()
    }
    
    private func setupFromNib() {
        // 加载 XIB
        let bundle = Bundle(for: CustomCardView.self)
        bundle.loadNibNamed("CustomCardView", owner: self, options: nil)
        
        // 添加内容视图
        contentView.frame = bounds
        contentView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        addSubview(contentView)
        
        // 设置圆角和阴影
        layer.cornerRadius = 8
        layer.shadowColor = UIColor.black.cgColor
        layer.shadowOffset = CGSize(width: 0, height: 2)
        layer.shadowOpacity = 0.2
        layer.shadowRadius = 4
    }
}

// 使用自定义卡片视图
let cardView = CustomCardView(frame: CGRect(x: 20, y: 200, width: view.bounds.width - 40, height: 150))
cardView.title = "自定义卡片"
cardView.descriptionText = "这是一个使用 XIB 创建的自定义卡片视图。"
cardView.image = UIImage(named: "card-image")
view.addSubview(cardView)
```

## 实践建议

### 性能优化

- **避免过深的视图层次**：视图层次越深，渲染性能越差
- **重用表格和集合视图的单元格**：使用 `dequeueReusableCell`
- **使用懒加载**：延迟创建视图直到需要时
- **最小化视图重绘**：避免频繁调用 `setNeedsDisplay`
- **离屏渲染**：尽量避免使用 `layer.masksToBounds` 和 `layer.cornerRadius` 的组合

```swift
// 懒加载示例
lazy var expensiveView: UIView = {
    let view = UIView()
    // 复杂设置...
    return view
}()

// 只在需要时访问
if needsExpensiveView {
    containerView.addSubview(expensiveView)
}
```

### 自适应布局

创建自适应布局以支持不同的屏幕尺寸和方向：

- 使用 Auto Layout 而不是硬编码的 frame
- 使用动态类型支持不同的字体大小
- 测试不同的尺寸类和屏幕方向
- 使用可变约束适应不同屏幕尺寸

```swift
// 设置动态字体
titleLabel.font = UIFont.preferredFont(forTextStyle: .title1)
descriptionLabel.font = UIFont.preferredFont(forTextStyle: .body)

// 启用自动调整
titleLabel.adjustsFontForContentSizeCategory = true
descriptionLabel.adjustsFontForContentSizeCategory = true

// 可变约束
NSLayoutConstraint.activate([
    // 紧凑宽度（如 iPhone 纵向）使用较小的边距
    contentView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20).withPriority(UILayoutPriority(900)),
    
    // 常规宽度（如 iPad）使用较大的边距
    contentView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 80).withPriority(UILayoutPriority(800))
])

// 辅助方法
extension NSLayoutConstraint {
    func withPriority(_ priority: UILayoutPriority) -> NSLayoutConstraint {
        self.priority = priority
        return self
    }
}
```

### 视图调试

- 使用 Xcode 的视图调试器可视化视图层次
- 使用视图标记和颜色进行区分
- 添加临时边框帮助布局调试

```swift
// 添加调试边框
#if DEBUG
view.layer.borderWidth = 1
view.layer.borderColor = UIColor.red.cgColor
#endif
```

### UIKit 与 SwiftUI 集成

UIKit 视图可以与 SwiftUI 集成，反之亦然：

```swift
// 在 SwiftUI 中使用 UIKit 视图
struct UIKitView: UIViewRepresentable {
    func makeUIView(context: Context) -> UIView {
        let view = CustomUIKitView()
        return view
    }
    
    func updateUIView(_ uiView: UIView, context: Context) {
        // 更新视图
    }
}

// 在 UIKit 中使用 SwiftUI 视图
import SwiftUI

class ViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // 创建 SwiftUI 视图
        let swiftUIView = UIHostingController(rootView: MySwiftUIView())
        
        // 添加为子视图控制器
        addChild(swiftUIView)
        view.addSubview(swiftUIView.view)
        
        // 配置约束
        swiftUIView.view.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            swiftUIView.view.topAnchor.constraint(equalTo: view.topAnchor),
            swiftUIView.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            swiftUIView.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            swiftUIView.view.bottomAnchor.constraint(equalTo: view.bottomAnchor)
        ])
        
        swiftUIView.didMove(toParent: self)
    }
}
```

## 总结

UIKit 是 iOS 开发的核心框架，掌握它的视图和控制器基础对于构建高质量的 iOS 应用程序至关重要。本文介绍了 UIKit 的基本概念、视图层次结构、常用控件、视图控制器生命周期、用户交互处理以及自定义视图的创建方法。

随着不断实践，您将能够更熟练地使用 UIKit 构建丰富、直观和高性能的用户界面。虽然 SwiftUI 是 Apple 为未来推出的新框架，但 UIKit 仍将在很长一段时间内保持其重要性，尤其是在处理复杂界面和与现有代码库集成时。

## 延伸阅读

- [UIKit 文档](https://developer.apple.com/documentation/uikit)
- [Auto Layout 指南](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/AutolayoutPG/)
- [iOS 人机界面指南](https://developer.apple.com/design/human-interface-guidelines/ios/overview/themes/)
- [视图控制器编程指南](https://developer.apple.com/library/archive/featuredarticles/ViewControllerPGforiPhoneOS/)