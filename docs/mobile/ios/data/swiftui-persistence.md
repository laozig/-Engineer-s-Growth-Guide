# SwiftUI 与数据持久化

本文将介绍如何在 SwiftUI 中整合各种数据持久化方案，实现高效、声明式的数据管理。

## 目录

- [SwiftUI 状态与持久化](#swiftui-状态与持久化)
- [@AppStorage](#appstorage)
- [SwiftData](#swiftdata)
- [Core Data 与 SwiftUI](#core-data-与-swiftui)
- [自定义持久化与 SwiftUI](#自定义持久化与-swiftui)
- [实战示例](#实战示例)

## SwiftUI 状态与持久化

SwiftUI 的声明式编程模型通过状态管理驱动 UI 渲染。将持久化数据与 SwiftUI 状态系统结合，能够创建响应式且数据驱动的应用程序。

### 状态管理回顾

SwiftUI 提供了多种状态管理方式：

```swift
// 视图内部状态
@State private var counter = 0

// 从外部传入的绑定
@Binding var name: String

// 引用类型的可观察对象
@ObservedObject var viewModel: ViewModel

// 环境值
@Environment(\.colorScheme) var colorScheme
@EnvironmentObject var appSettings: AppSettings

// 状态对象（自动创建并保持实例）
@StateObject var dataStore = DataStore()
```

## @AppStorage

`@AppStorage` 是 SwiftUI 提供的直接与 UserDefaults 集成的属性包装器。

### 基本用法

```swift
struct SettingsView: View {
    // 直接绑定到 UserDefaults
    @AppStorage("username") private var username = "Guest"
    @AppStorage("isDarkMode") private var isDarkMode = false
    @AppStorage("refreshInterval") private var refreshInterval = 60
    
    var body: some View {
        Form {
            TextField("用户名", text: $username)
            
            Toggle("深色模式", isOn: $isDarkMode)
            
            Picker("刷新间隔", selection: $refreshInterval) {
                Text("30秒").tag(30)
                Text("1分钟").tag(60)
                Text("5分钟").tag(300)
            }
        }
    }
}
```

### 自定义 UserDefaults 存储

```swift
struct SharedSettingsView: View {
    // 使用共享 UserDefaults
    @AppStorage("teamName", store: UserDefaults(suiteName: "group.com.company.app"))
    private var teamName = "未命名团队"
    
    var body: some View {
        TextField("团队名称", text: $teamName)
    }
}
```

### 存储复杂类型

使用 `RawRepresentable` 扩展存储枚举：

```swift
enum AppTheme: String, CaseIterable {
    case light, dark, system
}

extension AppTheme: RawRepresentable {}

struct ThemeSettingsView: View {
    @AppStorage("appTheme") private var appTheme = AppTheme.system
    
    var body: some View {
        Picker("主题", selection: $appTheme) {
            ForEach(AppTheme.allCases, id: \.self) { theme in
                Text(theme.rawValue.capitalized).tag(theme)
            }
        }
    }
}
```

对于复杂对象，创建自定义属性包装器：

```swift
struct CodableAppStorage<T: Codable>: DynamicProperty {
    @State private var value: T
    private let key: String
    private let store: UserDefaults
    
    init(wrappedValue: T, _ key: String, store: UserDefaults = .standard) {
        self.value = wrappedValue
        self.key = key
        self.store = store
        
        if let data = store.data(forKey: key),
           let value = try? JSONDecoder().decode(T.self, from: data) {
            self.value = value
        }
    }
    
    var wrappedValue: T {
        get { value }
        nonmutating set {
            value = newValue
            if let encoded = try? JSONEncoder().encode(newValue) {
                store.set(encoded, forKey: key)
            }
        }
    }
    
    var projectedValue: Binding<T> {
        Binding(
            get: { wrappedValue },
            set: { wrappedValue = $0 }
        )
    }
}

// 使用
struct UserProfile: Codable {
    var name: String
    var email: String
    var preferences: [String: Bool]
}

struct ProfileView: View {
    @CodableAppStorage("userProfile") private var profile = UserProfile(
        name: "Guest", 
        email: "", 
        preferences: [:]
    )
    
    var body: some View {
        Form {
            TextField("姓名", text: $profile.name)
            TextField("邮箱", text: $profile.email)
            
            Toggle("接收通知", isOn: Binding(
                get: { profile.preferences["notifications"] ?? true },
                set: { profile.preferences["notifications"] = $0 }
            ))
        }
    }
}
```

## SwiftData

SwiftData 是 iOS 17 引入的新框架，专为 SwiftUI 设计，提供声明式数据持久化。

### 基本设置

```swift
import SwiftUI
import SwiftData

// 定义模型
@Model
final class Todo {
    var title: String
    var isCompleted: Bool
    var createdAt: Date
    
    init(title: String, isCompleted: Bool = false) {
        self.title = title
        self.isCompleted = isCompleted
        self.createdAt = Date()
    }
}

// 配置 App
@main
struct TodoApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .modelContainer(for: Todo.self)
    }
}
```

### 在视图中使用

```swift
struct TodoListView: View {
    // 查询所有待办事项
    @Query private var todos: [Todo]
    
    // 带排序的查询
    @Query(sort: \Todo.createdAt, order: .reverse) 
    private var recentTodos: [Todo]
    
    // 带过滤的查询
    @Query(filter: #Predicate<Todo> { !$0.isCompleted })
    private var pendingTodos: [Todo]
    
    // 访问模型上下文
    @Environment(\.modelContext) private var context
    
    var body: some View {
        NavigationView {
            List {
                Section("待办事项") {
                    ForEach(pendingTodos) { todo in
                        Toggle(todo.title, isOn: $todo.isCompleted)
                    }
                    .onDelete(perform: deleteTodos)
                }
                
                Section("已完成") {
                    ForEach(todos.filter { $0.isCompleted }) { todo in
                        Text(todo.title)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .toolbar {
                Button("添加") {
                    addTodo()
                }
            }
        }
    }
    
    func addTodo() {
        let todo = Todo(title: "新待办事项")
        context.insert(todo)
    }
    
    func deleteTodos(at offsets: IndexSet) {
        for index in offsets {
            context.delete(pendingTodos[index])
        }
    }
}
```

### 高级功能

```swift
// 复杂查询和关系
@Model
final class Project {
    var name: String
    @Relationship(.cascade) var todos: [Todo]?
    
    init(name: String, todos: [Todo]? = nil) {
        self.name = name
        self.todos = todos
    }
}

// 带条件、排序和限制的查询
struct ProjectView: View {
    let project: Project
    
    @Query(sort: \Todo.createdAt, order: .forward)
    var allTodos: [Todo]
    
    var body: some View {
        VStack {
            // 实现项目视图
        }
        .onAppear {
            // 动态修改查询
            $allTodos.where(#Predicate {
                $0.project?.id == project.id
            })
        }
    }
}
```

## Core Data 与 SwiftUI

在 SwiftUI 中使用 Core Data 的方法。

### 基本设置

```swift
// 获取上下文
struct ContentView: View {
    @Environment(\.managedObjectContext) private var viewContext
    
    @FetchRequest(
        sortDescriptors: [NSSortDescriptor(keyPath: \Item.timestamp, ascending: true)],
        animation: .default)
    private var items: FetchedResults<Item>
    
    var body: some View {
        List {
            ForEach(items) { item in
                Text(item.timestamp!, formatter: itemFormatter)
            }
            .onDelete(perform: deleteItems)
        }
        .toolbar {
            Button(action: addItem) {
                Label("Add Item", systemImage: "plus")
            }
        }
    }
    
    private func addItem() {
        withAnimation {
            let newItem = Item(context: viewContext)
            newItem.timestamp = Date()

            do {
                try viewContext.save()
            } catch {
                let nsError = error as NSError
                fatalError("保存失败: \(nsError)")
            }
        }
    }
    
    private func deleteItems(offsets: IndexSet) {
        withAnimation {
            offsets.map { items[$0] }.forEach(viewContext.delete)

            do {
                try viewContext.save()
            } catch {
                let nsError = error as NSError
                fatalError("删除失败: \(nsError)")
            }
        }
    }
}
```

### 自定义 FetchRequest

```swift
struct FilteredTaskList: View {
    @FetchRequest private var tasks: FetchedResults<Task>
    
    init(priority: Int) {
        _tasks = FetchRequest<Task>(
            sortDescriptors: [
                SortDescriptor(\Task.dueDate, order: .forward)
            ],
            predicate: NSPredicate(format: "priority == %d", priority),
            animation: .default
        )
    }
    
    var body: some View {
        List(tasks) { task in
            TaskRow(task: task)
        }
    }
}

// 动态修改 FetchRequest
struct SearchableTaskList: View {
    @State private var searchText = ""
    @FetchRequest private var tasks: FetchedResults<Task>
    
    init() {
        _tasks = FetchRequest<Task>(
            sortDescriptors: [SortDescriptor(\Task.title)]
        )
    }
    
    var body: some View {
        List(tasks) { task in
            TaskRow(task: task)
        }
        .searchable(text: $searchText)
        .onChange(of: searchText) { oldValue, newValue in
            if newValue.isEmpty {
                tasks.nsPredicate = nil
            } else {
                tasks.nsPredicate = NSPredicate(
                    format: "title CONTAINS[cd] %@ OR notes CONTAINS[cd] %@", 
                    newValue, newValue
                )
            }
        }
    }
}
```

## 自定义持久化与 SwiftUI

将自定义持久化方案与 SwiftUI 集成。

### 使用 ObservableObject

```swift
// 定义一个可观察的数据存储
class DataStore: ObservableObject {
    @Published var notes: [Note] = []
    private let fileURL: URL
    
    init() {
        let documentsDirectory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = documentsDirectory.appendingPathComponent("notes.json")
        loadData()
    }
    
    func loadData() {
        do {
            let data = try Data(contentsOf: fileURL)
            notes = try JSONDecoder().decode([Note].self, from: data)
        } catch {
            print("加载数据失败: \(error)")
            // 如果文件不存在或解码失败，使用空数组
            notes = []
        }
    }
    
    func saveData() {
        do {
            let data = try JSONEncoder().encode(notes)
            try data.write(to: fileURL)
        } catch {
            print("保存数据失败: \(error)")
        }
    }
    
    func addNote(_ note: Note) {
        notes.append(note)
        saveData()
    }
    
    func deleteNote(at index: Int) {
        guard index < notes.count else { return }
        notes.remove(at: index)
        saveData()
    }
    
    func updateNote(_ note: Note) {
        if let index = notes.firstIndex(where: { $0.id == note.id }) {
            notes[index] = note
            saveData()
        }
    }
}

// 在 SwiftUI 中使用
struct NotesView: View {
    @StateObject private var dataStore = DataStore()
    @State private var newNoteText = ""
    
    var body: some View {
        VStack {
            List {
                ForEach(dataStore.notes) { note in
                    Text(note.text)
                }
                .onDelete { indexSet in
                    for index in indexSet {
                        dataStore.deleteNote(at: index)
                    }
                }
            }
            
            HStack {
                TextField("新笔记", text: $newNoteText)
                Button("添加") {
                    let note = Note(id: UUID(), text: newNoteText, date: Date())
                    dataStore.addNote(note)
                    newNoteText = ""
                }
                .disabled(newNoteText.isEmpty)
            }
            .padding()
        }
    }
}
```

### 使用环境对象共享数据

```swift
// 在 App 级别提供数据存储
@main
struct NotesApp: App {
    @StateObject private var dataStore = DataStore()
    
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(dataStore)
        }
    }
}

// 在视图中使用
struct ContentView: View {
    @EnvironmentObject var dataStore: DataStore
    
    var body: some View {
        TabView {
            NotesListView()
                .tabItem {
                    Label("笔记", systemImage: "note.text")
                }
            
            SettingsView()
                .tabItem {
                    Label("设置", systemImage: "gear")
                }
        }
    }
}

struct NotesListView: View {
    @EnvironmentObject var dataStore: DataStore
    
    var body: some View {
        NavigationView {
            List {
                ForEach(dataStore.notes) { note in
                    NavigationLink(destination: NoteDetailView(note: note)) {
                        Text(note.text)
                    }
                }
            }
            .navigationTitle("我的笔记")
        }
    }
}
```

## 实战示例

### 任务管理应用

结合 SwiftData 实现一个任务管理应用：

```swift
import SwiftUI
import SwiftData

@Model
final class Task {
    var title: String
    var isCompleted: Bool
    var priority: Priority
    var dueDate: Date?
    var notes: String?
    var tags: [String]
    
    init(title: String, priority: Priority = .normal, dueDate: Date? = nil) {
        self.title = title
        self.isCompleted = false
        self.priority = priority
        self.dueDate = dueDate
        self.tags = []
    }
    
    enum Priority: Int, Codable, CaseIterable {
        case low = 0
        case normal = 1
        case high = 2
        
        var label: String {
            switch self {
            case .low: return "低"
            case .normal: return "中"
            case .high: return "高"
            }
        }
        
        var color: Color {
            switch self {
            case .low: return .blue
            case .normal: return .green
            case .high: return .red
            }
        }
    }
}

struct TasksView: View {
    @Environment(\.modelContext) private var context
    @Query private var tasks: [Task]
    @State private var showingAddTask = false
    @State private var filterPriority: Task.Priority?
    
    var filteredTasks: [Task] {
        if let priority = filterPriority {
            return tasks.filter { $0.priority == priority }
        }
        return tasks
    }
    
    var body: some View {
        NavigationStack {
            VStack {
                // 优先级过滤器
                HStack {
                    Text("优先级过滤:")
                    ForEach(Task.Priority.allCases, id: \.self) { priority in
                        Button(priority.label) {
                            filterPriority = (filterPriority == priority) ? nil : priority
                        }
                        .padding(6)
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(filterPriority == priority ? priority.color : Color.gray.opacity(0.2))
                        )
                        .foregroundColor(filterPriority == priority ? .white : .primary)
                    }
                    
                    if filterPriority != nil {
                        Button("清除") {
                            filterPriority = nil
                        }
                    }
                }
                .padding(.horizontal)
                
                List {
                    ForEach(filteredTasks) { task in
                        TaskRow(task: task)
                    }
                    .onDelete(perform: deleteTasks)
                }
                .listStyle(.plain)
            }
            .navigationTitle("任务列表")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showingAddTask = true
                    } label: {
                        Image(systemName: "plus")
                    }
                }
            }
            .sheet(isPresented: $showingAddTask) {
                AddTaskView()
            }
        }
    }
    
    func deleteTasks(at offsets: IndexSet) {
        for index in offsets {
            context.delete(filteredTasks[index])
        }
    }
}

struct TaskRow: View {
    @Bindable var task: Task
    
    var body: some View {
        HStack {
            Button {
                task.isCompleted.toggle()
            } label: {
                Image(systemName: task.isCompleted ? "checkmark.circle.fill" : "circle")
                    .foregroundColor(task.isCompleted ? .green : .gray)
            }
            .buttonStyle(.plain)
            
            VStack(alignment: .leading) {
                Text(task.title)
                    .strikethrough(task.isCompleted)
                    .foregroundColor(task.isCompleted ? .gray : .primary)
                
                if let dueDate = task.dueDate {
                    Text(dueDate, style: .date)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
            
            Circle()
                .fill(task.priority.color)
                .frame(width: 12, height: 12)
        }
    }
}

struct AddTaskView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.modelContext) private var context
    
    @State private var title = ""
    @State private var priority = Task.Priority.normal
    @State private var dueDate: Date?
    @State private var notes = ""
    @State private var showDueDate = false
    
    var body: some View {
        NavigationStack {
            Form {
                TextField("任务标题", text: $title)
                
                Picker("优先级", selection: $priority) {
                    ForEach(Task.Priority.allCases, id: \.self) { priority in
                        Text(priority.label).tag(priority)
                    }
                }
                
                Toggle("设置截止日期", isOn: Binding(
                    get: { showDueDate },
                    set: { 
                        showDueDate = $0
                        if showDueDate && dueDate == nil {
                            dueDate = Date()
                        }
                    }
                ))
                
                if showDueDate {
                    DatePicker("截止日期", selection: Binding(
                        get: { dueDate ?? Date() },
                        set: { dueDate = $0 }
                    ), displayedComponents: .date)
                }
                
                Section("备注") {
                    TextEditor(text: $notes)
                        .frame(minHeight: 100)
                }
            }
            .navigationTitle("添加任务")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") {
                        dismiss()
                    }
                }
                
                ToolbarItem(placement: .confirmationAction) {
                    Button("保存") {
                        let task = Task(title: title, priority: priority, dueDate: showDueDate ? dueDate : nil)
                        task.notes = notes.isEmpty ? nil : notes
                        context.insert(task)
                        dismiss()
                    }
                    .disabled(title.isEmpty)
                }
            }
        }
    }
}
```

通过结合 SwiftUI 的声明式 UI 与各种数据持久化方案，可以创建出高效、响应式的应用程序，同时简化数据管理的复杂性。选择合适的持久化方案和集成方式对于不同类型的应用至关重要。 