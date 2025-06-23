# ToDo应用开发

本指南将带领你完成一个完整的Android ToDo应用开发过程，涵盖从设计到实现的各个方面。

## 应用概述

这个ToDo应用具有以下功能：
- 创建、查看、编辑和删除任务
- 设置任务优先级和截止日期
- 标记任务为已完成
- 按类别分组任务
- 本地数据持久化
- 简洁美观的Material Design界面

## 技术栈

- Kotlin语言
- MVVM架构
- Jetpack组件：Room、ViewModel、LiveData、Navigation
- Material Design组件
- Kotlin协程
- 单元测试和UI测试

## 开发步骤

### 1. 项目设置

创建一个新的Android项目：

```kotlin
// build.gradle (项目级)
buildscript {
    ext {
        kotlin_version = '1.6.10'
        room_version = '2.4.2'
        nav_version = '2.4.1'
    }
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath 'com.android.tools.build:gradle:7.1.2'
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
        classpath "androidx.navigation:navigation-safe-args-gradle-plugin:$nav_version"
    }
}

// build.gradle (应用级)
dependencies {
    implementation 'androidx.core:core-ktx:1.7.0'
    implementation 'androidx.appcompat:appcompat:1.4.1'
    implementation 'com.google.android.material:material:1.5.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.1.3'
    
    // Room
    implementation "androidx.room:room-runtime:$room_version"
    implementation "androidx.room:room-ktx:$room_version"
    kapt "androidx.room:room-compiler:$room_version"
    
    // Navigation
    implementation "androidx.navigation:navigation-fragment-ktx:$nav_version"
    implementation "androidx.navigation:navigation-ui-ktx:$nav_version"
    
    // ViewModel + LiveData
    implementation "androidx.lifecycle:lifecycle-viewmodel-ktx:2.4.1"
    implementation "androidx.lifecycle:lifecycle-livedata-ktx:2.4.1"
    
    // Testing
    testImplementation 'junit:junit:4.13.2'
    androidTestImplementation 'androidx.test.ext:junit:1.1.3'
    androidTestImplementation 'androidx.test.espresso:espresso-core:3.4.0'
}
```

### 2. 数据模型设计

创建Task数据类和Room数据库：

```kotlin
// Task.kt
@Entity(tableName = "tasks")
data class Task(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    var title: String,
    var description: String = "",
    var priority: Int = 0,  // 0: 低, 1: 中, 2: 高
    var dueDate: Long? = null,
    var category: String = "",
    var isCompleted: Boolean = false,
    val createdDate: Long = System.currentTimeMillis()
)

// TaskDao.kt
@Dao
interface TaskDao {
    @Query("SELECT * FROM tasks ORDER BY isCompleted, priority DESC, dueDate")
    fun getAllTasks(): Flow<List<Task>>
    
    @Query("SELECT * FROM tasks WHERE id = :taskId")
    fun getTaskById(taskId: Int): Flow<Task>
    
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertTask(task: Task): Long
    
    @Update
    suspend fun updateTask(task: Task)
    
    @Delete
    suspend fun deleteTask(task: Task)
    
    @Query("SELECT * FROM tasks WHERE category = :category")
    fun getTasksByCategory(category: String): Flow<List<Task>>
}

// AppDatabase.kt
@Database(entities = [Task::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun taskDao(): TaskDao
    
    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null
        
        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "todo_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
```

### 3. 仓库层

```kotlin
// TaskRepository.kt
class TaskRepository(private val taskDao: TaskDao) {
    val allTasks: Flow<List<Task>> = taskDao.getAllTasks()
    
    fun getTaskById(id: Int): Flow<Task> {
        return taskDao.getTaskById(id)
    }
    
    fun getTasksByCategory(category: String): Flow<List<Task>> {
        return taskDao.getTasksByCategory(category)
    }
    
    suspend fun insertTask(task: Task): Long {
        return taskDao.insertTask(task)
    }
    
    suspend fun updateTask(task: Task) {
        taskDao.updateTask(task)
    }
    
    suspend fun deleteTask(task: Task) {
        taskDao.deleteTask(task)
    }
}
```

### 4. ViewModel

```kotlin
// TaskViewModel.kt
class TaskViewModel(private val repository: TaskRepository) : ViewModel() {
    val allTasks: LiveData<List<Task>> = repository.allTasks.asLiveData()
    
    fun getTaskById(id: Int): LiveData<Task> {
        return repository.getTaskById(id).asLiveData()
    }
    
    fun getTasksByCategory(category: String): LiveData<List<Task>> {
        return repository.getTasksByCategory(category).asLiveData()
    }
    
    fun insertTask(task: Task) = viewModelScope.launch {
        repository.insertTask(task)
    }
    
    fun updateTask(task: Task) = viewModelScope.launch {
        repository.updateTask(task)
    }
    
    fun deleteTask(task: Task) = viewModelScope.launch {
        repository.deleteTask(task)
    }
    
    fun toggleTaskCompletion(task: Task) = viewModelScope.launch {
        val updatedTask = task.copy(isCompleted = !task.isCompleted)
        repository.updateTask(updatedTask)
    }
}

// TaskViewModelFactory.kt
class TaskViewModelFactory(private val repository: TaskRepository) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(TaskViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return TaskViewModel(repository) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}
```

### 5. UI实现

#### 主界面布局

```xml
<!-- fragment_task_list.xml -->
<?xml version="1.0" encoding="utf-8"?>
<androidx.coordinatorlayout.widget.CoordinatorLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent">

    <androidx.recyclerview.widget.RecyclerView
        android:id="@+id/recyclerView"
        android:layout_width="match_parent"
        android:layout_height="match_parent"
        app:layoutManager="androidx.recyclerview.widget.LinearLayoutManager"
        tools:listitem="@layout/item_task" />

    <com.google.android.material.floatingactionbutton.FloatingActionButton
        android:id="@+id/fab"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="bottom|end"
        android:layout_margin="16dp"
        android:contentDescription="@string/add_task"
        app:srcCompat="@drawable/ic_add" />

</androidx.coordinatorlayout.widget.CoordinatorLayout>
```

#### 任务列表Fragment

```kotlin
// TaskListFragment.kt
class TaskListFragment : Fragment() {
    private var _binding: FragmentTaskListBinding? = null
    private val binding get() = _binding!!
    
    private val taskViewModel: TaskViewModel by viewModels {
        TaskViewModelFactory((requireActivity().application as TodoApplication).repository)
    }
    
    private lateinit var adapter: TaskAdapter
    
    override fun onCreateView(
        inflater: LayoutInflater, 
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentTaskListBinding.inflate(inflater, container, false)
        return binding.root
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        adapter = TaskAdapter { task ->
            val action = TaskListFragmentDirections.actionTaskListToTaskDetail(task.id)
            findNavController().navigate(action)
        }
        
        binding.recyclerView.adapter = adapter
        
        taskViewModel.allTasks.observe(viewLifecycleOwner) { tasks ->
            adapter.submitList(tasks)
        }
        
        binding.fab.setOnClickListener {
            val action = TaskListFragmentDirections.actionTaskListToTaskEdit(0)
            findNavController().navigate(action)
        }
    }
    
    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
```

#### 任务编辑Fragment

```kotlin
// TaskEditFragment.kt
class TaskEditFragment : Fragment() {
    private var _binding: FragmentTaskEditBinding? = null
    private val binding get() = _binding!!
    
    private val args: TaskEditFragmentArgs by navArgs()
    private val taskViewModel: TaskViewModel by viewModels {
        TaskViewModelFactory((requireActivity().application as TodoApplication).repository)
    }
    
    private var task: Task? = null
    
    override fun onCreateView(
        inflater: LayoutInflater, 
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentTaskEditBinding.inflate(inflater, container, false)
        return binding.root
    }
    
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        val taskId = args.taskId
        if (taskId > 0) {
            taskViewModel.getTaskById(taskId).observe(viewLifecycleOwner) { loadedTask ->
                task = loadedTask
                populateUI()
            }
        }
        
        binding.saveButton.setOnClickListener {
            saveTask()
        }
    }
    
    private fun populateUI() {
        task?.let {
            binding.titleEditText.setText(it.title)
            binding.descriptionEditText.setText(it.description)
            binding.prioritySpinner.setSelection(it.priority)
            binding.categoryEditText.setText(it.category)
            // 设置日期选择器
        }
    }
    
    private fun saveTask() {
        val title = binding.titleEditText.text.toString()
        if (title.isEmpty()) {
            binding.titleEditText.error = "标题不能为空"
            return
        }
        
        val description = binding.descriptionEditText.text.toString()
        val priority = binding.prioritySpinner.selectedItemPosition
        val category = binding.categoryEditText.text.toString()
        
        if (task == null) {
            // 创建新任务
            val newTask = Task(
                title = title,
                description = description,
                priority = priority,
                category = category
            )
            taskViewModel.insertTask(newTask)
        } else {
            // 更新现有任务
            val updatedTask = task!!.copy(
                title = title,
                description = description,
                priority = priority,
                category = category
            )
            taskViewModel.updateTask(updatedTask)
        }
        
        findNavController().navigateUp()
    }
    
    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
```

### 6. 应用程序类

```kotlin
// TodoApplication.kt
class TodoApplication : Application() {
    val database by lazy { AppDatabase.getDatabase(this) }
    val repository by lazy { TaskRepository(database.taskDao()) }
}
```

## 扩展功能

完成基本功能后，可以考虑添加以下扩展功能：

1. **任务提醒**：使用AlarmManager或WorkManager实现截止日期提醒
2. **数据同步**：添加Firebase或自定义后端进行云同步
3. **主题切换**：支持浅色/深色主题
4. **小部件**：添加主屏幕小部件显示待办任务
5. **数据导入/导出**：支持任务列表的备份和恢复

## 测试

### 单元测试

```kotlin
// TaskDaoTest.kt
@RunWith(AndroidJUnit4::class)
class TaskDaoTest {
    private lateinit var database: AppDatabase
    private lateinit var taskDao: TaskDao
    
    @Before
    fun createDb() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(
            context, AppDatabase::class.java
        ).build()
        taskDao = database.taskDao()
    }
    
    @After
    fun closeDb() {
        database.close()
    }
    
    @Test
    fun insertAndGetTask() = runBlocking {
        val task = Task(title = "Test Task")
        val id = taskDao.insertTask(task)
        
        val tasks = taskDao.getAllTasks().first()
        assertEquals(1, tasks.size)
        assertEquals("Test Task", tasks[0].title)
    }
    
    // 更多测试...
}
```

### UI测试

```kotlin
// TaskListFragmentTest.kt
@RunWith(AndroidJUnit4::class)
class TaskListFragmentTest {
    @get:Rule
    val activityRule = ActivityScenarioRule(MainActivity::class.java)
    
    @Test
    fun clickAddTaskButton_navigatesToTaskEditFragment() {
        // 点击添加按钮
        onView(withId(R.id.fab)).perform(click())
        
        // 验证导航到了编辑页面
        onView(withId(R.id.titleEditText)).check(matches(isDisplayed()))
    }
    
    // 更多测试...
}
```

## 总结

通过本项目，你已经学习了如何使用现代Android开发技术栈构建一个完整的ToDo应用。这个项目涵盖了：

- Room数据库实现本地存储
- MVVM架构分离关注点
- Kotlin协程处理异步操作
- Navigation组件管理导航
- Material Design实现美观界面
- 单元测试和UI测试

这些技术和模式可以应用到更复杂的Android应用开发中。