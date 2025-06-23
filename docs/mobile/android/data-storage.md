# Android数据存储与访问

Android提供了多种方式来存储和访问应用数据。本文档将介绍常见的数据存储方式，从简单的键值对存储到复杂的数据库操作。

## SharedPreferences

SharedPreferences是一种轻量级的键值对存储机制，适用于存储少量的简单数据，如用户设置、登录状态等。

### 基本使用

```kotlin
// 获取SharedPreferences实例
val sharedPref = getSharedPreferences("app_preferences", Context.MODE_PRIVATE)

// 写入数据
val editor = sharedPref.edit()
editor.putString("username", "张三")
editor.putInt("age", 25)
editor.putBoolean("is_logged_in", true)
editor.apply() // 异步提交
// 或者 editor.commit() // 同步提交

// 读取数据
val username = sharedPref.getString("username", "") // 第二个参数是默认值
val age = sharedPref.getInt("age", 0)
val isLoggedIn = sharedPref.getBoolean("is_logged_in", false)

// 删除数据
editor.remove("username")
editor.apply()

// 清除所有数据
editor.clear()
editor.apply()
```

## 文件存储

Android提供了多种文件存储方式，可以存储文本文件、图像、音频等数据。

### 内部存储

内部存储是应用私有的存储空间，其他应用无法访问，当应用卸载时，这些文件会被删除。

```kotlin
// 写入文件
fun writeToInternalFile(filename: String, data: String) {
    try {
        val fileOutputStream = openFileOutput(filename, Context.MODE_PRIVATE)
        fileOutputStream.write(data.toByteArray())
        fileOutputStream.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}

// 读取文件
fun readFromInternalFile(filename: String): String {
    val stringBuilder = StringBuilder()
    try {
        val fileInputStream = openFileInput(filename)
        val inputStreamReader = InputStreamReader(fileInputStream)
        val bufferedReader = BufferedReader(inputStreamReader)
        var line: String?
        while (bufferedReader.readLine().also { line = it } != null) {
            stringBuilder.append(line)
        }
        fileInputStream.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return stringBuilder.toString()
}
```

### 外部存储

外部存储可以被其他应用访问，适合存储共享文件，如图片、下载的文档等。

```kotlin
// 检查外部存储是否可用
fun isExternalStorageWritable(): Boolean {
    return Environment.getExternalStorageState() == Environment.MEDIA_MOUNTED
}

// 写入文件到应用专有的外部存储目录
fun writeToExternalFile(filename: String, data: String) {
    if (isExternalStorageWritable()) {
        val file = File(getExternalFilesDir(null), filename)
        try {
            FileOutputStream(file).use { stream ->
                stream.write(data.toByteArray())
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }
}
```

## SQLite数据库

SQLite是Android内置的关系型数据库，适合存储结构化数据。

### 使用SQLiteOpenHelper

```kotlin
// 数据库帮助类
class DatabaseHelper(context: Context) : SQLiteOpenHelper(
    context, DATABASE_NAME, null, DATABASE_VERSION
) {
    companion object {
        private const val DATABASE_NAME = "app_database"
        private const val DATABASE_VERSION = 1
        private const val TABLE_NAME = "users"
        private const val COLUMN_ID = "id"
        private const val COLUMN_NAME = "name"
        private const val COLUMN_EMAIL = "email"
    }
    
    override fun onCreate(db: SQLiteDatabase) {
        val createTableQuery = """
            CREATE TABLE $TABLE_NAME (
                $COLUMN_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COLUMN_NAME TEXT,
                $COLUMN_EMAIL TEXT
            )
        """.trimIndent()
        db.execSQL(createTableQuery)
    }
    
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_NAME")
        onCreate(db)
    }
    
    // 添加用户
    fun addUser(name: String, email: String): Long {
        val db = writableDatabase
        val values = ContentValues().apply {
            put(COLUMN_NAME, name)
            put(COLUMN_EMAIL, email)
        }
        val id = db.insert(TABLE_NAME, null, values)
        db.close()
        return id
    }
    
    // 获取所有用户
    fun getAllUsers(): List<User> {
        val userList = mutableListOf<User>()
        val selectQuery = "SELECT * FROM $TABLE_NAME"
        val db = readableDatabase
        val cursor = db.rawQuery(selectQuery, null)
        
        if (cursor.moveToFirst()) {
            do {
                val id = cursor.getInt(cursor.getColumnIndexOrThrow(COLUMN_ID))
                val name = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_NAME))
                val email = cursor.getString(cursor.getColumnIndexOrThrow(COLUMN_EMAIL))
                userList.add(User(id, name, email))
            } while (cursor.moveToNext())
        }
        
        cursor.close()
        db.close()
        return userList
    }
}

// 用户模型类
data class User(val id: Int, val name: String, val email: String)
```

### 使用Room持久化库

Room是Android Jetpack的一部分，提供了一个抽象层来简化SQLite操作：

```kotlin
// 实体类
@Entity(tableName = "users")
data class User(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    @ColumnInfo(name = "name") val name: String,
    @ColumnInfo(name = "email") val email: String
)

// DAO接口
@Dao
interface UserDao {
    @Insert
    suspend fun insert(user: User): Long
    
    @Query("SELECT * FROM users")
    suspend fun getAllUsers(): List<User>
    
    @Update
    suspend fun updateUser(user: User): Int
    
    @Delete
    suspend fun deleteUser(user: User): Int
}

// 数据库类
@Database(entities = [User::class], version = 1)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
    
    companion object {
        @Volatile
        private var INSTANCE: AppDatabase? = null
        
        fun getDatabase(context: Context): AppDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    AppDatabase::class.java,
                    "app_database"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}
```

## 总结

Android提供了多种数据存储方式，每种方式都有其适用场景：

- **SharedPreferences**：适用于存储少量的简单键值对数据
- **文件存储**：适用于存储原始文件数据，如文本、图像等
- **SQLite数据库**：适用于存储结构化数据
- **Room**：提供了SQLite的抽象层，简化数据库操作

选择合适的存储方式取决于应用的需求、数据复杂性和性能要求。

## 下一步学习

- [网络编程](networking.md)
- [Jetpack组件](jetpack.md)
