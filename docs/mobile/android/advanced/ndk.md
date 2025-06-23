# NDK与原生开发

Android NDK (Native Development Kit) 是一套允许你在Android应用中使用C和C++代码的工具集。使用NDK可以帮助你复用现有的C/C++库、实现性能敏感型任务（如游戏物理引擎、信号处理）或进行底层硬件操作。

## 1. 为什么使用NDK？

- **代码复用**: 直接在Android项目中使用已有的C/C++代码库。
- **性能提升**: 对于计算密集型任务，C/C++通常比Java/Kotlin执行得更快。
- **底层访问**: 访问一些只能通过原生接口提供的系统功能。

## 2. 配置NDK环境

要使用NDK，你需要在Android Studio中安装以下组件：
- **NDK**: Native Development Kit本身。
- **CMake**: 用于构建原生库的跨平台构建工具。

可以通过 **SDK Manager > SDK Tools** 来安装它们。

## 3. 创建一个支持C/C++的项目

在Android Studio中创建新项目时，可以选择 **Native C++** 模板，它会自动为你配置好所有必需的文件。

如果向现有项目添加原生代码，你需要：

1.  在`app/src/main/`目录下创建一个`cpp`文件夹，用于存放C/C++源文件。
2.  在模块级的`build.gradle`文件中配置NDK和CMake。

## 4. CMake构建脚本

`CMakeLists.txt`是CMake的构建脚本，用于定义如何编译你的C/C++代码。

```cmake
# CMakeLists.txt

# 设置CMake最低版本要求
cmake_minimum_required(VERSION 3.18.1)

# 定义项目名称
project("myapp")

# 添加原生库源文件，并指定库的类型（SHARED表示动态库）
add_library(
        native-lib # 库的名称
        SHARED
        native-lib.cpp) # 源文件

# 查找并链接Android系统库（如日志库）
find_library(
        log-lib
        log)

# 将系统库链接到你的原生库
target_link_libraries(
        native-lib
        ${log-lib})
```

## 5. 在`build.gradle`中配置CMake

在模块级的`build.gradle`文件中，你需要指定`CMakeLists.txt`的路径。

```groovy
// app/build.gradle
android {
    // ...
    defaultConfig {
        // ...
        externalNativeBuild {
            cmake {
                cppFlags ''
            }
        }
    }
    // ...
    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt" // 指定CMake脚本路径
            version "3.18.1"
        }
    }
}
```

## 6. JNI (Java Native Interface)

JNI是连接Java/Kotlin代码和C/C++代码的桥梁。

### 从Kotlin调用C/C++

1.  **在Kotlin中声明native方法**:

    ```kotlin
    // MainActivity.kt
    class MainActivity : AppCompatActivity() {
        // ...
        
        /**
         * 声明一个原生方法。
         * 'external'关键字告诉编译器这个方法的实现在外部（C/C++）。
         */
        external fun stringFromJNI(): String

        companion object {
            init {
                // 加载原生库
                System.loadLibrary("native-lib")
            }
        }
    }
    ```

2.  **在C/C++中实现native方法**:

    JNI要求C/C++中的函数名遵循特定格式：`Java_包名_类名_方法名`。

    ```cpp
    // native-lib.cpp
    #include <jni.h>
    #include <string>

    extern "C" JNIEXPORT jstring JNICALL
    Java_com_example_myapp_MainActivity_stringFromJNI(
            JNIEnv* env,
            jobject /* this */) {
        std::string hello = "Hello from C++";
        return env->NewStringUTF(hello.c_str());
    }
    ```
    - `JNIEnv*`: 一个指向JNI环境的指针，提供了大多数JNI函数。
    - `jobject`: 指向调用此原生方法的Java/Kotlin对象。
    - `jstring`: JNI中代表Java/Kotlin字符串的类型。

### 从C/C++调用Kotlin

在C/C++中调用Kotlin方法更为复杂，通常涉及以下步骤：

1.  获取`JNIEnv`指针。
2.  使用`FindClass`找到目标Kotlin类的引用。
3.  使用`GetMethodID`获取目标方法的ID。
4.  使用`Call<Type>Method`（如`CallVoidMethod`）来调用该方法。

## 7. 调试原生代码

Android Studio提供了强大的原生代码调试支持。你可以在C/C++代码中设置断点，就像在Kotlin代码中一样。当应用执行到断点时，调试器会暂停，你可以检查变量、内存和线程。

## 结论

NDK是Android开发中的一个强大工具，它允许开发者利用C/C++的性能优势和现有代码库。通过CMake和JNI，可以实现托管代码与原生代码之间的无缝集成。然而，由于增加了复杂性，建议仅在确实需要时才使用NDK。 