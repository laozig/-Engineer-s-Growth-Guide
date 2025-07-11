# React Native 与原生模块交互

React Native 提供了跨平台的开发体验，但有时候我们需要访问平台特定的 API 或集成已有的原生库。本文档将介绍如何编写和集成原生模块与组件，以便在 React Native 应用中使用平台特定功能。

## 目录

- [原生模块概述](#原生模块概述)
- [Android 原生模块](#android-原生模块)
- [iOS 原生模块](#ios-原生模块)
- [原生 UI 组件](#原生-ui-组件)
- [发送事件到 JavaScript](#发送事件到-javascript)
- [性能考量](#性能考量)
- [故障排除](#故障排除)
- [TurboModules](#turbomodules)
- [Fabric](#fabric)
- [最佳实践](#最佳实践)

## 原生模块概述

原生模块是一种桥接 React Native JavaScript 代码与原生平台代码的机制。使用原生模块可以：

- 访问平台特定的 API（如生物识别、蓝牙等）
- 集成尚未支持的第三方原生库
- 编写性能关键的代码（图像处理、加密等）

### 原生模块工作原理

React Native 使用"桥接"机制在 JavaScript 和原生代码间通信：

1. JavaScript 代码通过桥接发送请求到原生模块
2. 原生模块执行所需操作并返回结果
3. 结果通过桥接返回给 JavaScript

这一机制支持同步和异步通信，但推荐使用异步方式以避免阻塞 JavaScript 线程。

## Android 原生模块

### 创建 Android 原生模块

在 Android 中创建原生模块需要以下步骤：

1. 创建一个继承自 `ReactContextBaseJavaModule` 的类
2. 实现所需方法
3. 创建一个包类注册模块

#### 步骤 1：创建模块类

```java
// ToastModule.java
package com.yourapp.toast;

import android.widget.Toast;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.util.HashMap;
import java.util.Map;

public class ToastModule extends ReactContextBaseJavaModule {
    private static final String DURATION_SHORT = "SHORT";
    private static final String DURATION_LONG = "LONG";

    public ToastModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        // 这个名称将在 JavaScript 中用来引用模块
        return "ToastExample";
    }

    @Override
    public Map<String, Object> getConstants() {
        final Map<String, Object> constants = new HashMap<>();
        constants.put(DURATION_SHORT, Toast.LENGTH_SHORT);
        constants.put(DURATION_LONG, Toast.LENGTH_LONG);
        return constants;
    }

    @ReactMethod
    public void show(String message, int duration) {
        Toast.makeText(getReactApplicationContext(), message, duration).show();
    }
}
```

#### 步骤 2：创建包类

```java
// ToastPackage.java
package com.yourapp.toast;

import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.uimanager.ViewManager;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ToastPackage implements ReactPackage {
    @Override
    public List<NativeModule> createNativeModules(ReactApplicationContext reactContext) {
        List<NativeModule> modules = new ArrayList<>();
        modules.add(new ToastModule(reactContext));
        return modules;
    }

    @Override
    public List<ViewManager> createViewManagers(ReactApplicationContext reactContext) {
        return Collections.emptyList();
    }
}
```

#### 步骤 3：注册包到 MainApplication

```java
// MainApplication.java
@Override
protected List<ReactPackage> getPackages() {
    @SuppressWarnings("UnnecessaryLocalVariable")
    List<ReactPackage> packages = new PackageList(this).getPackages();
    // 添加自定义包
    packages.add(new ToastPackage());
    return packages;
}
```

### 在 JavaScript 中使用 Android 原生模块

```javascript
import { NativeModules } from 'react-native';
const { ToastExample } = NativeModules;

ToastExample.show('来自原生代码的问候', ToastExample.DURATION_SHORT);
```

### 数据类型映射（Android）

| JavaScript 类型 | Java 类型    |
|----------------|-------------|
| string         | String      |
| number         | int, double |
| boolean        | boolean     |
| array          | ReadableArray |
| object         | ReadableMap |
| function       | Callback    |
| Promise        | Promise     |

### 支持回调

```java
@ReactMethod
public void measureLayout(
    int tag,
    int ancestorTag,
    Callback errorCallback,
    Callback successCallback) {
    try {
        // 计算操作...
        successCallback.invoke(x, y, width, height);
    } catch (Exception e) {
        errorCallback.invoke(e.getMessage());
    }
}
```

### 支持 Promise

```java
@ReactMethod
public void fetchData(String param, Promise promise) {
    try {
        String result = "获取到的数据: " + param;
        promise.resolve(result);
    } catch (Exception e) {
        promise.reject("ERR_DATA_FETCH", e.getMessage(), e);
    }
}
```

## iOS 原生模块

### 创建 iOS 原生模块

在 iOS 中创建原生模块需要以下步骤：

1. 创建一个继承自 `NSObject` 并实现 `RCTBridgeModule` 协议的类
2. 使用 `RCT_EXPORT_MODULE()` 宏导出模块
3. 使用 `RCT_EXPORT_METHOD()` 宏导出方法

#### 步骤 1：创建模块类

```objective-c
// RCTCalendarModule.h
#import <React/RCTBridgeModule.h>

@interface RCTCalendarModule : NSObject <RCTBridgeModule>
@end
```

```objective-c
// RCTCalendarModule.m
#import "RCTCalendarModule.h"
#import <React/RCTLog.h>

@implementation RCTCalendarModule

// 导出模块
RCT_EXPORT_MODULE();

// 导出常量
- (NSDictionary *)constantsToExport
{
  return @{ @"DEFAULT_EVENT_NAME": @"新事件" };
}

// 导出方法
RCT_EXPORT_METHOD(createCalendarEvent:(NSString *)name location:(NSString *)location)
{
  RCTLogInfo(@"创建日历事件 %@ 在 %@", name, location);
  // 实际的日历 API 调用
}

// 带有回调的方法
RCT_EXPORT_METHOD(createCalendarEventWithCallback:(NSString *)name callback:(RCTResponseSenderBlock)callback)
{
  // 在实际应用中，你可能会执行一些异步操作
  NSString *eventId = @"123";
  callback(@[eventId]);
}

// 支持 Promise 的方法
RCT_EXPORT_METHOD(createCalendarEventWithPromise:(NSString *)name
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    // 在实际应用中，你可能会执行一些异步操作
    NSString *eventId = @"123";
    resolve(eventId);
  } @catch (NSException *exception) {
    reject(@"event_creation_failed", @"无法创建事件", exception);
  }
}

@end
```

#### Swift 中创建模块

```swift
// CalendarModule.swift
import Foundation

@objc(CalendarModule)
class CalendarModule: NSObject {
  
  @objc(createCalendarEvent:location:)
  func createCalendarEvent(name: String, location: String) -> Void {
    print("创建日历事件 \(name) 在 \(location)")
  }
  
  @objc
  func constantsToExport() -> [String: Any] {
    return [
      "DEFAULT_EVENT_NAME": "新事件"
    ]
  }
  
  @objc
  static func requiresMainQueueSetup() -> Bool {
    return false
  }
}
```

```objective-c
// CalendarModule.m - 用于桥接
#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(CalendarModule, NSObject)

RCT_EXTERN_METHOD(createCalendarEvent:(NSString *)name location:(NSString *)location)

@end
```

### 在 JavaScript 中使用 iOS 原生模块

```javascript
import { NativeModules } from 'react-native';
const { CalendarModule } = NativeModules;

CalendarModule.createCalendarEvent('生日派对', '我的家');

// 使用回调
CalendarModule.createCalendarEventWithCallback('会议', (eventId) => {
  console.log(`创建的事件 ID: ${eventId}`);
});

// 使用 Promise
CalendarModule.createCalendarEventWithPromise('会议')
  .then((eventId) => console.log(`创建的事件 ID: ${eventId}`))
  .catch((error) => console.error(error));
```

### 数据类型映射（iOS）

| JavaScript 类型 | Objective-C 类型 | Swift 类型      |
|----------------|-----------------|---------------|
| string         | NSString        | String        |
| number         | NSNumber        | NSNumber      |
| boolean        | BOOL            | Bool          |
| array          | NSArray         | Array         |
| object         | NSDictionary    | Dictionary    |
| function       | RCTResponseSenderBlock | RCTResponseSenderBlock |
| Promise        | RCTPromiseResolveBlock, RCTPromiseRejectBlock | RCTPromiseResolveBlock, RCTPromiseRejectBlock |

## 原生 UI 组件

除了功能性模块外，React Native 还允许创建自定义 UI 组件。

### Android 自定义视图

#### 步骤 1：创建视图管理器

```java
// CustomButtonManager.java
package com.yourapp.custombutton;

import android.graphics.Color;
import androidx.annotation.NonNull;

import com.facebook.react.uimanager.SimpleViewManager;
import com.facebook.react.uimanager.ThemedReactContext;
import com.facebook.react.uimanager.annotations.ReactProp;
import android.widget.Button;

public class CustomButtonManager extends SimpleViewManager<Button> {

    @Override
    public String getName() {
        return "CustomButton";
    }

    @Override
    protected Button createViewInstance(@NonNull ThemedReactContext reactContext) {
        Button button = new Button(reactContext);
        button.setAllCaps(false);
        return button;
    }

    @ReactProp(name = "text")
    public void setText(Button view, String text) {
        view.setText(text);
    }

    @ReactProp(name = "color")
    public void setColor(Button view, String color) {
        view.setTextColor(Color.parseColor(color));
    }

    @ReactProp(name = "backgroundColor")
    public void setBackgroundColor(Button view, String backgroundColor) {
        view.setBackgroundColor(Color.parseColor(backgroundColor));
    }
}
```

#### 步骤 2：更新包类

```java
// CustomButtonPackage.java
@Override
public List<ViewManager> createViewManagers(ReactApplicationContext reactContext) {
    return Collections.singletonList(new CustomButtonManager());
}
```

### iOS 自定义视图

#### 步骤 1：创建视图

```objective-c
// CustomButtonView.h
#import <UIKit/UIKit.h>

@interface CustomButtonView : UIButton
@end

// CustomButtonView.m
#import "CustomButtonView.h"

@implementation CustomButtonView
@end
```

#### 步骤 2：创建视图管理器

```objective-c
// CustomButtonManager.h
#import <React/RCTViewManager.h>

@interface CustomButtonManager : RCTViewManager
@end

// CustomButtonManager.m
#import "CustomButtonManager.h"
#import "CustomButtonView.h"

@implementation CustomButtonManager

RCT_EXPORT_MODULE()

- (UIView *)view
{
  CustomButtonView *button = [CustomButtonView buttonWithType:UIButtonTypeSystem];
  [button setTitle:@"按钮" forState:UIControlStateNormal];
  return button;
}

RCT_CUSTOM_VIEW_PROPERTY(text, NSString, CustomButtonView)
{
  [view setTitle:json forState:UIControlStateNormal];
}

RCT_CUSTOM_VIEW_PROPERTY(color, NSString, CustomButtonView)
{
  [view setTitleColor:[self colorFromHexString:json] forState:UIControlStateNormal];
}

RCT_CUSTOM_VIEW_PROPERTY(backgroundColor, NSString, CustomButtonView)
{
  view.backgroundColor = [self colorFromHexString:json];
}

// 辅助方法：从十六进制字符串创建颜色
- (UIColor *)colorFromHexString:(NSString *)hexString
{
  unsigned rgbValue = 0;
  NSScanner *scanner = [NSScanner scannerWithString:hexString];
  [scanner setScanLocation:1]; // 跳过 '#' 字符
  [scanner scanHexInt:&rgbValue];
  return [UIColor colorWithRed:((rgbValue & 0xFF0000) >> 16)/255.0 green:((rgbValue & 0xFF00) >> 8)/255.0 blue:(rgbValue & 0xFF)/255.0 alpha:1.0];
}

@end
```

### 在 JavaScript 中使用自定义 UI 组件

创建 JavaScript 包装器组件：

```javascript
// CustomButton.js
import { requireNativeComponent } from 'react-native';

// 导入原生组件
const CustomButtonNative = requireNativeComponent('CustomButton');

// 创建 React 组件包装器
const CustomButton = (props) => {
  return <CustomButtonNative {...props} />;
};

export default CustomButton;
```

使用组件：

```javascript
import React from 'react';
import { StyleSheet, View } from 'react-native';
import CustomButton from './CustomButton';

export default function App() {
  return (
    <View style={styles.container}>
      <CustomButton
        text="自定义原生按钮"
        color="#FFFFFF"
        backgroundColor="#2196F3"
        style={styles.button}
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  button: {
    width: 200,
    height: 50,
  },
});
```

## 发送事件到 JavaScript

有时原生模块需要向 JavaScript 主动发送事件，如通知网络状态变化或外部设备的输入。

### Android 发送事件

```java
// NetworkModule.java
public class NetworkModule extends ReactContextBaseJavaModule {
    private final ReactApplicationContext reactContext;

    public NetworkModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "NetworkModule";
    }

    // 辅助方法：发送网络状态变化事件
    private void sendNetworkStatusEvent(boolean isConnected) {
        reactContext
            .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
            .emit("networkStatusChanged", isConnected);
    }

    // 公开方法：开始监听网络变化
    @ReactMethod
    public void startNetworkMonitoring() {
        // 实现监听网络状态变化的代码
        // 当检测到变化时调用 sendNetworkStatusEvent
    }
}
```

### iOS 发送事件

```objective-c
// NetworkModule.m
#import <React/RCTEventEmitter.h>

@interface NetworkModule : RCTEventEmitter <RCTBridgeModule>
@end

@implementation NetworkModule

RCT_EXPORT_MODULE();

// 定义支持的事件类型
- (NSArray<NSString *> *)supportedEvents
{
  return @[@"networkStatusChanged"];
}

// 发送事件
- (void)sendNetworkStatusEvent:(BOOL)isConnected
{
  [self sendEventWithName:@"networkStatusChanged" body:@(isConnected)];
}

// 公开方法：开始监听网络变化
RCT_EXPORT_METHOD(startNetworkMonitoring)
{
  // 实现监听网络状态变化的代码
  // 当检测到变化时调用 sendNetworkStatusEvent
}

@end
```

### 在 JavaScript 中接收事件

```javascript
import React, { useEffect } from 'react';
import { NativeModules, NativeEventEmitter } from 'react-native';

const { NetworkModule } = NativeModules;
const networkEventEmitter = new NativeEventEmitter(NetworkModule);

function NetworkStatusMonitor() {
  useEffect(() => {
    // 订阅事件
    const subscription = networkEventEmitter.addListener(
      'networkStatusChanged',
      (isConnected) => {
        console.log(`网络状态: ${isConnected ? '已连接' : '未连接'}`);
      }
    );

    // 开始监听
    NetworkModule.startNetworkMonitoring();

    // 清理订阅
    return () => subscription.remove();
  }, []);

  return null; // 此组件不渲染 UI
}
```

## 性能考量

### 批处理调用

当需要进行多个原生调用时，可以使用批处理减少桥接开销：

```javascript
// 不好的写法 - 多次桥接调用
DatabaseModule.insertItem('key1', 'value1');
DatabaseModule.insertItem('key2', 'value2');
DatabaseModule.insertItem('key3', 'value3');

// 好的写法 - 单次桥接调用
DatabaseModule.batchInsert([
  { key: 'key1', value: 'value1' },
  { key: 'key2', value: 'value2' },
  { key: 'key3', value: 'value3' }
]);
```

### 使用 TypeScript 增强类型安全

```typescript
// NativeModules.ts
import { NativeModules } from 'react-native';

interface CalendarModuleInterface {
  createCalendarEvent(name: string, location: string): void;
  createCalendarEventWithCallback(
    name: string,
    callback: (eventId: string) => void
  ): void;
  createCalendarEventWithPromise(name: string): Promise<string>;
  DEFAULT_EVENT_NAME: string;
}

export const CalendarModule = NativeModules.CalendarModule as CalendarModuleInterface;
```

## TurboModules

TurboModules 是 React Native 的新架构一部分，它优化了 JavaScript 和原生代码间的通信。

### 主要优势

1. **延迟加载**：只在需要时加载模块
2. **直接调用**：减少序列化/反序列化开销
3. **类型安全**：使用 Codegen 生成类型安全的接口

### TurboModule 规范 (Android)

```java
// 实现 TurboModule 接口的规范
@ReactModule(name = "SampleTurboModule")
public class SampleTurboModule extends NativeSampleTurboModuleSpec {
    public SampleTurboModule(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public void sampleMethod(String input, Promise promise) {
        promise.resolve("TurboModule 结果: " + input);
    }
}
```

### TurboModule 规范 (iOS)

```objective-c
// 实现 TurboModule 协议的规范
@interface SampleTurboModule : NSObject <NativeSampleTurboModuleSpec>
@end

@implementation SampleTurboModule

RCT_EXPORT_MODULE()

- (void)sampleMethod:(NSString *)input
           resolver:(RCTPromiseResolveBlock)resolve
           rejecter:(RCTPromiseRejectBlock)reject
{
  resolve([NSString stringWithFormat:@"TurboModule 结果: %@", input]);
}

@end
```

## Fabric

Fabric 是 React Native 新架构中负责 UI 部分的系统。

### 主要优势

1. **同步渲染**：JavaScript 和 Native 之间同步通信
2. **优化渲染**：只更新需要更改的部分
3. **一致性布局**：在所有平台使用相同的布局引擎

### 创建 Fabric 组件（Android）

```java
@ReactPropertyHolder
public class CustomFabricViewManager extends SimpleViewManager<CustomView> {
    public static final String REACT_CLASS = "CustomFabricView";

    @Override
    public String getName() {
        return REACT_CLASS;
    }

    @Override
    protected CustomView createViewInstance(ThemedReactContext reactContext) {
        return new CustomView(reactContext);
    }

    @ReactProp(name = "title")
    public void setTitle(CustomView view, String title) {
        view.setTitle(title);
    }
}
```

### 创建 Fabric 组件（iOS）

```objective-c
@interface CustomFabricViewManager : RCTViewManager
@end

@implementation CustomFabricViewManager

RCT_EXPORT_MODULE()

- (UIView *)view
{
  CustomView *view = [[CustomView alloc] init];
  return view;
}

RCT_CUSTOM_VIEW_PROPERTY(title, NSString, CustomView)
{
  view.title = json ? [RCTConvert NSString:json] : nil;
}

@end
```

## 故障排除

### 常见问题及解决方法

1. **模块未找到**
   - 确保模块名称正确
   - 确保包已正确注册
   - 重新构建应用

2. **方法未找到**
   - 确保方法名称正确
   - 确保方法已使用 @ReactMethod（Android）或 RCT_EXPORT_METHOD（iOS）导出

3. **参数类型错误**
   - 确保参数类型正确映射
   - 使用 TypeScript 定义准确的接口类型

4. **线程错误**
   - UI 操作必须在主线程执行
   - 使用 `runOnUiQueueThread`（iOS）或 `runOnUiThread`（Android）确保在主线程执行 UI 操作

5. **性能问题**
   - 使用批处理减少桥接调用
   - 避免频繁传输大量数据
   - 考虑使用 TurboModules 和 Fabric

## 最佳实践

### 1. 保持模块专注

每个原生模块应专注于特定功能领域，遵循单一职责原则。

### 2. 适当错误处理

```java
// Android
@ReactMethod
public void riskyCalls(Promise promise) {
    try {
        // 可能抛出异常的操作
        String result = performRiskyOperation();
        promise.resolve(result);
    } catch (Exception e) {
        promise.reject("ERR_UNEXPECTED_EXCEPTION", e);
    }
}
```

```objective-c
// iOS
RCT_EXPORT_METHOD(riskyCalls:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    // 可能抛出异常的操作
    NSString *result = [self performRiskyOperation];
    resolve(result);
  } @catch (NSException *exception) {
    reject(@"ERR_UNEXPECTED_EXCEPTION", exception.reason, nil);
  }
}
```

### 3. 提供清晰文档

为你的原生模块提供清晰的文档，包括：

- 模块和方法的用途
- 参数和返回值的类型和格式
- 错误代码和含义
- 使用示例

### 4. 性能优化

- 避免在主线程执行耗时操作
- 使用适当的数据类型减少转换开销
- 批处理调用减少桥接开销

### 5. 跨平台兼容性

为 Android 和 iOS 提供功能对等的实现，确保应用行为一致。

## 总结

原生模块为 React Native 应用提供了访问平台特定功能的强大途径，但也需要谨慎使用以避免失去跨平台开发的优势。通过遵循本文档的最佳实践和指南，你可以有效地创建和集成原生模块，同时保持应用的稳定性和性能。

随着 React Native 新架构（TurboModules 和 Fabric）的推出，原生模块的集成将变得更加高效和类型安全。无论你是需要访问平台特定 API，还是优化性能关键部分，了解如何正确创建和使用原生模块都是 React Native 开发者的重要技能。 