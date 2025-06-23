# Android位置服务与地图

本文档介绍如何在Android应用中使用位置服务和地图功能，包括获取用户位置、地理编码、地理围栏以及集成Google Maps。

## 位置服务基础

### 添加位置权限

在AndroidManifest.xml中添加位置权限：

```xml
<!-- 精确位置权限（GPS） -->
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<!-- 粗略位置权限（网络） -->
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
<!-- 后台位置权限（Android 10+） -->
<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
```

### 请求位置权限

在Android 6.0（API级别23）及以上版本，需要在运行时请求位置权限：

```kotlin
private val LOCATION_PERMISSION_REQUEST_CODE = 1

private fun checkLocationPermission() {
    if (ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) != PackageManager.PERMISSION_GRANTED
    ) {
        // 请求权限
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION),
            LOCATION_PERMISSION_REQUEST_CODE
        )
    } else {
        // 已有权限，获取位置
        getLastLocation()
    }
}

override fun onRequestPermissionsResult(
    requestCode: Int,
    permissions: Array<String>,
    grantResults: IntArray
) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults)
    if (requestCode == LOCATION_PERMISSION_REQUEST_CODE) {
        if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            // 权限已授予
            getLastLocation()
        } else {
            // 权限被拒绝
            Toast.makeText(
                this,
                "位置权限被拒绝，无法获取位置信息",
                Toast.LENGTH_SHORT
            ).show()
        }
    }
}
```

### 获取最后已知位置

使用FusedLocationProviderClient获取最后已知位置：

```kotlin
private lateinit var fusedLocationClient: FusedLocationProviderClient

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    
    fusedLocationClient = LocationServices.getFusedLocationProviderClient(this)
    
    checkLocationPermission()
}

@SuppressLint("MissingPermission")
private fun getLastLocation() {
    fusedLocationClient.lastLocation
        .addOnSuccessListener { location: Location? ->
            location?.let {
                // 使用位置信息
                val latitude = it.latitude
                val longitude = it.longitude
                Log.d("LocationDemo", "Lat: $latitude, Long: $longitude")
                
                // 更新UI
                updateLocationUI(it)
            } ?: run {
                // 位置为null，可能是位置服务被禁用
                Toast.makeText(this, "无法获取位置，请确保位置服务已启用", Toast.LENGTH_SHORT).show()
            }
        }
        .addOnFailureListener { e ->
            Log.e("LocationDemo", "获取位置失败: ${e.message}")
        }
}

private fun updateLocationUI(location: Location) {
    findViewById<TextView>(R.id.locationTextView).text = 
        "纬度: ${location.latitude}\n经度: ${location.longitude}"
}
```

### 持续获取位置更新

```kotlin
private lateinit var locationCallback: LocationCallback
private lateinit var locationRequest: LocationRequest

@SuppressLint("MissingPermission")
private fun startLocationUpdates() {
    locationRequest = LocationRequest.create().apply {
        interval = 10000 // 更新间隔，单位毫秒
        fastestInterval = 5000 // 最快更新间隔
        priority = LocationRequest.PRIORITY_HIGH_ACCURACY // 高精度
    }
    
    locationCallback = object : LocationCallback() {
        override fun onLocationResult(locationResult: LocationResult) {
            for (location in locationResult.locations) {
                // 处理位置更新
                updateLocationUI(location)
            }
        }
    }
    
    fusedLocationClient.requestLocationUpdates(
        locationRequest,
        locationCallback,
        Looper.getMainLooper()
    )
}

private fun stopLocationUpdates() {
    fusedLocationClient.removeLocationUpdates(locationCallback)
}

override fun onResume() {
    super.onResume()
    if (::locationCallback.isInitialized) {
        startLocationUpdates()
    }
}

override fun onPause() {
    super.onPause()
    if (::locationCallback.isInitialized) {
        stopLocationUpdates()
    }
}
```

## 地理编码

地理编码是将地址转换为地理坐标（纬度/经度），反向地理编码是将地理坐标转换为地址。

### 正向地理编码（地址转坐标）

```kotlin
private fun geocodeAddress(address: String) {
    val geocoder = Geocoder(this, Locale.getDefault())
    
    try {
        val addresses = geocoder.getFromLocationName(address, 1)
        if (addresses != null && addresses.isNotEmpty()) {
            val location = addresses[0]
            val latitude = location.latitude
            val longitude = location.longitude
            
            Log.d("GeocodingDemo", "Lat: $latitude, Long: $longitude")
            
            // 使用获取到的坐标
            moveMapToLocation(latitude, longitude)
        } else {
            Toast.makeText(this, "找不到该地址", Toast.LENGTH_SHORT).show()
        }
    } catch (e: IOException) {
        Log.e("GeocodingDemo", "地理编码失败: ${e.message}")
    }
}
```

### 反向地理编码（坐标转地址）

```kotlin
private fun reverseGeocodeLocation(latitude: Double, longitude: Double) {
    val geocoder = Geocoder(this, Locale.getDefault())
    
    try {
        val addresses = geocoder.getFromLocation(latitude, longitude, 1)
        if (addresses != null && addresses.isNotEmpty()) {
            val address = addresses[0]
            
            // 获取完整地址
            val fullAddress = address.getAddressLine(0)
            
            // 或者获取地址的各个部分
            val city = address.locality
            val state = address.adminArea
            val country = address.countryName
            val postalCode = address.postalCode
            
            Log.d("GeocodingDemo", "Address: $fullAddress")
            
            // 更新UI
            findViewById<TextView>(R.id.addressTextView).text = fullAddress
        } else {
            Toast.makeText(this, "无法获取地址信息", Toast.LENGTH_SHORT).show()
        }
    } catch (e: IOException) {
        Log.e("GeocodingDemo", "反向地理编码失败: ${e.message}")
    }
}
```

## 地理围栏

地理围栏是一个虚拟边界，当用户进入或离开该区域时，应用可以收到通知。

### 添加依赖

```gradle
dependencies {
    implementation 'com.google.android.gms:play-services-location:21.0.1'
}
```

### 创建地理围栏

```kotlin
private lateinit var geofencingClient: GeofencingClient
private val geofenceList = ArrayList<Geofence>()
private lateinit var geofencePendingIntent: PendingIntent

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    
    geofencingClient = LocationServices.getGeofencingClient(this)
    
    // 创建PendingIntent
    val geofenceIntent = Intent(this, GeofenceBroadcastReceiver::class.java)
    geofencePendingIntent = PendingIntent.getBroadcast(
        this,
        0,
        geofenceIntent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
    )
    
    // 创建地理围栏
    createGeofence()
}

private fun createGeofence() {
    // 添加地理围栏
    val geofence = Geofence.Builder()
        // 设置围栏ID
        .setRequestId("my_geofence")
        // 设置围栏中心点坐标和半径（单位：米）
        .setCircularRegion(37.7749, -122.4194, 100f)
        // 设置响应事件类型
        .setTransitionTypes(Geofence.GEOFENCE_TRANSITION_ENTER or Geofence.GEOFENCE_TRANSITION_EXIT)
        // 设置过期时间（毫秒）
        .setExpirationDuration(Geofence.NEVER_EXPIRE)
        // 设置延迟（毫秒）
        .setNotificationResponsiveness(1000)
        .build()
    
    geofenceList.add(geofence)
}

@SuppressLint("MissingPermission")
private fun addGeofences() {
    val geofencingRequest = GeofencingRequest.Builder().apply {
        // 初始触发：进入监控区域时触发
        setInitialTrigger(GeofencingRequest.INITIAL_TRIGGER_ENTER)
        // 添加地理围栏列表
        addGeofences(geofenceList)
    }.build()
    
    geofencingClient.addGeofences(geofencingRequest, geofencePendingIntent)
        .addOnSuccessListener {
            // 地理围栏添加成功
            Log.d("GeofenceDemo", "地理围栏添加成功")
        }
        .addOnFailureListener { e ->
            // 地理围栏添加失败
            Log.e("GeofenceDemo", "地理围栏添加失败: ${e.message}")
        }
}

private fun removeGeofences() {
    geofencingClient.removeGeofences(geofencePendingIntent)
        .addOnSuccessListener {
            // 地理围栏移除成功
            Log.d("GeofenceDemo", "地理围栏移除成功")
        }
        .addOnFailureListener { e ->
            // 地理围栏移除失败
            Log.e("GeofenceDemo", "地理围栏移除失败: ${e.message}")
        }
}
```

### 创建广播接收器处理地理围栏事件

```kotlin
class GeofenceBroadcastReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val geofencingEvent = GeofencingEvent.fromIntent(intent)
        
        if (geofencingEvent != null && !geofencingEvent.hasError()) {
            val geofenceTransition = geofencingEvent.geofenceTransition
            
            // 获取触发的地理围栏列表
            val triggeringGeofences = geofencingEvent.triggeringGeofences
            
            // 根据事件类型处理
            when (geofenceTransition) {
                Geofence.GEOFENCE_TRANSITION_ENTER -> {
                    // 进入地理围栏区域
                    sendNotification(context, "进入目标区域")
                }
                Geofence.GEOFENCE_TRANSITION_EXIT -> {
                    // 离开地理围栏区域
                    sendNotification(context, "离开目标区域")
                }
            }
        } else {
            // 处理错误
            val errorMessage = GeofenceStatusCodes.getStatusCodeString(
                geofencingEvent?.errorCode ?: -1
            )
            Log.e("GeofenceReceiver", "地理围栏错误: $errorMessage")
        }
    }
    
    private fun sendNotification(context: Context, message: String) {
        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        
        // 创建通知渠道（Android 8.0+）
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "geofence_channel",
                "地理围栏通知",
                NotificationManager.IMPORTANCE_DEFAULT
            )
            notificationManager.createNotificationChannel(channel)
        }
        
        // 构建通知
        val notificationBuilder = NotificationCompat.Builder(context, "geofence_channel")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("地理围栏提醒")
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
        
        // 显示通知
        notificationManager.notify(1, notificationBuilder.build())
    }
}
```

## Google Maps集成

### 添加依赖和API密钥

1. 在build.gradle中添加依赖：

```gradle
dependencies {
    implementation 'com.google.android.gms:play-services-maps:18.1.0'
}
```

2. 在AndroidManifest.xml中添加API密钥：

```xml
<application>
    <!-- 其他配置 -->
    <meta-data
        android:name="com.google.android.geo.API_KEY"
        android:value="YOUR_API_KEY" />
</application>
```

### 添加地图到布局

```xml
<fragment
    android:id="@+id/map"
    android:name="com.google.android.gms.maps.SupportMapFragment"
    android:layout_width="match_parent"
    android:layout_height="match_parent" />
```

### 基本地图操作

```kotlin
private lateinit var map: GoogleMap

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    
    // 获取地图Fragment
    val mapFragment = supportFragmentManager
        .findFragmentById(R.id.map) as SupportMapFragment
    
    // 异步加载地图
    mapFragment.getMapAsync { googleMap ->
        map = googleMap
        
        // 设置地图类型
        map.mapType = GoogleMap.MAP_TYPE_NORMAL
        
        // 启用我的位置层
        enableMyLocation()
        
        // 添加标记
        val sydney = LatLng(-34.0, 151.0)
        map.addMarker(
            MarkerOptions()
                .position(sydney)
                .title("悉尼")
                .snippet("澳大利亚最大的城市")
        )
        
        // 移动相机
        map.moveCamera(CameraUpdateFactory.newLatLngZoom(sydney, 12f))
        
        // 设置点击监听器
        map.setOnMapClickListener { latLng ->
            // 处理地图点击事件
            addMarkerAtPosition(latLng)
        }
        
        // 设置标记点击监听器
        map.setOnMarkerClickListener { marker ->
            // 处理标记点击事件
            Toast.makeText(this, "点击了: ${marker.title}", Toast.LENGTH_SHORT).show()
            false // 返回false表示继续执行默认行为
        }
    }
}

@SuppressLint("MissingPermission")
private fun enableMyLocation() {
    // 检查位置权限
    if (ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
    ) {
        map.isMyLocationEnabled = true
    } else {
        // 请求权限
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION),
            LOCATION_PERMISSION_REQUEST_CODE
        )
    }
}

private fun addMarkerAtPosition(latLng: LatLng) {
    map.addMarker(
        MarkerOptions()
            .position(latLng)
            .title("新标记")
            .icon(BitmapDescriptorFactory.defaultMarker(BitmapDescriptorFactory.HUE_AZURE))
    )
    
    // 可选：移动相机到新标记位置
    map.animateCamera(CameraUpdateFactory.newLatLng(latLng))
    
    // 可选：进行反向地理编码
    reverseGeocodeLocation(latLng.latitude, latLng.longitude)
}
```

### 自定义地图标记

```kotlin
private fun addCustomMarker(latLng: LatLng, title: String) {
    // 创建自定义标记图标
    val markerIcon = BitmapDescriptorFactory.fromResource(R.drawable.custom_marker)
    
    // 添加带自定义图标的标记
    map.addMarker(
        MarkerOptions()
            .position(latLng)
            .title(title)
            .icon(markerIcon)
    )
}

// 或者使用视图创建自定义标记
private fun addCustomViewMarker(latLng: LatLng, title: String) {
    // 创建自定义视图
    val markerView = layoutInflater.inflate(R.layout.custom_marker_layout, null)
    val titleTextView = markerView.findViewById<TextView>(R.id.marker_title)
    titleTextView.text = title
    
    // 将视图转换为Bitmap
    markerView.measure(View.MeasureSpec.UNSPECIFIED, View.MeasureSpec.UNSPECIFIED)
    markerView.layout(0, 0, markerView.measuredWidth, markerView.measuredHeight)
    val bitmap = Bitmap.createBitmap(
        markerView.measuredWidth,
        markerView.measuredHeight,
        Bitmap.Config.ARGB_8888
    )
    val canvas = Canvas(bitmap)
    markerView.draw(canvas)
    
    // 创建自定义标记图标
    val markerIcon = BitmapDescriptorFactory.fromBitmap(bitmap)
    
    // 添加带自定义图标的标记
    map.addMarker(
        MarkerOptions()
            .position(latLng)
            .title(title)
            .icon(markerIcon)
    )
}
```

### 绘制形状

```kotlin
// 绘制折线
private fun drawPolyline() {
    val polylineOptions = PolylineOptions()
        .add(LatLng(37.7749, -122.4194)) // 旧金山
        .add(LatLng(34.0522, -118.2437)) // 洛杉矶
        .add(LatLng(32.7157, -117.1611)) // 圣地亚哥
        .width(5f)
        .color(Color.RED)
    
    map.addPolyline(polylineOptions)
}

// 绘制多边形
private fun drawPolygon() {
    val polygonOptions = PolygonOptions()
        .add(LatLng(37.7749, -122.4194))
        .add(LatLng(37.8044, -122.2712))
        .add(LatLng(37.3382, -121.8863))
        .add(LatLng(37.7749, -122.4194)) // 闭合多边形
        .strokeColor(Color.BLUE)
        .strokeWidth(5f)
        .fillColor(Color.argb(70, 0, 0, 255)) // 半透明填充
    
    map.addPolygon(polygonOptions)
}

// 绘制圆形
private fun drawCircle() {
    val circleOptions = CircleOptions()
        .center(LatLng(37.7749, -122.4194))
        .radius(1000.0) // 半径（米）
        .strokeColor(Color.GREEN)
        .strokeWidth(3f)
        .fillColor(Color.argb(70, 0, 255, 0)) // 半透明填充
    
    map.addCircle(circleOptions)
}
```

### 地图样式自定义

```kotlin
private fun setMapStyle() {
    try {
        // 从资源文件加载样式
        val success = map.setMapStyle(
            MapStyleOptions.loadRawResourceStyle(
                this, R.raw.map_style
            )
        )
        
        if (!success) {
            Log.e("MapsActivity", "地图样式解析失败")
        }
    } catch (e: Resources.NotFoundException) {
        Log.e("MapsActivity", "无法找到样式资源: ${e.message}")
    }
}
```

在res/raw/map_style.json中定义样式：

```json
[
  {
    "featureType": "water",
    "elementType": "geometry",
    "stylers": [
      {
        "color": "#e9e9e9"
      },
      {
        "lightness": 17
      }
    ]
  },
  {
    "featureType": "landscape",
    "elementType": "geometry",
    "stylers": [
      {
        "color": "#f5f5f5"
      },
      {
        "lightness": 20
      }
    ]
  },
  {
    "featureType": "road.highway",
    "elementType": "geometry.fill",
    "stylers": [
      {
        "color": "#ffffff"
      },
      {
        "lightness": 17
      }
    ]
  }
]
```

### 地图交互控制

```kotlin
private fun configureMapSettings() {
    // 启用/禁用缩放控制
    map.uiSettings.isZoomControlsEnabled = true
    
    // 启用/禁用指南针
    map.uiSettings.isCompassEnabled = true
    
    // 启用/禁用我的位置按钮
    map.uiSettings.isMyLocationButtonEnabled = true
    
    // 启用/禁用地图工具栏
    map.uiSettings.isMapToolbarEnabled = true
    
    // 启用/禁用旋转手势
    map.uiSettings.isRotateGesturesEnabled = true
    
    // 启用/禁用倾斜手势
    map.uiSettings.isTiltGesturesEnabled = true
    
    // 设置最小/最大缩放级别
    map.setMinZoomPreference(5f)
    map.setMaxZoomPreference(20f)
    
    // 限制地图显示的区域
    val bounds = LatLngBounds(
        LatLng(32.0, -125.0), // 西南角
        LatLng(42.0, -115.0)  // 东北角
    )
    map.setLatLngBoundsForCameraTarget(bounds)
}
```

### 地图事件监听

```kotlin
private fun setupMapListeners() {
    // 地图点击事件
    map.setOnMapClickListener { latLng ->
        Log.d("MapEvents", "地图点击: $latLng")
    }
    
    // 地图长按事件
    map.setOnMapLongClickListener { latLng ->
        Log.d("MapEvents", "地图长按: $latLng")
        addMarkerAtPosition(latLng)
    }
    
    // 相机移动开始事件
    map.setOnCameraMoveStartedListener { reason ->
        when (reason) {
            GoogleMap.OnCameraMoveStartedListener.REASON_GESTURE -> {
                Log.d("MapEvents", "用户手势触发相机移动")
            }
            GoogleMap.OnCameraMoveStartedListener.REASON_API_ANIMATION -> {
                Log.d("MapEvents", "API动画触发相机移动")
            }
            GoogleMap.OnCameraMoveStartedListener.REASON_DEVELOPER_ANIMATION -> {
                Log.d("MapEvents", "开发者动画触发相机移动")
            }
        }
    }
    
    // 相机移动事件
    map.setOnCameraMoveListener {
        Log.d("MapEvents", "相机正在移动")
    }
    
    // 相机移动结束事件
    map.setOnCameraIdleListener {
        Log.d("MapEvents", "相机停止移动")
        val center = map.cameraPosition.target
        Log.d("MapEvents", "当前中心点: $center")
    }
}
```

### 地图截图

```kotlin
private fun takeMapSnapshot() {
    map.snapshot { bitmap ->
        bitmap?.let {
            // 保存截图
            saveMapSnapshot(it)
            
            // 或显示截图
            val imageView = findViewById<ImageView>(R.id.mapSnapshotImageView)
            imageView.setImageBitmap(it)
        }
    }
}

private fun saveMapSnapshot(bitmap: Bitmap) {
    // 保存到内部存储
    try {
        val fileName = "map_snapshot_${System.currentTimeMillis()}.jpg"
        openFileOutput(fileName, Context.MODE_PRIVATE).use { out ->
            bitmap.compress(Bitmap.CompressFormat.JPEG, 90, out)
        }
        Toast.makeText(this, "地图截图已保存", Toast.LENGTH_SHORT).show()
    } catch (e: IOException) {
        Log.e("MapSnapshot", "保存截图失败: ${e.message}")
    }
}
```

## 位置感知应用最佳实践

1. **权限处理**：始终优雅地处理权限请求和拒绝场景。
2. **电池优化**：
   - 根据应用需求选择适当的位置请求精度和频率。
   - 使用`LocationRequest.PRIORITY_BALANCED_POWER_ACCURACY`而非`PRIORITY_HIGH_ACCURACY`可以节省电量。
   - 当不需要位置更新时，务必移除位置监听器。
3. **用户体验**：
   - 清楚地解释为什么应用需要位置权限。
   - 提供位置服务未启用时的备选方案。
   - 考虑网络不可用情况下的离线地图功能。
4. **隐私考虑**：
   - 仅在必要时请求精确位置权限。
   - 避免不必要的后台位置访问。
   - 明确告知用户如何使用和存储其位置数据。
5. **地图性能优化**：
   - 使用聚合标记（Marker Clustering）处理大量标记点。
   - 使用适当的缓存策略。
   - 仅在可见区域加载数据。

## 总结

本文档介绍了Android位置服务和地图功能的核心内容，包括获取用户位置、地理编码、地理围栏以及Google Maps集成。通过这些API，开发者可以创建功能丰富的位置感知应用，提供基于位置的服务和交互式地图体验。

## 下一步学习

- [后台处理](background-processing.md)
- [通知与推送](notifications.md)
- [Jetpack组件](jetpack.md)
