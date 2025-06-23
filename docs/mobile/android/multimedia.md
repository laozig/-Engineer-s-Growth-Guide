# Android多媒体开发

Android提供了丰富的API用于处理多媒体内容，包括图像、音频和视频。本文档将介绍如何在Android应用中实现多媒体功能。

## 相机操作

### 使用系统相机应用

最简单的方式是使用系统相机应用拍照：

```kotlin
// 创建保存照片的文件
private lateinit var currentPhotoPath: String

private fun createImageFile(): File {
    val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
    val storageDir = getExternalFilesDir(Environment.DIRECTORY_PICTURES)
    return File.createTempFile(
        "JPEG_${timeStamp}_",
        ".jpg",
        storageDir
    ).apply {
        currentPhotoPath = absolutePath
    }
}

// 启动系统相机
private fun dispatchTakePictureIntent() {
    Intent(MediaStore.ACTION_IMAGE_CAPTURE).also { takePictureIntent ->
        takePictureIntent.resolveActivity(packageManager)?.also {
            val photoFile: File? = try {
                createImageFile()
            } catch (ex: IOException) {
                null
            }
            
            photoFile?.also {
                val photoURI: Uri = FileProvider.getUriForFile(
                    this,
                    "com.example.android.fileprovider",
                    it
                )
                takePictureIntent.putExtra(MediaStore.EXTRA_OUTPUT, photoURI)
                startActivityForResult(takePictureIntent, REQUEST_TAKE_PHOTO)
            }
        }
    }
}

// 处理相机返回结果
override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (requestCode == REQUEST_TAKE_PHOTO && resultCode == RESULT_OK) {
        // 照片已保存到currentPhotoPath
        setPic()
    }
}

// 将照片显示在ImageView中
private fun setPic() {
    val targetW: Int = imageView.width
    val targetH: Int = imageView.height
    
    val bmOptions = BitmapFactory.Options().apply {
        // 获取图片尺寸
        inJustDecodeBounds = true
        BitmapFactory.decodeFile(currentPhotoPath, this)
        val photoW: Int = outWidth
        val photoH: Int = outHeight
        
        // 计算缩放比例
        val scaleFactor: Int = Math.min(photoW / targetW, photoH / targetH)
        
        // 解码图片
        inJustDecodeBounds = false
        inSampleSize = scaleFactor
    }
    
    BitmapFactory.decodeFile(currentPhotoPath, bmOptions)?.also { bitmap ->
        imageView.setImageBitmap(bitmap)
    }
}
```

### 使用FileProvider

在AndroidManifest.xml中配置FileProvider：

```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="com.example.android.fileprovider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

创建res/xml/file_paths.xml：

```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <external-files-path name="my_images" path="Pictures" />
</paths>
```

### 使用CameraX

CameraX是Jetpack库，提供了更简单的相机API：

1. 添加依赖：

```gradle
dependencies {
    def camerax_version = "1.2.3"
    implementation "androidx.camera:camera-core:$camerax_version"
    implementation "androidx.camera:camera-camera2:$camerax_version"
    implementation "androidx.camera:camera-lifecycle:$camerax_version"
    implementation "androidx.camera:camera-video:$camerax_version"
    implementation "androidx.camera:camera-view:$camerax_version"
    implementation "androidx.camera:camera-extensions:$camerax_version"
}
```

2. 基本使用：

```kotlin
// 请求相机权限
private val REQUIRED_PERMISSIONS = arrayOf(Manifest.permission.CAMERA)
private val REQUEST_CODE_PERMISSIONS = 10

private fun allPermissionsGranted() = REQUIRED_PERMISSIONS.all {
    ContextCompat.checkSelfPermission(baseContext, it) == PackageManager.PERMISSION_GRANTED
}

override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    setContentView(R.layout.activity_main)
    
    if (allPermissionsGranted()) {
        startCamera()
    } else {
        ActivityCompat.requestPermissions(
            this, REQUIRED_PERMISSIONS, REQUEST_CODE_PERMISSIONS)
    }
    
    // 设置拍照按钮监听器
    findViewById<Button>(R.id.camera_capture_button).setOnClickListener {
        takePhoto()
    }
}

override fun onRequestPermissionsResult(
    requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
    if (requestCode == REQUEST_CODE_PERMISSIONS) {
        if (allPermissionsGranted()) {
            startCamera()
        } else {
            Toast.makeText(this, "未授予相机权限", Toast.LENGTH_SHORT).show()
            finish()
        }
    }
}

private lateinit var imageCapture: ImageCapture

private fun startCamera() {
    val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
    
    cameraProviderFuture.addListener({
        val cameraProvider: ProcessCameraProvider = cameraProviderFuture.get()
        
        val preview = Preview.Builder()
            .build()
            .also {
                it.setSurfaceProvider(findViewById<PreviewView>(R.id.viewFinder).surfaceProvider)
            }
            
        imageCapture = ImageCapture.Builder().build()
        
        val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
        
        try {
            // 解绑所有用例
            cameraProvider.unbindAll()
            
            // 绑定用例到相机
            cameraProvider.bindToLifecycle(
                this, cameraSelector, preview, imageCapture)
                
        } catch(exc: Exception) {
            Log.e(TAG, "相机绑定失败", exc)
        }
        
    }, ContextCompat.getMainExecutor(this))
}

private fun takePhoto() {
    val imageCapture = imageCapture ?: return
    
    val photoFile = File(
        outputDirectory,
        SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS", Locale.getDefault())
            .format(System.currentTimeMillis()) + ".jpg")
            
    val outputOptions = ImageCapture.OutputFileOptions.Builder(photoFile).build()
    
    imageCapture.takePicture(
        outputOptions, ContextCompat.getMainExecutor(this), object : ImageCapture.OnImageSavedCallback {
            override fun onError(exc: ImageCaptureException) {
                Log.e(TAG, "照片拍摄失败: ${exc.message}", exc)
            }
            
            override fun onImageSaved(output: ImageCapture.OutputFileResults) {
                val savedUri = Uri.fromFile(photoFile)
                val msg = "照片拍摄成功: $savedUri"
                Toast.makeText(baseContext, msg, Toast.LENGTH_SHORT).show()
                Log.d(TAG, msg)
            }
        })
}
```

## 音频处理

### 播放音频

使用MediaPlayer播放音频文件：

```kotlin
// 播放本地音频文件
private fun playLocalAudio() {
    val mediaPlayer = MediaPlayer().apply {
        setDataSource(context, Uri.parse("android.resource://$packageName/${R.raw.sound_file}"))
        prepare() // 可能需要较长时间，建议在后台线程中调用
        start()
    }
    
    // 释放资源
    mediaPlayer.setOnCompletionListener {
        it.release()
    }
}

// 播放网络音频
private fun playNetworkAudio(url: String) {
    val mediaPlayer = MediaPlayer().apply {
        setDataSource(url)
        prepareAsync() // 异步准备
        setOnPreparedListener {
            it.start()
        }
        setOnErrorListener { mp, what, extra ->
            Log.e(TAG, "音频播放错误: $what, $extra")
            mp.release()
            true
        }
    }
}

// 使用ExoPlayer播放音频
private fun playAudioWithExoPlayer(context: Context, uri: Uri) {
    val player = ExoPlayer.Builder(context).build()
    val mediaItem = MediaItem.fromUri(uri)
    player.setMediaItem(mediaItem)
    player.prepare()
    player.play()
    
    // 不再使用时释放资源
    player.release()
}
```

### 录制音频

```kotlin
private var mediaRecorder: MediaRecorder? = null
private var isRecording = false
private lateinit var audioFilePath: String

private fun startRecording() {
    // 创建录音文件
    val fileName = "${System.currentTimeMillis()}.mp3"
    val storageDir = getExternalFilesDir(Environment.DIRECTORY_MUSIC)
    val file = File(storageDir, fileName)
    audioFilePath = file.absolutePath
    
    mediaRecorder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        MediaRecorder(this)
    } else {
        MediaRecorder()
    }
    
    mediaRecorder?.apply {
        setAudioSource(MediaRecorder.AudioSource.MIC)
        setOutputFormat(MediaRecorder.OutputFormat.MPEG_4)
        setOutputFile(audioFilePath)
        setAudioEncoder(MediaRecorder.AudioEncoder.AAC)
        setAudioEncodingBitRate(128000)
        setAudioSamplingRate(44100)
        
        try {
            prepare()
            start()
            isRecording = true
        } catch (e: IOException) {
            Log.e(TAG, "录音准备失败", e)
        }
    }
}

private fun stopRecording() {
    if (isRecording) {
        mediaRecorder?.apply {
            stop()
            release()
        }
        mediaRecorder = null
        isRecording = false
    }
}
```

## 视频处理

### 播放视频

使用VideoView播放视频：

```xml
<VideoView
    android:id="@+id/videoView"
    android:layout_width="match_parent"
    android:layout_height="wrap_content" />
```

```kotlin
val videoView = findViewById<VideoView>(R.id.videoView)
val mediaController = MediaController(this)
mediaController.setAnchorView(videoView)
videoView.setMediaController(mediaController)

// 播放本地视频
videoView.setVideoPath("path/to/video.mp4")
videoView.start()

// 或播放网络视频
videoView.setVideoURI(Uri.parse("https://example.com/video.mp4"))
videoView.start()

// 设置监听器
videoView.setOnPreparedListener { mp ->
    mp.isLooping = true
}
videoView.setOnErrorListener { mp, what, extra ->
    Log.e(TAG, "视频播放错误: $what, $extra")
    true
}
```

使用ExoPlayer播放视频：

```gradle
dependencies {
    implementation 'com.google.android.exoplayer:exoplayer:2.18.7'
}
```

```xml
<com.google.android.exoplayer2.ui.PlayerView
    android:id="@+id/player_view"
    android:layout_width="match_parent"
    android:layout_height="wrap_content" />
```

```kotlin
private var player: ExoPlayer? = null

private fun initializePlayer() {
    player = ExoPlayer.Builder(this).build()
    findViewById<PlayerView>(R.id.player_view).player = player
    
    // 创建媒体项
    val mediaItem = MediaItem.fromUri("https://example.com/video.mp4")
    // 或本地视频
    // val mediaItem = MediaItem.fromUri(Uri.parse("android.resource://$packageName/${R.raw.video}"))
    
    player?.setMediaItem(mediaItem)
    player?.prepare()
    player?.play()
}

override fun onStart() {
    super.onStart()
    initializePlayer()
}

override fun onStop() {
    super.onStop()
    releasePlayer()
}

private fun releasePlayer() {
    player?.release()
    player = null
}
```

### 录制视频

使用系统相机应用录制视频：

```kotlin
private fun recordVideo() {
    Intent(MediaStore.ACTION_VIDEO_CAPTURE).also { takeVideoIntent ->
        takeVideoIntent.resolveActivity(packageManager)?.also {
            startActivityForResult(takeVideoIntent, REQUEST_VIDEO_CAPTURE)
        }
    }
}

override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (requestCode == REQUEST_VIDEO_CAPTURE && resultCode == RESULT_OK) {
        val videoUri: Uri? = data?.data
        videoView.setVideoURI(videoUri)
        videoView.start()
    }
}
```

使用CameraX录制视频：

```kotlin
private var videoCapture: VideoCapture<Recorder>? = null
private var recording: Recording? = null

private fun startCamera() {
    val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
    
    cameraProviderFuture.addListener({
        val cameraProvider = cameraProviderFuture.get()
        
        val preview = Preview.Builder()
            .build()
            .also {
                it.setSurfaceProvider(findViewById<PreviewView>(R.id.viewFinder).surfaceProvider)
            }
            
        val recorder = Recorder.Builder()
            .setQualitySelector(QualitySelector.from(Quality.HIGHEST))
            .build()
        videoCapture = VideoCapture.withOutput(recorder)
        
        val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
        
        try {
            cameraProvider.unbindAll()
            cameraProvider.bindToLifecycle(
                this, cameraSelector, preview, videoCapture)
        } catch(exc: Exception) {
            Log.e(TAG, "相机绑定失败", exc)
        }
    }, ContextCompat.getMainExecutor(this))
}

private fun startRecording() {
    val videoCapture = this.videoCapture ?: return
    
    val name = SimpleDateFormat("yyyy-MM-dd-HH-mm-ss-SSS", Locale.getDefault())
        .format(System.currentTimeMillis())
    val contentValues = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, name)
        put(MediaStore.MediaColumns.MIME_TYPE, "video/mp4")
        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.P) {
            put(MediaStore.Video.Media.RELATIVE_PATH, "Movies/CameraX-Video")
        }
    }
    
    val mediaStoreOutputOptions = MediaStoreOutputOptions
        .Builder(contentResolver, MediaStore.Video.Media.EXTERNAL_CONTENT_URI)
        .setContentValues(contentValues)
        .build()
        
    recording = videoCapture.output
        .prepareRecording(this, mediaStoreOutputOptions)
        .apply {
            if (PermissionChecker.checkSelfPermission(this@MainActivity,
                    Manifest.permission.RECORD_AUDIO) ==
                PermissionChecker.PERMISSION_GRANTED) {
                withAudioEnabled()
            }
        }
        .start(ContextCompat.getMainExecutor(this)) { recordEvent ->
            when(recordEvent) {
                is VideoRecordEvent.Start -> {
                    // 录制开始
                }
                is VideoRecordEvent.Finalize -> {
                    if (!recordEvent.hasError()) {
                        val msg = "视频录制成功: " +
                                "${recordEvent.outputResults.outputUri}"
                        Toast.makeText(baseContext, msg, Toast.LENGTH_SHORT).show()
                        Log.d(TAG, msg)
                    } else {
                        recording?.close()
                        recording = null
                        Log.e(TAG, "视频录制失败: ${recordEvent.error}")
                    }
                }
            }
        }
}

private fun stopRecording() {
    recording?.stop()
    recording = null
}
```

## 图像处理

### 加载和显示图像

```kotlin
// 从资源加载
imageView.setImageResource(R.drawable.image)

// 从文件加载
val bitmap = BitmapFactory.decodeFile(filePath)
imageView.setImageBitmap(bitmap)

// 使用Glide加载
Glide.with(this)
    .load("https://example.com/image.jpg")
    .placeholder(R.drawable.placeholder)
    .error(R.drawable.error)
    .into(imageView)
```

### 图像裁剪

```kotlin
private fun cropImage(uri: Uri) {
    val cropIntent = Intent("com.android.camera.action.CROP").apply {
        setDataAndType(uri, "image/*")
        putExtra("crop", "true")
        putExtra("aspectX", 1)
        putExtra("aspectY", 1)
        putExtra("outputX", 300)
        putExtra("outputY", 300)
        putExtra("return-data", true)
    }
    startActivityForResult(cropIntent, REQUEST_CROP_IMAGE)
}

override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
    if (requestCode == REQUEST_CROP_IMAGE && resultCode == RESULT_OK) {
        val extras = data?.extras
        val croppedBitmap = extras?.getParcelable<Bitmap>("data")
        imageView.setImageBitmap(croppedBitmap)
    }
}
```

### 图像滤镜

使用RenderScript应用滤镜：

```gradle
dependencies {
    implementation 'androidx.renderscript:renderscript:1.0.0'
}
```

```kotlin
// 应用模糊滤镜
private fun applyBlurFilter(bitmap: Bitmap, radius: Float): Bitmap {
    val rs = RenderScript.create(this)
    val input = Allocation.createFromBitmap(rs, bitmap)
    val output = Allocation.createTyped(rs, input.type)
    val script = ScriptIntrinsicBlur.create(rs, Element.U8_4(rs))
    script.setRadius(radius)
    script.setInput(input)
    script.forEach(output)
    output.copyTo(bitmap)
    rs.destroy()
    return bitmap
}

// 应用灰度滤镜
private fun applyGrayscaleFilter(bitmap: Bitmap): Bitmap {
    val width = bitmap.width
    val height = bitmap.height
    val result = Bitmap.createBitmap(width, height, bitmap.config)
    
    for (x in 0 until width) {
        for (y in 0 until height) {
            val pixel = bitmap.getPixel(x, y)
            val alpha = Color.alpha(pixel)
            val red = Color.red(pixel)
            val green = Color.green(pixel)
            val blue = Color.blue(pixel)
            
            val gray = (0.299 * red + 0.587 * green + 0.114 * blue).toInt()
            result.setPixel(x, y, Color.argb(alpha, gray, gray, gray))
        }
    }
    
    return result
}
```

## 媒体存储

### 保存媒体到公共目录

```kotlin
// 保存图片到相册
private fun saveImageToGallery(bitmap: Bitmap, title: String, description: String): Uri? {
    val values = ContentValues().apply {
        put(MediaStore.Images.Media.TITLE, title)
        put(MediaStore.Images.Media.DESCRIPTION, description)
        put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            put(MediaStore.Images.Media.DATE_TAKEN, System.currentTimeMillis())
            put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/MyApp")
            put(MediaStore.Images.Media.IS_PENDING, 1)
        }
    }
    
    val resolver = contentResolver
    val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)
    
    uri?.let {
        resolver.openOutputStream(it)?.use { outputStream ->
            bitmap.compress(Bitmap.CompressFormat.JPEG, 90, outputStream)
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            values.clear()
            values.put(MediaStore.Images.Media.IS_PENDING, 0)
            resolver.update(it, values, null, null)
        }
    }
    
    return uri
}

// 保存视频到相册
private fun saveVideoToGallery(videoFile: File): Uri? {
    val values = ContentValues().apply {
        put(MediaStore.Video.Media.TITLE, videoFile.name)
        put(MediaStore.Video.Media.DISPLAY_NAME, videoFile.name)
        put(MediaStore.Video.Media.MIME_TYPE, "video/mp4")
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            put(MediaStore.Video.Media.DATE_TAKEN, System.currentTimeMillis())
            put(MediaStore.Video.Media.RELATIVE_PATH, "Movies/MyApp")
            put(MediaStore.Video.Media.IS_PENDING, 1)
        } else {
            put(MediaStore.Video.Media.DATA, videoFile.absolutePath)
        }
    }
    
    val resolver = contentResolver
    val uri = resolver.insert(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, values)
    
    uri?.let {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            resolver.openOutputStream(it)?.use { outputStream ->
                videoFile.inputStream().use { inputStream ->
                    inputStream.copyTo(outputStream)
                }
            }
            
            values.clear()
            values.put(MediaStore.Video.Media.IS_PENDING, 0)
            resolver.update(it, values, null, null)
        }
    }
    
    return uri
}
```

### 查询媒体文件

```kotlin
// 查询图片
private fun queryImages(): List<MediaItem> {
    val images = mutableListOf<MediaItem>()
    
    val projection = arrayOf(
        MediaStore.Images.Media._ID,
        MediaStore.Images.Media.DISPLAY_NAME,
        MediaStore.Images.Media.DATE_ADDED
    )
    
    val sortOrder = "${MediaStore.Images.Media.DATE_ADDED} DESC"
    
    contentResolver.query(
        MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
        projection,
        null,
        null,
        sortOrder
    )?.use { cursor ->
        val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
        val nameColumn = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DISPLAY_NAME)
        val dateColumn = cursor.getColumnIndexOrThrow(MediaStore.Images.Media.DATE_ADDED)
        
        while (cursor.moveToNext()) {
            val id = cursor.getLong(idColumn)
            val name = cursor.getString(nameColumn)
            val date = cursor.getLong(dateColumn)
            
            val contentUri = ContentUris.withAppendedId(
                MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
                id
            )
            
            images.add(MediaItem(id, contentUri, name, date))
        }
    }
    
    return images
}

data class MediaItem(
    val id: Long,
    val uri: Uri,
    val name: String,
    val date: Long
)
```

## 总结

本文档介绍了Android多媒体开发的核心内容，包括相机操作、音频处理、视频处理、图像处理和媒体存储。通过这些API，开发者可以在应用中实现丰富的多媒体功能，提升用户体验。

## 下一步学习

- [位置服务与地图](location-maps.md)
- [后台处理](background-processing.md)
- [通知与推送](notifications.md)
