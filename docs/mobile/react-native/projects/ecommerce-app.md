# React Native 电商应用开发

本文档提供了使用 React Native 构建电商应用的全面指南，涵盖关键功能实现、架构设计和最佳实践。

## 目录

- [应用架构](#应用架构)
- [用户认证](#用户认证)
- [产品展示](#产品展示)
- [购物车实现](#购物车实现)
- [支付集成](#支付集成)
- [订单管理](#订单管理)
- [用户评价系统](#用户评价系统)
- [性能优化](#性能优化)
- [示例代码](#示例代码)

## 应用架构

电商应用架构建议采用以下结构：

```
src/
├── api/                # API 请求
├── assets/             # 静态资源
├── components/         # 可复用组件
│   ├── common/         # 通用组件
│   ├── product/        # 产品相关组件
│   └── checkout/       # 结账相关组件
├── navigation/         # 导航配置
├── screens/            # 屏幕组件
├── store/              # 状态管理
│   ├── actions/        # 操作定义
│   ├── reducers/       # 状态更新逻辑
│   └── selectors/      # 状态选择器
├── theme/              # 主题和样式
├── utils/              # 工具函数
└── App.js              # 入口文件
```

### 状态管理

推荐使用 Redux 或 Context API 进行状态管理，特别是购物车、用户信息和产品列表等数据：

```javascript
// 使用 Redux Toolkit 设置存储
import { configureStore } from '@reduxjs/toolkit';
import cartReducer from './slices/cartSlice';
import authReducer from './slices/authSlice';
import productsReducer from './slices/productsSlice';

export const store = configureStore({
  reducer: {
    cart: cartReducer,
    auth: authReducer,
    products: productsReducer,
  },
});
```

## 用户认证

### 认证流程

1. 注册/登录界面
2. 社交媒体登录整合
3. 密码重置功能
4. 持久化登录状态

使用 `@react-native-firebase/auth` 或 `AWS Amplify` 实现身份验证：

```javascript
// 使用 Firebase 的邮箱密码认证
import auth from '@react-native-firebase/auth';

const signIn = async (email, password) => {
  try {
    const response = await auth().signInWithEmailAndPassword(email, password);
    return response.user;
  } catch (error) {
    throw new Error(error.message);
  }
};

const signUp = async (email, password) => {
  try {
    const response = await auth().createUserWithEmailAndPassword(email, password);
    return response.user;
  } catch (error) {
    throw new Error(error.message);
  }
};
```

### 认证组件示例

```javascript
// screens/SignInScreen.js
import React, { useState } from 'react';
import { View, TextInput, Button, StyleSheet, Alert } from 'react-native';
import { signIn } from '../api/auth';

const SignInScreen = ({ navigation }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSignIn = async () => {
    if (!email || !password) {
      Alert.alert('错误', '请填写所有字段');
      return;
    }

    setLoading(true);
    try {
      const user = await signIn(email, password);
      // 处理登录成功
    } catch (error) {
      Alert.alert('登录失败', error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={styles.container}>
      <TextInput
        style={styles.input}
        placeholder="电子邮件"
        value={email}
        onChangeText={setEmail}
        keyboardType="email-address"
        autoCapitalize="none"
      />
      <TextInput
        style={styles.input}
        placeholder="密码"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
      />
      <Button
        title={loading ? "登录中..." : "登录"}
        onPress={handleSignIn}
        disabled={loading}
      />
      <Button
        title="注册新账户"
        onPress={() => navigation.navigate('SignUp')}
        type="clear"
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    justifyContent: 'center',
  },
  input: {
    height: 50,
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    marginBottom: 15,
    paddingHorizontal: 10,
  },
});

export default SignInScreen;
```

## 产品展示

### 产品列表与分类

实现产品列表需要考虑：

1. 分类筛选
2. 搜索功能
3. 排序选项（价格、评分等）
4. 分页加载

```javascript
// screens/ProductListScreen.js
import React, { useState, useEffect } from 'react';
import { FlatList, ActivityIndicator, View, StyleSheet } from 'react-native';
import { useSelector, useDispatch } from 'react-redux';
import { fetchProducts } from '../store/slices/productsSlice';
import ProductCard from '../components/product/ProductCard';
import FilterBar from '../components/product/FilterBar';

const ProductListScreen = ({ route, navigation }) => {
  const { categoryId } = route.params || {};
  const [page, setPage] = useState(1);
  const [filters, setFilters] = useState({
    sortBy: 'popularity',
    priceRange: [0, 10000],
  });
  
  const dispatch = useDispatch();
  const { products, loading, hasMore } = useSelector(state => state.products);
  
  useEffect(() => {
    loadProducts();
  }, [categoryId, filters, page]);
  
  const loadProducts = () => {
    dispatch(fetchProducts({ 
      categoryId, 
      page, 
      sortBy: filters.sortBy,
      minPrice: filters.priceRange[0],
      maxPrice: filters.priceRange[1]
    }));
  };
  
  const handleEndReached = () => {
    if (!loading && hasMore) {
      setPage(prevPage => prevPage + 1);
    }
  };
  
  const renderItem = ({ item }) => (
    <ProductCard
      product={item}
      onPress={() => navigation.navigate('ProductDetail', { productId: item.id })}
    />
  );
  
  return (
    <View style={styles.container}>
      <FilterBar
        filters={filters}
        onFilterChange={setFilters}
      />
      <FlatList
        data={products}
        renderItem={renderItem}
        keyExtractor={item => item.id.toString()}
        numColumns={2}
        onEndReached={handleEndReached}
        onEndReachedThreshold={0.1}
        ListFooterComponent={loading ? <ActivityIndicator /> : null}
        contentContainerStyle={styles.list}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8f8f8',
  },
  list: {
    padding: 8,
  },
});

export default ProductListScreen;
```

### 产品详情页

产品详情页应包含：

1. 图片轮播
2. 详细说明
3. 规格选择
4. 用户评价
5. 相关推荐

```javascript
// components/product/ImageCarousel.js
import React, { useState, useRef } from 'react';
import { View, Image, FlatList, Dimensions, StyleSheet } from 'react-native';

const { width } = Dimensions.get('window');

const ImageCarousel = ({ images }) => {
  const [activeIndex, setActiveIndex] = useState(0);
  const flatListRef = useRef(null);

  const handleScroll = (event) => {
    const slideIndex = Math.round(event.nativeEvent.contentOffset.x / width);
    if (slideIndex !== activeIndex) {
      setActiveIndex(slideIndex);
    }
  };

  return (
    <View style={styles.container}>
      <FlatList
        ref={flatListRef}
        data={images}
        horizontal
        pagingEnabled
        showsHorizontalScrollIndicator={false}
        onScroll={handleScroll}
        renderItem={({ item }) => (
          <Image source={{ uri: item }} style={styles.image} />
        )}
        keyExtractor={(_, index) => index.toString()}
      />
      
      <View style={styles.pagination}>
        {images.map((_, index) => (
          <View
            key={index}
            style={[
              styles.paginationDot,
              index === activeIndex && styles.paginationDotActive,
            ]}
          />
        ))}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    height: 300,
  },
  image: {
    width,
    height: 300,
    resizeMode: 'cover',
  },
  pagination: {
    flexDirection: 'row',
    position: 'absolute',
    bottom: 10,
    alignSelf: 'center',
  },
  paginationDot: {
    width: 8,
    height: 8,
    borderRadius: 4,
    marginHorizontal: 4,
    backgroundColor: 'rgba(255, 255, 255, 0.5)',
  },
  paginationDotActive: {
    backgroundColor: 'white',
  },
});

export default ImageCarousel;
```

## 购物车实现

### 购物车状态管理

使用 Redux 管理购物车状态：

```javascript
// store/slices/cartSlice.js
import { createSlice } from '@reduxjs/toolkit';

const initialState = {
  items: [],
  total: 0,
};

export const cartSlice = createSlice({
  name: 'cart',
  initialState,
  reducers: {
    addToCart: (state, action) => {
      const { product, quantity, selectedOptions } = action.payload;
      const existingItemIndex = state.items.findIndex(
        item => item.product.id === product.id && 
               JSON.stringify(item.selectedOptions) === JSON.stringify(selectedOptions)
      );

      if (existingItemIndex !== -1) {
        // 更新已有商品数量
        state.items[existingItemIndex].quantity += quantity;
      } else {
        // 添加新商品
        state.items.push({ product, quantity, selectedOptions });
      }
      
      // 重新计算总价
      state.total = state.items.reduce(
        (sum, item) => sum + item.product.price * item.quantity, 
        0
      );
    },
    updateQuantity: (state, action) => {
      const { itemId, quantity } = action.payload;
      const itemIndex = state.items.findIndex(item => item.product.id === itemId);
      
      if (itemIndex !== -1) {
        state.items[itemIndex].quantity = quantity;
        
        // 如果数量为0，移除该商品
        if (quantity <= 0) {
          state.items.splice(itemIndex, 1);
        }
        
        // 重新计算总价
        state.total = state.items.reduce(
          (sum, item) => sum + item.product.price * item.quantity, 
          0
        );
      }
    },
    removeFromCart: (state, action) => {
      const itemId = action.payload;
      state.items = state.items.filter(item => item.product.id !== itemId);
      
      // 重新计算总价
      state.total = state.items.reduce(
        (sum, item) => sum + item.product.price * item.quantity, 
        0
      );
    },
    clearCart: (state) => {
      state.items = [];
      state.total = 0;
    },
  },
});

export const { addToCart, updateQuantity, removeFromCart, clearCart } = cartSlice.actions;

export default cartSlice.reducer;
```

### 购物车组件

```javascript
// screens/CartScreen.js
import React from 'react';
import { View, Text, FlatList, Button, StyleSheet } from 'react-native';
import { useSelector, useDispatch } from 'react-redux';
import { updateQuantity, removeFromCart } from '../store/slices/cartSlice';
import CartItem from '../components/checkout/CartItem';
import EmptyCart from '../components/checkout/EmptyCart';

const CartScreen = ({ navigation }) => {
  const { items, total } = useSelector(state => state.cart);
  const dispatch = useDispatch();
  
  const handleQuantityChange = (itemId, newQuantity) => {
    dispatch(updateQuantity({ itemId, quantity: newQuantity }));
  };
  
  const handleRemoveItem = (itemId) => {
    dispatch(removeFromCart(itemId));
  };
  
  if (items.length === 0) {
    return <EmptyCart onStartShopping={() => navigation.navigate('Home')} />;
  }
  
  return (
    <View style={styles.container}>
      <FlatList
        data={items}
        renderItem={({ item }) => (
          <CartItem
            item={item}
            onQuantityChange={(quantity) => 
              handleQuantityChange(item.product.id, quantity)
            }
            onRemove={() => handleRemoveItem(item.product.id)}
          />
        )}
        keyExtractor={item => `${item.product.id}-${JSON.stringify(item.selectedOptions)}`}
      />
      
      <View style={styles.summary}>
        <Text style={styles.totalText}>总计: ¥{total.toFixed(2)}</Text>
        <Button
          title="结算"
          onPress={() => navigation.navigate('Checkout')}
        />
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
  },
  summary: {
    padding: 16,
    borderTopWidth: 1,
    borderColor: '#eee',
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  totalText: {
    fontSize: 18,
    fontWeight: 'bold',
  },
});

export default CartScreen;
```

## 支付集成

### 支付网关集成

常用支付网关：

1. Stripe
2. PayPal
3. 支付宝
4. 微信支付

下面是集成 Stripe 的示例：

```javascript
// 安装: npm install @stripe/stripe-react-native

// components/checkout/StripePayment.js
import React, { useState } from 'react';
import { View, Alert, StyleSheet } from 'react-native';
import { CardField, useStripe } from '@stripe/stripe-react-native';

const StripePayment = ({ amount, onPaymentSuccess, onPaymentError }) => {
  const { confirmPayment } = useStripe();
  const [cardDetails, setCardDetails] = useState(null);
  
  const handlePayPress = async () => {
    if (!cardDetails?.complete) {
      Alert.alert('错误', '请完成信用卡信息');
      return;
    }
    
    try {
      // 从后端获取支付意图
      const response = await fetch('https://your-api.com/create-payment-intent', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          amount: amount * 100, // Stripe使用分为单位
          currency: 'cny',
        }),
      });
      
      const { clientSecret } = await response.json();
      
      // 确认支付
      const { paymentIntent, error } = await confirmPayment(clientSecret, {
        type: 'Card',
      });
      
      if (error) {
        onPaymentError(error.message);
      } else if (paymentIntent) {
        onPaymentSuccess(paymentIntent);
      }
    } catch (error) {
      onPaymentError('支付过程中发生错误');
    }
  };
  
  return (
    <View style={styles.container}>
      <CardField
        postalCodeEnabled={false}
        placeholder={{
          number: '4242 4242 4242 4242',
        }}
        cardStyle={styles.card}
        style={styles.cardContainer}
        onCardChange={setCardDetails}
      />
      <Button
        title="支付 ¥{amount.toFixed(2)}"
        onPress={handlePayPress}
        disabled={!cardDetails?.complete}
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    width: '100%',
    marginVertical: 20,
  },
  cardContainer: {
    height: 50,
    marginVertical: 10,
  },
  card: {
    backgroundColor: '#efefefef',
  },
});

export default StripePayment;
```

## 订单管理

### 订单跟踪

订单状态管理及跟踪流程：

1. 已下单
2. 支付中
3. 已支付
4. 处理中
5. 已发货
6. 已送达
7. 已完成

```javascript
// screens/OrderDetailScreen.js
import React, { useEffect, useState } from 'react';
import { View, Text, StyleSheet, ScrollView, ActivityIndicator } from 'react-native';
import { fetchOrderDetails } from '../api/orders';
import OrderStatusBar from '../components/order/OrderStatusBar';
import OrderItems from '../components/order/OrderItems';
import AddressInfo from '../components/order/AddressInfo';
import PaymentInfo from '../components/order/PaymentInfo';

const OrderDetailScreen = ({ route }) => {
  const { orderId } = route.params;
  const [order, setOrder] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  useEffect(() => {
    const getOrderDetails = async () => {
      try {
        setLoading(true);
        const data = await fetchOrderDetails(orderId);
        setOrder(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    
    getOrderDetails();
  }, [orderId]);
  
  if (loading) {
    return <ActivityIndicator size="large" style={styles.loader} />;
  }
  
  if (error) {
    return <Text style={styles.errorText}>加载订单失败: {error}</Text>;
  }
  
  return (
    <ScrollView style={styles.container}>
      <Text style={styles.orderId}>订单号: {order.id}</Text>
      <Text style={styles.date}>
        下单时间: {new Date(order.createdAt).toLocaleDateString()}
      </Text>
      
      <OrderStatusBar status={order.status} steps={order.statusHistory} />
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>商品信息</Text>
        <OrderItems items={order.items} />
      </View>
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>配送信息</Text>
        <AddressInfo address={order.shippingAddress} />
      </View>
      
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>支付信息</Text>
        <PaymentInfo 
          paymentMethod={order.paymentMethod}
          total={order.total}
          status={order.paymentStatus}
        />
      </View>
    </ScrollView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    padding: 16,
  },
  loader: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  errorText: {
    color: 'red',
    textAlign: 'center',
    marginTop: 20,
  },
  orderId: {
    fontSize: 16,
    fontWeight: 'bold',
  },
  date: {
    color: '#666',
    marginBottom: 20,
  },
  section: {
    marginVertical: 15,
    borderWidth: 1,
    borderColor: '#eee',
    borderRadius: 8,
    padding: 12,
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 10,
  },
});

export default OrderDetailScreen;
```

## 用户评价系统

实现评价系统，包括：

1. 星级评分
2. 文字评价
3. 图片上传
4. 评价管理

```javascript
// components/review/RatingInput.js
import React from 'react';
import { View, TouchableOpacity, StyleSheet } from 'react-native';
import Icon from 'react-native-vector-icons/MaterialIcons';

const RatingInput = ({ rating, setRating, size = 30, color = '#FFD700' }) => {
  return (
    <View style={styles.container}>
      {[1, 2, 3, 4, 5].map((star) => (
        <TouchableOpacity
          key={star}
          onPress={() => setRating(star)}
        >
          <Icon
            name={rating >= star ? 'star' : 'star-border'}
            size={size}
            color={color}
            style={styles.star}
          />
        </TouchableOpacity>
      ))}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flexDirection: 'row',
    justifyContent: 'center',
    marginVertical: 10,
  },
  star: {
    marginHorizontal: 2,
  },
});

export default RatingInput;
```

## 性能优化

电商应用性能优化关键点：

1. **图片优化**：
   - 使用适当尺寸的图片
   - 实现图片懒加载
   - 使用缓存策略

2. **列表优化**：
   - 使用 `FlatList` 的 `getItemLayout` 提高性能
   - 实现虚拟列表或分页加载
   - 使用 `memo` 优化列表项渲染

3. **状态管理优化**：
   - 使用选择器避免不必要的重新渲染
   - 优化 reducer 逻辑
   - 考虑使用不可变数据结构

4. **网络优化**：
   - 实现数据预取
   - 使用缓存策略
   - 优化 API 请求

## 示例代码

### 产品卡片组件

```javascript
// components/product/ProductCard.js
import React, { memo } from 'react';
import { View, Text, Image, TouchableOpacity, StyleSheet } from 'react-native';
import { useDispatch } from 'react-redux';
import { addToCart } from '../../store/slices/cartSlice';
import Icon from 'react-native-vector-icons/MaterialIcons';
import FastImage from 'react-native-fast-image';

const ProductCard = ({ product, onPress }) => {
  const dispatch = useDispatch();
  
  const handleAddToCart = () => {
    dispatch(addToCart({
      product,
      quantity: 1,
      selectedOptions: {},
    }));
  };
  
  return (
    <TouchableOpacity 
      style={styles.container}
      onPress={onPress}
      activeOpacity={0.7}
    >
      <FastImage 
        source={{ uri: product.imageUrl }} 
        style={styles.image}
        resizeMode={FastImage.resizeMode.cover}
      />
      
      {product.discount > 0 && (
        <View style={styles.discountBadge}>
          <Text style={styles.discountText}>-{product.discount}%</Text>
        </View>
      )}
      
      <View style={styles.details}>
        <Text style={styles.title} numberOfLines={2}>{product.name}</Text>
        
        <View style={styles.priceRow}>
          <Text style={styles.price}>¥{product.price.toFixed(2)}</Text>
          {product.originalPrice > product.price && (
            <Text style={styles.originalPrice}>
              ¥{product.originalPrice.toFixed(2)}
            </Text>
          )}
        </View>
        
        <View style={styles.ratingContainer}>
          <Icon name="star" size={14} color="#FFD700" />
          <Text style={styles.rating}>{product.rating.toFixed(1)}</Text>
          <Text style={styles.ratingCount}>({product.ratingCount})</Text>
        </View>
      </View>
      
      <TouchableOpacity 
        style={styles.addButton}
        onPress={handleAddToCart}
      >
        <Icon name="add-shopping-cart" size={20} color="#fff" />
      </TouchableOpacity>
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    margin: 8,
    backgroundColor: '#fff',
    borderRadius: 8,
    elevation: 2,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.1,
    shadowRadius: 2,
    position: 'relative',
    overflow: 'hidden',
  },
  image: {
    height: 150,
    width: '100%',
  },
  discountBadge: {
    position: 'absolute',
    top: 10,
    left: 10,
    backgroundColor: '#ff3b30',
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  discountText: {
    color: '#fff',
    fontSize: 12,
    fontWeight: 'bold',
  },
  details: {
    padding: 10,
  },
  title: {
    fontSize: 14,
    fontWeight: '500',
    marginBottom: 5,
    height: 40,
  },
  priceRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 5,
  },
  price: {
    fontSize: 16,
    fontWeight: 'bold',
    color: '#ff3b30',
  },
  originalPrice: {
    fontSize: 12,
    color: '#999',
    textDecorationLine: 'line-through',
    marginLeft: 5,
  },
  ratingContainer: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  rating: {
    fontSize: 12,
    color: '#666',
    marginLeft: 2,
  },
  ratingCount: {
    fontSize: 12,
    color: '#999',
    marginLeft: 2,
  },
  addButton: {
    position: 'absolute',
    bottom: 10,
    right: 10,
    backgroundColor: '#007bff',
    width: 30,
    height: 30,
    borderRadius: 15,
    justifyContent: 'center',
    alignItems: 'center',
  },
});

export default memo(ProductCard);
```

通过以上组件和功能实现，你可以构建一个功能完整、性能优化的 React Native 电商应用。根据实际需求，你可以进一步扩展和定制这些功能。
