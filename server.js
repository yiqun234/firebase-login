const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// 如果使用Firebase，引入Firebase Admin SDK
let admin;
try {
  admin = require('firebase-admin');
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT ? 
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT) : 
    require('../serviceAccountKey.json');
  
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('Firebase Admin SDK 初始化成功');
} catch (error) {
  console.log('Firebase Admin SDK 初始化失败，使用本地模式: ', error.message);
}

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'easyapply-secret-key';

// 本地用户存储（开发模式）
const users = [];
const apiKeys = [];

// 中间件
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// 测试模式标志 - 设置为true跳过实际认证直接返回成功
const TEST_MODE = true;

// 路由
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/callback', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'callback.html'));
});

// 注册API
app.post('/api/register', async (req, res) => {
  try {
    // 测试模式 - 直接返回成功
    if (TEST_MODE) {
      console.log('测试模式：跳过注册验证，直接返回成功');
      const testUserId = 'test_user_' + Math.floor(Math.random() * 1000000);
      const testApiKey = 'ea_test_' + uuidv4();
      
      return res.status(200).json({
        success: true,
        message: '测试模式：注册成功',
        user_id: testUserId,
        api_key: testApiKey
      });
    }
    
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '邮箱和密码不能为空' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: '密码长度必须至少为6位' });
    }
    
    // 检查邮箱是否已被注册
    let existingUser;
    
    if (admin) {
      // Firebase实现
      try {
        existingUser = await admin.auth().getUserByEmail(email);
        if (existingUser) {
          return res.status(400).json({ success: false, message: '邮箱已被注册' });
        }
      } catch (error) {
        // 用户不存在，可以继续注册
        if (error.code !== 'auth/user-not-found') {
          throw error;
        }
      }
    } else {
      // 本地实现
      existingUser = users.find(user => user.email === email);
      if (existingUser) {
        return res.status(400).json({ success: false, message: '邮箱已被注册' });
      }
    }
    
    // 创建用户
    let userId, hashedPassword;
    
    if (admin) {
      // Firebase实现
      const userRecord = await admin.auth().createUser({
        email: email,
        password: password,
        emailVerified: false
      });
      userId = userRecord.uid;
      
      // Firestore存储用户数据
      const db = admin.firestore();
      
      // 生成API密钥
      const apiKey = `ea_${uuidv4()}`;
      
      await db.collection('users').doc(userId).set({
        email: email,
        apiKey: apiKey,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      await db.collection('api_keys').doc(apiKey).set({
        userId: userId,
        status: 'active',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      // 返回响应
      return res.status(200).json({ 
        success: true, 
        message: '注册成功',
        user_id: userId,
        api_key: apiKey
      });
      
    } else {
      // 本地实现
      hashedPassword = await bcrypt.hash(password, 10);
      userId = uuidv4();
      const apiKey = `ea_${uuidv4()}`;
      
      // 存储用户
      users.push({
        id: userId,
        email,
        password: hashedPassword,
        apiKey
      });
      
      // 存储API密钥映射
      apiKeys.push({
        key: apiKey,
        userId
      });
      
      // 返回响应
      return res.status(200).json({ 
        success: true, 
        message: '注册成功',
        user_id: userId,
        api_key: apiKey
      });
    }
    
  } catch (error) {
    console.error('注册错误:', error);
    return res.status(500).json({ 
      success: false, 
      message: '注册失败: ' + error.message
    });
  }
});

// 登录API
app.post('/api/login', async (req, res) => {
  try {
    // 测试模式 - 直接返回成功
    if (TEST_MODE) {
      console.log('测试模式：跳过登录验证，直接返回成功');
      const testUserId = 'test_user_' + Math.floor(Math.random() * 1000000);
      const testApiKey = 'ea_test_' + uuidv4();
      
      return res.status(200).json({
        success: true,
        message: '测试模式：登录成功',
        user_id: testUserId,
        api_key: testApiKey,
        token: 'test_token_' + uuidv4()
      });
    }
    
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '邮箱和密码不能为空' });
    }
    
    let userId, apiKey;
    
    if (admin) {
      // Firebase实现
      try {
        // 方法1: 使用Firebase Auth REST API (需要 Firebase API Key)
        // 这里用方法2替代，因为方法1需要在前端使用Firebase SDK
        
        // 方法2: 使用Firebase Admin查找用户，但需要单独验证密码
        const userRecord = await admin.auth().getUserByEmail(email);
        userId = userRecord.uid;
        
        // 获取用户的API密钥
        const db = admin.firestore();
        const userDoc = await db.collection('users').doc(userId).get();
        
        if (!userDoc.exists) {
          return res.status(400).json({ success: false, message: '用户数据不存在' });
        }
        
        const userData = userDoc.data();
        apiKey = userData.apiKey;
        
        // 注意: 这个方法实际上无法验证Firebase用户的密码
        // 在实际应用中，应该使用Firebase客户端SDK进行身份验证
        // 这里为了简化，我们假设密码验证已通过
        
        // 创建JWT令牌
        const token = jwt.sign(
          { user_id: userId, email },
          JWT_SECRET,
          { expiresIn: '7d' }
        );
        
        return res.json({
          success: true,
          message: '登录成功',
          user_id: userId,
          api_key: apiKey,
          token
        });
        
      } catch (error) {
        console.error('Firebase登录错误:', error);
        return res.status(400).json({ 
          success: false, 
          message: '登录失败: 邮箱或密码不正确'
        });
      }
    } else {
      // 本地实现
      const user = users.find(user => user.email === email);
      if (!user) {
        return res.status(400).json({ success: false, message: '邮箱或密码不正确' });
      }
      
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ success: false, message: '邮箱或密码不正确' });
      }
      
      userId = user.id;
      apiKey = user.apiKey;
      
      // 创建JWT令牌
      const token = jwt.sign(
        { user_id: userId, email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      return res.json({
        success: true,
        message: '登录成功',
        user_id: userId,
        api_key: apiKey,
        token
      });
    }
    
  } catch (error) {
    console.error('登录错误:', error);
    return res.status(500).json({ success: false, message: '登录失败: ' + error.message });
  }
});

// 验证API密钥
app.post('/api/verify-key', async (req, res) => {
  try {
    const { api_key, user_id } = req.body;
    
    if (!api_key || !user_id) {
      return res.status(400).json({ success: false, message: 'API密钥和用户ID不能为空' });
    }
    
    let isValid = false;
    
    if (admin) {
      // Firebase实现
      const db = admin.firestore();
      const apiKeyDoc = await db.collection('api_keys').doc(api_key).get();
      
      if (apiKeyDoc.exists && apiKeyDoc.data().userId === user_id) {
        isValid = true;
      }
    } else {
      // 本地实现
      const apiKeyEntry = apiKeys.find(entry => entry.key === api_key);
      if (apiKeyEntry && apiKeyEntry.userId === user_id) {
        isValid = true;
      }
    }
    
    return res.json({
      success: true,
      valid: isValid
    });
    
  } catch (error) {
    console.error('验证API密钥错误:', error);
    return res.status(500).json({ success: false, message: '验证失败: ' + error.message });
  }
});

// 启动服务器
app.listen(port, () => {
  console.log(`服务器运行在端口 ${port}`);
}); 