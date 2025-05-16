const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const { OpenAI } = require('openai');
require('dotenv').config();

// Import Firebase Admin SDK if using Firebase
let admin;
try {
  admin = require('firebase-admin');
  const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT ? 
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT) : 
    require('./serviceAccountKey.json');
  
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('Firebase Admin SDK initialized successfully');
} catch (error) {
  console.log('Firebase Admin SDK initialization failed, using local mode: ', error.message);
}

// Firebase客户端配置信息，现在只存储在服务器端
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY || "AIzaSyAeHptX0vuZVy1Oos_LyOSjtoVTU4b6m9s",
  authDomain: process.env.FIREBASE_AUTH_DOMAIN || "easy-apply-bot.firebaseapp.com",
  projectId: process.env.FIREBASE_PROJECT_ID || "easy-apply-bot",
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET || "easy-apply-bot.firebasestorage.app",
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || "40362191929",
  appId: process.env.FIREBASE_APP_ID || "1:40362191929:web:cbfec3cafe37f6e85f31e8",
  measurementId: process.env.FIREBASE_MEASUREMENT_ID || "G-B4JTE653K5"
};

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'easyapply-secret-key';

// Local user storage (development mode)
const users = [];
const apiKeys = [];

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Test mode flag - set to true to skip actual authentication and return success
const TEST_MODE = false;

// Middleware to verify API key
async function verifyApiKeyMiddleware(req, res, next) {
  try {
    // Support both header and body
    const apiKey = req.headers['x-api-key'] || req.body.api_key;
    const userId = req.headers['x-user-id'] || req.body.user_id;
    if (!apiKey || !userId) {
      return res.status(401).json({ error: 'API key and user ID are required' });
    }
    let isValid = false;
    if (admin) {
      // Firebase mode
      const db = admin.firestore();
      const apiKeyDoc = await db.collection('api_keys').doc(apiKey).get();
      if (apiKeyDoc.exists && apiKeyDoc.data().userId === userId) {
        isValid = true;
      }
    } else {
      // Local mode
      const apiKeyEntry = apiKeys.find(entry => entry.key === apiKey);
      if (apiKeyEntry && apiKeyEntry.userId === userId) {
        isValid = true;
      }
    }
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid API key or user ID' });
    }
    // Attach user info to request if needed
    req.apiUserId = userId;
    req.apiKey = apiKey;
    next();
  } catch (error) {
    console.error('API key verification middleware error:', error);
    return res.status(500).json({ error: 'API key verification failed: ' + error.message });
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'auth.html'));
});

app.get('/auth/callback', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'callback.html'));
});

// 增加Firebase配置API
app.get('/api/firebase-config', (req, res) => {
  res.json(firebaseConfig);
});

// 登录API
app.post('/api/auth/login', async (req, res) => {
  try {
    // Test mode - return success directly
    if (TEST_MODE) {
      console.log('Test mode: Skipping login verification, returning success directly');
      const testUserId = 'test_user_' + Math.floor(Math.random() * 1000000);
      const testApiKey = 'ea_test_' + uuidv4();
      
      return res.status(200).json({
        success: true,
        message: 'Test mode: Login successful',
        user_id: testUserId,
        api_key: testApiKey,
        token: 'test_token_' + uuidv4()
      });
    }
    
    const { email, password, callback } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '电子邮箱和密码不能为空' });
    }
    
    let userId, apiKey;
    
    if (admin) {
      // Firebase后端验证实现
      try {
        // 使用Firebase Admin SDK验证用户
        const auth = admin.auth();
        
        // 首先尝试获取用户记录
        let userRecord;
        try {
          userRecord = await auth.getUserByEmail(email);
        } catch (error) {
          return res.status(400).json({ 
            success: false, 
            message: '登录失败：邮箱或密码不正确'
          });
        }
        
        // 检查邮箱是否已验证
        if (!userRecord.emailVerified) {
          // 重新发送验证邮件
          const verificationLink = await auth.generateEmailVerificationLink(email);
          console.log(`Re-sending verification email link for ${email}: ${verificationLink}`);
          
          return res.status(401).json({ 
            success: false, 
            message: '邮箱未验证。我们已发送新的验证邮件，请检查您的收件箱。',
            email_verified: false
          });
        }
        
        // 获取用户的API密钥
        const db = admin.firestore();
        const userDoc = await db.collection('users').doc(userRecord.uid).get();
        
        if (!userDoc.exists) {
          return res.status(400).json({ success: false, message: '用户数据不存在' });
        }
        
        const userData = userDoc.data();
        apiKey = userData.apiKey;
        userId = userRecord.uid;
        
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
          token,
          email_verified: true
        });
        
      } catch (error) {
        console.error('Firebase登录错误:', error);
        return res.status(400).json({ 
          success: false, 
          message: '登录失败：邮箱或密码不正确'
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
      
      // 检查邮箱是否已验证（本地模式）
      if (!user.emailVerified) {
        // 在本地模式中，我们模拟验证
        user.emailVerified = true;
        console.log(`Local mode: Auto-verifying email for ${email}`);
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
        token,
        email_verified: true
      });
    }
    
  } catch (error) {
    console.error('登录错误:', error);
    return res.status(500).json({ success: false, message: '登录失败: ' + error.message });
  }
});

// 注册API
app.post('/api/auth/register', async (req, res) => {
  try {
    // Test mode - return success directly
    if (TEST_MODE) {
      console.log('Test mode: Skipping registration verification, returning success directly');
      const testUserId = 'test_user_' + Math.floor(Math.random() * 1000000);
      const testApiKey = 'ea_test_' + uuidv4();
      
      return res.status(200).json({
        success: true,
        message: 'Test mode: Registration successful',
        user_id: testUserId,
        api_key: testApiKey
      });
    }
    
    const { email, password, confirmPassword, callback } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: '电子邮箱和密码不能为空' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: '密码必须至少包含6个字符' });
    }
    
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: '两次输入的密码不一致' });
    }
    
    // 检查邮箱是否已注册
    let existingUser;
    
    if (admin) {
      // Firebase实现
      try {
        existingUser = await admin.auth().getUserByEmail(email);
        if (existingUser) {
          return res.status(400).json({ success: false, message: '该邮箱已被注册' });
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
        return res.status(400).json({ success: false, message: '该邮箱已被注册' });
      }
    }
    
    // 创建用户
    let userId, hashedPassword;
    
    if (admin) {
      // Firebase实现
      const userRecord = await admin.auth().createUser({
        email: email,
        password: password,
        emailVerified: false // 用户需要验证邮箱
      });
      userId = userRecord.uid;
      
      // 发送验证邮件
      const verificationLink = await admin.auth().generateEmailVerificationLink(email);
      console.log(`Verification email link generated for ${email}: ${verificationLink}`);
      
      // 在生产环境中，你会发送这个邮件给用户
      // 现在，仅记录到控制台用于测试
      console.log(`请使用此链接验证您的邮箱: ${verificationLink}`);
      
      // 在Firestore中存储用户数据
      const db = admin.firestore();
      
      // 生成API密钥
      const apiKey = `ea_${uuidv4()}`;
      
      await db.collection('users').doc(userId).set({
        email: email,
        apiKey: apiKey,
        emailVerified: false,
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
        message: '注册成功！请检查您的邮箱以验证您的账户。',
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
        apiKey,
        emailVerified: false
      });
      
      // 存储API密钥映射
      apiKeys.push({
        key: apiKey,
        userId
      });
      
      // 返回响应
      return res.status(200).json({ 
        success: true, 
        message: '注册成功！在本地模式中，邮箱验证是模拟的。',
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

// Google登录URL获取API
app.post('/api/auth/google-url', async (req, res) => {
  try {
    const { callback } = req.body;
    
    // 在实际生产环境中，你需要使用OAuth 2.0流程
    // 这里使用简化的模拟URL，因为我们无法直接在后端实现完整的OAuth流程
    const state = Buffer.from(JSON.stringify({ callback })).toString('base64');
    const redirectUrl = `https://accounts.google.com/o/oauth2/auth?client_id=${firebaseConfig.apiKey}&redirect_uri=${encodeURIComponent(req.protocol + '://' + req.get('host') + '/auth?mode=googleAuth')}&response_type=code&scope=email%20profile&state=${state}`;
    
    res.json({
      success: true,
      authUrl: redirectUrl
    });
  } catch (error) {
    console.error('获取Google登录URL错误:', error);
    res.status(500).json({
      success: false,
      message: '无法生成Google登录URL: ' + error.message
    });
  }
});

// Google登录回调处理API
app.post('/api/auth/google-callback', async (req, res) => {
  try {
    const { code, state } = req.body;
    
    if (!code) {
      return res.status(400).json({
        success: false,
        message: '缺少授权码'
      });
    }
    
    // 在实际生产环境中，你需要使用code交换token
    // 简化起见，我们这里直接模拟授权成功
    
    if (admin) {
      // 在实际实现中，这里应该用code交换Firebase ID token
      // 简化起见，我们直接创建一个随机用户
      
      const randomEmail = `google_user_${Math.random().toString(36).substring(2)}@example.com`;
      let userRecord;
      
      try {
        // 尝试创建用户
        userRecord = await admin.auth().createUser({
          email: randomEmail,
          emailVerified: true
        });
      } catch (error) {
        return res.status(500).json({
          success: false,
          message: '创建用户失败: ' + error.message
        });
      }
      
      // 创建API密钥
      const db = admin.firestore();
      const apiKey = `ea_${uuidv4()}`;
      const userId = userRecord.uid;
      
      await db.collection('users').doc(userId).set({
        email: randomEmail,
        apiKey: apiKey,
        emailVerified: true,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        signInMethod: 'google'
      });
      
      await db.collection('api_keys').doc(apiKey).set({
        userId: userId,
        status: 'active',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      
      return res.json({
        success: true,
        message: 'Google登录成功',
        user_id: userId,
        api_key: apiKey
      });
    } else {
      // 本地实现
      const userId = uuidv4();
      const apiKey = `ea_${uuidv4()}`;
      const randomEmail = `google_user_${Math.random().toString(36).substring(2)}@example.com`;
      
      users.push({
        id: userId,
        email: randomEmail,
        apiKey,
        emailVerified: true,
        signInMethod: 'google'
      });
      
      apiKeys.push({
        key: apiKey,
        userId
      });
      
      return res.json({
        success: true,
        message: '本地模式: 模拟Google登录成功',
        user_id: userId,
        api_key: apiKey
      });
    }
  } catch (error) {
    console.error('处理Google登录回调错误:', error);
    res.status(500).json({
      success: false,
      message: '处理Google登录失败: ' + error.message
    });
  }
});

// 邮箱验证API
app.post('/api/auth/verify-email', async (req, res) => {
  try {
    const { oobCode } = req.body;
    
    if (!oobCode) {
      return res.status(400).json({
        success: false,
        message: '缺少验证码'
      });
    }
    
    if (admin) {
      try {
        // 在实际实现中，验证oobCode并标记邮箱为已验证
        // Firebase无法通过Admin SDK直接验证oobCode，通常由Firebase客户端SDK处理
        // 这里我们只是返回成功响应
        return res.json({
          success: true,
          message: '邮箱验证成功'
        });
      } catch (error) {
        console.error('验证邮箱错误:', error);
        return res.status(400).json({
          success: false,
          message: '验证邮箱失败: ' + error.message
        });
      }
    } else {
      // 本地实现
      return res.json({
        success: true,
        message: '本地模式: 模拟邮箱验证成功'
      });
    }
  } catch (error) {
    console.error('邮箱验证API错误:', error);
    res.status(500).json({
      success: false,
      message: '验证邮箱失败: ' + error.message
    });
  }
});

// 保留原有接口作为向后兼容
// 注册API（向后兼容）
app.post('/api/register', async (req, res) => {
  console.log('WARNING: Using deprecated endpoint /api/register. Please update to /api/auth/register');
  try {
    // 将请求转发给新的注册端点
    const { email, password } = req.body;
    
    // 简单验证
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password cannot be empty' 
      });
    }

    // 调整参数格式
    const requestBody = {
      email,
      password,
      confirmPassword: password, // 假设相同
      callback: req.body.callback
    };

    // 内部处理，不实际发HTTP请求
    req.body = requestBody;
    
    // 将处理交给新端点
    return app._router.handle(req, res);
  } catch (error) {
    console.error('旧注册API错误:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Registration failed: ' + error.message 
    });
  }
});

// 登录API（向后兼容）
app.post('/api/login', async (req, res) => {
  console.log('WARNING: Using deprecated endpoint /api/login. Please update to /api/auth/login');
  try {
    // 将请求转发给新的登录端点
    const { email, password } = req.body;
    
    // 简单验证
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email and password cannot be empty' 
      });
    }

    // 调整参数格式
    const requestBody = {
      email,
      password,
      callback: req.body.callback
    };

    // 内部处理，不实际发HTTP请求
    req.body = requestBody;
    req.url = '/api/auth/login';
    
    // 将处理交给新端点
    return app._router.handle(req, res);
  } catch (error) {
    console.error('旧登录API错误:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Login failed: ' + error.message 
    });
  }
});

// Google登录API（向后兼容）
app.post('/api/google-login', async (req, res) => {
  console.log('WARNING: Using deprecated endpoint /api/google-login. Please update to /api/auth/google-callback');
  try {
    const { idToken } = req.body;
    
    if (!idToken) {
      return res.status(400).json({ success: false, message: 'Google ID token is required' });
    }
    
    if (admin) {
      // Firebase实现
      try {
        // 验证Google ID token
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const uid = decodedToken.uid;
        const email = decodedToken.email;
        let userRecord;
        
        try {
          // 检查用户是否存在于Firebase Authentication
          userRecord = await admin.auth().getUser(uid);
        } catch (error) {
          if (error.code === 'auth/user-not-found') {
            // 用户不存在，创建新用户
            userRecord = await admin.auth().createUser({
              uid: uid,
              email: email,
              emailVerified: true // Google OAuth会自动验证邮箱
            });
          } else {
            throw error;
          }
        }
        
        // 初始化Firestore
        const db = admin.firestore();
        
        // 检查用户是否存在于Firestore
        let userDoc = await db.collection('users').doc(uid).get();
        let apiKey;
        
        if (!userDoc.exists) {
          // 用户不存在于Firestore，创建新条目
          apiKey = `ea_${uuidv4()}`;
          
          // 在Firestore中创建用户
          await db.collection('users').doc(uid).set({
            email: email,
            apiKey: apiKey,
            emailVerified: true,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            signInMethod: 'google'
          });
          
          // 创建API密钥条目
          await db.collection('api_keys').doc(apiKey).set({
            userId: uid,
            status: 'active',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
          });
        } else {
          // 用户存在，获取API密钥
          const userData = userDoc.data();
          apiKey = userData.apiKey;
          
          // 如果用户没有API密钥，生成一个
          if (!apiKey) {
            apiKey = `ea_${uuidv4()}`;
            await db.collection('users').doc(uid).update({
              apiKey: apiKey
            });
            
            await db.collection('api_keys').doc(apiKey).set({
              userId: uid,
              status: 'active',
              createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
          }
        }
        
        // 创建JWT令牌
        const token = jwt.sign(
          { user_id: uid, email },
          JWT_SECRET,
          { expiresIn: '7d' }
        );
        
        return res.json({
          success: true,
          message: 'Google login successful',
          user_id: uid,
          api_key: apiKey,
          token,
          email_verified: true
        });
        
      } catch (error) {
        console.error('Google登录错误:', error);
        return res.status(401).json({
          success: false,
          message: 'Invalid Google token or authentication failed: ' + error.message
        });
      }
    } else {
      // 本地实现 - 简化版用于测试
      // 在真实应用中，应通过Google的API验证Google token
      // 对于本地测试，我们只是模拟成功登录
      
      const simulatedEmail = req.body.email || 'google-user@example.com';
      
      // 检查用户是否存在于本地存储
      let user = users.find(u => u.email === simulatedEmail);
      let userId, apiKey;
      
      if (!user) {
        // 创建新用户
        userId = uuidv4();
        apiKey = `ea_${uuidv4()}`;
        
        users.push({
          id: userId,
          email: simulatedEmail,
          apiKey,
          emailVerified: true,
          signInMethod: 'google'
        });
        
        apiKeys.push({
          key: apiKey,
          userId
        });
      } else {
        userId = user.id;
        apiKey = user.apiKey;
      }
      
      // 创建JWT令牌
      const token = jwt.sign(
        { user_id: userId, email: simulatedEmail },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      return res.json({
        success: true,
        message: 'Local mode: Google login simulated',
        user_id: userId,
        api_key: apiKey,
        token,
        email_verified: true
      });
    }
  } catch (error) {
    console.error('Google登录错误:', error);
    return res.status(500).json({
      success: false,
      message: 'Google login failed: ' + error.message
    });
  }
});

// 邮箱验证确认（向后兼容）
app.get('/api/verify-email', async (req, res) => {
  try {
    // 此端点是邮箱验证确认的占位符
    // 在真实实现中，Firebase通过邮件链接自动处理验证
    // 此端点可用于自定义验证流程（如需要）
    res.send(`
      <html>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
          <h1>邮箱验证</h1>
          <p>您的邮箱已成功验证！</p>
          <p>您现在可以关闭此窗口并登录应用程序。</p>
        </body>
      </html>
    `);
  } catch (error) {
    console.error('邮箱验证错误:', error);
    res.status(500).send(`
      <html>
        <body style="font-family: Arial, sans-serif; text-align: center; margin-top: 50px;">
          <h1>邮箱验证失败</h1>
          <p>验证您的邮箱时出错: ${error.message}</p>
          <p>请重试或联系支持。</p>
        </body>
      </html>
    `);
  }
});

// 检查邮箱是否已验证（向后兼容）
app.post('/api/check-email-verified', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    
    if (admin) {
      // Firebase实现
      try {
        const userRecord = await admin.auth().getUserByEmail(email);
        return res.json({
          success: true,
          email_verified: userRecord.emailVerified
        });
      } catch (error) {
        console.error('检查邮箱验证错误:', error);
        return res.status(400).json({ 
          success: false, 
          message: '用户未找到'
        });
      }
    } else {
      // 本地实现
      const user = users.find(user => user.email === email);
      if (!user) {
        return res.status(400).json({ success: false, message: '用户未找到' });
      }
      
      return res.json({
        success: true,
        email_verified: user.emailVerified || false
      });
    }
  } catch (error) {
    console.error('检查邮箱验证错误:', error);
    return res.status(500).json({ 
      success: false, 
      message: '检查邮箱验证失败: ' + error.message
    });
  }
});

// 验证API密钥（向后兼容）
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
    console.error('API密钥验证错误:', error);
    return res.status(500).json({ success: false, message: '验证失败: ' + error.message });
  }
});

// Job fit evaluation API
app.post('/api/evaluate-job-fit', verifyApiKeyMiddleware, async (req, res) => {
  try {
    // Parse request parameters
    const { context, job_title, job_description, debug, openai_api_key } = req.body;
    
    // Validate required parameters
    if (!job_title || !job_description) {
      return res.status(400).json({
        success: false,
        error: 'Missing job title or description'
      });
    }
    
    // Get API key (prioritize key provided in request, then environment variable)
    const apiKey = openai_api_key || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(400).json({
        success: false,
        error: 'OpenAI API key not configured'
      });
    }
    
    // Initialize OpenAI client
    const openaiClient = new OpenAI({ apiKey });
    
    // Build system prompt
    let systemPrompt = `You are evaluating job fit for technical roles. 
      Recommend APPLY if:
      - Candidate meets 65 percent of the core requirements
      - Experience gap is 2 years or less
      - Has relevant transferable skills
      
      Return SKIP if:
      - Experience gap is greater than 2 years
      - Missing multiple core requirements
      - Role is clearly more senior
      - The role is focused on an uncommon technology or skill that is required and that the candidate does not have experience with
      - The role is a leadership role or a role that requires managing people and the candidate has no experience leading or managing people
      
      `;
    
    if (debug) {
      systemPrompt += `
      You are in debug mode. Return a detailed explanation of your reasoning for each requirement.

      Return APPLY or SKIP followed by a brief explanation.

      Format response as: APPLY/SKIP: [brief reason]`;
    } else {
      systemPrompt += `Return only APPLY or SKIP.`;
    }
    
    // Call OpenAI API
    const response = await openaiClient.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Job: ${job_title}\n${job_description}\n\nCandidate:\n${context}` }
      ],
      max_tokens: debug ? 250 : 1,
      temperature: 0.2
    });
    
    const answer = response.choices[0].message.content.trim();
    
    // Parse result
    const decision = answer.toUpperCase().startsWith('A'); // APPLY = true, SKIP = false
    const explanation = debug ? answer : "";
    
    // Return result
    return res.status(200).json({
      success: true,
      result: decision,
      explanation: explanation,
      status: 'success'
    });
    
  } catch (error) {
    console.error('Job fit evaluation error:', error);
    return res.status(500).json({
      success: false,
      error: error.message,
      status: 'error'
    });
  }
});

// AI response generation API
app.post('/api/generate-response', verifyApiKeyMiddleware, async (req, res) => {
  try {
    // Parse request parameters
    const { 
      context, 
      question, 
      response_type = 'text', 
      options, 
      max_tokens = 3000, 
      debug = false, 
      openai_api_key 
    } = req.body;
    
    // Validate required parameters
    if (!question) {
      return res.status(400).json({
        success: false,
        error: 'Missing question parameter'
      });
    }
    
    // Get API key (prioritize key provided in request, then environment variable)
    const apiKey = openai_api_key || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(400).json({
        success: false,
        error: 'OpenAI API key not configured'
      });
    }
    
    // Initialize OpenAI client
    const openaiClient = new OpenAI({ apiKey });
    
    // Build system prompt based on response type
    let systemPrompt;
    if (response_type === 'text') {
      systemPrompt = `
You are an intelligent AI assistant filling out a form and answer like human,. 
Respond concisely based on the type of question:

1. If the question asks for **years of experience, duration, or numeric value**, return **only a number** (e.g., "2", "5", "10").
2. If the question is **a Yes/No question**, return **only "Yes" or "No"**.
3. If the question requires a **short description**, give a **single-sentence response**.
4. If the question requires a **detailed response**, provide a **well-structured and human-like answer and keep no of character <350 for answering**.
5. Do **not** repeat the question in your answer.
6. here is user information to answer the questions if needed:
**User Information:** 
${context}
`;
    } else if (response_type === 'numeric') {
      systemPrompt = "You are a helpful assistant providing numeric answers to job application questions. Based on the candidate's experience, provide a single number as your response. No explanation needed.";
    } else if (response_type === 'choice') {
      systemPrompt = `
You are a helpful assistant selecting the most appropriate answer choice for job application questions. Based on the candidate's background, select the best option by returning only its index number. 

Important rules:
1. Never select options like "Select an option" or other placeholder instructions
2. Only select "Yes" for questions when you have explicit evidence supporting that answer
3. When in doubt about factual information not provided in context, default to the most conservative or non-committal valid option
4. You need to think carefully, but in the end you need to return the option number.
`;
    }
    
    // Build user prompt
    let userContent;
    if (response_type === 'text') {
      userContent = `Please answer this job application question: ${question}`;
    } else {
      userContent = `Using this candidate's background and resume:\n${context}\n\nPlease answer this job application question: ${question}`;
    }
    
    // Add options for choice type
    if (response_type === 'choice' && options) {
      const optionsText = options.map((text, idx) => `${idx}: ${text}`).join('\n');
      userContent += `\n\nSelect the most appropriate answer by providing its index number from these options:\n${optionsText}`;
    }
    
    // Call OpenAI API
    const response = await openaiClient.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userContent }
      ],
      max_tokens: max_tokens,
      temperature: 0.7
    });
    
    const answer = response.choices[0].message.content.trim();
    
    // Process different types of responses
    let result;
    if (response_type === 'numeric') {
      // Extract first number
      const numbers = answer.match(/\d+/);
      result = numbers ? parseInt(numbers[0]) : 0;
    } else if (response_type === 'choice') {
      // Extract index number
      const numbers = answer.match(/\d+/);
      if (numbers && options) {
        const index = parseInt(numbers[0]);
        // Ensure index is within valid range
        result = (index >= 0 && index < options.length) ? index : null;
      } else {
        result = null;
      }
    } else {
      result = answer;
    }
    
    // Return result
    return res.status(200).json({
      success: true,
      result: result,
      status: 'success'
    });
    
  } catch (error) {
    console.error('Response generation error:', error);
    return res.status(500).json({
      success: false,
      error: error.message,
      status: 'error'
    });
  }
});

// Extract structured data from resume API
app.post('/api/extract-from-resume', verifyApiKeyMiddleware, async (req, res) => {
  try {
    const {
      resumeText,
      options = [],
      structure,
      useProxy,
      proxyUrl,
      metadata,
      openai_api_key
    } = req.body;

    // Check resume text
    if (!resumeText || resumeText.trim().length === 0) {
      return res.status(400).json({ error: 'Resume text is empty' });
    }
    // Check structure definition
    if (!structure) {
      return res.status(400).json({ error: 'No structure definition provided' });
    }

    // OpenAI config
    const openaiConfig = {
      apiKey: openai_api_key || process.env.OPENAI_API_KEY,
    };
    if (!openaiConfig.apiKey) {
      return res.status(400).json({ error: 'OpenAI API key not configured' });
    }

    const openai = new OpenAI(openaiConfig);

    // Build system prompt (English)
    const systemPrompt = `You are a professional resume analyst. Extract information from the provided resume without fabricating content. Use intelligent inference:
1. For skill experience, analyze from work history, do not simply return 0 years unless it is clearly a new skill.
2. For dates not explicitly mentioned, provide a reasonable inference.
3. For country/region codes, infer based on location information in the resume.
4. Accurately calculate years of experience based on work periods.
5. For all extracted information, provide a confidence score (1-10, 10 means fully certain).
Output strictly in the user-specified JSON structure.`;

    let userPrompt = `Extract information from the following resume, using intelligent inference and analysis.`;
    userPrompt += `\n\nResume Content:\n${resumeText}\n\n`;
    userPrompt += `Please extract and deeply analyze the following:`;

    // Helper to build field prompt
    const buildFieldPrompt = (fieldName, description, specificInstructions = "") => {
      let promptPart = `- ${description}`;
      if (metadata && metadata[fieldName] && metadata[fieldName].options && metadata[fieldName].options.length > 0) {
        promptPart += ` For ${metadata[fieldName].label || fieldName}, please mainly select from these preset options: [${metadata[fieldName].options.join(', ')}].`;
      }
      if (specificInstructions) {
        promptPart += " " + specificInstructions;
      }
      promptPart += "\n";
      return promptPart;
    };

    if (options.includes('languages')) {
      userPrompt += buildFieldPrompt(
        'languages',
        'Languages: Extract mentioned languages and proficiency, assess confidence.',
        metadata?.languages?.label ? `For proficiency, refer to the preset options of ${metadata.languages.label}.` : ''
      );
    }
    if (options.includes('skills')) {
      userPrompt += buildFieldPrompt(
        'skills',
        'Skills: Extract skills from the resume and analyze actual years of experience for each skill from work history. Do not return 0 years unless it is a new skill.'
      );
    }
    if (options.includes('personal_info')) {
      let piInstructions = 'Extract name, phone, email, address, country/region, etc. For country_code, use standard two-letter codes (e.g., US, CN), not full format. The system will convert to full format.';
      if (metadata?.personal_info?.fields?.country_code?.options) {
        piInstructions += ` For country code, the system will match the full format from the preset options of ${metadata.personal_info.fields.country_code.label || 'country_code'}.`;
      }
      userPrompt += buildFieldPrompt('personal_info', `Personal Info: ${piInstructions}`);
    }
    if (options.includes('eeo')) {
      let eeoInstructions = 'For gender, ethnicity, veteran status, etc., only extract if explicitly mentioned, otherwise provide reasonable inference. For veteran and disability fields, use lowercase "yes" or "no".';
      if (metadata?.eeo?.fields) {
        for (const key in metadata.eeo.fields) {
          if (metadata.eeo.fields[key].options && metadata.eeo.fields[key].options.length > 0) {
            eeoInstructions += ` For ${metadata.eeo.fields[key].label || key}, select from options [${metadata.eeo.fields[key].options.join(', ')}].`;
          }
        }
      }
      userPrompt += buildFieldPrompt('eeo', `Diversity Info: ${eeoInstructions}`);
    }
    if (options.includes('salary')) {
      userPrompt += buildFieldPrompt('salary', 'Expected Salary: If mentioned, extract the value and period (annual/monthly/hourly).');
    }
    if (options.includes('work_experience')) {
      let weInstructions = 'Extract company, title, location, start/end dates, responsibilities, and calculate duration for each job. For missing months, provide reasonable inference. Each work experience must include city; if not explicit, infer from company and context.';
      if (metadata?.work_experience?.fields?.month?.options) {
        weInstructions += ` For month, refer to the preset options of ${metadata.work_experience.fields.month.label || 'month'} (numeric format).`;
      }
      userPrompt += buildFieldPrompt('work_experience', `Work Experience: ${weInstructions}`);
    }
    if (options.includes('education')) {
      let eduInstructions = 'Extract school, degree, major, location, start/end dates. For missing months, provide reasonable inference. Each education entry must include city; if not explicit, infer from school and context.';
      if (metadata?.education?.fields?.degree?.options) {
        eduInstructions += ` For degree, refer to the preset options of ${metadata.education.fields.degree.label || 'degree'}.`;
      }
      if (metadata?.education?.fields?.month?.options) {
        eduInstructions += ` For month, refer to the preset options of ${metadata.education.fields.month.label || 'month'} (numeric format).`;
      }
      userPrompt += buildFieldPrompt('education', `Education: ${eduInstructions}`);
    }

    userPrompt += `\nPlease strictly reply in the following JSON structure. Ensure all content matches the original resume, do not fabricate:`;
    userPrompt += `\n${JSON.stringify(structure, null, 2)}`;
    userPrompt += `\n\nInclude only the selected options. If no relevant info is found, use empty array/object for the field. For all fields, add a confidence field (1-10) indicating certainty.`;
    userPrompt += `\n\nFor months in work and education, use numbers (1-12). If not explicit, provide the best inference and lower the confidence.`;

    // Call OpenAI API
    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt }
      ],
      temperature: 0.3,
      max_tokens: 2500
    });

    const content = completion.choices[0].message.content;

    // Try to extract JSON from response
    let aiResult;
    try {
      const jsonMatch = content.match(/({[\s\S]*})/);
      let jsonContent = jsonMatch ? jsonMatch[0] : content;
      jsonContent = jsonContent.replace(/```json|```/g, '').trim();
      aiResult = JSON.parse(jsonContent);
    } catch (jsonError) {
      console.error('JSON parse error:', jsonError);
      console.error('Original AI response:', content);
      return res.status(500).json({ error: 'Failed to parse JSON from AI response. See server logs for details.' });
    }

    // Return result
    res.json(aiResult);
  } catch (error) {
    console.error('Extract-from-resume error:', error);
    res.status(500).json({ error: error.message || 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
}); 