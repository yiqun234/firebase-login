const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const { OpenAI } = require('openai');
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


app.get('/response-generator', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'response-generator.html'));
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

// 工作匹配评估API
app.post('/api/evaluate-job-fit', async (req, res) => {
  try {
    // 解析请求参数
    const { context, job_title, job_description, debug, openai_api_key } = req.body;
    
    // 验证必要参数
    if (!job_title || !job_description) {
      return res.status(400).json({
        success: false,
        error: '缺少工作标题或描述'
      });
    }
    
    // 获取API密钥（优先使用请求中提供的密钥，其次使用环境变量）
    const apiKey = openai_api_key || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(400).json({
        success: false,
        error: 'OpenAI API密钥未配置'
      });
    }
    
    // 初始化OpenAI客户端
    const openaiClient = new OpenAI({ apiKey });
    
    // 构建系统提示
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
    
    // 调用OpenAI API
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
    
    // 解析结果
    const decision = answer.toUpperCase().startsWith('A'); // APPLY = true, SKIP = false
    const explanation = debug ? answer : "";
    
    // 返回结果
    return res.status(200).json({
      success: true,
      result: decision,
      explanation: explanation,
      status: 'success'
    });
    
  } catch (error) {
    console.error('评估工作匹配度错误:', error);
    return res.status(500).json({
      success: false,
      error: error.message,
      status: 'error'
    });
  }
});

// AI响应生成API
app.post('/api/generate-response', async (req, res) => {
  try {
    // 解析请求参数
    const { 
      context, 
      question, 
      response_type = 'text', 
      options, 
      max_tokens = 3000, 
      debug = false, 
      openai_api_key 
    } = req.body;
    
    // 验证必要参数
    if (!question) {
      return res.status(400).json({
        success: false,
        error: '缺少问题参数'
      });
    }
    
    // 获取API密钥（优先使用请求中提供的密钥，其次使用环境变量）
    const apiKey = openai_api_key || process.env.OPENAI_API_KEY;
    if (!apiKey) {
      return res.status(400).json({
        success: false,
        error: 'OpenAI API密钥未配置'
      });
    }
    
    // 初始化OpenAI客户端
    const openaiClient = new OpenAI({ apiKey });
    
    // 根据响应类型构建系统提示
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
    
    // 构建用户提示
    let userContent;
    if (response_type === 'text') {
      userContent = `Please answer this job application question: ${question}`;
    } else {
      userContent = `Using this candidate's background and resume:\n${context}\n\nPlease answer this job application question: ${question}`;
    }
    
    // 如果是选择题，添加选项
    if (response_type === 'choice' && options) {
      const optionsText = options.map((text, idx) => `${idx}: ${text}`).join('\n');
      userContent += `\n\nSelect the most appropriate answer by providing its index number from these options:\n${optionsText}`;
    }
    
    // 调用OpenAI API
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
    
    // 处理不同类型的响应
    let result;
    if (response_type === 'numeric') {
      // 提取第一个数字
      const numbers = answer.match(/\d+/);
      result = numbers ? parseInt(numbers[0]) : 0;
    } else if (response_type === 'choice') {
      // 提取索引号
      const numbers = answer.match(/\d+/);
      if (numbers && options) {
        const index = parseInt(numbers[0]);
        // 确保索引在有效范围内
        result = (index >= 0 && index < options.length) ? index : null;
      } else {
        result = null;
      }
    } else {
      result = answer;
    }
    
    // 返回结果
    return res.status(200).json({
      success: true,
      result: result,
      status: 'success'
    });
    
  } catch (error) {
    console.error('AI响应生成错误:', error);
    return res.status(500).json({
      success: false,
      error: error.message,
      status: 'error'
    });
  }
});

// 启动服务器
app.listen(port, () => {
  console.log(`服务器运行在端口 ${port}`);
}); 