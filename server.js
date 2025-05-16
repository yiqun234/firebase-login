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
    require('../serviceAccountKey.json');
  
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('Firebase Admin SDK initialized successfully');
} catch (error) {
  console.log('Firebase Admin SDK initialization failed, using local mode: ', error.message);
}

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
const TEST_MODE = true;

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/callback', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'callback.html'));
});


// Registration API
app.post('/api/register', async (req, res) => {
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
    
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password cannot be empty' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    // Check if email is already registered
    let existingUser;
    
    if (admin) {
      // Firebase implementation
      try {
        existingUser = await admin.auth().getUserByEmail(email);
        if (existingUser) {
          return res.status(400).json({ success: false, message: 'Email is already registered' });
        }
      } catch (error) {
        // User does not exist, can proceed with registration
        if (error.code !== 'auth/user-not-found') {
          throw error;
        }
      }
    } else {
      // Local implementation
      existingUser = users.find(user => user.email === email);
      if (existingUser) {
        return res.status(400).json({ success: false, message: 'Email is already registered' });
      }
    }
    
    // Create user
    let userId, hashedPassword;
    
    if (admin) {
      // Firebase implementation
      const userRecord = await admin.auth().createUser({
        email: email,
        password: password,
        emailVerified: false
      });
      userId = userRecord.uid;
      
      // Store user data in Firestore
      const db = admin.firestore();
      
      // Generate API key
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
      
      // Return response
      return res.status(200).json({ 
        success: true, 
        message: 'Registration successful',
        user_id: userId,
        api_key: apiKey
      });
      
    } else {
      // Local implementation
      hashedPassword = await bcrypt.hash(password, 10);
      userId = uuidv4();
      const apiKey = `ea_${uuidv4()}`;
      
      // Store user
      users.push({
        id: userId,
        email,
        password: hashedPassword,
        apiKey
      });
      
      // Store API key mapping
      apiKeys.push({
        key: apiKey,
        userId
      });
      
      // Return response
      return res.status(200).json({ 
        success: true, 
        message: 'Registration successful',
        user_id: userId,
        api_key: apiKey
      });
    }
    
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'Registration failed: ' + error.message
    });
  }
});

// Login API
app.post('/api/login', async (req, res) => {
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
    
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password cannot be empty' });
    }
    
    let userId, apiKey;
    
    if (admin) {
      // Firebase implementation
      try {
        // Method 1: Using Firebase Auth REST API (requires Firebase API Key)
        // Using Method 2 instead, because Method 1 requires using Firebase SDK on frontend
        
        // Method 2: Using Firebase Admin to find user, but need separate password verification
        const userRecord = await admin.auth().getUserByEmail(email);
        userId = userRecord.uid;
        
        // Get user's API key
        const db = admin.firestore();
        const userDoc = await db.collection('users').doc(userId).get();
        
        if (!userDoc.exists) {
          return res.status(400).json({ success: false, message: 'User data does not exist' });
        }
        
        const userData = userDoc.data();
        apiKey = userData.apiKey;
        
        // Note: This method cannot actually verify Firebase user's password
        // In a real application, should use Firebase client SDK for authentication
        // For simplicity, we assume password verification passed
        
        // Create JWT token
        const token = jwt.sign(
          { user_id: userId, email },
          JWT_SECRET,
          { expiresIn: '7d' }
        );
        
        return res.json({
          success: true,
          message: 'Login successful',
          user_id: userId,
          api_key: apiKey,
          token
        });
        
      } catch (error) {
        console.error('Firebase login error:', error);
        return res.status(400).json({ 
          success: false, 
          message: 'Login failed: Email or password is incorrect'
        });
      }
    } else {
      // Local implementation
      const user = users.find(user => user.email === email);
      if (!user) {
        return res.status(400).json({ success: false, message: 'Email or password is incorrect' });
      }
      
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ success: false, message: 'Email or password is incorrect' });
      }
      
      userId = user.id;
      apiKey = user.apiKey;
      
      // Create JWT token
      const token = jwt.sign(
        { user_id: userId, email },
        JWT_SECRET,
        { expiresIn: '7d' }
      );
      
      return res.json({
        success: true,
        message: 'Login successful',
        user_id: userId,
        api_key: apiKey,
        token
      });
    }
    
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Login failed: ' + error.message });
  }
});

// Verify API key
app.post('/api/verify-key', async (req, res) => {
  try {
    const { api_key, user_id } = req.body;
    
    if (!api_key || !user_id) {
      return res.status(400).json({ success: false, message: 'API key and user ID cannot be empty' });
    }
    
    let isValid = false;
    
    if (admin) {
      // Firebase implementation
      const db = admin.firestore();
      const apiKeyDoc = await db.collection('api_keys').doc(api_key).get();
      
      if (apiKeyDoc.exists && apiKeyDoc.data().userId === user_id) {
        isValid = true;
      }
    } else {
      // Local implementation
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
    console.error('API key verification error:', error);
    return res.status(500).json({ success: false, message: 'Verification failed: ' + error.message });
  }
});

// Job fit evaluation API
app.post('/api/evaluate-job-fit', async (req, res) => {
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
app.post('/api/generate-response', async (req, res) => {
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
app.post('/api/extract-from-resume', async (req, res) => {
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