const express = require('express');
const session = require('express-session');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const OpenAI = require('openai');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const { spawn } = require('child_process');
require('dotenv').config();

// Import models and services
const User = require('./models/User');
const Chat = require('./models/Chat');
const Message = require('./models/Message');
const Attachment = require('./models/Attachment');
const AuthToken = require('./models/AuthToken');
const FileUploadService = require('./services/fileUpload');
const FileParser = require('./services/fileParser');
const upload = require('./middleware/upload');

const app = express();
const PORT = process.env.PORT || 3000;

// Environment validation
const requiredEnvVars = [
  'OPENAI_API_KEY',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_REDIRECT_URI',
  'SESSION_SECRET',
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY'
];

const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);
if (missingEnvVars.length > 0) {
  console.error('❌ Missing required environment variables:', missingEnvVars);
  process.exit(1);
}

console.log('✅ Environment variables validated');
console.log('🔗 Frontend URL:', process.env.FRONTEND_URL);
console.log('🔗 Google Redirect URI:', process.env.GOOGLE_REDIRECT_URI);
console.log('🔗 Environment:', process.env.NODE_ENV);

// Initialize services
const googleClient = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:5173',
      'http://localhost:3000',
      'https://ai-chatbot-frontend-9dq0.onrender.com',
      process.env.FRONTEND_URL
    ].filter(Boolean);
    
    console.log('🔍 CORS Check - Origin:', origin);
    
    if (allowedOrigins.includes(origin)) {
      console.log('✅ CORS: Origin allowed');
      callback(null, true);
    } else {
      console.log('❌ CORS: Origin not allowed');
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie'],
  exposedHeaders: ['Set-Cookie']
};

app.use(cors(corsOptions));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  },
  name: 'sessionId'
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`📝 ${req.method} ${req.path} - Origin: ${req.get('Origin')} - Session: ${req.session?.user?.email || 'none'}`);
  next();
});

// Root route for health checks
app.get('/', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'ai-chatbot-backend',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// MCP Server Management
let mcpProcess = null;
let mcpReady = false;

async function startMCPServer(userId = null) {
  try {
    console.log('🚀 Starting MCP server...');
    
    if (mcpProcess) {
      console.log('🔄 Stopping existing MCP server...');
      mcpProcess.kill();
      mcpProcess = null;
      mcpReady = false;
    }

    const pythonPath = process.env.PYTHON_PATH || 'python3';
    const scriptPath = path.join(__dirname, 'mcp_toolkit.py');
    
    // Set up environment for MCP server
    const mcpEnv = { ...process.env };
    
    if (userId) {
      try {
        const tokenData = await AuthToken.findByUserId(userId);
        if (tokenData) {
          mcpEnv.GOOGLE_ACCESS_TOKEN = tokenData.access_token;
          mcpEnv.GOOGLE_REFRESH_TOKEN = tokenData.refresh_token;
          mcpEnv.GOOGLE_ID_TOKEN = tokenData.id_token;
          mcpEnv.GOOGLE_TOKEN_URI = 'https://oauth2.googleapis.com/token';
          mcpEnv.GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
          mcpEnv.GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
          console.log('✅ MCP: Complete token data loaded for user');
        }
      } catch (error) {
        console.error('❌ MCP: Failed to load token data:', error);
      }
    }

    mcpProcess = spawn(pythonPath, [scriptPath], {
      env: mcpEnv,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    mcpProcess.stdout.on('data', (data) => {
      const output = data.toString();
      console.log('📡 MCP stdout:', output.trim());
      if (output.includes('MCP server ready')) {
        mcpReady = true;
        console.log('✅ MCP server is ready');
      }
    });

    mcpProcess.stderr.on('data', (data) => {
      console.error('📡 MCP stderr:', data.toString().trim());
    });

    mcpProcess.on('close', (code) => {
      console.log(`📡 MCP process exited with code ${code}`);
      mcpReady = false;
    });

    mcpProcess.on('error', (error) => {
      console.error('📡 MCP process error:', error);
      mcpReady = false;
    });

    // Wait a bit for the server to start
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    return true;
  } catch (error) {
    console.error('❌ Failed to start MCP server:', error);
    return false;
  }
}

// Start MCP server on startup
startMCPServer();

// Authentication Routes
app.get('/auth/google', (req, res) => {
  console.log('🔐 Google OAuth initiated');
  
  const authUrl = googleClient.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'openid',
      'profile',
      'email',
      'https://www.googleapis.com/auth/drive',
      'https://www.googleapis.com/auth/gmail.modify',
      'https://www.googleapis.com/auth/calendar'
    ],
    prompt: 'consent'
  });
  
  console.log('🔗 Redirecting to Google OAuth URL');
  res.redirect(authUrl);
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    console.log('🔐 Google OAuth callback received');
    const { code, error } = req.query;
    
    if (error) {
      console.error('❌ OAuth error:', error);
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
      return res.redirect(`${frontendUrl}/login?error=${encodeURIComponent(error)}`);
    }
    
    if (!code) {
      console.error('❌ No authorization code received');
      const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
      return res.redirect(`${frontendUrl}/login?error=no_code`);
    }
    
    console.log('🔐 Exchanging code for tokens...');
    const { tokens } = await googleClient.getTokens(code);
    
    console.log('🔐 Getting user info...');
    googleClient.setCredentials(tokens);
    const ticket = await googleClient.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    console.log('✅ User authenticated:', payload.email);
    
    // Find or create user
    let user = await User.findByGoogleId(payload.sub);
    if (!user) {
      console.log('👤 Creating new user...');
      user = await User.create({
        googleId: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture
      });
    } else {
      console.log('👤 Updating existing user...');
      user = await User.update(user.id, {
        name: payload.name,
        picture: payload.picture
      });
    }
    
    // Store tokens with all required fields
    const expiresAt = new Date(Date.now() + (tokens.expires_in * 1000));
    
    try {
      // Delete existing tokens first
      await AuthToken.delete(user.id);
    } catch (e) {
      // Ignore if no existing tokens
    }
    
    await AuthToken.create({
      userId: user.id,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      idToken: tokens.id_token,
      expiresAt: expiresAt.toISOString()
    });
    
    console.log('✅ Tokens stored successfully');
    
    // Set session
    req.session.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture
    };
    
    console.log('✅ Session created for user:', user.email);
    
    // Restart MCP server with new credentials
    await startMCPServer(user.id);
    
    // Redirect to frontend with success
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    const userParam = encodeURIComponent(JSON.stringify(req.session.user));
    res.redirect(`${frontendUrl}/?success=true&user=${userParam}`);
    
  } catch (error) {
    console.error('❌ OAuth callback error:', error);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.redirect(`${frontendUrl}/login?error=${encodeURIComponent(error.message)}`);
  }
});

app.get('/auth/user', (req, res) => {
  console.log('🔍 Auth check - Session user:', req.session?.user?.email || 'none');
  console.log('🔍 Auth check - Session ID:', req.sessionID);
  console.log('🔍 Auth check - Cookies:', req.headers.cookie ? 'present' : 'missing');
  
  if (req.session?.user) {
    console.log('✅ User authenticated via session');
    res.json({
      authenticated: true,
      user: req.session.user
    });
  } else {
    console.log('❌ User not authenticated');
    res.status(401).json({
      authenticated: false,
      user: null
    });
  }
});

app.post('/auth/logout', (req, res) => {
  console.log('👋 Logout requested for user:', req.session?.user?.email || 'unknown');
  
  req.session.destroy((err) => {
    if (err) {
      console.error('❌ Session destruction error:', err);
      return res.status(500).json({ error: 'Failed to logout' });
    }
    
    res.clearCookie('sessionId');
    console.log('✅ User logged out successfully');
    res.json({ success: true });
  });
});

// Authentication middleware
const requireAuth = (req, res, next) => {
  if (!req.session?.user) {
    console.log('❌ Authentication required - no session');
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    mcpReady,
    environment: process.env.NODE_ENV || 'development',
    service: 'ai-chatbot-backend'
  });
});

// MCP status endpoint
app.get('/api/mcp/status', (req, res) => {
  res.json({
    ready: mcpReady,
    processRunning: mcpProcess !== null,
    pid: mcpProcess?.pid || null
  });
});

// Restart MCP server endpoint
app.post('/api/mcp/restart', requireAuth, async (req, res) => {
  try {
    console.log('🔄 MCP restart requested by:', req.session.user.email);
    await startMCPServer(req.session.user.id);
    res.json({ success: true, ready: mcpReady });
  } catch (error) {
    console.error('❌ MCP restart failed:', error);
    res.status(500).json({ error: 'Failed to restart MCP server' });
  }
});

// Chat endpoints
app.post('/api/chat', requireAuth, upload.array('attachments', 5), async (req, res) => {
  try {
    const { message, chatId, model = 'gpt-4', enabledTools = [] } = req.body;
    const userId = req.session.user.id;
    const files = req.files || [];
    
    console.log('💬 Chat request:', {
      userId: req.session.user.email,
      message: message?.substring(0, 100) + '...',
      chatId,
      model,
      filesCount: files.length,
      enabledTools: JSON.parse(enabledTools || '[]')
    });
    
    if (!message && files.length === 0) {
      return res.status(400).json({ error: 'Message or files required' });
    }
    
    let currentChatId = chatId;
    let chat;
    
    // Create or get chat
    if (!currentChatId || currentChatId === 'new') {
      const title = message ? message.substring(0, 50) + '...' : 'File Upload';
      chat = await Chat.create(userId, title);
      currentChatId = chat.id;
      console.log('📝 Created new chat:', currentChatId);
    } else {
      chat = await Chat.findById(currentChatId);
      if (!chat || chat.user_id !== userId) {
        return res.status(404).json({ error: 'Chat not found' });
      }
    }
    
    // Handle file uploads
    let attachmentData = [];
    let fileContents = [];
    
    if (files.length > 0) {
      console.log('📎 Processing file uploads...');
      
      for (const file of files) {
        try {
          // Upload file to Supabase Storage
          const uploadResult = await FileUploadService.uploadFile(file, userId);
          
          // Create attachment record
          const attachment = await Attachment.create({
            messageId: null, // Will be updated after message creation
            userId,
            filename: uploadResult.filename,
            originalName: uploadResult.originalName,
            mimeType: uploadResult.mimeType,
            fileSize: uploadResult.fileSize,
            storagePath: uploadResult.storagePath
          });
          
          attachmentData.push(attachment);
          
          // Parse file content
          const content = await FileParser.parseFile(
            uploadResult.storagePath,
            uploadResult.mimeType,
            uploadResult.originalName
          );
          
          fileContents.push({
            filename: uploadResult.originalName,
            content
          });
          
          console.log('✅ File processed:', uploadResult.originalName);
        } catch (error) {
          console.error('❌ File processing error:', error);
          fileContents.push({
            filename: file.originalname,
            content: `Error processing file: ${error.message}`
          });
        }
      }
    }
    
    // Prepare message content
    let fullMessage = message || '';
    if (fileContents.length > 0) {
      const fileSection = fileContents.map(file => 
        `\n\n--- File: ${file.filename} ---\n${file.content}`
      ).join('');
      fullMessage += fileSection;
    }
    
    // Create user message
    const userMessage = await Message.create({
      chatId: currentChatId,
      userId,
      role: 'user',
      content: message || 'File upload',
      model,
      attachments: attachmentData.map(att => ({
        id: att.id,
        filename: att.filename,
        original_name: att.original_name,
        mime_type: att.mime_type,
        file_size: att.file_size,
        storage_path: att.storage_path
      }))
    });
    
    // Update attachment records with message ID
    for (const attachment of attachmentData) {
      await Attachment.update(attachment.id, { message_id: userMessage.id });
    }
    
    // Get AI response
    console.log('🤖 Getting AI response...');
    
    const messages = [
      {
        role: 'system',
        content: `You are a helpful AI assistant with access to Google Workspace tools. You can help with Google Drive, Gmail, Calendar, and file analysis. The user has uploaded ${files.length} file(s) if any.`
      },
      {
        role: 'user',
        content: fullMessage
      }
    ];
    
    const completion = await openai.chat.completions.create({
      model,
      messages,
      temperature: 0.7,
      max_tokens: 2000
    });
    
    const aiResponse = completion.choices[0].message.content;
    
    // Create assistant message
    await Message.create({
      chatId: currentChatId,
      userId,
      role: 'assistant',
      content: aiResponse,
      model,
      toolsUsed: []
    });
    
    // Update chat timestamp
    await Chat.update(currentChatId, { updated_at: new Date().toISOString() });
    
    console.log('✅ Chat response sent');
    
    res.json({
      response: aiResponse,
      chatId: currentChatId,
      model,
      toolsUsed: []
    });
    
  } catch (error) {
    console.error('❌ Chat error:', error);
    res.status(500).json({ error: 'Failed to process chat message' });
  }
});

app.get('/api/chat/:chatId', requireAuth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const userId = req.session.user.id;
    
    const chatData = await Chat.getWithMessages(chatId, userId);
    
    if (!chatData) {
      return res.status(404).json({ error: 'Chat not found' });
    }
    
    res.json(chatData);
  } catch (error) {
    console.error('❌ Get chat error:', error);
    res.status(500).json({ error: 'Failed to get chat' });
  }
});

app.get('/api/chats/:userId', requireAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Ensure user can only access their own chats
    if (userId !== req.session.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    const chats = await Chat.findByUserId(userId);
    res.json({ chats });
  } catch (error) {
    console.error('❌ Get chats error:', error);
    res.status(500).json({ error: 'Failed to get chats' });
  }
});

app.delete('/api/chat/:chatId', requireAuth, async (req, res) => {
  try {
    const { chatId } = req.params;
    const userId = req.session.user.id;
    
    // Verify ownership
    const chat = await Chat.findById(chatId);
    if (!chat || chat.user_id !== userId) {
      return res.status(404).json({ error: 'Chat not found' });
    }
    
    await Chat.delete(chatId);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Delete chat error:', error);
    res.status(500).json({ error: 'Failed to delete chat' });
  }
});

// Tools endpoint
app.get('/api/tools', requireAuth, (req, res) => {
  // Return available tools (fallback list)
  const tools = [
    {
      function: {
        name: 'drive_search',
        description: 'Search for files in Google Drive'
      }
    },
    {
      function: {
        name: 'drive_read_file',
        description: 'Read content from a Google Drive file'
      }
    },
    {
      function: {
        name: 'gmail_send',
        description: 'Send an email via Gmail'
      }
    },
    {
      function: {
        name: 'calendar_create_event',
        description: 'Create a new calendar event'
      }
    }
  ];
  
  res.json({ tools });
});

// File download endpoint
app.get('/api/attachments/:attachmentId/download', requireAuth, async (req, res) => {
  try {
    const { attachmentId } = req.params;
    const attachment = await Attachment.findById(attachmentId);
    
    if (!attachment) {
      return res.status(404).json({ error: 'Attachment not found' });
    }
    
    const signedUrl = await Attachment.getSignedUrl(attachment.storage_path);
    res.redirect(signedUrl);
  } catch (error) {
    console.error('❌ Download error:', error);
    res.status(500).json({ error: 'Failed to download file' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('❌ Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
  console.log('❌ 404 - Route not found:', req.method, req.path);
  res.status(404).json({ error: 'Route not found' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  if (mcpProcess) {
    mcpProcess.kill();
  }
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  if (mcpProcess) {
    mcpProcess.kill();
  }
  process.exit(0);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔗 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Frontend URL: ${process.env.FRONTEND_URL}`);
});