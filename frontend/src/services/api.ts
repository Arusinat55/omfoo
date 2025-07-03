import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

console.log('🔗 API Base URL:', API_BASE_URL);

const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000, // 30 second timeout
});

// Request interceptor for debugging
api.interceptors.request.use(
  (config) => {
    console.log(`🚀 API Request: ${config.method?.toUpperCase()} ${config.url}`);
    console.log('🍪 Request cookies:', document.cookie ? 'present' : 'missing');
    return config;
  },
  (error) => {
    console.error('❌ API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor for debugging and error handling
api.interceptors.response.use(
  (response) => {
    console.log(`✅ API Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('❌ API Response Error:', {
      status: error.response?.status,
      data: error.response?.data,
      url: error.config?.url,
      message: error.message
    });

    // Handle authentication errors
    if (error.response?.status === 401) {
      console.log('🔄 Authentication error - user needs to login');
      // Don't redirect here, let the component handle it
    }

    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  checkAuth: () => {
    console.log('🔍 Checking authentication status...');
    return api.get('/auth/user');
  },
  login: async (credentials: { email: string; password: string }) => {
    console.log('🔐 Attempting email/password login...');
    return api.post('/auth/login', credentials);
  },
  logout: () => {
    console.log('👋 Logging out...');
    return api.post('/auth/logout');
  },
  googleLogin: () => {
    const googleAuthUrl = `${API_BASE_URL}/auth/google`;
    console.log('🔗 Redirecting to Google OAuth:', googleAuthUrl);
    window.location.href = googleAuthUrl;
  },
  updatePreferences: (preferences: any) => api.put('/api/user/preferences', preferences),
  getPreferences: () => api.get('/api/user/preferences'),
};

// Chat API
export const chatAPI = {
  sendMessage: (message: string, chatId?: string, model?: string, enabledTools?: string[]) =>
    api.post('/api/chat', { message, chatId, model, enabledTools }),
  sendMessageWithAttachments: (formData: FormData) => {
    return api.post('/api/chat', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
  },
  getChat: (chatId: string) => api.get(`/api/chat/${chatId}`),
  getUserChats: (userId: string) => api.get(`/api/chats/${userId}`),
  deleteChat: (chatId: string) => api.delete(`/api/chat/${chatId}`),
};

// Tools API
export const toolsAPI = {
  getAvailableTools: () => api.get('/api/tools'),
  updateToolPreferences: (enabledTools: string[]) => 
    api.put('/api/tools/preferences', { enabledTools }),
};

// Health API
export const healthAPI = {
  getStatus: () => api.get('/api/health'),
};

// Attachments API
export const attachmentsAPI = {
  download: (attachmentId: string) => api.get(`/api/attachments/${attachmentId}/download`, {
    responseType: 'blob'
  }),
};

export default api;