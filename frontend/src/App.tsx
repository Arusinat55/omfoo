import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { LoginPage } from './components/auth/LoginPage';
import { ProtectedRoute } from './components/auth/ProtectedRoute';
import { ChatLayout } from './components/chat/ChatLayout';
import { useAuthStore } from './store/authStore';

function App() {
  const { isAuthenticated, isLoading, setLoading, setUser, logout } = useAuthStore();

  useEffect(() => {
    const handleAuthCallback = () => {
      // Check for auth success/error in URL params (from OAuth callback)
      const urlParams = new URLSearchParams(window.location.search);
      const error = urlParams.get('error');
      const success = urlParams.get('success');
      const userData = urlParams.get('user');
      
      console.log('🔍 App: Checking URL params:', { 
        error, 
        success, 
        userData: !!userData,
        currentPath: window.location.pathname,
        fullUrl: window.location.href
      });
      
      if (error) {
        console.error('❌ Auth error:', error);
        logout();
        // Clear the error from URL and redirect to login
        window.history.replaceState({}, document.title, '/login');
        setLoading(false);
        return true;
      }
      
      if (success === 'true' && userData) {
        try {
          const user = JSON.parse(decodeURIComponent(userData));
          console.log('✅ OAuth success, setting user:', user);
          setUser(user);
          // Clear the success params from URL and redirect to chat
          window.history.replaceState({}, document.title, '/chat');
          setLoading(false);
          return true;
        } catch (e) {
          console.error('❌ Failed to parse user data from URL:', e);
          logout();
          // If parsing fails, redirect to login
          window.history.replaceState({}, document.title, '/login');
          setLoading(false);
          return true;
        }
      }
      
      return false;
    };

    // Handle auth callback if present
    const wasCallback = handleAuthCallback();
    
    // If not a callback, just set loading to false
    if (!wasCallback) {
      setLoading(false);
    }
  }, [setLoading, setUser, logout]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        {/* Public Routes */}
        <Route 
          path="/login" 
          element={
            isAuthenticated ? <Navigate to="/chat" replace /> : <LoginPage />
          } 
        />
        
        {/* Protected Routes */}
        <Route
          path="/chat"
          element={
            <ProtectedRoute>
              <ChatLayout />
            </ProtectedRoute>
          }
        />
        
        <Route
          path="/chat/:chatId"
          element={
            <ProtectedRoute>
              <ChatLayout />
            </ProtectedRoute>
          }
        />
        
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <ChatLayout />
            </ProtectedRoute>
          }
        />
        
        <Route
          path="/config"
          element={
            <ProtectedRoute>
              <div className="p-8">
                <h1 className="text-2xl font-bold">MCP Configuration</h1>
                <p>Configuration page coming soon...</p>
              </div>
            </ProtectedRoute>
          }
        />
        
        <Route
          path="/workflow"
          element={
            <ProtectedRoute>
              <div className="p-8">
                <h1 className="text-2xl font-bold">Workflow</h1>
                <p>Workflow page coming soon...</p>
              </div>
            </ProtectedRoute>
          }
        />

        {/* Default redirect */}
        <Route 
          path="/" 
          element={
            <Navigate to={isAuthenticated ? "/chat" : "/login"} replace />
          } 
        />
        
        {/* Catch all route - redirect to appropriate page */}
        <Route 
          path="*" 
          element={
            <Navigate to={isAuthenticated ? "/chat" : "/login"} replace />
          } 
        />
      </Routes>
    </Router>
  );
}

export default App;