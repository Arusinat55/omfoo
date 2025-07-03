import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../../store/authStore';
import { authAPI } from '../../services/api';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, user, setUser, setLoading } = useAuthStore();
  const [isChecking, setIsChecking] = useState(true);
  const location = useLocation();

  useEffect(() => {
    const checkAuth = async () => {
      try {
        console.log('🔍 ProtectedRoute: Checking authentication status...');
        console.log('🔍 ProtectedRoute: Current auth state:', { isAuthenticated, userEmail: user?.email });
        
        setIsChecking(true);
        
        // If we already have a user in store, try to verify it's still valid
        if (user && isAuthenticated) {
          console.log('🔍 ProtectedRoute: User exists in store, verifying with server...');
        }
        
        const response = await authAPI.checkAuth();
        console.log('✅ ProtectedRoute: Auth check response:', {
          authenticated: response.data.authenticated,
          userEmail: response.data.user?.email,
          status: response.status
        });
        
        if (response.data.authenticated && response.data.user) {
          console.log('✅ ProtectedRoute: User authenticated:', response.data.user.email);
          setUser(response.data.user);
        } else {
          console.log('❌ ProtectedRoute: User not authenticated');
          setUser(null);
        }
      } catch (error: any) {
        console.error('❌ ProtectedRoute: Auth check failed:', {
          status: error.response?.status,
          message: error.message,
          data: error.response?.data,
          url: error.config?.url
        });
        
        // Only clear user if we get a definitive auth error
        if (error.response?.status === 401) {
          console.log('❌ ProtectedRoute: 401 Unauthorized - clearing user');
          setUser(null);
        } else {
          console.log('❌ ProtectedRoute: Network/other error - keeping current auth state');
          // Don't clear user on network errors, just proceed with current state
        }
      } finally {
        setIsChecking(false);
        setLoading(false);
      }
    };

    // Always check auth status when entering a protected route
    checkAuth();
  }, [setUser, setLoading, location.pathname]);

  // Show loading spinner while checking authentication
  if (isChecking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto mb-4"></div>
          <p className="text-gray-600">Checking authentication...</p>
        </div>
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated || !user) {
    console.log('🔄 ProtectedRoute: Redirecting to login - not authenticated');
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Render the protected content
  console.log('✅ ProtectedRoute: Rendering protected content for:', user.email);
  return <>{children}</>;
};