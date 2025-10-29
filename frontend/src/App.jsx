import React, { useState, useEffect, createContext, useContext } from 'react';
import {
  BrowserRouter,
  Routes,
  Route,
  Link,
  useNavigate,
  Outlet,
  useLocation,
  Navigate,
  useParams,
} from 'react-router-dom';
import axios from 'axios';

const GlobalStyles = () => (
  <style>{`
    body {
      overflow-y: scroll;
    }
    
    .aurora-background {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100vh;
      z-index: -10;
      overflow: hidden;
    }
    
    .dark .aurora-background {
      background: #030712;
    }
    
    .light .aurora-background {
      background: #f0f9ff;
    }

    .aurora-background::before,
    .aurora-background::after {
      content: '';
      position: absolute;
      width: 60vmax;
      height: 60vmax;
      border-radius: 50%;
      filter: blur(120px);
      animation: aurora 20s linear infinite;
    }
    
    .dark .aurora-background::before {
      background: radial-gradient(circle, #7c3aed, transparent 40%);
      top: -30vmax;
      left: -30vmax;
      opacity: 0.25;
    }
    
    .dark .aurora-background::after {
      background: radial-gradient(circle, #2563eb, transparent 40%);
      bottom: -30vmax;
      right: -30vmax;
      animation-delay: 5s;
      opacity: 0.25;
    }

    .light .aurora-background::before {
      background: radial-gradient(circle, #a5b4fc, transparent 40%);
      top: -30vmax;
      left: -30vmax;
      opacity: 0.4;
    }
    
    .light .aurora-background::after {
      background: radial-gradient(circle, #7dd3fc, transparent 40%);
      bottom: -30vmax;
      right: -30vmax;
      animation-delay: 5s;
      opacity: 0.4;
    }

    @keyframes aurora {
      0% { transform: rotate(0deg) scale(1); }
      50% { transform: rotate(180deg) scale(1.2); }
      100% { transform: rotate(360deg) scale(1); }
    }
  `}</style>
);

const ROLES = {
  Admin: 'Admin',
  Editor: 'Editor',
  Viewer: 'Viewer',
};

const PERMISSIONS = {
  [ROLES.Admin]: {
    content: ['create', 'read', 'update_all', 'delete_all'],
    users: ['read', 'update', 'delete'],
  },
  [ROLES.Editor]: {
    content: ['create', 'read', 'update_own', 'delete_own'],
    users: [],
  },
  [ROLES.Viewer]: {
    content: ['read'],
    users: [],
  },
};

const AuthContext = createContext(null);
const ThemeContext = createContext(null);

const apiClient = axios.create({
  baseURL: 'http://localhost:5001/api',
  withCredentials: true,
});

apiClient.interceptors.request.use(
  (config) => {
    const { accessToken } = JSON.parse(localStorage.getItem('auth') || '{}');
    if (accessToken) {
      config.headers['Authorization'] = `Bearer ${accessToken}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const { data } = await apiClient.post('/auth/refresh');
        const newAccessToken = data.accessToken;
        
        let authData = JSON.parse(localStorage.getItem('auth') || '{}');
        authData.accessToken = newAccessToken;
        localStorage.setItem('auth', JSON.stringify(authData));
        
        originalRequest.headers['Authorization'] = `Bearer ${newAccessToken}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        localStorage.removeItem('auth');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    return Promise.reject(error);
  }
);

const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState('dark');

  useEffect(() => {
    const root = window.document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      {children}
    </ThemeContext.Provider>
  );
};

const useTheme = () => useContext(ThemeContext);

const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    try {
      const authData = JSON.parse(localStorage.getItem('auth'));
      if (authData && authData.user) {
        setUser(authData.user);
      }
    } catch (error) {
      console.error('Failed to parse auth data from localStorage');
    }
    setLoading(false);
  }, []);

  const login = (userData) => {
    const authData = {
      accessToken: userData.accessToken,
      user: userData.user,
    };
    localStorage.setItem('auth', JSON.stringify(authData));
    setUser(userData.user);
  };

  const logout = async () => {
    try {
      await apiClient.post('/auth/logout');
    } catch (error) {
      console.error('Logout failed', error);
    }
    localStorage.removeItem('auth');
    setUser(null);
  };

  const value = { user, login, logout, loading };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  return useContext(AuthContext);
};

const usePermissions = () => {
  const { user } = useAuth();
  
  const can = (action, subject) => {
    if (!user) return false;
    
    const [resource, requiredPermission] = action.split(':');
    const userPermissions = PERMISSIONS[user.role]?.[resource] || [];

    if (userPermissions.includes(requiredPermission) || userPermissions.includes(`${requiredPermission}_all`)) {
      return true;
    }

    if (userPermissions.includes(`${requiredPermission}_own`)) {
      if (!subject) {
        return true;
      }
      return subject.authorId === user.id;
    }
    
    return false;
  };

  const canRead = (resource = 'content') => can(`${resource}:read`);
  const canCreate = (resource = 'content') => can(`${resource}:create`);
  const canUpdate = (subject, resource = 'content') => can(`${resource}:update`, subject);
  const canDelete = (subject, resource = 'content') => can(`${resource}:delete`, subject);
  const canManageUsers = () => can('users:read');


  return { can, canRead, canCreate, canUpdate, canDelete, canManageUsers, userRole: user?.role, userId: user?.id };
};

const Layout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { canManageUsers } = usePermissions();
  const { theme, toggleTheme } = useTheme();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen font-sans relative z-10 text-gray-900 dark:text-gray-100">
      <div className="aurora-background" />
      <nav className="bg-white/10 dark:bg-black/10 shadow-lg border-b border-white/10 dark:border-white/5 backdrop-blur-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Link to="/" className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-600 dark:from-blue-400 dark:to-purple-500">
                RBAC Platform
              </Link>
            </div>
            <div className="flex items-center space-x-4">
              <Link to="/" className="text-gray-800 dark:text-gray-200 hover:text-blue-500 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium transition-colors">
                Home
              </Link>
              {canManageUsers() && (
                <Link to="/admin" className="text-gray-800 dark:text-gray-200 hover:text-blue-500 dark:hover:text-blue-400 px-3 py-2 rounded-md text-sm font-medium transition-colors">
                  Admin Panel
                </Link>
              )}
              {user ? (
                <>
                  <span className="text-gray-800 dark:text-gray-200 text-sm">Hi, {user.username} ({user.role})</span>
                  <button
                    onClick={handleLogout}
                    className="bg-gradient-to-r from-red-500 to-red-600 text-white px-4 py-2 rounded-lg text-sm font-medium shadow-md hover:from-red-600 hover:to-red-700 transition-all duration-300 transform hover:scale-105"
                  >
                    Logout
                  </button>
                </>
              ) : (
                <>
                  <Link
                    to="/login"
                    className="text-gray-800 dark:text-gray-200 bg-white/20 dark:bg-black/20 border border-white/20 dark:border-white/10 px-4 py-2 rounded-lg text-sm font-medium hover:bg-white/40 dark:hover:bg-black/40 transition-all duration-300"
                  >
                    Login
                  </Link>
                  <Link
                    to="/register"
                    className="bg-gradient-to-r from-blue-500 to-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium shadow-md hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105"
                  >
                    Sign Up
                  </Link>
                </>
              )}
              <button 
                onClick={toggleTheme} 
                className="flex items-center justify-center w-10 h-10 rounded-lg bg-white/10 dark:bg-black/20 text-gray-800 dark:text-gray-200 hover:bg-white/20 dark:hover:bg-black/30 transition-colors"
                aria-label="Toggle theme"
              >
                {theme === 'light' ? 
                  (<svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" /></svg>) : 
                  (<svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm-7.071 0l-.707.707a1 1 0 001.414 1.414l.707-.707a1 1 0 00-1.414-1.414zM10 16a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM3 9a1 1 0 011-1h1a1 1 0 110 2H4a1 1 0 01-1-1zm14 0a1 1 0 011-1h1a1 1 0 110 2h-1a1 1 0 01-1-1zM4.95 15.05l-.707-.707a1 1 0 00-1.414 1.414l.707.707a1 1 0 001.414-1.414zM15.05 4.95l.707-.707a1 1 0 00-1.414-1.414l-.707.707a1 1 0 001.414 1.414z" clipRule="evenodd" /></svg>)
                }
              </button>
            </div>
          </div>
        </div>
      </nav>
      <main className="py-10 relative z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
};

const HomePage = () => {
  const [content, setContent] = useState([]);
  const [error, setError] = useState(null);
  const { canCreate } = usePermissions();
  
  const fetchContent = async () => {
    try {
      setError(null);
      const { data } = await apiClient.get('/content');
      setContent(data);
    } catch (err) {
      setError('Failed to fetch content.');
      console.error(err);
    }
  };

  useEffect(() => {
    fetchContent();
  }, []);

  if (error) {
    return <p className="text-red-500 text-center">{error}</p>;
  }

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex justify-between items-center mb-8">
        <h1 className="text-4xl font-bold text-gray-900 dark:text-gray-100">Content Feed</h1>
        {canCreate() && (
          <Link 
            to="/create" 
            className="bg-gradient-to-r from-green-500 to-green-600 text-white px-5 py-2.5 rounded-lg shadow-md hover:from-green-600 hover:to-green-700 transition-all duration-300 transform hover:scale-105"
          >
            + Create New Post
          </Link>
        )}
      </div>
      <div className="space-y-6">
        {content.length > 0 ? content.map((item) => (
          <ContentItem key={item._id} item={item} onDelete={fetchContent} />
        )) : (
          <p className="text-gray-600 dark:text-gray-400 text-center">No content yet. Be the first to create a post!</p>
        )}
      </div>
    </div>
  );
};

const ContentItem = ({ item, onDelete }) => {
  const { canUpdate, canDelete } = usePermissions();
  const [showConfirm, setShowConfirm] = useState(false);
  const [deleteError, setDeleteError] = useState(null);
  
  const subject = { authorId: item.author._id };
  const canEdit = canUpdate(subject);
  const canRemove = canDelete(subject);

  const requestDelete = () => {
    setDeleteError(null);
    setShowConfirm(true);
  };

  const cancelDelete = () => {
    setShowConfirm(false);
  };

  const confirmDelete = async () => {
    try {
      await apiClient.delete(`/content/${item._id}`);
      onDelete();
      setShowConfirm(false);
    } catch (err) {
      setDeleteError('Failed to delete post.');
      console.error(err);
      setShowConfirm(false);
    }
  };

  return (
    <div className="bg-white/10 dark:bg-black/10 p-6 rounded-2xl shadow-lg border border-white/20 dark:border-white/10 backdrop-blur-lg transition-all duration-300 hover:shadow-xl">
      <div className="flex justify-between items-start">
        <div>
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-2">{item.title}</h2>
          <p className="text-gray-600 dark:text-gray-400 text-sm mb-4">By <span className="font-medium text-gray-800 dark:text-gray-200">{item.author.username}</span></p>
        </div>
        <div className="flex space-x-2 flex-shrink-0 ml-4">
          {canEdit && (
            <Link 
              to={`/edit/${item._id}`}
              className="text-sm bg-gradient-to-r from-yellow-400 to-yellow-500 text-white px-4 py-2 rounded-lg shadow-md hover:from-yellow-500 hover:to-yellow-600 transition-all duration-300 transform hover:scale-105"
              title="Edit this post"
            >
              Edit
            </Link>
          )}
          {canRemove && (
            <button
              onClick={requestDelete}
              className="text-sm bg-gradient-to-r from-red-500 to-red-600 text-white px-4 py-2 rounded-lg shadow-md hover:from-red-600 hover:to-red-700 transition-all duration-300 transform hover:scale-105"
              title="Delete this post"
            >
              Delete
            </button>
          )}
        </div>
      </div>
      <p className="text-gray-800 dark:text-gray-300 leading-relaxed">{item.body}</p>

      {deleteError && (
        <p className="text-red-500 text-sm mt-4 text-center bg-red-100 border border-red-400 p-3 rounded-lg">{deleteError}</p>
      )}

      {showConfirm && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-900 p-8 rounded-2xl shadow-2xl max-w-sm w-full border border-white/10">
            <h3 className="text-2xl font-bold mb-6 text-center text-gray-900 dark:text-gray-100">Are you sure?</h3>
            <p className="text-gray-700 dark:text-gray-300 mb-8 text-center">
              Do you really want to delete this post? This action cannot be undone.
            </p>
            <div className="flex justify-around space-x-4">
              <button
                onClick={cancelDelete}
                className="w-full bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 px-6 py-3 rounded-lg font-semibold hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-300"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                className="w-full bg-gradient-to-r from-red-500 to-red-600 text-white px-6 py-3 rounded-lg shadow-md hover:from-red-600 hover:to-red-700 transition-all duration-300 transform hover:scale-105"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const AuthFormWrapper = ({ title, children }) => (
  <div className="max-w-md mx-auto bg-white/10 dark:bg-black/10 p-8 md:p-10 rounded-2xl shadow-2xl border border-white/20 dark:border-white/10 backdrop-blur-lg">
    <h2 className="text-3xl font-bold text-center mb-8 text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-600 dark:from-blue-400 dark:to-purple-500">
      {title}
    </h2>
    {children}
  </div>
);

const LoginPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      const { data } = await apiClient.post('/auth/login', { username, password });
      login(data);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid username or password.');
      console.error(err);
    }
  };

  const handleDemoLogin = (role) => {
    if (role === 'admin') {
      setUsername('admin');
      setPassword('adminpassword');
    } else if (role === 'editor') {
      setUsername('editor');
      setPassword('editorpassword');
    } else if (role === 'viewer') {
      setUsername('viewer');
      setPassword('viewerpassword');
    }
  };

  return (
    <AuthFormWrapper title="Welcome Back!">
      <form onSubmit={handleSubmit}>
        {error && <p className="text-red-500 text-center mb-4 text-sm">{error}</p>}
        <div className="mb-4">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <div className="mb-6">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white px-4 py-2.5 rounded-lg shadow-lg shadow-blue-500/30 dark:shadow-blue-400/20 hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105"
        >
          Login
        </button>
      </form>
      
      <div className="mt-8 text-center">
        <p className="text-sm text-gray-700 dark:text-gray-300 mb-4">Or try a demo user:</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <button 
            type="button" 
            onClick={() => handleDemoLogin('admin')} 
            className="w-full px-4 py-2.5 rounded-lg text-sm font-semibold text-white bg-gradient-to-r from-purple-500 to-indigo-600 shadow-md hover:from-purple-600 hover:to-indigo-700 transition-all duration-300 transform hover:scale-105"
          >
            Admin
          </button>
          <button 
            type="button" 
            onClick={() => handleDemoLogin('editor')} 
            className="w-full px-4 py-2.5 rounded-lg text-sm font-semibold text-white bg-gradient-to-r from-blue-500 to-cyan-600 shadow-md hover:from-blue-600 hover:to-cyan-700 transition-all duration-300 transform hover:scale-105"
          >
            Editor
          </button>
          <button 
            type="button" 
            onClick={() => handleDemoLogin('viewer')} 
            className="w-full px-4 py-2.5 rounded-lg text-sm font-semibold text-white bg-gradient-to-r from-teal-500 to-emerald-600 shadow-md hover:from-teal-600 hover:to-emerald-700 transition-all duration-300 transform hover:scale-105"
          >
            Viewer
          </button>
        </div>
      </div>

      <p className="mt-8 text-center text-sm text-gray-600 dark:text-gray-400">
        Don't have an account?{' '}
        <Link to="/register" className="font-medium text-blue-500 dark:text-blue-400 hover:text-blue-400 dark:hover:text-blue-300">
          Sign Up
        </Link>
      </p>
    </AuthFormWrapper>
  );
};

const RegisterPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      const { data } = await apiClient.post('/auth/register', { username, password });
      login(data);
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to register. Username might be taken.');
      console.error(err);
    }
  };

  return (
    <AuthFormWrapper title="Create Your Account">
      <form onSubmit={handleSubmit}>
        {error && <p className="text-red-500 text-center mb-4 text-sm">{error}</p>}
        <div className="mb-4">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <div className="mb-6">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-green-500 to-green-600 text-white px-4 py-2.5 rounded-lg shadow-lg shadow-green-500/30 dark:shadow-green-400/20 hover:from-green-600 hover:to-green-700 transition-all duration-300 transform hover:scale-105"
        >
          Register
        </button>
      </form>
      <p className="mt-6 text-center text-sm text-gray-600 dark:text-gray-400">
        Already have an account?{' '}
        <Link to="/login" className="font-medium text-blue-500 dark:text-blue-400 hover:text-blue-400 dark:hover:text-blue-300">
          Login
        </Link>
      </p>
    </AuthFormWrapper>
  );
};

const AdminPage = () => {
  const [users, setUsers] = useState([]);
  const [fetchError, setFetchError] = useState(null);
  const [updateError, setUpdateError] = useState(null);

  const fetchUsers = async () => {
    try {
      setFetchError(null);
      const { data } = await apiClient.get('/users');
      setUsers(data);
    } catch (err) {
      setFetchError('Failed to fetch users.');
      console.error(err);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleRoleChange = async (userId, newRole) => {
    try {
      setUpdateError(null);
      await apiClient.put(`/users/${userId}/role`, { role: newRole });
      fetchUsers();
    } catch (err) {
      setUpdateError('Failed to update role.');
      console.error(err);
    }
  };

  if (fetchError) {
    return <p className="text-red-500 text-center">{fetchError}</p>;
  }

  return (
    <div className="max-w-4xl mx-auto bg-white/10 dark:bg-black/10 p-8 rounded-2xl shadow-2xl border border-white/20 dark:border-white/10 backdrop-blur-lg">
      <h2 className="text-3xl font-bold mb-6 text-gray-900 dark:text-gray-100">User Management</h2>
      
      {updateError && (
        <p className="text-red-500 text-center mb-4 bg-red-100 border border-red-400 p-3 rounded-lg">
          {updateError}
        </p>
      )}

      <div className="overflow-x-auto">
        <table className="w-full table-auto min-w-max">
          <thead>
            <tr className="bg-slate-500/10 dark:bg-slate-800/20 text-left text-gray-700 dark:text-gray-300 uppercase text-sm">
              <th className="px-6 py-3 font-semibold">Username</th>
              <th className="px-6 py-3 font-semibold">Role</th>
              <th className="px-6 py-3 font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody className="text-gray-800 dark:text-gray-200">
            {users.map((user) => (
              <tr key={user._id} className="border-b border-white/10 dark:border-white/5 hover:bg-slate-500/5 dark:hover:bg-slate-800/10">
                <td className="px-6 py-4">{user.username}</td>
                <td className="px-6 py-4">{user.role}</td>
                <td className="px-6 py-4">
                  <select
                    value={user.role}
                    onChange={(e) => handleRoleChange(user._id, e.target.value)}
                    className="px-3 py-2 border border-white/30 dark:border-white/10 rounded-lg bg-white/20 dark:bg-black/20 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300"
                  >
                    {Object.values(ROLES).map((role) => (
                      <option key={role} value={role}>{role}</option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const ContentFormWrapper = ({ title, children }) => (
  <div className="max-w-2xl mx-auto bg-white/10 dark:bg-black/10 p-8 md:p-10 rounded-2xl shadow-2xl border border-white/20 dark:border-white/10 backdrop-blur-lg">
    <h2 className="text-3xl font-bold text-center mb-8 text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-600 dark:from-blue-400 dark:to-purple-500">
      {title}
    </h2>
    {children}
  </div>
);

const CreatePostPage = () => {
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!title || !body) {
      setError('Title and body are required.');
      return;
    }
    try {
      await apiClient.post('/content', { title, body });
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create post.');
      console.error(err);
    }
  };

  return (
    <ContentFormWrapper title="Create New Post">
      <form onSubmit={handleSubmit}>
        {error && <p className="text-red-500 text-center mb-4 text-sm">{error}</p>}
        <div className="mb-4">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="title">Title</label>
          <input
            type="text"
            id="title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <div className="mb-6">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="body">Body</label>
          <textarea
            id="body"
            rows="10"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white px-4 py-2.5 rounded-lg shadow-lg shadow-blue-500/30 dark:shadow-blue-400/20 hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105"
        >
          Publish Post
        </button>
      </form>
    </ContentFormWrapper>
  );
};

const EditPostPage = () => {
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const { id } = useParams();

  useEffect(() => {
    const fetchPost = async () => {
      try {
        const { data } = await apiClient.get(`/content/${id}`);
        setTitle(data.title);
        setBody(data.body);
        setLoading(false);
      } catch (err) {
        setError('Failed to fetch post data. You may not have permission to edit this.');
        console.error(err);
        setLoading(false);
      }
    };
    fetchPost();
  }, [id]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (!title || !body) {
      setError('Title and body are required.');
      return;
    }
    try {
      await apiClient.put(`/content/${id}`, { title, body });
      navigate('/');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to update post.');
      console.error(err);
    }
  };

  if (loading) {
    return <div className="text-center text-gray-600 dark:text-gray-400">Loading post...</div>;
  }
  
  if (error && !title) {
     return <p className="text-red-500 text-center">{error}</p>;
  }

  return (
    <ContentFormWrapper title="Edit Post">
      <form onSubmit={handleSubmit}>
        {error && <p className="text-red-500 text-center mb-4 text-sm">{error}</p>}
        <div className="mb-4">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="title">Title</label>
          <input
            type="text"
            id="title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <div className="mb-6">
          <label className="block text-gray-800 dark:text-gray-200 mb-2 font-medium" htmlFor="body">Body</label>
          <textarea
            id="body"
            rows="10"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className="w-full px-4 py-2.5 bg-white/20 dark:bg-black/20 border border-white/30 dark:border-white/10 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-all"
          />
        </div>
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white px-4 py-2.5 rounded-lg shadow-lg shadow-blue-500/30 dark:shadow-blue-400/20 hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105"
        >
          Update Post
        </button>
      </form>
    </ContentFormWrapper>
  );
};

const UnauthorizedPage = () => {
  return (
    <div className="text-center p-10 bg-white/10 dark:bg-black/10 rounded-2xl shadow-2xl max-w-lg mx-auto border border-white/20 dark:border-white/10 backdrop-blur-lg">
      <h1 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-yellow-500 dark:from-red-400 dark:to-yellow-400">Access Denied</h1>
      <p className="mt-6 text-xl text-gray-700 dark:text-gray-300">You do not have the required permissions to view this page.</p>
      <Link to="/" className="mt-8 inline-block bg-gradient-to-r from-blue-500 to-blue-600 text-white px-6 py-3 rounded-lg shadow-md hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105">
        Go Back to Home
      </Link>
    </div>
  );
};

const ProtectedRoute = ({ allowedRoles }) => {
  const { user } = useAuth();
  const location = useLocation();
  const { userRole } = usePermissions();

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (allowedRoles && !allowedRoles.includes(userRole)) {
    return <Navigate to="/unauthorized" state={{ from: location }} replace />;
  }

  return <Outlet />;
};

export default function App() {
  return (
    <ThemeProvider>
      <GlobalStyles />
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/" element={<Layout />}>
              
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
              <Route path="/unauthorized" element={<UnauthorizedPage />} />
              
              <Route element={<ProtectedRoute />}>
                <Route index element={<HomePage />} />
              </Route>
              
              <Route element={<ProtectedRoute allowedRoles={[ROLES.Admin, ROLES.Editor]} />}>
                <Route path="create" element={<CreatePostPage />} />
                <Route path="edit/:id" element={<EditPostPage />} />
              </Route>
              
              <Route element={<ProtectedRoute allowedRoles={[ROLES.Admin]} />}>
                <Route path="admin" element={<AdminPage />} />
              </Route>

            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}

