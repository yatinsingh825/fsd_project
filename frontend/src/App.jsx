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

// --- Configuration ---

const ROLES = {
  Admin: 'Admin',
  Editor: 'Editor',
  Viewer: 'Viewer',
};

// Simplified permission definitions (for frontend checks)
const PERMISSIONS = {
  [ROLES.Admin]: {
    content: ['create', 'read', 'update_all', 'delete_all'],
    users: ['read', 'update', 'delete'],
    auditlog: ['read'],
  },
  [ROLES.Editor]: {
    content: ['create', 'read', 'update_own', 'delete_own'],
    users: [],
    auditlog: [],
  },
  [ROLES.Viewer]: {
    content: ['read'],
    users: [],
    auditlog: [],
  },
};

// --- Mock Data ---
const MOCK_AUDIT_LOGS = [
    { _id: '1', timestamp: '2023-10-27T10:30:00Z', eventType: 'USER_LOGIN', user: { username: 'admin' }, details: { ip: '192.168.1.1' } },
    { _id: '2', timestamp: '2023-10-27T10:35:00Z', eventType: 'ROLE_UPDATE', user: { username: 'admin' }, targetUser: { username: 'editor' }, details: { from: 'Editor', to: 'Viewer' } },
    { _id: '3', timestamp: '2023-10-27T10:40:00Z', eventType: 'USER_REGISTER', user: { username: 'newUser' }, details: { role: 'Viewer' } },
    { _id: '4', timestamp: '2023-10-27T09:00:00Z', eventType: 'USER_LOGIN', user: { username: 'editor' }, details: { ip: '10.0.0.5' } },
    { _id: '5', timestamp: '2023-10-26T18:15:00Z', eventType: 'ROLE_UPDATE', user: { username: 'admin' }, targetUser: { username: 'viewer' }, details: { from: 'Viewer', to: 'Editor' } },
    { _id: '6', timestamp: '2023-10-27T11:00:00Z', eventType: 'USER_LOGIN', user: { username: 'admin' }, details: { ip: '192.168.1.1' } },
];

// --- Theme Classes (Hardcoded Dark) ---
const themeClasses = {
  layout: "min-h-screen font-sans transition-colors duration-300 bg-gray-900",
  nav: "sticky top-0 z-30 shadow-sm border-b bg-black/20 backdrop-blur-lg text-white border-white/10",
  card: "rounded-xl bg-black/20 backdrop-blur-lg border border-white/20 shadow-xl",
  input: "w-full px-4 py-2.5 border rounded-lg focus:outline-none focus:ring-2 transition-all bg-gray-700/50 border-white/20 text-white placeholder-gray-300 focus:ring-blue-500 focus:border-blue-500",
  text: "text-white",
  textMuted: "text-gray-300",
  textLabel: "text-gray-100",
  textHeading: "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-400",
  aurora: "absolute top-0 left-0 w-full h-full overflow-hidden -z-10",
  solidBg: "bg-gray-800",
  solidBorder: "border-gray-700"
};

// --- Auth Context ---
const AuthContext = createContext(null);

// --- Axios API Client ---
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

// --- AuthProvider Component ---
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

// --- Auth Hooks ---
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
  const canViewAuditLog = () => can('auditlog:read');

  return { can, canRead, canCreate, canUpdate, canDelete, canManageUsers, canViewAuditLog, userRole: user?.role, userId: user?.id };
};

// --- UI Components ---

// Modal
const Modal = ({ title, children, onClose }) => {
  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 flex items-center justify-center p-4">
      <div className={`relative w-full max-w-md p-6 ${themeClasses.card}`}>
        <h3 className={`text-xl font-semibold mb-4 ${themeClasses.text}`}>{title}</h3>
        <div className={themeClasses.textMuted}>
          {children}
        </div>
        <button 
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-gray-200"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path></svg>
        </button>
      </div>
    </div>
  );
};

// Aurora Background
const AuroraBackground = () => {
  return (
    <div className={themeClasses.aurora}>
      <style>{`
        .aurora-blur {
          filter: blur(100px);
        }
        .aurora-1 {
          position: absolute;
          width: 500px;
          height: 500px;
          background: radial-gradient(circle, rgba(139, 92, 246, 0.4) 0%, rgba(139, 92, 246, 0) 70%);
          animation: aurora-anim-1 20s infinite alternate;
        }
        .aurora-2 {
          position: absolute;
          width: 400px;
          height: 400px;
          background: radial-gradient(circle, rgba(59, 130, 246, 0.4) 0%, rgba(59, 130, 246, 0) 70%);
          animation: aurora-anim-2 22s infinite alternate;
        }
        .aurora-3 {
          position: absolute;
          width: 300px;
          height: 300px;
          background: radial-gradient(circle, rgba(236, 72, 153, 0.4) 0%, rgba(236, 72, 153, 0) 70%);
          animation: aurora-anim-3 18s infinite alternate;
        }
        @keyframes aurora-anim-1 {
          0% { top: 10%; left: 10%; }
          100% { top: 30%; left: 60%; }
        }
        @keyframes aurora-anim-2 {
          0% { top: 50%; left: 70%; }
          100% { top: 40%; left: 20%; }
        }
        @keyframes aurora-anim-3 {
          0% { top: 80%; left: 40%; }
          100% { top: 60%; left: 80%; }
        }
      `}</style>
      <div className="aurora-blur">
        <div className="aurora-1"></div>
        <div className="aurora-2"></div>
        <div className="aurora-3"></div>
      </div>
    </div>
  );
};

// --- Page Components ---

// Layout
const Layout = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const { canManageUsers } = usePermissions();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className={themeClasses.layout}>
      <AuroraBackground />
      <nav className={themeClasses.nav}>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Link to="/" className="text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-500 to-purple-500">
                RBAC Platform
              </Link>
            </div>
            <div className="flex items-center space-x-4">
              <Link to="/" className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium transition-colors">
                Home
              </Link>
              {canManageUsers() && (
                <Link to="/admin" className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium transition-colors">
                  Admin Panel
                </Link>
              )}
              {user ? (
                <>
                  <span className={`${themeClasses.textMuted} text-sm`}>Hi, {user.username} ({user.role})</span>
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
                    className="text-gray-300 bg-white/10 hover:bg-white/20 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-300"
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

// Home Page (Content List)
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
        <h1 className={`text-4xl font-bold ${themeClasses.text}`}>Content Feed</h1>
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
          <p className={`${themeClasses.textMuted} text-center`}>No content yet. Be the first to create a post!</p>
        )}
      </div>
    </div>
  );
};

// Content Item
const ContentItem = ({ item, onDelete }) => {
  const { canUpdate, canDelete } = usePermissions();
  const [showConfirm, setShowConfirm] = useState(false);
  const [deleteError, setDeleteError] = useState(null);
  
  const subject = { authorId: item.author?._id };
  const canEdit = canUpdate(subject);
  const canRemove = canDelete(subject);

  const handleDelete = async () => {
    try {
      setDeleteError(null);
      await apiClient.delete(`/content/${item._id}`);
      setShowConfirm(false);
      onDelete();
    } catch (err) {
      setDeleteError('Failed to delete post.');
      console.error(err);
      setShowConfirm(false);
    }
  };

  return (
    <>
      <div className={`p-6 transition-all duration-300 ${themeClasses.card}`}>
        <div className="flex justify-between items-start">
          <div>
            <h2 className={`text-2xl font-semibold ${themeClasses.text} mb-2`}>{item.title}</h2>
            <p className={`${themeClasses.textMuted} text-sm mb-4`}>
              By <span className={`font-medium ${themeClasses.textLabel}`}>{item.author?.username || 'Unknown Author'}</span>
            </p>
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
                onClick={() => setShowConfirm(true)}
                className="text-sm bg-gradient-to-r from-red-500 to-red-600 text-white px-4 py-2 rounded-lg shadow-md hover:from-red-600 hover:to-red-700 transition-all duration-300 transform hover:scale-105"
                title="Delete this post"
              >
                Delete
              </button>
            )}
          </div>
        </div>
        <p className={`${themeClasses.textMuted} leading-relaxed`}>{item.body}</p>
        {deleteError && <p className="text-red-500 text-sm mt-4">{deleteError}</p>}
      </div>

      {showConfirm && (
        <Modal title="Delete Post?" onClose={() => setShowConfirm(false)}>
          <p>Are you sure you want to delete the post titled "{item.title}"? This action cannot be undone.</p>
          <div className="flex justify-end space-x-3 mt-6">
            <button
              onClick={() => setShowConfirm(false)}
              className="px-4 py-2 rounded-lg bg-gray-200 text-gray-800 hover:bg-gray-300"
            >
              Cancel
            </button>
            <button
              onClick={handleDelete}
              className="px-4 py-2 rounded-lg bg-red-600 text-white hover:bg-red-700"
            >
              Delete
            </button>
          </div>
        </Modal>
      )}
    </>
  );
};

// Form Wrapper Component
const AuthFormWrapper = ({ title, children }) => {
  return (
    <div className={`max-w-md mx-auto p-8 md:p-10 ${themeClasses.card}`}>
      <h2 className={`text-center mb-8 ${themeClasses.textHeading}`}>
        {title}
      </h2>
      {children}
    </div>
  );
};

// Login Page
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
      if (data.user.role === ROLES.Admin) {
        navigate('/admin');
      } else {
        navigate('/');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Invalid username or password.');
      console.error(err);
    }
  };

  const fillDemoUser = (user, pass) => {
    setUsername(user);
    setPassword(pass);
  };

  return (
    <AuthFormWrapper title="Welcome Back!">
      <form onSubmit={handleSubmit}>
        {error && <p className="text-red-500 text-center mb-4 text-sm">{error}</p>}
        <div className="mb-4">
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        <div className="mb-6">
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white px-4 py-2.5 rounded-lg shadow-md hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105"
        >
          Login
        </button>
      </form>
      <div className="mt-6 text-center">
        <p className={`mb-3 ${themeClasses.textMuted} text-sm`}>Or try a demo user:</p>
        <div className="grid grid-cols-3 gap-3">
          <button 
            onClick={() => fillDemoUser('admin', 'adminpassword')}
            className="px-4 py-2 rounded-lg text-white font-medium bg-gradient-to-r from-purple-500 to-indigo-500 shadow-md hover:scale-105 transform transition-all"
          >
            Admin
          </button>
          <button 
            onClick={() => fillDemoUser('editor', 'editorpassword')}
            className="px-4 py-2 rounded-lg text-white font-medium bg-gradient-to-r from-cyan-500 to-blue-500 shadow-md hover:scale-105 transform transition-all"
          >
            Editor
          </button>
          <button 
            onClick={() => fillDemoUser('viewer', 'viewerpassword')}
            className="px-4 py-2 rounded-lg text-white font-medium bg-gradient-to-r from-green-500 to-teal-500 shadow-md hover:scale-105 transform transition-all"
          >
            Viewer
          </button>
        </div>
      </div>
      <p className={`mt-6 text-center text-sm ${themeClasses.textMuted}`}>
        Don't have an account?{' '}
        <Link to="/register" className="font-medium text-blue-500 hover:text-blue-400">
          Sign Up
        </Link>
      </p>
    </AuthFormWrapper>
  );
};

// Register Page
const RegisterPage = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState(ROLES.Viewer);
  const [error, setError] = useState(null);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    try {
      const { data } = await apiClient.post('/auth/register', { username, password, role });
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
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        <div className="mb-4">
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        
        <div className="mb-6">
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="role">Register as:</label>
          <select
            id="role"
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className={themeClasses.input}
          >
            <option className="bg-gray-700 text-white" value={ROLES.Viewer}>Viewer</option>
            <option className="bg-gray-700 text-white" value={ROLES.Editor}>Editor</option>
          </select>
        </div>
        
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-green-500 to-green-600 text-white px-4 py-2.5 rounded-lg shadow-md hover:from-green-600 hover:to-green-700 transition-all duration-300 transform hover:scale-105"
        >
          Register
        </button>
      </form>
      <p className={`mt-6 text-center text-sm ${themeClasses.textMuted}`}>
        Already have an account?{' '}
        <Link to="/login" className="font-medium text-blue-500 hover:text-blue-400">
          Login
        </Link>
      </p>
    </AuthFormWrapper>
  );
};

// AdminDashboard Page
const AdminDashboard = () => {
  const AdminButton = ({ to, title, description, icon }) => (
    <Link 
      to={to} 
      className={`block p-6 transition-all duration-300 transform hover:scale-105 hover:shadow-2xl ${themeClasses.card}`}
    >
      <div className="flex items-center space-x-4">
        <div className="p-3 rounded-full bg-gradient-to-r from-blue-500 to-purple-500 text-white">
          {icon}
        </div>
        <div>
          <h3 className={`text-xl font-semibold ${themeClasses.text}`}>{title}</h3>
          <p className={themeClasses.textMuted}>{description}</p>
        </div>
      </div>
    </Link>
  );

  return (
    <div className="max-w-4xl mx-auto">
      <h2 className={`text-4xl font-bold mb-8 text-center ${themeClasses.textHeading}`}>Admin Dashboard</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <AdminButton 
          to="/"
          title="Manage Content Feed"
          description="View, edit, and delete all posts."
          icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 12h6M7 8h6"></path></svg>}
        />
        <AdminButton 
          to="/admin/users"
          title="Manage Users"
          description="View all users and change their roles."
          icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 016-6h6m6 3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>}
        />
        <AdminButton 
          to="/admin/audit"
          title="View Audit Log"
          description="See a log of important system events."
          icon={<svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>}
        />
      </div>
    </div>
  );
};


// Admin Page (User Management)
const AdminPage = () => {
  const [users, setUsers] = useState([]);
  const [error, setError] = useState(null);
  const [editingRole, setEditingRole] = useState({});
  const [updateError, setUpdateError] = useState(null);
  const { userId: adminUserId } = usePermissions();

  const fetchUsers = async () => {
    try {
      setError(null);
      const { data } = await apiClient.get('/users');
      setUsers(data);
    } catch (err) {
      setError('Failed to fetch users.');
      console.error(err);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleRoleChange = (userId, newRole) => {
    setEditingRole(prev => ({ ...prev, [userId]: newRole }));
  };
  
  const handleSaveRole = async (userId) => {
    const newRole = editingRole[userId];
    if (!newRole) return;
    
    setUpdateError(null);
    try {
      await apiClient.put(`/users/${userId}/role`, { role: newRole });
      setEditingRole(prev => {
        const newState = { ...prev };
        delete newState[userId];
        return newState;
      });
      fetchUsers();
    } catch (err) {
      setUpdateError('Failed to update role.');
      console.error(err);
    }
  };

  if (error) {
    return <p className="text-red-500 text-center">{error}</p>;
  }

  return (
    <div className={`max-w-4xl mx-auto p-8 ${themeClasses.card}`}>
      <h2 className={`text-center mb-6 ${themeClasses.textHeading}`}>User Management</h2>
      {updateError && <p className="text-red-500 text-center mb-4 text-sm">{updateError}</p>}
      <div className="overflow-x-auto">
        <table className="w-full table-auto min-w-max">
          <thead>
            <tr className={`bg-gray-700/50 text-left ${themeClasses.textLabel} uppercase text-sm`}>
              <th className="px-6 py-3 font-semibold">Username</th>
              <th className="px-6 py-3 font-semibold">Role</th>
              <th className="px-6 py-3 font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody className={themeClasses.textMuted}>
            {users.map((user) => (
              <tr key={user._id} className={`border-b ${themeClasses.solidBorder} hover:bg-gray-700/50`}>
                <td className="px-6 py-4">{user.username}</td>
                <td className="px-6 py-4">{user.role}</td>
                <td className="px-6 py-4 flex items-center space-x-3">
                  <select
                    value={editingRole[user._id] || user.role}
                    onChange={(e) => handleRoleChange(user._id, e.target.value)}
                    disabled={user._id === adminUserId}
                    className={`${themeClasses.input} ${user._id === adminUserId ? 'bg-gray-600/50' : ''}`}
                  >
                    {Object.values(ROLES).map((role) => (
                      <option 
                        key={role} 
                        value={role} 
                        className="bg-gray-700 text-white"
                      >
                        {role}
                      </option>
                    ))}
                  </select>
                  {editingRole[user._id] && editingRole[user._id] !== user.role && (
                    <button
                      onClick={() => handleSaveRole(user._id)}
                      className="px-4 py-2 rounded-lg bg-green-600 text-white text-sm hover:bg-green-700"
                    >
                      Save
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// AuditLogPage
const AuditLogPage = () => {
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        setError(null);
        // --- MOCK DATA ---
        const sortedLogs = MOCK_AUDIT_LOGS.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        setLogs(sortedLogs.slice(0, 5));

      } catch (err) {
        setError('Failed to fetch audit logs.');
        console.error(err);
      }
    };
    fetchLogs();
  }, []);
  
  const renderLogDetails = (log) => {
    switch (log.eventType) {
      case 'ROLE_UPDATE':
        return `changed ${log.targetUser.username}'s role from ${log.details.from} to ${log.details.to}.`;
      case 'USER_LOGIN':
        return `logged in from ${log.details.ip}.`;
      case 'USER_REGISTER':
        return `registered a new account with role ${log.details.role}.`;
      default:
        return 'performed an unknown action.';
    }
  };

  return (
     <div className={`max-w-4xl mx-auto p-8 ${themeClasses.card}`}>
      <h2 className={`text-center mb-6 ${themeClasses.textHeading}`}>Audit Log (Top 5 Recent)</h2>
      {error && <p className="text-red-500 text-center mb-4 text-sm">{error}</p>}
      <div className="space-y-4">
        {logs.length > 0 ? logs.map(log => (
          <div key={log._id} className="p-4 rounded-lg bg-gray-700/50">
            <p className={themeClasses.text}>
              <span className="font-semibold text-blue-400">{log.user.username}</span> {renderLogDetails(log)}
            </p>
            <p className={`text-sm ${themeClasses.textMuted} mt-1`}>
              {new Date(log.timestamp).toLocaleString()}
            </p>
          </div>
        )) : (
          <p className={themeClasses.textMuted}>No audit logs found.</p>
        )}
      </div>
    </div>
  );
};


// Form Wrapper for Content
const ContentFormWrapper = ({ title, children }) => {
  return (
    <div className={`max-w-2xl mx-auto p-8 md:p-10 ${themeClasses.card}`}>
      <h2 className={`text-center mb-8 ${themeClasses.textHeading}`}>
        {title}
      </h2>
      {children}
    </div>
  );
};

// CreatePostPage
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
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="title">Title</label>
          <input
            type="text"
            id="title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        <div className="mb-6">
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="body">Body</label>
          <textarea
            id="body"
            rows="10"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white px-4 py-2.5 rounded-lg shadow-md hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105"
        >
          Publish Post
        </button>
      </form>
    </ContentFormWrapper>
  );
};

// EditPostPage
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
    return <div className={`text-center ${themeClasses.textMuted}`}>Loading post...</div>;
  }
  
  if (error && !title) {
     return <p className="text-red-500 text-center">{error}</p>;
  }

  return (
    <ContentFormWrapper title="Edit Post">
      <form onSubmit={handleSubmit}>
        {error && <p className="text-red-500 text-center mb-4 text-sm">{error}</p>}
        <div className="mb-4">
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="title">Title</label>
          <input
            type="text"
            id="title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        <div className="mb-6">
          <label className={`block mb-2 font-medium ${themeClasses.textLabel}`} htmlFor="body">Body</label>
          <textarea
            id="body"
            rows="10"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            className={themeClasses.input}
          />
        </div>
        <button
          type="submit"
          className="w-full bg-gradient-to-r from-blue-500 to-blue-600 text-white px-4 py-2.5 rounded-lg shadow-md hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105"
        >
          Update Post
        </button>
      </form>
    </ContentFormWrapper>
  );
};

// Unauthorized Page
const UnauthorizedPage = () => {
  return (
    <div className={`text-center p-10 max-w-lg mx-auto ${themeClasses.card}`}>
      <h1 className="text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-yellow-500">Access Denied</h1>
      <p className={`mt-6 text-xl ${themeClasses.textMuted}`}>You do not have the required permissions to view this page.</p>
      <Link to="/" className="mt-8 inline-block bg-gradient-to-r from-blue-500 to-blue-600 text-white px-6 py-3 rounded-lg shadow-md hover:from-blue-600 hover:to-blue-700 transition-all duration-300 transform hover:scale-105">
        Go Back to Home
      </Link>
    </div>
  );
};

// --- Protected Route Component ---
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

// --- App Component ---
export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            
            {/* Public Routes */}
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/unauthorized" element={<UnauthorizedPage />} />
            
            {/* Protected Routes (All logged-in users) */}
            <Route element={<ProtectedRoute />}>
              <Route index element={<HomePage />} />
            </Route>
            
            {/* Protected Routes (Editors & Admins) */}
            <Route element={<ProtectedRoute allowedRoles={[ROLES.Admin, ROLES.Editor]} />}>
              <Route path="create" element={<CreatePostPage />} />
              <Route path="edit/:id" element={<EditPostPage />} />
            </Route>
            
            {/* Protected Routes (Admins Only) */}
            <Route element={<ProtectedRoute allowedRoles={[ROLES.Admin]} />}>
              <Route path="admin" element={<AdminDashboard />} />
              <Route path="admin/users" element={<AdminPage />} />
              <Route path="admin/audit" element={<AuditLogPage />} />
            </Route>

          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

