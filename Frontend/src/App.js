import React, { useState } from 'react';
import { AlertCircle, CheckCircle, LogOut, User, Shield, Users, Settings } from 'lucide-react';

const API_BASE_URL = 'http://localhost:3000/api';

const Alert = ({ message, type }) => {
  if (!message) return null;
  return (
    <div className={`alert ${type === 'success' ? 'alert-success' : 'alert-error'}`}>
      {type === 'success' ? <CheckCircle size={18} /> : <AlertCircle size={18} />}
      <span>{message}</span>
    </div>
  );
};

const LoginForm = ({ onSuccess, onAlert }) => {
  const [formData, setFormData] = useState({ username: '', password: '' });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (!formData.username || !formData.password) {
      onAlert('Please fill in all fields', 'error');
      return;
    }

    setLoading(true);
    onAlert('', '');

    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (response.ok && data.success) {
        onSuccess(data.data);
      } else {
        onAlert(data.message || 'Login failed. Please check your credentials.', 'error');
      }
    } catch (error) {
      onAlert('Network error. Please check your connection.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-section">
      <div className="form-group">
        <label htmlFor="loginUsername">Username</label>
        <input
          type="text"
          id="loginUsername"
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
          onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder="Enter your username"
        />
      </div>
      <div className="form-group">
        <label htmlFor="loginPassword">Password</label>
        <input
          type="password"
          id="loginPassword"
          value={formData.password}
          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
          onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder="Enter your password"
        />
      </div>
      <button onClick={handleSubmit} className="btn" disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>
    </div>
  );
};

const RegisterForm = ({ onSuccess, onAlert }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    firstName: '',
    lastName: '',
    password: '',
    confirmPassword: '',
    role: 'user'
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (!formData.username || !formData.email || !formData.password) {
      onAlert('Please fill in all required fields', 'error');
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      onAlert('Passwords do not match!', 'error');
      return;
    }

    setLoading(true);
    onAlert('', '');

    try {
      const response = await fetch(`${API_BASE_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: formData.username,
          email: formData.email,
          firstName: formData.firstName,
          lastName: formData.lastName,
          password: formData.password,
          role: formData.role
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        onAlert(`Registration successful as ${formData.role}! You can now login.`, 'success');
        setFormData({
          username: '',
          email: '',
          firstName: '',
          lastName: '',
          password: '',
          confirmPassword: '',
          role: 'user'
        });
        setTimeout(() => onSuccess(), 2000);
      } else {
        onAlert(data.message || 'Registration failed. Please try again.', 'error');
      }
    } catch (error) {
      onAlert('Network error. Please check your connection.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="form-section">
      <div className="form-group">
        <label htmlFor="regUsername">Username *</label>
        <input
          type="text"
          id="regUsername"
          value={formData.username}
          onChange={(e) => setFormData({ ...formData, username: e.target.value })}
          placeholder="Choose a username"
        />
      </div>
      <div className="form-group">
        <label htmlFor="regEmail">Email *</label>
        <input
          type="email"
          id="regEmail"
          value={formData.email}
          onChange={(e) => setFormData({ ...formData, email: e.target.value })}
          placeholder="Enter your email"
        />
      </div>
      <div className="form-group">
        <label htmlFor="regFirstName">First Name</label>
        <input
          type="text"
          id="regFirstName"
          value={formData.firstName}
          onChange={(e) => setFormData({ ...formData, firstName: e.target.value })}
          placeholder="Enter your first name"
        />
      </div>
      <div className="form-group">
        <label htmlFor="regLastName">Last Name</label>
        <input
          type="text"
          id="regLastName"
          value={formData.lastName}
          onChange={(e) => setFormData({ ...formData, lastName: e.target.value })}
          placeholder="Enter your last name"
        />
      </div>
      <div className="form-group">
        <label htmlFor="regRole">Role *</label>
        <select
          id="regRole"
          value={formData.role}
          onChange={(e) => setFormData({ ...formData, role: e.target.value })}
          style={{
            width: '100%',
            padding: '12px 15px',
            border: '2px solid #e0e0e0',
            borderRadius: '8px',
            fontSize: '14px',
            outline: 'none',
            cursor: 'pointer'
          }}
        >
          <option value="user">User - Basic Access</option>
          <option value="manager">Manager - Team Management</option>
          <option value="admin">Admin - Full Access</option>
        </select>
      </div>
      <div className="form-group">
        <label htmlFor="regPassword">Password *</label>
        <input
          type="password"
          id="regPassword"
          value={formData.password}
          onChange={(e) => setFormData({ ...formData, password: e.target.value })}
          placeholder="Create a password"
        />
      </div>
      <div className="form-group">
        <label htmlFor="regConfirmPassword">Confirm Password *</label>
        <input
          type="password"
          id="regConfirmPassword"
          value={formData.confirmPassword}
          onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
          onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder="Confirm your password"
        />
      </div>
      <button onClick={handleSubmit} className="btn" disabled={loading}>
        {loading ? 'Registering...' : 'Register'}
      </button>
    </div>
  );
};

const RoleBadge = ({ role }) => {
  const colors = {
    admin: '#dc3545',
    manager: '#ffc107',
    user: '#28a745'
  };
  
  return (
    <span style={{
      display: 'inline-block',
      padding: '4px 12px',
      borderRadius: '12px',
      fontSize: '12px',
      fontWeight: '600',
      backgroundColor: colors[role] || '#6c757d',
      color: 'white',
      textTransform: 'uppercase',
      marginLeft: '8px'
    }}>
      {role}
    </span>
  );
};

const Dashboard = ({ userData, accessToken, refreshToken, onLogout, onAlert }) => {
  const [loading, setLoading] = useState(false);
  const [activeView, setActiveView] = useState('profile');
  const [dashboardData, setDashboardData] = useState(null);
  const [users, setUsers] = useState([]);

  const userRoles = userData?.roles || [];
  const isAdmin = userRoles.includes('admin');
  const isManager = userRoles.includes('manager') || isAdmin;

  const loadDashboard = async (endpoint) => {
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      const data = await response.json();
      if (data.success) {
        setDashboardData(data);
      } else {
        onAlert(data.message, 'error');
      }
    } catch (error) {
      onAlert('Failed to load dashboard data', 'error');
    }
  };

  const loadUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/admin/users`, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });
      const data = await response.json();
      if (data.success) {
        setUsers(data.data);
      } else {
        onAlert(data.message, 'error');
      }
    } catch (error) {
      onAlert('Failed to load users', 'error');
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    try {
      await fetch(`${API_BASE_URL}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken })
      });
      onAlert('Logged out successfully!', 'success');
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setLoading(false);
      onLogout();
    }
  };

  return (
    <div className="dashboard active">
      <div className="user-info">
        <h3>
          <User size={20} style={{ display: 'inline', marginRight: '8px', verticalAlign: 'middle' }} />
          User Profile
        </h3>
        <div className="info-item">
          <span className="info-label">Username:</span>
          <span className="info-value">{userData?.preferred_username || 'N/A'}</span>
        </div>
        <div className="info-item">
          <span className="info-label">Email:</span>
          <span className="info-value">{userData?.email || 'N/A'}</span>
        </div>
        <div className="info-item">
          <span className="info-label">Name:</span>
          <span className="info-value">{userData?.name || 'N/A'}</span>
        </div>
        <div className="info-item">
          <span className="info-label">Roles:</span>
          <span className="info-value">
            {userRoles.map(role => (
              <RoleBadge key={role} role={role} />
            ))}
          </span>
        </div>
      </div>

      <div className="dashboard-tabs">
        <button
          className={`dash-tab ${activeView === 'profile' ? 'active' : ''}`}
          onClick={() => setActiveView('profile')}
        >
          <User size={16} /> Profile
        </button>
        {isManager && (
          <button
            className={`dash-tab ${activeView === 'manager' ? 'active' : ''}`}
            onClick={() => {
              setActiveView('manager');
              loadDashboard('/manager/dashboard');
            }}
          >
            <Shield size={16} /> Manager
          </button>
        )}
        {isAdmin && (
          <button
            className={`dash-tab ${activeView === 'admin' ? 'active' : ''}`}
            onClick={() => {
              setActiveView('admin');
              loadDashboard('/admin/dashboard');
              loadUsers();
            }}
          >
            <Settings size={16} /> Admin
          </button>
        )}
      </div>

      {activeView === 'profile' && (
        <div className="dashboard-content">
          <div className="token-display">
            <strong>🔑 Access Token:</strong>
            <div style={{ color: '#666', marginTop: '8px', fontSize: '11px' }}>
              {accessToken?.substring(0, 80)}...
            </div>
          </div>
        </div>
      )}

      {activeView === 'manager' && dashboardData && (
        <div className="dashboard-content">
          <div className="feature-box">
            <h4>Manager Dashboard</h4>
            <p>{dashboardData.message}</p>
            <div style={{ marginTop: '15px' }}>
              <strong>Permissions:</strong>
              <ul style={{ marginTop: '8px', paddingLeft: '20px' }}>
                {dashboardData.data?.permissions?.map(perm => (
                  <li key={perm} style={{ marginBottom: '5px' }}>{perm}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {activeView === 'admin' && (
        <div className="dashboard-content">
          {dashboardData && (
            <div className="feature-box">
              <h4>Admin Dashboard</h4>
              <p>{dashboardData.message}</p>
              <div style={{ marginTop: '15px' }}>
                <strong>Permissions:</strong>
                <ul style={{ marginTop: '8px', paddingLeft: '20px' }}>
                  {dashboardData.data?.permissions?.map(perm => (
                    <li key={perm} style={{ marginBottom: '5px' }}>{perm}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
          
          {users.length > 0 && (
            <div className="feature-box" style={{ marginTop: '15px' }}>
              <h4><Users size={18} style={{ verticalAlign: 'middle', marginRight: '8px' }} />All Users</h4>
              <div style={{ marginTop: '15px' }}>
                {users.map(user => (
                  <div key={user.id} style={{
                    padding: '10px',
                    background: '#f8f9fa',
                    borderRadius: '5px',
                    marginBottom: '8px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}>
                    <div>
                      <strong>{user.username}</strong>
                      <div style={{ fontSize: '12px', color: '#666' }}>{user.email}</div>
                    </div>
                    <span style={{
                      padding: '4px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      backgroundColor: user.enabled ? '#d4edda' : '#f8d7da',
                      color: user.enabled ? '#155724' : '#721c24'
                    }}>
                      {user.enabled ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <button onClick={handleLogout} className="btn btn-logout" disabled={loading}>
        <LogOut size={18} style={{ display: 'inline', marginRight: '8px', verticalAlign: 'middle' }} />
        {loading ? 'Logging out...' : 'Logout'}
      </button>
    </div>
  );
};

export default function App() {
  const [activeTab, setActiveTab] = useState('login');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [tokens, setTokens] = useState({ accessToken: null, refreshToken: null });
  const [userData, setUserData] = useState(null);
  const [alert, setAlert] = useState({ message: '', type: '' });

  const showAlert = (message, type) => {
    setAlert({ message, type });
    if (message) {
      setTimeout(() => setAlert({ message: '', type: '' }), 5000);
    }
  };

  const handleLoginSuccess = async (data) => {
    setTokens({
      accessToken: data.access_token,
      refreshToken: data.refresh_token
    });

    try {
      let response = await fetch(`${API_BASE_URL}/userinfo`, {
        headers: { 'Authorization': `Bearer ${data.access_token}` }
      });
      
      let result = await response.json();
      
      if (!response.ok && response.status === 403) {
        response = await fetch(`${API_BASE_URL}/decode-token`, {
          headers: { 'Authorization': `Bearer ${data.access_token}` }
        });
        result = await response.json();
      }
      
      if (result.success) {
        setUserData(result.data);
        setIsAuthenticated(true);
        showAlert('', '');
      } else {
        setUserData({ preferred_username: 'User', roles: [] });
        setIsAuthenticated(true);
      }
    } catch (error) {
      console.error('Error fetching user info:', error);
      setUserData({ preferred_username: 'User', roles: [] });
      setIsAuthenticated(true);
    }
  };

  const handleRegisterSuccess = () => {
    setActiveTab('login');
  };

  const handleLogout = () => {
    setIsAuthenticated(false);
    setTokens({ accessToken: null, refreshToken: null });
    setUserData(null);
    setActiveTab('login');
  };

  return (
    <div style={{ minHeight: '100vh', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', display: 'flex', justifyContent: 'center', alignItems: 'center', padding: '20px' }}>
      <style>{`
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .container { background: white; border-radius: 20px; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3); overflow: hidden; max-width: 550px; width: 100%; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; }
        .header h1 { font-size: 28px; margin-bottom: 5px; }
        .header p { font-size: 14px; opacity: 0.9; }
        .tabs { display: flex; background: #f5f5f5; }
        .tab { flex: 1; padding: 15px; text-align: center; cursor: pointer; background: #f5f5f5; border: none; font-size: 16px; font-weight: 600; color: #666; transition: all 0.3s ease; }
        .tab.active { background: white; color: #667eea; border-bottom: 3px solid #667eea; }
        .form-container { padding: 30px; }
        .form-section { animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #333; font-weight: 500; font-size: 14px; }
        input, select { width: 100%; padding: 12px 15px; border: 2px solid #e0e0e0; border-radius: 8px; font-size: 14px; transition: all 0.3s ease; outline: none; }
        input:focus, select:focus { border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        .btn { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s ease; margin-top: 10px; }
        .btn:hover:not(:disabled) { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .alert { padding: 12px 15px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; display: flex; align-items: center; gap: 10px; animation: slideDown 0.3s ease; }
        @keyframes slideDown { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .dashboard { padding: 30px; animation: fadeIn 0.3s ease; }
        .user-info { background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .user-info h3 { color: #667eea; margin-bottom: 15px; }
        .info-item { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #e0e0e0; }
        .info-item:last-child { border-bottom: none; }
        .info-label { font-weight: 600; color: #666; }
        .info-value { color: #333; }
        .btn-logout { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .btn-logout:hover:not(:disabled) { box-shadow: 0 10px 20px rgba(245, 87, 108, 0.3); }
        .token-display { background: #f8f9fa; padding: 15px; border-radius: 8px; word-break: break-all; font-size: 12px; font-family: monospace; max-height: 120px; overflow-y: auto; }
        .token-display strong { display: block; margin-bottom: 8px; color: #667eea; font-size: 14px; }
        .dashboard-tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .dash-tab { flex: 1; padding: 12px; background: #f8f9fa; border: none; border-radius: 8px; font-weight: 600; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 8px; transition: all 0.3s; }
        .dash-tab.active { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .dashboard-content { margin-bottom: 20px; }
        .feature-box { background: #f8f9fa; padding: 20px; border-radius: 10px; }
        .feature-box h4 { color: #667eea; margin-bottom: 10px; }
      `}</style>

      <div className="container">
        <div className="header">
          <h1>🔐 Role-Based Authentication</h1>
          <p>Secure login with Keycloak RBAC</p>
        </div>

        {!isAuthenticated ? (
          <>
            <div className="tabs">
              <button className={`tab ${activeTab === 'login' ? 'active' : ''}`} onClick={() => { setActiveTab('login'); showAlert('', ''); }}>Login</button>
              <button className={`tab ${activeTab === 'register' ? 'active' : ''}`} onClick={() => { setActiveTab('register'); showAlert('', ''); }}>Register</button>
            </div>
            <div className="form-container">
              <Alert message={alert.message} type={alert.type} />
              {activeTab === 'login' ? <LoginForm onSuccess={handleLoginSuccess} onAlert={showAlert} /> : <RegisterForm onSuccess={handleRegisterSuccess} onAlert={showAlert} />}
            </div>
          </>
        ) : (
          <Dashboard userData={userData} accessToken={tokens.accessToken} refreshToken={tokens.refreshToken} onLogout={handleLogout} onAlert={showAlert} />
        )}
      </div>
    </div>
  );
}