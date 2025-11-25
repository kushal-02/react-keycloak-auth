const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: 'http://localhost:3001', // React dev server default port
    credentials: true
}));
app.use(bodyParser.json());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Keycloak Configuration
const KEYCLOAK_URL = process.env.KEYCLOAK_URL;
const REALM = process.env.KEYCLOAK_REALM;
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID;
const CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET;
const ADMIN_USERNAME = process.env.KEYCLOAK_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYCLOAK_ADMIN_PASSWORD;

// Helper function to get admin access token
async function getAdminToken() {
  try {
    const response = await axios.post(
      `${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: ADMIN_USERNAME,
        password: ADMIN_PASSWORD
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    return response.data.access_token;
  } catch (error) {
    console.error('Error getting admin token:', error.response?.data || error.message);
    throw new Error('Failed to authenticate admin');
  }
}

// ==================== REGISTRATION ENDPOINT ====================
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email, and password are required'
      });
    }

    // Get admin token
    const adminToken = await getAdminToken();

    // Create user in Keycloak
    const userData = {
      username: username,
      email: email,
      firstName: firstName || '',
      lastName: lastName || '',
      enabled: true,
      emailVerified: false,
      credentials: [
        {
          type: 'password',
          value: password,
          temporary: false
        }
      ]
    };

    const createUserResponse = await axios.post(
      `${KEYCLOAK_URL}/admin/realms/${REALM}/users`,
      userData,
      {
        headers: {
          'Authorization': `Bearer ${adminToken}`,
          'Content-Type': 'application/json'
        }
      }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        username: username,
        email: email
      }
    });

  } catch (error) {
    console.error('Registration error:', error.response?.data || error.message);
    
    if (error.response?.status === 409) {
      return res.status(409).json({
        success: false,
        message: 'User already exists'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Registration failed',
      error: error.response?.data || error.message
    });
  }
});

// ==================== LOGIN ENDPOINT ====================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username and password are required'
      });
    }

    // Authenticate user with Keycloak
    const response = await axios.post(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'password',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        username: username,
        password: password
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    // Return tokens to client
    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token,
        expires_in: response.data.expires_in,
        token_type: response.data.token_type
      }
    });

  } catch (error) {
    console.error('Login error:', error.response?.data || error.message);

    if (error.response?.status === 401) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.response?.data?.error_description || error.message
    });
  }
});

// ==================== REFRESH TOKEN ENDPOINT ====================
app.post('/api/refresh', async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    const response = await axios.post(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`,
      new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: refresh_token
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        access_token: response.data.access_token,
        refresh_token: response.data.refresh_token,
        expires_in: response.data.expires_in
      }
    });

  } catch (error) {
    console.error('Token refresh error:', error.response?.data || error.message);
    res.status(401).json({
      success: false,
      message: 'Token refresh failed',
      error: error.response?.data?.error_description || error.message
    });
  }
});

// ==================== LOGOUT ENDPOINT ====================
app.post('/api/logout', async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        success: false,
        message: 'Refresh token is required'
      });
    }

    await axios.post(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/logout`,
      new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token: refresh_token
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    res.status(200).json({
      success: true,
      message: 'Logout successful'
    });

  } catch (error) {
    console.error('Logout error:', error.response?.data || error.message);
    res.status(500).json({
      success: false,
      message: 'Logout failed',
      error: error.response?.data || error.message
    });
  }
});

// ==================== USER INFO ENDPOINT ====================
app.get('/api/userinfo', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const token = authHeader.split(' ')[1];

    const response = await axios.get(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/userinfo`,
      {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      }
    );

    res.status(200).json({
      success: true,
      data: response.data
    });

  } catch (error) {
    console.error('Userinfo error:', error.response?.data || error.message);
    res.status(401).json({
      success: false,
      message: 'Invalid or expired token',
      error: error.response?.data || error.message
    });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Keycloak URL: ${KEYCLOAK_URL}`);
  console.log(`Realm: ${REALM}`);
});