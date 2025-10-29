const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

// --- Configuration ---
const PORT = process.env.PORT || 5001;
const MONGO_URI = 'mongodb://localhost:27017/rbac-db';
const ACCESS_TOKEN_SECRET = 'your-access-token-secret-key-CHANGE-ME';
const REFRESH_TOKEN_SECRET = 'your-refresh-token-secret-key-CHANGE-ME';
const ACCESS_TOKEN_EXPIRATION = '15m';
const REFRESH_TOKEN_EXPIRATION = '7d';

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

const app = express();

// --- Middleware ---
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use(morgan('dev'));

// --- Database Connection ---
mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB connected successfully.');
    seedDatabase();
  })
  .catch((err) => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas ---
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true },
  role: { type: String, enum: Object.values(ROLES), default: ROLES.Viewer },
}, { timestamps: true });

userSchema.pre('save', async function(next) {
  // Only hash if the password is new or has been changed
  if (this.isNew || this.isModified('password')) {
    try {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
      console.log(`[Hashing]: Password for '${this.username}' has been hashed.`);
      next();
    } catch (error) {
      next(error);
    }
  } else {
    next();
  }
});

const User = mongoose.model('User', userSchema);

const contentSchema = new mongoose.Schema({
  title: { type: String, required: true },
  body: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

const Content = mongoose.model('Content', contentSchema);

// --- Utility Functions ---
const createToken = (payload, secret, expiresIn) => {
  return jwt.sign(payload, secret, { expiresIn });
};

const sendAuthTokens = (res, user) => {
  const userData = { id: user._id, username: user.username, role: user.role };
  
  const accessToken = createToken(userData, ACCESS_TOKEN_SECRET, ACCESS_TOKEN_EXPIRATION);
  const refreshToken = createToken({ id: user._id }, REFRESH_TOKEN_SECRET, REFRESH_TOKEN_EXPIRATION);

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  
  res.json({
    message: 'Authentication successful',
    accessToken,
    user: userData,
  });
};

// --- Rate Limiter ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many authentication attempts from this IP, please try again after 15 minutes',
});

// --- Auth Middleware ---
const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided, authorization denied.' });
  }

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid.' });
  }
};

const authorize = (action) => {
  return (req, res, next) => {
    const [resource, requiredPermission] = action.split(':');
    const userRole = req.user.role;
    const userPermissions = PERMISSIONS[userRole]?.[resource] || [];

    const hasPermission = userPermissions.includes(requiredPermission) ||
                          userPermissions.includes(`${requiredPermission}_all`);
                          
    if (!hasPermission) {
      if (userPermissions.includes(`${requiredPermission}_own`)) {
        req.isOwnershipCheckRequired = true;
        return next();
      }
      return res.status(403).json({ message: 'Forbidden: You do not have permission.' });
    }
    
    next();
  };
};

// --- API Routes ---

// 1. Auth Routes
app.post('/api/auth/register', authLimiter, [
  body('username', 'Username must be at least 3 characters long').isLength({ min: 3 }).trim().escape(),
  body('password', 'Password must be at least 6 characters long').isLength({ min: 6 }),
], async (req, res) => {
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { username, password } = req.body;
    let user = await User.findOne({ username });
    if (user) {
      return res.status(400).json({ message: 'User already exists.' });
    }
    
    user = new User({ username, password, role: ROLES.Viewer });
    await user.save();
    
    sendAuthTokens(res, user);
  } catch (error) {
    res.status(500).json({ message: 'Server error during registration.', error: error.message });
  }
});

app.post('/api/auth/login', authLimiter, [
  body('username', 'Username is required').notEmpty().trim().escape(),
  body('password', 'Password is required').notEmpty(),
], async (req, res) => {
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
      console.log(`[Login Attempt]: User '${username}' not found.`);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    
    console.log(`[Login Attempt]: Found user '${username}'. Comparing passwords...`);
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      console.log(`[Login Attempt]: Password for '${username}' does NOT match.`);
      return res.status(400).json({ message: 'Invalid credentials.' });
    }
    
    console.log(`[Login Attempt]: Password for '${username}' matched. Logging in.`);
    sendAuthTokens(res, user);
  } catch (error) {
    res.status(500).json({ message: 'Server error during login.', error: error.message });
  }
});

app.post('/api/auth/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided.' });
  }

  try {
    const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
    
    User.findById(decoded.id).then(user => {
      if (!user) {
        return res.status(401).json({ message: 'Invalid refresh token.' });
      }
      
      const userData = { id: user._id, username: user.username, role: user.role };
      const accessToken = createToken(userData, ACCESS_TOKEN_SECRET, ACCESS_TOKEN_EXPIRATION);
      
      res.json({ accessToken });
    });
  } catch (err) {
    res.status(401).json({ message: 'Invalid refresh token.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.cookie('refreshToken', '', {
    httpOnly: true,
    expires: new Date(0),
  });
  res.status(200).json({ message: 'Logged out successfully.' });
});

// 2. Content Routes
app.use('/api/content', authenticate);

app.get('/api/content', authorize('content:read'), async (req, res) => {
  try {
    const content = await Content.find().populate('author', 'username').sort({ createdAt: -1 });
    res.json(content);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

app.get('/api/content/:id', authorize('content:read'), async (req, res) => {
  try {
    const content = await Content.findById(req.params.id).populate('author', 'username');
    if (!content) {
      return res.status(404).json({ message: 'Content not found.' });
    }
    res.json(content);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});


app.post('/api/content', authorize('content:create'), [
  body('title', 'Title is required').notEmpty().trim().escape(),
  body('body', 'Body is required').notEmpty().trim().escape(),
], async (req, res) => {
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const { title, body } = req.body;
    const content = new Content({
      title,
      body,
      author: req.user.id,
    });
    await content.save();
    res.status(201).json(content);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

app.put('/api/content/:id', authorize('content:update'), [
  body('title', 'Title is required').notEmpty().trim().escape(),
  body('body', 'Body is required').notEmpty().trim().escape(),
], async (req, res) => {
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { title, body } = req.body;
    let content = await Content.findById(req.params.id);

    if (!content) {
      return res.status(404).json({ message: 'Content not found.' });
    }

    if (req.isOwnershipCheckRequired && content.author.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Forbidden: You can only update your own content.' });
    }
    
    content.title = title;
    content.body = body;
    await content.save();
    
    res.json(content);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

app.delete('/api/content/:id', authorize('content:delete'), async (req, res) => {
  try {
    const content = await Content.findById(req.params.id);

    if (!content) {
      return res.status(404).json({ message: 'Content not found.' });
    }

    if (req.isOwnershipCheckRequired && content.author.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Forbidden: You can only delete your own content.' });
    }
    
    await Content.findByIdAndDelete(req.params.id);
    
    res.json({ message: 'Content deleted successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

// 3. Admin Routes
app.use('/api/users', authenticate, authorize('users:read'));

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

app.put('/api/users/:id/role', authorize('users:update'), [
  body('role', 'A valid role is required').isIn(Object.values(ROLES)),
], async (req, res) => {
  
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  try {
    const { role } = req.body;
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }
    
    user.role = role;
    await user.save();
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error.', error: error.message });
  }
});

// --- Server Start ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// --- Database Seeding ---
async function seedDatabase() {
  try {
    await User.deleteMany({});
    await Content.deleteMany({});
    
    const adminUser = new User({
      username: 'admin',
      password: 'adminpassword',
      role: ROLES.Admin,
    });
    const editorUser = new User({
      username: 'editor',
      password: 'editorpassword',
      role: ROLES.Editor,
    });
    const viewerUser = new User({
      username: 'viewer',
      password: 'viewerpassword',
      role: ROLES.Viewer,
    });
    
    await adminUser.save();
    await editorUser.save();
    await viewerUser.save();
    
    const content1 = new Content({
      title: 'Admin\'s Post',
      body: 'This post was created by the Admin. Only the Admin can edit or delete this.',
      author: adminUser._id,
    });
    const content2 = new Content({
      title: 'Editor\'s Post',
      body: 'This post was created by the Editor. The Admin can edit/delete it, and the Editor who wrote it can also edit/delete it.',
      author: editorUser._id,
    });
    const content3 = new Content({
      title: 'Another Editor\'s Post',
      body: 'This is a second post by the Editor.',
      author: editorUser._id,
    });

    await content1.save();
    await content2.save();
    await content3.save();

    console.log('Database seeded successfully.');
  } catch (error) {
    console.error('Error seeding database:', error.message);
  }
}

