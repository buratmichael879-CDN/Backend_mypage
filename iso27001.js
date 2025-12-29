const crypto = require('crypto');

// Generate secure session configuration
const session = require('express-session');
const store = new session.MemoryStore(); // Use Redis in production

app.use(session({
  secret: crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: store,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  }
}));

// Security middleware stack for login
const securityMiddleware = [
  helmet(),
  loginLimiter,
  express.json({ limit: '10kb' }), // Limit request size
  (req, res, next) => {
    // Log login attempts
    console.log(`Login attempt from ${req.ip} at ${new Date().toISOString()}`);
    next();
  }
];

// Apply to login route
app.post('/api/login', securityMiddleware, [
  body('username').trim().escape().notEmpty(),
  body('password').trim().notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors.array() 
      });
    }

    const { username, password } = req.body;
    
    // Your authentication logic here
    // Always use bcrypt for password comparison
    const bcrypt = require('bcrypt');
    
    // Simulated user lookup
    const user = await findUser(username);
    
    if (!user) {
      // Simulate delay to prevent timing attacks
      await bcrypt.compare(password, '$2b$10$fakehashforsecurity');
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }
    
    const isValid = await bcrypt.compare(password, user.passwordHash);
    
    if (!isValid) {
      return res.status(401).json({ 
        error: 'Invalid credentials' 
      });
    }
    
    // Generate secure session/token
    req.session.userId = user.id;
    
    res.json({ 
      message: 'Login successful',
      user: { id: user.id, username: user.username }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
