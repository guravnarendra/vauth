const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Import database connection
const connectDB = require('./config/database');

// Import routes
const userRoutes = require('./routes/userRoutes');
const adminRoutes = require('./routes/adminRoutes');
app.set('trust proxy', 1);

// Import middleware
const { cleanupExpiredData } = require('./middleware/cleanup');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  },
  pingTimeout: 60000, // Increase timeout to 60 seconds
  pingInterval: 25000 // Send ping every 25 seconds
});

// Connect to database
connectDB();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable for development
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: true,
  credentials: true
}));

// Rate limiting
const loginLimiter = rateLimit({
  windowMs: parseInt(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
  max: parseInt(process.env.LOGIN_RATE_LIMIT_MAX_ATTEMPTS) || 5,
  message: 'Too many login attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const tokenLimiter = rateLimit({
  windowMs: parseInt(process.env.TOKEN_RATE_LIMIT_WINDOW_MS) || 300000, // 5 minutes
  max: parseInt(process.env.TOKEN_RATE_LIMIT_MAX_ATTEMPTS) || 10,
  message: 'Too many token verification attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    touchAfter: 24 * 3600 // lazy session update
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // 24 hours
  },
  name: 'vauth.sid'
}));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Make io available to routes
app.use((req, res, next) => {
  req.io = io;
  next();
});

// Apply rate limiting to specific routes
app.use('/api/user/login', loginLimiter);
app.use('/api/user/verify-token', tokenLimiter);
app.use('/api/admin/login', loginLimiter);

// Routes
app.use('/api/user', userRoutes);
app.use('/api/admin', adminRoutes);

// Serve main pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/2fa', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', '2fa.html'));
});

app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

// Socket.io connection handling with better error handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Handle admin room joining
  socket.on('join-admin', () => {
    socket.join('admin');
    console.log('Admin joined real-time monitoring:', socket.id);
  });

  // Handle client disconnection
  socket.on('disconnect', (reason) => {
    console.log('Client disconnected:', socket.id, 'Reason:', reason);
  });

  // Handle connection errors
  socket.on('error', (error) => {
    console.error('Socket error:', socket.id, error);
  });
});

// Cleanup expired data every 5 minutes
setInterval(cleanupExpiredData, 5 * 60 * 1000);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found'
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`VAUTH Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
  console.log(`Access the application at: http://localhost:${PORT}`);
});

module.exports = { app, io };