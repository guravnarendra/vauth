# VAUTH - Secure Authentication System

A comprehensive two-factor authentication system with real-time monitoring, encrypted data storage, and advanced admin controls.

## Features

### Core Authentication
- **Two-Factor Authentication**: Username/password + VAUTH device token verification
- **Encrypted Data Storage**: AES-256 encryption for all personal information (PII)
- **Session Management**: Automatic session expiry and force logout capabilities
- **Security Monitoring**: Real-time alerts for suspicious activities

### Admin Dashboard
- **User Management**: Add, view, and manage users
- **Token Control**: View, delete, and auto-cleanup expired tokens
- **Session Monitoring**: Real-time session tracking with force logout
- **Virtual Device**: Generate tokens for testing and development
- **Live Request Map**: Visual representation of authentication requests
- **Security Alerts**: Automatic detection of failed login attempts

### Real-time Features
- **WebSocket Integration**: Live updates for admin dashboard
- **Request Visualization**: Real-time authentication flow animations
- **Activity Monitoring**: Live feed of system activities
- **Instant Notifications**: Immediate alerts for security events

## Technology Stack

- **Frontend**: HTML5, Tailwind CSS, JavaScript
- **Backend**: Node.js with Express.js
- **Database**: MongoDB with Mongoose ODM
- **Real-time**: Socket.io for WebSocket communication
- **Security**: bcrypt for password hashing, AES-256 for PII encryption
- **Session Management**: Express sessions with MongoDB store

## Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- MongoDB (v4.4 or higher)
- npm or yarn package manager

### Installation Steps

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Configure Environment**
   - Copy `.env` file and update values as needed
   - Default admin credentials: `admin` / `admin123`
   - Encryption key is auto-generated for security

3. **Start MongoDB**
   ```bash
   # Ubuntu/Debian
   sudo systemctl start mongod
   sudo systemctl enable mongod
   
   # macOS with Homebrew
   brew services start mongodb-community
   
   # Windows
   net start MongoDB
   ```

4. **Start the Application**
   ```bash
   npm start
   ```

5. **Access the Application**
   - Main Application: http://localhost:3000
   - Admin Dashboard: http://localhost:3000/admin/login

## Usage Guide

### For End Users

1. **Registration**: Contact admin to create your account
2. **Login Process**:
   - Visit http://localhost:3000
   - Click "User Login"
   - Enter username and password
   - Enter 6-character VAUTH token when prompted
   - Access your secure dashboard

### For Administrators

1. **Admin Access**:
   - Visit http://localhost:3000/admin/login
   - Use admin credentials (default: admin/admin123)

2. **User Management**:
   - Navigate to "Add New User" section
   - Fill in user details (name, email, mobile, country)
   - System generates secure credentials automatically
   - Share credentials securely with the user

3. **Token Management**:
   - View all active/expired tokens in "TokenDB"
   - Delete specific tokens manually
   - Enable auto-cleanup for expired tokens

4. **Session Monitoring**:
   - Monitor active user sessions in real-time
   - Force logout suspicious or unauthorized sessions
   - View session details (IP, duration, device)

5. **Virtual Device Testing**:
   - Generate test tokens for development
   - Specify custom device IDs
   - Test authentication flows

## Security Features

### Data Protection
- **Encryption**: All PII data encrypted with AES-256
- **Password Security**: bcrypt hashing with salt rounds
- **Session Security**: httpOnly cookies with secure flags
- **Input Validation**: Comprehensive sanitization and validation

### Monitoring & Alerts
- **Failed Login Detection**: Automatic alerts for multiple failed attempts
- **Session Anomalies**: Detection of unusual session patterns
- **Real-time Logging**: Complete audit trail of all activities
- **Rate Limiting**: Protection against brute force attacks

### Access Control
- **Role-based Access**: Separate user and admin authentication
- **Session Isolation**: Independent session management
- **Automatic Logout**: Configurable session timeouts
- **Force Logout**: Admin capability to terminate sessions

## API Endpoints

### User Authentication
- `POST /api/user/login` - User login with credentials
- `POST /api/user/verify-token` - VAUTH token verification
- `POST /api/user/logout` - User logout
- `GET /api/user/dashboard` - User dashboard data

### Admin Management
- `POST /api/admin/login` - Admin authentication
- `GET /api/admin/dashboard-stats` - Dashboard statistics
- `POST /api/admin/add-user` - Create new user
- `GET /api/admin/users` - List all users
- `GET /api/admin/tokens` - List all tokens
- `DELETE /api/admin/tokens/:id` - Delete specific token
- `GET /api/admin/sessions` - List active sessions
- `POST /api/admin/sessions/:id/force-logout` - Force logout session
- `POST /api/admin/virtual-device/generate-token` - Generate virtual token

## Database Schema

### Users Collection
```javascript
{
  username: String (unique),
  password_hash: String (bcrypt),
  vauth_device_ID: String (unique),
  name: String (encrypted),
  email: String (encrypted),
  mobile: String (encrypted),
  operating_country: String (encrypted),
  created_at: Date
}
```

### Tokens Collection
```javascript
{
  device_id: String,
  token_hash: String (SHA-512),
  status: String (ACTIVE/USED/EXPIRED),
  created_at: Date,
  expires_at: Date,
  used_at: Date
}
```

### Sessions Collection
```javascript
{
  username: String,
  device_id: String,
  ip: String,
  started_at: Date,
  expires_at: Date,
  status: String (ACTIVE/FORCED_LOGOUT/EXPIRED)
}
```

## Configuration

### Environment Variables (.env)
```
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/vauth
SESSION_SECRET=your-session-secret-here
ENCRYPTION_KEY=your-encryption-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
```

### Security Settings
- Session timeout: 30 minutes (configurable)
- Token expiry: 5 minutes (configurable)
- Failed login threshold: 5 attempts
- Rate limiting: 100 requests per 15 minutes

## Development

### Project Structure
```
vauth-website/
├── config/
│   └── database.js          # MongoDB configuration
├── middleware/
│   └── cleanup.js           # Cleanup middleware
├── models/
│   ├── User.js              # User model with encryption
│   ├── Token.js             # Token model
│   └── Session.js           # Session model
├── public/
│   ├── css/                 # Stylesheets
│   ├── js/                  # Client-side JavaScript
│   ├── images/              # Static images
│   ├── index.html           # Landing page
│   ├── login.html           # User login
│   ├── 2fa.html             # Token verification
│   ├── dashboard.html       # User dashboard
│   ├── admin-login.html     # Admin login
│   └── admin-dashboard.html # Admin dashboard
├── routes/
│   ├── userRoutes.js        # User API routes
│   └── adminRoutes.js       # Admin API routes
├── utils/
│   └── encryption.js        # Encryption utilities
├── views/                   # Server-side templates
├── server.js                # Main server file
├── package.json             # Dependencies
├── .env                     # Environment configuration
└── README.md                # This file
```

### Adding New Features
1. Create new routes in appropriate route files
2. Add corresponding frontend interfaces
3. Update database models if needed
4. Implement real-time updates via Socket.io
5. Add proper error handling and validation

## Troubleshooting

### Common Issues

1. **MongoDB Connection Failed**
   - Ensure MongoDB is running: `sudo systemctl status mongod`
   - Check connection string in `.env` file
   - Verify MongoDB is accessible on default port 27017

2. **Encryption Errors**
   - Verify `ENCRYPTION_KEY` is set in `.env`
   - Ensure key is at least 32 characters long
   - Check Node.js version compatibility

3. **Session Issues**
   - Clear browser cookies and try again
   - Check `SESSION_SECRET` in `.env` file
   - Verify session store is properly configured

4. **Real-time Features Not Working**
   - Check browser console for WebSocket errors
   - Ensure Socket.io client is properly loaded
   - Verify server WebSocket configuration

### Performance Optimization
- Enable MongoDB indexing for better query performance
- Implement connection pooling for database connections
- Use Redis for session storage in production
- Enable gzip compression for static assets
- Implement caching for frequently accessed data

## Security Considerations

### Production Deployment
1. **Environment Security**:
   - Use strong, unique passwords for admin accounts
   - Generate secure random keys for encryption and sessions
   - Enable HTTPS with valid SSL certificates
   - Configure proper CORS policies

2. **Database Security**:
   - Enable MongoDB authentication
   - Use database connection encryption
   - Implement regular backup procedures
   - Monitor database access logs

3. **Application Security**:
   - Keep dependencies updated
   - Implement proper input validation
   - Use security headers (helmet.js)
   - Enable audit logging

## Support & Maintenance

### Regular Maintenance Tasks
- Monitor system logs for errors and anomalies
- Clean up expired tokens and sessions
- Update dependencies for security patches
- Backup database regularly
- Monitor system performance metrics

### Monitoring
- Set up log aggregation and monitoring
- Implement health check endpoints
- Monitor authentication success/failure rates
- Track session duration and patterns
- Alert on security events

## License

This project is proprietary software. All rights reserved.

## Contact

For technical support or questions about this implementation, please refer to the project documentation or contact the development team.

---

**Note**: This is a complete implementation of the VAUTH system as specified. The application includes all requested features including two-factor authentication, real-time monitoring, encrypted data storage, and comprehensive admin controls.




User Created Successfully!
Username: narendragurav1157

Password: aE@ejKrUc3Km

VAUTH Device ID: VAUTH-9UG4PRIT

Please save these credentials securely. They will not be shown again.