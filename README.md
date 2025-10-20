# WebSSH - Secure Web-Based SSH Client

**Author:** steven
**Version:** 0.1.0
**License:** MIT

A modern, secure web-based SSH client built with Rust and xterm.js. This is a standalone application that provides enterprise-grade security features including JWT authentication, 2FA, password encryption, and comprehensive audit logging.

## ✨ Features

### 🚀 Core Functionality
- **Real-time SSH Connections** - WebSocket-based SSH sessions with full terminal emulation
- **Multiple Authentication Methods** - Support for password and private key authentication
- **Terminal Emulation** - Full-featured terminal powered by xterm.js with auto-resize
- **Copy/Paste Support** - Right-click to copy, Ctrl+V to paste
- **Modern UI** - Clean, responsive interface with dark theme
- **Standalone Application** - Single binary, no external dependencies required

### 🔐 Security Features
- **JWT Authentication** - Token-based authentication with configurable expiration
- **Two-Factor Authentication (2FA)** - TOTP-based 2FA compatible with Google Authenticator, Microsoft Authenticator, Authy, etc.
- **Password Encryption** - Bcrypt password hashing with cost factor 12 (4096 iterations)
- **Master Password Protection** - AES-256-GCM encryption for SSH credentials with PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
- **SSH Host Key Verification** - Prevent man-in-the-middle attacks
- **Role-Based Access Control** - Admin and User roles with granular permissions
- **Comprehensive Audit Logging** - Track all user actions and SSH connections
- **Password Change Functionality** - Users can change their passwords with validation

### 📝 Management Features
- **SSH Configuration Management** - Save and manage frequently used SSH connections
- **User Management** - Create, list, and delete users (Admin only)
- **Audit Log Viewer** - Review security events and user activities
- **Encrypted Storage** - All sensitive data encrypted at rest

## 🛠️ Technology Stack

### Backend
- **Rust** - Systems programming language for performance and safety
- **Warp 0.3** - Fast, composable web framework
- **ssh2 0.9** - SSH client library
- **Tokio 1.28** - Async runtime
- **jsonwebtoken 9.2** - JWT authentication
- **bcrypt 0.15** - Password hashing (cost factor 12)
- **aes-gcm 0.10** - AES-256-GCM encryption
- **pbkdf2 0.11** - Key derivation (600,000 iterations)
- **totp-lite 2.0** - TOTP implementation for 2FA
- **qrcode 0.12** - QR code generation for 2FA setup
- **chrono 0.4** - Date and time handling
- **uuid 1.6** - Unique identifier generation

### Frontend
- **xterm.js 5.3.0** - Full-featured terminal emulator
- **xterm-addon-fit** - Terminal auto-resize addon
- **Vanilla JavaScript** - No framework dependencies
- **WebSocket** - Real-time bidirectional communication

## 🚀 Quick Start

### Prerequisites

- **Rust 1.75.0+** - [Install Rust](https://rustup.rs/)
- **Cargo** - Comes with Rust installation

### Installation

If you haven't installed Rust yet:

```bash
# Linux/macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Windows
# Download and run rustup-init.exe from https://rustup.rs/
```

### Running the Application

1. **Clone or download this project**

2. **Navigate to project directory:**
   ```bash
   cd webssh
   ```

3. **Build and run (development mode):**
   ```bash
   cargo run
   ```

4. **Enter master password when prompted:**
   ```
   Enter master password to decrypt SSH configurations:
   (First time: set a strong password. Subsequent: use the same password)
   ```

   ⚠️ **Important:** Remember this password! It encrypts all SSH credentials.

5. **Open browser and navigate to:**
   ```
   http://127.0.0.1:18022
   ```

6. **Login with default admin account:**
   - Username: `admin`
   - Password: `admin`

   🔴 **CRITICAL:** Change the default password immediately after first login!

### Building for Production

```bash
# Build optimized release binary
cargo build --release

# Binary location
./target/release/webssh      # Linux/macOS
.\target\release\webssh.exe   # Windows
```

### Quick Start Scripts

**Windows:**
```cmd
start_server.bat
```

**Linux/macOS:**
```bash
# Make script executable (first time only)
chmod +x start_server.sh

# Run the script
./start_server.sh
```

## 📖 Usage Guide

### First-Time Setup

1. **Change Default Password**
   - Click **🔑 Change Password** button in the top navigation
   - Enter current password: `admin`
   - Set a strong new password (minimum 6 characters)
   - Confirm new password

2. **Enable Two-Factor Authentication (Recommended)**
   - Click **🔐 2FA** button
   - Click **Enable 2FA**
   - Scan QR code with authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.)
   - Or manually enter the secret key
   - Enter the 6-digit verification code
   - Click **Confirm Enable**

### Connecting to SSH Servers

#### Method 1: Quick Connect
1. Fill in SSH connection details:
   - **Host:** IP address or hostname
   - **Port:** SSH port (default: 22)
   - **Username:** SSH username
   - **Authentication:** Choose password or private key
   - **Password/Key:** Enter credentials
2. Click **Connect**
3. Verify host key on first connection
4. Terminal session starts automatically

#### Method 2: Using Saved Configurations
1. Click **📝 SSH Configs** button
2. Click **Add Configuration**
3. Fill in configuration details and save
4. Select configuration from list
5. Click **Connect**

### Terminal Operations

- **Copy:** Select text with mouse, then right-click
- **Paste:** Press `Ctrl+V` (Windows/Linux) or `Cmd+V` (macOS)
- **Resize:** Terminal automatically adjusts to window size
- **Disconnect:** Close browser tab or click disconnect button

### Managing SSH Configurations

- **Create:** Click **Add Configuration**, fill details, save
- **Edit:** Click edit icon next to configuration
- **Delete:** Click delete icon (requires confirmation)
- **Connect:** Click configuration name to load and connect

### Viewing Audit Logs

1. Click **📊 Audit Logs** button
2. Review user activities and SSH connections
3. Filter by action type or user
4. Export logs for compliance reporting

## 📁 Project Structure

```
webssh/
├── src/
│   ├── main.rs                    # Application entry point
│   ├── api.rs                     # API module aggregator
│   ├── auth.rs                    # Authentication & user management
│   ├── ssh_config.rs              # SSH configuration management
│   ├── audit.rs                   # Audit logging service
│   ├── host_key.rs                # SSH host key verification
│   ├── crypto.rs                  # Encryption service (AES-256-GCM)
│   └── api/
│       ├── auth.rs                # Authentication API routes
│       ├── config.rs              # SSH config API routes
│       ├── audit.rs               # Audit log API routes
│       ├── files.rs               # Static file serving
│       ├── not_found.rs           # 404 handler
│       └── ssh_websocket/
│           ├── mod.rs             # WebSocket route setup
│           └── session.rs         # SSH session management
├── static/
│   ├── index.html                 # Main application page
│   ├── login.html                 # Login page
│   ├── style.css                  # Application styles
│   ├── app.js                     # Frontend logic
│   └── 404.html                   # 404 error page
├── data/                          # Data directory (auto-created)
│   ├── users.json                 # User accounts (bcrypt hashed)
│   ├── ssh_configs.json           # SSH configurations (encrypted)
│   ├── audit_logs.json            # Audit logs
│   └── host_keys.json             # Known SSH host keys
├── Cargo.toml                     # Rust project configuration
├── start_server.bat               # Windows startup script
├── start_server.sh                # Linux/macOS startup script
└── README.md                      # This file
```

## 🔌 WebSocket Protocol

Client and server communicate via WebSocket using JSON messages with base64-encoded payloads.

### Client → Server Messages

```json
// Set SSH server address
{"addr": "base64_encoded_host:port"}

// Set username
{"login": "base64_encoded_username"}

// Set password
{"password": "base64_encoded_password"}

// Set private key
{"key": "base64_encoded_private_key"}

// Initiate SSH connection
{"connect": true}

// Send terminal input
{"stdin": "base64_encoded_input"}

// Resize terminal
{"resize": {"cols": 80, "rows": 24}}
```

### Server → Client Messages

```json
// Terminal output
{"stdout": "base64_encoded_output"}

// Error output
{"stderr": "base64_encoded_error"}
```

## 🔗 API Documentation

### Authentication API

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin",
  "totp_code": "123456"  // Optional, required if 2FA enabled
}

Response 200:
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "username": "admin",
  "role": "Admin"
}

Response 401:
{
  "error": "Invalid credentials"
}
```

#### Verify Token
```http
GET /api/auth/verify
Authorization: Bearer <token>

Response 200:
{
  "sub": "user-id",
  "username": "admin",
  "role": "Admin",
  "exp": 1234567890
}
```

#### Change Password
```http
POST /api/auth/change-password
Authorization: Bearer <token>
Content-Type: application/json

{
  "old_password": "current_password",
  "new_password": "new_password"
}

Response 200:
{
  "message": "Password changed successfully"
}
```

#### Setup 2FA
```http
POST /api/auth/totp/setup
Authorization: Bearer <token>

Response 200:
{
  "secret": "BASE32_ENCODED_SECRET",
  "qr_code": "data:image/svg+xml;base64,...",
  "manual_entry": "Account: admin\nSecret: ..."
}
```

#### Enable 2FA
```http
POST /api/auth/totp/enable
Authorization: Bearer <token>
Content-Type: application/json

{
  "secret": "BASE32_ENCODED_SECRET",
  "code": "123456"
}

Response 200:
{
  "message": "2FA enabled successfully"
}
```

#### Disable 2FA
```http
POST /api/auth/totp/disable
Authorization: Bearer <token>
Content-Type: application/json

{
  "password": "current_password",
  "code": "123456"
}

Response 200:
{
  "message": "2FA disabled successfully"
}
```

#### Get 2FA Status
```http
GET /api/auth/totp/status
Authorization: Bearer <token>

Response 200:
{
  "enabled": true
}
```

#### Create User (Admin Only)
```http
POST /api/auth/users
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "newuser",
  "password": "password",
  "role": "User"
}

Response 201:
{
  "message": "User created successfully"
}
```

#### List Users (Admin Only)
```http
GET /api/auth/users
Authorization: Bearer <token>

Response 200:
[
  {
    "id": "uuid",
    "username": "admin",
    "role": "Admin",
    "created_at": 1234567890,
    "totp_enabled": true
  }
]
```

#### Delete User (Admin Only)
```http
DELETE /api/auth/users/{username}
Authorization: Bearer <token>

Response 200:
{
  "message": "User deleted successfully"
}
```

### SSH Configuration API

#### Create Configuration
```http
POST /api/configs
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Production Server",
  "host": "192.168.1.100",
  "port": 22,
  "username": "root",
  "password": "encrypted_password",  // Optional
  "private_key": "-----BEGIN...",    // Optional
  "auth_type": "password"            // "password" or "key"
}

Response 201:
{
  "id": "config-uuid",
  "message": "Configuration created successfully"
}
```

#### List Configurations
```http
GET /api/configs
Authorization: Bearer <token>

Response 200:
[
  {
    "id": "uuid",
    "name": "Production Server",
    "host": "192.168.1.100",
    "port": 22,
    "username": "root",
    "auth_type": "password",
    "created_at": 1234567890,
    "updated_at": 1234567890
  }
]
```

#### Get Configuration
```http
GET /api/configs/{config_id}
Authorization: Bearer <token>

Response 200:
{
  "id": "uuid",
  "name": "Production Server",
  "host": "192.168.1.100",
  "port": 22,
  "username": "root",
  "password": "decrypted_password",  // Decrypted on retrieval
  "auth_type": "password"
}
```

#### Update Configuration
```http
PUT /api/configs/{config_id}
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Updated Name",
  "host": "192.168.1.101",
  "port": 2222,
  "username": "admin",
  "password": "new_password",
  "auth_type": "password"
}

Response 200:
{
  "message": "Configuration updated successfully"
}
```

#### Delete Configuration
```http
DELETE /api/configs/{config_id}
Authorization: Bearer <token>

Response 200:
{
  "message": "Configuration deleted successfully"
}
```

### Audit Log API

#### Get Audit Logs
```http
GET /api/audit/logs?limit=100
Authorization: Bearer <token>

Response 200:
[
  {
    "id": "uuid",
    "timestamp": 1234567890,
    "user_id": "user-uuid",
    "username": "admin",
    "action": "Login",
    "details": "Successful login",
    "ip_address": "192.168.1.100",
    "success": true
  }
]
```

#### Get User Activity
```http
GET /api/audit/activity?limit=50
Authorization: Bearer <token>

Response 200:
[
  {
    "username": "admin",
    "action": "SshConnect",
    "timestamp": 1234567890,
    "details": "Connected to 192.168.1.100:22"
  }
]
```

### WebSocket SSH Connection

```http
GET /ws/ssh
Authorization: Bearer <token>
Upgrade: websocket

// After WebSocket connection established, send JSON messages
// See WebSocket Protocol section above
```

## 🔒 Security Features in Detail

### Implemented Security Measures

| Feature | Implementation | Details |
|---------|---------------|---------|
| **Password Storage** | Bcrypt | Cost factor 12 (4096 iterations) |
| **SSH Credential Encryption** | AES-256-GCM | Master password protected |
| **Key Derivation** | PBKDF2-HMAC-SHA256 | 600,000 iterations |
| **Authentication** | JWT | 24-hour token expiration |
| **Two-Factor Auth** | TOTP (RFC 6238) | 30-second time step, ±60s tolerance |
| **Access Control** | RBAC | Admin and User roles |
| **Audit Logging** | Comprehensive | All actions logged with timestamps |
| **Host Key Verification** | SSH fingerprints | Prevent MITM attacks |

### Security Best Practices

#### For Production Deployment

1. **Change JWT Secret**
   - Edit `JWT_SECRET` in `src/auth.rs`
   - Use a strong, random 256-bit key
   - Never commit secrets to version control

2. **Enable HTTPS/WSS**
   - Use reverse proxy (nginx, Apache, Caddy)
   - Obtain SSL/TLS certificate (Let's Encrypt)
   - Force HTTPS redirects

3. **Master Password**
   - Use a strong master password (20+ characters)
   - Store securely (password manager)
   - Never share or write down

4. **Enable 2FA**
   - Require 2FA for all admin accounts
   - Enforce 2FA for sensitive operations
   - Keep backup codes secure

5. **Network Security**
   - Configure firewall rules
   - Limit access to trusted IPs
   - Use VPN for remote access
   - Disable unnecessary ports

6. **Regular Maintenance**
   - Review audit logs weekly
   - Update dependencies regularly
   - Backup `data/` directory
   - Monitor for suspicious activity

7. **Password Policy**
   - Enforce minimum password length (12+ characters)
   - Require password changes every 90 days
   - Prevent password reuse
   - Implement account lockout after failed attempts

### Data Storage

All sensitive data is stored in the `data/` directory:

- **users.json** - User accounts with bcrypt-hashed passwords
- **ssh_configs.json** - SSH configurations with AES-256-GCM encrypted credentials
- **audit_logs.json** - Audit logs (max 1000 entries, FIFO)
- **host_keys.json** - Known SSH host keys

⚠️ **Backup Recommendation:** Regularly backup the `data/` directory to prevent data loss.

## 🐛 Troubleshooting

### Common Issues

**Problem:** Cannot connect to SSH server
**Solution:**
- Verify SSH server is running and accessible
- Check firewall rules on both client and server
- Verify credentials are correct
- Check SSH server logs for errors

**Problem:** 2FA code always fails
**Solution:**
- Ensure server and phone time are synchronized
- Check time zone settings
- Try codes from ±60 second window
- Re-setup 2FA if issue persists

**Problem:** Forgot master password
**Solution:**
- Master password cannot be recovered
- Delete `data/` directory to reset (loses all data)
- Restore from backup if available

**Problem:** WebSocket connection fails
**Solution:**
- Check browser console for errors
- Verify JWT token is valid
- Ensure WebSocket is not blocked by firewall/proxy
- Try different browser

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd webssh

# Install dependencies
cargo build

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run
```

## 📄 License

MIT License

Copyright (c) 2024 steven

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 🙏 Acknowledgments

- [xterm.js](https://xtermjs.org/) - Terminal emulator
- [Warp](https://github.com/seanmonstar/warp) - Web framework
- [ssh2-rs](https://github.com/alexcrichton/ssh2-rs) - SSH client library
- [Rust](https://www.rust-lang.org/) - Programming language

---

**Built with ❤️ using Rust**


