# MERN Auth

Modern user authentication system - MongoDB, Express, React, Node.js

## Features

- User registration and login
- Email verification (OTP)
- Password reset
- JWT authentication
- Protected routes
- Responsive design

## Technologies

**Backend:** Node.js, Express, MongoDB, JWT, Bcrypt, Nodemailer  
**Frontend:** React, Vite, React Router, Axios

## Installation

### 1. Clone the Project

```bash
git clone https://github.com/yourusername/MernAuth.git
cd MernAuth
```

### 2. Backend Setup

```bash
cd backend
npm install
```

Create backend `.env` file:
```env
PORT=4000
MONGODB_URI=mongodb://localhost:27017/mern-auth
JWT_SECRET=your_super_secret_jwt_key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
FRONTEND_URL=http://localhost:5173
```

Run backend:
```bash
npm run server
```

Backend: `http://localhost:4000`

### 3. Frontend Setup

Open new terminal:
```bash
cd frontend
npm install
```

Create frontend `.env` file:
```env
VITE_BACKEND_URL=http://localhost:4000
```

Run frontend:
```bash
npm run dev
```

Frontend: `http://localhost:5173`

## API Endpoints

### Auth (`/api/auth`)
- `POST /register` - User registration
- `POST /login` - User login
- `POST /logout` - User logout
- `POST /send-verify-otp` - Send verification code
- `POST /verify-account` - Verify account
- `POST /send-reset-otp` - Send password reset code
- `POST /verify-reset-otp` - Verify password reset code
- `POST /reset-password` - Reset password
- `POST /is-auth` - Check token validity

### User (`/api/user`)
- `GET /data` - Get user information

## User Schema

```javascript
{
  name: String,
  email: String (unique),
  password: String (hashed),
  verifyOtp: String,
  verifyOtpExpireAt: Number,
  isAccountVerified: Boolean,
  resetOtp: String,
  resetOtpExpireAt: Number
}
```

## Security

- Passwords are hashed with bcrypt
- JWT token authentication
- OTP expires after 10 minutes
- CORS protection
- Environment variables

## Gmail SMTP Setup

1. Google Account → Security
2. Enable 2-Step Verification
3. Create App passwords
4. Use the password as `SMTP_PASS` in `.env` file
