# Secure Auth System — Backend

![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat&logo=node.js&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat&logo=typescript&logoColor=white)
![Express](https://img.shields.io/badge/Express-000000?style=flat&logo=express&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=flat&logo=mongodb&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=flat&logo=jsonwebtokens&logoColor=white)

> REST API for full authentication lifecycle — registration, login, JWT sessions, email verification, and password recovery.

## About

Backend service for the [secure-auth-system](https://github.com/kevinmistrele/secure-auth-system) frontend. Built with Express and TypeScript, it handles all authentication logic including JWT token management, bcrypt password hashing, and transactional email delivery via Nodemailer.

## Features

- User registration with hashed passwords (bcrypt)
- Login with JWT access tokens
- Email verification on sign-up
- Password recovery via email (Nodemailer)
- Protected route middleware
- CORS configured for frontend integration
- MongoDB data persistence with Mongoose

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js + TypeScript |
| Framework | Express |
| Database | MongoDB + Mongoose |
| Auth | JWT + bcrypt |
| Email | Nodemailer |
| Config | dotenv |

## Getting Started

### Prerequisites

- Node.js 18+
- MongoDB instance (local or Atlas)
- SMTP credentials (Gmail App Password or similar)

### Installation

```bash
git clone https://github.com/kevinmistrele/secure-auth-system-backend.git
cd secure-auth-system-backend
npm install
```

### Environment Variables

Create a `.env` file in the root:

```env
PORT=3333
MONGODB_URI=mongodb://localhost:27017/secure-auth
JWT_SECRET=your_jwt_secret
EMAIL_FROM=your@email.com
EMAIL_PASS=your_app_password
CLIENT_URL=http://localhost:5173
```

### Running

```bash
# Development
npm run dev

# Production
npm run start
```

## API Endpoints

| Method | Route | Description |
|---|---|---|
| POST | `/auth/register` | Register new user |
| POST | `/auth/login` | Login and receive JWT |
| GET | `/auth/verify/:token` | Verify email address |
| POST | `/auth/forgot-password` | Send recovery email |
| POST | `/auth/reset-password` | Reset password with token |

## Project Structure

```
src/
├── controllers/    # Route handlers
├── middlewares/    # Auth and error middleware
├── models/         # Mongoose schemas
├── routes/         # Express route definitions
├── services/       # Business logic (email, token)
└── server.ts       # Entry point
```

## Frontend

Pair this API with the [secure-auth-system](https://github.com/kevinmistrele/secure-auth-system) React frontend.

## Author

Made by [Kevin Mistrele](https://github.com/kevinmistrele)
