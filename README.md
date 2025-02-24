# Online Code Execution Platform

A secure, real-time code execution platform with authentication and dark mode support.

## Features

- 🔒 Secure user authentication
- 💻 Multi-language code execution (JavaScript, Python)
- 🌓 Dark/Light mode toggle
- 📝 Code history and submissions
- ⚡ Real-time code execution
- 🔍 Rate limiting and security measures

## Tech Stack

- Frontend:
  - Next.js 13+ (App Router)
  - TailwindCSS
  - Monaco Editor
  - Context API for theme management

- Backend:
  - Node.js & Express
  - SQLite3 for database
  - JWT for authentication
  - VM2 for secure code execution

## Project Structure

```
online-code-platform/
├── frontend/               # Next.js frontend application
│   ├── app/               # App router components
│   ├── components/        # Reusable components
│   └── context/           # Theme context
└── backend/               # Express backend server
    ├── server.js          # Main server file
    └── codeplatform.db    # SQLite database
```

## Getting Started

1. Clone the repository
```bash
git clone <repository-url>
cd online-code-platform
```

2. Install dependencies
```bash
# Install frontend dependencies
cd frontend
npm install

# Install backend dependencies
cd ../backend
npm install
```

3. Set up environment variables:
   - Create `.env.local` in frontend directory
   - Create `.env` in backend directory

4. Run development servers
```bash
# Start backend server
cd backend
npm run dev

# Start frontend development server
cd frontend
npm run dev
```

## Deployment

### Backend Deployment (Render/Railway)

1. Create a new web service
2. Connect your GitHub repository
3. Set environment variables:
   - `PORT`
   - `JWT_SECRET`
   - `DATABASE_PATH`
   - `CORS_ORIGIN`
4. Deploy with build command: `npm install`
5. Start command: `node server.js`

### Frontend Deployment (Vercel/Netlify)

1. Connect your GitHub repository
2. Set environment variables:
   - `NEXT_PUBLIC_API_URL`
3. Deploy with default Next.js settings

## Security Measures

- Rate limiting for API requests
- Secure code execution in isolated environments
- JWT-based authentication
- Input validation and sanitization
- CORS protection
- Code execution timeout limits

## Future Improvements

- [ ] Add more programming languages
- [ ] Implement user profiles
- [ ] Add code sharing functionality
- [ ] Real-time collaboration features
- [ ] Advanced code analytics
