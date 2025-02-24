require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { exec } = require('child_process');
const vm = require('vm');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const xss = require('xss-clean');
const helmet = require('helmet');
const app = express();
const port = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(xss());
app.set('trust proxy', 1);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/login', limiter);

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN.split(','),
  credentials: true,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Authorization'],
  maxAge: 600 // 10 minutes
}));
app.use(bodyParser.json());

// SQLite Database Setup
const db = new sqlite3.Database(process.env.DATABASE_PATH || './codeplatform.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to SQLite database');
  }
});

// Create tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    code TEXT,
    language TEXT,
    output TEXT,
    error TEXT,
    executionTime INTEGER,
    hash TEXT,
    fingerprint TEXT,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (userId) REFERENCES users(id)
  )`);

  db.run(`CREATE INDEX IF NOT EXISTS idx_submissions_userId ON submissions(userId)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_submissions_hash ON submissions(hash)`);
});

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized' });
    req.userId = decoded.id;

    next();
  });
};

// Login Endpoint with password hashing
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!user) {
      const hashedPassword = await bcrypt.hash(password, 12);
      const result = await new Promise((resolve, reject) => {
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
          [username, hashedPassword], 
          function(err) {
            if (err) reject(err);
            resolve(this.lastID);
          });
      });
      
      const token = jwt.sign(
        { id: result },
        process.env.JWT_SECRET,
        { expiresIn: '1h', algorithm: 'HS256' }
      );
      res.json({ token });
    } else {
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      const token = jwt.sign(
        { id: user.id },
        process.env.JWT_SECRET,
        { expiresIn: '1h', algorithm: 'HS256' }
      );
      res.json({ token });
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Execute code in a safe environment
const executeCode = async (code, language) => {
  // Input validation
  if (!code || typeof code !== 'string') {
    throw new Error('Invalid code input');
  }

  if (!['javascript', 'python'].includes(language)) {
    throw new Error('Unsupported language');
  }

  // Sanitize code
  code = code.replace(/[^a-zA-Z0-9\s+\-*/=><{}\[\]().,;:'"!?]/g, '');

  const start = Date.now();
  let output = '';
  let error = '';

  try {
    switch (language) {
      case 'javascript':
        const result = vm.runInNewContext(code, {}, { timeout: 5000 });
        output = result !== undefined ? String(result) : '';
        break;
      case 'python':
        const pythonFile = path.join(__dirname, `temp_${Date.now()}.py`);
        fs.writeFileSync(pythonFile, code);
        const pythonResult = await new Promise((resolve) => {
          exec(`python ${pythonFile}`, { timeout: 5000 }, (err, stdout, stderr) => {
            fs.unlinkSync(pythonFile);
            resolve({ stdout, stderr: err ? err.message : stderr });
          });
        });
        output = pythonResult.stdout;
        error = pythonResult.stderr;
        break;
      // Add other language cases as needed
      default:
        throw new Error('Unsupported language');
    }
  } catch (err) {
    error = err.message || 'Execution error';
  }

  return {
    output: output || '',
    error: error || '',
    executionTime: Date.now() - start
  };
};

// Execute Endpoint
app.post('/execute', authenticate, async (req, res) => {
  const { code, language } = req.body;

  if (code.length > 10000) {
    return res.status(400).json({ message: 'Code too long' });
  }

  const codeHash = crypto.createHash('md5').update(code).digest('hex');
  
  try {
    const result = await executeCode(code, language);
    const fingerprint = crypto.createHash('md5')
      .update(req.userId + code + Date.now())
      .digest('hex');

    db.run(
      'INSERT INTO submissions (userId, code, language, output, error, executionTime, hash, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [req.userId, code, language, result.output, result.error, result.executionTime, codeHash, fingerprint],
      (err) => {
        if (err) console.error('Error saving submission:', err);
        res.json(result);
      }
    );
  } catch (err) {
    res.status(500).json({ message: 'Execution failed', error: err.message });
  }
});

// Submissions Endpoint
app.get('/submissions', authenticate, (req, res) => {
  db.all('SELECT * FROM submissions WHERE userId = ? ORDER BY createdAt DESC', [req.userId], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(rows);
  });
});

app.get('/', (req, res) => {
  res.send('Backend running!');
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});