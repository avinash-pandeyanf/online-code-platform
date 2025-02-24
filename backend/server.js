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
const app = express();
const port = process.env.PORT || 3001;

app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://onlinecodeplat.netlify.app/',
    process.env.CORS_ORIGIN
  ].filter(Boolean),
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
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

// Rate limiting
const rateLimit = {};

// Authentication Middleware
const authenticate = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized' });
    req.userId = decoded.id;

    // Implement rate limiting
    if (!rateLimit[req.userId]) {
      rateLimit[req.userId] = {
        count: 1,
        firstRequest: Date.now()
      };
    } else {
      // Reset counter after 1 hour
      if (Date.now() - rateLimit[req.userId].firstRequest > 3600000) {
        rateLimit[req.userId] = {
          count: 1,
          firstRequest: Date.now()
        };
      } else if (rateLimit[req.userId].count >= 100) {
        return res.status(429).json({ message: 'Too many requests' });
      }
      rateLimit[req.userId].count++;
    }

    next();
  });
};

// Login Endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!user) {
      db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], function(err) {
        if (err) return res.status(500).json({ message: 'Error creating user' });
        const token = jwt.sign({ id: this.lastID }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
      });
    } else {
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    }
  });
});

// Execute code in a safe environment
const executeCode = async (code, language) => {
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