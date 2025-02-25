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

// CORS configuration - before other middleware
app.use(cors({
  origin: ['https://onlinecodeplat.netlify.app', 'http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  exposedHeaders: ['Authorization'],
  preflightContinue: false,
  optionsSuccessStatus: 204
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
  try {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
      return res.status(401).json({ message: 'Authorization header missing' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Token missing' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error('Token verification error:', err);
        return res.status(401).json({ 
          message: 'Invalid or expired token',
          error: err.message 
        });
      }
      
      req.userId = decoded.id;
      next();
    });
  } catch (err) {
    console.error('Authentication error:', err);
    return res.status(500).json({ 
      message: 'Server error during authentication',
      error: err.message 
    });
  }
};

// Login Endpoint with password hashing
app.post('/login', async (req, res) => {
  console.log('Login request received:', req.body);
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    // Check if user exists
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!user) {
      // Create new user
      const hashedPassword = await bcrypt.hash(password, 12);
      const result = await new Promise((resolve, reject) => {
        db.run('INSERT INTO users (username, password) VALUES (?, ?)', 
          [username, hashedPassword], 
          function(err) {
            if (err) reject(err);
            resolve(this.lastID);
          }
        );
      });

      const token = jwt.sign(
        { id: result },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      return res.status(201).json({ token });
    } else {
      // Login existing user
      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { id: user.id },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
      );
      return res.status(200).json({ token });
    }
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Execute code in a safe environment
const executeCode = async (code, language) => {
  // Input validation
  if (!code || typeof code !== 'string') {
    throw new Error('Invalid code input');
  }

  if (!['javascript', 'python', 'java', 'cpp', 'ruby'].includes(language)) {
    throw new Error('Unsupported language');
  }

  // Sanitize code
  code = code.replace(/[^a-zA-Z0-9\s+\-*/=><{}\[\]().,;:'"!?]/g, '');

  let output = '';
  let error = '';

  try {
    switch (language) {
      case 'javascript':
        let consoleOutput = [];
        const context = {
          console: {
            log: (...args) => {
              consoleOutput.push(args.map(arg => String(arg)).join(' '));
            },
            error: (...args) => {
              consoleOutput.push('Error: ' + args.map(arg => String(arg)).join(' '));
            },
            warn: (...args) => {
              consoleOutput.push('Warning: ' + args.map(arg => String(arg)).join(' '));
            }
          },
          setTimeout: (cb, ms) => {
            if (ms > 5000) throw new Error('Timeout too long');
            cb();
          },
          setInterval: () => {
            throw new Error('setInterval is not allowed');
          }
        };
        
        const result = vm.runInNewContext(code, context, { 
          timeout: 5000,
          displayErrors: true
        });
        
        output = consoleOutput.join('\n');
        if (result !== undefined && !output) {
          output = String(result);
        }
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

      case 'java':
        const javaFile = path.join(__dirname, `Main_${Date.now()}.java`);
        const javaCode = `
          public class Main_${Date.now()} {
            public static void main(String[] args) {
              ${code}
            }
          }`;
        fs.writeFileSync(javaFile, javaCode);
        try {
          await new Promise((resolve, reject) => {
            exec(`javac "${javaFile}"`, { timeout: 5000 }, (err, stdout, stderr) => {
              if (err) reject(new Error(stderr));
              resolve(stdout);
            });
          });
          const javaResult = await new Promise((resolve) => {
            exec(`java -cp "${path.dirname(javaFile)}" Main_${Date.now()}`, 
              { timeout: 5000 }, 
              (err, stdout, stderr) => {
                resolve({ stdout, stderr: err ? err.message : stderr });
            });
          });
          output = javaResult.stdout;
          error = javaResult.stderr;
        } finally {
          fs.unlinkSync(javaFile);
          fs.unlinkSync(javaFile.replace('.java', '.class'));
        }
        break;

      case 'cpp':
        const cppFile = path.join(__dirname, `temp_${Date.now()}.cpp`);
        const exeFile = path.join(__dirname, `temp_${Date.now()}.exe`);
        const cppCode = `
          #include <iostream>
          int main() {
            ${code}
            return 0;
          }`;
        fs.writeFileSync(cppFile, cppCode);
        try {
          await new Promise((resolve, reject) => {
            exec(`g++ "${cppFile}" -o "${exeFile}"`, { timeout: 5000 }, (err, stdout, stderr) => {
              if (err) reject(new Error(stderr));
              resolve(stdout);
            });
          });
          const cppResult = await new Promise((resolve) => {
            exec(exeFile, { timeout: 5000 }, (err, stdout, stderr) => {
              resolve({ stdout, stderr: err ? err.message : stderr });
            });
          });
          output = cppResult.stdout;
          error = cppResult.stderr;
        } finally {
          fs.unlinkSync(cppFile);
          if (fs.existsSync(exeFile)) fs.unlinkSync(exeFile);
        }
        break;

      case 'ruby':
        const rubyFile = path.join(__dirname, `temp_${Date.now()}.rb`);
        fs.writeFileSync(rubyFile, code);
        const rubyResult = await new Promise((resolve) => {
          exec(`ruby "${rubyFile}"`, { timeout: 5000 }, (err, stdout, stderr) => {
            fs.unlinkSync(rubyFile);
            resolve({ stdout, stderr: err ? err.message : stderr });
          });
        });
        output = rubyResult.stdout;
        error = rubyResult.stderr;
        break;
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