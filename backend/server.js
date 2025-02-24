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

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {andling
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
  } catch (err) {CT * FROM users WHERE username = ?', [username], (err, row) => {
    console.error('Authentication error:', err);
    return res.status(500).json({ r('Database error:', err);
      message: 'Server error during authentication', reject(err);
      error: err.message 
    });esolve(row);
  });
};    });

// Login Endpoint with password hashing
app.post('/login', async (req, res) => {
  console.log('Login request received:', req.body); // Add logging hashedPassword = await bcrypt.hash(password, 10);
  const { username, password } = req.body;
  
  if (!username || !password) {password) VALUES (?, ?)', 
    return res.status(400).json({ message: 'Username and password required' });Password], 
  }{

  try {'User creation error:', err);
    const user = await new Promise((resolve, reject) => {eject(err);
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {olve(this.lastID);
          console.error('Database error:', err); // Add logging
          reject(err););
        }
        resolve(row);
      });
    });
ocess.env.JWT_SECRET,
    if (!user) {
      // New user registration
      const hashedPassword = await bcrypt.hash(password, 12);
      try {
        const result = await new Promise((resolve, reject) => {eturn res.status(201).json({ 
          db.run('INSERT INTO users (username, password) VALUES (?, ?)', n,
            [username, hashedPassword], ed successfully' 
            function(err) {
              if (err) {
                console.error('User creation error:', err); // Add logging
                reject(err);
              } isValidPassword = await bcrypt.compare(password, user.password);
              resolve(this.lastID);!isValidPassword) {
            });word attempt');
        });1).json({ message: 'Invalid credentials' });
        
        const token = jwt.sign(
          { id: result },token = jwt.sign(
          process.env.JWT_SECRET,
          { expiresIn: '1h', algorithm: 'HS256' }_SECRET,
        );
        return res.status(201).json({ token });
      } catch (err) {
        console.error('Registration error:', err); // Add loggingonsole.log('User logged in successfully');
        return res.status(500).json({ message: 'Error creating user' });atus(200).json({ token });
      }
    } else {
      // Existing user login console.error('Server error during login:', err);
      try { return res.status(500).json({ 
        const isValid = await bcrypt.compare(password, user.password);      message: 'Server error during authentication',
        if (!isValid) {
          return res.status(401).json({ message: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
          { id: user.id },Execute code in a safe environment
          process.env.JWT_SECRET,const executeCode = async (code, language) => {
          { expiresIn: '1h', algorithm: 'HS256' }
        );
        return res.status(200).json({ token }); throw new Error('Invalid code input');
      } catch (err) {  }
        console.error('Password comparison error:', err); // Add logging
        return res.status(500).json({ message: 'Server error during authentication' });
      }    throw new Error('Unsupported language');
    }
  } catch (err) {
    console.error('Login error:', err); // Add logginge
    return res.status(500).json({ message: 'Server error' });  code = code.replace(/[^a-zA-Z0-9\s+\-*/=><{}\[\]().,;:'"!?]/g, '');
  }
});w();

// Execute code in a safe environment
const executeCode = async (code, language) => {
  // Input validation
  if (!code || typeof code !== 'string') {) {
    throw new Error('Invalid code input');
  }ode, {}, { timeout: 5000 });

  if (!['javascript', 'python'].includes(language)) {
    throw new Error('Unsupported language');
  }py`);
iteFileSync(pythonFile, code);
  // Sanitize codest pythonResult = await new Promise((resolve) => {
          exec(`python ${pythonFile}`, { timeout: 5000 }, (err, stdout, stderr) => {\-*/=><{}\[\]().,;:'"!?]/g, '');
            fs.unlinkSync(pythonFile);
            resolve({ stdout, stderr: err ? err.message : stderr });= Date.now();
          });
        });'';
        output = pythonResult.stdout;
        error = pythonResult.stderr; {
        break;age) {
      // Add other language cases as needed
      default:     const result = vm.runInNewContext(code, {}, { timeout: 5000 });
        throw new Error('Unsupported language');        output = result !== undefined ? String(result) : '';
    }eak;
  } catch (err) {
    error = err.message || 'Execution error';e = path.join(__dirname, `temp_${Date.now()}.py`);
  }code);
    const pythonResult = await new Promise((resolve) => {
  return {        exec(`python ${pythonFile}`, { timeout: 5000 }, (err, stdout, stderr) => {
    output: output || '',            fs.unlinkSync(pythonFile);
    error: error || '',({ stdout, stderr: err ? err.message : stderr });
    executionTime: Date.now() - start
  };
};        output = pythonResult.stdout;
.stderr;
// Execute Endpoint
app.post('/execute', authenticate, async (req, res) => {   // Add other language cases as needed
  const { code, language } = req.body;      default:

  if (code.length > 10000) {  }
    return res.status(400).json({ message: 'Code too long' });ch (err) {
  }

  const codeHash = crypto.createHash('md5').update(code).digest('hex');
  
  try {    output: output || '',
    const result = await executeCode(code, language);error || '',
    const fingerprint = crypto.createHash('md5')
      .update(req.userId + code + Date.now())
      .digest('hex');

    db.run(
      'INSERT INTO submissions (userId, code, language, output, error, executionTime, hash, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',t('/execute', authenticate, async (req, res) => {
      [req.userId, code, language, result.output, result.error, result.executionTime, codeHash, fingerprint],t { code, language } = req.body;
      (err) => {
        if (err) console.error('Error saving submission:', err);
        res.json(result); return res.status(400).json({ message: 'Code too long' });
      }
    );
  } catch (err) {to.createHash('md5').update(code).digest('hex');
    res.status(500).json({ message: 'Execution failed', error: err.message });
  }
});
nt = crypto.createHash('md5')
// Submissions Endpoint .update(req.userId + code + Date.now())
app.get('/submissions', authenticate, (req, res) => {   .digest('hex');
  db.all('SELECT * FROM submissions WHERE userId = ? ORDER BY createdAt DESC', [req.userId], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    res.json(rows);(userId, code, language, output, error, executionTime, hash, fingerprint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  });   [req.userId, code, language, result.output, result.error, result.executionTime, codeHash, fingerprint],
});      (err) => {
.error('Error saving submission:', err);
app.get('/', (req, res) => {
  res.send('Backend running!');   }





});  console.log(`Server running on http://localhost:${port}`);app.listen(port, () => {});    );
  } catch (err) {
    res.status(500).json({ message: 'Execution failed', error: err.message });
  }
});











});  console.log(`Server running on http://localhost:${port}`);app.listen(port, () => {});  res.send('Backend running!');app.get('/', (req, res) => {});  });    res.json(rows);
// Submissions Endpoint
app.get('/submissions', authenticate, (req, res) => {
  db.all('SELECT * FROM submissions WHERE userId = ? ORDER BY createdAt DESC', [req.userId], (err, rows) => {
    if (err) return res.status(500).json({ message: 'Database error' });