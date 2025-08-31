const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');

const app = express();
const db = new sqlite3.Database('./patients.db');

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));


require('dotenv').config();
const session_secret = process.env.SESSION_SECRET || 'smile-hub-secret-key-2025';

// Session configuration
app.use(session({
  secret: 'smile-hub-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Initialize database tables with user_id for multi-tenancy
db.serialize(() => {
  // Users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      fullName TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Patients table with user_id for data isolation
  db.run(`
    CREATE TABLE IF NOT EXISTS patients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      contactNo TEXT NOT NULL,
      email TEXT,
      patientDescription TEXT,
      treatmentStart TEXT NOT NULL,
      totalFee REAL DEFAULT 0,
      paidFees REAL DEFAULT 0,
      patientType TEXT,
      user_id INTEGER NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `);

  // Create default admin user if doesn't exist
  db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, user) => {
    if (!user) {
      const hashedPassword = bcrypt.hashSync('admin123', 10);
      db.run('INSERT INTO users (username, password, fullName) VALUES (?, ?, ?)', 
        ['admin', hashedPassword, 'System Administrator'], 
        (err) => {
          if (!err) {
            console.log('Default admin user created: admin/admin123');
          }
        }
      );
    }
  });

  // Create sample user "tanuj" if doesn't exist
  db.get('SELECT * FROM users WHERE username = ?', ['tanuj'], (err, user) => {
    if (!user) {
      const hashedPassword = bcrypt.hashSync('tanuj123', 10);
      db.run('INSERT INTO users (username, password, fullName) VALUES (?, ?, ?)', 
        ['tanuj', hashedPassword, 'Tanuj Pavan'], 
        (err) => {
          if (!err) {
            console.log('Sample user created: tanuj/tanuj123');
          }
        }
      );
    }
  });
});

// Passport Local Strategy
passport.use(new LocalStrategy((username, password, done) => {
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    
    if (!bcrypt.compareSync(password, user.password)) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    
    return done(null, user);
  });
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
    done(err, user);
  });
});

// Authentication middleware
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'Authentication required' });
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'home.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Authentication Routes
app.post('/auth/login', passport.authenticate('local'), (req, res) => {
  res.json({ 
    success: true, 
    message: 'Login successful',
    user: { id: req.user.id, username: req.user.username, fullName: req.user.fullName }
  });
});

app.post('/auth/register', async (req, res) => {
  const { username, password, email, fullName } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, existingUser) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (existingUser) return res.status(400).json({ error: 'Username already exists' });

      const hashedPassword = bcrypt.hashSync(password, 10);
      db.run('INSERT INTO users (username, password, email, fullName) VALUES (?, ?, ?, ?)', 
        [username, hashedPassword, email, fullName], 
        function(err) {
          if (err) return res.status(500).json({ error: 'Failed to create user' });
          res.json({ success: true, message: 'User registered successfully' });
        }
      );
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.json({ success: true, message: 'Logged out successfully' });
  });
});

app.get('/auth/user', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ 
      authenticated: true, 
      user: { id: req.user.id, username: req.user.username, fullName: req.user.fullName }
    });
  } else {
    res.json({ authenticated: false });
  }
});

// Patient validation function
function validatePatient(body, isCreate = true) {
  const errors = [];
  
  if (isCreate && (!body.name || !body.name.trim())) {
    errors.push('Name is required');
  }
  
  if (isCreate && (!body.contactNo || !/^[6-9][0-9]{9}$/.test(body.contactNo))) {
    errors.push('Mobile number must be exactly 10 digits starting with 6, 7, 8, or 9');
  }
  
  if (isCreate && (!body.treatmentStart)) {
    errors.push('Treatment start date is required');
  }
  
  if (body.treatmentStart) {
    const selectedDate = new Date(body.treatmentStart);
    const today = new Date();
    const threeYearsAgo = new Date(today.getFullYear() - 3, today.getMonth(), today.getDate());
    
    if (selectedDate < threeYearsAgo || selectedDate > today) {
      errors.push('Treatment start date must be within the last 3 years');
    }
  }
  
  const totalFee = Number(body.totalFee ?? 0);
  const paidFees = Number(body.paidFees ?? 0);
  
  if (Number.isNaN(totalFee) || totalFee < 0) {
    errors.push('Total fee must be >= 0');
  }
  if (Number.isNaN(paidFees) || paidFees < 0) {
    errors.push('Paid fees must be >= 0');
  }
  if (paidFees > totalFee) {
    errors.push('Paid fees cannot exceed total fee');
  }
  
  return errors;
}

// USER-SPECIFIC Protected Patient Routes - Each user sees only their own data
app.get('/api/patients', ensureAuthenticated, (req, res) => {
  const userId = req.user.id;
  db.all('SELECT * FROM patients WHERE user_id = ? ORDER BY id DESC', [userId], (err, rows) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.get('/api/patients/:id', ensureAuthenticated, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT * FROM patients WHERE id = ? AND user_id = ?', [req.params.id, userId], (err, row) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!row) return res.status(404).json({ error: 'Patient not found' });
    res.json(row);
  });
});

app.post('/api/patients', ensureAuthenticated, (req, res) => {
  console.log('Received patient data:', req.body);
  
  const errors = validatePatient(req.body, true);
  if (errors.length) {
    console.log('Validation errors:', errors);
    return res.status(400).json({ errors });
  }

  const userId = req.user.id;
  const {
    name,
    contactNo,
    email = null,
    patientDescription = null,
    treatmentStart,
    totalFee = 0,
    paidFees = 0,
    patientType = null
  } = req.body;

  const sql = `
    INSERT INTO patients (name, contactNo, email, patientDescription, treatmentStart, totalFee, paidFees, patientType, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  
  const params = [
    name.trim(),
    contactNo,
    email,
    patientDescription,
    treatmentStart,
    Number(totalFee),
    Number(paidFees),
    patientType,
    userId
  ];

  db.run(sql, params, function (err) {
    if (err) {
      console.error('Insert error:', err);
      return res.status(500).json({ error: 'Database insert error: ' + err.message });
    }
    
    db.get('SELECT * FROM patients WHERE id = ?', [this.lastID], (e, row) => {
      if (e) {
        console.error('Fetch error:', e);
        return res.status(500).json({ error: 'Database fetch error' });
      }
      console.log('Patient created:', row);
      res.status(201).json(row);
    });
  });
});

app.put('/api/patients/:id', ensureAuthenticated, (req, res) => {
  const errors = validatePatient(req.body, false);
  if (errors.length) return res.status(400).json({ errors });

  const userId = req.user.id;
  db.get('SELECT * FROM patients WHERE id = ? AND user_id = ?', [req.params.id, userId], (err, existing) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!existing) return res.status(404).json({ error: 'Patient not found' });

    const merged = {
      name: req.body.name ?? existing.name,
      contactNo: req.body.contactNo ?? existing.contactNo,
      email: req.body.email ?? existing.email,
      patientDescription: req.body.patientDescription ?? existing.patientDescription,
      treatmentStart: req.body.treatmentStart ?? existing.treatmentStart,
      totalFee: Number(req.body.totalFee ?? existing.totalFee),
      paidFees: Number(req.body.paidFees ?? existing.paidFees),
      patientType: req.body.patientType ?? existing.patientType
    };

    const sql = `
      UPDATE patients
      SET name = ?, contactNo = ?, email = ?, patientDescription = ?,
          treatmentStart = ?, totalFee = ?, paidFees = ?, patientType = ?,
          updatedAt = CURRENT_TIMESTAMP
      WHERE id = ? AND user_id = ?
    `;
    
    const params = [
      merged.name, merged.contactNo, merged.email, merged.patientDescription,
      merged.treatmentStart, merged.totalFee, merged.paidFees,
      merged.patientType, req.params.id, userId
    ];
    
    db.run(sql, params, function (e2) {
      if (e2) {
        console.error('Update error:', e2);
        return res.status(500).json({ error: 'Database update error' });
      }
      
      db.get('SELECT * FROM patients WHERE id = ? AND user_id = ?', [req.params.id, userId], (e3, row) => {
        if (e3) {
          console.error('Fetch error:', e3);
          return res.status(500).json({ error: 'Database fetch error' });
        }
        res.json(row);
      });
    });
  });
});

app.delete('/api/patients/:id', ensureAuthenticated, (req, res) => {
  const userId = req.user.id;
  db.run('DELETE FROM patients WHERE id = ? AND user_id = ?', [req.params.id, userId], function (err) {
    if (err) {
      console.error('Delete error:', err);
      return res.status(500).json({ error: 'Database delete error' });
    }
    if (this.changes === 0) return res.status(404).json({ error: 'Patient not found' });
    console.log('Patient deleted, id:', req.params.id);
    res.status(204).send();
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Smile Hub server running on port ${PORT}`);
  console.log(`📱 Visit: http://localhost:${PORT}`);
});

