const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
require('dotenv').config();

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));

const session_secret = process.env.SESSION_SECRET || 'smile-hub-secret-key-2025';

app.use(session({
  secret: session_secret,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

async function queryDB(text, params) {
  return pool.query(text, params);
}

// -------------------------------
// Database Setup (run once)
// -------------------------------
async function initDB() {
  await queryDB(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      email VARCHAR(255),
      fullName VARCHAR(255),
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);
  await queryDB(`
    CREATE TABLE IF NOT EXISTS patients (
      id SERIAL PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      contactNo VARCHAR(20),
      email VARCHAR(255),
      patientDescription TEXT,
      treatmentStart DATE,
      totalFee NUMERIC(10,2) DEFAULT 0,
      paidFees NUMERIC(10,2) DEFAULT 0,
      patientType VARCHAR(100),
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`);
  // Create admin user (if needed)
  const { rowCount } = await queryDB('SELECT 1 FROM users WHERE username=$1', ['admin']);
  if (!rowCount) {
    const hp = bcrypt.hashSync('admin123', 10);
    await queryDB('INSERT INTO users (username, password, fullName) VALUES ($1, $2, $3)', ['admin', hp, 'System Administrator']);
    console.log('Default admin user created');
  }
  // Optionally: create sample user
  const { rowCount: tanujCount } = await queryDB('SELECT 1 FROM users WHERE username=$1', ['tanuj']);
  if (!tanujCount) {
    const hp = bcrypt.hashSync('tanuj123', 10);
    await queryDB('INSERT INTO users (username, password, fullName) VALUES ($1, $2, $3)', ['tanuj', hp, 'Tanuj Pavan']);
  }
}
initDB();

// -------------------------------
// Passport Auth
// -------------------------------
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const res = await queryDB('SELECT * FROM users WHERE username = $1', [username]);
    const user = res.rows[0];
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    if (!bcrypt.compareSync(password, user.password))
      return done(null, false, { message: 'Incorrect password.' });
    return done(null, user);
  } catch (err) { return done(err); }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const res = await queryDB('SELECT * FROM users WHERE id = $1', [id]);
    done(null, res.rows[0] || null);
  } catch (err) { done(err, null); }
});
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Authentication required' });
}

// --------------------------
// Routes
// --------------------------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'home.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

// Auth
app.post('/auth/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(400).json({ success: false, message: info.message });
    req.logIn(user, err => {
      if (err) return next(err);
      res.json({ success: true, user: { id: user.id, username: user.username, fullName: user.fullName } });
    });
  })(req, res, next);
});
app.post('/auth/register', async (req, res) => {
  const { username, password, email, fullName } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password are required' });
  // Check duplicate
  const check = await queryDB('SELECT 1 FROM users WHERE username = $1', [username]);
  if (check.rowCount) return res.status(400).json({ error: 'Username already exists' });
  const hp = bcrypt.hashSync(password, 10);
  await queryDB('INSERT INTO users (username, password, email, fullName) VALUES ($1, $2, $3, $4)', [username, hp, email, fullName]);
  res.json({ success: true, message: 'User registered successfully' });
});
app.post('/auth/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    res.json({ success: true, message: 'Logged out successfully' });
  });
});
app.get('/auth/user', (req, res) => {
  if (req.isAuthenticated()) {
    const { id, username, fullName } = req.user;
    res.json({ authenticated: true, user: { id, username, fullName } });
  } else {
    res.json({ authenticated: false });
  }
});

// Patients --------------------------------------------------------------
function validatePatient(body, isCreate = true) {
  const errors = [];
  if (isCreate && (!body.name || !body.name.trim())) errors.push('Name is required');
  if (isCreate && (!body.contactNo || !/^[6-9][0-9]{9}$/.test(body.contactNo)))
    errors.push('Mobile number must be exactly 10 digits starting with 6, 7, 8, or 9');
  if (isCreate && !body.treatmentStart) errors.push('Treatment start date is required');
  if (body.treatmentStart) {
    const d = new Date(body.treatmentStart), t = new Date(), y3 = new Date(t.getFullYear() - 3, t.getMonth(), t.getDate());
    if (d < y3 || d > t) errors.push('Treatment start date must be within the last 3 years');
  }
  const totalFee = Number(body.totalFee ?? 0), paidFees = Number(body.paidFees ?? 0);
  if (Number.isNaN(totalFee) || totalFee < 0) errors.push('Total fee must be >= 0');
  if (Number.isNaN(paidFees) || paidFees < 0) errors.push('Paid fees must be >= 0');
  if (paidFees > totalFee) errors.push('Paid fees cannot exceed total fee');
  return errors;
}

// GET ALL PATIENTS FOR AUTHENTICATED USER
app.get('/api/patients', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const result = await queryDB('SELECT * FROM patients WHERE user_id = $1 ORDER BY id DESC', [userId]);
    res.json(result.rows);
  } catch (err) {
    console.error('DB error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/patients/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const result = await queryDB('SELECT * FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Patient not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.post('/api/patients', ensureAuthenticated, async (req, res) => {
  const errors = validatePatient(req.body, true);
  if (errors.length) return res.status(400).json({ errors });
  try {
    const { id: userId } = req.user;
    const {
      name, contactNo, email = null, patientDescription = null, treatmentStart,
      totalFee = 0, paidFees = 0, patientType = null
    } = req.body;
    const result = await queryDB(
      `INSERT INTO patients (name, contactNo, email, patientDescription, treatmentStart, totalFee, paidFees, patientType, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [name.trim(), contactNo, email, patientDescription, treatmentStart, Number(totalFee), Number(paidFees), patientType, userId]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Insert error:', err);
    res.status(500).json({ error: 'Database insert error: ' + err.message });
  }
});

app.put('/api/patients/:id', ensureAuthenticated, async (req, res) => {
  const errors = validatePatient(req.body, false);
  if (errors.length) return res.status(400).json({ errors });
  try {
    const { id: userId } = req.user;
    const getResult = await queryDB('SELECT * FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    if (!getResult.rows.length) return res.status(404).json({ error: 'Patient not found' });
    const existing = getResult.rows[0];
    const merged = {
      name: req.body.name ?? existing.name,
      contactNo: req.body.contactno ?? existing.contactno,
      email: req.body.email ?? existing.email,
      patientDescription: req.body.patientdescription ?? existing.patientdescription,
      treatmentStart: req.body.treatmentstart ?? existing.treatmentstart,
      totalFee: Number(req.body.totalfee ?? existing.totalfee),
      paidFees: Number(req.body.paidfees ?? existing.paidfees),
      patientType: req.body.patienttype ?? existing.patienttype
    };
    await queryDB(
      `UPDATE patients SET name = $1, contactNo = $2, email = $3, patientDescription = $4,
        treatmentStart = $5, totalFee = $6, paidFees = $7, patientType = $8, updatedAt = CURRENT_TIMESTAMP
        WHERE id = $9 AND user_id = $10`,
      [merged.name, merged.contactNo, merged.email, merged.patientDescription,
        merged.treatmentStart, merged.totalFee, merged.paidFees, merged.patientType, req.params.id, userId]
    );
    const updated = await queryDB('SELECT * FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    res.json(updated.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Database update error' });
  }
});

app.delete('/api/patients/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const result = await queryDB('DELETE FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Patient not found' });
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: 'Database delete error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Smile Hub server running on port ${PORT}`);
});
