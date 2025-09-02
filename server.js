const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
const pgSession = require('connect-pg-simple')(session);
require('dotenv').config();

const app = express();

// CRITICAL: Trust proxy settings (essential for Render/Heroku)
app.set('trust proxy', 1);

// Enhanced PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// FIXED: CORS configuration with proper credentials
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://smile-hub.onrender.com'] 
    : ['http://localhost:3000', 'http://localhost:5000'],
  credentials: true, // Essential for cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));

const session_secret = process.env.SESSION_SECRET || 'smile-hub-secret-key-2025';

// FIXED: Session configuration for production
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'user_sessions'
  }),
  secret: session_secret,
  resave: false,
  saveUninitialized: false, // Only save when modified
  rolling: true, // Reset expiry on activity
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
    httpOnly: true, // Prevent XSS
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' // Cross-origin in prod
    // DON'T set domain - let browser handle it
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// Database query helper
async function queryDB(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Database initialization
async function initDB() {
  try {
    console.log('Initializing database tables...');
    
    // Create user_sessions table
    await queryDB(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        sid VARCHAR NOT NULL,
        sess JSON NOT NULL,
        expire TIMESTAMP(6) NOT NULL
      );
    `);
    
    // Check and add primary key
    const pkCheck = await queryDB(`
      SELECT constraint_name 
      FROM information_schema.table_constraints 
      WHERE table_name = 'user_sessions' 
      AND constraint_type = 'PRIMARY KEY'
    `);
    
    if (pkCheck.rows.length === 0) {
      await queryDB(`ALTER TABLE user_sessions ADD CONSTRAINT session_pkey PRIMARY KEY (sid);`);
    }
    
    await queryDB(`CREATE INDEX IF NOT EXISTS idx_session_expire ON user_sessions (expire);`);
    
    // Users table
    await queryDB(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        email VARCHAR(255),
        fullName VARCHAR(255),
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
      
    // Patients table
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
      );
    `);
      
    // Create admin user
    const { rowCount } = await queryDB('SELECT 1 FROM users WHERE username=$1', ['admin']);
    if (!rowCount) {
      const hp = bcrypt.hashSync('admin123', 10);
      await queryDB('INSERT INTO users (username, password, fullName) VALUES ($1, $2, $3)', ['admin', hp, 'System Administrator']);
      console.log('✅ Default admin user created');
    }
    
    console.log('✅ Database initialization completed');
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    if (!error.message.includes('multiple primary keys')) {
      process.exit(1);
    }
  }
}
initDB();

// FIXED: Passport configuration
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const res = await queryDB('SELECT * FROM users WHERE username = $1', [username]);
    const user = res.rows[0];
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    if (!bcrypt.compareSync(password, user.password))
      return done(null, false, { message: 'Incorrect password.' });
    console.log('✅ User authenticated:', user.username);
    return done(null, user);
  } catch (err) { 
    console.error('❌ Auth error:', err);
    return done(err); 
  }
}));

passport.serializeUser((user, done) => {
  console.log('🔐 Serializing user:', user.id, user.username);
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    console.log('🔓 Deserializing user ID:', id);
    const res = await queryDB('SELECT * FROM users WHERE id = $1', [id]);
    const user = res.rows[0];
    console.log('👤 Deserialized user:', user ? user.username : 'not found');
    done(null, user || null);
  } catch (err) { 
    console.error('❌ Deserialize error:', err);
    done(err, null); 
  }
});

function ensureAuthenticated(req, res, next) {
  console.log('🛡️ Auth check - authenticated:', req.isAuthenticated(), 'user:', req.user?.username);
  console.log('🍪 Session ID:', req.sessionID);
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Authentication required' });
}

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'home.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/patient.html', (req, res) => res.sendFile(path.join(__dirname, 'patient.html')));

// Debug session endpoint
app.get('/api/debug-session', (req, res) => {
  res.json({
    sessionID: req.sessionID,
    authenticated: req.isAuthenticated(),
    user: req.user,
    cookies: req.headers.cookie,
    session: {
      passport: req.session.passport,
      cookie: req.session.cookie
    }
  });
});

// FIXED: Auth routes with proper session handling
app.post('/auth/login', (req, res, next) => {
  console.log('🔑 Login attempt for:', req.body.username);
  console.log('🍪 Session before login:', req.sessionID);
  
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('❌ Auth error:', err);
      return next(err);
    }
    if (!user) {
      console.log('❌ Login failed:', info.message);
      return res.status(400).json({ success: false, message: info.message });
    }
    
    req.logIn(user, err => {
      if (err) {
        console.error('❌ Login error:', err);
        return next(err);
      }
      
      // CRITICAL: Save session before responding
      req.session.save((err) => {
        if (err) {
          console.error('❌ Session save error:', err);
          return next(err);
        }
        console.log('✅ User logged in and session saved:', user.username);
        console.log('🍪 Session after login:', req.sessionID);
        res.json({ 
          success: true, 
          user: { 
            id: user.id, 
            username: user.username, 
            fullName: user.fullName 
          } 
        });
      });
    });
  })(req, res, next);
});

app.post('/auth/register', async (req, res) => {
  try {
    const { username, password, email, fullName } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password are required' });
    
    const check = await queryDB('SELECT 1 FROM users WHERE username = $1', [username]);
    if (check.rowCount) return res.status(400).json({ error: 'Username already exists' });
    
    const hp = bcrypt.hashSync(password, 10);
    await queryDB('INSERT INTO users (username, password, email, fullName) VALUES ($1, $2, $3, $4)', [username, hp, email, fullName]);
    res.json({ success: true, message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed due to server error' });
  }
});

app.post('/auth/logout', (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy((err) => {
      if (err) {
        console.error('❌ Session destroy error:', err);
        return res.status(500).json({ error: 'Logout failed' });
      }
      res.clearCookie('connect.sid');
      console.log('✅ User logged out and session destroyed');
      res.json({ success: true, message: 'Logged out successfully' });
    });
  });
});

// FIXED: Auth check route
app.get('/auth/user', (req, res) => {
  console.log('🔍 Auth check - Session ID:', req.sessionID);
  console.log('🔍 Auth check - Is authenticated:', req.isAuthenticated());
  console.log('🔍 Auth check - User:', req.user?.username);
  
  if (req.isAuthenticated()) {
    const { id, username, fullName } = req.user;
    res.json({ authenticated: true, user: { id, username, fullName } });
  } else {
    res.json({ authenticated: false });
  }
});

// Patient routes (your existing patient routes here)
app.get('/api/patients', ensureAuthenticated, async (req, res) => {
  try {
    console.log('📍 GET /api/patients - User:', req.user?.username, 'ID:', req.user?.id);
    
    const query = `
      SELECT 
        id, name, contactno, email, patientdescription,
        treatmentstart, totalfee, paidfees,
        (totalfee - paidfees) as due_money,
        patienttype, user_id, createdat, updatedat
      FROM patients 
      WHERE user_id = $1
      ORDER BY createdat DESC
    `;
    
    const result = await queryDB(query, [req.user.id]);
    console.log('📊 Found patients:', result.rows.length);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Database error:', error);
    res.status(500).json({ error: 'Database error', details: error.message });
  }
});

// Enhanced PUT route with better error handling
app.put('/api/patients/:id', ensureAuthenticated, async (req, res) => {
  try {
    console.log('📝 PUT request for patient:', req.params.id, 'by user:', req.user.username);
    
    const { id: userId } = req.user;
    const getResult = await queryDB('SELECT * FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    
    if (!getResult.rows.length) {
      return res.status(404).json({ error: 'Patient not found' });
    }
    
    const existing = getResult.rows[0];
    
    // Validate and merge data
    const updatedData = {
      name: req.body.name || existing.name,
      contactNo: req.body.contactNo || existing.contactno,
      email: req.body.email || existing.email,
      patientDescription: req.body.patientDescription || existing.patientdescription,
      treatmentStart: req.body.treatmentStart || existing.treatmentstart,
      totalFee: Number(req.body.totalFee) || Number(existing.totalfee),
      paidFees: Number(req.body.paidFees) || Number(existing.paidfees),
      patientType: req.body.patientType || existing.patienttype
    };
    
    // Update query
    await queryDB(
      `UPDATE patients SET name = $1, contactNo = $2, email = $3, patientDescription = $4,
        treatmentStart = $5, totalFee = $6, paidFees = $7, patientType = $8, updatedAt = CURRENT_TIMESTAMP
        WHERE id = $9 AND user_id = $10`,
      [updatedData.name, updatedData.contactNo, updatedData.email, updatedData.patientDescription,
        updatedData.treatmentStart, updatedData.totalFee, updatedData.paidFees, updatedData.patientType, 
        req.params.id, userId]
    );
    
    // Return updated patient
    const updated = await queryDB('SELECT * FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    
    console.log('✅ Patient updated successfully');
    res.json(updated.rows[0]);
    
  } catch (err) {
    console.error('❌ Update error:', err);
    res.status(500).json({ error: 'Database update error', details: err.message });
  }
});

// Health check
app.get('/health', async (req, res) => {
  try {
    await queryDB('SELECT 1');
    res.json({ 
      status: 'healthy', 
      database: 'connected', 
      timestamp: new Date().toISOString(),
      sessions: 'PostgreSQL'
    });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', database: 'disconnected', error: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Smile Hub server running on port ${PORT}`);
  console.log('🌍 Environment:', process.env.NODE_ENV);
  console.log('🔐 Trust proxy enabled');
  console.log('🍪 Sessions: PostgreSQL store');
});
