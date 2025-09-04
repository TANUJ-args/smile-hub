const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const flash = require('connect-flash');
const helmet = require('helmet');
const multer = require('multer');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();

// Enhanced PostgreSQL connection pool configuration for Neon
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Test database connection on startup
pool.on('connect', () => {
  console.log('Connected to Neon PostgreSQL database');
});

pool.on('error', (err, client) => {
  console.error('Unexpected error on idle client', err);
  process.exit(-1);
});

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdir(uploadDir, { recursive: true }).catch(console.error);

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 500 * 1024, // 500KB limit
    files: 10 // Max 10 files at once
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// CRITICAL: Trust proxy for hosted environments
app.set('trust proxy', 1);

// Add Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "code.jquery.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "cdnjs.cloudflare.com", "fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"]
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true
    }
  }
}));

// CORS with proper credentials support
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://smile-hub.onrender.com']
    : ['http://localhost:3000', 'http://localhost:5000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('.'));
app.use('/uploads', express.static('uploads'));

const session_secret = process.env.SESSION_SECRET || 'smile-hub-super-9999secure-session-key-2025';

// Configure PostgreSQL session store
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'user_sessions'
  }),
  secret: session_secret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

async function queryDB(text, params) {
  const client = await pool.connect();
  const start = Date.now();
  try {
    console.log('🔍 DB Query:', { text, params: params || 'none' });
    const result = await client.query(text, params);
    const duration = Date.now() - start;
    console.log('✅ DB Query complete', {
      duration_ms: duration,
      rows: result.rowCount
    });
    return result;
  } catch (error) {
    const duration = Date.now() - start;
    console.error('❌ DB Query error:', {
      error: error.message,
      code: error.code,
      duration_ms: duration,
      query: text,
      params: params || 'none'
    });

    if (error.code === '23505') {
      throw new Error('This record already exists: ' + error.detail);
    } else if (error.code === '23503') {
      throw new Error('Referenced record does not exist: ' + error.detail);
    } else if (error.code === '42P01') {
      throw new Error('Database table not found. Please contact support.');
    } else {
      throw error;
    }
  } finally {
    client.release();
  }
}

// -------------------------------
// Database Setup (run once)
// -------------------------------
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
      try {
        await queryDB(`ALTER TABLE user_sessions ADD CONSTRAINT session_pkey PRIMARY KEY (sid);`);
      } catch (e) {
        console.log('Note: Primary key for sessions may already exist');
      }
    }

    await queryDB(`CREATE INDEX IF NOT EXISTS idx_session_expire ON user_sessions (expire);`);

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

    // Create patient_images table
    await queryDB(`
      CREATE TABLE IF NOT EXISTS patient_images (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
        filename VARCHAR(255) NOT NULL,
        original_filename VARCHAR(255) NOT NULL,
        file_path VARCHAR(500) NOT NULL,
        file_size INTEGER NOT NULL,
        mime_type VARCHAR(100) NOT NULL,
        rotation INTEGER DEFAULT 0,
        is_mirrored BOOLEAN DEFAULT FALSE,
        crop_data TEXT,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create installment_payments table
    await queryDB(`
      CREATE TABLE IF NOT EXISTS installment_payments (
        id SERIAL PRIMARY KEY,
        patient_id INTEGER REFERENCES patients(id) ON DELETE CASCADE,
        amount NUMERIC(10,2) NOT NULL,
        payment_date DATE NOT NULL,
        payment_method VARCHAR(50),
        notes TEXT,
        recorded_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

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
      console.log('Sample user "tanuj" created');
    }

    console.log('Database initialization completed successfully');
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
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

// Health check endpoint
app.get('/health', async (req, res) => {
  const healthData = {
    status: 'initializing',
    version: process.env.npm_package_version || '1.0.0',
    timestamp: new Date().toISOString(),
    uptime: `${Math.floor(process.uptime())} seconds`,
    environment: process.env.NODE_ENV || 'development',
    components: {
      database: { status: 'checking' },
      session: { status: 'active' }
    }
  };

  try {
    const dbStart = Date.now();
    await queryDB('SELECT 1');
    const dbDuration = Date.now() - dbStart;
    healthData.components.database = {
      status: 'connected',
      responseTime: `${dbDuration}ms`
    };

    try {
      const sessionCheck = await queryDB('SELECT COUNT(*) FROM user_sessions');
      healthData.components.session = {
        status: 'active',
        count: parseInt(sessionCheck.rows[0].count, 10)
      };
    } catch (sessionError) {
      healthData.components.session = {
        status: 'error',
        error: sessionError.message
      };
    }

    healthData.status = 'healthy';
    res.json(healthData);
  } catch (error) {
    healthData.status = 'unhealthy';
    healthData.components.database = {
      status: 'disconnected',
      error: error.message
    };
    res.status(503).json(healthData);
  }
});

// Auth Routes
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
  console.log('🚪 Logout request received for user:', req.user?.username);
  console.log('🍪 Session at logout:', req.sessionID);
  req.logout(err => {
    if (err) {
      console.error('❌ Logout error:', err);
      return next(err);
    }
    req.session.destroy(err => {
      if (err) {
        console.error('❌ Session destruction error:', err);
        return next(err);
      }
      console.log('✅ User logged out and session destroyed');
      res.clearCookie('connect.sid');
      res.json({ success: true, message: 'Logged out successfully' });
    });
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

// Patient validation
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
    const result = await queryDB(`
      SELECT p.*, 
             COALESCE(SUM(ip.amount), 0) as total_installments_paid,
             COUNT(pi.id) as image_count
      FROM patients p 
      LEFT JOIN installment_payments ip ON p.id = ip.patient_id
      LEFT JOIN patient_images pi ON p.id = pi.patient_id
      WHERE p.user_id = $1 
      GROUP BY p.id
      ORDER BY p.id DESC
    `, [userId]);

    const rows = result.rows.map(row => ({
      id: row.id,
      name: row.name,
      contactNo: row.contactno,
      email: row.email,
      patientDescription: row.patientdescription,
      treatmentStart: row.treatmentstart,
      totalFee: row.totalfee,
      paidFees: row.paidfees,
      patientType: row.patienttype,
      userId: row.user_id,
      createdAt: row.createdat,
      updatedAt: row.updatedat,
      totalInstallmentsPaid: parseFloat(row.total_installments_paid || 0),
      imageCount: parseInt(row.image_count || 0)
    }));

    res.json(rows);
  } catch (err) {
    console.error('DB error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// GET SINGLE PATIENT WITH IMAGES AND INSTALLMENTS
app.get('/api/patients/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const patientResult = await queryDB('SELECT * FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    
    if (!patientResult.rows.length) return res.status(404).json({ error: 'Patient not found' });

    const row = patientResult.rows[0];
    
    // Get patient images
    const imagesResult = await queryDB(`
      SELECT id, filename, original_filename, file_path, file_size, mime_type, 
             rotation, is_mirrored, crop_data, uploaded_at
      FROM patient_images 
      WHERE patient_id = $1 
      ORDER BY uploaded_at DESC
    `, [req.params.id]);

    // Get installment payments
    const installmentsResult = await queryDB(`
      SELECT ip.*, u.fullName as recorded_by_name
      FROM installment_payments ip
      LEFT JOIN users u ON ip.recorded_by = u.id
      WHERE ip.patient_id = $1 
      ORDER BY ip.payment_date DESC, ip.created_at DESC
    `, [req.params.id]);

    const patient = {
      id: row.id,
      name: row.name,
      contactNo: row.contactno,
      email: row.email,
      patientDescription: row.patientdescription,
      treatmentStart: row.treatmentstart,
      totalFee: row.totalfee,
      paidFees: row.paidfees,
      patientType: row.patienttype,
      userId: row.user_id,
      createdAt: row.createdat,
      updatedAt: row.updatedat,
      images: imagesResult.rows,
      installments: installmentsResult.rows.map(inst => ({
        id: inst.id,
        amount: parseFloat(inst.amount),
        paymentDate: inst.payment_date,
        paymentMethod: inst.payment_method,
        notes: inst.notes,
        recordedBy: inst.recorded_by_name,
        createdAt: inst.created_at
      }))
    };

    res.json(patient);
  } catch (err) {
    console.error('DB error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// CREATE NEW PATIENT
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

// UPDATE PATIENT
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
      contactNo: req.body.contactNo ?? existing.contactno,
      email: req.body.email ?? existing.email,
      patientDescription: req.body.patientDescription ?? existing.patientdescription,
      treatmentStart: req.body.treatmentStart ?? existing.treatmentstart,
      totalFee: Number(req.body.totalFee ?? existing.totalfee),
      paidFees: Number(req.body.paidFees ?? existing.paidfees),
      patientType: req.body.patientType ?? existing.patienttype
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
    console.error('Update error:', err);
    res.status(500).json({ error: 'Database update error: ' + err.message });
  }
});

// DELETE PATIENT
app.delete('/api/patients/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    
    // Get patient images to delete files
    const imagesResult = await queryDB('SELECT file_path FROM patient_images WHERE patient_id = $1', [req.params.id]);
    
    // Delete patient (cascade will handle images and installments)
    const result = await queryDB('DELETE FROM patients WHERE id = $1 AND user_id = $2', [req.params.id, userId]);
    if (!result.rowCount) return res.status(404).json({ error: 'Patient not found' });

    // Delete physical image files
    for (const image of imagesResult.rows) {
      try {
        await fs.unlink(image.file_path);
      } catch (err) {
        console.error('Error deleting image file:', err);
      }
    }

    res.status(204).send();
  } catch (err) {
    console.error('Delete error:', err);
    res.status(500).json({ error: 'Database delete error: ' + err.message });
  }
});

// IMAGE UPLOAD FOR PATIENT
app.post('/api/patients/:id/images', ensureAuthenticated, upload.array('images', 10), async (req, res) => {
  try {
    const { id: userId } = req.user;
    const patientId = req.params.id;

    // Verify patient exists and belongs to user
    const patientCheck = await queryDB('SELECT 1 FROM patients WHERE id = $1 AND user_id = $2', [patientId, userId]);
    if (!patientCheck.rowCount) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: 'No images uploaded' });
    }

    const uploadedImages = [];

    for (const file of req.files) {
      try {
        // Generate unique filename
        const fileId = uuidv4();
        const extension = path.extname(file.originalname);
        const filename = `${fileId}${extension}`;
        const filePath = path.join(uploadDir, filename);

        // Process and save image using Sharp
        await sharp(file.buffer)
          .resize(1024, 1024, { fit: 'inside', withoutEnlargement: true })
          .jpeg({ quality: 85 })
          .toFile(filePath);

        // Save to database
        const imageResult = await queryDB(`
          INSERT INTO patient_images (patient_id, filename, original_filename, file_path, file_size, mime_type)
          VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
        `, [patientId, filename, file.originalname, filePath, file.size, file.mimetype]);

        uploadedImages.push(imageResult.rows[0]);
      } catch (error) {
        console.error('Error processing image:', error);
      }
    }

    res.json({ success: true, images: uploadedImages });
  } catch (err) {
    console.error('Image upload error:', err);
    res.status(500).json({ error: 'Image upload failed' });
  }
});

// UPDATE IMAGE (rotation, mirror, crop)
app.put('/api/images/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { rotation = 0, is_mirrored = false, crop_data = null } = req.body;
    const imageId = req.params.id;

    // Verify image belongs to user's patient
    const imageCheck = await queryDB(`
      SELECT pi.*, p.user_id 
      FROM patient_images pi 
      JOIN patients p ON pi.patient_id = p.id 
      WHERE pi.id = $1 AND p.user_id = $2
    `, [imageId, req.user.id]);

    if (!imageCheck.rowCount) {
      return res.status(404).json({ error: 'Image not found' });
    }

    await queryDB(`
      UPDATE patient_images 
      SET rotation = $1, is_mirrored = $2, crop_data = $3 
      WHERE id = $4
    `, [rotation, is_mirrored, crop_data, imageId]);

    res.json({ success: true, message: 'Image updated successfully' });
  } catch (err) {
    console.error('Image update error:', err);
    res.status(500).json({ error: 'Image update failed' });
  }
});

// DELETE IMAGE
app.delete('/api/images/:id', ensureAuthenticated, async (req, res) => {
  try {
    const imageId = req.params.id;

    // Get image details and verify ownership
    const imageResult = await queryDB(`
      SELECT pi.file_path, p.user_id 
      FROM patient_images pi 
      JOIN patients p ON pi.patient_id = p.id 
      WHERE pi.id = $1 AND p.user_id = $2
    `, [imageId, req.user.id]);

    if (!imageResult.rowCount) {
      return res.status(404).json({ error: 'Image not found' });
    }

    const filePath = imageResult.rows[0].file_path;

    // Delete from database
    await queryDB('DELETE FROM patient_images WHERE id = $1', [imageId]);

    // Delete physical file
    try {
      await fs.unlink(filePath);
    } catch (err) {
      console.error('Error deleting image file:', err);
    }

    res.json({ success: true, message: 'Image deleted successfully' });
  } catch (err) {
    console.error('Image delete error:', err);
    res.status(500).json({ error: 'Image delete failed' });
  }
});

// ADD INSTALLMENT PAYMENT
app.post('/api/patients/:id/installments', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const patientId = req.params.id;
    const { amount, payment_date, payment_method = 'Cash', notes = '' } = req.body;

    // Validate input
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid payment amount' });
    }
    if (!payment_date) {
      return res.status(400).json({ error: 'Payment date is required' });
    }

    // Verify patient exists and belongs to user
    const patientCheck = await queryDB('SELECT 1 FROM patients WHERE id = $1 AND user_id = $2', [patientId, userId]);
    if (!patientCheck.rowCount) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Add installment payment
    const result = await queryDB(`
      INSERT INTO installment_payments (patient_id, amount, payment_date, payment_method, notes, recorded_by)
      VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
    `, [patientId, Number(amount), payment_date, payment_method, notes, userId]);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Installment payment error:', err);
    res.status(500).json({ error: 'Failed to add installment payment' });
  }
});

// GET INSTALLMENT PAYMENTS FOR PATIENT
app.get('/api/patients/:id/installments', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const patientId = req.params.id;

    // Verify patient exists and belongs to user
    const patientCheck = await queryDB('SELECT 1 FROM patients WHERE id = $1 AND user_id = $2', [patientId, userId]);
    if (!patientCheck.rowCount) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    const result = await queryDB(`
      SELECT ip.*, u.fullName as recorded_by_name
      FROM installment_payments ip
      LEFT JOIN users u ON ip.recorded_by = u.id
      WHERE ip.patient_id = $1 
      ORDER BY ip.payment_date DESC, ip.created_at DESC
    `, [patientId]);

    res.json(result.rows);
  } catch (err) {
    console.error('Get installments error:', err);
    res.status(500).json({ error: 'Failed to fetch installment payments' });
  }
});

// DELETE INSTALLMENT PAYMENT
app.delete('/api/installments/:id', ensureAuthenticated, async (req, res) => {
  try {
    const { id: userId } = req.user;
    const installmentId = req.params.id;

    // Verify installment belongs to user's patient
    const installmentCheck = await queryDB(`
      SELECT ip.id 
      FROM installment_payments ip 
      JOIN patients p ON ip.patient_id = p.id 
      WHERE ip.id = $1 AND p.user_id = $2
    `, [installmentId, userId]);

    if (!installmentCheck.rowCount) {
      return res.status(404).json({ error: 'Installment payment not found' });
    }

    await queryDB('DELETE FROM installment_payments WHERE id = $1', [installmentId]);
    res.json({ success: true, message: 'Installment payment deleted successfully' });
  } catch (err) {
    console.error('Delete installment error:', err);
    res.status(500).json({ error: 'Failed to delete installment payment' });
  }
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await pool.end();
  console.log('Database pool closed.');
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('Shutting down gracefully...');
  await pool.end();
  console.log('Database pool closed.');
  process.exit(0);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Smile Hub server running on port ${PORT}`);
  console.log('Environment:', process.env.NODE_ENV);
  if (process.env.DATABASE_URL) {
    try {
      console.log('DB host:', new URL(process.env.DATABASE_URL).hostname);
    } catch (error) {
      console.log('DB connection configured');
    }
  }
});