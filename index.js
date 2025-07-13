// 📁 File: index.js
require('dotenv').config();
const mysql = require('mysql2');

const express = require('express');
const bodyParser = require('body-parser');
const MySQL = require('mysql2');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const validator = require('validator');
const { Resend } = require('resend');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// ✅ Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'otp-secret-key',
  resave: false,
  saveUninitialized: true
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// 🔐 AES helpers
function encrypt(text, keyHex) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText, keyHex) {
  const [ivHex, encrypted] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ✅ MySQL Connection


const db = mysql.createPool({
  connectionLimit: 5,
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
   connectTimeout: 30000
});


db.query('SELECT 1', (err) => {
  if (err) console.error("❌ DB connection failed:", err);
  else console.log("✅ Connected to MySQL with Pool");
});

 


// ✅ Send OTP via Resend
function sendOTP(email, otp, res) {
  resend.emails.send({
    from: process.env.RESEND_SENDER,
    to: email,
    subject: 'Your OTP for Voting',
    text: `Your OTP is ${otp}`
  }).then(() => {
    console.log("✅ OTP Sent to", email);
    res.render('otp', { error: null });
  }).catch((error) => {
    console.error("❌ Resend error:", error);
    res.render('verify', { error: 'Failed to send OTP. Try again.' });
  });
}

// ✅ POST: /send-otp
app.post('/send-otp', (req, res) => {
  const rawEmail = req.body.email;
  if (!rawEmail || typeof rawEmail !== 'string') {
    return res.render('verify', { error: '❌ Email is missing' });
  }

  const email = rawEmail.trim().toLowerCase();
  if (!validator.isEmail(email)) {
    return res.render('verify', { error: '❌ Invalid email address' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  req.session.email = email;
  req.session.otp = otp;
  req.session.otpTimestamp = Date.now();

  sendOTP(email, otp, res);
});

// 🔁 Resend OTP
app.post('/resend-otp', (req, res) => {
  const email = req.session.email;
  if (!email) return res.redirect('/verify');

  const otp = Math.floor(100000 + Math.random() * 900000);
  req.session.otp = otp;
  req.session.otpTimestamp = Date.now();

  sendOTP(email, otp, res);
});

// ✅ POST: /verify-otp
app.post('/verify-otp', (req, res) => {
  const userOtp = req.body.otp;
  const now = Date.now();
  const otpTime = req.session.otpTimestamp;

  if (!otpTime || now - otpTime > 5 * 60 * 1000) {
    return res.render('otp', { error: '❌ OTP expired. Try again.' });
  }

  if (parseInt(userOtp) === req.session.otp) {
    req.session.verified = true;
    db.query('INSERT IGNORE INTO verified_emails (email) VALUES (?)', [req.session.email], (err) => {
      if (err) console.error('❌ Failed to save verified email:', err);
    });
    res.redirect('/vote');
  } else {
    res.render('otp', { error: '❌ Invalid OTP. Please try again.' });
  }
});

// ✅ GET: /verify page
app.get('/verify', (req, res) => {
  res.render('verify', { error: null });
});

// ✅ GET: /vote
app.get('/vote', (req, res) => {
  if (!req.session.verified) return res.redirect('/verify');
  res.render('vote', { session: req.session });
});

// ✅ POST: /vote
app.post('/vote', (req, res) => {
  if (!req.session.verified) return res.redirect('/verify');

  const { choice } = req.body;
  const hashedEmail = crypto.createHash('sha256').update(req.session.email).digest('hex');
  const secret = process.env.AES_SECRET;

  db.query('SELECT * FROM votes WHERE email_hash = ?', [hashedEmail], (err, results) => {
    if (err) return res.send("❌ DB Error");
    if (results.length > 0) {
      return res.send(`
        <div style="text-align:center;margin-top:50px;">
          <h3>⚠ You’ve already voted!</h3>
          <a href="/verify" class="btn btn-warning mt-3">Back</a>
        </div>
      `);
    }

    const encryptedVote = encrypt(choice, secret);
    db.query('INSERT INTO votes (email_hash, choice) VALUES (?, ?)', [hashedEmail, encryptedVote], err => {
      if (err) return res.send("❌ Error saving vote");
      req.session.destroy();
      res.redirect('/success');
    });
  });
});

// ✅ GET: /admin-login
app.get('/admin-login', (req, res) => {
  res.render('adminlogin', { error: null });
});

// ✅ POST: /admin-login
app.post('/admin-login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'quantum123') {
    req.session.admin = true;
    res.redirect('/results');
  } else {
    res.render('adminlogin', { error: '❌ Invalid credentials' });
  }
});

// ✅ Admin-only middleware
function requireAdmin(req, res, next) {
  if (req.session.admin) return next();
  res.redirect('/admin-login');
}

// ✅ GET: /results
app.get('/results', requireAdmin, (req, res) => {
  res.render('results');
});

// ✅ GET: /results-data
app.get('/results-data', requireAdmin, (req, res) => {
  const secret = process.env.AES_SECRET;
  db.query('SELECT choice FROM votes', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB Error' });

    const counts = {
      AWS: 0,
      Azure: 0,
      "Google Cloud": 0,
      "IBM Quantum": 0
    };

    rows.forEach(row => {
      try {
        const decrypted = decrypt(row.choice, secret);
        if (counts[decrypted] !== undefined) counts[decrypted]++;
      } catch (e) {
        console.error("⚠ Decryption error:", e.message);
      }
    });

    res.json({ labels: Object.keys(counts), counts: Object.values(counts) });
  });
});

// ✅ GET: /admin-logout
app.get('/admin-logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/admin-login');
  });
});

// ✅ GET: /success
app.get('/success', (req, res) => {
  res.render('success');
});

// ✅ Default Route
app.get('/', (req, res) => {
  res.redirect('/verify');
});

// ✅ Start server
app.listen(3000, () => console.log("🚀 Server running at http://localhost:3000"));
