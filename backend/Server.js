const express = require("express");
const app = express();
const path = require('path');
const router = express.Router();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const session = require('express-session');
require('dotenv').config();

app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET,  // secret key for signing the session ID cookie
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 60 * 60 * 1000  // 1 hour
    }
}));

// Allowlist of public paths
const publicPaths = ['/login', '/api/login-check', '/api/verify-otp'];

app.use((req, res, next) => {
    const isApi = req.path.startsWith('/api/');
    const isPublic = publicPaths.includes(req.path);

    // Allow static assets (css/js/images)
    const isAsset = req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico)$/);

    if (req.session.user || isPublic || isAsset || req.path === '/') {
        return next(); //  allow
    }

    // Redirect browser to login
    if (!isApi) {
        return res.redirect('/login');
    }

    //  Reject API calls with 401
    res.status(401).json({ error: "Unauthorized" });
});


const db = new sqlite3.Database('../election_booth.db', (err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('✅ Connected to the SQLite database.');
});


db.all('SELECT * FROM voters', [], (err, rows) => {
    if (err) {
        console.error('❌ Error querying voters:', err.message);
        return;
    }

    console.log('🗳️ Voters List:');
    rows.forEach((row) => {
        console.log(`🆔 ${row.national_id} | 👤 ${row.name} | 📱 ${row.phone}`);
    });
});


// Store OTP in memory for demo (replace with Redis for production)
const otps = {};

// 2. Check if voter exists and send OTP
app.post('/api/login-check', (req, res) => {
    const { national_id, phone } = req.body;
    db.get("SELECT * FROM voters WHERE national_id = ? AND phone = ?", [national_id, phone], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.status(404).json({ error: "Not found" });

        // Generate 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expires = Date.now() + 3 * 60 * 1000; // 5 minutes
        otps[national_id] = {
            code: otp,
            expires: expires
        };
        console.log(`OTP for ${national_id}: ${otp} (expires in 3 minutes)`);

        return res.json({ success: true, message: "OTP sent" });
    });
});

const otpAttemptsByIP = {}; // { "127.0.0.1": { count: 3, lastTry: 1713378981112 } }

// 3. Verify OTP
app.post('/api/verify-otp', (req, res) => {
    const { national_id, otp } = req.body;

    // 🧠 Get the requester's IP address
    const ip = req.ip === "::1" ? "127.0.0.1" : req.ip;

    // Initialize IP attempt tracking
    if (!otpAttemptsByIP[ip]) {
        otpAttemptsByIP[ip] = { count: 0, lastTry: Date.now() };
    }

    const ipData = otpAttemptsByIP[ip];
    const tooManyIPAttempts = ipData.count >= 5 && Date.now() - ipData.lastTry < 5 * 60 * 1000;

    if (tooManyIPAttempts) {
        console.warn(`⚠️ Blocked OTP attempt: IP ${ip} exceeded limit (${ipData.count} attempts)`);
        return res.status(429).json({ error: "Too many OTP attempts from this IP. Please wait 5 minutes." });
    }

    const record = otps[national_id];

    // Check for existence
    if (!record) {
        otpAttemptsByIP[ip].count++;
        otpAttemptsByIP[ip].lastTry = Date.now();
        return res.status(400).json({ error: "OTP not found. Please request a new one." });
    }

    // Check expiration
    if (Date.now() > record.expires) {
        delete otps[national_id];
        otpAttemptsByIP[ip].count++;
        otpAttemptsByIP[ip].lastTry = Date.now();
        return res.status(410).json({ error: "OTP expired. Please request a new one." });
    }

    // ✅ OTP correct
    if (record.code === otp) {
        delete otps[national_id];
        delete otpAttemptsByIP[ip];

        req.session.user = { national_id };
        return res.json({ success: true });
    }

    // ❌ OTP wrong
    otpAttemptsByIP[ip].count++;
    otpAttemptsByIP[ip].lastTry = Date.now();
    return res.status(401).json({ error: "Invalid OTP" });
});



app.get('/api/vote-status', (req, res) => {
    const user = req.session.user;
    if (!user || !user.national_id) {
        return res.status(401).json({ error: "Not logged in" });
    }

    const crypto = require('crypto');
    const hashed_id = crypto.createHash('sha256').update(user.national_id).digest('hex');

    db.get("SELECT * FROM votes WHERE national_id = ?", [hashed_id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });

        if (row) {
            return res.json({ voted: true });
        } else {
            return res.json({ voted: false });
        }
    });
});


app.get('/api/vote-result', (req, res) => {
    const sql = `
        SELECT 
        candidates.party AS name, 
        COUNT(votes.id) AS vote_count
        FROM candidates
        LEFT JOIN votes ON candidates.id = votes.candidate_id
        GROUP BY candidates.id
    `;
    db.all(sql, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows); // → [{ name: "Candidate 1", vote_count: 10 }, ...]
    });
});


app.post('/api/vote', (req, res) => {
    const user = req.session.user;
    const candidate_id = req.body.candidate_id;

    if (!user || !user.national_id) {
        return res.status(401).json({ error: "Not logged in" });
    }

    // Hash the national ID before storing
    const hashed_id = crypto.createHash('sha256').update(user.national_id).digest('hex');

    // Prevent double voting
    db.get("SELECT * FROM votes WHERE national_id = ?", [hashed_id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });

        if (row) {
            return res.status(400).json({ error: "You have already voted!" });
        }

        db.run(
            "INSERT INTO votes (national_id, candidate_id) VALUES (?, ?)",
            [hashed_id, candidate_id],
            function (err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ success: true });
            }
        );
    });
});


app.post('/api/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: "Logout failed" });

        res.clearCookie('connect.sid'); // default session cookie name
        res.json({ success: true });
    });
});




app.get('/api/candidates', (req, res) => {
    db.all('SELECT * FROM candidates', [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});


app.use(bodyParser.urlencoded({ extended: true }));
app.use(router);
app.use('/image', express.static(path.join(__dirname, '..', 'image')));
app.use('/html', express.static(path.join(__dirname, '..', 'html')));
app.use(cookieParser());

app.use(
    cors({
        origin: "*",
        credentials: true,
    })
)

router.get('/', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.status(200).sendFile(path.join(__dirname, '..', 'html', 'nav.html'));
});

router.get('/list-candidate', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.status(200).sendFile(path.join(__dirname, '..', 'html', 'list.html'));
});

router.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.status(200).sendFile(path.join(__dirname, '..', 'html', 'login1.html'));
});

router.get('/chart', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    res.status(200).sendFile(path.join(__dirname, '..', 'html', 'vote-chart.html'));
});


app.listen(process.env.PORT, function () {
    console.log(`Server listening port:${process.env.PORT}`);
    console.log(`🔗 link : http://localhost:${process.env.PORT}`);
});

